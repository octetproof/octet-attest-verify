//! Apple App Attest — offline verification.
//!
//! The verification logic (CBOR parse, chain-to-root, assertion check) lands in
//! Phase E.2. This module currently defines the **vocabulary**: the expected
//! app identity, the evidence pulled off a proof, the cached attested key, the
//! verdict, and — most importantly — the pure functions that reconstruct the
//! per-proof challenge. Those reconstruction functions ARE the cross-platform
//! wire contract (see `spec/attestation-verification.md`); they are pure and
//! unit-tested so the contract can't drift silently from the SDK side.

use crate::error::{AttestError, Result};
use sha2::{Digest, Sha256};
use x509_cert::der::{Decode, Encode};
use x509_cert::Certificate;

/// App Attest environment an attestation was produced in, read from the AAGUID
/// in the authenticator data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestEnvironment {
    /// `appattestdevelop` — development (Xcode-signed) builds.
    Development,
    /// `appattest` — production (TestFlight / App Store) builds.
    Production,
}

/// Apple's nonce extension OID `1.2.840.113635.100.8.2`.
const APPLE_NONCE_OID: &str = "1.2.840.113635.100.8.2";
const AAGUID_PRODUCTION: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
const AAGUID_DEVELOPMENT: &[u8; 16] = b"appattestdevelop";

/// The expected application identity an attestation must bind to.
///
/// Apple App Attest commits `SHA256("<TeamID>.<BundleID>")` (the *App ID*) into
/// the attestation's authenticator data. A verifier compares that against the
/// identity it expects for this proof — which Octet carries as a *signed* claim
/// in the activation bearer (`app_id` / `team_id`), so the expected value is
/// itself trusted, not caller-asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppId(pub [u8; 32]);

impl AppId {
    /// Compute the App Attest App ID hash from a Team ID and bundle identifier,
    /// e.g. `from_team_and_bundle("6ZH5F97PWU", "com.octetproof.tester")`.
    ///
    /// Apple's App ID string is `"<TeamID>.<BundleID>"`; the value committed in
    /// the attestation is its SHA-256.
    pub fn from_team_and_bundle(team_id: &str, bundle_id: &str) -> Self {
        let mut h = Sha256::new();
        h.update(team_id.as_bytes());
        h.update(b".");
        h.update(bundle_id.as_bytes());
        AppId(h.finalize().into())
    }
}

/// The App Attest evidence carried by one proof, already extracted from the
/// `DeviceAttestation` protobuf by the caller.
#[derive(Debug, Clone)]
pub struct AppAttestEvidence<'a> {
    /// `key_id` — Apple's identifier for the attested key (proto field 1).
    pub key_id: &'a [u8],
    /// `app_attest_attestation` (field 8): the CBOR attestation object. Present
    /// only on the first proof after a key is attested; `None` afterwards.
    pub attestation_object: Option<&'a [u8]>,
    /// `app_attest_assertion` (field 9): the per-window assertion.
    pub assertion: &'a [u8],
    /// `attestation_nonce` (field 10): the window nonce the assertion signs over.
    pub nonce: &'a [u8],
    /// The proof's own `position_commitment` (field 5).
    pub commitment: &'a [u8],
    /// The proof's own `timestamp_ms` (field 7).
    pub timestamp_ms: i64,
}

/// A public key recovered from an attestation object, plus the last assertion
/// counter seen for it. A verifier caches one of these per `key_id` so that
/// later assertion-only proofs (which omit the ~5 KB attestation object) can
/// still be verified, and so counter rollback can be detected.
#[derive(Debug, Clone)]
pub struct AttestedKey {
    /// SEC1-encoded P-256 public key recovered from the attestation leaf cert.
    pub public_key_sec1: Vec<u8>,
    /// Highest assertion counter observed (App Attest counters are monotonic).
    pub last_counter: u32,
}

/// Outcome of verifying a single proof's App Attest evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// All checks the available evidence allowed passed.
    Verified,
    /// A check failed; carries the reason.
    NotVerified(crate::error::AttestError),
}

// --- Wire contract: challenge reconstruction (pure) ---
//
// These mirror the device SDK's challenge construction exactly. The App Attest
// assertion signs `SHA256(nonce)` — window-level, so one assertion serves every
// proof in a cadence window. The Secure Enclave signature (a separate field)
// signs `SHA256(commitment ‖ ts(8B big-endian) ‖ nonce)` — per proof. A
// verifier rebuilds both from fields already on the proof (commitment = 5,
// ts = 7, nonce = 10), holding nothing server-side.

/// `clientDataHash` the App Attest assertion is generated over: `SHA256(nonce)`.
/// Window-level (depends only on the nonce), hence reusable across a cadence
/// window.
pub fn assertion_client_data_hash(nonce: &[u8]) -> [u8; 32] {
    Sha256::digest(nonce).into()
}

/// The raw per-proof Secure Enclave challenge: `commitment ‖ ts(8B big-endian)
/// ‖ nonce`. Returned unhashed; see [`se_client_data_hash`] for the value the
/// SE key actually signs.
pub fn se_challenge(commitment: &[u8], timestamp_ms: i64, nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(commitment.len() + 8 + nonce.len());
    out.extend_from_slice(commitment);
    out.extend_from_slice(&timestamp_ms.to_be_bytes());
    out.extend_from_slice(nonce);
    out
}

/// `SHA256(commitment ‖ ts ‖ nonce)` — the per-proof challenge hash the device
/// key signs under [`DEVICE_ATTESTATION_DOMAIN`] (see [`verify_device_signature`]).
pub fn se_client_data_hash(commitment: &[u8], timestamp_ms: i64, nonce: &[u8]) -> [u8; 32] {
    Sha256::digest(se_challenge(commitment, timestamp_ms, nonce)).into()
}

/// Domain-separation prefix the device key signs `DeviceAttestation.signature`
/// (field 2) under. A shared, versioned, public constant — identical on iOS and
/// Android — so the signed message is reconstructable from the proof alone.
pub const DEVICE_ATTESTATION_DOMAIN: &[u8] = b"octet-device-attestation-v1";

/// Verify the per-proof device-key signature (`DeviceAttestation.signature`,
/// field 2): ECDSA-P256 over `DEVICE_ATTESTATION_DOMAIN ‖ SHA256(commitment ‖
/// ts ‖ nonce)` using the device public key.
///
/// `signature` may be DER or raw `r‖s` (Android emits DER, iOS raw); high-S is
/// accepted (normalised to low-S, which is an equally-valid signature for the
/// same message). The device public key is SEC1-encoded P-256 — the Android
/// `certificate_chain` leaf key, or an out-of-band iOS Secure-Enclave key.
pub fn verify_device_signature(
    commitment: &[u8],
    timestamp_ms: i64,
    nonce: &[u8],
    device_public_key_sec1: &[u8],
    signature: &[u8],
) -> Result<()> {
    use p256::ecdsa::signature::Verifier;

    let mut message = DEVICE_ATTESTATION_DOMAIN.to_vec();
    message.extend_from_slice(&se_client_data_hash(commitment, timestamp_ms, nonce));

    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(device_public_key_sec1)
        .map_err(|_| AttestError::DeviceSignatureInvalid)?;
    let parsed = p256::ecdsa::Signature::from_der(signature)
        .or_else(|_| p256::ecdsa::Signature::from_slice(signature))
        .map_err(|_| AttestError::DeviceSignatureInvalid)?;
    // Accept Android Keystore's high-S form; the low-S twin verifies identically.
    let sig = parsed.normalize_s().unwrap_or(parsed);
    vk.verify(&message, &sig)
        .map_err(|_| AttestError::DeviceSignatureInvalid)
}

/// Which App Attest environments a verifier accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptEnvironment {
    /// Accept only development attestations.
    Development,
    /// Accept only production attestations.
    Production,
    /// Accept either.
    Any,
}

impl AcceptEnvironment {
    fn accepts(&self, env: AttestEnvironment) -> bool {
        matches!(
            (self, env),
            (AcceptEnvironment::Any, _)
                | (AcceptEnvironment::Development, AttestEnvironment::Development)
                | (AcceptEnvironment::Production, AttestEnvironment::Production)
        )
    }
}

// --- CBOR helpers ---

fn cbor_map_get<'a>(v: &'a ciborium::value::Value, key: &str) -> Option<&'a ciborium::value::Value> {
    v.as_map()?
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, val)| val)
}

/// Parsed pieces of the CBOR attestation object we need.
struct AttestationObject {
    auth_data: Vec<u8>,
    /// DER certificates, leaf first.
    x5c: Vec<Vec<u8>>,
}

fn parse_attestation_object(cbor: &[u8]) -> Result<AttestationObject> {
    let v: ciborium::value::Value = ciborium::from_reader(cbor)
        .map_err(|e| AttestError::MalformedAttestation(format!("cbor: {e}")))?;
    let fmt = cbor_map_get(&v, "fmt").and_then(|f| f.as_text());
    if fmt != Some("apple-appattest") {
        return Err(AttestError::MalformedAttestation(format!("fmt={fmt:?}")));
    }
    let att_stmt = cbor_map_get(&v, "attStmt")
        .ok_or_else(|| AttestError::MalformedAttestation("no attStmt".into()))?;
    let x5c_val = cbor_map_get(att_stmt, "x5c")
        .and_then(|x| x.as_array())
        .ok_or_else(|| AttestError::MalformedAttestation("no x5c".into()))?;
    let x5c: Vec<Vec<u8>> = x5c_val
        .iter()
        .filter_map(|c| c.as_bytes().cloned())
        .collect();
    if x5c.len() < 2 {
        return Err(AttestError::MalformedAttestation("x5c needs leaf + intermediate".into()));
    }
    let auth_data = cbor_map_get(&v, "authData")
        .and_then(|a| a.as_bytes())
        .cloned()
        .ok_or_else(|| AttestError::MalformedAttestation("no authData".into()))?;
    Ok(AttestationObject { auth_data, x5c })
}

// --- X.509 chain ---

fn p384_key_from_cert(cert: &Certificate) -> Result<p384::ecdsa::VerifyingKey> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| AttestError::MalformedCertChain("issuer SPKI not octet-aligned".into()))?;
    p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
        .map_err(|e| AttestError::MalformedCertChain(format!("issuer P-384 key: {e}")))
}

/// Verify `subject`'s signature was produced by `issuer_key` (ECDSA P-384 /
/// SHA-384 — the algorithm Apple's App Attest CA chain uses).
fn verify_cert_signature(
    subject: &Certificate,
    issuer_key: &p384::ecdsa::VerifyingKey,
) -> Result<()> {
    use p384::ecdsa::signature::Verifier;
    let tbs = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| AttestError::MalformedCertChain(format!("tbs der: {e}")))?;
    let sig_bytes = subject
        .signature
        .as_bytes()
        .ok_or_else(|| AttestError::MalformedCertChain("signature not octet-aligned".into()))?;
    let sig = p384::ecdsa::Signature::from_der(sig_bytes)
        .map_err(|e| AttestError::MalformedCertChain(format!("ecdsa sig: {e}")))?;
    issuer_key
        .verify(&tbs, &sig)
        .map_err(|_| AttestError::ChainNotAnchored)
}

/// Extract the 32-byte nonce from the leaf's Apple nonce extension (OID
/// 1.2.840.113635.100.8.2). The extension value is DER
/// `SEQUENCE { [1] { OCTET STRING (nonce) } }`; we locate the inner 32-byte
/// OCTET STRING.
fn extract_nonce_extension(leaf: &Certificate) -> Result<[u8; 32]> {
    let exts = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| AttestError::MalformedCertChain("leaf has no extensions".into()))?;
    let ext = exts
        .iter()
        .find(|e| e.extn_id.to_string() == APPLE_NONCE_OID)
        .ok_or_else(|| AttestError::MalformedCertChain("no Apple nonce extension".into()))?;
    scan_octet_string_32(ext.extn_value.as_bytes())
        .ok_or_else(|| AttestError::MalformedCertChain("nonce extension shape".into()))
}

/// Find the `04 20` (OCTET STRING, length 32) TLV in a DER blob and return its
/// 32 contents. Pure so the parse is unit-testable without a full certificate.
fn scan_octet_string_32(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut i = 0usize;
    while i + 2 + 32 <= bytes.len() {
        if bytes[i] == 0x04 && bytes[i + 1] == 0x20 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes[i + 2..i + 2 + 32]);
            return Some(out);
        }
        i += 1;
    }
    None
}

// --- Authenticator data ---

struct AuthData {
    rp_id_hash: [u8; 32],
    counter: u32,
    /// Present only in attestation authData (attested credential data).
    aaguid: Option<[u8; 16]>,
    credential_id: Option<Vec<u8>>,
}

fn parse_auth_data(d: &[u8], with_credential: bool) -> Result<AuthData> {
    if d.len() < 37 {
        return Err(AttestError::MalformedAttestation("authData < 37 bytes".into()));
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&d[0..32]);
    let counter = u32::from_be_bytes([d[33], d[34], d[35], d[36]]);
    if !with_credential {
        return Ok(AuthData { rp_id_hash, counter, aaguid: None, credential_id: None });
    }
    if d.len() < 55 {
        return Err(AttestError::MalformedAttestation("authData missing attested cred data".into()));
    }
    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&d[37..53]);
    let cred_len = u16::from_be_bytes([d[53], d[54]]) as usize;
    if d.len() < 55 + cred_len {
        return Err(AttestError::MalformedAttestation("authData credential_id truncated".into()));
    }
    let credential_id = d[55..55 + cred_len].to_vec();
    Ok(AuthData { rp_id_hash, counter, aaguid: Some(aaguid), credential_id: Some(credential_id) })
}

// --- Public verification entry points ---

/// Verify an attestation object (the first proof of a key). On success returns
/// the [`AttestedKey`] (recovered public key + initial counter) the caller
/// caches by `key_id` to verify later assertions.
pub fn verify_attestation(
    attestation_object: &[u8],
    nonce: &[u8],
    expected_app_id: &AppId,
    key_id: &[u8],
    accept_env: AcceptEnvironment,
) -> Result<AttestedKey> {
    crate::root::verify_pin()?;
    let obj = parse_attestation_object(attestation_object)?;

    // Apple nonce = SHA256(authData ‖ clientDataHash), clientDataHash = SHA256(nonce).
    let client_data_hash = assertion_client_data_hash(nonce);
    let apple_nonce: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(&obj.auth_data);
        h.update(client_data_hash);
        h.finalize().into()
    };

    let leaf = Certificate::from_der(&obj.x5c[0])
        .map_err(|e| AttestError::MalformedCertChain(format!("leaf: {e}")))?;
    let intermediate = Certificate::from_der(&obj.x5c[1])
        .map_err(|e| AttestError::MalformedCertChain(format!("intermediate: {e}")))?;
    let root = crate::root::root();

    // Chain: intermediate signed by the embedded root; leaf signed by intermediate.
    verify_cert_signature(&intermediate, &p384_key_from_cert(&root)?)?;
    verify_cert_signature(&leaf, &p384_key_from_cert(&intermediate)?)?;

    // Nonce binding.
    if extract_nonce_extension(&leaf)? != apple_nonce {
        return Err(AttestError::NonceMismatch);
    }

    // App identity + environment.
    let ad = parse_auth_data(&obj.auth_data, true)?;
    if ad.rp_id_hash != expected_app_id.0 {
        return Err(AttestError::AppIdMismatch);
    }
    let env = match ad.aaguid {
        Some(a) if &a == AAGUID_PRODUCTION => AttestEnvironment::Production,
        Some(a) if &a == AAGUID_DEVELOPMENT => AttestEnvironment::Development,
        _ => return Err(AttestError::MalformedAttestation("unknown AAGUID".into())),
    };
    if !accept_env.accepts(env) {
        return Err(AttestError::WrongEnvironment);
    }

    // Leaf P-256 public key + key_id binding (key_id == SHA256(pubkey) == credentialId).
    let leaf_pub = leaf
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| AttestError::MalformedCertChain("leaf SPKI not octet-aligned".into()))?
        .to_vec();
    let pub_hash: [u8; 32] = Sha256::digest(&leaf_pub).into();
    if pub_hash.as_slice() != key_id {
        return Err(AttestError::KeyIdMismatch);
    }
    if ad.credential_id.as_deref() != Some(pub_hash.as_slice()) {
        return Err(AttestError::KeyIdMismatch);
    }

    Ok(AttestedKey { public_key_sec1: leaf_pub, last_counter: ad.counter })
}

/// Verify an assertion against a previously [`AttestedKey`]. Returns the new
/// (advanced) counter on success; the caller updates the cached key with it.
pub fn verify_assertion(
    assertion: &[u8],
    nonce: &[u8],
    expected_app_id: &AppId,
    key: &AttestedKey,
) -> Result<u32> {
    use p256::ecdsa::signature::Verifier;

    let v: ciborium::value::Value = ciborium::from_reader(assertion)
        .map_err(|e| AttestError::MalformedAttestation(format!("assertion cbor: {e}")))?;
    let signature = cbor_map_get(&v, "signature")
        .and_then(|s| s.as_bytes())
        .ok_or_else(|| AttestError::MalformedAttestation("no assertion signature".into()))?;
    let auth_data = cbor_map_get(&v, "authenticatorData")
        .and_then(|a| a.as_bytes())
        .ok_or_else(|| AttestError::MalformedAttestation("no authenticatorData".into()))?;

    // Signature is over SHA256(authenticatorData ‖ clientDataHash); verify()
    // applies the SHA-256 itself, so we pass the concatenation as the message.
    let client_data_hash = assertion_client_data_hash(nonce);
    let mut message = auth_data.clone();
    message.extend_from_slice(&client_data_hash);

    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.public_key_sec1)
        .map_err(|_| AttestError::AssertionSignatureInvalid)?;
    let sig = p256::ecdsa::Signature::from_der(signature)
        .map_err(|_| AttestError::AssertionSignatureInvalid)?;
    vk.verify(&message, &sig)
        .map_err(|_| AttestError::AssertionSignatureInvalid)?;

    let ad = parse_auth_data(auth_data, false)?;
    if ad.rp_id_hash != expected_app_id.0 {
        return Err(AttestError::AppIdMismatch);
    }
    if ad.counter <= key.last_counter {
        return Err(AttestError::CounterReplay);
    }
    Ok(ad.counter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn se_challenge_is_commitment_then_be_ts_then_nonce() {
        // Mirrors the device SDK's challenge-layout test: this byte order
        // is the wire contract — if it drifts, every SE signature fails to
        // verify.
        let c = se_challenge(&[0xAA, 0xBB], 0x0102_0304_0506_0708, &[0x11, 0x22]);
        assert_eq!(
            c,
            vec![0xAA, 0xBB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x22]
        );
    }

    #[test]
    fn assertion_hash_depends_only_on_nonce() {
        // Window-level: same nonce → same client-data hash regardless of which
        // proof in the window presents it.
        let n = [9u8; 32];
        assert_eq!(assertion_client_data_hash(&n), assertion_client_data_hash(&n));
        assert_ne!(assertion_client_data_hash(&n), assertion_client_data_hash(&[8u8; 32]));
    }

    #[test]
    fn app_id_matches_apple_app_id_string_hash() {
        // App ID hash = SHA256("<TeamID>.<BundleID>").
        let got = AppId::from_team_and_bundle("6ZH5F97PWU", "com.octetproof.tester");
        let want: [u8; 32] = Sha256::digest(b"6ZH5F97PWU.com.octetproof.tester").into();
        assert_eq!(got.0, want);
    }

    #[test]
    fn scan_finds_32_byte_octet_string() {
        // DER: SEQUENCE { [1] { OCTET STRING (32) } } around a known nonce.
        let nonce = [0xABu8; 32];
        let mut der = vec![0x30, 0x24, 0xA1, 0x22, 0x04, 0x20];
        der.extend_from_slice(&nonce);
        assert_eq!(scan_octet_string_32(&der), Some(nonce));
        // No 32-byte octet string present → None.
        assert_eq!(scan_octet_string_32(&[0x30, 0x03, 0x04, 0x01, 0x00]), None);
    }

    #[test]
    fn parse_auth_data_reads_fields() {
        let mut d = vec![0u8; 55];
        d[0..32].copy_from_slice(&[0x11; 32]); // rpIdHash
        d[33..37].copy_from_slice(&7u32.to_be_bytes()); // counter
        d[37..53].copy_from_slice(AAGUID_DEVELOPMENT); // aaguid
        d[53..55].copy_from_slice(&0u16.to_be_bytes()); // credIdLen = 0
        let ad = parse_auth_data(&d, true).unwrap();
        assert_eq!(ad.rp_id_hash, [0x11; 32]);
        assert_eq!(ad.counter, 7);
        assert_eq!(ad.aaguid, Some(*AAGUID_DEVELOPMENT));
    }

    #[test]
    fn accept_environment_policy() {
        let prod = AttestEnvironment::Production;
        let dev = AttestEnvironment::Development;
        assert!(AcceptEnvironment::Any.accepts(prod) && AcceptEnvironment::Any.accepts(dev));
        assert!(AcceptEnvironment::Production.accepts(prod));
        assert!(!AcceptEnvironment::Production.accepts(dev));
        assert!(AcceptEnvironment::Development.accepts(dev));
        assert!(!AcceptEnvironment::Development.accepts(prod));
    }

    // --- Assertion verification with a synthetic P-256 key ---
    //
    // The full attestation-object path (chain to Apple's root) needs a real
    // device-produced object and is exercised in Phase F. The assertion path
    // does not need a cert chain — only the cached public key — so it is fully
    // testable here against a key we generate.

    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn test_key() -> SigningKey {
        // Fixed non-zero scalar → deterministic test key.
        let scalar = [0x42u8; 32];
        SigningKey::from_slice(&scalar).expect("valid scalar")
    }

    fn attested_key(sk: &SigningKey) -> AttestedKey {
        AttestedKey {
            public_key_sec1: sk.verifying_key().to_sec1_bytes().to_vec(),
            last_counter: 0,
        }
    }

    fn assertion_auth_data(rp_id_hash: &[u8; 32], counter: u32) -> Vec<u8> {
        let mut d = Vec::with_capacity(37);
        d.extend_from_slice(rp_id_hash);
        d.push(0); // flags
        d.extend_from_slice(&counter.to_be_bytes());
        d
    }

    fn make_assertion(sk: &SigningKey, auth_data: &[u8], nonce: &[u8]) -> Vec<u8> {
        let mut message = auth_data.to_vec();
        message.extend_from_slice(&assertion_client_data_hash(nonce));
        let sig: Signature = sk.sign(&message);
        let value = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("signature".into()),
                ciborium::value::Value::Bytes(sig.to_der().as_bytes().to_vec()),
            ),
            (
                ciborium::value::Value::Text("authenticatorData".into()),
                ciborium::value::Value::Bytes(auth_data.to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).unwrap();
        out
    }

    #[test]
    fn assertion_round_trip_verifies_and_returns_counter() {
        let sk = test_key();
        let app_id = AppId::from_team_and_bundle("T", "b");
        let nonce = [9u8; 32];
        let ad = assertion_auth_data(&app_id.0, 5);
        let assertion = make_assertion(&sk, &ad, &nonce);

        let new_counter = verify_assertion(&assertion, &nonce, &app_id, &attested_key(&sk)).unwrap();
        assert_eq!(new_counter, 5);
    }

    #[test]
    fn assertion_rejects_non_advancing_counter() {
        let sk = test_key();
        let app_id = AppId::from_team_and_bundle("T", "b");
        let nonce = [9u8; 32];
        let ad = assertion_auth_data(&app_id.0, 5);
        let assertion = make_assertion(&sk, &ad, &nonce);
        let mut key = attested_key(&sk);
        key.last_counter = 5; // already seen 5 → replay
        assert_eq!(
            verify_assertion(&assertion, &nonce, &app_id, &key),
            Err(AttestError::CounterReplay)
        );
    }

    #[test]
    fn assertion_rejects_wrong_app_id() {
        let sk = test_key();
        let signed_for = AppId::from_team_and_bundle("T", "b");
        let expected = AppId::from_team_and_bundle("OTHER", "app");
        let nonce = [9u8; 32];
        let ad = assertion_auth_data(&signed_for.0, 5);
        let assertion = make_assertion(&sk, &ad, &nonce);
        // Signature verifies (over whatever authData was signed), but the
        // rpIdHash doesn't match the expected app → AppIdMismatch.
        assert_eq!(
            verify_assertion(&assertion, &nonce, &expected, &attested_key(&sk)),
            Err(AttestError::AppIdMismatch)
        );
    }

    #[test]
    fn assertion_rejects_tampered_signature() {
        let sk = test_key();
        let app_id = AppId::from_team_and_bundle("T", "b");
        let nonce = [9u8; 32];
        let ad = assertion_auth_data(&app_id.0, 5);
        // Verify against a DIFFERENT key → signature invalid.
        let other = SigningKey::from_slice(&[0x43u8; 32]).unwrap();
        let assertion = make_assertion(&sk, &ad, &nonce);
        assert_eq!(
            verify_assertion(&assertion, &nonce, &app_id, &attested_key(&other)),
            Err(AttestError::AssertionSignatureInvalid)
        );
    }

    // --- device-key signature (field 2) ---

    /// Sign field 2 the way the SDK does: ECDSA-P256-SHA256 over
    /// `DOMAIN ‖ SHA256(commitment ‖ ts ‖ nonce)`.
    fn sign_field2(sk: &SigningKey, commitment: &[u8], ts: i64, nonce: &[u8]) -> Vec<u8> {
        let mut msg = DEVICE_ATTESTATION_DOMAIN.to_vec();
        msg.extend_from_slice(&se_client_data_hash(commitment, ts, nonce));
        let sig: Signature = sk.sign(&msg);
        sig.to_der().as_bytes().to_vec()
    }

    #[test]
    fn device_signature_round_trips() {
        let sk = test_key();
        let pk = sk.verifying_key().to_sec1_bytes().to_vec();
        let (commitment, ts, nonce) = (vec![1u8, 2, 3], 1_780_000_000_000i64, [9u8; 32]);
        let sig = sign_field2(&sk, &commitment, ts, &nonce);
        assert!(verify_device_signature(&commitment, ts, &nonce, &pk, &sig).is_ok());
    }

    #[test]
    fn device_signature_rejects_tampered_timestamp() {
        // Editing the top-level timestamp_ms breaks field 2 — the device key
        // signed the original ts inside the challenge.
        let sk = test_key();
        let pk = sk.verifying_key().to_sec1_bytes().to_vec();
        let (commitment, nonce) = (vec![1u8, 2, 3], [9u8; 32]);
        let sig = sign_field2(&sk, &commitment, 1_780_000_000_000, &nonce);
        assert_eq!(
            verify_device_signature(&commitment, 1_780_000_000_001, &nonce, &pk, &sig),
            Err(AttestError::DeviceSignatureInvalid)
        );
    }

    #[test]
    fn device_signature_rejects_wrong_key() {
        let sk = test_key();
        let other = SigningKey::from_slice(&[0x43u8; 32]).unwrap();
        let pk = other.verifying_key().to_sec1_bytes().to_vec();
        let (commitment, ts, nonce) = (vec![1u8, 2, 3], 1_780_000_000_000i64, [9u8; 32]);
        let sig = sign_field2(&sk, &commitment, ts, &nonce);
        assert_eq!(
            verify_device_signature(&commitment, ts, &nonce, &pk, &sig),
            Err(AttestError::DeviceSignatureInvalid)
        );
    }

    #[test]
    fn device_signature_rejects_wrong_nonce() {
        let sk = test_key();
        let pk = sk.verifying_key().to_sec1_bytes().to_vec();
        let commitment = vec![1u8, 2, 3];
        let sig = sign_field2(&sk, &commitment, 1_780_000_000_000, &[9u8; 32]);
        assert_eq!(
            verify_device_signature(&commitment, 1_780_000_000_000, &[8u8; 32], &pk, &sig),
            Err(AttestError::DeviceSignatureInvalid)
        );
    }

    #[test]
    fn assertion_rejects_nonce_mismatch() {
        // A verifier reconstructing the wrong nonce (e.g. wrong window) gets a
        // different clientDataHash → signature fails.
        let sk = test_key();
        let app_id = AppId::from_team_and_bundle("T", "b");
        let ad = assertion_auth_data(&app_id.0, 5);
        let assertion = make_assertion(&sk, &ad, &[9u8; 32]);
        assert_eq!(
            verify_assertion(&assertion, &[8u8; 32], &app_id, &attested_key(&sk)),
            Err(AttestError::AssertionSignatureInvalid)
        );
    }
}
