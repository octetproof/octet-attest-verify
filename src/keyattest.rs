//! Offline Android hardware **key attestation** validation (feature `keyattest`).
//!
//! Android Keystore emits, at key-generation time, an X.509 certificate chain
//! whose leaf carries a Key Attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`)
//! and which chains leaf → intermediate(s) → a **Google hardware-attestation
//! root**. Validating that chain offline establishes that the device signing key
//! is genuine Secure-Element / TEE hardware — the Android counterpart of the
//! Apple App Attest layer in [`crate::appattest`].
//!
//! This module is self-contained and pulls the only RSA dependency in the crate,
//! so it sits behind the `keyattest` feature; the default App Attest build stays
//! lean. The two Google roots (the long-standing RSA-4096 root and the ECDSA
//! P-384 `Key Attestation CA1` root that became effective 2026-02-01) are baked
//! in and pinned by fingerprint, exactly as the Apple root is.
//!
//! The crate stays **fully offline** and does no network I/O. Revocation is still
//! honoured on the bootstrap path, but the crate does not fetch Google's status
//! list itself: the caller (which has network + a cache) fetches
//! `android.googleapis.com/attestkey/v1/status` and passes the revoked serials in
//! via [`AttestMode::Bootstrap`]; the crate extracts each chain cert's serial and
//! rejects a match. This keeps the verifier deterministic and testable, and leaves
//! the fetch / cache / fail-closed-on-fetch-failure policy with the caller.
//!
//! Two postures, selected by [`AttestMode`]: the **proof** path keeps a softer
//! posture (no verified-boot or revocation enforcement); the **bootstrap** path
//! (minting a licence) additionally requires verified boot + a locked bootloader
//! and consults the revocation list.

use crate::error::{AttestError, Result};
use sha2::{Digest, Sha256, Sha384};
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

/// The Android Key Attestation extension OID.
const KEY_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

/// Upper bound on the presented chain length. Real Android chains are at most
/// root + two intermediates + leaf (RKP adds one), so anything beyond this is
/// an attacker padding the input; cap the work before doing per-cert crypto.
const MAX_CHAIN_LEN: usize = 10;

// Signature-algorithm OIDs we accept up an Android attestation chain.
const RSA_SHA256_OID: &str = "1.2.840.113549.1.1.11";
const RSA_SHA384_OID: &str = "1.2.840.113549.1.1.12";
const ECDSA_SHA256_OID: &str = "1.2.840.10045.4.3.2";
const ECDSA_SHA384_OID: &str = "1.2.840.10045.4.3.3";

// Named-curve OIDs for an EC issuer key.
const P256_OID: &str = "1.2.840.10045.3.1.7";
const P384_OID: &str = "1.3.132.0.34";

/// Keymaster/KeyMint security level of the attested key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// `0` — key lives in software. Rejected: not hardware-backed.
    Software,
    /// `1` — Trusted Execution Environment.
    TrustedEnvironment,
    /// `2` — dedicated StrongBox secure element.
    StrongBox,
}

/// The result of a successful key-attestation validation.
#[derive(Debug, Clone)]
pub struct KeyAttestation {
    /// The leaf device key, SEC1-encoded (the P-256 key the proof's stage chain
    /// and field-2 signature are verified against).
    pub leaf_pubkey_sec1: Vec<u8>,
    /// The hardware security level the leaf attests to (TEE or StrongBox; a
    /// Software level is rejected before this is returned).
    pub security_level: SecurityLevel,
    /// The attestation schema version from the KeyDescription.
    pub attestation_version: i64,
    /// The attested app identity (package names + signing-cert SHA-256 digests)
    /// for the caller to compare against a registered `(package, cert_sha256)`
    /// pair — the **bootstrap identity-comparison contract**. `None` when the
    /// `attestationApplicationId` is absent or unparseable. See
    /// [`AttestedAppIdentity`].
    pub app_identity: Option<AttestedAppIdentity>,
    /// The device's verified-boot state + bootloader lock, when the RootOfTrust
    /// was present and parseable. On the bootstrap path this is enforced (see
    /// [`AttestMode`]); it is surfaced here for the proof path too, as
    /// information.
    pub root_of_trust: Option<RootOfTrust>,
}

/// Which verification posture to apply. The proof channel is softer; the
/// bootstrap channel (minting a licence) is strict.
pub enum AttestMode<'a> {
    /// Proof channel: chain + challenge + hardware security level only. Verified
    /// boot and revocation are **not** enforced (a proof from a rooted device is
    /// flagged downstream, not rejected here). The pre-existing behaviour.
    Proof,
    /// Bootstrap channel (first licence claim): everything the proof path checks,
    /// **plus** `verifiedBootState == Verified`, `deviceLocked == true`, and a
    /// revocation check against `revoked_serials`.
    Bootstrap {
        /// Certificate serial numbers the caller has determined are revoked, from
        /// Google's `attestkey/v1/status`. Raw big-endian INTEGER value bytes;
        /// leading zeroes are ignored on both sides when comparing. The crate does
        /// **not** fetch or cache — the caller owns the fetch, TTL cache, and the
        /// fail-closed-on-fetch-failure policy. Empty ⇒ nothing revoked.
        revoked_serials: &'a [Vec<u8>],
    },
}

/// The device's Android RootOfTrust: verified-boot state and bootloader lock.
/// Parsed from the KeyDescription `teeEnforced` authorization list
/// (`rootOfTrust [704]`) only — a copy in `softwareEnforced` is untrusted and
/// ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootOfTrust {
    /// `true` iff the bootloader is locked (`deviceLocked`).
    pub device_locked: bool,
    /// The verified-boot state.
    pub verified_boot_state: VerifiedBootState,
}

/// Android `verifiedBootState` — the boot chain's integrity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBootState {
    /// `0` — full chain of trust to a device-manufacturer root (green). The only
    /// state accepted on the bootstrap path.
    Verified,
    /// `1` — boot verified to a user-installed key (yellow).
    SelfSigned,
    /// `2` — verification disabled (orange).
    Unverified,
    /// `3` — dm-verity / boot verification failed (red).
    Failed,
}

/// The attested Android app identity, in the shape the backend compares against a
/// registered `(package_name, signing_cert_sha256)` pair: registered pair matches
/// iff `package_name ∈ package_names` **and** `signing_cert_sha256 ∈
/// cert_sha256_digests`.
///
/// Use this (returned on [`KeyAttestation`]) for the **bootstrap** identity
/// comparison. The softer proof-side path can instead pass an
/// [`ExpectedAppIdentity`] to [`verify_key_attestation`] and let the crate match.
///
/// Multiple entries are preserved verbatim (Android allows multiple declared
/// packages and rotated signing certs — do not collapse). `package_names` are
/// UTF-8 text; `cert_sha256_digests` are raw 32-byte digests — the caller
/// hex-encodes if it needs to, the crate does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedAppIdentity {
    /// The declared app package name(s), e.g. `["com.example.app"]`.
    pub package_names: Vec<String>,
    /// SHA-256 digest(s) of the app signing certificate(s), raw bytes.
    pub cert_sha256_digests: Vec<[u8; 32]>,
}

// --- Embedded Google hardware-attestation roots, pinned by fingerprint. ---

const ROOT_RSA_PEM: &str = include_str!("../roots/Google_Hardware_Attestation_Root_RSA.pem");
const ROOT_EC_PEM: &str = include_str!("../roots/Google_Hardware_Attestation_Root_EC.pem");

/// SHA-256 of the RSA-4096 root's DER (serial `F1C172A699EAF51D`).
pub const ROOT_RSA_SHA256: [u8; 32] = [
    0xce, 0xdb, 0x1c, 0xb6, 0xdc, 0x89, 0x6a, 0xe5, 0xec, 0x79, 0x73, 0x48, 0xbc, 0xe9, 0x28, 0x67,
    0x53, 0xc2, 0xb3, 0x8e, 0xe7, 0x1c, 0xe0, 0xfb, 0xe3, 0x4a, 0x9a, 0x12, 0x48, 0x80, 0x0d, 0xfc,
];

/// SHA-256 of the ECDSA P-384 `Key Attestation CA1` root's DER.
pub const ROOT_EC_SHA256: [u8; 32] = [
    0x6d, 0x9d, 0xb4, 0xce, 0x6c, 0x5c, 0x0b, 0x29, 0x31, 0x66, 0xd0, 0x89, 0x86, 0xe0, 0x57, 0x74,
    0xa8, 0x77, 0x6c, 0xeb, 0x52, 0x5d, 0x9e, 0x43, 0x29, 0x52, 0x0d, 0xe1, 0x2b, 0xa4, 0xbc, 0xc0,
];

/// Parse the embedded roots, each paired with its pinned fingerprint.
fn embedded_roots() -> Result<Vec<(Certificate, [u8; 32])>> {
    use x509_cert::der::DecodePem;
    let rsa = Certificate::from_pem(ROOT_RSA_PEM)
        .map_err(|e| AttestError::MalformedCertChain(format!("embedded RSA root: {e}")))?;
    let ec = Certificate::from_pem(ROOT_EC_PEM)
        .map_err(|e| AttestError::MalformedCertChain(format!("embedded EC root: {e}")))?;
    Ok(vec![(rsa, ROOT_RSA_SHA256), (ec, ROOT_EC_SHA256)])
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Verify an Android key-attestation certificate chain, fully offline.
///
/// `chain_der[0]` is the leaf (the device key); later entries are the
/// intermediate(s); the chain may or may not include the Google root itself.
/// `expected_challenge` is the value the SDK passed to `setAttestationChallenge`
/// at key generation (a known constant in the Octet flow). `now_unix_secs` is
/// the current time for validity-window checks.
///
/// On success the chain is signature-valid leaf → … → a pinned Google root, every
/// certificate is within its validity window, the leaf's attestation challenge
/// equals `expected_challenge`, and the attested security level is TEE or
/// StrongBox (a Software level is rejected).
///
/// `mode` selects the posture ([`AttestMode`]). [`AttestMode::Proof`] is the
/// pre-existing behaviour. [`AttestMode::Bootstrap`] additionally requires
/// `verifiedBootState == Verified`, `deviceLocked == true`, and that no cert in
/// the chain is in the supplied revoked-serials set — the stricter bar for
/// minting a licence.
///
/// The returned [`KeyAttestation`] carries the parsed [`AttestedAppIdentity`] and
/// [`RootOfTrust`] for the caller to inspect (e.g. the bootstrap identity
/// comparison), independent of the opt-in `expected_app` match.
pub fn verify_key_attestation(
    chain_der: &[Vec<u8>],
    expected_challenge: &[u8],
    now_unix_secs: u64,
    expected_app: Option<&ExpectedAppIdentity>,
    mode: AttestMode,
) -> Result<KeyAttestation> {
    if chain_der.is_empty() {
        return Err(AttestError::MalformedCertChain("empty certificate chain".into()));
    }
    if chain_der.len() > MAX_CHAIN_LEN {
        return Err(AttestError::KeyAttestChainTooLong);
    }
    let certs: Vec<Certificate> = chain_der
        .iter()
        .map(|d| {
            Certificate::from_der(d)
                .map_err(|e| AttestError::MalformedCertChain(format!("cert parse: {e}")))
        })
        .collect::<Result<_>>()?;

    // 1. Every certificate must be within its validity window right now.
    for c in &certs {
        check_validity(c, now_unix_secs)?;
    }

    // 2. Internal linkage. For each adjacent pair, `pair[1]` is the issuer of
    //    `pair[0]`. Two things must hold:
    //      a. NO issuer may carry the key-attestation extension — it belongs on
    //         the leaf (the target) alone;
    //      b. the issuer's key produced the subject's signature.
    //
    //    (a) is the chain-extension fix, and it is Google's own defence
    //    (`android/keyattestation` KeyAttestationCertPathValidator: the target
    //    must carry the attestation extension and any other cert carrying it is
    //    CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION). The attack: an
    //    attacker holds a real device's attested-key private half, signs a
    //    forged sub-cert with it, and presents `[forged, genuine_device_leaf,
    //    …]`. The verifier would read the attestation bytes from the
    //    attacker-authored `forged` at index 0 — but `genuine_device_leaf`, now
    //    an issuer, still carries its own attestation extension, which betrays
    //    the extension. We deliberately do NOT require issuers to be CAs: real
    //    devices ship non-CA `CA:FALSE` batch certificates (e.g. Sony Xperia 10
    //    III), and requiring CA:TRUE there rejects genuine hardware — which is
    //    exactly why Google's validator does not require it either.
    //
    //    The complementary half — the leaf (certs[0]) MUST carry the extension —
    //    is enforced by parse_key_description below, which errors if it is
    //    absent.
    for pair in certs.windows(2) {
        let subject = &pair[0];
        let issuer = &pair[1];
        if has_key_attestation_extension(issuer) {
            return Err(AttestError::KeyAttestChainExtension);
        }
        verify_signed_by(subject, issuer)?;
    }

    // 3. Anchor: the top of the supplied chain must be, or be signed by, a pinned
    //    Google root.
    anchor_to_google_root(certs.last().expect("non-empty"))?;

    // 4. Leaf: the attestation challenge and security level live in its extension.
    let leaf = &certs[0];
    let kd = parse_key_description(leaf)?;
    if kd.challenge != expected_challenge {
        return Err(AttestError::AttestChallengeMismatch);
    }
    // App-identity binding (opt-in). When an expected identity is supplied, the
    // attested `attestationApplicationId` must name that package and carry that
    // signing-cert digest; a missing/unparseable id fails closed. Omitted ⇒ the
    // hardware root is checked but the key is not bound to any app (prior behavior).
    if let Some(expected) = expected_app {
        match &kd.app_id {
            Some(app_id) if app_id.matches(expected) => {}
            _ => return Err(AttestError::AndroidAppIdentityMismatch),
        }
    }
    let security_level = match kd.security_level {
        1 => SecurityLevel::TrustedEnvironment,
        2 => SecurityLevel::StrongBox,
        _ => return Err(AttestError::InsecureSecurityLevel),
    };

    // 5. Bootstrap posture (licence mint): verified boot + locked bootloader +
    //    revocation. The proof path skips all of this by design.
    if let AttestMode::Bootstrap { revoked_serials } = mode {
        enforce_verified_boot(kd.root_of_trust)?;
        let chain_serials: Vec<&[u8]> = certs
            .iter()
            .map(|c| c.tbs_certificate.serial_number.as_bytes())
            .collect();
        if is_revoked(&chain_serials, revoked_serials) {
            return Err(AttestError::AttestationRevoked);
        }
    }

    // 6. The leaf's SEC1 P-256 device key — what proof signatures verify against.
    let leaf_pubkey_sec1 = leaf_sec1_p256(leaf)?;

    Ok(KeyAttestation {
        leaf_pubkey_sec1,
        security_level,
        attestation_version: kd.version,
        app_identity: kd.app_id.as_ref().map(AttestationApplicationId::to_public),
        root_of_trust: kd.root_of_trust,
    })
}

/// Bootstrap: require a parsed RootOfTrust in the `Verified` state with a locked
/// bootloader. Absent RootOfTrust ⇒ verified boot cannot be established ⇒ treated
/// as unverified (fail closed).
fn enforce_verified_boot(rot: Option<RootOfTrust>) -> Result<()> {
    match rot {
        None => Err(AttestError::AttestationUnverifiedBoot),
        Some(r) if r.verified_boot_state != VerifiedBootState::Verified => {
            Err(AttestError::AttestationUnverifiedBoot)
        }
        Some(r) if !r.device_locked => Err(AttestError::AttestationBootloaderUnlocked),
        Some(_) => Ok(()),
    }
}

/// True iff any serial in `chain_serials` is in `revoked_serials`. Compared on
/// leading-zero-stripped bytes so a caller's hex-decoded serial need not match
/// DER's positive-integer sign padding. Empty `revoked_serials` ⇒ never revoked.
fn is_revoked(chain_serials: &[&[u8]], revoked_serials: &[Vec<u8>]) -> bool {
    chain_serials.iter().any(|s| {
        let s = strip_leading_zeros(s);
        revoked_serials.iter().any(|r| strip_leading_zeros(r) == s)
    })
}

/// Leading-zero-stripped view, for comparing certificate serials without caring
/// about DER positive-integer sign padding vs. a caller's hex-decoded bytes.
fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

/// Confirm `now` is within `cert`'s `notBefore`..`notAfter`.
fn check_validity(cert: &Certificate, now_unix_secs: u64) -> Result<()> {
    let v = &cert.tbs_certificate.validity;
    let nb = v.not_before.to_unix_duration().as_secs();
    let na = v.not_after.to_unix_duration().as_secs();
    if now_unix_secs < nb || now_unix_secs > na {
        Err(AttestError::CertExpired)
    } else {
        Ok(())
    }
}

/// The top of the provided chain is trusted if it is itself a pinned root, or if
/// its signature verifies against a pinned root whose subject is its issuer.
/// Whether `cert` carries the Android key-attestation extension. Used to reject
/// any issuer that carries it: the extension belongs on the target leaf alone,
/// and its presence on a non-leaf cert is the chain-extension attack (see
/// the linkage loop). Not the same as parsing it — presence, not contents.
fn has_key_attestation_extension(cert: &Certificate) -> bool {
    cert.tbs_certificate
        .extensions
        .as_ref()
        .is_some_and(|exts| exts.iter().any(|e| e.extn_id.to_string() == KEY_ATTESTATION_OID))
}

fn anchor_to_google_root(top: &Certificate) -> Result<()> {
    let top_der = top
        .to_der()
        .map_err(|e| AttestError::MalformedCertChain(format!("top cert der: {e}")))?;
    let top_fp = sha256(&top_der);
    let roots = embedded_roots()?;

    // Case 1: the chain already ends at a pinned root.
    if roots.iter().any(|(_, fp)| *fp == top_fp) {
        return Ok(());
    }
    // Case 2: the top intermediate is signed by a pinned root.
    for (root, _) in &roots {
        if root.tbs_certificate.subject == top.tbs_certificate.issuer
            && verify_signed_by(top, root).is_ok()
        {
            return Ok(());
        }
    }
    Err(AttestError::KeyAttestNotAnchored)
}

/// Verify `subject`'s signature was produced by `issuer`'s public key. Dispatches
/// on the subject's `signatureAlgorithm` (RSA-PKCS#1 v1.5 or ECDSA, SHA-256/384)
/// and, for ECDSA, on the issuer key's named curve (P-256 or P-384).
fn verify_signed_by(subject: &Certificate, issuer: &Certificate) -> Result<()> {
    let tbs = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| AttestError::MalformedCertChain(format!("tbs der: {e}")))?;
    let sig = subject
        .signature
        .as_bytes()
        .ok_or_else(|| AttestError::MalformedCertChain("signature not octet-aligned".into()))?;
    let spki = &issuer.tbs_certificate.subject_public_key_info;
    let alg = subject.signature_algorithm.oid.to_string();
    match alg.as_str() {
        RSA_SHA256_OID => verify_rsa(spki, &tbs, sig, false),
        RSA_SHA384_OID => verify_rsa(spki, &tbs, sig, true),
        ECDSA_SHA256_OID => verify_ecdsa(spki, &tbs, sig, false),
        ECDSA_SHA384_OID => verify_ecdsa(spki, &tbs, sig, true),
        other => Err(AttestError::MalformedCertChain(format!(
            "unsupported chain signature algorithm {other}"
        ))),
    }
}

/// RSA PKCS#1 v1.5 verify over SHA-256/384, issuer key from its SPKI.
fn verify_rsa(spki: &SubjectPublicKeyInfoOwned, tbs: &[u8], sig: &[u8], sha384: bool) -> Result<()> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::{Pkcs1v15Sign, RsaPublicKey};
    let spki_der = spki
        .to_der()
        .map_err(|e| AttestError::MalformedCertChain(format!("issuer spki der: {e}")))?;
    let key = RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| AttestError::MalformedCertChain(format!("issuer RSA key: {e}")))?;
    let ok = if sha384 {
        key.verify(Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(tbs), sig)
    } else {
        key.verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(tbs), sig)
    };
    ok.map_err(|_| AttestError::KeyAttestNotAnchored)
}

/// ECDSA verify; the issuer key's curve is read from its SPKI named-curve
/// parameter, the digest from the subject's signature algorithm.
fn verify_ecdsa(
    spki: &SubjectPublicKeyInfoOwned,
    tbs: &[u8],
    sig_der: &[u8],
    sha384: bool,
) -> Result<()> {
    let sec1 = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| AttestError::MalformedCertChain("issuer SPKI not octet-aligned".into()))?;
    let curve = ec_curve_oid(spki)?;
    let prehash: Vec<u8> = if sha384 {
        Sha384::digest(tbs).to_vec()
    } else {
        Sha256::digest(tbs).to_vec()
    };
    match curve {
        EcCurve::P256 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
                .map_err(|e| AttestError::MalformedCertChain(format!("issuer P-256 key: {e}")))?;
            let sig = p256::ecdsa::Signature::from_der(sig_der)
                .map_err(|e| AttestError::MalformedCertChain(format!("ecdsa sig: {e}")))?;
            key.verify_prehash(&prehash, &sig)
                .map_err(|_| AttestError::KeyAttestNotAnchored)
        }
        EcCurve::P384 => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
                .map_err(|e| AttestError::MalformedCertChain(format!("issuer P-384 key: {e}")))?;
            let sig = p384::ecdsa::Signature::from_der(sig_der)
                .map_err(|e| AttestError::MalformedCertChain(format!("ecdsa sig: {e}")))?;
            key.verify_prehash(&prehash, &sig)
                .map_err(|_| AttestError::KeyAttestNotAnchored)
        }
    }
}

enum EcCurve {
    P256,
    P384,
}

/// Read the named-curve OID from an EC issuer's SPKI algorithm parameters.
fn ec_curve_oid(spki: &SubjectPublicKeyInfoOwned) -> Result<EcCurve> {
    use x509_cert::der::asn1::ObjectIdentifier;
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| AttestError::MalformedCertChain("EC issuer has no curve parameter".into()))?;
    let oid: ObjectIdentifier = params
        .decode_as()
        .map_err(|e| AttestError::MalformedCertChain(format!("EC curve oid: {e}")))?;
    match oid.to_string().as_str() {
        P256_OID => Ok(EcCurve::P256),
        P384_OID => Ok(EcCurve::P384),
        other => Err(AttestError::MalformedCertChain(format!("unsupported EC curve {other}"))),
    }
}

/// Extract and validate the leaf's SEC1 P-256 public key.
fn leaf_sec1_p256(leaf: &Certificate) -> Result<Vec<u8>> {
    let sec1 = leaf
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| AttestError::MalformedCertChain("leaf SPKI not octet-aligned".into()))?;
    p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1)
        .map_err(|e| AttestError::MalformedCertChain(format!("leaf P-256 key: {e}")))?;
    Ok(sec1.to_vec())
}

/// The KeyDescription fields we enforce, plus the best-effort app identity.
#[derive(Debug)]
struct KeyDescription {
    version: i64,
    security_level: u8,
    challenge: Vec<u8>,
    /// The `attestationApplicationId` from the `softwareEnforced` list, when it
    /// could be located and parsed. `None` when absent or unparseable — a caller
    /// that requires app binding treats `None` as a mismatch (fail closed).
    app_id: Option<AttestationApplicationId>,
    /// The `rootOfTrust [704]` from `teeEnforced` only, when present and
    /// parseable (a copy in `softwareEnforced` is untrusted and ignored).
    /// `None` when absent — the bootstrap path treats `None` as unverified boot
    /// (fail closed).
    root_of_trust: Option<RootOfTrust>,
}

/// The Android `attestationApplicationId`: which app(s) and signing cert(s) the
/// attested key was bound to at generation. Sets, because an app may declare
/// more than one package or rotate signing certs.
#[derive(Debug)]
struct AttestationApplicationId {
    package_names: Vec<Vec<u8>>,
    signature_digests: Vec<Vec<u8>>,
}

/// The expected Android app identity to bind a key-attestation to. Supply it to
/// [`verify_key_attestation`] to require that the attested `attestationApplicationId`
/// names this package and includes this signing-cert digest; omit it to check the
/// hardware root only (the pre-existing behavior).
#[derive(Debug, Clone)]
pub struct ExpectedAppIdentity {
    /// The app package name, e.g. `com.example.app`.
    pub package_name: String,
    /// SHA-256 of the app signing certificate's DER (an Android `signatureDigests` entry).
    pub signing_cert_sha256: [u8; 32],
}

impl AttestationApplicationId {
    /// Convert the raw parsed form into the caller-facing [`AttestedAppIdentity`]:
    /// package names as UTF-8 (lossy — Android names are UTF-8 by spec; a garbled
    /// name simply won't match a registered one), and only well-formed 32-byte
    /// SHA-256 digests (a non-32-byte entry can't be a signing-cert digest, so it
    /// is dropped rather than surfaced).
    fn to_public(&self) -> AttestedAppIdentity {
        AttestedAppIdentity {
            package_names: self
                .package_names
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect(),
            cert_sha256_digests: self
                .signature_digests
                .iter()
                .filter_map(|d| <[u8; 32]>::try_from(d.as_slice()).ok())
                .collect(),
        }
    }

    /// True iff this attestation names `expected.package_name` **and** carries
    /// `expected.signing_cert_sha256` among its signature digests. Both must hold.
    fn matches(&self, expected: &ExpectedAppIdentity) -> bool {
        let pkg_ok = self
            .package_names
            .iter()
            .any(|p| p.as_slice() == expected.package_name.as_bytes());
        let sig_ok = self
            .signature_digests
            .iter()
            .any(|d| d.as_slice() == expected.signing_cert_sha256);
        pkg_ok && sig_ok
    }
}

/// Parse the leaf's Key Attestation extension. The first five fields
/// (through `attestationChallenge`) are the security-relevant ones and are
/// parsed strictly; the `attestationApplicationId` inside `softwareEnforced` is
/// then extracted **best-effort** (see [`extract_app_id`]).
///
/// ```text
/// KeyDescription ::= SEQUENCE {
///     attestationVersion        INTEGER,
///     attestationSecurityLevel  ENUMERATED,   -- 0 sw / 1 TEE / 2 StrongBox
///     keymasterVersion          INTEGER,
///     keymasterSecurityLevel    ENUMERATED,
///     attestationChallenge      OCTET STRING,
///     uniqueId                  OCTET STRING,
///     softwareEnforced          AuthorizationList,  -- attestationApplicationId [709], rootOfTrust [704]
///     teeEnforced               AuthorizationList,  -- rootOfTrust [704] (usual home)
/// }
/// ```
fn parse_key_description(leaf: &Certificate) -> Result<KeyDescription> {
    let exts = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or_else(|| AttestError::MalformedCertChain("leaf has no extensions".into()))?;
    let ext = exts
        .iter()
        .find(|e| e.extn_id.to_string() == KEY_ATTESTATION_OID)
        .ok_or_else(|| AttestError::MalformedCertChain("no key-attestation extension".into()))?;
    parse_key_description_der(ext.extn_value.as_bytes())
}

/// Pure KeyDescription parse (unit-testable without a full certificate).
fn parse_key_description_der(der: &[u8]) -> Result<KeyDescription> {
    let bad = |w: &str| AttestError::MalformedCertChain(format!("KeyDescription {w}"));
    // Outer SEQUENCE.
    let (tag, seq, _) = der_tlv(der).ok_or_else(|| bad("not a TLV"))?;
    if tag != 0x30 {
        return Err(bad("outer not SEQUENCE"));
    }
    // attestationVersion INTEGER.
    let (t, v, rest) = der_tlv(seq).ok_or_else(|| bad("truncated at version"))?;
    if t != 0x02 {
        return Err(bad("version not INTEGER"));
    }
    let version = be_int(v);
    // attestationSecurityLevel ENUMERATED.
    let (t, v, rest) = der_tlv(rest).ok_or_else(|| bad("truncated at security level"))?;
    if t != 0x0a {
        return Err(bad("attSecurityLevel not ENUMERATED"));
    }
    let security_level = *v.last().unwrap_or(&0xff);
    // keymasterVersion INTEGER.
    let (t, _v, rest) = der_tlv(rest).ok_or_else(|| bad("truncated at km version"))?;
    if t != 0x02 {
        return Err(bad("kmVersion not INTEGER"));
    }
    // keymasterSecurityLevel ENUMERATED.
    let (t, _v, rest) = der_tlv(rest).ok_or_else(|| bad("truncated at km security level"))?;
    if t != 0x0a {
        return Err(bad("kmSecurityLevel not ENUMERATED"));
    }
    // attestationChallenge OCTET STRING.
    let (t, v, rest) = der_tlv(rest).ok_or_else(|| bad("truncated at challenge"))?;
    if t != 0x04 {
        return Err(bad("challenge not OCTET STRING"));
    }
    // attestationApplicationId lives deeper (softwareEnforced [709]); parse it
    // best-effort so a variant/absent encoding can never break the strict
    // challenge/security-level path above — a required-but-unparseable app id is
    // handled as a mismatch by the caller, not as a parse error here.
    let app_id = extract_app_id(rest);
    let root_of_trust = extract_root_of_trust(rest);
    Ok(KeyDescription { version, security_level, challenge: v.to_vec(), app_id, root_of_trust })
}

/// Best-effort walk from just-after-`attestationChallenge` to the `rootOfTrust`
/// (`[704]`) in `teeEnforced` **only**. `softwareEnforced` is walked past but its
/// rootOfTrust is never read: it is framework-populated, not TA-vouched, so
/// trusting it inverts the anti-root check. A rootOfTrust found solely in
/// `softwareEnforced` is thus reported as absent. `None` on any deviation — the
/// bootstrap caller treats `None` as unverified boot (fail closed).
///
/// ```text
/// AuthorizationList ::= SEQUENCE { ... rootOfTrust [704] EXPLICIT RootOfTrust OPTIONAL ... }
/// RootOfTrust ::= SEQUENCE {
///     verifiedBootKey    OCTET STRING,
///     deviceLocked       BOOLEAN,
///     verifiedBootState  ENUMERATED,  -- 0 Verified / 1 SelfSigned / 2 Unverified / 3 Failed
///     verifiedBootHash   OCTET STRING OPTIONAL,
/// }
/// ```
fn extract_root_of_trust(after_challenge: &[u8]) -> Option<RootOfTrust> {
    // uniqueId OCTET STRING.
    let (t, _unique, rest) = der_tlv(after_challenge)?;
    if t != 0x04 {
        return None;
    }
    // softwareEnforced AuthorizationList (SEQUENCE). Walk PAST it — never read a
    // rootOfTrust from here. softwareEnforced is populated by the Android
    // framework / keystore2, not vouched for by the KeyMint TA, so a rootOfTrust
    // in this list is attacker-influenceable on a rooted or custom-ROM device.
    // The old code returned this copy first when present, inverting the trust
    // order on the only anti-root check: a device whose genuine teeEnforced said
    // Unverified/unlocked could carry Verified+locked in softwareEnforced and
    // mint a licence (the second finding).
    let (t, _sw_enforced, rest) = der_tlv(rest)?;
    if t != 0x30 {
        return None;
    }
    // teeEnforced AuthorizationList (SEQUENCE) — the only trusted home for
    // rootOfTrust. A rootOfTrust present solely in softwareEnforced is therefore
    // reported as absent, so the bootstrap gate fails closed
    // (AttestationUnverifiedBoot) rather than trusting the untrusted copy.
    let (t, tee_enforced, _rest) = der_tlv(rest)?;
    if t != 0x30 {
        return None;
    }
    find_root_of_trust(tee_enforced)
}

/// Scan an AuthorizationList for `rootOfTrust [704]` (identifier octets
/// `0xBF 0x85 0x40`; EXPLICIT, so its content is the RootOfTrust SEQUENCE
/// directly) and parse it.
fn find_root_of_trust(authlist: &[u8]) -> Option<RootOfTrust> {
    const ROOT_OF_TRUST_TAG: &[u8] = &[0xBF, 0x85, 0x40];
    let mut cursor = authlist;
    while !cursor.is_empty() {
        let (tag, value, next) = der_tlv_hightag(cursor)?;
        if tag == ROOT_OF_TRUST_TAG {
            return parse_root_of_trust(value);
        }
        cursor = next;
    }
    None
}

/// Parse a `RootOfTrust` SEQUENCE: `verifiedBootKey` (skipped), `deviceLocked`,
/// `verifiedBootState`. A trailing `verifiedBootHash`, if present, is ignored.
fn parse_root_of_trust(der: &[u8]) -> Option<RootOfTrust> {
    let (tag, seq, _) = der_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    // verifiedBootKey OCTET STRING (skipped).
    let (t, _vbk, rest) = der_tlv(seq)?;
    if t != 0x04 {
        return None;
    }
    // deviceLocked BOOLEAN — any non-zero content octet is TRUE.
    let (t, locked, rest) = der_tlv(rest)?;
    if t != 0x01 {
        return None;
    }
    let device_locked = locked.iter().any(|&b| b != 0x00);
    // verifiedBootState ENUMERATED.
    let (t, state, _) = der_tlv(rest)?;
    if t != 0x0a {
        return None;
    }
    let verified_boot_state = match state.last().copied()? {
        0 => VerifiedBootState::Verified,
        1 => VerifiedBootState::SelfSigned,
        2 => VerifiedBootState::Unverified,
        3 => VerifiedBootState::Failed,
        _ => return None,
    };
    Some(RootOfTrust { device_locked, verified_boot_state })
}

/// Best-effort walk from just-after-`attestationChallenge` to the
/// `attestationApplicationId`: skip `uniqueId`, enter `softwareEnforced`, find the
/// context-tagged `[709]` field, and parse the `AttestationApplicationId` inside.
/// Any deviation returns `None` (the field is optional and non-security-critical
/// on its own; binding is enforced by the caller against `ExpectedAppIdentity`).
///
/// ```text
/// AuthorizationList ::= SEQUENCE { ... attestationApplicationId [709] EXPLICIT OCTET STRING OPTIONAL ... }
/// AttestationApplicationId ::= SEQUENCE {
///     packageInfos      SET OF SEQUENCE { packageName OCTET STRING, version INTEGER },
///     signatureDigests  SET OF OCTET STRING,
/// }
/// ```
fn extract_app_id(after_challenge: &[u8]) -> Option<AttestationApplicationId> {
    // uniqueId OCTET STRING.
    let (t, _unique, rest) = der_tlv(after_challenge)?;
    if t != 0x04 {
        return None;
    }
    // softwareEnforced AuthorizationList (SEQUENCE).
    let (t, sw_enforced, _rest) = der_tlv(rest)?;
    if t != 0x30 {
        return None;
    }
    // Find attestationApplicationId [709] EXPLICIT — context|constructed, high-tag
    // form: identifier octets 0xBF 0x85 0x45. Its content is an OCTET STRING whose
    // content is the DER-encoded AttestationApplicationId.
    const ATT_APP_ID_TAG: &[u8] = &[0xBF, 0x85, 0x45];
    let mut cursor = sw_enforced;
    let app_id_octets = loop {
        let (tag, value, next) = der_tlv_hightag(cursor)?;
        if tag == ATT_APP_ID_TAG {
            let (t, inner, _) = der_tlv(value)?; // the wrapped OCTET STRING
            if t != 0x04 {
                return None;
            }
            break inner;
        }
        cursor = next;
    };
    parse_attestation_application_id(app_id_octets)
}

/// Parse an `AttestationApplicationId` DER SEQUENCE into its package names and
/// signature digests.
fn parse_attestation_application_id(der: &[u8]) -> Option<AttestationApplicationId> {
    let (tag, seq, _) = der_tlv(der)?; // SEQUENCE
    if tag != 0x30 {
        return None;
    }
    // packageInfos SET OF SEQUENCE { packageName OCTET STRING, version INTEGER }.
    let (t, pkg_set, rest) = der_tlv(seq)?;
    if t != 0x31 {
        return None;
    }
    let mut package_names = Vec::new();
    let mut p = pkg_set;
    while !p.is_empty() {
        let (t, info, next) = der_tlv(p)?; // AttestationPackageInfo SEQUENCE
        if t != 0x30 {
            return None;
        }
        let (t, name, _) = der_tlv(info)?; // packageName OCTET STRING
        if t != 0x04 {
            return None;
        }
        package_names.push(name.to_vec());
        p = next;
    }
    // signatureDigests SET OF OCTET STRING.
    let (t, sig_set, _) = der_tlv(rest)?;
    if t != 0x31 {
        return None;
    }
    let mut signature_digests = Vec::new();
    let mut s = sig_set;
    while !s.is_empty() {
        let (t, dig, next) = der_tlv(s)?; // OCTET STRING
        if t != 0x04 {
            return None;
        }
        signature_digests.push(dig.to_vec());
        s = next;
    }
    Some(AttestationApplicationId { package_names, signature_digests })
}

/// Fold a DER INTEGER's content bytes (big-endian, non-negative in practice for a
/// schema version) into an i64. Saturates rather than panicking on overlong input.
fn be_int(bytes: &[u8]) -> i64 {
    let mut acc: i64 = 0;
    for &b in bytes.iter().take(8) {
        acc = (acc << 8) | i64::from(b);
    }
    acc
}

/// Minimal DER TLV split: returns `(tag, value, rest)` for the first TLV in `b`,
/// or `None` on truncation / an unsupported (indefinite or > 4-byte) length.
fn der_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let (len, hdr) = der_len(b.get(1..)?)?;
    let start = 1 + hdr;
    let end = start.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    Some((tag, &b[start..end], &b[end..]))
}

/// Like [`der_tlv`] but returns the full identifier octets, so a multi-byte
/// high-tag-number tag (e.g. the context tag `[709]` = `0xBF 0x85 0x45`) can be
/// matched. Returns `(tag_bytes, value, rest)`.
fn der_tlv_hightag(b: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let first = *b.first()?;
    // High-tag-number form: low 5 bits all set (0x1F); subsequent octets carry
    // the number, each with MSB=1 except the last.
    let tag_len = if first & 0x1f == 0x1f {
        let mut n = 1;
        loop {
            let byte = *b.get(n)?;
            n += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        n
    } else {
        1
    };
    let (len, hdr) = der_len(b.get(tag_len..)?)?;
    let start = tag_len + hdr;
    let end = start.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    Some((&b[..tag_len], &b[start..end], &b[end..]))
}

/// Decode a DER length, returning `(length, header_bytes_consumed)`.
fn der_len(b: &[u8]) -> Option<(usize, usize)> {
    let first = *b.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None; // indefinite form or a length we refuse to handle
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | (*b.get(1 + i)? as usize);
    }
    Some((len, 1 + n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_roots_match_pins_and_self_verify() {
        // If the roots/ PEM is corrupt or swapped, either the fingerprint pin or
        // the self-signature check fails — a trust-anchor change must be loud.
        let roots = embedded_roots().expect("roots parse");
        for (root, pin) in &roots {
            let der = root.to_der().unwrap();
            assert_eq!(sha256(&der), *pin, "root fingerprint drifted from its pin");
            // A self-signed root verifies under its own key; any transcription
            // error in the PEM breaks this.
            verify_signed_by(root, root).expect("root self-signature must verify");
            assert_eq!(
                root.tbs_certificate.subject, root.tbs_certificate.issuer,
                "root must be self-issued"
            );
        }
    }

    #[test]
    fn empty_chain_is_malformed() {
        let err = verify_key_attestation(&[], b"x", 1_700_000_000, None, AttestMode::Proof).unwrap_err();
        assert!(matches!(err, AttestError::MalformedCertChain(_)));
    }

    #[test]
    fn garbage_cert_is_malformed() {
        let err = verify_key_attestation(&[vec![0, 1, 2, 3]], b"x", 1_700_000_000, None, AttestMode::Proof)
            .unwrap_err();
        assert!(matches!(err, AttestError::MalformedCertChain(_)));
    }

    // --- KeyDescription parser ---

    /// Hand-built KeyDescription: version=4, attSecLevel=2 (StrongBox),
    /// kmVersion=300, kmSecLevel=2, challenge="abc".
    fn key_description_der(att_sec: u8, challenge: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
            let mut out = vec![tag, val.len() as u8];
            out.extend_from_slice(val);
            out
        }
        let mut body = Vec::new();
        body.extend(tlv(0x02, &[4])); // attestationVersion
        body.extend(tlv(0x0a, &[att_sec])); // attestationSecurityLevel
        body.extend(tlv(0x02, &[0x01, 0x2c])); // keymasterVersion = 300
        body.extend(tlv(0x0a, &[1])); // keymasterSecurityLevel
        body.extend(tlv(0x04, challenge)); // attestationChallenge
        tlv(0x30, &body)
    }

    #[test]
    fn parses_security_level_and_challenge() {
        let der = key_description_der(2, b"abc");
        let kd = parse_key_description_der(&der).unwrap();
        assert_eq!(kd.version, 4);
        assert_eq!(kd.security_level, 2);
        assert_eq!(kd.challenge, b"abc");
    }

    // --- attestationApplicationId ([709]) parsing + matching ---

    /// DER length (short + long form) for the builders below.
    fn der_encode_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            return vec![len as u8];
        }
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.insert(0, (n & 0xff) as u8);
            n >>= 8;
        }
        let mut out = vec![0x80 | bytes.len() as u8];
        out.extend(bytes);
        out
    }

    /// TLV with an arbitrary (possibly multi-byte) tag and correct DER length.
    fn der(tag: &[u8], val: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        out.extend(der_encode_len(val.len()));
        out.extend_from_slice(val);
        out
    }

    /// A full KeyDescription carrying `attestationApplicationId [709]` with one
    /// package + one signing-cert digest — exercises uniqueId + softwareEnforced.
    fn key_description_der_with_app_id(challenge: &[u8], package: &[u8], sig_digest: &[u8]) -> Vec<u8> {
        let pkg_info = der(&[0x30], &[der(&[0x04], package), der(&[0x02], &[1])].concat());
        let package_infos = der(&[0x31], &pkg_info); // SET OF AttestationPackageInfo
        let signature_digests = der(&[0x31], &der(&[0x04], sig_digest)); // SET OF OCTET STRING
        let att_app_id = der(&[0x30], &[package_infos, signature_digests].concat());
        // [709] EXPLICIT { OCTET STRING { att_app_id } }
        let tagged = der(&[0xBF, 0x85, 0x45], &der(&[0x04], &att_app_id));
        let software_enforced = der(&[0x30], &tagged);
        let tee_enforced = der(&[0x30], &[]);
        let body = [
            der(&[0x02], &[4]),          // attestationVersion
            der(&[0x0a], &[2]),          // attestationSecurityLevel = StrongBox
            der(&[0x02], &[0x01, 0x2c]), // keymasterVersion = 300
            der(&[0x0a], &[2]),          // keymasterSecurityLevel
            der(&[0x04], challenge),     // attestationChallenge
            der(&[0x04], &[]),           // uniqueId (empty)
            software_enforced,
            tee_enforced,
        ]
        .concat();
        der(&[0x30], &body)
    }

    #[test]
    fn parses_attestation_application_id() {
        let digest = [0x11u8; 32];
        let der_bytes = key_description_der_with_app_id(b"chal", b"com.octetproof.sample", &digest);
        let kd = parse_key_description_der(&der_bytes).unwrap();
        // Strict fields still parse alongside the deep app id.
        assert_eq!(kd.challenge, b"chal");
        assert_eq!(kd.security_level, 2);
        let app = kd.app_id.expect("app id parsed");
        assert_eq!(app.package_names, vec![b"com.octetproof.sample".to_vec()]);
        assert_eq!(app.signature_digests, vec![digest.to_vec()]);
    }

    #[test]
    fn app_identity_matches_requires_both_package_and_digest() {
        let digest = [0x11u8; 32];
        let der_bytes = key_description_der_with_app_id(b"chal", b"com.octetproof.sample", &digest);
        let app = parse_key_description_der(&der_bytes).unwrap().app_id.unwrap();

        assert!(app.matches(&ExpectedAppIdentity {
            package_name: "com.octetproof.sample".into(),
            signing_cert_sha256: digest,
        }));
        // Wrong package OR wrong digest → no match (both must hold).
        assert!(!app.matches(&ExpectedAppIdentity {
            package_name: "com.evil.app".into(),
            signing_cert_sha256: digest,
        }));
        assert!(!app.matches(&ExpectedAppIdentity {
            package_name: "com.octetproof.sample".into(),
            signing_cert_sha256: [0x22; 32],
        }));
    }

    #[test]
    fn app_id_absent_is_none_and_does_not_break_strict_parse() {
        // The minimal helper stops after the challenge (no authorization lists) →
        // best-effort extraction yields None, strict fields still parse.
        let kd = parse_key_description_der(&key_description_der(2, b"abc")).unwrap();
        assert!(kd.app_id.is_none());
        assert_eq!(kd.challenge, b"abc");
    }

    #[test]
    fn rejects_non_sequence() {
        let err = parse_key_description_der(&[0x04, 0x01, 0x00]).unwrap_err();
        assert!(matches!(err, AttestError::MalformedCertChain(_)));
    }

    #[test]
    fn der_len_rejects_indefinite_and_overlong() {
        assert!(der_len(&[0x80]).is_none()); // indefinite
        assert!(der_len(&[0x85, 1, 2, 3, 4, 5]).is_none()); // 5-byte length
        assert_eq!(der_len(&[0x02]), Some((2, 1))); // short form
        assert_eq!(der_len(&[0x82, 0x01, 0x00]), Some((256, 3))); // long form
    }

    // --- AttestedAppIdentity emission (the bootstrap identity contract) ---

    #[test]
    fn attested_app_identity_to_public_shapes_fields() {
        let digest = [0x11u8; 32];
        let der_bytes = key_description_der_with_app_id(b"chal", b"com.octetproof.sample", &digest);
        let public = parse_key_description_der(&der_bytes).unwrap().app_id.unwrap().to_public();
        assert_eq!(public.package_names, vec!["com.octetproof.sample".to_string()]);
        assert_eq!(public.cert_sha256_digests, vec![digest]);
    }

    #[test]
    fn to_public_drops_non_32_byte_digests() {
        // A digest that isn't 32 bytes can't be a SHA-256, so it's dropped rather
        // than surfaced as a malformed `[u8; 32]`.
        let app = AttestationApplicationId {
            package_names: vec![b"com.x".to_vec()],
            signature_digests: vec![vec![0x11; 32], vec![0x22; 20]],
        };
        assert_eq!(app.to_public().cert_sha256_digests, vec![[0x11u8; 32]]);
    }

    // --- RootOfTrust parsing + the bootstrap verified-boot gate ---

    /// A `RootOfTrust` SEQUENCE: verifiedBootKey (32 B), deviceLocked, verifiedBootState.
    fn root_of_trust_der(device_locked: bool, vb_state: u8) -> Vec<u8> {
        let vbk = der(&[0x04], &[0u8; 32]);
        let locked = der(&[0x01], &[if device_locked { 0xff } else { 0x00 }]);
        let state = der(&[0x0a], &[vb_state]);
        der(&[0x30], &[vbk, locked, state].concat())
    }

    /// A full KeyDescription carrying `rootOfTrust [704]` in `teeEnforced`.
    fn key_description_der_with_root_of_trust(challenge: &[u8], device_locked: bool, vb_state: u8) -> Vec<u8> {
        // [704] EXPLICIT ⇒ its content is the RootOfTrust SEQUENCE directly.
        let rot_tagged = der(&[0xBF, 0x85, 0x40], &root_of_trust_der(device_locked, vb_state));
        let software_enforced = der(&[0x30], &[]);
        let tee_enforced = der(&[0x30], &rot_tagged);
        let body = [
            der(&[0x02], &[4]),
            der(&[0x0a], &[2]),
            der(&[0x02], &[0x01, 0x2c]),
            der(&[0x0a], &[2]),
            der(&[0x04], challenge),
            der(&[0x04], &[]), // uniqueId
            software_enforced,
            tee_enforced,
        ]
        .concat();
        der(&[0x30], &body)
    }

    #[test]
    fn parses_root_of_trust_from_tee_enforced() {
        let kd = parse_key_description_der(&key_description_der_with_root_of_trust(b"chal", true, 0)).unwrap();
        let rot = kd.root_of_trust.expect("root of trust parsed");
        assert!(rot.device_locked);
        assert_eq!(rot.verified_boot_state, VerifiedBootState::Verified);
        // Strict fields still parse alongside the deep RootOfTrust.
        assert_eq!(kd.challenge, b"chal");
    }

    #[test]
    fn parses_all_verified_boot_states() {
        for (raw, want) in [
            (0u8, VerifiedBootState::Verified),
            (1, VerifiedBootState::SelfSigned),
            (2, VerifiedBootState::Unverified),
            (3, VerifiedBootState::Failed),
        ] {
            let kd = parse_key_description_der(&key_description_der_with_root_of_trust(b"c", false, raw)).unwrap();
            let rot = kd.root_of_trust.unwrap();
            assert_eq!(rot.verified_boot_state, want);
            assert!(!rot.device_locked);
        }
    }

    #[test]
    fn root_of_trust_absent_is_none() {
        // The app-id fixture has an empty teeEnforced and no [704].
        let kd = parse_key_description_der(&key_description_der_with_app_id(b"c", b"com.x", &[0u8; 32])).unwrap();
        assert!(kd.root_of_trust.is_none());
    }

    /// A KeyDescription with `rootOfTrust` placed independently in
    /// `softwareEnforced` and/or `teeEnforced` — for the trust-order tests
    /// (the second finding). Each `Some((device_locked, vb_state))` emits a
    /// `[704]` into that list; `None` leaves the list empty.
    fn key_description_der_split_rot(
        challenge: &[u8],
        software: Option<(bool, u8)>,
        tee: Option<(bool, u8)>,
    ) -> Vec<u8> {
        let list = |rot: Option<(bool, u8)>| match rot {
            Some((locked, state)) => {
                der(&[0x30], &der(&[0xBF, 0x85, 0x40], &root_of_trust_der(locked, state)))
            }
            None => der(&[0x30], &[]),
        };
        let body = [
            der(&[0x02], &[4]),
            der(&[0x0a], &[2]),
            der(&[0x02], &[0x01, 0x2c]),
            der(&[0x0a], &[2]),
            der(&[0x04], challenge),
            der(&[0x04], &[]), // uniqueId
            list(software),
            list(tee),
        ]
        .concat();
        der(&[0x30], &body)
    }

    #[test]
    fn root_of_trust_only_in_software_enforced_is_ignored() {
        // A rooted / custom-ROM device can populate the framework-controlled
        // softwareEnforced list with Verified+locked while its genuine
        // teeEnforced carries no rootOfTrust. That copy must NOT be trusted:
        // extract reports absent, so the bootstrap gate fails closed. This is
        // the fix for the second finding — before it, this device minted a
        // licence.
        let kd = parse_key_description_der(&key_description_der_split_rot(
            b"chal",
            Some((true, 0)), // softwareEnforced: Verified + locked (the lie)
            None,            // teeEnforced: no rootOfTrust
        ))
        .unwrap();
        assert!(kd.root_of_trust.is_none(), "softwareEnforced rootOfTrust must be ignored");
        assert_eq!(
            enforce_verified_boot(kd.root_of_trust).unwrap_err(),
            AttestError::AttestationUnverifiedBoot,
        );
    }

    #[test]
    fn tee_enforced_root_of_trust_wins_over_software_enforced() {
        // Both lists carry a rootOfTrust and they disagree: softwareEnforced
        // claims Verified+locked, the TA-vouched teeEnforced says
        // Unverified+unlocked. The teeEnforced copy must be the one returned, so
        // the gate rejects — the softwareEnforced value can never override the
        // hardware truth. Pinning the tee state (not just "some error") is what
        // catches a regression back to reading softwareEnforced first.
        let kd = parse_key_description_der(&key_description_der_split_rot(
            b"chal",
            Some((true, 0)),  // softwareEnforced: Verified + locked
            Some((false, 2)), // teeEnforced: Unverified + unlocked (the truth)
        ))
        .unwrap();
        let rot = kd.root_of_trust.expect("teeEnforced rootOfTrust parsed");
        assert_eq!(rot.verified_boot_state, VerifiedBootState::Unverified);
        assert!(!rot.device_locked);
        assert_eq!(
            enforce_verified_boot(kd.root_of_trust).unwrap_err(),
            AttestError::AttestationUnverifiedBoot,
        );
    }

    #[test]
    fn bootstrap_verified_boot_gate() {
        let rot = |locked, s| Some(RootOfTrust { device_locked: locked, verified_boot_state: s });
        // Verified + locked passes.
        assert!(enforce_verified_boot(rot(true, VerifiedBootState::Verified)).is_ok());
        // Any non-Verified state → unverified-boot.
        for s in [VerifiedBootState::SelfSigned, VerifiedBootState::Unverified, VerifiedBootState::Failed] {
            assert_eq!(enforce_verified_boot(rot(true, s)).unwrap_err(), AttestError::AttestationUnverifiedBoot);
        }
        // Verified but unlocked → bootloader-unlocked.
        assert_eq!(
            enforce_verified_boot(rot(false, VerifiedBootState::Verified)).unwrap_err(),
            AttestError::AttestationBootloaderUnlocked
        );
        // Absent RootOfTrust → fail closed as unverified.
        assert_eq!(enforce_verified_boot(None).unwrap_err(), AttestError::AttestationUnverifiedBoot);
    }

    // --- revocation matching (leading-zero-insensitive) ---

    #[test]
    fn revocation_matching() {
        let chain: &[&[u8]] = &[&[0x01, 0x02, 0x03], &[0xAA]];
        assert!(!is_revoked(chain, &[])); // empty set → never revoked
        assert!(!is_revoked(chain, &[vec![0x09, 0x09]])); // un-revoked
        assert!(is_revoked(chain, &[vec![0x01, 0x02, 0x03]])); // exact match
        // Leading zeros ignored on either side.
        assert!(is_revoked(chain, &[vec![0x00, 0x00, 0xAA]]));
        assert!(is_revoked(&[&[0x00, 0xAA]], &[vec![0xAA]]));
    }
}
