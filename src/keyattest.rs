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
//! What it does **not** do: online revocation. Google publishes a certificate
//! status list (`android.googleapis.com/attestation/status`); a fully-offline
//! verifier cannot consult it, so a key revoked after issuance is not detected
//! here. Callers that need revocation must layer it on with network access.

use crate::error::{AttestError, Result};
use sha2::{Digest, Sha256, Sha384};
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

/// The Android Key Attestation extension OID.
const KEY_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

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
pub fn verify_key_attestation(
    chain_der: &[Vec<u8>],
    expected_challenge: &[u8],
    now_unix_secs: u64,
) -> Result<KeyAttestation> {
    if chain_der.is_empty() {
        return Err(AttestError::MalformedCertChain("empty certificate chain".into()));
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

    // 2. Internal linkage: each cert is signed by the next one up.
    for pair in certs.windows(2) {
        verify_signed_by(&pair[0], &pair[1])?;
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
    let security_level = match kd.security_level {
        1 => SecurityLevel::TrustedEnvironment,
        2 => SecurityLevel::StrongBox,
        _ => return Err(AttestError::InsecureSecurityLevel),
    };

    // 5. The leaf's SEC1 P-256 device key — what proof signatures verify against.
    let leaf_pubkey_sec1 = leaf_sec1_p256(leaf)?;

    Ok(KeyAttestation { leaf_pubkey_sec1, security_level, attestation_version: kd.version })
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

/// The KeyDescription fields we enforce.
#[derive(Debug)]
struct KeyDescription {
    version: i64,
    security_level: u8,
    challenge: Vec<u8>,
}

/// Parse the leaf's Key Attestation extension into the first five KeyDescription
/// fields. Only those are security-relevant here; the rest of the SEQUENCE
/// (authorization lists) is intentionally not walked.
///
/// ```text
/// KeyDescription ::= SEQUENCE {
///     attestationVersion        INTEGER,
///     attestationSecurityLevel  ENUMERATED,   -- 0 sw / 1 TEE / 2 StrongBox
///     keymasterVersion          INTEGER,
///     keymasterSecurityLevel    ENUMERATED,
///     attestationChallenge      OCTET STRING,
///     ...                                      -- not parsed
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
    let (t, v, _rest) = der_tlv(rest).ok_or_else(|| bad("truncated at challenge"))?;
    if t != 0x04 {
        return Err(bad("challenge not OCTET STRING"));
    }
    Ok(KeyDescription { version, security_level, challenge: v.to_vec() })
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
        let err = verify_key_attestation(&[], b"x", 1_700_000_000).unwrap_err();
        assert!(matches!(err, AttestError::MalformedCertChain(_)));
    }

    #[test]
    fn garbage_cert_is_malformed() {
        let err = verify_key_attestation(&[vec![0, 1, 2, 3]], b"x", 1_700_000_000).unwrap_err();
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
}
