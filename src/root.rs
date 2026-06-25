//! The Apple App Attestation Root CA — the offline trust anchor.
//!
//! The root is **public** (published by Apple) and baked into the crate, so the
//! App Attest layer needs no network and no configuration to establish trust.
//! Its DER fingerprint is pinned in code: if the embedded PEM is ever swapped,
//! [`verify_pin`] (and the test below) fail loudly rather than letting the trust
//! anchor shift silently.

use sha2::{Digest, Sha256};
use x509_cert::der::{DecodePem, Encode};
use x509_cert::Certificate;

/// PEM of the Apple App Attestation Root CA, fetched from
/// <https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem>.
const ROOT_PEM: &str = include_str!("../roots/Apple_App_Attestation_Root_CA.pem");

/// SHA-256 of the embedded root's DER encoding (its certificate fingerprint).
/// Pinned to detect a tampered or swapped root file.
pub const ROOT_SHA256: [u8; 32] = [
    0x1c, 0xb9, 0x82, 0x3b, 0xa2, 0x8b, 0xa6, 0xad, 0x2d, 0x33, 0xa0, 0x06, 0x94, 0x1d, 0xe2, 0xae,
    0x4f, 0x51, 0x3e, 0xf1, 0xd4, 0xe8, 0x31, 0xb9, 0xf7, 0xe0, 0xfa, 0x7b, 0x62, 0x42, 0xc9, 0x32,
];

/// Parse the embedded root certificate. Infallible in practice (the PEM is a
/// compile-time constant); panics only if the baked-in file is not valid PEM,
/// which a build could never have shipped past the test below.
pub fn root() -> Certificate {
    Certificate::from_pem(ROOT_PEM).expect("embedded Apple App Attestation root must be valid PEM")
}

/// Confirm the embedded root matches the pinned fingerprint. Called once before
/// the root is used as a trust anchor.
pub fn verify_pin() -> crate::Result<()> {
    let der = root()
        .to_der()
        .map_err(|e| crate::AttestError::MalformedCertChain(format!("root DER: {e}")))?;
    let fp: [u8; 32] = Sha256::digest(&der).into();
    if fp == ROOT_SHA256 {
        Ok(())
    } else {
        Err(crate::AttestError::ChainNotAnchored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_root_matches_pinned_fingerprint() {
        // If this fails, the roots/ PEM was changed without updating the pin —
        // a trust-anchor change must be deliberate and reviewed.
        verify_pin().expect("embedded root fingerprint must match the pin");
    }

    #[test]
    fn embedded_root_is_self_signed_apple_ca() {
        let c = root();
        // Self-issued root: subject == issuer.
        assert_eq!(c.tbs_certificate.subject, c.tbs_certificate.issuer);
        assert!(
            format!("{}", c.tbs_certificate.subject).contains("Apple App Attestation Root CA"),
            "unexpected root subject: {}",
            c.tbs_certificate.subject
        );
    }
}
