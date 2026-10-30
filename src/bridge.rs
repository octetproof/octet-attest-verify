//! The native WebView bridge signature (`OctetWebBridge` v1).
//!
//! In a partner app that ships the Octet SDK, the bridge signs a web page's
//! report with the device key: the Secure Enclave key on iOS (bound to App Attest
//! with [`crate::appattest::se_binding_client_data_hash`]), or the attested
//! Keystore key on Android (the leaf of a [`crate::keyattest`] chain). This module
//! rebuilds the signed bytes and checks the signature. The layout is specified in
//! `spec/attestation-verification.md`.

use crate::error::{AttestError, Result};
use sha2::{Digest, Sha256};

/// Domain-separation prefix of the bridge preimage.
pub const BRIDGE_DOMAIN: &[u8] = b"octet-browser-bridge-v1";

/// The bytes the bridge signs:
/// `utf8("octet-browser-bridge-v1") ‖ SHA256(utf8(s0)) ‖ d ‖ be64(t) ‖ SHA256(k)`.
///
/// `s0` is the challenge token as given to the collector, `d` the SHA-256 of the
/// signed bundle, `t` the signing time in milliseconds since the Unix epoch, and
/// `k` the page's public key (a raw uncompressed P-256 point).
pub fn bridge_preimage(s0: &str, d: &[u8; 32], t: u64, k: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(BRIDGE_DOMAIN.len() + 32 + 32 + 8 + 32);
    out.extend_from_slice(BRIDGE_DOMAIN);
    out.extend_from_slice(&Sha256::digest(s0.as_bytes()));
    out.extend_from_slice(d);
    out.extend_from_slice(&t.to_be_bytes());
    out.extend_from_slice(&Sha256::digest(k));
    out
}

/// Verify a bridge signature: ECDSA P-256 with SHA-256 over
/// [`bridge_preimage`], DER-encoded (X9.62), under `device_public_key_sec1` (the
/// iOS Secure Enclave key, or the Android attested leaf key). A high-S signature
/// is accepted (normalised to low-S, an equally valid signature for the same
/// message), since neither platform's keystore promises low-S. Fails with
/// [`AttestError::DeviceSignatureInvalid`].
pub fn verify_bridge_signature(
    device_public_key_sec1: &[u8],
    s0: &str,
    d: &[u8; 32],
    t: u64,
    k: &[u8],
    der_signature: &[u8],
) -> Result<()> {
    use p256::ecdsa::signature::Verifier;

    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(device_public_key_sec1)
        .map_err(|_| AttestError::DeviceSignatureInvalid)?;
    let parsed = p256::ecdsa::Signature::from_der(der_signature)
        .map_err(|_| AttestError::DeviceSignatureInvalid)?;
    let sig = parsed.normalize_s().unwrap_or(parsed);
    vk.verify(&bridge_preimage(s0, d, t, k), &sig)
        .map_err(|_| AttestError::DeviceSignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_slice(&[0x42u8; 32]).unwrap()
    }

    #[test]
    fn preimage_layout() {
        let p = bridge_preimage("s", &[7u8; 32], 0x0102_0304_0506_0708, &[4u8; 65]);
        assert_eq!(p.len(), 23 + 32 + 32 + 8 + 32);
        assert_eq!(&p[..23], BRIDGE_DOMAIN);
        assert_eq!(&p[23..55], &Sha256::digest(b"s")[..]);
        assert_eq!(&p[55..87], &[7u8; 32]);
        assert_eq!(&p[87..95], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&p[95..], &Sha256::digest([4u8; 65])[..]);
    }

    #[test]
    fn signature_round_trips_and_binds_every_field() {
        let sk = key();
        let pubkey = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let (s0, d, t, k) = ("token", [9u8; 32], 1_761_000_000_000u64, [4u8; 65]);
        let sig: Signature = sk.sign(&bridge_preimage(s0, &d, t, &k));
        let der = sig.to_der().as_bytes().to_vec();
        assert!(verify_bridge_signature(&pubkey, s0, &d, t, &k, &der).is_ok());
        assert!(verify_bridge_signature(&pubkey, "other", &d, t, &k, &der).is_err());
        assert!(verify_bridge_signature(&pubkey, s0, &[8u8; 32], t, &k, &der).is_err());
        assert!(verify_bridge_signature(&pubkey, s0, &d, t + 1, &k, &der).is_err());
        assert!(verify_bridge_signature(&pubkey, s0, &d, t, &[5u8; 65], &der).is_err());
        // Raw r‖s is not DER and is refused.
        assert!(verify_bridge_signature(&pubkey, s0, &d, t, &k, &sig.to_bytes()).is_err());
    }
}
