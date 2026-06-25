//! Typed verification errors.
//!
//! Every failure mode is its own variant so a verifier can record *why* a
//! verdict was not `Verified` rather than collapsing everything to a boolean.

use thiserror::Error;

/// Why an attestation check did not pass.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AttestError {
    /// The CBOR attestation object could not be parsed.
    #[error("malformed attestation object: {0}")]
    MalformedAttestation(String),

    /// The X.509 certificate chain could not be parsed.
    #[error("malformed certificate chain: {0}")]
    MalformedCertChain(String),

    /// The certificate chain did not validate to the expected Apple App Attest
    /// root.
    #[error("certificate chain does not anchor to the Apple App Attest root")]
    ChainNotAnchored,

    /// The `appId` (SHA256(teamID ‖ bundleID)) baked into the attestation did
    /// not match the expected identity.
    #[error("app identity mismatch")]
    AppIdMismatch,

    /// The nonce committed in the attestation / assertion did not match the
    /// challenge reconstructed from the proof.
    #[error("challenge/nonce mismatch")]
    NonceMismatch,

    /// The assertion signature did not verify against the attested public key.
    #[error("assertion signature invalid")]
    AssertionSignatureInvalid,

    /// The per-proof device-key signature (DeviceAttestation.signature, field 2)
    /// did not verify against the device public key.
    #[error("device-key signature invalid")]
    DeviceSignatureInvalid,

    /// The assertion counter did not advance (replay / rollback).
    #[error("assertion counter did not advance (replay)")]
    CounterReplay,

    /// `SHA256(public key)` did not match the expected `key_id`.
    #[error("key_id does not match the attested public key")]
    KeyIdMismatch,

    /// The attestation's environment (development/production) is not accepted by
    /// policy.
    #[error("attestation environment not accepted by policy")]
    WrongEnvironment,

    /// An assertion was presented for a `key_id` whose attestation has not been
    /// seen, so there is no public key to verify it against.
    #[error("no attested public key cached for key_id")]
    UnknownKey,

    /// A certificate in an Android key-attestation chain is outside its
    /// `notBefore`..`notAfter` validity window at the verification time.
    #[error("certificate is expired or not yet valid")]
    CertExpired,

    /// An Android key-attestation chain did not validate to a pinned Google
    /// hardware-attestation root.
    #[error("certificate chain does not anchor to a Google hardware-attestation root")]
    KeyAttestNotAnchored,

    /// The Android attestation challenge in the leaf did not match the expected
    /// key-generation challenge.
    #[error("attestation challenge mismatch")]
    AttestChallengeMismatch,

    /// The attested key is software-backed (security level 0), not TEE/StrongBox.
    #[error("attested key is not hardware-backed (TEE/StrongBox)")]
    InsecureSecurityLevel,
}

/// Result of any attestation verification step.
pub type Result<T> = core::result::Result<T, AttestError>;
