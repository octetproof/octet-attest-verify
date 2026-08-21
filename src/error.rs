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

    /// The Android key-attestation `attestationApplicationId` (package name +
    /// signing-cert digest) did not match the expected app identity — or an
    /// expected identity was required but the attestation carried none.
    #[error("android app identity mismatch")]
    AndroidAppIdentityMismatch,

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

    /// A certificate OTHER than the leaf carries the Android key-attestation
    /// extension. This is the chain-extension fix, and it mirrors Google's own
    /// "chain-extension attack prevention"
    /// (`android/keyattestation` → `CHAIN_EXTENDED_WITH_FAKE_ATTESTATION_EXTENSION`).
    ///
    /// The attack: an attacker holds a real device's attested-key private half,
    /// so they can sign a forged sub-certificate with it and present
    /// `[forged_leaf, genuine_device_leaf, …google]`. The verifier would read
    /// the attestation bytes from the attacker-authored `forged_leaf`. What
    /// gives the attack away is that `genuine_device_leaf`, now sitting as an
    /// issuer, still carries its OWN attestation extension — the extension may
    /// appear only on the target leaf. We do NOT require issuers to be CAs:
    /// real devices ship non-CA batch certificates, and requiring `CA:TRUE`
    /// there rejects genuine hardware (which is why Google does not do it).
    #[error("a non-leaf certificate carries the attestation extension (chain-extension attack)")]
    KeyAttestChainExtension,

    /// The presented chain has more certificates than the accepted maximum. A
    /// bound on work done on attacker-supplied input.
    #[error("certificate chain exceeds the maximum length")]
    KeyAttestChainTooLong,

    /// The Android attestation challenge in the leaf did not match the expected
    /// key-generation challenge.
    #[error("attestation challenge mismatch")]
    AttestChallengeMismatch,

    /// The attested key is software-backed (security level 0), not TEE/StrongBox.
    #[error("attested key is not hardware-backed (TEE/StrongBox)")]
    InsecureSecurityLevel,

    /// Bootstrap only: the device's `verifiedBootState` is not `Verified` (or the
    /// RootOfTrust was absent/unparseable, so verified boot could not be
    /// established). A rooted / custom-ROM device must not mint a licence.
    #[error("verified-boot state is not VERIFIED (bootstrap)")]
    AttestationUnverifiedBoot,

    /// Bootstrap only: the device bootloader is unlocked (`deviceLocked == false`).
    #[error("device bootloader is unlocked (bootstrap)")]
    AttestationBootloaderUnlocked,

    /// Bootstrap only: a certificate in the attestation chain is on the caller-
    /// supplied revocation list (Google `attestkey/v1/status`).
    #[error("attestation key is revoked (bootstrap)")]
    AttestationRevoked,
}

/// Result of any attestation verification step.
pub type Result<T> = core::result::Result<T, AttestError>;
