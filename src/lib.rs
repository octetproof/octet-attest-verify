//! # octet-attest-verify
//!
//! Offline verification of the mobile device-attestation evidence that an
//! Octet `LocationProof` carries in its `DeviceAttestation` message.
//!
//! Two independent layers:
//!
//! * [`appattest`] — **Apple App Attest**, fully offline. Given the attestation
//!   object + assertion a proof carries (fields 8/9 of `DeviceAttestation`), the
//!   nonce (field 10), and the proof's own commitment + timestamp, it validates
//!   the certificate chain to Apple's static App Attest root, binds the evidence
//!   to the expected app identity, and checks the per-proof challenge. No
//!   network, no secrets — the trust anchor is a public Apple root baked into
//!   the crate.
//!
//! * [`playintegrity`] (feature `playintegrity`) — a **Google Play Integrity**
//!   decode helper. Unlike App Attest, Play Integrity tokens cannot be verified
//!   offline: decoding is bound to a Google Play Console project. This layer is
//!   for an integrator wiring their own Cloud project (or Octet's demo verifier
//!   wiring Octet's), and is gated behind a cargo feature so the audited
//!   offline core stays dependency-light.
//!
//! This crate is **proof-format agnostic**: it operates on the already-extracted
//! attestation bytes and parameters, so the caller (e.g. `octet-verify`) owns
//! the protobuf decoding and passes the fields in. That keeps the trust-bearing
//! crypto here free of any wire-format coupling.
//!
//! ## Wire contract
//!
//! The exact byte layouts this verifier reconstructs are specified, language-
//! agnostically, in `spec/attestation-verification.md`. They must match what the
//! SDK emits; the spec is the single source of truth for both sides.

#![forbid(unsafe_code)]

pub mod appattest;
pub mod error;
pub mod root;

#[cfg(feature = "config")]
pub mod config;

#[cfg(feature = "playintegrity")]
pub mod playintegrity;

pub use error::{AttestError, Result};
