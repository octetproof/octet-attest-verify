# Changelog

All notable changes to `octet-attest-verify` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/); this project uses
date-stamped pre-release versions until the first stable cut.

## [Unreleased]

### Added
- Initial crate scaffold: offline Apple App Attest verification layer (default)
  and a feature-gated Google Play Integrity decode helper (`playintegrity`).
- App Attest verification vocabulary: expected app identity (`AppId`), proof
  evidence (`AppAttestEvidence`), cached attested key, and verdict types.
- Pure challenge-reconstruction functions matching the SDK wire contract
  (`SHA256(nonce)` for the assertion; `SHA256(commitment ‖ ts ‖ nonce)` for the
  Secure Enclave signature), with unit tests pinning the byte layout.
- Language-agnostic verification spec under `spec/`.
- Embedded Apple App Attestation Root CA (fingerprint-pinned) as the offline
  trust anchor.
- Single-file TOML config (`config` feature) so app identity and Google-project
  settings are never hardcoded.
- App Attest verification: attestation-object CBOR parse, X.509 chain validation
  to the embedded root (P-384/SHA-384), Apple nonce-extension binding, App ID
  and key-id checks, AAGUID environment policy, and assertion signature +
  monotonic-counter verification. Synthetic-vector tested; the full
  real-device attestation-object path is exercised end-to-end separately.
- `verify_device_signature` + `DEVICE_ATTESTATION_DOMAIN`: verify the per-proof
  device-key signature (`DeviceAttestation.signature`, field 2) — ECDSA-P256
  over `DOMAIN ‖ SHA256(commitment ‖ ts ‖ nonce)` — against the device public
  key. Accepts DER and raw signatures and high-S. Confirms the device key signed
  this commitment/timestamp/nonce (and that the top-level timestamp wasn't
  tampered). Spec §2.5 updated with the exact preimage + shared domain constant.
- Play Integrity (`playintegrity` feature): parse a *decoded* token payload
  (bare or `tokenPayloadExternal`-wrapped) into a normalised `IntegrityVerdict`
  (device integrity, app recognition, package, nonce) and bind it to the proof
  (nonce + package). The token decode/decrypt step (Google API or local keys)
  is wired separately once a Cloud project + real token exist.
