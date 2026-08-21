# Changelog

All notable changes to `octet-attest-verify` are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/); versioning is
[SemVer](https://semver.org/).

## [2.1.1] - 2026-08-21

Security fix for the Android key-attestation path (`verify_key_attestation`).
Two hardening changes; the public Rust API is unchanged. 2.1.0 is published with
these flaws, so 2.1.1 supersedes it.

### Fixed
- **Chain-extension attack: a genuine device leaf could sign a forged leaf.**
  The chain walk verified each link's signature but not that a signer was
  permitted to issue certificates, so a real, Google-signed device leaf — whose
  private key is usable through the ordinary KeyStore signing API — could sign a
  sub-certificate carrying an attacker-authored attestation extension
  (challenge, `rootOfTrust`, app identity), and the forged chain was accepted.
  The extension's **position** is now constrained: the attestation extension
  (`1.3.6.1.4.1.11129.2.1.17`) may appear only on the target leaf, and any
  issuer carrying it is rejected. This matches Google's own certificate-path
  validator, and the chain-length bound is kept. Deliberately **not** added: an
  RFC 5280 `basicConstraints cA=TRUE` / `keyUsage` requirement on issuers — real
  devices ship non-CA batch certificates, so that check rejects genuine
  hardware, which is why Google's verifier omits it too.
- **RootOfTrust trust order: `softwareEnforced` was consulted before
  `teeEnforced`.** `extract_root_of_trust` returned the first `rootOfTrust` it
  found and searched the framework-populated `softwareEnforced` list first, so a
  device whose hardware `teeEnforced` reported Unverified / unlocked could carry
  `Verified` + locked in `softwareEnforced` and pass the bootstrap verified-boot
  gate. The `rootOfTrust` is now read from `teeEnforced` only; a copy found
  solely in `softwareEnforced` is treated as absent, so the gate fails closed.

### Note on validation
Certificate-path validation is now covered by a captured genuine-device corpus
(both pinned roots, TEE and StrongBox security levels, and the RKP chain shape),
so the hardening is demonstrated not to reject real hardware.

## [2.1.0] - 2026-08-20

Delivers the bootstrap key-attestation path to the **Python** consumer. The Rust
API is unchanged from 2.0.0 — this is a binding and packaging release.

### Added
- **`verify_key_attestation` on the Python binding.** 2.0.0 shipped the Rust
  function but the binding exposed only App Attest, so a Python consumer could
  not reach the Android key-attestation path at all. Callers resolve the
  attribute lazily, so a 2.0.0 wheel imports cleanly and then raises on first
  use. Anything consuming the wheel needs 2.1.0 or later.
- **The wheel ships as a release asset.** Built inside `python:3.12-slim` so
  the compiled extension is not linked against a newer glibc than the image it
  has to load on, and import-checked on that same image before it is attached.

### Changed
- pyo3 0.26.0 → 0.29.0, and `Cargo.lock` refreshed.

### Note on scope
Certificate-chain path validation is not changed in this release. Hardening it
is tracked separately and needs a captured genuine chain first, so that the
change can be shown not to reject real devices; see `test-vectors/`.

## [2.0.0] - 2026-08-14

Adds the **bootstrap attestation posture** for the attested-bootstrap licence
model. Android key-attestation gains a stricter mode for minting a licence,
distinct from the softer proof path.

### Changed (breaking)
- **`verify_key_attestation` takes an `AttestMode` parameter.** `AttestMode::Proof`
  is the previous behaviour; `AttestMode::Bootstrap { revoked_serials }` adds the
  strict checks below — call sites must now pass a mode. `KeyAttestation` also
  gains `app_identity` and `root_of_trust` fields.

### Added
- **Bootstrap verified-boot gate.** Parses `RootOfTrust` (from `teeEnforced` or
  `softwareEnforced`, `[704]`) and, on `Bootstrap`, requires
  `verifiedBootState == Verified` and `deviceLocked == true`; an absent RootOfTrust
  fails closed. New errors `AttestationUnverifiedBoot` /
  `AttestationBootloaderUnlocked`. The proof path is unchanged.
- **Bootstrap revocation.** Rejects (`AttestationRevoked`) if any chain cert's
  serial is in the caller-supplied `revoked_serials`. The crate stays fully
  offline: the caller fetches Google's `attestkey/v1/status`, caches it, and owns
  the fail-closed-on-fetch-failure policy; the crate only extracts serials and
  checks membership (leading-zero-insensitive).
- **`AttestedAppIdentity` accessor.** `KeyAttestation.app_identity` emits the parsed
  `attestationApplicationId` as `{ package_names: Vec<String>, cert_sha256_digests:
  Vec<[u8; 32]> }` for the caller to compare against a registered
  `(package_name, signing_cert_sha256)` pair — multiple signers preserved.
  Complements the existing opt-in `ExpectedAppIdentity` match.

## [1.1.0] - 2026-07-29

### Added
- **Android app-identity binding (opt-in).** `verify_key_attestation` gains an
  `Option<&ExpectedAppIdentity>` (`{ package_name, signing_cert_sha256 }`). When
  supplied, the Keystore attestation's `attestationApplicationId` (parsed from the
  `softwareEnforced` authorization list at context tag `[709]`) must name that
  package and include that signing-cert SHA-256 among its `signatureDigests`; a
  mismatch — or an absent/unparseable id when one was required — fails closed
  (`AndroidAppIdentityMismatch`). This binds an attested key to a specific app
  (the Android analog of App Attest's `appId`). When omitted, behavior is
  unchanged (hardware root only). The `attestationApplicationId` is parsed
  best-effort so it can never weaken the strict challenge / security-level checks.

## [1.0.0] - 2026-06-25

First public release: an offline verifier for the mobile device-attestation
evidence carried on an Octet `LocationProof` — Apple App Attest (validated to
Apple's embedded root), offline Android key-attestation chain validation (to
embedded Google roots), and a Google Play Integrity decode helper. The default
build is a lean, network-free, secret-free trust anchor; Android key attestation,
Play Integrity, and config are opt-in features. Real-device Apple attestations
verify end-to-end.

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
- Android key attestation (`keyattest` feature): `verify_key_attestation`
  validates an Android Keystore certificate chain offline — signatures leaf → …
  → an embedded, fingerprint-pinned Google hardware-attestation root (both the
  RSA-4096 root and the ECDSA P-384 root effective 2026-02-01), validity windows,
  and the leaf's KeyDescription extension (challenge match + TEE/StrongBox
  security level). Synthetic-vector and reject-path tested; the real-device
  accept path is validated on hardware separately (spec §3.1). Revocation
  (Google's online status list) and verified-boot are out of scope.
