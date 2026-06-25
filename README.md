# octet-attest-verify

Offline verification of the mobile device-attestation evidence carried on an
[Octet](https://octetproof.com) `LocationProof`.

A proof can carry, in its `DeviceAttestation`, evidence that the device which
produced it is a genuine app instance on a genuine device:

- **Apple App Attest** (iOS) — an attestation object and per-proof assertions
  rooted in Apple's App Attest certificate authority.
- **Android key attestation** — a Keystore certificate chain rooted in a Google
  hardware-attestation root, proving the device key is TEE / StrongBox hardware.
- **Google Play Integrity** (Android) — a signed integrity token.

This crate verifies that evidence.

## Layers, deliberately different

| | App Attest (iOS) | Key attestation (Android) | Play Integrity (Android) |
|---|---|---|---|
| Trust anchor | Apple's static App Attest **root CA**, baked in | Google hardware-attestation **roots**, baked in | Google, via your **Play Console project** |
| Offline? | **Yes** — no network, no secrets | **Yes** — no network, no secrets | **No** — decode is bound to your Cloud project |
| Feature | default | `--features keyattest` | `--features playintegrity` |

App Attest and key attestation are the layers you're asked to trust as auditable
anchors: pure, offline, and depending only on published vendor roots. Play
Integrity decoding inherently needs Google, so it lives behind a feature flag and
is for integrators wiring their own Cloud project.

## What it checks (App Attest)

Given the attestation object + assertion a proof carries, the nonce, and the
proof's own commitment and timestamp, the verifier:

1. parses the CBOR attestation object,
2. validates the X.509 certificate chain to the Apple App Attest root,
3. confirms the attested **App ID** matches the identity you expect
   (`SHA256("<TeamID>.<BundleID>")`),
4. verifies the assertion signature against the attested key and checks the
   assertion counter advanced (anti-replay),
5. reconstructs the per-proof challenge from the proof's own fields and confirms
   the binding.

It holds **no secret** and makes **no network call** — the same proof verifies
identically anywhere, which is the point.

## What it checks (Android key attestation, `--features keyattest`)

Given the proof's `certificate_chain` and the expected key-generation challenge,
`verify_key_attestation`:

1. parses the chain and checks every certificate's validity window,
2. verifies each signature up the chain (RSA or ECDSA, SHA-256/384),
3. anchors the top to an embedded, fingerprint-pinned Google hardware-attestation
   root (both the RSA-4096 root and the ECDSA P-384 root effective 2026-02-01),
4. parses the leaf's KeyDescription extension and enforces the attestation
   challenge and a TEE / StrongBox security level.

Offline, like App Attest. It does **not** check online revocation (Google's
status list) — see [spec §3.1](spec/attestation-verification.md).

## Wire contract

The exact byte layouts the verifier reconstructs are specified, language-
agnostically, in [`spec/attestation-verification.md`](spec/attestation-verification.md).
That spec is the single source of truth shared with the SDK that produces the
proofs and with any non-Rust re-implementation.

## Status

`1.0.0`. The App Attest offline core, the Android key-attestation layer, and the
shared spec are the focus. The Android key-attestation accept path is validated
on real hardware; the Play Integrity decode helper is wired against a live token.

## License

Apache-2.0. See [LICENSE](LICENSE).
