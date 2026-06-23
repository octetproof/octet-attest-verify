# octet-attest-verify

Offline verification of the mobile device-attestation evidence carried on an
[Octet](https://octetproof.com) `LocationProof`.

A proof can carry, in its `DeviceAttestation`, evidence that the device which
produced it is a genuine app instance on a genuine device:

- **Apple App Attest** (iOS) — an attestation object and per-proof assertions
  rooted in Apple's App Attest certificate authority.
- **Google Play Integrity** (Android) — a signed integrity token.

This crate verifies that evidence.

## Two layers, deliberately different

| | App Attest (iOS) | Play Integrity (Android) |
|---|---|---|
| Trust anchor | Apple's static App Attest **root CA**, baked into this crate | Google, via your **Play Console project** |
| Offline? | **Yes** — no network, no secrets | **No** — decode is bound to your Cloud project |
| Feature | default | `--features playintegrity` |

The App Attest layer is the one you're asked to trust as an auditable anchor:
it is pure, offline, and depends only on a published Apple root. Play Integrity
decoding inherently needs Google, so it lives behind a feature flag and is for
integrators wiring their own Cloud project.

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

## Wire contract

The exact byte layouts the verifier reconstructs are specified, language-
agnostically, in [`spec/attestation-verification.md`](spec/attestation-verification.md).
That spec is the single source of truth shared with the SDK that produces the
proofs and with any non-Rust re-implementation.

## Status

Early (`1.0.0-alpha`). The App Attest offline core and the shared spec are the
focus; the Play Integrity decode helper is being built against a live token.

## License

Apache-2.0. See [LICENSE](LICENSE).
