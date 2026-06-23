# Attestation verification spec

Version: 1.0.0-alpha · Status: draft

This is the language-agnostic contract for verifying the device-attestation
evidence carried on an Octet `LocationProof`. It is the single source of truth
shared by:

- the **SDK** that produces proofs (it must emit exactly these bytes), and
- any **verifier** that consumes them (the reference Rust implementation in this
  repo, `octet-verify`, or a third-party re-implementation).

A proof carries attestation evidence in its `octet.proof.DeviceAttestation`
message. The relevant fields:

| Field | # | Meaning |
|---|---|---|
| `key_id` | 1 | platform key identifier |
| `signature` | 2 | Secure Enclave / device-key signature (see §3) |
| `certificate_chain` | 3 | Android cert chain (Play Integrity path) |
| `play_integrity_token` | 4 | Android Play Integrity token (§4) |
| `security_level` | 7 | device key security tier (informational) |
| `app_attest_attestation` | 8 | iOS App Attest attestation object, CBOR (§2) |
| `app_attest_assertion` | 9 | iOS App Attest assertion (§2) |
| `attestation_nonce` | 10 | the window nonce both bindings reference (§1) |

The proof also carries `position_commitment` (field 5) and `timestamp_ms`
(field 7 of `LocationProof`), which the verifier uses to reconstruct the
per-proof challenge.

---

## 1. The nonce and the cadence window

The SDK fetches one attestation **verdict** per *cadence window* (`perProof`,
`periodic`, or `perSession`) and reuses it for every proof issued in that
window. To make this sound, two bindings are kept separate:

- **Window-level** (the App Attest assertion / Play Integrity token): bound only
  to a random **`attestation_nonce`** (field 10), so one verdict serves the
  whole window.
- **Per-proof** (the Secure Enclave signature, field 2): bound to *this* proof's
  `position_commitment` and `timestamp_ms` **and** the window nonce — so each
  proof is individually tied to the verdict's nonce.

`attestation_nonce` is **32 random bytes**, identical across every proof in one
window, fresh per window. The verifier needs nothing held server-side: both
bindings are reconstructable from fields already on the proof.

---

## 2. Apple App Attest (offline)

Trust anchor: the **Apple App Attest Root CA** (public, static). Verification is
fully offline.

### 2.1 Inputs

- `attestation_object` (field 8) — present only on the **first** proof after a
  key is attested. CBOR map `{ fmt: "apple-appattest", attStmt: { x5c, receipt },
  authData }`. A verifier caches the public key it recovers, keyed by `key_id`,
  to verify later assertion-only proofs.
- `assertion` (field 9) — present on every proof in the window.
- `attestation_nonce` (field 10).
- Expected **App ID** — `SHA256("<TeamID>.<BundleID>")`. The expected Team ID +
  bundle id are carried as **signed claims** in the Octet activation bearer
  (`team_id` / `app_id`), so the expected identity is itself trusted, not
  caller-asserted.

### 2.2 `clientDataHash`

Both `attestKey` and the per-window assertion are computed by the SDK over:

```
clientDataHash = SHA256(attestation_nonce)
```

This is window-level (depends only on the nonce), which is what lets one verdict
cover a cadence window.

### 2.3 Attestation object verification (first proof of a key)

Following Apple's published algorithm:

1. Parse the CBOR. Require `fmt == "apple-appattest"`.
2. Validate the `x5c` chain up to the **Apple App Attest Root CA**.
3. Compute `nonce = SHA256(authData ‖ clientDataHash)`.
4. Read the leaf certificate extension **OID `1.2.840.113635.100.8.2`**; its
   single octet-string must equal `nonce`.
5. `authData[0..32]` (`rpIdHash`) must equal the expected App ID
   (`SHA256("<TeamID>.<BundleID>")`).
6. Recover the leaf certificate's P-256 public key. Its `SHA256` must equal the
   credential id in `authData`, which must equal `key_id`.
7. The AAGUID (`authData[37..53]`) must be `appattest` (production) or
   `appattestdevelop` (development) — the verifier records which.
8. Sign counter in `authData` starts at 0; cache `{ key_id → public_key,
   counter }`.

On success the recovered public key is trusted for this `key_id`.

### 2.4 Assertion verification (every proof)

1. `clientDataHash = SHA256(attestation_nonce)` (§2.2).
2. The assertion is CBOR `{ signature, authenticatorData }`. Verify `signature`
   (ECDSA-P256) over `SHA256(authenticatorData ‖ clientDataHash)` using the
   public key cached for `key_id` (§2.3). If no key is cached, the verdict is
   `UnknownKey` (a proof presented an assertion before its attestation was seen).
3. `authenticatorData[0..32]` must equal the expected App ID hash.
4. The sign counter in `authenticatorData` must be **strictly greater** than the
   cached counter; update the cache. A non-advancing counter is a replay.

### 2.5 Octet device-key binding (per-proof)

Independently of Apple's algorithm, `DeviceAttestation.signature` (field 2) is
the device key's signature (iOS Secure Enclave / Android hardware Keystore) over
a per-proof challenge that ties *this* proof's commitment and timestamp to the
window nonce the App Attest assertion / Play Integrity token vouches for:

```
se_challenge      = position_commitment ‖ timestamp_ms (8 bytes, big-endian) ‖ attestation_nonce
se_clientDataHash = SHA256(se_challenge)
signed_message    = DOMAIN ‖ se_clientDataHash          ; DOMAIN = "octet-device-attestation-v1" (ASCII)
field2            = ECDSA-P256-SHA256( device_key, signed_message )
```

`DOMAIN` is a **shared, versioned, public constant** — identical on iOS and
Android — that domain-separates this signature from the stage-chain signatures
made by the same key. Because it is a known constant (not a per-proof value) and
`commitment` / `timestamp_ms` / `attestation_nonce` are all on the proof (fields
5 / 7 / 10), a verifier reconstructs `signed_message` from the proof alone and
verifies field 2 against the device public key (the Android `certificate_chain`,
field 3, or an out-of-band iOS Secure-Enclave key).

> Two load-bearing details: (1) the challenge byte order — `commitment`, then the
> **big-endian** 8-byte timestamp, then the nonce; (2) the signer applies SHA-256
> to `signed_message` itself (standard ECDSA-P256-SHA256), so a verifier passes
> the full `DOMAIN ‖ se_clientDataHash` message to an ECDSA verify that hashes,
> *not* the pre-hashed value. Both are unit-pinned on the SDK and verifier sides.

Verifying field 2 confirms the device key signed this exact commitment, time, and
nonce — and, since `timestamp_ms` is inside the signed challenge, that the
top-level timestamp was not tampered. A verifier with no device key available
reports this `NOT-CHECKED` rather than failing.

### 2.6 Verdict

The verifier emits a trusted `DeviceIntegrityVerdict`:

- all checks pass → `INTEGRITY_VERIFIED_COMPLIANT`
- a check fails → `INTEGRITY_VERIFIED_NON_COMPLIANT` with the failing reason

This iteration **reports** the verdict; it does not hard-reject the proof.

---

## 3. Android device key (Secure-Enclave equivalent)

The per-proof binding in §2.5 applies identically on Android: field 2 is the
hardware-backed key's signature over `SHA256(commitment ‖ ts ‖ nonce)` with the
same byte layout, so the per-proof binding is cross-platform. Only the
window-level evidence differs (Play Integrity instead of App Attest).

---

## 4. Google Play Integrity (decode-bound, not offline)

Unlike App Attest, a Play Integrity token **cannot be verified offline** — decode
is bound to the Google Play Console project the app is linked to. A verifier with
the appropriate credentials (the app's own Cloud project, or Octet's for
Octet-published apps) decodes `play_integrity_token` (field 4) and reads:

- `deviceIntegrity` → device genuineness (`MEETS_DEVICE_INTEGRITY`, etc.). This
  is available even for a sideloaded build.
- `appIntegrity.appRecognitionVerdict` → `PLAY_RECOGNIZED` only when the binary
  was distributed by Play; otherwise `UNRECOGNIZED_VERSION` / `UNEVALUATED`.
- the request nonce, which must equal `attestation_nonce` (field 10) so the
  token binds to the same window as the per-proof signature in §3.

Because decode needs Google, a fully offline verifier (e.g. `octet-verify` with
no Play credentials) treats the Play Integrity verdict as **backend-asserted
only** — it cannot independently confirm it.

---

## 5. Versioning

This spec is versioned with the crate. Any change to a byte layout, OID, hash
input, or verdict mapping is a wire-contract change and is called out in the
changelog of both this repo and the SDK.
