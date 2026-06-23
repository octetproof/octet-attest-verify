# App Attest test vectors

A real Apple App Attest object can only be produced on a physical device, so the
end-to-end attestation-chain test (validate to Apple's root, recover the key,
verify an assertion against it) runs against a captured device vector dropped in
here. Until that capture exists, `tests/appattest_vectors.rs` **skips** (it does
not fail) — the synthetic-key assertion tests in `src/appattest.rs` cover the
crypto in the meantime.

To enable the end-to-end test, capture one attestation + one assertion from a
real build of an App-Attest-enabled app and add these files:

```
test-vectors/appattest/
  attestation_object.bin   # the CBOR attestation object (proto field 8)
  assertion.bin            # one assertion for the same key (proto field 9)
  meta.txt                 # parameters (see below)
```

`meta.txt` is simple `key=value` lines:

```
nonce_hex=<hex of attestation_nonce, proto field 10>
key_id_hex=<hex of the 32-byte credential id = base64-decoded proto key_id>
team_id=<Apple Team ID>
bundle_id=<app bundle id>
env=development            # or production
```

With those present, `cargo test` runs the full
`verify_attestation` → `verify_assertion` path against Apple's embedded root.

> Do not commit a vector tied to a private/internal build if its bundle id or
> Team ID should not be public — this repo is intended to be published. A vector
> from a throwaway demo app id is fine.
