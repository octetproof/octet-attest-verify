//! End-to-end App Attest verification against a captured real-device vector.
//!
//! A genuine attestation object can only come from a physical device, so this
//! test is **skip-if-absent**: with no vector checked in it returns early
//! (printing a notice) rather than failing, and the synthetic-key assertion
//! tests in `src/appattest.rs` carry the crypto coverage. Drop the files
//! described in `test-vectors/appattest/README.md` to activate it.

use std::collections::HashMap;
use std::path::PathBuf;

use octet_attest_verify::appattest::{
    verify_assertion, verify_assertion_with_binding, verify_attestation, AcceptEnvironment, AppId,
    AssertionBinding,
};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors/appattest")
}

fn parse_meta(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

#[test]
fn real_device_vector_verifies_end_to_end() {
    let dir = vectors_dir();
    let (obj_path, asrt_path, meta_path) = (
        dir.join("attestation_object.bin"),
        dir.join("assertion.bin"),
        dir.join("meta.txt"),
    );
    if !(obj_path.exists() && asrt_path.exists() && meta_path.exists()) {
        eprintln!(
            "skipping: no real-device App Attest vector in {} (see README); \
             synthetic-key tests cover the assertion crypto",
            dir.display()
        );
        return;
    }

    let attestation = std::fs::read(&obj_path).expect("read attestation_object.bin");
    let assertion = std::fs::read(&asrt_path).expect("read assertion.bin");
    let cert0 = std::fs::read(dir.join("cert0.bin")).expect("read cert0.bin (certificate_chain[0], SE key)");
    let meta = parse_meta(&std::fs::read_to_string(&meta_path).expect("read meta.txt"));

    let nonce = hex::decode(meta.get("nonce_hex").expect("meta nonce_hex")).expect("nonce hex");
    let key_id = hex::decode(meta.get("key_id_hex").expect("meta key_id_hex")).expect("key_id hex");
    let app_id = AppId::from_team_and_bundle(
        meta.get("team_id").expect("meta team_id"),
        meta.get("bundle_id").expect("meta bundle_id"),
    );
    let env = match meta.get("env").map(String::as_str) {
        Some("production") => AcceptEnvironment::Production,
        Some("development") => AcceptEnvironment::Development,
        _ => AcceptEnvironment::Any,
    };

    // Attestation object → recovered App Attest key (verified to Apple's root).
    let key = verify_attestation(&attestation, &nonce, &app_id, &key_id, env)
        .expect("real attestation object must verify to Apple's root");

    // #38 / #317: this is a *bound-form* vector — the assertion's clientDataHash
    // is SHA256(nonce ‖ cert0), where cert0 is the Secure-Enclave signing key.
    // The App Attest key and the SE signing key are distinct by design (this is
    // exactly why iOS needs the binding, not a key-equality check).
    assert_ne!(
        key.public_key_sec1, cert0,
        "App Attest key and SE signing key are distinct on iOS — the fixture must reflect that"
    );

    // RequireBound against the genuine SE key verifies, and returns the counter.
    let counter = verify_assertion_with_binding(
        &assertion,
        &nonce,
        &app_id,
        &key,
        AssertionBinding::RequireBound { signing_key_sec1: &cert0 },
    )
    .expect("real #317 assertion must verify under RequireBound with the genuine SE key");
    eprintln!("real-device bound-form vector verified; assertion counter = {counter}");

    // The legacy nonce-only form MUST fail on a #317 bound assertion — proving
    // the signature genuinely commits to SHA256(nonce ‖ cert0), not SHA256(nonce).
    assert!(
        verify_assertion(&assertion, &nonce, &app_id, &key).is_err(),
        "a #317 bound assertion must NOT verify under the legacy nonce-only form"
    );

    // RequireBound with a DIFFERENT signing key must fail — this is the replay
    // the binding defeats (borrowing a genuine (nonce, assertion) pair and
    // pairing it with an attacker's SE key). Flip a byte so the key differs.
    let mut wrong = cert0.clone();
    *wrong.last_mut().unwrap() ^= 0xFF;
    assert!(
        verify_assertion_with_binding(
            &assertion,
            &nonce,
            &app_id,
            &key,
            AssertionBinding::RequireBound { signing_key_sec1: &wrong },
        )
        .is_err(),
        "a bound assertion must NOT verify against a different signing key (replay defense)"
    );
}
