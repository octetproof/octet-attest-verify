//! End-to-end App Attest verification against a captured real-device vector.
//!
//! A genuine attestation object can only come from a physical device, so this
//! test is **skip-if-absent**: with no vector checked in it returns early
//! (printing a notice) rather than failing, and the synthetic-key assertion
//! tests in `src/appattest.rs` carry the crypto coverage. Drop the files
//! described in `test-vectors/appattest/README.md` to activate it.

use std::collections::HashMap;
use std::path::PathBuf;

use octet_attest_verify::appattest::{verify_assertion, verify_attestation, AcceptEnvironment, AppId};

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

    // Attestation object → recovered key, then an assertion against it.
    let key = verify_attestation(&attestation, &nonce, &app_id, &key_id, env)
        .expect("real attestation object must verify to Apple's root");
    let counter = verify_assertion(&assertion, &nonce, &app_id, &key)
        .expect("real assertion must verify against the attested key");
    eprintln!("real-device vector verified; assertion counter = {counter}");
}
