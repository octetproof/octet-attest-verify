//! The WebView bridge golden vectors (`test-vectors/bridge/vectors.json`, made
//! by `generate.py` independently of this crate): the SE binding
//! `clientDataHash`, the binding assertion, the receipt-free attestation object
//! and the bridge signature. The SDK and the stateless verifier test against the
//! same file.

use std::path::PathBuf;

use octet_attest_verify::appattest::{
    se_binding_client_data_hash, verify_assertion_with_client_data_hash,
    verify_attestation_with_client_data_hash, AcceptEnvironment, AppId, AttestEnvironment, AttestedKey,
};
use octet_attest_verify::bridge::{bridge_preimage, verify_bridge_signature};
use octet_attest_verify::AttestError;
use serde_json::Value;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors/bridge")
}

fn vectors() -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir().join("vectors.json")).unwrap()).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn hex32(v: &Value) -> [u8; 32] {
    hex(v).try_into().unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn cases<'a>(v: &'a Value, section: &str) -> &'a Vec<Value> {
    let c = v[section]["cases"].as_array().unwrap();
    assert!(!c.is_empty(), "{section} has no cases");
    c
}

fn app_id(c: &Value) -> AppId {
    AppId::from_team_and_bundle(s(&c["team_id"]), s(&c["bundle_id"]))
}

fn error_code(e: &AttestError) -> &'static str {
    match e {
        AttestError::CertExpired => "cert_expired",
        AttestError::NonceMismatch => "nonce_mismatch",
        AttestError::WrongEnvironment => "wrong_environment",
        AttestError::CounterReplay => "counter_replay",
        AttestError::AssertionSignatureInvalid => "assertion_signature_invalid",
        AttestError::DeviceSignatureInvalid => "device_signature_invalid",
        other => panic!("unexpected error {other:?}"),
    }
}

#[test]
fn se_binding_client_data_hash_matches() {
    let v = vectors();
    for c in cases(&v, "se_binding") {
        assert_eq!(se_binding_client_data_hash(&hex(&c["se_pub_hex"])), hex32(&c["client_data_hash_hex"]));
    }
}

#[test]
fn bind_assertions() {
    let v = vectors();
    for c in cases(&v, "bind_assertion") {
        let name = s(&c["name"]);
        // The key as the attestation returns it: counter 0.
        let key = AttestedKey { public_key_sec1: hex(&c["app_attest_public_key_hex"]), last_counter: 0 };
        let cdh = se_binding_client_data_hash(&hex(&c["se_pub_hex"]));
        let got = verify_assertion_with_client_data_hash(&hex(&c["assertion_hex"]), &cdh, &app_id(c), &key);
        match s(&c["result"]) {
            "ok" => assert_eq!(got.unwrap(), c["counter"].as_u64().unwrap() as u32, "{name}"),
            want => assert_eq!(error_code(&got.unwrap_err()), want, "{name}"),
        }
    }
}

#[test]
fn attestation_without_receipt() {
    let v = vectors();
    let section = &v["attestation_without_receipt"];
    for c in cases(&v, "attestation_without_receipt") {
        let name = s(&c["name"]);
        let obj = std::fs::read(dir().join(s(&c["file"]))).unwrap();
        assert_eq!(obj.len() as u64, section["stripped_object_bytes"].as_u64().unwrap());
        let env = match s(&c["environment"]) {
            "production" => AcceptEnvironment::Production,
            "development" => AcceptEnvironment::Development,
            other => panic!("{other}"),
        };
        let got = verify_attestation_with_client_data_hash(
            &obj,
            &hex32(&c["client_data_hash_hex"]),
            &app_id(c),
            &hex(&c["key_id_hex"]),
            env,
            c["now"].as_u64().unwrap(),
        );
        match s(&c["result"]) {
            "ok" => {
                let a = got.unwrap_or_else(|e| panic!("{name}: {e:?}"));
                assert_eq!(a.environment, AttestEnvironment::Development);
                assert_eq!(a.key.last_counter, 0, "{name}");
                assert_eq!(a.validity.leaf_not_before, c["leaf_not_before"].as_u64().unwrap());
            }
            want => assert_eq!(error_code(&got.unwrap_err()), want, "{name}"),
        }
    }
}

#[test]
fn bridge_signatures() {
    let v = vectors();
    for c in cases(&v, "bridge_signature") {
        let name = s(&c["name"]);
        let (s0, d, t, k) = (s(&c["s0"]), hex32(&c["d_hex"]), c["t"].as_u64().unwrap(), hex(&c["k_hex"]));
        assert_eq!(bridge_preimage(s0, &d, t, &k), hex(&c["preimage_hex"]), "{name}");
        let got = verify_bridge_signature(&hex(&c["public_key_hex"]), s0, &d, t, &k, &hex(&c["signature_der_hex"]));
        match s(&c["result"]) {
            "ok" => got.unwrap_or_else(|e| panic!("{name}: {e:?}")),
            want => assert_eq!(error_code(&got.unwrap_err()), want, "{name}"),
        }
    }
}
