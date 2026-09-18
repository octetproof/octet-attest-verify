//! Play Integrity pass-policy golden vectors — a shared cross-implementation
//! reference, kept in lockstep across the crate and the mobile clients.
//!
//! Running them here keeps the crate's `from_decoded_json` +
//! `check_device_integrity` + `check_binding_packages` + `check_freshness`
//! consistent with the agreed pass policy:
//!
//! - device gate = `MEETS_DEVICE_INTEGRITY` || `MEETS_STRONG_INTEGRITY`
//! - nonce = base64-decode `requestDetails.nonce` (std + URL-safe, padding
//!   optional), RAW byte-compare to the expected nonce
//! - package = `requestPackageName` == expected
//! - freshness = within `maxAge`, +60 s forward skew
//! - `appRecognitionVerdict` informational; `appLicensingVerdict` ignored
//!
//! The source of truth is `test-vectors/playintegrity/vectors.json`. If a verdict
//! here ever disagrees with the crate, that is real drift: fix the crate (or
//! renegotiate the policy) — never edit a vector to go green. The vectors are a
//! private fixture (not published), so this test skips cleanly when they are
//! absent, mirroring the other vector tests.
#![cfg(feature = "playintegrity")]

use std::path::PathBuf;

use base64::Engine;
use octet_attest_verify::playintegrity::IntegrityVerdict;
use serde_json::Value;

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors/playintegrity/vectors.json")
}

/// The full pass policy, composed as the online verifier composes it: PASS iff
/// the payload parses AND meets the device gate AND binds (nonce + package) AND
/// is fresh. App recognition and licensing are never consulted.
fn passes(payload_json: &str, nonce: &[u8], pkg: &str, now_ms: i64, max_age_ms: i64) -> bool {
    match IntegrityVerdict::from_decoded_json(payload_json) {
        Ok(v) => {
            v.check_device_integrity().is_ok()
                && v.check_binding_packages(nonce, Some(&[pkg])).is_ok()
                && v.check_freshness(now_ms, max_age_ms).is_ok()
        }
        Err(_) => false,
    }
}

#[test]
fn shared_golden_vectors() {
    let path = vectors_path();
    if !path.exists() {
        eprintln!(
            "skipping: no golden vectors at {} (private fixture, not published); \
             the crate's playintegrity unit tests cover the policy logic",
            path.display()
        );
        return;
    }
    let raw = std::fs::read_to_string(&path).expect("read vectors.json");
    let doc: Value = serde_json::from_str(&raw).expect("parse vectors.json");

    let params = &doc["params"];
    let now_ms = params["nowMs"].as_i64().expect("nowMs");
    let max_age_ms = params["maxAgeMs"].as_i64().expect("maxAgeMs");
    let pkg = params["expectedPackage"].as_str().expect("expectedPackage");
    let nonce = base64::engine::general_purpose::STANDARD
        .decode(params["expectedNonceB64Std"].as_str().expect("expectedNonceB64Std"))
        .expect("decode expectedNonce");
    // Pin the reference nonce to the agreed raw bytes.
    assert_eq!(
        nonce,
        [0x01, 0x02, 0x03, 0x04, 0xFB, 0xFF, 0xBF],
        "expected-nonce raw bytes drifted from the agreed value"
    );

    let mut checked = 0usize;
    for vector in doc["vectors"].as_array().expect("vectors array") {
        let name = vector["name"].as_str().expect("vector name");
        let want_pass = match vector["expect"].as_str().expect("expect") {
            "PASS" => true,
            "FAIL" => false,
            other => panic!("vector `{name}`: unknown expect `{other}`"),
        };
        // Feed the bare decoded payload; `from_decoded_json` also accepts the
        // `{ "tokenPayloadExternal": … }` wrapper Google's decode API returns.
        let payload =
            serde_json::to_string(&vector["tokenPayloadExternal"]).expect("serialize payload");
        let got = passes(&payload, &nonce, pkg, now_ms, max_age_ms);
        assert_eq!(
            got, want_pass,
            "vector `{name}`: crate verdict PASS={got} but reference expects PASS={want_pass}"
        );
        checked += 1;
    }

    // The malformed case feeds raw bytes that are not a JSON object; it must
    // fail closed rather than panic or pass.
    let mal = &doc["malformedJson"];
    let mal_name = mal["name"].as_str().expect("malformed name");
    let raw_bytes = mal["rawBytes"].as_str().expect("rawBytes");
    assert!(
        !passes(raw_bytes, &nonce, pkg, now_ms, max_age_ms),
        "vector `{mal_name}`: malformed JSON must fail closed"
    );
    checked += 1;

    assert_eq!(checked, 16, "expected 15 vectors + 1 malformed case, ran {checked}");
}
