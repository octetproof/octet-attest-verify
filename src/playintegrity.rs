//! Google Play Integrity — decode helper (feature `playintegrity`).
//!
//! Unlike App Attest, a Play Integrity token **cannot be verified offline**:
//! turning the opaque token into a verdict is bound to the Google Play Console
//! project the app is linked to (either Google's `decodeIntegrityToken` API or
//! local decryption with the project's response keys).
//!
//! This module implements the part that is **not** gated on that setup: parsing
//! the *already-decoded* payload JSON into a normalised [`IntegrityVerdict`] and
//! binding it to the proof's nonce. The decode/decrypt step itself (which needs
//! Google credentials and a real token) is wired separately once the project is
//! configured.

use base64::Engine;
use serde::Deserialize;

/// The integrity verdicts a decoded Play Integrity token yields, normalised to
/// the fields Octet records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityVerdict {
    /// Device integrity (e.g. `MEETS_DEVICE_INTEGRITY`). Obtainable even for a
    /// sideloaded build.
    pub device_integrity: DeviceIntegrity,
    /// Whether Play recognises this exact app/version. `Unevaluated` until the
    /// app ships through a Play track.
    pub app_recognition: AppRecognition,
    /// The request package name from the token, for binding to the expected app.
    pub request_package_name: Option<String>,
    /// The nonce echoed back in the token (raw bytes, base64-decoded), for
    /// binding to the proof's `attestation_nonce`.
    pub nonce: Vec<u8>,
    /// The token's `requestDetails.timestampMillis` (ms since epoch) when present
    /// and parseable, for the optional freshness-window check. `None` if the
    /// field is absent or not a valid integer.
    pub timestamp_ms: Option<i64>,
}

/// Device-integrity level from the token's `deviceIntegrity` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceIntegrity {
    /// Met `MEETS_STRONG_INTEGRITY` (hardware-backed boot integrity — the
    /// strongest signal, implies device integrity).
    MeetsStrong,
    /// Met `MEETS_DEVICE_INTEGRITY` (genuine, uncompromised device).
    MeetsDevice,
    /// Only basic integrity (`MEETS_BASIC_INTEGRITY`).
    MeetsBasic,
    /// No integrity labels present.
    None,
}

/// App-recognition level from the token's `appIntegrity.appRecognitionVerdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppRecognition {
    /// `PLAY_RECOGNIZED` — the binary matches what Play distributed.
    PlayRecognized,
    /// `UNRECOGNIZED_VERSION` — installed but not a Play-distributed build.
    Unrecognized,
    /// `UNEVALUATED` — verdict not evaluated (e.g. app not on Play).
    Unevaluated,
}

/// Play Integrity parsing / binding failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlayIntegrityError {
    #[error("malformed decoded payload: {0}")]
    Malformed(String),
    #[error("token nonce does not match the proof nonce")]
    NonceMismatch,
    #[error("device integrity verdict is below the accepted band")]
    DeviceIntegrityInsufficient,
    #[error("token package name is not one of the accepted packages")]
    PackageMismatch,
    #[error("token carries no parseable timestampMillis")]
    MissingTimestamp,
    #[error("token timestamp is outside the accepted freshness window")]
    TimestampOutOfWindow,
}

/// Clock-skew tolerance for the freshness window: a token whose timestamp is up
/// to this far in the future is still accepted (matches the proof-freshness
/// skew used elsewhere in the pipeline).
const CLOCK_SKEW_MS: i64 = 60_000;

// --- Decoded-payload JSON shape (subset we consume) ---

#[derive(Deserialize)]
struct Payload {
    #[serde(rename = "requestDetails")]
    request_details: Option<RequestDetails>,
    #[serde(rename = "appIntegrity")]
    app_integrity: Option<AppIntegrity>,
    #[serde(rename = "deviceIntegrity")]
    device_integrity: Option<DeviceIntegrityRaw>,
}

#[derive(Deserialize)]
struct RequestDetails {
    #[serde(rename = "requestPackageName")]
    request_package_name: Option<String>,
    nonce: Option<String>,
    /// Play Integrity carries this as a string of ms-since-epoch (e.g. "1700000000000").
    #[serde(rename = "timestampMillis")]
    timestamp_millis: Option<String>,
}

#[derive(Deserialize)]
struct AppIntegrity {
    #[serde(rename = "appRecognitionVerdict")]
    app_recognition_verdict: Option<String>,
}

#[derive(Deserialize)]
struct DeviceIntegrityRaw {
    #[serde(rename = "deviceRecognitionVerdict")]
    device_recognition_verdict: Option<Vec<String>>,
}

impl IntegrityVerdict {
    /// Parse a *decoded* Play Integrity payload. Accepts either the bare payload
    /// or the `{ "tokenPayloadExternal": { … } }` wrapper Google's decode API
    /// returns.
    pub fn from_decoded_json(json: &str) -> Result<Self, PlayIntegrityError> {
        let root: serde_json::Value =
            serde_json::from_str(json).map_err(|e| PlayIntegrityError::Malformed(e.to_string()))?;
        // Unwrap the API envelope if present.
        let payload_val = root
            .get("tokenPayloadExternal")
            .cloned()
            .unwrap_or(root);
        let payload: Payload = serde_json::from_value(payload_val)
            .map_err(|e| PlayIntegrityError::Malformed(e.to_string()))?;

        let device_integrity = match payload
            .device_integrity
            .and_then(|d| d.device_recognition_verdict)
        {
            // Verdicts nest — STRONG implies DEVICE implies BASIC — and a real
            // token carries the whole ladder it qualifies for. Classify to the
            // strongest label present so STRONG never reads as a weaker band.
            Some(labels) if labels.iter().any(|l| l == "MEETS_STRONG_INTEGRITY") => {
                DeviceIntegrity::MeetsStrong
            }
            Some(labels) if labels.iter().any(|l| l == "MEETS_DEVICE_INTEGRITY") => {
                DeviceIntegrity::MeetsDevice
            }
            Some(labels) if labels.iter().any(|l| l == "MEETS_BASIC_INTEGRITY") => {
                DeviceIntegrity::MeetsBasic
            }
            _ => DeviceIntegrity::None,
        };

        let app_recognition = match payload
            .app_integrity
            .and_then(|a| a.app_recognition_verdict)
            .as_deref()
        {
            Some("PLAY_RECOGNIZED") => AppRecognition::PlayRecognized,
            Some("UNRECOGNIZED_VERSION") => AppRecognition::Unrecognized,
            _ => AppRecognition::Unevaluated,
        };

        let (request_package_name, nonce, timestamp_ms) = match payload.request_details {
            Some(rd) => {
                let nonce = match rd.nonce {
                    Some(n) => decode_nonce(&n)?,
                    None => Vec::new(),
                };
                // timestampMillis is a decimal string; a non-numeric value is
                // treated as absent (None) rather than a hard parse error.
                let timestamp_ms = rd.timestamp_millis.as_deref().and_then(|s| s.parse::<i64>().ok());
                (rd.request_package_name, nonce, timestamp_ms)
            }
            None => (None, Vec::new(), None),
        };

        Ok(IntegrityVerdict {
            device_integrity,
            app_recognition,
            request_package_name,
            nonce,
            timestamp_ms,
        })
    }

    /// Confirm the token binds to the proof: its nonce equals the proof's
    /// `attestation_nonce` and (if an expected package is given) its
    /// `requestPackageName` matches.
    ///
    /// The nonce is a random per-window value the SDK echoes into the token and
    /// stores as the proof's `attestation_nonce`; this is a byte-equality check,
    /// **not** a recomputation — the nonce is not derived from anything. The
    /// proof's commitment/timestamp are tied to this same nonce by the separate
    /// device-attestation (field-2) signature, so the token is bound to *this*
    /// proof through that, not through the nonce's contents.
    ///
    /// Single-package convenience over [`check_binding_packages`]; new code that
    /// accepts a set of packages (e.g. a public + an internal build variant)
    /// should call that directly.
    pub fn check_binding(
        &self,
        expected_nonce: &[u8],
        expected_package: Option<&str>,
    ) -> Result<(), PlayIntegrityError> {
        match expected_package {
            Some(p) => self.check_binding_packages(expected_nonce, Some(&[p])),
            None => self.check_binding_packages(expected_nonce, None),
        }
    }

    /// Like [`check_binding`] but accepts a **set** of accepted packages — the
    /// token's `requestPackageName` must be one of them. Use this when one config
    /// serves multiple package names (e.g. `com.x` + `com.x.internal`). `None`
    /// checks the nonce only; an empty slice accepts no package.
    pub fn check_binding_packages(
        &self,
        expected_nonce: &[u8],
        expected_packages: Option<&[&str]>,
    ) -> Result<(), PlayIntegrityError> {
        if self.nonce != expected_nonce {
            return Err(PlayIntegrityError::NonceMismatch);
        }
        if let Some(pkgs) = expected_packages {
            match self.request_package_name.as_deref() {
                Some(pkg) if pkgs.contains(&pkg) => {}
                _ => return Err(PlayIntegrityError::PackageMismatch),
            }
        }
        Ok(())
    }

    /// Confirm the token's `timestampMillis` is fresh: no older than `max_age_ms`
    /// and not implausibly in the future (beyond [`CLOCK_SKEW_MS`]).
    ///
    /// Within a Play Integrity cadence window the token — and thus this
    /// timestamp — is **reused** across proofs, so this is a WINDOW freshness
    /// check, never a per-proof uniqueness check: identical tokens across proofs
    /// in a window are expected, and each proof binds independently via its own
    /// device-attestation signature. A token with no parseable timestamp fails
    /// closed ([`PlayIntegrityError::MissingTimestamp`]) so an absent value can
    /// never silently pass.
    pub fn check_freshness(&self, now_ms: i64, max_age_ms: i64) -> Result<(), PlayIntegrityError> {
        let ts = self.timestamp_ms.ok_or(PlayIntegrityError::MissingTimestamp)?;
        if ts > now_ms.saturating_add(CLOCK_SKEW_MS) {
            return Err(PlayIntegrityError::TimestampOutOfWindow); // implausibly future
        }
        if now_ms.saturating_sub(ts) > max_age_ms {
            return Err(PlayIntegrityError::TimestampOutOfWindow); // stale
        }
        Ok(())
    }

    /// Confirm the token meets the device-integrity gate. This is the **shared
    /// reference** for the pass policy locked with the SDK: the token passes on
    /// `MEETS_DEVICE_INTEGRITY` **or** `MEETS_STRONG_INTEGRITY` (STRONG folds in
    /// as the stronger signal). Everything weaker fails **closed** —
    /// `MEETS_BASIC_INTEGRITY`, an empty `deviceRecognitionVerdict` array, and a
    /// `deviceIntegrity` field that is absent entirely all map to
    /// [`DeviceIntegrityError::DeviceIntegrityInsufficient`](PlayIntegrityError::DeviceIntegrityInsufficient)
    /// — so a missing or unevaluated verdict can never silently pass.
    ///
    /// This gate is deliberately independent of nonce/package binding
    /// ([`check_binding_packages`](Self::check_binding_packages)) and freshness
    /// ([`check_freshness`](Self::check_freshness)); a full pass composes all
    /// three.
    pub fn check_device_integrity(&self) -> Result<(), PlayIntegrityError> {
        match self.device_integrity {
            DeviceIntegrity::MeetsStrong | DeviceIntegrity::MeetsDevice => Ok(()),
            DeviceIntegrity::MeetsBasic | DeviceIntegrity::None => {
                Err(PlayIntegrityError::DeviceIntegrityInsufficient)
            }
        }
    }
}

/// Decode the token nonce, which Play Integrity carries base64-encoded. Accepts
/// standard and URL-safe alphabets (with or without padding).
fn decode_nonce(s: &str) -> Result<Vec<u8>, PlayIntegrityError> {
    let std = base64::engine::general_purpose::STANDARD;
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    std.decode(s)
        .or_else(|_| url.decode(s.trim_end_matches('=')))
        .map_err(|_| PlayIntegrityError::Malformed("nonce is not valid base64".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A decoded payload in the shape Google documents.
    fn sample(nonce_b64: &str, app_verdict: &str, device: &str) -> String {
        format!(
            r#"{{
              "requestDetails": {{
                "requestPackageName": "com.octetproof.tester",
                "timestampMillis": "1700000000000",
                "nonce": "{nonce_b64}"
              }},
              "appIntegrity": {{ "appRecognitionVerdict": "{app_verdict}", "packageName": "com.octetproof.tester" }},
              "deviceIntegrity": {{ "deviceRecognitionVerdict": ["{device}"] }},
              "accountDetails": {{ "appLicensingVerdict": "LICENSED" }}
            }}"#
        )
    }

    #[test]
    fn parses_documented_payload() {
        let nonce = [0xABu8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        let v = IntegrityVerdict::from_decoded_json(&sample(
            &b64,
            "PLAY_RECOGNIZED",
            "MEETS_DEVICE_INTEGRITY",
        ))
        .unwrap();
        assert_eq!(v.device_integrity, DeviceIntegrity::MeetsDevice);
        assert_eq!(v.app_recognition, AppRecognition::PlayRecognized);
        assert_eq!(v.request_package_name.as_deref(), Some("com.octetproof.tester"));
        assert_eq!(v.nonce, nonce);
        assert_eq!(v.timestamp_ms, Some(1_700_000_000_000));
    }

    #[test]
    fn unwraps_decode_api_envelope() {
        let nonce = [1u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        let wrapped = format!(
            r#"{{ "tokenPayloadExternal": {} }}"#,
            sample(&b64, "UNRECOGNIZED_VERSION", "MEETS_BASIC_INTEGRITY")
        );
        let v = IntegrityVerdict::from_decoded_json(&wrapped).unwrap();
        assert_eq!(v.device_integrity, DeviceIntegrity::MeetsBasic);
        assert_eq!(v.app_recognition, AppRecognition::Unrecognized);
        assert_eq!(v.nonce, nonce);
    }

    #[test]
    fn sideloaded_app_is_unevaluated_not_error() {
        // App not on Play → no appRecognitionVerdict; device integrity still present.
        let nonce = [2u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        let json = format!(
            r#"{{ "requestDetails": {{ "nonce": "{b64}" }},
                  "deviceIntegrity": {{ "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"] }} }}"#
        );
        let v = IntegrityVerdict::from_decoded_json(&json).unwrap();
        assert_eq!(v.app_recognition, AppRecognition::Unevaluated);
        assert_eq!(v.device_integrity, DeviceIntegrity::MeetsDevice);
    }

    #[test]
    fn binding_checks_nonce_and_package_set() {
        let nonce = [7u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        let v = IntegrityVerdict::from_decoded_json(&sample(
            &b64,
            "PLAY_RECOGNIZED",
            "MEETS_DEVICE_INTEGRITY",
        ))
        .unwrap();

        // Package ∈ the accepted set (public + internal variant) passes.
        assert!(v
            .check_binding_packages(&nonce, Some(&["com.octetproof.sample", "com.octetproof.tester"]))
            .is_ok());
        // A single-element set still works.
        assert!(v.check_binding_packages(&nonce, Some(&["com.octetproof.tester"])).is_ok());
        // None checks nonce only.
        assert!(v.check_binding_packages(&nonce, None).is_ok());
        // Wrong nonce → NonceMismatch (checked before package).
        assert_eq!(
            v.check_binding_packages(&[0u8; 32], Some(&["com.octetproof.tester"])),
            Err(PlayIntegrityError::NonceMismatch)
        );
        // Package not in the set → PackageMismatch.
        assert_eq!(
            v.check_binding_packages(&nonce, Some(&["com.evil.app", "com.other.app"])),
            Err(PlayIntegrityError::PackageMismatch)
        );
        // Empty accepted set rejects any package.
        assert_eq!(
            v.check_binding_packages(&nonce, Some(&[])),
            Err(PlayIntegrityError::PackageMismatch)
        );

        // The single-package convenience wrapper still works (backward-compat).
        assert!(v.check_binding(&nonce, Some("com.octetproof.tester")).is_ok());
        assert!(v.check_binding(&nonce, None).is_ok());
        assert_eq!(
            v.check_binding(&nonce, Some("com.evil.app")),
            Err(PlayIntegrityError::PackageMismatch)
        );
    }

    #[test]
    fn freshness_window_accepts_recent_rejects_stale_future_and_missing() {
        let nonce = [8u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        // Token timestamp = 1_700_000_000_000 (from the sample).
        let v = IntegrityVerdict::from_decoded_json(&sample(
            &b64,
            "PLAY_RECOGNIZED",
            "MEETS_DEVICE_INTEGRITY",
        ))
        .unwrap();
        let ts = 1_700_000_000_000i64;
        let max_age = 300_000; // 5 min window

        // now shortly after ts, within max_age → fresh.
        assert!(v.check_freshness(ts + 120_000, max_age).is_ok());
        // now == ts → fresh.
        assert!(v.check_freshness(ts, max_age).is_ok());
        // older than max_age → stale.
        assert_eq!(
            v.check_freshness(ts + max_age + 1, max_age),
            Err(PlayIntegrityError::TimestampOutOfWindow)
        );
        // token timestamp implausibly in the future (beyond skew) → rejected.
        assert_eq!(
            v.check_freshness(ts - CLOCK_SKEW_MS - 1, max_age),
            Err(PlayIntegrityError::TimestampOutOfWindow)
        );
        // within skew into the future → accepted.
        assert!(v.check_freshness(ts - CLOCK_SKEW_MS + 1, max_age).is_ok());

        // A token with no timestamp fails closed.
        let no_ts = IntegrityVerdict::from_decoded_json(
            r#"{ "requestDetails": { "nonce": "AAAA" },
                 "deviceIntegrity": { "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"] } }"#,
        )
        .unwrap();
        assert_eq!(no_ts.timestamp_ms, None);
        assert_eq!(
            no_ts.check_freshness(ts, max_age),
            Err(PlayIntegrityError::MissingTimestamp)
        );
    }

    #[test]
    fn strong_integrity_folds_into_device_gate() {
        // A STRONG-only verdict (highest band) must classify as MeetsStrong and
        // pass the device gate — the regression this change fixes.
        let nonce = [3u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        let v = IntegrityVerdict::from_decoded_json(&sample(
            &b64,
            "PLAY_RECOGNIZED",
            "MEETS_STRONG_INTEGRITY",
        ))
        .unwrap();
        assert_eq!(v.device_integrity, DeviceIntegrity::MeetsStrong);
        assert!(v.check_device_integrity().is_ok());

        // When the whole ladder is present, classify to the strongest.
        let laddered = IntegrityVerdict::from_decoded_json(&format!(
            r#"{{ "requestDetails": {{ "nonce": "{b64}" }},
                  "deviceIntegrity": {{ "deviceRecognitionVerdict":
                    ["MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"] }} }}"#
        ))
        .unwrap();
        assert_eq!(laddered.device_integrity, DeviceIntegrity::MeetsStrong);
    }

    #[test]
    fn device_gate_passes_device_and_strong_fails_closed_otherwise() {
        let b64 = base64::engine::general_purpose::STANDARD.encode([4u8; 32]);
        let gate = |device_json: &str| {
            IntegrityVerdict::from_decoded_json(&format!(
                r#"{{ "requestDetails": {{ "nonce": "{b64}" }}, "deviceIntegrity": {device_json} }}"#
            ))
            .unwrap()
            .check_device_integrity()
        };
        assert!(gate(r#"{ "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"] }"#).is_ok());
        assert!(gate(r#"{ "deviceRecognitionVerdict": ["MEETS_STRONG_INTEGRITY"] }"#).is_ok());
        // Basic, empty array, and absent field all fail closed.
        assert_eq!(
            gate(r#"{ "deviceRecognitionVerdict": ["MEETS_BASIC_INTEGRITY"] }"#),
            Err(PlayIntegrityError::DeviceIntegrityInsufficient)
        );
        assert_eq!(
            gate(r#"{ "deviceRecognitionVerdict": [] }"#),
            Err(PlayIntegrityError::DeviceIntegrityInsufficient)
        );
        // deviceIntegrity absent entirely.
        let absent = IntegrityVerdict::from_decoded_json(&format!(
            r#"{{ "requestDetails": {{ "nonce": "{b64}" }} }}"#
        ))
        .unwrap();
        assert_eq!(absent.device_integrity, DeviceIntegrity::None);
        assert_eq!(
            absent.check_device_integrity(),
            Err(PlayIntegrityError::DeviceIntegrityInsufficient)
        );
    }

    #[test]
    fn rejects_garbage_json() {
        assert!(matches!(
            IntegrityVerdict::from_decoded_json("not json"),
            Err(PlayIntegrityError::Malformed(_))
        ));
    }
}
