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
}

/// Device-integrity level from the token's `deviceIntegrity` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceIntegrity {
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
    #[error("token package name does not match the expected package")]
    PackageMismatch,
}

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

        let (request_package_name, nonce) = match payload.request_details {
            Some(rd) => {
                let nonce = match rd.nonce {
                    Some(n) => decode_nonce(&n)?,
                    None => Vec::new(),
                };
                (rd.request_package_name, nonce)
            }
            None => (None, Vec::new()),
        };

        Ok(IntegrityVerdict {
            device_integrity,
            app_recognition,
            request_package_name,
            nonce,
        })
    }

    /// Confirm the token binds to the proof: its nonce equals the proof's
    /// `attestation_nonce` and (if an expected package is given) its package
    /// matches.
    pub fn check_binding(
        &self,
        expected_nonce: &[u8],
        expected_package: Option<&str>,
    ) -> Result<(), PlayIntegrityError> {
        if self.nonce != expected_nonce {
            return Err(PlayIntegrityError::NonceMismatch);
        }
        if let Some(pkg) = expected_package {
            if self.request_package_name.as_deref() != Some(pkg) {
                return Err(PlayIntegrityError::PackageMismatch);
            }
        }
        Ok(())
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
    fn binding_checks_nonce_and_package() {
        let nonce = [7u8; 32];
        let b64 = base64::engine::general_purpose::STANDARD.encode(nonce);
        let v = IntegrityVerdict::from_decoded_json(&sample(
            &b64,
            "PLAY_RECOGNIZED",
            "MEETS_DEVICE_INTEGRITY",
        ))
        .unwrap();

        assert!(v.check_binding(&nonce, Some("com.octetproof.tester")).is_ok());
        assert_eq!(
            v.check_binding(&[0u8; 32], Some("com.octetproof.tester")),
            Err(PlayIntegrityError::NonceMismatch)
        );
        assert_eq!(
            v.check_binding(&nonce, Some("com.evil.app")),
            Err(PlayIntegrityError::PackageMismatch)
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
