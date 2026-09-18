//! Unified verification config (feature `config`).
//!
//! A single TOML file is the one place a developer sets everything needed to
//! verify proofs from *their* app — so neither this crate nor `octet-verify`
//! hardcodes any identity or Google-project detail. The library itself stays
//! parameter-based; this module just loads the file into those parameters.
//!
//! ```toml
//! # octet-attest-verify.toml
//! [app_attest]
//! team_id     = "ABCDE12345"
//! bundle_id   = "com.example.app"
//! environment = "production"        # "development" | "production" | "any"
//!
//! [play_integrity]                  # optional; only for the Android path
//! cloud_project_number = 123456789012
//! # One or more accepted package names — the decoded token's requestPackageName
//! # must be one of these (e.g. a public + an internal build variant).
//! package_names        = ["com.example.app", "com.example.app.internal"]
//! # Path to the service-account JSON used to decode tokens. NEVER commit this
//! # file — keep it local and reference it by path.
//! service_account_json = "/secrets/play-integrity-sa.json"
//! ```

use serde::Deserialize;
use std::path::Path;

/// Top-level config, loaded from one TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// iOS Apple App Attest expectations. Optional so an Android-only
    /// integrator can omit it.
    pub app_attest: Option<AppAttestConfig>,
    /// Android Play Integrity settings. Optional so an iOS-only integrator can
    /// omit it.
    pub play_integrity: Option<PlayIntegrityConfig>,
}

/// Expected iOS app identity + environment.
#[derive(Debug, Clone, Deserialize)]
pub struct AppAttestConfig {
    /// Apple Developer Team ID, e.g. `"ABCDE12345"`.
    pub team_id: String,
    /// App bundle identifier, e.g. `"com.example.app"`.
    pub bundle_id: String,
    /// Which App Attest environment to accept. Defaults to `Any`.
    #[serde(default)]
    pub environment: Environment,
}

/// Which App Attest environment a verifier accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Accept only attestations from the development environment.
    Development,
    /// Accept only attestations from the production environment.
    Production,
    /// Accept either. Default — most permissive, useful while integrating.
    #[default]
    Any,
}

impl From<Environment> for crate::appattest::AcceptEnvironment {
    fn from(e: Environment) -> Self {
        match e {
            Environment::Development => crate::appattest::AcceptEnvironment::Development,
            Environment::Production => crate::appattest::AcceptEnvironment::Production,
            Environment::Any => crate::appattest::AcceptEnvironment::Any,
        }
    }
}

/// Google Play Integrity decode settings (used by the `playintegrity` layer).
#[derive(Debug, Clone, Deserialize)]
pub struct PlayIntegrityConfig {
    /// The Cloud project number the app's Play Integrity is linked to.
    pub cloud_project_number: u64,
    /// The app package name(s) the token is accepted for — the decoded token's
    /// `requestPackageName` must be one of these. A set so a public build and an
    /// internal/variant build (e.g. `…` and `….internal`) can share one config.
    pub package_names: Vec<String>,
    /// Path to the service-account JSON used to decode tokens. Referenced by
    /// path only — the file is never read into config and never committed.
    pub service_account_json: Option<String>,
}

impl Config {
    /// Load and parse the config from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::from_toml_str(&text)
    }

    /// Parse the config from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// The expected [`AppId`](crate::appattest::AppId) hash from the
    /// `[app_attest]` section, if configured.
    pub fn expected_app_id(&self) -> Option<crate::appattest::AppId> {
        self.app_attest
            .as_ref()
            .map(|a| crate::appattest::AppId::from_team_and_bundle(&a.team_id, &a.bundle_id))
    }
}

/// Config load/parse failures.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config file: {0}")]
    Io(String),
    #[error("parsing config TOML: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let cfg = Config::from_toml_str(
            r#"
            [app_attest]
            team_id = "6ZH5F97PWU"
            bundle_id = "com.octetproof.tester"
            environment = "development"

            [play_integrity]
            cloud_project_number = 123456789012
            package_names = ["com.octetproof.tester", "com.octetproof.tester.internal"]
            service_account_json = "/secrets/sa.json"
            "#,
        )
        .expect("valid config");

        let aa = cfg.app_attest.as_ref().unwrap();
        assert_eq!(aa.team_id, "6ZH5F97PWU");
        assert_eq!(aa.environment, Environment::Development);
        let pi = cfg.play_integrity.as_ref().unwrap();
        assert_eq!(pi.cloud_project_number, 123456789012);
        assert_eq!(
            pi.package_names,
            vec!["com.octetproof.tester".to_string(), "com.octetproof.tester.internal".to_string()]
        );
        // expected_app_id matches the documented App ID hash.
        assert_eq!(
            cfg.expected_app_id().unwrap(),
            crate::appattest::AppId::from_team_and_bundle("6ZH5F97PWU", "com.octetproof.tester")
        );
    }

    #[test]
    fn environment_defaults_to_any() {
        let cfg = Config::from_toml_str(
            r#"
            [app_attest]
            team_id = "T"
            bundle_id = "b"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.app_attest.unwrap().environment, Environment::Any);
    }

    #[test]
    fn ios_only_config_omits_play_integrity() {
        let cfg = Config::from_toml_str(
            "[app_attest]\nteam_id=\"T\"\nbundle_id=\"b\"\n",
        )
        .unwrap();
        assert!(cfg.play_integrity.is_none());
    }
}
