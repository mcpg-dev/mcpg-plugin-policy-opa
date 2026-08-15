//! Operator-supplied configuration for the OPA policy engine.
//!
//! v0.2 scope: both `mode: remote` (OPA REST `Data` API) and
//! `mode: embedded` (compiled rego via wasmtime) are accepted.
//! Embedded mode requires `policy_bundle.{source_path, sha256,
//! entrypoint}`; remote mode requires `remote.{url, package}`.

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaPolicyConfig {
    /// Deployment mode.
    pub mode: Mode,

    /// Required when `mode: remote`. Ignored otherwise.
    #[serde(default)]
    pub remote: Option<RemoteConfig>,

    /// Required when `mode: embedded`. Ignored otherwise.
    #[serde(default)]
    pub policy_bundle: Option<EmbeddedBundleConfig>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// OPA REST `Data` API at a configured URL. Operates against
    /// any standalone OPA server.
    Remote,
    /// Rego compiled to WASM via `opa build -t wasm`. The plugin
    /// runs the WASM in-process via wasmtime — no external OPA
    /// dependency.
    Embedded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    /// OPA server URL — `http://opa:8181` or `https://opa.svc:8181`.
    pub url: String,

    /// Rego package the plugin queries for decisions. The plugin
    /// POSTs to `{url}/v1/data/{package}` (slashes in the package
    /// name preserved per OPA's HTTP path scheme; `pkg.subpkg`
    /// becomes `pkg/subpkg`).
    pub package: String,

    /// Per-evaluation timeout (ms). Includes connect + request +
    /// response decode.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// TLS knobs. Only consulted for `https://` URLs.
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Future use: forward MCPG decisions into OPA's own decision
    /// log. Not implemented in v0.1; flag is parsed but no-op.
    #[serde(default)]
    pub decision_log_forwarding: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to a CA-cert bundle the plugin trusts in addition to
    /// the system roots.
    #[serde(default)]
    pub ca_cert: Option<String>,
    #[serde(default = "default_verify_peer")]
    pub verify_peer: bool,
}

/// Reserved shape for v0.2's embedded mode. The field names are
/// fixed now so v0.2 can wire them without operator-config churn.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedBundleConfig {
    pub source_path: String,
    pub sha256: String,
    pub entrypoint: String,
    #[serde(default)]
    pub reload: Option<EmbeddedReloadConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedReloadConfig {
    #[serde(default = "default_reload_enabled")]
    pub enabled: bool,
    #[serde(default = "default_reload_check_interval_sec")]
    pub check_interval_sec: u64,
}

fn default_timeout_ms() -> u64 {
    500
}
fn default_verify_peer() -> bool {
    true
}
fn default_reload_enabled() -> bool {
    true
}
fn default_reload_check_interval_sec() -> u64 {
    60
}

impl OpaPolicyConfig {
    pub fn parse(config_json: &str) -> Result<Self, ConfigError> {
        let cfg: Self = serde_json::from_str(config_json)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        match self.mode {
            Mode::Remote => {
                if self.policy_bundle.is_some() {
                    return Err(ConfigError::Invalid(
                        "`policy_bundle` is for `mode: embedded` only — \
                         omit when `mode: remote`"
                            .into(),
                    ));
                }
                let remote = self.remote.as_ref().ok_or_else(|| {
                    ConfigError::Invalid("`remote` is required when `mode: remote`".into())
                })?;
                if remote.url.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "`remote.url` must not be empty".into(),
                    ));
                }
                if !(remote.url.starts_with("http://") || remote.url.starts_with("https://")) {
                    return Err(ConfigError::Invalid(format!(
                        "`remote.url` must use scheme http:// or https:// — got `{}`",
                        remote.url
                    )));
                }
                if remote.package.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "`remote.package` must not be empty (e.g. `mcpg/allow`)".into(),
                    ));
                }
                if remote.timeout_ms == 0 {
                    return Err(ConfigError::Invalid(
                        "`remote.timeout_ms` must be > 0".into(),
                    ));
                }
            }
            Mode::Embedded => {
                if self.remote.is_some() {
                    return Err(ConfigError::Invalid(
                        "`remote` is for `mode: remote` only — \
                         omit when `mode: embedded`"
                            .into(),
                    ));
                }
                let bundle = self.policy_bundle.as_ref().ok_or_else(|| {
                    ConfigError::Invalid(
                        "`policy_bundle` is required when `mode: embedded` \
                         (set source_path + sha256 + entrypoint)"
                            .into(),
                    )
                })?;
                if bundle.source_path.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "`policy_bundle.source_path` must not be empty".into(),
                    ));
                }
                if bundle.sha256.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "`policy_bundle.sha256` must not be empty — \
                         compute via `sha256sum policy.wasm`"
                            .into(),
                    ));
                }
                if bundle.entrypoint.trim().is_empty() {
                    return Err(ConfigError::Invalid(
                        "`policy_bundle.entrypoint` must not be empty \
                         (e.g. `mcpg/allow`)"
                            .into(),
                    ));
                }
                if let Some(reload) = &bundle.reload
                    && reload.check_interval_sec == 0
                {
                    return Err(ConfigError::Invalid(
                        "`policy_bundle.reload.check_interval_sec` must be > 0".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote_blob() -> &'static str {
        r#"{
            "mode": "remote",
            "remote": {
                "url": "http://opa:8181",
                "package": "mcpg/allow"
            }
        }"#
    }

    #[test]
    fn minimal_remote_parses() {
        let cfg = OpaPolicyConfig::parse(remote_blob()).unwrap();
        assert_eq!(cfg.mode, Mode::Remote);
        let r = cfg.remote.unwrap();
        assert_eq!(r.url, "http://opa:8181");
        assert_eq!(r.package, "mcpg/allow");
        assert_eq!(r.timeout_ms, 500);
        assert!(!r.decision_log_forwarding);
    }

    #[test]
    fn embedded_mode_now_accepted_in_v02() {
        let cfg = OpaPolicyConfig::parse(
            r#"{"mode": "embedded", "policy_bundle": {"source_path": "/etc/policy.wasm", "sha256": "abc", "entrypoint": "mcpg/allow"}}"#,
        )
        .unwrap();
        assert_eq!(cfg.mode, Mode::Embedded);
        let bundle = cfg.policy_bundle.unwrap();
        assert_eq!(bundle.source_path, "/etc/policy.wasm");
        assert_eq!(bundle.entrypoint, "mcpg/allow");
    }

    #[test]
    fn embedded_mode_without_policy_bundle_rejected() {
        let err = OpaPolicyConfig::parse(r#"{"mode": "embedded"}"#).unwrap_err();
        assert!(err.to_string().contains("policy_bundle"));
    }

    #[test]
    fn embedded_mode_with_remote_block_rejected() {
        let err = OpaPolicyConfig::parse(
            r#"{
                "mode": "embedded",
                "policy_bundle": {"source_path": "/x", "sha256": "h", "entrypoint": "e"},
                "remote": {"url": "http://x", "package": "p"}
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("remote"));
    }

    #[test]
    fn embedded_empty_source_path_rejected() {
        let err = OpaPolicyConfig::parse(
            r#"{"mode": "embedded", "policy_bundle": {"source_path": "", "sha256": "h", "entrypoint": "e"}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("source_path"));
    }

    #[test]
    fn embedded_empty_sha256_rejected() {
        let err = OpaPolicyConfig::parse(
            r#"{"mode": "embedded", "policy_bundle": {"source_path": "/x", "sha256": "", "entrypoint": "e"}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn embedded_empty_entrypoint_rejected() {
        let err = OpaPolicyConfig::parse(
            r#"{"mode": "embedded", "policy_bundle": {"source_path": "/x", "sha256": "h", "entrypoint": ""}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("entrypoint"));
    }

    #[test]
    fn embedded_zero_reload_interval_rejected() {
        let err = OpaPolicyConfig::parse(
            r#"{"mode": "embedded", "policy_bundle": {"source_path": "/x", "sha256": "h", "entrypoint": "e", "reload": {"enabled": true, "check_interval_sec": 0}}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("check_interval_sec"));
    }

    #[test]
    fn remote_without_remote_block_rejected() {
        let err = OpaPolicyConfig::parse(r#"{"mode": "remote"}"#).unwrap_err();
        assert!(err.to_string().contains("`remote` is required"));
    }

    #[test]
    fn empty_url_rejected() {
        let err =
            OpaPolicyConfig::parse(r#"{"mode": "remote", "remote": {"url": "", "package": "p"}}"#)
                .unwrap_err();
        assert!(err.to_string().contains("url"));
    }

    #[test]
    fn ftp_url_rejected() {
        let err = OpaPolicyConfig::parse(
            r#"{"mode": "remote", "remote": {"url": "ftp://x", "package": "p"}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("scheme"));
    }

    #[test]
    fn empty_package_rejected() {
        let err = OpaPolicyConfig::parse(
            r#"{"mode": "remote", "remote": {"url": "http://x", "package": ""}}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("package"));
    }

    #[test]
    fn unknown_field_rejected() {
        let err = OpaPolicyConfig::parse(
            r#"{"mode": "remote", "remote": {"url": "http://x", "package": "p"}, "bogus": 1}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn policy_bundle_rejected_in_remote_mode() {
        let err = OpaPolicyConfig::parse(
            r#"{
                "mode": "remote",
                "remote": {"url": "http://x", "package": "p"},
                "policy_bundle": {"source_path": "/x", "sha256": "h", "entrypoint": "e"}
            }"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("policy_bundle"));
        assert!(err.to_string().contains("embedded"));
    }

    #[test]
    fn embedded_reload_enabled_parses() {
        let cfg = OpaPolicyConfig::parse(
            r#"{"mode": "embedded", "policy_bundle": {"source_path": "/x", "sha256": "h", "entrypoint": "e", "reload": {"enabled": true, "check_interval_sec": 30}}}"#,
        )
        .unwrap();
        let bundle = cfg.policy_bundle.unwrap();
        let reload = bundle.reload.unwrap();
        assert!(reload.enabled);
        assert_eq!(reload.check_interval_sec, 30);
    }

    #[test]
    fn embedded_reload_disabled_parses() {
        let cfg = OpaPolicyConfig::parse(
            r#"{"mode": "embedded", "policy_bundle": {"source_path": "/x", "sha256": "h", "entrypoint": "e", "reload": {"enabled": false, "check_interval_sec": 60}}}"#,
        )
        .unwrap();
        let reload = cfg.policy_bundle.unwrap().reload.unwrap();
        assert!(!reload.enabled);
    }

    #[test]
    fn embedded_reload_defaults_to_enabled_when_block_present() {
        // `reload.enabled` field uses default = "default_reload_enabled"
        // (which returns true). So `{"reload": {"check_interval_sec": 60}}`
        // parses as enabled=true.
        let cfg = OpaPolicyConfig::parse(
            r#"{"mode": "embedded", "policy_bundle": {"source_path": "/x", "sha256": "h", "entrypoint": "e", "reload": {"check_interval_sec": 60}}}"#,
        )
        .unwrap();
        let reload = cfg.policy_bundle.unwrap().reload.unwrap();
        assert!(reload.enabled);
    }
}
