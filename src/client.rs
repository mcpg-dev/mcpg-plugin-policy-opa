//! Minimal OPA REST client.
//!
//! Single endpoint: `POST {base_url}/v1/data/{package_path}` with
//! body `{"input": <input-document>}`. Response shape:
//!
//! ```json
//! {"result": <result>}
//! ```
//!
//! `<result>` is whatever the policy package or rule produces — a
//! boolean for a single rule (`/v1/data/mcpg/allow`), or an object
//! for a package-level query (`/v1/data/mcpg`). Both shapes flow
//! through to the decision-document parser in `decision.rs`.

use std::time::Duration;

use mcpg_plugin_protocol::policy::PolicyDecision;
use reqwest::{Client as HttpClient, StatusCode};
use serde::Deserialize;

use crate::config::RemoteConfig;

/// Wrapper over `reqwest::Client` pinned to one OPA endpoint.
pub(crate) struct OpaClient {
    http: HttpClient,
    /// Pre-built data URL: `{base}/v1/data/{package_path}`.
    data_url: String,
    timeout: Duration,
}

impl OpaClient {
    pub(crate) fn from_config(cfg: &RemoteConfig) -> Result<Self, String> {
        let mut builder = HttpClient::builder()
            .connect_timeout(Duration::from_millis(cfg.timeout_ms))
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .user_agent(format!(
                "mcpg-plugin-policy-opa/{}",
                env!("CARGO_PKG_VERSION")
            ));
        if let Some(tls) = &cfg.tls {
            if let Some(ca_path) = &tls.ca_cert {
                let pem = std::fs::read(ca_path)
                    .map_err(|e| format!("opa tls: failed to read ca_cert {ca_path}: {e}"))?;
                let cert = reqwest::Certificate::from_pem(&pem)
                    .map_err(|e| format!("opa tls: invalid ca_cert {ca_path}: {e}"))?;
                builder = builder.add_root_certificate(cert);
            }
            if !tls.verify_peer {
                builder = builder.danger_accept_invalid_certs(true);
            }
        }
        let http = builder
            .build()
            .map_err(|e| format!("opa http builder: {e}"))?;

        // OPA expects the package path to use `/` separators after
        // `/v1/data/`. Operators sometimes write the rego dot-form
        // (`mcpg.policies.allow`) — translate transparently.
        let path = cfg.package.replace('.', "/");
        let base = cfg.url.trim_end_matches('/');
        let data_url = format!("{base}/v1/data/{path}");

        Ok(Self {
            http,
            data_url,
            timeout: Duration::from_millis(cfg.timeout_ms),
        })
    }

    /// Issue an OPA evaluation. Returns the raw `result` value or
    /// a [`PolicyDecision::deny(...)`] capturing the failure.
    /// Trait contract is "no Result" so failures get encoded as
    /// Deny up the stack — `policy_version` is supplied by the
    /// caller so an early Deny still carries the audit stamp.
    pub(crate) async fn evaluate_raw(
        &self,
        input: serde_json::Value,
        policy_version_hash: &str,
    ) -> Result<serde_json::Value, PolicyDecision> {
        let body = serde_json::json!({ "input": input });
        let send = self.http.post(&self.data_url).json(&body).send();

        let resp = match tokio::time::timeout(self.timeout, send).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::warn!(
                    url = %self.data_url,
                    error = %e,
                    "opa policy: HTTP error during evaluate"
                );
                return Err(PolicyDecision::deny(
                    format!("opa remote error: {e}"),
                    policy_version_hash,
                ));
            }
            Err(_) => {
                tracing::warn!(
                    url = %self.data_url,
                    "opa policy: timeout"
                );
                return Err(PolicyDecision::deny("opa timeout", policy_version_hash));
            }
        };

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let snippet = body.lines().next().unwrap_or("").trim();
            tracing::warn!(
                url = %self.data_url,
                status = %status,
                body = %snippet,
                "opa policy: non-2xx response"
            );
            // 404 is special — OPA returns 404 when the queried path
            // produces no value (rule doesn't fire AND has no
            // default). That maps to NotApplicable so
            // the engine declines cleanly.
            if status == StatusCode::NOT_FOUND {
                return Err(PolicyDecision::not_applicable(policy_version_hash));
            }
            return Err(PolicyDecision::deny(
                format!("opa remote error: HTTP {status}"),
                policy_version_hash,
            ));
        }

        let parsed: DataResponse = match serde_json::from_str(&body) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    url = %self.data_url,
                    error = %e,
                    body_snippet = %body.chars().take(200).collect::<String>(),
                    "opa policy: response decode"
                );
                return Err(PolicyDecision::deny(
                    format!("opa response decode: {e}"),
                    policy_version_hash,
                ));
            }
        };

        Ok(parsed.result.unwrap_or(serde_json::Value::Null))
    }
}

#[derive(Debug, Deserialize)]
struct DataResponse {
    /// Absent when the policy path produced no result. Trait-impl
    /// layer maps absent → NotApplicable.
    #[serde(default)]
    result: Option<serde_json::Value>,
}
