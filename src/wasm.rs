//! Embedded OPA WASM runtime.
//!
//! Loads a `policy.wasm` produced by `opa build -t wasm` and runs
//! evaluations in-process via `wasmtime`. The OPA WASM ABI
//! (opa_malloc / opa_eval_ctx_new / opa_json_dump etc.) is wrapped
//! by the `opa-wasm` crate so this module only deals with the
//! plugin-side glue: SHA-256 verification, lazy compilation, and
//! the eval-call shape.
//!
//! ## Eval lifecycle
//!
//! Each `evaluate` call gets a fresh wasmtime [`Store`] +
//! [`Runtime`] + [`Policy`]. That's not zero-cost — instantiation
//! is on the millisecond order — but it keeps the eval state
//! machine simple: no shared mutable state, no thread-safety
//! puzzles around the eval context, no ergonomic hazards from
//! pooling the store across requests. Production-rate operators
//! who hit the per-request cost can revisit pooling in v0.3.
//!
//! ## OPA result shape
//!
//! `Policy::evaluate` deserializes whatever shape OPA's WASM
//! emitted, which for the canonical rule shape is the
//! result-set array: `[{"result": <decision-document>}]`. The
//! plugin unwraps this in [`unwrap_result_set`] before handing
//! the decision document off to `decision::parse_decision`.

use opa_wasm::Runtime;
use opa_wasm::wasmtime::{Config, Engine, Module, Store};
use serde_json::Value;

use crate::error::ConfigError;

/// Compiled OPA policy ready for evaluation.
pub(crate) struct WasmRuntime {
    engine: Engine,
    module: Module,
    /// SHA-256 of the bundle bytes loaded at registration. Surfaced
    /// via `bundle_sha256()` for the plugin's `policy_version`
    /// stamping. Computed independently of the
    /// `mcpg_bundle_reload::BundleSource` fingerprint (which mixes
    /// the path into its hash); operators expect `policy_version.hash`
    /// to depend purely on bundle bytes, so we keep both.
    bundle_sha256: String,
    entrypoint: String,
}

impl WasmRuntime {
    /// Compile pre-read bytes. Used by the `mcpg_bundle_reload`
    /// parser closure: it reads the bundle file, computes a fresh
    /// SHA, and passes it as `expected_sha256` so verification
    /// always passes on rotated files. On the very first parse
    /// the parser supplies `EmbeddedBundleConfig::sha256` to
    /// preserve the boot-time supply-chain check.
    pub(crate) fn from_bytes(
        bytes: &[u8],
        expected_sha256: &str,
        entrypoint: &str,
    ) -> Result<Self, ConfigError> {
        let actual = sha256_hex(bytes);
        if !sha_matches(&actual, expected_sha256) {
            return Err(ConfigError::Invalid(format!(
                "policy_bundle.sha256 mismatch — config says {expected_sha256} but file is sha256:{actual}",
            )));
        }

        // opa-wasm ≥0.2 + wasmtime ≥42 made `async_support` the
        // default; the explicit toggle is deprecated. `Config::new()`
        // alone is enough for the async APIs opa-wasm uses
        // internally (memory.grow_async, etc.).
        let wasm_cfg = Config::new();
        let engine = Engine::new(&wasm_cfg)
            .map_err(|e| ConfigError::Invalid(format!("wasmtime engine init: {e}")))?;
        let module = Module::new(&engine, bytes).map_err(|e| {
            ConfigError::Invalid(format!("policy_bundle: failed to compile WASM: {e}"))
        })?;

        Ok(Self {
            engine,
            module,
            bundle_sha256: actual,
            entrypoint: entrypoint.to_owned(),
        })
    }

    /// Hex SHA-256 of the bytes the plugin loaded. Matches
    /// `EmbeddedBundleConfig::sha256` once the validator passes.
    pub(crate) fn bundle_sha256(&self) -> &str {
        &self.bundle_sha256
    }

    pub(crate) fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    /// Run a single OPA evaluation. The async opa-wasm API is
    /// required (see [`from_config`]'s `async_support(true)`); the
    /// trait is sync so the caller wraps this in
    /// `runtime.block_on(...)`.
    pub(crate) async fn evaluate(&self, input: &Value) -> Result<Value, String> {
        let mut store = Store::new(&self.engine, ());
        let runtime = Runtime::new(&mut store, &self.module)
            .await
            .map_err(|e| format!("opa wasm runtime init: {e}"))?;

        // OPA WASM bundles can be queried with arbitrary
        // top-level data documents. The plugin doesn't load any —
        // operators inject data via `input.context.*` instead.
        let policy = runtime
            .with_data(&mut store, &Value::Object(serde_json::Map::new()))
            .await
            .map_err(|e| format!("opa wasm with_data: {e}"))?;

        let raw: Value = policy
            .evaluate(&mut store, &self.entrypoint, input)
            .await
            .map_err(|e| format!("opa wasm evaluate `{}`: {e}", self.entrypoint))?;

        Ok(unwrap_result_set(raw))
    }
}

/// OPA WASM eval returns a result-set array shaped like
/// `[{"result": <decision-document>}]`. Unwrap to the inner
/// document so the existing `decision::parse_decision` handles
/// it without a remote/embedded fork.
///
/// Edge cases:
/// - Empty array — entrypoint matched no rules → return null
///   (which `parse_decision` maps to `NotApplicable`).
/// - Missing `result` member — return null (same fallback).
/// - Already-unwrapped value (defensive) — pass through.
pub(crate) fn unwrap_result_set(raw: Value) -> Value {
    match raw {
        Value::Array(mut arr) => {
            if let Some(first) = arr.pop() {
                if let Value::Object(mut obj) = first {
                    obj.remove("result").unwrap_or(Value::Null)
                } else {
                    first
                }
            } else {
                Value::Null
            }
        }
        other => other,
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Match a computed SHA against an operator-supplied value,
/// tolerating optional `sha256:` prefix + case differences.
fn sha_matches(actual: &str, expected: &str) -> bool {
    let stripped = expected.strip_prefix("sha256:").unwrap_or(expected);
    actual.eq_ignore_ascii_case(stripped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unwrap_handles_canonical_result_set() {
        let raw = json!([{"result": {"allow": true}}]);
        assert_eq!(unwrap_result_set(raw), json!({"allow": true}));
    }

    #[test]
    fn unwrap_empty_array_yields_null() {
        let raw = json!([]);
        assert_eq!(unwrap_result_set(raw), Value::Null);
    }

    #[test]
    fn unwrap_missing_result_key_yields_null() {
        let raw = json!([{"unrelated": 1}]);
        assert_eq!(unwrap_result_set(raw), Value::Null);
    }

    #[test]
    fn unwrap_passes_through_already_unwrapped() {
        let raw = json!({"allow": true});
        assert_eq!(unwrap_result_set(raw.clone()), raw);
    }

    #[test]
    fn unwrap_passes_through_bool() {
        let raw = json!(true);
        assert_eq!(unwrap_result_set(raw.clone()), raw);
    }

    #[test]
    fn sha_matches_with_prefix() {
        assert!(sha_matches("abcd1234", "sha256:abcd1234"));
        assert!(sha_matches("abcd1234", "abcd1234"));
        assert!(sha_matches("ABCD1234", "abcd1234"));
        assert!(!sha_matches("abcd1234", "deadbeef"));
    }

    #[test]
    fn sha256_hex_known_vector() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
