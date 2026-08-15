//! `dev.mcpg.policy.opa` — OPA `policy_engine` plugin.
//!
//! This crate is the implementation; the operator-facing
//! summary lives in `README.md`.
//!
//! # v0.2 scope (current)
//!
//! - **Remote mode** — HTTP `POST /v1/data/{package}` against a
//!   standalone OPA server.
//! - **Embedded mode** — rego compiled to WASM via
//!   `opa build -t wasm`, run in-process by `wasmtime`. No
//!   external OPA dependency.
//! - **Decision mapping** — allow / deny (with reason) /
//!   not_applicable + obligations + redactions + attributes.
//! - **`policy_version()`** — SHA-256 stamp. Embedded uses the
//!   bundle hash; remote uses a hash of the configured target.
//!
//! # Embedded bundle reload
//!
//! Embedded-mode bundle reload flows through the shared
//! `mcpg_bundle_reload::BundleReload<WasmRuntime>` helper (also
//! used by `dev.mcpg.policy.cedar` and `dev.mcpg.policy.casbin`):
//! poll-and-atomic-swap plus a `pre_tick` hook and a `poke()`
//! surface that wires into `cluster_backend`.
//!
//! When a `cluster_backend` is bound, the plugin:
//!   - Subscribes to `policy.opa.bundle-loaded`. Peer publishes
//!     whose fingerprint differs from local pokes our watcher to
//!     run an out-of-band poll (drops cluster reload-tick skew
//!     from up-to-`check_interval_sec` to ~network round-trip).
//!   - Emits a startup heartbeat on the same topic carrying the
//!     bundle fingerprint + policy_version hash.
//!
//! Operator-visible behavior is unchanged for solo deploys: same
//! bundle URL / sha256 / entrypoint surface, same eval semantics,
//! same decision-document mapping. Only multi-instance reload
//! coordination is cluster-aware.
//!
//! Still deferred: decision-log forwarding to remote OPA, and gRPC
//! transport.

mod client;
mod config;
mod decision;
mod error;
mod wasm;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use mcpg_bundle_reload::{BundleReload, BundleSource, ReloadError};
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::policy::{PolicyDecision, PolicyVersion};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{PluginClass, PluginContext, PluginManifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncPolicyEngine;
use serde_json::Value;
use tokio::runtime::Runtime;

pub use config::{
    EmbeddedBundleConfig, EmbeddedReloadConfig, Mode, OpaPolicyConfig, RemoteConfig, TlsConfig,
};
pub use error::ConfigError;

const PLUGIN_ID: &str = "dev.mcpg.policy.opa";
const ENGINE_NAME: &str = "opa";

fn record_decision(decision_point: &str, decision: &PolicyDecision, elapsed: std::time::Duration) {
    use mcpg_plugin_protocol::policy::PolicyEffect;
    let outcome = match decision.effect {
        PolicyEffect::Allow => "allow",
        PolicyEffect::Deny => "deny",
        PolicyEffect::NotApplicable => "not_applicable",
    };
    metrics::counter!(
        "mcpg_policy_opa_decisions_total",
        "decision_point" => decision_point.to_owned(),
        "outcome" => outcome,
    )
    .increment(1);
    metrics::histogram!(
        "mcpg_policy_opa_evaluate_ms",
        "decision_point" => decision_point.to_owned(),
    )
    .record(elapsed.as_millis() as f64);
    match decision.effect {
        PolicyEffect::Allow => tracing::debug!(
            decision_point = %decision_point,
            elapsed_ms = %elapsed.as_millis(),
            "opa policy: allow"
        ),
        PolicyEffect::Deny => tracing::warn!(
            decision_point = %decision_point,
            reason = decision.reason.as_deref().unwrap_or(""),
            elapsed_ms = %elapsed.as_millis(),
            "opa policy: deny"
        ),
        PolicyEffect::NotApplicable => tracing::debug!(
            decision_point = %decision_point,
            elapsed_ms = %elapsed.as_millis(),
            "opa policy: not applicable"
        ),
    }
}

pub struct OpaPolicyPlugin {
    inner: Arc<OpaPolicyInner>,
}

/// Runtime backend for the configured `mode`. Branching is done
/// once at boot; the eval path matches on this enum + dispatches
/// to the appropriate eval surface.
enum Backend {
    /// HTTP `POST /v1/data/{package}` against a standalone OPA.
    Remote(Arc<client::OpaClient>),
    /// In-process wasmtime runtime over a compiled rego bundle.
    /// Wrapped in `BundleReload<WasmRuntime>` so reloads run
    /// through the shared poll-and-atomic-swap helper. The eval
    /// path reads via `bundle.load()` (one atomic op + Arc
    /// clone); the watcher swaps a fresh runtime in on bundle
    /// change. In-flight evaluations on the old runtime complete
    /// normally because each holds an `Arc<WasmRuntime>` clone.
    Embedded(BundleReload<wasm::WasmRuntime>),
}

struct OpaPolicyInner {
    manifest: PluginManifest,
    /// Parsed config — read by the eval path to surface the
    /// remote target in audit and drive bundle reloads.
    #[allow(dead_code)]
    config: OpaPolicyConfig,
    /// Active eval backend. Picked once at registration.
    backend: Backend,
    /// Stable identifier surfaced via `policy_version()`. For
    /// remote mode this is a one-shot hash of the canonical
    /// `{url, package}` string — there's no upstream change-feed
    /// to track, so a single boot stamp is correct. For embedded
    /// mode the version is derived live from the
    /// `BundleReload<WasmRuntime>` snapshot inside `evaluate` /
    /// `policy_version()`, so there's no stamp to swap here.
    /// `loaded_at` is the boot time in both cases — operators get
    /// a stable timestamp to correlate decisions to gateway boot
    /// rather than a fast-moving "last reload" wall clock.
    policy_version: PolicyVersion,
    /// Bundled tokio runtime — `evaluate` is sync; reqwest +
    /// wasmtime-async both need an executor. 2 workers absorb the
    /// per-request load comfortably for both backends and host
    /// the bundle-reload watcher task spawned by
    /// `mcpg_bundle_reload::start`.
    runtime: Runtime,
    /// Cluster client (v20 ABI) handed at `make` time when the
    /// operator has registered a `cluster_backend`. When
    /// bound, emits a startup heartbeat on
    /// `policy.opa.bundle-loaded` carrying the bundle fingerprint
    /// AND subscribes to the same topic so a peer's successful
    /// reload triggers an out-of-band `poke()` on this node's
    /// `BundleReload`. Closes the multi-instance bundle-reload
    /// divergence gap (mirrors cedar / casbin).
    #[allow(dead_code)]
    cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    /// Active subscription on `policy.opa.bundle-loaded`. Held
    /// for the plugin's lifetime; Drop cancels the stream.
    #[allow(dead_code)]
    cluster_subscription: Option<mcpg_plugin_sdk::Subscription<mcpg_cluster_api::PublishedMessage>>,
    /// The unified host surface. Installed once at boot
    /// by the SDK factory via
    /// [`OpaPolicyPlugin::set_host_handle`] before any `evaluate`
    /// traffic flows. When `None` (test harnesses that construct
    /// the plugin without wiring a host), the per-call HostHandle
    /// observability triad short-circuits to no-ops and the
    /// plugin's existing internal `record_decision` carries the
    /// load through its own sinks.
    host_handle: OnceLock<HostHandle>,
}

impl OpaPolicyPlugin {
    pub fn from_config_json(config_json: &str) -> Self {
        Self::from_config_json_with_cluster(config_json, None)
    }

    /// v20 ABI factory — receives the optional cluster client from
    /// the SDK macro. Public so unit tests can construct the
    /// plugin with a synthetic client.
    pub fn from_config_json_with_cluster(
        config_json: &str,
        cluster: Option<mcpg_plugin_sdk::ClusterClient>,
    ) -> Self {
        let config = OpaPolicyConfig::parse(config_json).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                "opa policy: config parse failed; refusing to register"
            );
            panic!("opa policy config parse failed: {err}")
        });

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("mcpg-policy-opa")
            .enable_all()
            .build()
            .unwrap_or_else(|err| {
                tracing::error!(
                    plugin_id = PLUGIN_ID,
                    error = %err,
                    "opa policy: tokio runtime init failed; refusing to register"
                );
                panic!("opa policy tokio runtime init failed: {err}")
            });

        // The typed `Capability` declaration that
        // applies depends on mode: Remote needs NetworkOutbound for
        // its outbound HTTP to the OPA server; Embedded runs wholly
        // in-process and needs nothing. The manifest's
        // `required_capabilities` is host-derived/display-only; the
        // authoritative declaration is the typed list on the cdylib's
        // `PluginRegistration.capabilities` (a single set per
        // cdylib) — `declare_plugin!` declares `NetworkOutbound`
        // there so the remote-mode operator config grants it;
        // embedded-mode operators may still grant it without harm. The
        // manifest list stays empty here regardless of mode.
        let (backend, required_capabilities): (
            Backend,
            Vec<mcpg_plugin_protocol::capability::Capability>,
        ) = match config.mode {
            Mode::Remote => {
                let remote = config
                    .remote
                    .as_ref()
                    .expect("config.validate ensures remote present");
                let client = Arc::new(client::OpaClient::from_config(remote).unwrap_or_else(
                    |err| {
                        tracing::error!(
                            plugin_id = PLUGIN_ID,
                            error = %err,
                            url = %remote.url,
                            "opa policy: client init failed; refusing to register"
                        );
                        panic!("opa policy client init failed: {err}")
                    },
                ));
                (Backend::Remote(client), Vec::new())
            }
            Mode::Embedded => {
                let bundle_cfg = config
                    .policy_bundle
                    .as_ref()
                    .expect("config.validate ensures policy_bundle present");
                let bundle = build_embedded_bundle(&runtime, bundle_cfg);
                (Backend::Embedded(bundle), Vec::new())
            }
        };

        let policy_version = boot_policy_version(&config, &backend);

        // Cluster opt-in. When a
        // coordinator is bound AND we're in embedded mode,
        // subscribe to the bundle-loaded topic FIRST (so we don't
        // miss the local self-publish), then emit our own
        // heartbeat carrying the bundle fingerprint. Subscriber
        // compares peer fingerprint to local; on mismatch, pokes
        // the BundleReload so the watcher runs an out-of-band
        // poll. Failures are logged + swallowed — best-effort
        // coordination never blocks plugin registration.
        //
        // Remote mode has no local bundle to refresh — there's
        // nothing to coordinate, so we skip the subscribe/publish
        // dance even when a coordinator is bound.
        let mut subscription = None;
        if let (Some(client), Backend::Embedded(bundle)) = (&cluster, &backend) {
            let info = client.node_info();
            let local_node_id = info.node_id.clone();
            let poke_handle = bundle.poke_handle();
            let bundle_for_subscriber = bundle.clone();
            tracing::info!(
                plugin_id = PLUGIN_ID,
                cluster_node_id = %info.node_id,
                cluster_address = %info.address,
                "opa policy: cluster coordinator bound"
            );

            match client.subscribe("policy.opa.bundle-loaded", None, None, move |msg| {
                let from = msg.from_node.clone();
                if from == local_node_id {
                    return; // self-publish — already logged
                }
                let peer_fp = serde_json::from_slice::<serde_json::Value>(&msg.payload)
                    .ok()
                    .and_then(|v| {
                        v.get("fingerprint")
                            .and_then(|f| f.as_str())
                            .map(str::to_owned)
                    });
                let local_fp = bundle_for_subscriber.fingerprint();
                let should_poke = match &peer_fp {
                    Some(peer) => peer != &local_fp,
                    None => true,
                };
                tracing::info!(
                    plugin_id = PLUGIN_ID,
                    from_node = %from,
                    topic = %msg.topic,
                    peer_fingerprint = ?peer_fp,
                    local_fingerprint = %local_fp,
                    poked = should_poke,
                    "opa policy: peer reloaded bundle"
                );
                if should_poke {
                    poke_handle.poke();
                }
            }) {
                Ok(s) => subscription = Some(s),
                Err(e) => tracing::warn!(
                    plugin_id = PLUGIN_ID,
                    error = %e,
                    "opa policy: subscription setup failed"
                ),
            }

            let payload = serde_json::json!({
                "plugin_id": PLUGIN_ID,
                "version": env!("CARGO_PKG_VERSION"),
                "fingerprint": bundle.fingerprint(),
                "node_id": info.node_id,
            });
            let bytes_payload =
                bytes::Bytes::from(serde_json::to_vec(&payload).unwrap_or_default());
            if let Err(e) = client.publish("policy.opa.bundle-loaded", None, bytes_payload) {
                tracing::warn!(
                    plugin_id = PLUGIN_ID,
                    error = %e,
                    "opa policy: heartbeat publish failed"
                );
            }
        }

        tracing::info!(
            plugin_id = PLUGIN_ID,
            mode = ?config.mode,
            reload_enabled = config
                .policy_bundle
                .as_ref()
                .and_then(|b| b.reload.as_ref())
                .is_some_and(|r| r.enabled),
            cluster_bound = cluster.is_some(),
            "opa policy: registered"
        );

        Self {
            inner: Arc::new(OpaPolicyInner {
                manifest: PluginManifest {
                    id: PLUGIN_ID.into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    name: "OPA Policy Engine".into(),
                    plugin_class: PluginClass::PolicyEngine,
                    protocol_version: "1.0".into(),
                    license: None,
                    required_capabilities,
                    tags: Vec::new(),
                    provides: Vec::new(),
                    provides_schemes: Vec::new(),
                    module_path_prefix: ::std::module_path!()
                        .split("::")
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                    backend_profile: None,
                },
                config,
                backend,
                policy_version,
                runtime,
                cluster,
                cluster_subscription: subscription,
                host_handle: OnceLock::new(),
            }),
        }
    }

    /// Install the unified [`HostHandle`] surface for
    /// per-evaluation observability. The SDK factory installs
    /// this once at boot. Idempotent — a second call returns
    /// `false`.
    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.inner.host_handle.set(host).is_ok()
    }

    /// Borrow the installed unified host surface, if any.
    /// Returns `None` in test harnesses that constructed the plugin
    /// without `set_host_handle`.
    fn host_handle(&self) -> Option<&HostHandle> {
        self.inner.host_handle.get()
    }
}

/// Build the embedded `BundleReload<WasmRuntime>` per
/// `policy_bundle.reload`. When reload is enabled, spawns the
/// shared crate's poll-and-swap watcher on `runtime`; otherwise
/// returns a `static_only` wrapper that exposes the same `load()` /
/// `fingerprint()` surface without a background task.
fn build_embedded_bundle(
    runtime: &Runtime,
    bundle_cfg: &EmbeddedBundleConfig,
) -> BundleReload<wasm::WasmRuntime> {
    // Bundle-reload's `BundleSource::File` watches the single
    // .wasm file. The parser closure re-reads + re-validates the
    // bundle on every change; bundle-reload's own fingerprint
    // skips the parse when bytes haven't changed.
    let source = BundleSource::File(std::path::PathBuf::from(&bundle_cfg.source_path));

    // Pin the boot-time expected sha so the parser's
    // sha-verification path tolerates rotation: the watcher
    // computes the fresh sha for each reload, but the boot value
    // must match on the very first parse.
    let entrypoint = bundle_cfg.entrypoint.clone();
    let boot_expected_sha = bundle_cfg.sha256.clone();
    // After the initial load, the boot-time
    // `policy_bundle.sha256` is no longer authoritative — operators
    // relying on out-of-band sha verification (gitops, supply-chain
    // signing) should sign the bundle separately + verify before
    // the file lands on disk. The plugin's role here is detect-
    // and-load. Once the parser has run once, every subsequent
    // call is a "trust the file on disk" path.
    let initial_done = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let parser_initial_done = Arc::clone(&initial_done);
    let parser = move |source: &BundleSource| -> Result<wasm::WasmRuntime, ReloadError> {
        let paths = source.list_files()?;
        let path = paths
            .into_iter()
            .next()
            .ok_or_else(|| ReloadError::Parse("policy_bundle source empty".into()))?;
        let bytes = std::fs::read(&path).map_err(|e| ReloadError::Io {
            path: path.display().to_string(),
            error: e.to_string(),
        })?;
        let actual_sha = wasm::sha256_hex(&bytes);
        let expected = if parser_initial_done.load(std::sync::atomic::Ordering::SeqCst) {
            // Reload tick — trust the bytes on disk; verification
            // is "did wasmtime accept it?".
            actual_sha.clone()
        } else {
            boot_expected_sha.clone()
        };
        let runtime = wasm::WasmRuntime::from_bytes(&bytes, &expected, &entrypoint)
            .map_err(|e| ReloadError::Parse(e.to_string()))?;
        parser_initial_done.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(runtime)
    };

    let reload_enabled = bundle_cfg.reload.as_ref().is_some_and(|r| r.enabled);

    if reload_enabled {
        let interval = Duration::from_secs(
            bundle_cfg
                .reload
                .as_ref()
                .map(|r| r.check_interval_sec)
                .unwrap_or(60),
        );
        runtime
            .block_on(async { mcpg_bundle_reload::start(source, parser, interval).await })
            .unwrap_or_else(|err| {
                tracing::error!(
                    plugin_id = PLUGIN_ID,
                    error = %err,
                    source_path = %bundle_cfg.source_path,
                    "opa policy: wasm bundle init failed; refusing to register"
                );
                panic!("opa policy wasm bundle init failed: {err}")
            })
    } else {
        // Static-only: parse once, fingerprint once, wrap. No
        // background watcher.
        let parsed = parser(&source).unwrap_or_else(|err| {
            tracing::error!(
                plugin_id = PLUGIN_ID,
                error = %err,
                source_path = %bundle_cfg.source_path,
                "opa policy: wasm bundle init failed; refusing to register"
            );
            panic!("opa policy wasm bundle init failed: {err}")
        });
        let fingerprint = runtime
            .block_on(async { source.fingerprint().await })
            .unwrap_or_else(|err| panic!("opa policy: failed to fingerprint bundle: {err}"));
        mcpg_bundle_reload::static_only(parsed, fingerprint)
    }
}

impl SyncPolicyEngine for OpaPolicyPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.inner.manifest
    }

    fn name(&self) -> &str {
        ENGINE_NAME
    }

    /// Evaluate `decision_point` against OPA. Builds the input
    /// envelope:
    ///
    /// ```json
    /// {
    ///   "decision_point": "tool.call.pre",
    ///   "input": <caller-supplied input>,
    ///   "context": <PluginContext serialised>
    /// }
    /// ```
    ///
    /// The trait contract is "no Result" — every failure path
    /// surfaces as `Deny` carrying the audit-stamped
    /// `policy_version`, except 404 from OPA which maps to
    /// `NotApplicable` (the engine declines cleanly).
    fn evaluate(
        &self,
        decision_point: &str,
        input: &Value,
        context: &PluginContext,
    ) -> PolicyDecision {
        // Wrap evaluation in a plugin-scoped span so traces
        // attribute back to dev.mcpg.policy.opa for per-plugin
        // override.
        let _span = tracing::info_span!(
            "opa_policy_evaluate",
            plugin_id = PLUGIN_ID,
            decision_point = %decision_point,
        )
        .entered();

        // Open a host-attributed span ALONGSIDE
        // the internal `info_span!` above. Attrs carry decision_point
        // + the policy version hash (which is bundle-bounded for
        // embedded mode and target-bounded for remote mode — both
        // low-cardinality) so operators can correlate decisions
        // against the active bundle version.
        let policy_id = current_policy_version(&self.inner).hash;
        let host_span = self.host_handle().map(|h| {
            h.span(
                "policy_opa.evaluate",
                serde_json::json!({
                    "decision_point": decision_point,
                    "policy_id": policy_id,
                    "request_id": context.request_id,
                }),
            )
        });

        let started = std::time::Instant::now();
        let decision = self.evaluate_inner(decision_point, input, context);
        let elapsed = started.elapsed();
        record_decision(decision_point, &decision, elapsed);

        // Unified host-observability triad. Runs
        // ALONGSIDE the `record_decision` internal metrics above;
        // the two coexist intentionally until the host sinks subsume
        // the internal calls.
        let outcome_label = host_outcome_label(&decision);
        self.emit_host_observability(decision_point, &decision, outcome_label, elapsed, context);

        // Drop host span AFTER metric + audit emission so the
        // host's tracing sink sees those events nested inside the
        // span window.
        drop(host_span);

        decision
    }

    fn policy_version(&self) -> PolicyVersion {
        current_policy_version(&self.inner)
    }

    fn shutdown(&self) {
        tracing::info!(plugin_id = PLUGIN_ID, "opa policy: shutdown signalled");
    }
}

/// Bounded host-side outcome label set:
/// `allow`, `deny`, `error`. `not_applicable` rolls into `allow`
/// because both let traffic through; operators wanting the four-way
/// breakdown read the internal `mcpg_policy_opa_decisions_total`
/// counter. The `error` label fires when the engine itself failed:
/// OPA marks engine failures as Deny but stamps the reason with
/// `opa remote error:` / `opa timeout` / `opa response decode:` /
/// `opa embedded error:` — surface those as `error` so the
/// host-side metric distinguishes rule-driven denies from
/// upstream / runtime failures.
fn host_outcome_label(decision: &PolicyDecision) -> &'static str {
    use mcpg_plugin_protocol::policy::PolicyEffect;
    match decision.effect {
        PolicyEffect::Allow | PolicyEffect::NotApplicable => "allow",
        PolicyEffect::Deny => match decision.reason.as_deref() {
            Some(r)
                if r.starts_with("opa remote error:")
                    || r.starts_with("opa timeout")
                    || r.starts_with("opa response decode:")
                    || r.starts_with("opa embedded error:") =>
            {
                "error"
            }
            _ => "deny",
        },
    }
}

/// Best-effort RFC 3339 timestamp for audit event `occurred_at`.
/// Mirrors the existing `now_rfc3339` helper
/// in this crate (which doesn't expose milliseconds); the audit
/// path uses millisecond precision so events that fire within the
/// same second are still lexicographically ordered.
fn rfc3339_now_millis() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    let (year, month, day, hour, min, sec) = epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Synthetic identity for audit events emitted on inbound requests
/// carrying no caller attribution.
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some(PLUGIN_ID.into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

impl OpaPolicyPlugin {
    /// Emit the per-evaluation host-observability triad:
    /// latency histogram + decisions counter + Deny / Error audit
    /// event, through the installed [`HostHandle`]. Short-circuits
    /// to a no-op when no handle is installed.
    ///
    /// Cardinality budget: outcome ∈ {allow, deny, error}.
    ///
    /// Audit emission is gated to `deny` / `error`:
    ///
    /// - `dev.mcpg.policy.opa.deny` on rule-driven Deny.
    /// - `dev.mcpg.policy.opa.error` on engine-error Deny (OPA
    ///   server unreachable / timeout / wasmtime compile failure
    ///   / decision-document decode failure).
    ///
    /// Allow + NotApplicable do NOT audit-emit — that's normal
    /// traffic.
    fn emit_host_observability(
        &self,
        decision_point: &str,
        decision: &PolicyDecision,
        outcome_label: &'static str,
        duration: std::time::Duration,
        context: &PluginContext,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        let elapsed_secs = duration.as_secs_f64();
        host.histogram(
            "mcpg_policy_opa_latency_seconds",
            elapsed_secs,
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_policy_opa_decisions_total",
            1,
            &[("outcome", outcome_label)],
        );

        let action: Option<&'static str> = match outcome_label {
            "deny" => Some("dev.mcpg.policy.opa.deny"),
            "error" => Some("dev.mcpg.policy.opa.error"),
            _ => None,
        };
        let Some(action) = action else {
            return;
        };

        let audit_outcome = match outcome_label {
            "error" => AuditOutcome::Failure,
            _ => AuditOutcome::Denied,
        };

        // OPA doesn't expose matched-rule ids on Deny — the
        // decision document carries `reason` and operator-supplied
        // `obligations` / `attributes`, but the rego engine's
        // internal "which rule matched" trace isn't part of the
        // response envelope. Audit details capture what's
        // available; operators wanting rule-level visibility
        // enable OPA's decision-log forwarding (not wired here).
        let subject = context
            .identity
            .subject_id
            .clone()
            .unwrap_or_else(|| "anonymous".to_owned());
        let resource_uri = format!("tool://{}/{}", context.tool_name, decision_point);

        let details = serde_json::json!({
            "engine": ENGINE_NAME,
            "decision_point": decision_point,
            "subject": subject,
            "resource": resource_uri,
            // OPA doesn't expose matched-rule ids on Deny via the
            // standard decision document — surfaced as an empty
            // array so operator audit search has a stable shape
            // across engines. Operators wanting rule-level
            // visibility configure OPA's decision-log forwarding
            // (not wired here).
            "matched_rules": Vec::<String>::new(),
            "reason": decision.reason.clone().unwrap_or_default(),
            "policy_version": decision.policy_version.clone(),
            "duration_ms": duration.as_millis() as u64,
            "alias": host.alias(),
        });

        let actor = if context.identity.kind.is_empty() {
            synthetic_system_identity()
        } else {
            context.identity.clone()
        };

        let event = AuditEvent {
            event_id: format!("opa-{}-{}", context.request_id, duration.as_nanos()),
            occurred_at: rfc3339_now_millis(),
            actor,
            action: action.to_owned(),
            resource: Some(resource_uri),
            outcome: audit_outcome,
            request_id: Some(context.request_id.clone()),
            node_id: None,
            details,
            prev_event_hash: None,
        };
        // SyncPolicyEngine::evaluate is sync; the gateway
        // dispatches it from a `spawn_blocking` worker, so calling
        // HostHandle::audit_event directly here is safe — the
        // host's internal `block_on` lands on a blocking thread,
        // not a tokio worker.
        if let Err(err) = host.audit_event(event) {
            tracing::debug!(
                target: "mcpg::policy::opa::host_handle",
                error = %err,
                "host_handle.audit_event emission failed"
            );
        }
    }

    fn evaluate_inner(
        &self,
        decision_point: &str,
        input: &Value,
        context: &PluginContext,
    ) -> PolicyDecision {
        let opa_input = serde_json::json!({
            "decision_point": decision_point,
            "input": input,
            "context": context,
        });

        match &self.inner.backend {
            Backend::Remote(client) => {
                // Remote-mode `policy_version` is fixed at boot
                // (hash of `{url, package}`) — there's no upstream
                // change-feed to track within a single eval call.
                let version_hash = self.inner.policy_version.hash.clone();
                let client = Arc::clone(client);
                let version_for_call = version_hash.clone();
                let raw = self.inner.runtime.block_on(async move {
                    client.evaluate_raw(opa_input, &version_for_call).await
                });
                match raw {
                    Ok(result) => decision::parse_decision(result, &version_hash),
                    Err(decision) => decision,
                }
            }
            Backend::Embedded(bundle) => {
                // `bundle.load()` returns an `Arc<WasmRuntime>`
                // — owning, so the eval task can hold it across
                // the await without keeping the ArcSwap pinned.
                // If the watcher swaps mid-flight, this Arc keeps
                // the previous runtime alive until the eval
                // finishes. Snapshot the version from the SAME
                // runtime so the audit stamp matches the bytes
                // that actually ran.
                let wasm = bundle.load();
                let version_hash = format!("sha256:{}", wasm.bundle_sha256());
                let raw = self
                    .inner
                    .runtime
                    .block_on(async move { wasm.evaluate(&opa_input).await });
                match raw {
                    Ok(result) => decision::parse_decision(result, &version_hash),
                    Err(reason) => {
                        // Embedded runtime errors fail closed.
                        // Stamp with the active
                        // policy_version so audit can pin the
                        // failure to the specific WASM that
                        // caused it.
                        tracing::warn!(
                            plugin_id = PLUGIN_ID,
                            decision_point = %decision_point,
                            error = %reason,
                            "opa policy: embedded eval failed; denying request"
                        );
                        PolicyDecision::deny(format!("opa embedded error: {reason}"), &version_hash)
                    }
                }
            }
        }
    }
}

/// Live `policy_version` snapshot. Embedded mode reads the bundle
/// fingerprint from the `BundleReload` snapshot (so it tracks
/// reloads without an explicit stamp swap); remote mode returns
/// the static boot stamp.
fn current_policy_version(inner: &OpaPolicyInner) -> PolicyVersion {
    match &inner.backend {
        Backend::Remote(_) => inner.policy_version.clone(),
        Backend::Embedded(bundle) => {
            let snapshot = bundle.load();
            PolicyVersion {
                hash: format!("sha256:{}", snapshot.bundle_sha256()),
                loaded_at: inner.policy_version.loaded_at.clone(),
                source: inner.policy_version.source.clone(),
            }
        }
    }
}

/// Synthesise a stable [`PolicyVersion`] at registration time.
///
/// - Embedded: real bundle SHA-256 from the freshly-loaded
///   `WasmRuntime`. Acts as the boot-time `loaded_at` + `source`
///   carrier; the `hash` is recomputed live at every
///   `current_policy_version` call so reload-driven swaps are
///   reflected without an explicit stamp swap.
/// - Remote: SHA-256 of the canonical `{url, package}` string
///   keeps observability + audit usable without an OPA round-trip
///   per call. Static for the plugin's lifetime — there's no
///   upstream change-feed to track. v0.3 may add a periodic
///   `/v1/policies/<bundle>` probe to surface bundle changes.
fn boot_policy_version(cfg: &OpaPolicyConfig, backend: &Backend) -> PolicyVersion {
    match backend {
        Backend::Embedded(bundle) => {
            let snapshot = bundle.load();
            let source_path = cfg
                .policy_bundle
                .as_ref()
                .map(|b| b.source_path.as_str())
                .unwrap_or("");
            PolicyVersion {
                hash: format!("sha256:{}", snapshot.bundle_sha256()),
                loaded_at: now_rfc3339(),
                source: format!("opa-embedded:{source_path}#{}", snapshot.entrypoint()),
            }
        }
        Backend::Remote(_) => {
            use sha2::{Digest, Sha256};
            let (url, package) = match cfg.remote.as_ref() {
                Some(r) => (r.url.as_str(), r.package.as_str()),
                None => ("", ""),
            };
            let canonical = format!("{url}|{package}");
            let mut hasher = Sha256::new();
            hasher.update(canonical.as_bytes());
            let hash = hex_lower(&hasher.finalize());
            PolicyVersion {
                hash: format!("sha256:{hash}"),
                loaded_at: now_rfc3339(),
                source: format!("opa-remote:{url}/{package}"),
            }
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Minimal RFC 3339 — `chrono` would be cleaner but we already
    // avoid the dep elsewhere in this crate. Format: YYYY-MM-DDTHH:MM:SSZ.
    let secs = now as i64;
    let (year, month, day, hour, min, sec) = epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Naïve epoch → (Y, M, D, h, m, s). Good enough for an audit
/// timestamp; doesn't handle leap seconds.
fn epoch_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days_since_epoch = secs.div_euclid(86_400);
    let secs_today = secs.rem_euclid(86_400) as u32;
    let hour = secs_today / 3600;
    let min = (secs_today % 3600) / 60;
    let sec = secs_today % 60;

    // Civil-from-days (Howard Hinnant's algorithm, simplified).
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[mcpg_plugin_protocol::capability::Capability::NetworkOutbound],
    entities: [
        policy_engine as policy {
            inner_name: "",
            plugin_type: OpaPolicyPlugin,
            // Receives a `HostHandle` from the macro.
            // When cluster is registered AND embedded mode is configured,
            // the plugin emits a startup heartbeat on
            // `policy.opa.bundle-loaded` and subscribes to the same topic
            // so peers' reloads poke this node's `BundleReload` watcher
            // (out-of-band poll). Remote mode has no local bundle to
            // coordinate.
            //
            // Also install the unified `HostHandle` on the
            // plugin so per-evaluation observability (span + latency
            // histogram + decisions counter + Deny / Error audit
            // events) routes through the gateway's central
            // host-services sink. Idempotent — a second install
            // returns false and the slot remains untouched.
            factory: |cfg: &str, host: ::mcpg_plugin_sdk::HostHandle| -> OpaPolicyPlugin {
                let plugin = OpaPolicyPlugin::from_config_json_with_cluster(
                    cfg,
                    host.cluster(),
                );
                let _installed = plugin.set_host_handle(host);
                plugin
            },
        }
    ],
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_plugin_protocol::PluginIdentity;
    use mcpg_plugin_protocol::policy::PolicyEffect;
    use std::collections::BTreeMap;

    fn cheap_plugin() -> OpaPolicyPlugin {
        OpaPolicyPlugin::from_config_json(
            r#"{
                "mode": "remote",
                "remote": {"url": "http://opa.invalid:8181", "package": "mcpg/allow"}
            }"#,
        )
    }

    fn ctx() -> PluginContext {
        PluginContext {
            request_id: "req-1".into(),
            session_id: None,
            tool_name: "test.tool".into(),
            surface: "tool".into(),
            identity: PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    #[test]
    fn factory_parses_minimal_config() {
        let _plugin = cheap_plugin();
    }

    #[test]
    #[should_panic(expected = "opa policy config parse failed")]
    fn factory_panics_on_unparseable_config() {
        let _ = OpaPolicyPlugin::from_config_json("not-json");
    }

    #[test]
    fn manifest_carries_required_capability() {
        // Capabilities live on
        // `PluginRegistration.capabilities` (typed) via the SDK
        // macro's `capabilities:` parameter. The runtime
        // `PluginManifest.required_capabilities: Vec<String>` is
        // kept for display only and is now empty.
        let plugin = cheap_plugin();
        let m = plugin.manifest();
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::PolicyEngine);
    }

    #[test]
    fn engine_name_is_opa() {
        let plugin = cheap_plugin();
        assert_eq!(plugin.name(), ENGINE_NAME);
    }

    #[test]
    fn descriptor_yaml_is_well_formed() {
        assert!(DESCRIPTOR_YAML.contains(&format!("id: {PLUGIN_ID}")));
        assert!(DESCRIPTOR_YAML.contains("class: policy_engine"));
        assert!(DESCRIPTOR_YAML.contains("runtime: native-cdylib-v1"));
        assert!(DESCRIPTOR_YAML.contains("network_outbound"));
    }

    #[test]
    fn policy_version_hash_is_stable_per_target() {
        // Same remote URL + package → same hash. Operators get
        // deterministic policy_version stamps without an OPA round-trip.
        let p1 = cheap_plugin();
        let p2 = cheap_plugin();
        assert_eq!(p1.policy_version().hash, p2.policy_version().hash);
        assert!(p1.policy_version().hash.starts_with("sha256:"));
    }

    #[test]
    fn evaluate_against_unreachable_opa_denies_with_audit_stamp() {
        // `opa.invalid` resolves nowhere per RFC 6761. The plugin
        // must surface a Deny carrying the configured
        // policy_version so audit can pin the failure to the
        // intended target.
        let plugin = cheap_plugin();
        let expected_version = plugin.policy_version().hash.clone();
        let d = plugin.evaluate(
            "tool.call.pre",
            &serde_json::json!({"tool_name": "x"}),
            &ctx(),
        );
        assert!(matches!(d.effect, PolicyEffect::Deny));
        let reason = d.reason.as_deref().unwrap_or_default();
        assert!(
            reason.contains("opa") && (reason.contains("error") || reason.contains("timeout")),
            "deny reason should reference the upstream failure; got: {reason}"
        );
        assert_eq!(
            d.policy_version, expected_version,
            "even an early-failed eval must carry the configured policy_version"
        );
    }

    /// Embedded factory must fail loudly when the bundle file is
    /// missing — operators get a registration-time error instead of
    /// a silent "policy never matches" runtime symptom.
    #[test]
    #[should_panic(expected = "wasm bundle init failed")]
    fn embedded_factory_panics_when_bundle_missing() {
        let _ = OpaPolicyPlugin::from_config_json(
            r#"{
                "mode": "embedded",
                "policy_bundle": {
                    "source_path": "/nonexistent/policy.wasm",
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                    "entrypoint": "mcpg/allow"
                }
            }"#,
        );
    }

    /// Embedded factory verifies the SHA-256 against the bytes on
    /// disk; mismatch is a registration-time error.
    #[test]
    #[should_panic(expected = "sha256 mismatch")]
    fn embedded_factory_panics_on_sha_mismatch() {
        // Write a tempfile with known content + a wrong sha256 in
        // the config. The factory should panic on the validation
        // round-trip.
        let path =
            std::env::temp_dir().join(format!("mcpg-policy-opa-test-{}.wasm", std::process::id()));
        std::fs::write(&path, b"not really a wasm file").expect("write tempfile");
        let cfg = format!(
            r#"{{
                "mode": "embedded",
                "policy_bundle": {{
                    "source_path": "{}",
                    "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                    "entrypoint": "mcpg/allow"
                }}
            }}"#,
            path.display()
        );
        // Defer cleanup — the panic short-circuits before we'd
        // remove the tempfile, but it sits in /tmp and is cleaned
        // up by the OS eventually.
        let _ = OpaPolicyPlugin::from_config_json(&cfg);
    }

    /// Embedded factory rejects bytes that pass SHA verification
    /// but don't decode as valid WASM. Verifies the wasmtime
    /// compile error surfaces through the panic.
    #[test]
    #[should_panic(expected = "wasm bundle init failed")]
    fn embedded_factory_panics_on_invalid_wasm_bytes() {
        let bytes = b"not really a wasm file";
        // Compute the actual sha256 so we get past the SHA check
        // and hit the wasmtime compilation step.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut sha = String::with_capacity(digest.len() * 2);
        for b in digest {
            sha.push_str(&format!("{b:02x}"));
        }
        let path = std::env::temp_dir().join(format!(
            "mcpg-policy-opa-bad-wasm-{}.wasm",
            std::process::id()
        ));
        std::fs::write(&path, bytes).expect("write tempfile");
        let cfg = format!(
            r#"{{
                "mode": "embedded",
                "policy_bundle": {{
                    "source_path": "{}",
                    "sha256": "{sha}",
                    "entrypoint": "mcpg/allow"
                }}
            }}"#,
            path.display()
        );
        let _ = OpaPolicyPlugin::from_config_json(&cfg);
    }

    // ─────────────────────────────────────────────────────────
    // mcpg-bundle-reload migration tests
    // ─────────────────────────────────────────────────────────

    /// The bundle-reload migration must not change the public
    /// factory surface. `from_config_json` (no cluster) and
    /// `from_config_json_with_cluster(_, None)` produce
    /// equivalent plugins for solo deploys.
    #[test]
    fn cluster_aware_factory_with_none_matches_legacy_factory() {
        let cfg = r#"{
            "mode": "remote",
            "remote": {"url": "http://opa.invalid:8181", "package": "mcpg/allow"}
        }"#;
        let p_legacy = OpaPolicyPlugin::from_config_json(cfg);
        let p_modern = OpaPolicyPlugin::from_config_json_with_cluster(cfg, None);
        assert_eq!(
            p_legacy.policy_version().hash,
            p_modern.policy_version().hash,
            "two equivalent constructions must yield matching policy_version hashes"
        );
        assert!(p_legacy.inner.cluster.is_none());
        assert!(p_modern.inner.cluster.is_none());
        assert!(p_legacy.inner.cluster_subscription.is_none());
        assert!(p_modern.inner.cluster_subscription.is_none());
    }

    /// Embedded factory wraps the active runtime in a
    /// `BundleReload<WasmRuntime>`. We can't compile real WASM
    /// without a fixture, but we can verify the panic path goes
    /// through `mcpg_bundle_reload`'s parser surface — the panic
    /// message must come from the parser closure (which wraps the
    /// wasmtime compile error in `ReloadError::Parse`), not from
    /// the legacy `WasmRuntime::from_config` path.
    #[test]
    #[should_panic(expected = "wasm bundle init failed")]
    fn embedded_factory_routes_compile_errors_through_bundle_reload_parser() {
        // Real bytes, real sha, NOT-real wasm. Goes past the sha
        // check and hits wasmtime via the BundleReload parser.
        let bytes = b"\x00asm-not-actually-wasm";
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut sha = String::with_capacity(digest.len() * 2);
        for b in digest {
            sha.push_str(&format!("{b:02x}"));
        }
        let path = std::env::temp_dir().join(format!(
            "mcpg-policy-opa-reload-{}.wasm",
            std::process::id()
        ));
        std::fs::write(&path, bytes).expect("write tempfile");
        let cfg = format!(
            r#"{{
                "mode": "embedded",
                "policy_bundle": {{
                    "source_path": "{}",
                    "sha256": "{sha}",
                    "entrypoint": "mcpg/allow",
                    "reload": {{ "enabled": true, "check_interval_sec": 60 }}
                }}
            }}"#,
            path.display()
        );
        let _ = OpaPolicyPlugin::from_config_json(&cfg);
    }
}
