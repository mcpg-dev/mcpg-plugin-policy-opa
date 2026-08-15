# OPA Policy Engine — `dev.mcpg.policy.opa`

> class `policy_engine` · `native` · package `mcpg-plugin-policy-opa` · artifact `libmcpg_plugin_policy_opa.so`

Open Policy Agent authorization engine. Two modes: `remote`
dispatches evaluations to a standalone OPA server over its REST `Data` API;
`embedded` evaluates Rego compiled to WASM in-process via wasmtime. Reach for it
when policy lives in Rego, whether served centrally or shipped as a local bundle.

## What it does
- `mode: remote` — POSTs the evaluation envelope to `{url}/v1/data/{package}`
  (package dots become path slashes). Optional TLS knobs. Requires capability
  `network_outbound`.
- `mode: embedded` — loads + verifies a WASM bundle (`sha256`) and evaluates the
  `entrypoint` in-process; optional bundle hot-reload. No egress needed.
- Decision mapping: OPA `404` (no such rule) → `NotApplicable` ("engine
  declines"); all other failures fail closed to `Deny`.
- `policy_version().hash` is a stable identifier for the loaded policy.
- The capability `network_outbound` is declared for both modes; only consumed
  in `remote`.

## Configuration
Selected via the gateway's policy-engine binding and loaded via the top-level
`plugins:` list. Remote mode:

```yaml
plugins:
  - id: dev.mcpg.policy.opa
    class: policy_engine
    source: { path: ./plugins/libmcpg_plugin_policy_opa.so }
    config:
      mode: remote
      remote:
        url: "http://opa:8181"
        package: "mcpg/allow"          # POSTs to /v1/data/mcpg/allow
        timeout_ms: 500
        tls:
          ca_cert: /etc/mcpg/opa-ca.pem
          verify_peer: true
```

Embedded mode:

```yaml
    config:
      mode: embedded
      policy_bundle:
        source_path: /etc/mcpg/policy.wasm
        sha256: "<sha256sum policy.wasm>"
        entrypoint: "mcpg/allow"
        reload:
          enabled: true
          check_interval_sec: 60
```

| Field | Type | Default | Description |
|---|---|---|---|
| `mode` | enum | — | `remote` or `embedded`. Required. |
| `remote` | object? | `null` | Required for `remote` mode; rejected otherwise. |
| `remote.url` | string | — | OPA server URL (`http://`/`https://`). |
| `remote.package` | string | — | Rego package queried for decisions. |
| `remote.timeout_ms` | u64 | `500` | Per-evaluation timeout (connect + request + decode). |
| `remote.tls.ca_cert` | string? | `null` | Extra CA bundle (https only). |
| `remote.tls.verify_peer` | bool | `true` | Verify the server cert (https only). |
| `remote.decision_log_forwarding` | bool | `false` | Reserved; parsed but no-op. |
| `policy_bundle` | object? | `null` | Required for `embedded` mode; rejected otherwise. |
| `policy_bundle.source_path` | string | — | Path to the compiled WASM bundle. |
| `policy_bundle.sha256` | string | — | Expected SHA-256 of the bundle. |
| `policy_bundle.entrypoint` | string | — | Rego entrypoint (e.g. `mcpg/allow`). |
| `policy_bundle.reload.enabled` | bool | `true` | Poll the bundle and hot-swap. |
| `policy_bundle.reload.check_interval_sec` | u64 | `60` | Poll interval (> 0). |

Unknown config fields are rejected at parse time; mode/section mismatches fail
validation with a precise message.

## Build
```bash
cargo build -p mcpg-plugin-policy-opa --features cdylib-export --release   # → target/release/libmcpg_plugin_policy_opa.so
```

## Sign & load (production)
Sign the artifact, pin/verify via the entry's `signature:` block, and honour
revocations. See <https://mcpg.dev/docs/security/plugin-security>.

## See also
- Plugin system overview: `apps/gateway/docs/plugins.md`
- Full config reference: `apps/gateway/config.example.yaml`
