//! OPA decision-document parser.
//!
//! Converts the raw `result` value an OPA `POST /v1/data/{...}`
//! returns into a [`PolicyDecision`]. The conversion intentionally
//! tolerates two query shapes:
//!
//! 1. **Sub-rule path** (e.g. `package: mcpg/allow`): OPA returns
//!    a bool — `true` → Allow, `false` → NotApplicable. No
//!    obligations / redactions reachable through this shape.
//! 2. **Package path** (e.g. `package: mcpg`): OPA returns an
//!    object document. The plugin reads `allow`, `deny`,
//!    `obligations`, `redactions`, `attributes`.
//!
//! Operators picking shape (1) trade obligation/redaction support
//! for a smaller policy + simpler tests. Shape (2) is recommended
//! once they need anything beyond plain Allow/Deny.

use mcpg_plugin_protocol::policy::{Obligation, PolicyDecision, PolicyEffect, Redaction};
use serde_json::Value;
use std::collections::BTreeMap;

/// Translate `result` from OPA into [`PolicyDecision`]. Caller
/// supplies the `policy_version.hash` so the produced decision
/// carries the audit stamp.
pub(crate) fn parse_decision(result: Value, policy_version_hash: &str) -> PolicyDecision {
    match result {
        Value::Bool(true) => PolicyDecision {
            effect: PolicyEffect::Allow,
            obligations: Vec::new(),
            redactions: Vec::new(),
            attributes: BTreeMap::new(),
            reason: None,
            policy_version: policy_version_hash.to_owned(),
        },
        Value::Bool(false) => PolicyDecision::not_applicable(policy_version_hash),
        Value::Null => PolicyDecision::not_applicable(policy_version_hash),
        Value::Object(map) => parse_object(map, policy_version_hash),
        // OPA can return arrays / strings / numbers from a partial
        // evaluation. We don't speak those shapes; declining
        // cleanly is the safest default and matches the "engine
        // declines" semantic of NotApplicable.
        _ => PolicyDecision::not_applicable(policy_version_hash),
    }
}

fn parse_object(map: serde_json::Map<String, Value>, policy_version_hash: &str) -> PolicyDecision {
    // Explicit deny wins over allow. The deny field can be:
    //   - boolean true  → Deny without reason
    //   - object        → check `.reason` for the operator-supplied message
    //   - array         → take the first non-empty element's `.reason`
    if let Some(deny) = map.get("deny")
        && let Some(reason) = deny_reason(deny)
    {
        let mut decision = PolicyDecision::deny(reason, policy_version_hash);
        decision.obligations = parse_obligations(map.get("obligations"));
        decision.redactions = parse_redactions(map.get("redactions"));
        decision.attributes = parse_attributes(map.get("attributes"));
        return decision;
    }

    let allow = matches!(map.get("allow"), Some(Value::Bool(true)));
    if !allow {
        // Either `allow: false` or no `allow` field at all → engine
        // declines: the default-allow-false path.
        return PolicyDecision::not_applicable(policy_version_hash);
    }

    PolicyDecision {
        effect: PolicyEffect::Allow,
        obligations: parse_obligations(map.get("obligations")),
        redactions: parse_redactions(map.get("redactions")),
        attributes: parse_attributes(map.get("attributes")),
        reason: None,
        policy_version: policy_version_hash.to_owned(),
    }
}

/// Pull a deny reason out of the assorted shapes a rego policy
/// might emit. Returns `None` when `deny` is absent or false-y
/// (`null`, `false`, `[]`, `{}` without a `reason`).
fn deny_reason(deny: &Value) -> Option<String> {
    match deny {
        Value::Bool(true) => Some("denied by policy".to_owned()),
        Value::Bool(false) | Value::Null => None,
        Value::String(s) if !s.trim().is_empty() => Some(s.clone()),
        Value::Object(o) => {
            let reason = o.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            if reason.trim().is_empty() {
                None
            } else {
                Some(reason.to_owned())
            }
        }
        Value::Array(arr) => arr.iter().find_map(deny_reason),
        _ => None,
    }
}

fn parse_obligations(value: Option<&Value>) -> Vec<Obligation> {
    let arr = match value {
        // `obligations` declared as an object map (rego sometimes
        // emits a set keyed on the obligation kind) — flatten to
        // [{kind, args}].
        Some(Value::Object(map)) => {
            return map
                .iter()
                .map(|(k, v)| Obligation {
                    kind: k.clone(),
                    args: v.clone(),
                })
                .collect();
        }
        Some(Value::Array(a)) => a,
        _ => return Vec::new(),
    };
    arr.iter()
        .filter_map(|v| {
            let obj = v.as_object()?;
            let kind = obj.get("kind").and_then(|x| x.as_str())?.to_owned();
            let args = obj.get("args").cloned().unwrap_or(Value::Null);
            Some(Obligation { kind, args })
        })
        .collect()
}

fn parse_redactions(value: Option<&Value>) -> Vec<Redaction> {
    let arr = match value {
        Some(Value::Array(a)) => a,
        _ => return Vec::new(),
    };
    arr.iter()
        .filter_map(|v| {
            let obj = v.as_object()?;
            let json_pointer = obj.get("json_pointer").and_then(|x| x.as_str())?.to_owned();
            let replacement = obj
                .get("replacement")
                .cloned()
                .unwrap_or(Value::String("***".into()));
            Some(Redaction {
                json_pointer,
                replacement,
            })
        })
        .collect()
}

fn parse_attributes(value: Option<&Value>) -> BTreeMap<String, Value> {
    match value {
        Some(Value::Object(map)) => map.clone().into_iter().collect(),
        _ => BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VER: &str = "sha256:test";

    #[test]
    fn bool_true_is_allow() {
        let d = parse_decision(json!(true), VER);
        assert!(matches!(d.effect, PolicyEffect::Allow));
        assert_eq!(d.policy_version, VER);
    }

    #[test]
    fn bool_false_is_not_applicable() {
        let d = parse_decision(json!(false), VER);
        assert!(matches!(d.effect, PolicyEffect::NotApplicable));
    }

    #[test]
    fn null_is_not_applicable() {
        let d = parse_decision(Value::Null, VER);
        assert!(matches!(d.effect, PolicyEffect::NotApplicable));
    }

    #[test]
    fn object_with_allow_true_is_allow() {
        let d = parse_decision(json!({"allow": true}), VER);
        assert!(matches!(d.effect, PolicyEffect::Allow));
        assert!(d.obligations.is_empty());
        assert!(d.redactions.is_empty());
    }

    #[test]
    fn object_with_allow_false_is_not_applicable() {
        let d = parse_decision(json!({"allow": false}), VER);
        assert!(matches!(d.effect, PolicyEffect::NotApplicable));
    }

    #[test]
    fn object_without_allow_is_not_applicable() {
        // Empty package output (no rule matched + no `default
        // allow`) maps to NotApplicable.
        let d = parse_decision(json!({}), VER);
        assert!(matches!(d.effect, PolicyEffect::NotApplicable));
    }

    #[test]
    fn explicit_deny_overrides_allow_true() {
        let d = parse_decision(
            json!({"allow": true, "deny": {"reason": "tenant disabled"}}),
            VER,
        );
        assert!(matches!(d.effect, PolicyEffect::Deny));
        assert_eq!(d.reason.as_deref(), Some("tenant disabled"));
    }

    #[test]
    fn deny_string_form_supplies_reason() {
        let d = parse_decision(json!({"deny": "blocked"}), VER);
        assert!(matches!(d.effect, PolicyEffect::Deny));
        assert_eq!(d.reason.as_deref(), Some("blocked"));
    }

    #[test]
    fn deny_bool_true_supplies_default_reason() {
        let d = parse_decision(json!({"deny": true}), VER);
        assert!(matches!(d.effect, PolicyEffect::Deny));
        let r = d.reason.unwrap();
        assert!(r.contains("policy"), "got reason {r:?}");
    }

    #[test]
    fn deny_array_picks_first_with_reason() {
        let d = parse_decision(
            json!({"deny": [
                {},
                {"reason": "second wins"},
                {"reason": "third"}
            ]}),
            VER,
        );
        assert_eq!(d.reason.as_deref(), Some("second wins"));
    }

    #[test]
    fn obligations_array_form_is_parsed() {
        let d = parse_decision(
            json!({
                "allow": true,
                "obligations": [
                    {"kind": "audit.emit", "args": {"severity": "info"}},
                    {"kind": "header.inject", "args": {"X-Tenant": "t1"}}
                ]
            }),
            VER,
        );
        assert_eq!(d.obligations.len(), 2);
        assert_eq!(d.obligations[0].kind, "audit.emit");
        assert_eq!(d.obligations[1].kind, "header.inject");
    }

    #[test]
    fn obligations_map_form_is_flattened() {
        // Rego sometimes emits obligations as an object keyed on
        // the kind (`obligations["audit.emit"] = {...}`). Verify
        // the parser flattens that to the canonical list shape.
        let d = parse_decision(
            json!({
                "allow": true,
                "obligations": {
                    "audit.emit": {"severity": "info"}
                }
            }),
            VER,
        );
        assert_eq!(d.obligations.len(), 1);
        assert_eq!(d.obligations[0].kind, "audit.emit");
    }

    #[test]
    fn redactions_with_replacement_default() {
        let d = parse_decision(
            json!({
                "allow": true,
                "redactions": [
                    {"json_pointer": "/ssn", "replacement": "***"},
                    {"json_pointer": "/email"}
                ]
            }),
            VER,
        );
        assert_eq!(d.redactions.len(), 2);
        assert_eq!(d.redactions[0].json_pointer, "/ssn");
        assert_eq!(d.redactions[0].replacement, json!("***"));
        // Missing replacement defaults to `"***"`.
        assert_eq!(d.redactions[1].json_pointer, "/email");
        assert_eq!(d.redactions[1].replacement, json!("***"));
    }

    #[test]
    fn attributes_round_trip() {
        let d = parse_decision(
            json!({
                "allow": true,
                "attributes": {
                    "tenant_id": "acme",
                    "risk_score": 0.42
                }
            }),
            VER,
        );
        assert_eq!(d.attributes.len(), 2);
        assert_eq!(d.attributes.get("tenant_id"), Some(&json!("acme")));
    }

    #[test]
    fn malformed_obligation_entries_are_skipped() {
        let d = parse_decision(
            json!({
                "allow": true,
                "obligations": [
                    {"kind": "good", "args": {}},
                    {"args": {}},                  // missing kind — drop
                    "not-an-object"                // wrong shape  — drop
                ]
            }),
            VER,
        );
        assert_eq!(d.obligations.len(), 1);
        assert_eq!(d.obligations[0].kind, "good");
    }
}
