//! Config errors are local; runtime OPA errors do **not** translate
//! into a `PolicyError` — the `PolicyEngine` trait returns a
//! `PolicyDecision` directly per spec §9.14, so failure encoding
//! lives at the trait-impl layer (Deny with reason / NotApplicable).

use thiserror::Error;

/// Failures while parsing the operator-supplied config blob.
/// Surface verbatim in the host startup log.
#[derive(Debug, Clone, Error)]
pub enum ConfigError {
    #[error("opa policy config: failed to parse JSON: {0}")]
    ParseError(String),

    #[error("opa policy config: invalid: {0}")]
    Invalid(String),
}
