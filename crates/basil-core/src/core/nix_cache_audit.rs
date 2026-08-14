// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Secret-free audit records for purpose-specific Nix cache operations.

use serde_json::{Map, Value, json};
use std::fmt::Write as _;

use crate::audit::timestamp;

/// Nix cache operation recorded in the Basil audit stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NixCacheAuditOp {
    /// Describe an enrolled verifier identity.
    Describe,
    /// Enroll pending backend material.
    Enroll,
    /// Sign a canonical fingerprint.
    Sign,
}

impl NixCacheAuditOp {
    /// Stable operation token shared with policy and protocol terminology.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Describe => "describe_nix_cache_key",
            Self::Enroll => "enroll_nix_cache_key",
            Self::Sign => "sign_nix_cache_fingerprint",
        }
    }
}

/// Outcome of a purpose-specific Nix cache operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NixCacheAuditOutcome {
    /// Policy or identity state denied the operation.
    Deny,
    /// The operation completed successfully.
    Success,
    /// Validation or backend execution failed.
    Failure,
}

impl NixCacheAuditOutcome {
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Deny => "deny",
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Dedicated secret-free audit event for one Nix cache operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NixCacheAuditEvent<'a> {
    /// Operation being attempted.
    pub op: NixCacheAuditOp,
    /// Policy subject established from the request transport, when resolved.
    pub policy_subject: Option<&'a str>,
    /// Kernel-attested Unix presenter PID, when captured.
    pub presenter_pid: Option<u32>,
    /// Kernel-attested Unix presenter UID, when captured.
    pub presenter_uid: Option<u32>,
    /// Serving generation pinned for the complete operation.
    pub generation: u64,
    /// Dotted catalog key id.
    pub key_id: &'a str,
    /// Nix verifier key name, when an identity was resolved.
    pub key_name: Option<&'a str>,
    /// Actual/pinned backend version, when an identity was resolved.
    pub backend_version: Option<u32>,
    /// Exact raw protocol batch correlation id.
    pub batch_id: [u8; 16],
    /// Exact raw protocol request correlation id.
    pub request_id: [u8; 16],
    /// Lowercase hexadecimal SHA-256 digest for sign operations only.
    pub fingerprint_sha256: Option<&'a str>,
    /// Outcome.
    pub outcome: NixCacheAuditOutcome,
    /// Stable secret-free reason token.
    pub reason: &'static str,
}

impl NixCacheAuditEvent<'_> {
    /// Convert to JSON without fingerprint bytes, signatures, private material,
    /// or any claim that a caller installed the returned verifier identity.
    #[must_use]
    pub fn to_json_value(&self) -> Value {
        let mut value = Map::new();
        value.insert(
            "event".into(),
            json!({ "kind": "basil.audit.nix_cache_operation", "version": 1 }),
        );
        value.insert("occurred_at".into(), Value::String(timestamp()));
        value.insert("op".into(), Value::String(self.op.token().into()));
        value.insert(
            "actor".into(),
            json!({
                "kind": "unix_transport_presenter",
                "pid": self.presenter_pid,
                "uid": self.presenter_uid,
            }),
        );
        value.insert(
            "policy_subject".into(),
            self.policy_subject
                .map_or(Value::Null, |subject| Value::String(subject.into())),
        );
        value.insert("generation".into(), self.generation.into());
        value.insert("key_id".into(), Value::String(self.key_id.into()));
        value.insert(
            "key_name".into(),
            self.key_name
                .map_or(Value::Null, |name| Value::String(name.into())),
        );
        value.insert(
            "backend_version".into(),
            self.backend_version.map_or(Value::Null, Value::from),
        );
        value.insert("batch_id".into(), Value::String(lower_hex(&self.batch_id)));
        value.insert(
            "request_id".into(),
            Value::String(lower_hex(&self.request_id)),
        );
        if let Some(digest) = self.fingerprint_sha256 {
            value.insert("fingerprint_sha256".into(), Value::String(digest.into()));
        }
        value.insert("outcome".into(), Value::String(self.outcome.token().into()));
        value.insert("reason".into(), Value::String(self.reason.into()));
        Value::Object(value)
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_exact_ids_and_redacts_operation_material() {
        let batch_id = [0xabu8; 16];
        let request_id = [0x01u8; 16];
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let value = NixCacheAuditEvent {
            op: NixCacheAuditOp::Sign,
            policy_subject: Some("builder"),
            presenter_pid: Some(1234),
            presenter_uid: Some(1000),
            generation: 42,
            key_id: "cache.signing",
            key_name: Some("cache.example-1"),
            backend_version: Some(1),
            batch_id,
            request_id,
            fingerprint_sha256: Some(digest),
            outcome: NixCacheAuditOutcome::Success,
            reason: "ok",
        }
        .to_json_value();
        assert_eq!(value["batch_id"], "abababababababababababababababab");
        assert_eq!(value["request_id"], "01010101010101010101010101010101");
        assert_eq!(value["fingerprint_sha256"], digest);
        assert_eq!(value["actor"]["pid"], 1234);
        assert_eq!(value["actor"]["uid"], 1000);
        assert_eq!(value["policy_subject"], "builder");

        let rendered = value.to_string();
        for forbidden in [
            "fingerprint_bytes",
            "signature",
            "private",
            "installed",
            "nix_caller",
        ] {
            assert!(!rendered.contains(forbidden), "leaked field {forbidden}");
        }
    }
}
