// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The per-request authorization decision record (the audit hook point).
//!
//! Every **PDP-gated** op produces exactly one [`DecisionRecord`]: the broker
//! decides `(subject, op, key) -> Allow|Deny` (via [`crate::catalog::pdp::Pdp`]),
//! builds a record, and logs it structurally with `tracing`. This is the single
//! place a decision is materialized; `vault-vq5` will persist these records to a
//! JSONL audit file by hooking [`DecisionRecord::record`] (or reusing the fields
//! it carries). This module deliberately does **not** open or write any file.
//!
//! A record never carries secret bytes, only the policy generation id it was
//! decided against, the actor subject, presenter summary, op, key name, outcome,
//! and reason.

use tracing::{info, warn};

use crate::actor::{AuthenticatedActor, ProofKind};
use crate::catalog::policy::Op;
use crate::catalog::{AllowVia, Decision, DenyReason};
use crate::peer::PeerInfo;

/// The outcome of a gated request, in audit-friendly form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The request was permitted.
    Allow,
    /// The request was denied.
    Deny,
}

impl Outcome {
    /// The lowercase wire string for this outcome (`allow` / `deny`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// A structured record of one authorization decision (the audit hook point).
///
/// Built from a [`Decision`] plus the request's `(subject, op, key)` and
/// presenter context. It carries everything the audit sink needs to serialize a
/// JSONL audit line and **nothing** secret: no payloads, no key bytes, no
/// signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionRecord {
    /// The id of the policy generation this decision was made against
    /// (`basil-y3e`). Lets the audit trail tie a decision to the exact
    /// catalog/policy snapshot that produced it across a hot reload.
    pub generation: u64,
    /// The op that was gated (the policy [`Op`], e.g. `sign`, `new_key`).
    pub op: Op,
    /// The dotted catalog key the op targeted.
    pub key: String,
    /// Actor kind. M1 authorization records are subject-based.
    pub actor_kind: String,
    /// The policy subject being authorized.
    pub actor_id: String,
    /// Evidence summaries that established the actor.
    pub authenticated_by: Vec<String>,
    /// Presenter kind, e.g. `unix_peercred`.
    pub presenter_kind: String,
    /// Presenter id, preferably the configured `name(uid)` label.
    pub presenter_id: String,
    /// Allow or deny.
    pub outcome: Outcome,
    /// On an allow, *what* granted it (subject / public-class); on a
    /// deny, *which* check failed (unknown-key / not-writable / not-permitted).
    /// Always a short stable token, never secret.
    pub reason: String,
}

impl DecisionRecord {
    /// Build a record from a `PDP` [`Decision`] for an [`AuthenticatedActor`].
    #[must_use]
    pub fn from_actor_decision(
        generation: u64,
        actor: &AuthenticatedActor,
        op: Op,
        key: &str,
        decision: &Decision,
    ) -> Self {
        let (outcome, reason) = match decision {
            Decision::Allow { via } => (Outcome::Allow, allow_via_str(via)),
            Decision::Deny { reason } => (Outcome::Deny, deny_reason_str(*reason).to_string()),
        };
        Self {
            generation,
            op,
            key: sanitize_log_value(key),
            actor_kind: "subject".to_string(),
            actor_id: sanitize_log_value(&actor.subject),
            authenticated_by: authenticated_by(actor),
            presenter_kind: presenter_kind(actor),
            presenter_id: presenter_id(actor),
            outcome,
            reason,
        }
    }

    /// Build a denied record for a request whose presenter could not resolve to
    /// a subject.
    #[must_use]
    pub fn from_resolution_error(
        generation: u64,
        peer: &PeerInfo,
        op: Op,
        key: &str,
        reason: String,
    ) -> Self {
        let (presenter_kind, presenter_id) = presenter_from_peer(peer);
        Self {
            generation,
            op,
            key: sanitize_log_value(key),
            actor_kind: "subject".to_string(),
            actor_id: "unresolved".to_string(),
            authenticated_by: Vec::new(),
            presenter_kind,
            presenter_id,
            outcome: Outcome::Deny,
            reason,
        }
    }

    /// Emit this record to the tracing log (the in-handler audit hook).
    ///
    /// Allows log at `info`, denials at `warn`. `vault-vq5` will tap the same
    /// records to append a JSONL audit line; this method is intentionally the
    /// only side effect today.
    pub fn record(&self) {
        let event_kind = "basil.audit.authz";
        let event_version = 2_u16;
        let op = op_token(self.op);
        match self.outcome {
            Outcome::Allow => info!(
                name: "basil.audit.authz",
                event_kind = event_kind,
                event_version = event_version,
                generation = self.generation,
                op = op,
                target_kind = "catalog_key",
                target_id = %self.key,
                actor_kind = %self.actor_kind,
                actor_id = %self.actor_id,
                authenticated_by = ?self.authenticated_by,
                presenter_kind = %self.presenter_kind,
                presenter_id = %self.presenter_id,
                decision = self.outcome.as_str(),
                outcome = self.outcome.as_str(),
                reason = %self.reason,
                "authz decision",
            ),
            Outcome::Deny => warn!(
                name: "basil.audit.authz",
                event_kind = event_kind,
                event_version = event_version,
                generation = self.generation,
                op = op,
                target_kind = "catalog_key",
                target_id = %self.key,
                actor_kind = %self.actor_kind,
                actor_id = %self.actor_id,
                authenticated_by = ?self.authenticated_by,
                presenter_kind = %self.presenter_kind,
                presenter_id = %self.presenter_id,
                decision = self.outcome.as_str(),
                outcome = self.outcome.as_str(),
                reason = %self.reason,
                "authz decision: denied",
            ),
        }
    }
}

/// Escape control characters in a client-influenced value (the requested key
/// name, the subject) before it enters the record. The catalog/policy loader
/// rejects control characters in real key/subject names, but a *denied* request
/// is recorded with the raw client-supplied key (`UnknownKey` included), and
/// the text `tracing` sinks (stdout `fmt`, rolling file) do not escape `%`
/// Display fields: a newline in the key would forge a log line in the security
/// record. The JSONL audit sink escapes independently via serde; sanitized
/// values contain only printables, so it is unaffected.
fn sanitize_log_value(value: &str) -> String {
    if value.chars().any(char::is_control) {
        value
            .chars()
            .flat_map(|c| {
                let escaped: Box<dyn Iterator<Item = char>> = if c.is_control() {
                    Box::new(c.escape_default())
                } else {
                    Box::new(std::iter::once(c))
                };
                escaped
            })
            .collect()
    } else {
        value.to_string()
    }
}

fn authenticated_by(actor: &AuthenticatedActor) -> Vec<String> {
    actor
        .authenticated_by
        .iter()
        .map(|proof| match proof.kind {
            ProofKind::UnixPeerCredentials => format!("unix_peercred:{}", proof.subject),
            ProofKind::Unauthenticated => format!("unauthenticated:{}", proof.subject),
            ProofKind::SignatureKey => format!("signature-key:{}", proof.subject),
        })
        .collect()
}

fn presenter_kind(actor: &AuthenticatedActor) -> String {
    if actor.presenter.uid.is_some() {
        "unix_peercred".to_string()
    } else {
        "none".to_string()
    }
}

fn presenter_id(actor: &AuthenticatedActor) -> String {
    actor.presenter.display_label.clone().unwrap_or_else(|| {
        actor
            .presenter
            .uid
            .map_or_else(|| "unknown".to_string(), |uid| format!("uid:{uid}"))
    })
}

fn presenter_from_peer(peer: &PeerInfo) -> (String, String) {
    let kind = if peer.uid.is_some() {
        "unix_peercred"
    } else {
        "none"
    };
    let id = peer.display_label.clone().unwrap_or_else(|| {
        peer.uid
            .map_or_else(|| "unknown".to_string(), |uid| format!("uid:{uid}"))
    });
    (kind.to_string(), id)
}

/// The stable wire spelling for a broker policy op (delegates to [`Op::token`],
/// the single source of truth for the op→token mapping).
#[must_use]
pub const fn op_token(op: Op) -> &'static str {
    op.token()
}

/// A stable token for the grant that allowed a request (for audit).
fn allow_via_str(via: &AllowVia) -> String {
    match via {
        AllowVia::Subject(subject) => format!("subject:{subject}"),
        AllowVia::PublicClass => "public_class".to_string(),
    }
}

/// A stable token for the check that denied a request (for audit).
const fn deny_reason_str(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::UnknownKey => "unknown_key",
        DenyReason::NotWritable => "not_writable",
        DenyReason::IssuerRawSign => "issuer_raw_sign",
        DenyReason::NotPermitted => "not_permitted",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::{PresenterInfo, ProofSummary, TransportInfo};

    fn actor() -> AuthenticatedActor {
        AuthenticatedActor {
            subject: "svc.nats".to_string(),
            authenticated_by: vec![ProofSummary {
                kind: ProofKind::UnixPeerCredentials,
                subject: "svc.nats".to_string(),
            }],
            presenter: PresenterInfo {
                pid: Some(123),
                uid: Some(9002),
                gid: Some(9002),
                executable_path: None,
                display_label: Some("svc-nats(9002)".to_string()),
            },
            transport: TransportInfo::default(),
        }
    }

    #[test]
    fn allow_via_subject_record_is_audit_shaped() {
        let decision = Decision::Allow {
            via: AllowVia::Subject("svc.nats".to_string()),
        };
        let rec =
            DecisionRecord::from_actor_decision(3, &actor(), Op::Sign, "nats.account", &decision);
        assert_eq!(rec.generation, 3);
        assert_eq!(rec.op, Op::Sign);
        assert_eq!(rec.key, "nats.account");
        assert_eq!(rec.actor_kind, "subject");
        assert_eq!(rec.actor_id, "svc.nats");
        assert_eq!(rec.authenticated_by, ["unix_peercred:svc.nats"]);
        assert_eq!(rec.presenter_kind, "unix_peercred");
        assert_eq!(rec.presenter_id, "svc-nats(9002)");
        assert_eq!(rec.outcome, Outcome::Allow);
        assert_eq!(rec.reason, "subject:svc.nats");
        // Logging must not panic.
        rec.record();
    }

    #[test]
    fn deny_record_carries_reason_and_subject() {
        let decision = Decision::Deny {
            reason: DenyReason::NotPermitted,
        };
        let rec =
            DecisionRecord::from_actor_decision(1, &actor(), Op::Get, "nats.account", &decision);
        assert_eq!(rec.outcome, Outcome::Deny);
        assert_eq!(rec.reason, "not_permitted");
        assert_eq!(rec.actor_id, "svc.nats");
        rec.record();
    }

    #[test]
    fn hostile_key_and_subject_names_are_escaped_before_logging() {
        // A client-supplied key is recorded even on a denied UnknownKey request;
        // a newline/control char in it must not be able to forge a line in the
        // text tracing sinks.
        let decision = Decision::Deny {
            reason: DenyReason::UnknownKey,
        };
        let hostile = "x\n{\"event_kind\":\"basil.audit.authz\",\"outcome\":\"allow\"}\u{1b}[0m";
        let rec = DecisionRecord::from_actor_decision(1, &actor(), Op::Get, hostile, &decision);
        assert!(
            !rec.key.contains('\n') && !rec.key.contains('\u{1b}'),
            "control chars must be escaped, got {:?}",
            rec.key
        );
        assert!(rec.key.contains("\\n"), "newline is visibly escaped");
        // A benign dotted-lowercase key is unchanged.
        let rec =
            DecisionRecord::from_actor_decision(1, &actor(), Op::Get, "web.tls.key", &decision);
        assert_eq!(rec.key, "web.tls.key");
        rec.record();
    }

    #[test]
    fn deny_reasons_have_stable_tokens() {
        for (reason, token) in [
            (DenyReason::UnknownKey, "unknown_key"),
            (DenyReason::NotWritable, "not_writable"),
            (DenyReason::IssuerRawSign, "issuer_raw_sign"),
            (DenyReason::NotPermitted, "not_permitted"),
        ] {
            let rec = DecisionRecord::from_actor_decision(
                1,
                &actor(),
                Op::Set,
                "k",
                &Decision::Deny { reason },
            );
            assert_eq!(rec.reason, token);
        }
    }
}
