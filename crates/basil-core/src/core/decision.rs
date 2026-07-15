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

use crate::actor::{AuthenticatedActor, ProofKind, SubjectResolutionError};
use crate::catalog::policy::Op;
use crate::catalog::{AllowVia, Decision, DenyReason};
use crate::catalog::{AuthorizationDomain, EvidenceState};
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
    /// Independently resolved local workload domain, when available.
    pub authorization_domain: Option<String>,
    /// Three-state result of the evidence evaluation that reached this record.
    pub evidence_state: String,
    /// Evidence summaries that established the actor.
    pub authenticated_by: Vec<String>,
    /// Bounded matching-subject prefix for overlap diagnostics.
    pub matching_subjects: Vec<String>,
    /// Total eligible subjects whose evidence matched.
    pub matching_subject_count: usize,
    /// Total eligible subjects whose evidence conclusively did not match.
    pub no_match_subject_count: usize,
    /// Total eligible subjects whose evidence was unavailable.
    pub unavailable_subject_count: usize,
    /// Whether `matching_subjects` omits additional matches.
    pub matching_subjects_truncated: bool,
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
            authorization_domain: Some(actor.domain.token().to_string()),
            evidence_state: EvidenceState::Match.token().to_string(),
            authenticated_by: authenticated_by(actor),
            matching_subjects: Vec::new(),
            matching_subject_count: 1,
            no_match_subject_count: 0,
            unavailable_subject_count: 0,
            matching_subjects_truncated: false,
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
        authorization_domain: Option<AuthorizationDomain>,
        evidence_state: EvidenceState,
        reason: &str,
    ) -> Self {
        let (presenter_kind, presenter_id) = presenter_from_peer(peer);
        Self {
            generation,
            op,
            key: sanitize_log_value(key),
            actor_kind: "subject".to_string(),
            actor_id: "unresolved".to_string(),
            authorization_domain: authorization_domain.map(|domain| domain.token().to_string()),
            evidence_state: evidence_state.token().to_string(),
            authenticated_by: Vec::new(),
            matching_subjects: Vec::new(),
            matching_subject_count: 0,
            no_match_subject_count: 0,
            unavailable_subject_count: 0,
            matching_subjects_truncated: false,
            presenter_kind,
            presenter_id,
            outcome: Outcome::Deny,
            reason: sanitize_log_value(reason),
        }
    }

    /// Build a denied record with bounded subject-resolution diagnostics.
    #[must_use]
    pub fn from_subject_resolution_error(
        generation: u64,
        peer: &PeerInfo,
        op: Op,
        key: &str,
        error: &SubjectResolutionError,
        reason: &str,
    ) -> Self {
        let mut record = Self::from_resolution_error(
            generation,
            peer,
            op,
            key,
            error.domain(),
            error.evidence_state(),
            reason,
        );
        let (matching, no_match, unavailable) = error.subject_counts();
        record.matching_subjects = error
            .matching_subjects()
            .iter()
            .map(|subject| sanitize_log_value(subject))
            .collect();
        record.matching_subject_count = matching;
        record.no_match_subject_count = no_match;
        record.unavailable_subject_count = unavailable;
        record.matching_subjects_truncated = error.matching_subjects_truncated();
        record
    }

    /// Build a denied record after an actor resolved but a secondary evidence
    /// equality check failed.
    #[must_use]
    pub fn from_actor_evidence_denial(
        generation: u64,
        actor: &AuthenticatedActor,
        op: Op,
        key: &str,
        evidence_state: EvidenceState,
        reason: &str,
    ) -> Self {
        let mut record = Self::from_actor_decision(
            generation,
            actor,
            op,
            key,
            &Decision::Deny {
                reason: DenyReason::NotPermitted,
            },
        );
        record.evidence_state = evidence_state.token().to_string();
        record.reason = sanitize_log_value(reason);
        record
    }

    /// Emit this record to the tracing log (the in-handler audit hook).
    ///
    /// Allows log at `info`, denials at `warn`. `vault-vq5` will tap the same
    /// records to append a JSONL audit line; this method is intentionally the
    /// only side effect today.
    pub fn record(&self) {
        let event_kind = "basil.audit.authz";
        let event_version = 3_u16;
        let op = op_token(self.op);
        let authorization_domain = self.authorization_domain.as_deref().unwrap_or("unresolved");
        let evidence_state = self.evidence_state.as_str();
        let matching_subject_count = self.matching_subject_count;
        let no_match_subject_count = self.no_match_subject_count;
        let unavailable_subject_count = self.unavailable_subject_count;
        let matching_subjects_truncated = self.matching_subjects_truncated;
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
                authorization_domain = authorization_domain,
                evidence_state = evidence_state,
                matching_subject_count = matching_subject_count,
                no_match_subject_count = no_match_subject_count,
                unavailable_subject_count = unavailable_subject_count,
                matching_subjects_truncated = matching_subjects_truncated,
                authenticated_by = ?self.authenticated_by,
                matching_subjects = ?self.matching_subjects,
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
                authorization_domain = authorization_domain,
                evidence_state = evidence_state,
                matching_subject_count = matching_subject_count,
                no_match_subject_count = no_match_subject_count,
                unavailable_subject_count = unavailable_subject_count,
                matching_subjects_truncated = matching_subjects_truncated,
                authenticated_by = ?self.authenticated_by,
                matching_subjects = ?self.matching_subjects,
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
    const MAX_CHARS: usize = 256;
    let mut sanitized = String::new();
    let mut truncated = false;
    for (index, character) in value.chars().enumerate() {
        if index >= MAX_CHARS {
            truncated = true;
            break;
        }
        if character.is_control() {
            sanitized.extend(character.escape_default());
        } else {
            sanitized.push(character);
        }
    }
    if truncated {
        sanitized.push_str("...[truncated]");
    }
    sanitized
}

fn authenticated_by(actor: &AuthenticatedActor) -> Vec<String> {
    actor
        .authenticated_by
        .iter()
        .map(|proof| {
            let kind = match proof.kind {
                ProofKind::ProcessCredentials => "process-credentials",
                ProofKind::SystemdUnit => "systemd-unit",
                ProofKind::Container => "container",
                ProofKind::SignatureKey => "signature-key",
            };
            proof.fingerprint.as_ref().map_or_else(
                || format!("{kind}:{}", proof.subject),
                |fingerprint| format!("{kind}:{}:{fingerprint}", proof.subject),
            )
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
            domain: AuthorizationDomain::HostProcess,
            subject: "svc.nats".to_string(),
            authenticated_by: vec![ProofSummary {
                kind: ProofKind::ProcessCredentials,
                subject: "svc.nats".to_string(),
                fingerprint: None,
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
        assert_eq!(rec.authorization_domain.as_deref(), Some("host-process"));
        assert_eq!(rec.authenticated_by, ["process-credentials:svc.nats"]);
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
        let oversized = "x".repeat(1_000);
        let rec = DecisionRecord::from_actor_decision(1, &actor(), Op::Get, &oversized, &decision);
        assert!(rec.key.len() < 300);
        assert!(rec.key.ends_with("...[truncated]"));
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

    #[test]
    fn resolution_error_retains_domain_and_bounds_reason() {
        let reason = format!("bad\n{}", "x".repeat(1_000));
        let record = DecisionRecord::from_resolution_error(
            4,
            &PeerInfo::default(),
            Op::Get,
            "app.secret",
            Some(AuthorizationDomain::Container),
            EvidenceState::Unavailable,
            &reason,
        );
        assert_eq!(record.authorization_domain.as_deref(), Some("container"));
        assert_eq!(record.evidence_state, "unavailable");
        assert!(!record.reason.contains('\n'));
        assert!(record.reason.ends_with("...[truncated]"));
        assert!(record.reason.len() < 300);
    }

    #[test]
    fn subject_resolution_record_retains_bounded_overlap_diagnostics() {
        let error = SubjectResolutionError::AmbiguousSubject {
            domain: AuthorizationDomain::Container,
            subjects: vec!["svc.a".to_string(), "svc.b".to_string()],
            total: 12,
            truncated: true,
            no_match_count: 3,
            unavailable_count: 1,
        };
        let record = DecisionRecord::from_subject_resolution_error(
            5,
            &PeerInfo::default(),
            Op::Get,
            "app.secret",
            &error,
            "ambiguous_actor_subject",
        );
        assert_eq!(record.matching_subjects, ["svc.a", "svc.b"]);
        assert_eq!(record.matching_subject_count, 12);
        assert_eq!(record.no_match_subject_count, 3);
        assert_eq!(record.unavailable_subject_count, 1);
        assert!(record.matching_subjects_truncated);
    }
}
