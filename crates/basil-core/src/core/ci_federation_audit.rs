// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! One terminal, secret-free audit summary for a federated CI invocation.

use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

use crate::core::ci_federation::{
    ProviderClaimEvidence, ProviderKind, ProviderOperationProfile, RunQuotaReceipt,
    VerifiedProviderEvidence,
};
use crate::state::BrokerState;

/// Maximum serialized size of one CI invocation audit event.
pub const MAX_CI_INVOCATION_EVENT_BYTES: usize = 8 * 1024;

/// Provider identity-verification state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiIdentityState {
    /// One bounded token was presented after the outer COSE verified.
    PresentedUnverified,
    /// The token and its selected configured rule verified.
    Verified,
}

/// Freshness-challenge state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiFreshnessState {
    /// Processing ended before freshness was decided.
    NotReached,
    /// The bound single-use challenge was consumed.
    Accepted,
    /// The challenge was absent, expired, mismatched, or already consumed.
    Denied,
    /// The challenge table was unavailable.
    Unavailable,
}

/// Per-run quota state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiQuotaState {
    /// Processing ended before quota was charged.
    NotReached,
    /// One operation was charged atomically.
    Charged,
    /// The run's configured operation count was exhausted.
    Exhausted,
    /// No bounded bucket could track the run.
    Untracked,
    /// The quota value or table was unavailable.
    Unavailable,
}

/// Authorization state for one policy gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiAuthorizationState {
    /// Processing ended before this authorization gate.
    NotReached,
    /// Policy allowed the operation.
    Allowed,
    /// Policy denied the operation.
    Denied,
}

/// Execution state for the requested backend operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiExecutionState {
    /// Processing ended before backend execution.
    NotReached,
    /// The backend operation was dispatched and has not returned.
    Started,
    /// The backend operation completed.
    Succeeded,
    /// The backend operation failed.
    Failed,
    /// The request future ended after dispatch but before the result was observed.
    Indeterminate,
}

/// Protected response-delivery state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiResponseState {
    /// Processing ended before response protection.
    NotReached,
    /// Response protection was dispatched and has not returned.
    Started,
    /// The protected response was constructed for delivery.
    Succeeded,
    /// Response protection failed.
    Failed,
    /// The request future ended after dispatch but before the result was observed.
    Indeterminate,
}

/// Final processing stage reached by the invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiTerminalStage {
    /// Provider identity verification.
    IdentityVerification,
    /// Envelope operation authority.
    EnvelopeAuthority,
    /// Freshness challenge consumption.
    Freshness,
    /// Policy-subject resolution.
    SubjectResolution,
    /// Per-run quota charge.
    Quota,
    /// Request recipient shape and configured key selection.
    RecipientValidation,
    /// Request-decryption authorization.
    DecryptAuthorization,
    /// Request decryption and opening.
    RequestDecryption,
    /// Typed operation decoding and validation.
    OperationValidation,
    /// Signing authorization.
    SignAuthorization,
    /// Requested backend operation.
    BackendExecution,
    /// Protected response construction.
    ResponseDelivery,
    /// Every required phase completed.
    Complete,
}

/// Terminal invocation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiTerminalOutcome {
    /// The request completed successfully.
    Success,
    /// A closed identity, freshness, quota, validation, or policy check denied it.
    Denied,
    /// Runtime execution or response protection failed.
    Failure,
    /// The request future ended without an explicit terminal path.
    Aborted,
}

/// Stable, secret-free terminal reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiTerminalReason {
    /// Every invocation phase completed.
    Completed,
    /// Provider identity did not verify.
    IdentityRejected,
    /// Envelope authority or shape was rejected.
    EnvelopeRejected,
    /// The transport presenter or policy subject was rejected.
    SubjectRejected,
    /// Freshness was denied.
    FreshnessDenied,
    /// Freshness state was unavailable.
    FreshnessUnavailable,
    /// Per-run quota was exhausted.
    QuotaExhausted,
    /// The run could not be tracked in the bounded quota table.
    QuotaUntracked,
    /// Quota state was unavailable.
    QuotaUnavailable,
    /// Request-decryption policy denied the operation.
    DecryptDenied,
    /// The request recipient identifier or configured recipient was invalid.
    RecipientRejected,
    /// Request decryption or opening failed.
    DecryptFailed,
    /// The decrypted operation body was invalid or unsupported.
    OperationRejected,
    /// Signing policy denied the requested target.
    SignDenied,
    /// Backend execution failed.
    BackendFailed,
    /// Response protection failed after the earlier states were retained.
    ResponseFailed,
    /// The request future was cancelled or otherwise dropped in flight.
    Aborted,
}

/// Verified provider identity projected into the audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiVerifiedIdentity {
    /// Closed provider kind selected from trusted configuration.
    pub provider: ProviderKind,
    /// Exact configured issuer.
    pub issuer: String,
    /// Exact configured rule ID.
    pub rule_id: String,
    /// Exact policy subject granted by the rule.
    pub subject: String,
    /// Stable provider repository ID.
    pub repository_id: u64,
    /// Stable provider repository-owner ID.
    pub repository_owner_id: u64,
    /// Provider repository name.
    pub repository: String,
    /// Provider actor ID, when attested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<u64>,
    /// Provider workflow identity.
    pub workflow_ref: String,
    /// Provider workflow commit, when attested separately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow_sha: Option<String>,
    /// Triggering ref.
    pub ref_name: String,
    /// Ref type, when attested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_type: Option<String>,
    /// Triggering commit, when attested separately.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
    /// Closed provider event.
    pub event_name: String,
    /// Runner trust class, when attested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runner_environment: Option<String>,
    /// Protected deployment environment, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Provider run ID.
    pub run_id: u64,
    /// Provider run attempt.
    pub run_attempt: u64,
}

impl From<&VerifiedProviderEvidence> for CiVerifiedIdentity {
    fn from(evidence: &VerifiedProviderEvidence) -> Self {
        match &evidence.claims {
            ProviderClaimEvidence::GithubActions(claims) => Self {
                provider: evidence.provider,
                issuer: evidence.issuer.clone(),
                rule_id: evidence.rule_id.clone(),
                subject: evidence.subject.clone(),
                repository_id: claims.repository_id,
                repository_owner_id: claims.repository_owner_id,
                repository: claims.repository.clone(),
                actor_id: claims.actor_id,
                workflow_ref: claims.workflow_ref.clone(),
                workflow_sha: Some(claims.workflow_sha.clone()),
                ref_name: claims.ref_name.clone(),
                ref_type: None,
                sha: None,
                event_name: claims.event_name.clone(),
                runner_environment: Some(claims.runner_environment.clone()),
                environment: claims.environment.clone(),
                run_id: claims.run_id,
                run_attempt: claims.run_attempt,
            },
            ProviderClaimEvidence::ForgejoActions(claims) => Self {
                provider: evidence.provider,
                issuer: evidence.issuer.clone(),
                rule_id: evidence.rule_id.clone(),
                subject: evidence.subject.clone(),
                repository_id: claims.repository_id,
                repository_owner_id: claims.repository_owner_id,
                repository: claims.repository.clone(),
                actor_id: claims.actor_id,
                workflow_ref: claims.workflow_ref.clone(),
                workflow_sha: None,
                ref_name: claims.ref_name.clone(),
                ref_type: Some(claims.ref_type.clone()),
                sha: Some(claims.sha.clone()),
                event_name: claims.event_name.clone(),
                runner_environment: None,
                environment: None,
                run_id: claims.run_id,
                run_attempt: claims.run_attempt,
            },
        }
    }
}

/// Correlation values derived after outer COSE verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiInvocationCorrelation {
    /// Invocation ID derived from the complete request, fixed 43-character base64url.
    pub invocation_id: String,
    /// Bounded COSE message ID, encoded as base64url when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// Keyed raw-token digest, fixed 43-character base64url after verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_digest: Option<String>,
    /// Keyed token-ID digest, fixed 43-character base64url after verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti_digest: Option<String>,
    /// RFC 7638 proof-key thumbprint, fixed 43-character base64url.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_jkt: Option<String>,
}

/// Envelope authority accepted after verified identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiAcceptedOperation {
    /// Closed provider operation profile.
    pub profile: ProviderOperationProfile,
    /// Exact catalog target authorized by the envelope and selected rule.
    pub target: String,
}

/// Exact quota state and atomic receipt, when charged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiQuotaAudit {
    /// Closed quota state.
    pub state: CiQuotaState,
    /// Exact configured per-run limit, when identity verification selected a rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Count after this request's atomic charge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charged_count: Option<u64>,
    /// Remaining charges after this request's atomic charge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining: Option<u64>,
}

/// One terminal CI invocation summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiInvocationAuditEvent {
    event: CiInvocationEventVersion,
    started_at: String,
    occurred_at: String,
    /// Serving generation pinned at request entry.
    pub generation: u64,
    /// Identity-verification state.
    pub identity_state: CiIdentityState,
    /// Verified identity, present only after successful verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<CiVerifiedIdentity>,
    /// Correlation values; none are raw request credentials or bodies.
    pub correlation: CiInvocationCorrelation,
    /// Accepted operation authority, present only after envelope authorization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_operation: Option<CiAcceptedOperation>,
    /// Freshness phase state.
    pub freshness: CiFreshnessState,
    /// Per-run quota phase state.
    pub quota: CiQuotaAudit,
    /// Request-decryption authorization state.
    pub decrypt_authorization: CiAuthorizationState,
    /// Signing authorization state.
    pub sign_authorization: CiAuthorizationState,
    /// Requested backend-operation state.
    pub backend_execution: CiExecutionState,
    /// Protected response state.
    pub response_delivery: CiResponseState,
    /// Final stage.
    pub stage: CiTerminalStage,
    /// Final outcome.
    pub outcome: CiTerminalOutcome,
    /// Stable terminal reason.
    pub reason: CiTerminalReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CiInvocationEventVersion {
    kind: &'static str,
    version: u8,
}

impl CiInvocationAuditEvent {
    /// Serialize the complete version-one event.
    pub(crate) fn json_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }

    /// Correlation ID retained by the complete event and its trace record.
    pub(crate) fn invocation_id(&self) -> &str {
        &self.correlation.invocation_id
    }

    /// Verified rule included after identity verification.
    pub(crate) fn rule_id(&self) -> Option<&str> {
        self.identity
            .as_ref()
            .map(|identity| identity.rule_id.as_str())
    }

    /// Verified provider included after identity verification.
    pub(crate) fn provider(&self) -> Option<ProviderKind> {
        self.identity.as_ref().map(|identity| identity.provider)
    }

    /// Accepted target included after envelope authority.
    pub(crate) fn accepted_target(&self) -> Option<&str> {
        self.accepted_operation
            .as_ref()
            .map(|operation| operation.target.as_str())
    }
}

trait CiInvocationEventSink: Send + Sync {
    fn record(&self, event: &CiInvocationAuditEvent);
}

impl CiInvocationEventSink for BrokerState {
    fn record(&self, event: &CiInvocationAuditEvent) {
        self.record_ci_invocation_event(event);
    }
}

/// Non-cloneable lifecycle that emits exactly one terminal event.
pub struct CiInvocationAudit {
    sink: Arc<dyn CiInvocationEventSink>,
    event: Option<CiInvocationAuditEvent>,
}

impl fmt::Debug for CiInvocationAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CiInvocationAudit")
            .field("sink", &"event sink")
            .field("event", &self.event)
            .finish()
    }
}

impl CiInvocationAudit {
    /// Start an audit lifecycle after outer COSE verification found one bounded token.
    pub(crate) fn presented(
        state: Arc<BrokerState>,
        generation: u64,
        request_digest: [u8; 32],
        message_id: Option<&[u8]>,
    ) -> Self {
        Self::with_sink(state, generation, request_digest, message_id)
    }

    fn with_sink(
        sink: Arc<dyn CiInvocationEventSink>,
        generation: u64,
        request_digest: [u8; 32],
        message_id: Option<&[u8]>,
    ) -> Self {
        Self {
            sink,
            event: Some(CiInvocationAuditEvent {
                event: CiInvocationEventVersion {
                    kind: "basil.audit.ci_invocation",
                    version: 1,
                },
                started_at: crate::audit::timestamp(),
                occurred_at: String::new(),
                generation,
                identity_state: CiIdentityState::PresentedUnverified,
                identity: None,
                correlation: CiInvocationCorrelation {
                    invocation_id: encode_digest(&request_digest),
                    message_id: message_id.map(|id| URL_SAFE_NO_PAD.encode(id)),
                    token_digest: None,
                    jti_digest: None,
                    proof_jkt: None,
                },
                accepted_operation: None,
                freshness: CiFreshnessState::NotReached,
                quota: CiQuotaAudit {
                    state: CiQuotaState::NotReached,
                    limit: None,
                    charged_count: None,
                    remaining: None,
                },
                decrypt_authorization: CiAuthorizationState::NotReached,
                sign_authorization: CiAuthorizationState::NotReached,
                backend_execution: CiExecutionState::NotReached,
                response_delivery: CiResponseState::NotReached,
                stage: CiTerminalStage::IdentityVerification,
                outcome: CiTerminalOutcome::Aborted,
                reason: CiTerminalReason::Aborted,
            }),
        }
    }

    /// Bind a proof-key thumbprint after strict proof-key decoding.
    pub(crate) fn proof_key(&mut self, thumbprint: &[u8; 32]) {
        if let Some(event) = &mut self.event {
            event.correlation.proof_jkt = Some(encode_digest(thumbprint));
        }
    }

    /// Bind a keyed raw-token digest before identity verification.
    pub(crate) fn presented_token(&mut self, digest: &[u8; 32]) {
        if let Some(event) = &mut self.event {
            event.correlation.token_digest = Some(encode_digest(digest));
        }
    }

    /// Record successful provider identity verification.
    pub(crate) fn verified(&mut self, evidence: &VerifiedProviderEvidence) {
        if let Some(event) = &mut self.event {
            event.identity_state = CiIdentityState::Verified;
            event.identity = Some(CiVerifiedIdentity::from(evidence));
            event.correlation.token_digest = Some(encode_digest(evidence.claims.token_digest()));
            event.correlation.jti_digest = Some(encode_digest(evidence.claims.jti_digest()));
            event.quota.limit = evidence.max_operations_per_run;
            event.stage = CiTerminalStage::EnvelopeAuthority;
        }
    }

    /// Record envelope authority only after the verified rule accepted it.
    pub(crate) fn accepted_operation(&mut self, target: String) {
        if let Some(event) = &mut self.event {
            event.accepted_operation = Some(CiAcceptedOperation {
                profile: ProviderOperationProfile::ArtifactSign,
                target,
            });
            event.stage = CiTerminalStage::Freshness;
        }
    }

    /// Record successful freshness consumption.
    pub(crate) const fn freshness_accepted(&mut self) {
        if let Some(event) = &mut self.event {
            event.freshness = CiFreshnessState::Accepted;
            event.stage = CiTerminalStage::SubjectResolution;
        }
    }

    /// Record a freshness denial.
    pub(crate) const fn freshness_denied(&mut self) {
        if let Some(event) = &mut self.event {
            event.freshness = CiFreshnessState::Denied;
            event.stage = CiTerminalStage::Freshness;
        }
    }

    /// Record unavailable freshness state.
    pub(crate) const fn freshness_unavailable(&mut self) {
        if let Some(event) = &mut self.event {
            event.freshness = CiFreshnessState::Unavailable;
            event.stage = CiTerminalStage::Freshness;
        }
    }

    /// Advance past subject resolution.
    pub(crate) const fn subject_resolved(&mut self) {
        if let Some(event) = &mut self.event {
            event.stage = CiTerminalStage::Quota;
        }
    }

    /// Record one atomic quota charge receipt.
    pub(crate) const fn quota_charged(&mut self, receipt: RunQuotaReceipt) {
        if let Some(event) = &mut self.event {
            event.quota.state = CiQuotaState::Charged;
            event.quota.charged_count = Some(receipt.charged_count);
            event.quota.remaining = Some(receipt.remaining);
            event.stage = CiTerminalStage::DecryptAuthorization;
        }
    }

    /// Record an exact quota denial state.
    pub(crate) const fn quota_denied(&mut self, state: CiQuotaState) {
        if let Some(event) = &mut self.event {
            event.quota.state = state;
            event.stage = CiTerminalStage::Quota;
        }
    }

    /// Record request-decryption authorization.
    pub(crate) const fn decrypt_authorized(&mut self, allowed: bool) {
        if let Some(event) = &mut self.event {
            event.decrypt_authorization = if allowed {
                CiAuthorizationState::Allowed
            } else {
                CiAuthorizationState::Denied
            };
            event.stage = if allowed {
                CiTerminalStage::RequestDecryption
            } else {
                CiTerminalStage::DecryptAuthorization
            };
        }
    }

    /// Advance after the request body was decrypted and opened.
    pub(crate) const fn request_decrypted(&mut self) {
        if let Some(event) = &mut self.event {
            event.stage = CiTerminalStage::OperationValidation;
        }
    }

    /// Record signing authorization.
    pub(crate) const fn sign_authorized(&mut self, allowed: bool) {
        if let Some(event) = &mut self.event {
            event.sign_authorization = if allowed {
                CiAuthorizationState::Allowed
            } else {
                CiAuthorizationState::Denied
            };
            event.stage = if allowed {
                CiTerminalStage::BackendExecution
            } else {
                CiTerminalStage::SignAuthorization
            };
        }
    }

    /// Record requested backend execution without changing earlier states.
    pub(crate) const fn backend_started(&mut self) {
        if let Some(event) = &mut self.event {
            event.backend_execution = CiExecutionState::Started;
            event.stage = CiTerminalStage::BackendExecution;
        }
    }

    /// Record requested backend execution without changing earlier states.
    pub(crate) const fn backend_executed(&mut self, succeeded: bool) {
        if let Some(event) = &mut self.event {
            event.backend_execution = if succeeded {
                CiExecutionState::Succeeded
            } else {
                CiExecutionState::Failed
            };
            event.stage = CiTerminalStage::ResponseDelivery;
        }
    }

    /// Record response protection dispatch without changing earlier states.
    pub(crate) const fn response_started(&mut self) {
        if let Some(event) = &mut self.event {
            event.response_delivery = CiResponseState::Started;
            event.stage = CiTerminalStage::ResponseDelivery;
        }
    }

    /// Record response protection completion without changing earlier states.
    pub(crate) const fn response_delivered(&mut self, succeeded: bool) {
        if let Some(event) = &mut self.event {
            event.response_delivery = if succeeded {
                CiResponseState::Succeeded
            } else {
                CiResponseState::Failed
            };
            event.stage = if succeeded {
                CiTerminalStage::Complete
            } else {
                CiTerminalStage::ResponseDelivery
            };
        }
    }

    /// Emit the terminal event once. Later calls and `Drop` are inert.
    pub(crate) fn finish(
        &mut self,
        stage: CiTerminalStage,
        outcome: CiTerminalOutcome,
        reason: CiTerminalReason,
    ) {
        let Some(mut event) = self.event.take() else {
            return;
        };
        event.occurred_at = crate::audit::timestamp();
        event.stage = stage;
        event.outcome = outcome;
        event.reason = reason;
        self.sink.record(&event);
    }
}

impl Drop for CiInvocationAudit {
    fn drop(&mut self) {
        let Some(mut event) = self.event.take() else {
            return;
        };
        if event.backend_execution == CiExecutionState::Started {
            event.backend_execution = CiExecutionState::Indeterminate;
        }
        if event.response_delivery == CiResponseState::Started {
            event.response_delivery = CiResponseState::Indeterminate;
        }
        event.occurred_at = crate::audit::timestamp();
        event.outcome = CiTerminalOutcome::Aborted;
        event.reason = CiTerminalReason::Aborted;
        self.sink.record(&event);
    }
}

fn encode_digest(digest: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;

    use super::*;
    use crate::core::ci_federation::{
        ForgejoEvidence, GithubEvidence, MAX_AUDIT_SHORT_BYTES, MAX_AUDIT_TEXT_BYTES,
        MAX_AUDIT_WORKFLOW_BYTES, MAX_PROVIDER_URL_BYTES, proof_key_thumbprint,
    };

    #[derive(Default)]
    struct RecordingSink(Mutex<Vec<CiInvocationAuditEvent>>);

    impl CiInvocationEventSink for RecordingSink {
        fn record(&self, event: &CiInvocationAuditEvent) {
            self.0.lock().expect("recording sink").push(event.clone());
        }
    }

    fn github_evidence() -> VerifiedProviderEvidence {
        VerifiedProviderEvidence {
            provider: ProviderKind::GithubActions,
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            rule_id: "release".to_string(),
            subject: "ci/release".to_string(),
            broker_audience: "basil://ci.test/invocation".to_string(),
            operation_profiles: vec![ProviderOperationProfile::ArtifactSign],
            artifact_sign_key_ids: vec!["release-signing".to_string()],
            max_operations_per_run: Some(8),
            run_bucket_retention_secs: 330,
            claims: ProviderClaimEvidence::GithubActions(GithubEvidence {
                repository_id: 42,
                repository_owner_id: 7,
                repository: "openbasil/basil".to_string(),
                actor_id: Some(9),
                workflow_ref: "openbasil/basil/.github/workflows/release.yml@refs/heads/main"
                    .to_string(),
                workflow_sha: "a".repeat(40),
                ref_name: "refs/heads/main".to_string(),
                event_name: "push".to_string(),
                runner_environment: "github-hosted".to_string(),
                environment: None,
                run_id: 100,
                run_attempt: 2,
                jti_digest: [2; 32],
                token_digest: [3; 32],
            }),
        }
    }

    fn forgejo_evidence() -> VerifiedProviderEvidence {
        VerifiedProviderEvidence {
            provider: ProviderKind::ForgejoActions,
            issuer: "https://forge.example/api/actions".to_string(),
            rule_id: "nightly".to_string(),
            subject: "ci/nightly".to_string(),
            broker_audience: "basil://ci.test/invocation".to_string(),
            operation_profiles: vec![ProviderOperationProfile::ArtifactSign],
            artifact_sign_key_ids: vec!["nightly-signing".to_string()],
            max_operations_per_run: Some(4),
            run_bucket_retention_secs: 330,
            claims: ProviderClaimEvidence::ForgejoActions(ForgejoEvidence {
                repository_id: 11,
                repository_owner_id: 3,
                repository: "forge/basil".to_string(),
                actor_id: None,
                workflow_ref: "forge/basil/.forgejo/workflows/release.yml@refs/heads/main"
                    .to_string(),
                ref_name: "refs/heads/main".to_string(),
                ref_type: "branch".to_string(),
                sha: "b".repeat(40),
                run_id: 900,
                run_attempt: 1,
                event_name: "push".to_string(),
                jti_digest: [4; 32],
                token_digest: [5; 32],
            }),
        }
    }

    fn lifecycle(sink: Arc<RecordingSink>) -> CiInvocationAudit {
        CiInvocationAudit::with_sink(sink, 7, [1; 32], Some(&[9; 16]))
    }

    fn keyed_marker(marker: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&[0x5a; 32])
            .expect("fixed key");
        mac.update(marker);
        mac.finalize().into_bytes().into()
    }

    #[test]
    fn provider_shapes_omit_unattested_optional_evidence() {
        let sink = Arc::new(RecordingSink::default());
        let mut github = lifecycle(Arc::clone(&sink));
        github.verified(&github_evidence());
        github.finish(
            CiTerminalStage::IdentityVerification,
            CiTerminalOutcome::Denied,
            CiTerminalReason::EnvelopeRejected,
        );
        let mut forgejo = lifecycle(Arc::clone(&sink));
        forgejo.verified(&forgejo_evidence());
        forgejo.finish(
            CiTerminalStage::IdentityVerification,
            CiTerminalOutcome::Denied,
            CiTerminalReason::EnvelopeRejected,
        );

        let events = sink.0.lock().expect("events");
        let github = serde_json::to_value(&events[0]).expect("serialize github");
        let forgejo = serde_json::to_value(&events[1]).expect("serialize forgejo");
        assert!(github["identity"].get("environment").is_none());
        assert!(github["identity"].get("ref_type").is_none());
        assert!(forgejo["identity"].get("actor_id").is_none());
        assert!(forgejo["identity"].get("runner_environment").is_none());
        assert!(forgejo["identity"].get("workflow_sha").is_none());
        drop(events);
    }

    #[test]
    fn terminal_paths_emit_exactly_once_and_cancellation_aborts() {
        let sink = Arc::new(RecordingSink::default());
        let mut success = lifecycle(Arc::clone(&sink));
        success.finish(
            CiTerminalStage::Complete,
            CiTerminalOutcome::Success,
            CiTerminalReason::Completed,
        );
        success.finish(
            CiTerminalStage::ResponseDelivery,
            CiTerminalOutcome::Failure,
            CiTerminalReason::ResponseFailed,
        );
        drop(success);

        let mut denied = lifecycle(Arc::clone(&sink));
        denied.freshness_denied();
        denied.finish(
            CiTerminalStage::Freshness,
            CiTerminalOutcome::Denied,
            CiTerminalReason::FreshnessDenied,
        );
        drop(denied);

        let mut response_failure = lifecycle(Arc::clone(&sink));
        response_failure.backend_executed(true);
        response_failure.response_delivered(false);
        response_failure.finish(
            CiTerminalStage::ResponseDelivery,
            CiTerminalOutcome::Failure,
            CiTerminalReason::ResponseFailed,
        );
        drop(response_failure);

        drop(lifecycle(Arc::clone(&sink)));
        let mut backend_cancelled = lifecycle(Arc::clone(&sink));
        backend_cancelled.backend_started();
        drop(backend_cancelled);
        let mut response_cancelled = lifecycle(Arc::clone(&sink));
        response_cancelled.backend_started();
        response_cancelled.backend_executed(true);
        response_cancelled.response_started();
        drop(response_cancelled);
        let events = sink.0.lock().expect("events");
        assert_eq!(events.len(), 6);
        assert_eq!(events[0].outcome, CiTerminalOutcome::Success);
        assert_eq!(events[1].outcome, CiTerminalOutcome::Denied);
        assert_eq!(events[2].backend_execution, CiExecutionState::Succeeded);
        assert_eq!(events[2].response_delivery, CiResponseState::Failed);
        assert_eq!(events[3].outcome, CiTerminalOutcome::Aborted);
        assert_eq!(events[4].backend_execution, CiExecutionState::Indeterminate);
        assert_eq!(events[4].response_delivery, CiResponseState::NotReached);
        assert_eq!(events[5].backend_execution, CiExecutionState::Succeeded);
        assert_eq!(events[5].response_delivery, CiResponseState::Indeterminate);
        assert!(events.iter().all(|event| !event.occurred_at.is_empty()));
        drop(events);
    }

    #[test]
    fn phase_matrix_retains_charge_across_later_failure_and_redacts_material() {
        let sink = Arc::new(RecordingSink::default());
        let raw_token = b"raw-jwt-marker";
        let raw_jti = b"raw-jti-marker";
        let mut raw_proof_key = [0u8; 32];
        raw_proof_key[..16].copy_from_slice(b"proof-key-marker");
        let raw_request = b"plaintext-marker|signature-marker";
        let request_digest = basil_cose::request_hash(raw_request).0;
        let mut evidence = github_evidence();
        let ProviderClaimEvidence::GithubActions(claims) = &mut evidence.claims else {
            panic!("GitHub fixture changed provider shape");
        };
        claims.token_digest = keyed_marker(raw_token);
        claims.jti_digest = keyed_marker(raw_jti);
        let mut audit =
            CiInvocationAudit::with_sink(sink.clone(), 7, request_digest, Some(&[9; 16]));
        audit.presented_token(&keyed_marker(raw_token));
        audit.proof_key(&proof_key_thumbprint(&raw_proof_key));
        audit.verified(&evidence);
        audit.accepted_operation("release-signing".to_string());
        audit.freshness_accepted();
        audit.subject_resolved();
        audit.quota_charged(RunQuotaReceipt {
            charged_count: 3,
            remaining: 5,
        });
        audit.decrypt_authorized(true);
        audit.request_decrypted();
        audit.sign_authorized(true);
        audit.backend_executed(false);
        audit.response_delivered(true);
        audit.finish(
            CiTerminalStage::BackendExecution,
            CiTerminalOutcome::Failure,
            CiTerminalReason::BackendFailed,
        );

        let events = sink.0.lock().expect("events");
        let rendered = serde_json::to_string(&events[0]).expect("serialize event");
        assert!(rendered.len() <= MAX_CI_INVOCATION_EVENT_BYTES);
        assert_eq!(events[0].quota.state, CiQuotaState::Charged);
        assert_eq!(events[0].quota.charged_count, Some(3));
        assert_eq!(events[0].quota.remaining, Some(5));
        assert_eq!(events[0].backend_execution, CiExecutionState::Failed);
        assert_eq!(events[0].response_delivery, CiResponseState::Succeeded);
        assert_eq!(events[0].correlation.invocation_id.len(), 43);
        assert_eq!(
            events[0].correlation.token_digest.as_deref().map(str::len),
            Some(43)
        );
        assert_eq!(
            events[0].correlation.jti_digest.as_deref().map(str::len),
            Some(43)
        );
        assert_eq!(
            events[0].correlation.proof_jkt.as_deref().map(str::len),
            Some(43)
        );
        drop(events);
        for forbidden in [
            "raw-jwt-marker",
            "raw-jti-marker",
            "proof-key-marker",
            "plaintext-marker",
            "signature-marker",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }

    fn finish_maximal_event(sink: Arc<RecordingSink>, evidence: &VerifiedProviderEvidence) {
        let mut audit =
            CiInvocationAudit::with_sink(sink, u64::MAX, [u8::MAX; 32], Some(&[u8::MAX; 64]));
        audit.proof_key(&[u8::MAX; 32]);
        audit.verified(evidence);
        audit.accepted_operation("\\".repeat(128));
        audit.freshness_accepted();
        audit.subject_resolved();
        audit.quota_charged(RunQuotaReceipt {
            charged_count: u64::MAX,
            remaining: u64::MAX,
        });
        audit.decrypt_authorized(true);
        audit.request_decrypted();
        audit.sign_authorized(true);
        audit.backend_started();
        audit.backend_executed(true);
        audit.response_started();
        audit.response_delivered(true);
        audit.finish(
            CiTerminalStage::Complete,
            CiTerminalOutcome::Success,
            CiTerminalReason::Completed,
        );
    }

    #[test]
    fn maximal_escape_heavy_verified_events_fit_complete_v1_shape() {
        let sink = Arc::new(RecordingSink::default());
        let mut github = github_evidence();
        github.rule_id = "\\".repeat(128);
        github.subject = "\"".repeat(256);
        let ProviderClaimEvidence::GithubActions(claims) = &mut github.claims else {
            panic!("GitHub fixture changed provider shape");
        };
        claims.repository = "\\".repeat(MAX_AUDIT_TEXT_BYTES);
        claims.workflow_ref = "\"".repeat(MAX_AUDIT_WORKFLOW_BYTES);
        claims.workflow_sha = "\\".repeat(MAX_AUDIT_SHORT_BYTES);
        claims.ref_name = "\"".repeat(MAX_AUDIT_TEXT_BYTES);
        claims.event_name = "\\".repeat(MAX_AUDIT_SHORT_BYTES);
        claims.runner_environment = "\"".repeat(MAX_AUDIT_SHORT_BYTES);
        claims.environment = Some("\\".repeat(MAX_AUDIT_TEXT_BYTES));
        claims.actor_id = Some(u64::MAX);
        claims.run_id = u64::MAX;
        claims.run_attempt = u64::MAX;
        finish_maximal_event(Arc::clone(&sink), &github);

        let mut forgejo = forgejo_evidence();
        let suffix = "/api/actions";
        forgejo.issuer = format!(
            "https://forge.example/{}{}",
            "a".repeat(MAX_PROVIDER_URL_BYTES - "https://forge.example/".len() - suffix.len()),
            suffix
        );
        forgejo.rule_id = "\"".repeat(128);
        forgejo.subject = "\\".repeat(256);
        let ProviderClaimEvidence::ForgejoActions(claims) = &mut forgejo.claims else {
            panic!("Forgejo fixture changed provider shape");
        };
        claims.repository = "\"".repeat(MAX_AUDIT_TEXT_BYTES);
        claims.workflow_ref = "\\".repeat(MAX_AUDIT_WORKFLOW_BYTES);
        claims.ref_name = "\"".repeat(MAX_AUDIT_TEXT_BYTES);
        claims.ref_type = "\\".repeat(MAX_AUDIT_SHORT_BYTES);
        claims.sha = "\"".repeat(MAX_AUDIT_SHORT_BYTES);
        claims.event_name = "\\".repeat(MAX_AUDIT_SHORT_BYTES);
        claims.actor_id = Some(u64::MAX);
        claims.run_id = u64::MAX;
        claims.run_attempt = u64::MAX;
        finish_maximal_event(Arc::clone(&sink), &forgejo);

        let events = sink.0.lock().expect("events");
        assert_eq!(events.len(), 2);
        for event in events.iter() {
            let value = event.json_value().expect("serialize complete event");
            let serialized = serde_json::to_vec(&value).expect("render complete event");
            assert!(serialized.len() <= MAX_CI_INVOCATION_EVENT_BYTES);
            assert!(value.get("bounded").is_none());
            assert!(value.get("identity").is_some());
            assert_eq!(value["accepted_operation"]["target"], "\\".repeat(128));
            assert_eq!(value["backend_execution"], "succeeded");
            assert_eq!(value["response_delivery"], "succeeded");
        }
    }
}
