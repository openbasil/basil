#![allow(clippy::result_large_err)]

// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil_cose::{
    Claims, ContentAlgorithm, ContentType, ExternalAad, KdfParties, KeyId, MessageId, MessageRole,
    ResponseSubject, SealParams, SealedAad, SignError, Signature, SignatureAlgorithm, Signer,
    Subject, UnixTime, ValidationParams, Verifier, VerifyError, VerifySealedParams,
    X25519RecipientPublic, build_sealed, request_hash, verify_sealed,
};
use basil_proto::broker::v1 as pb;
use basil_proto::broker::v1::invocation_service_server::InvocationService;
use basil_proto::invocation::{
    CONTENT_TYPE_SIGN_REQUEST, CONTENT_TYPE_SIGN_RESPONSE, DEFAULT_EXPIRES_AFTER_SECS,
    InvocationStatus, SignInvocationRequest, SignInvocationResponse,
};
use tonic::{Code, Request, Response, Status};
use zeroize::Zeroizing;

use crate::actor::{AuthenticatedActor, host_process_snapshot, resolve_evidence_actor};
use crate::actor::{PresenterInfo, ProofKind, ProofSummary, TransportInfo};
use crate::catalog::Class;
use crate::catalog::evidence::{
    EvidencePredicate, EvidenceState, EvidenceValue, SignatureKeyEvidence,
};
use crate::catalog::policy::{Op, ResolvedPolicy, SignatureKeyAlgorithm};
use crate::decision::DecisionRecord;
use crate::service::broker::{BrokerGrpc, GrpcResult};
use crate::service::shared::{invalid_request, manager_status};
use crate::transport::{broker_status, peer_from_request};

const BROKER_KEY_USE_LABEL: &str = "broker_key_use";
const BROKER_RESPONSE_ENCRYPTION_USE: &str = "response-encryption";
const INVOKE_OP: &str = "invoke";
const CHALLENGE_OP: &str = "get_invocation_challenge";
/// Frozen local courier contract version from SPEC revision 4.2.
const COURIER_PROTOCOL_VERSION: u32 = 1;
/// Wire bound on `courier_observed_source`: a rate-limit partition key only.
const MAX_COURIER_SOURCE_BYTES: usize = 128;

#[tonic::async_trait]
impl InvocationService for BrokerGrpc {
    async fn invoke(&self, request: Request<pb::SealedRequest>) -> GrpcResult<pb::SealedResponse> {
        if !self.invocation.enabled {
            return Err(broker_status(
                Code::FailedPrecondition,
                "INVOCATION_DISABLED",
                INVOKE_OP,
                "InvocationService is disabled; set invocation.enable=true to accept sealed invocations",
            ));
        }
        match self.prepare_invocation(&request).await? {
            PreparedRequest::Proceed(prepared) => {
                tracing::debug!(
                    sender_subject = %prepared.actor.subject,
                    recipient_key_id = %prepared.recipient_key_id,
                    response_key_id = %prepared.response_recipient.key_id(),
                    plaintext_len = prepared.body.len(),
                    "sealed invocation preflight accepted",
                );
                self.execute_invocation(*prepared)
                    .await
                    .map(Response::new)
                    .map_err(|error| {
                        tracing::warn!(%error, "sealed invocation response protection failed");
                        response_protection_failed()
                    })
            }
            PreparedRequest::Denied(denied) => self
                .protect_denied_invocation(&denied)
                .await
                .map(Response::new)
                .map_err(|error| {
                    tracing::warn!(%error, "sealed invocation response protection failed");
                    response_protection_failed()
                }),
        }
    }

    /// Issue a single-use freshness challenge (SPEC rev 4 Freshness).
    ///
    /// Reachable without authentication: the requested `jkt` is self-asserted
    /// and grants nothing; it only binds the issued challenge to one proof
    /// key and partitions issuance rate limits. Declined issuance under
    /// capacity or rate-limit pressure is `RESOURCE_EXHAUSTED` with the
    /// stable reason `CHALLENGE_ISSUANCE_DECLINED`, retryable with the same
    /// request after backoff.
    async fn get_invocation_challenge(
        &self,
        request: Request<pb::GetInvocationChallengeRequest>,
    ) -> GrpcResult<pb::GetInvocationChallengeResponse> {
        if !self.invocation.enabled {
            return Err(broker_status(
                Code::FailedPrecondition,
                "INVOCATION_DISABLED",
                CHALLENGE_OP,
                "InvocationService is disabled; set invocation.enable=true to issue challenges",
            ));
        }
        let body = request.get_ref();
        let Ok(jkt) = <[u8; 32]>::try_from(body.jkt.as_slice()) else {
            return Err(invalid_request(
                CHALLENGE_OP,
                "jkt must be exactly 32 bytes",
            ));
        };
        let source = body.courier_observed_source.as_deref();
        if source.is_some_and(|source| source.len() > MAX_COURIER_SOURCE_BYTES) {
            return Err(invalid_request(
                CHALLENGE_OP,
                "courier_observed_source exceeds 128 bytes",
            ));
        }
        let generation = self.state.load_generation().id();
        let now = i64::from(self.invocation_now_unix());
        let issued = self
            .invocation_tables
            .lock()
            .map_err(|_| challenge_table_unavailable(CHALLENGE_OP))?
            .issue(jkt, source, generation, now);
        match issued {
            Ok(issued) => Ok(Response::new(pb::GetInvocationChallengeResponse {
                challenge: issued.challenge.to_vec(),
                generation,
                expires_at_unix: issued.expires_at_unix,
            })),
            Err(decline) => {
                tracing::debug!(reason = %decline, "invocation challenge issuance declined");
                Err(challenge_issuance_declined())
            }
        }
    }

    async fn get_invocation_capabilities(
        &self,
        _request: Request<pb::GetInvocationCapabilitiesRequest>,
    ) -> GrpcResult<pb::GetInvocationCapabilitiesResponse> {
        let listener_profile = match self.listener_type {
            crate::transport::grpc_server::ListenerType::Host => pb::ListenerProfile::Host,
            crate::transport::grpc_server::ListenerType::Container => {
                pb::ListenerProfile::Container
            }
            crate::transport::grpc_server::ListenerType::Courier => pb::ListenerProfile::Courier,
        };
        Ok(Response::new(pb::GetInvocationCapabilitiesResponse {
            listener_profile: listener_profile.into(),
            require_challenge: self.invocation.require_challenge,
            courier_protocol_version: COURIER_PROTOCOL_VERSION,
        }))
    }
}

#[derive(Clone, PartialEq, Eq)]
struct DecryptedInvocationBody(Zeroizing<Vec<u8>>);

impl DecryptedInvocationBody {
    const fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for DecryptedInvocationBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedInvocationBody")
            .field("len", &self.len())
            .field("redacted", &true)
            .finish()
    }
}

/// Outcome of the invocation preflight: proceed to the typed operation, or
/// answer a sealed denial — a freshness denial (`CHALLENGE_UNKNOWN`, before
/// authorization, quota, or the backend) or a per-run quota denial
/// (retryable-never `PER_RUN_QUOTA_EXCEEDED` on exhaustion, retryable
/// `RUN_QUOTA_UNTRACKED` on bucket-table pressure; both after subject
/// resolution and before authorization or the backend).
#[derive(Debug)]
enum PreparedRequest {
    Proceed(Box<PreparedInvocation>),
    Denied(DeniedInvocation),
}

#[derive(Debug)]
struct PreparedInvocation {
    generation: std::sync::Arc<crate::state::Generation>,
    actor: AuthenticatedActor,
    recipient_key_id: String,
    response_recipient: ResponseRecipient,
    response_subject: Option<String>,
    content_type: String,
    claims: Claims,
    request_message: Vec<u8>,
    body: DecryptedInvocationBody,
}

impl PreparedInvocation {
    fn envelope(&self) -> ResponseEnvelope<'_> {
        ResponseEnvelope {
            response_recipient: &self.response_recipient,
            response_subject: self.response_subject.as_deref(),
            request_message: &self.request_message,
            request_message_id: &self.claims.message_id,
        }
    }
}

/// The sealed status a denied preflight answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SealedDenial {
    /// The freshness challenge did not consume; the client fetches a fresh
    /// challenge and rebuilds. Not retryable with the same message.
    ChallengeUnknown,
    /// The rule's per-run operation quota is exhausted for this
    /// `(rule, run_id, run_attempt)`; never retryable within the run.
    PerRunQuotaExceeded,
    /// The rule's bounded run-bucket allowance cannot track this run yet
    /// (table pressure, not exhaustion); retryable after expired buckets
    /// are reclaimed.
    RunQuotaUntracked,
}

impl SealedDenial {
    fn status(self) -> InvocationStatus {
        match self {
            Self::ChallengeUnknown => InvocationStatus::challenge_unknown(),
            Self::PerRunQuotaExceeded => InvocationStatus::per_run_quota_exceeded(),
            Self::RunQuotaUntracked => InvocationStatus::run_quota_untracked(),
        }
    }
}

/// A request denied at the freshness-challenge or per-run quota step.
/// Carries exactly what is needed to protect the sealed denial response;
/// the request body is never decrypted.
#[derive(Debug)]
struct DeniedInvocation {
    generation: std::sync::Arc<crate::state::Generation>,
    denial: SealedDenial,
    response_recipient: ResponseRecipient,
    response_subject: Option<String>,
    request_message_id: MessageId,
    request_message: Vec<u8>,
}

impl DeniedInvocation {
    fn envelope(&self) -> ResponseEnvelope<'_> {
        ResponseEnvelope {
            response_recipient: &self.response_recipient,
            response_subject: self.response_subject.as_deref(),
            request_message: &self.request_message,
            request_message_id: &self.request_message_id,
        }
    }
}

/// The request-derived inputs of response protection, shared by success,
/// operation-status, and challenge-denial responses.
struct ResponseEnvelope<'a> {
    response_recipient: &'a ResponseRecipient,
    response_subject: Option<&'a str>,
    request_message: &'a [u8],
    request_message_id: &'a MessageId,
}

/// The response-encryption recipient resolved once during preflight.
///
/// Catalog recipients retain the existing local subject-key behavior.
/// Ephemeral recipients are supplied by a successfully verified provider
/// proof and carry the already validated public half directly; response
/// protection never consults a catalog entry with the same key ID.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResponseRecipient {
    Catalog { key_id: String },
    Ephemeral { key_id: String, public: [u8; 32] },
}

impl ResponseRecipient {
    fn key_id(&self) -> &str {
        match self {
            Self::Catalog { key_id } | Self::Ephemeral { key_id, .. } => key_id,
        }
    }

    const fn is_catalog(&self) -> bool {
        matches!(self, Self::Catalog { .. })
    }
}

/// Why the freshness-challenge step denied the request. Every variant maps
/// to the sealed `CHALLENGE_UNKNOWN` (`retryable = false`); the client
/// obtains a fresh challenge and rebuilds with a fresh message ID.
#[derive(Debug, Clone, Copy, thiserror::Error)]
enum ChallengeDenial {
    #[error("missing required freshness challenge")]
    Missing,
    #[error("{0}")]
    Denied(crate::core::challenge::ConsumeDenied),
}

impl BrokerGrpc {
    #[allow(
        clippy::too_many_lines,
        reason = "ordered security preflight is kept linear"
    )]
    async fn prepare_invocation(
        &self,
        request: &Request<pb::SealedRequest>,
    ) -> Result<PreparedRequest, Status> {
        let message = request.get_ref();
        if message.message.is_empty() {
            return Err(invalid_request(INVOKE_OP, "missing sealed COSE message"));
        }

        let peer = peer_from_request(request);
        let generation = self.state.load_generation().to_owned();
        let generation_id = generation.id();
        let policy = generation.policy().clone();
        let config = generation.config().clone();

        let policy_verifier = PolicyVerifier::new(&policy);
        let validation = self.request_validation_params(generation.federation().is_some())?;
        let sealed = match verify_sealed(
            &message.message,
            &policy_verifier,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation,
            },
        )
        .await
        {
            Ok(sealed) => sealed,
            Err(error) => {
                self.state
                    .record_decision(&DecisionRecord::from_resolution_error(
                        generation_id,
                        &peer,
                        Op::Decrypt,
                        "unknown",
                        None,
                        EvidenceState::NoMatch,
                        &format!("invalid_actor_proof: {error}"),
                    ));
                return Err(verify_status(&error));
            }
        };

        let provider_evidence = if sealed.protected_headers.signer_certificates_jwt.is_empty() {
            None
        } else {
            Some(
                self.verify_provider_evidence(
                    &generation,
                    &sealed.protected_headers.signer_certificates_jwt,
                    sealed.protected_headers.signer_public_key_cose.as_deref(),
                    &sealed.claims,
                )
                .await?,
            )
        };
        if provider_evidence.is_some()
            && sealed
                .claims
                .audience
                .as_ref()
                .map(Subject::as_str)
                .is_none()
        {
            return Err(invalid_request(INVOKE_OP, "missing provider audience"));
        }
        if provider_evidence.is_none()
            && !self.invocation.audiences.is_empty()
            && !sealed.claims.audience.as_ref().is_some_and(|audience| {
                self.invocation
                    .audiences
                    .iter()
                    .any(|allowed| allowed == audience.as_str())
            })
        {
            return Err(invalid_request(INVOKE_OP, "invocation audience rejected"));
        }
        if !sealed.protected_headers.signer_certificates_jwt.is_empty()
            && sealed.protected_headers.signer_public_key_cose.is_none()
        {
            return Err(invalid_request(INVOKE_OP, "missing proof key"));
        }
        let proof_public = if let Some(proof_key) = &sealed.protected_headers.signer_public_key_cose
        {
            let public = crate::ci_federation::decode_proof_key_cose(proof_key)
                .map_err(|_| invalid_request(INVOKE_OP, "malformed proof key"))?;
            let expected_audience = crate::ci_federation::proof_audience(&public);
            if sealed.claims.audience.as_ref().map(Subject::as_str)
                != Some(expected_audience.as_str())
            {
                return Err(invalid_request(INVOKE_OP, "proof key audience mismatch"));
            }
            if sealed.protected_headers.signer_certificates_jwt.is_empty() {
                return Err(invalid_request(INVOKE_OP, "missing signer certificate"));
            }
            Some(public)
        } else {
            None
        };

        // SPEC revision 4.2 step 3: resolve the one response recipient after
        // provider verification and before peer admission, challenge
        // consumption, policy, or backend use. The provider-proof and local
        // subject-key shapes are disjoint and never fall back into one
        // another, even when an ephemeral thumbprint collides with a catalog
        // key name.
        let response_recipient = Self::resolve_response_recipient(
            &generation,
            &sealed.claims,
            provider_evidence.is_some(),
        )?;

        let Some(uid) = peer.uid else {
            self.state
                .record_decision(&DecisionRecord::from_resolution_error(
                    generation_id,
                    &peer,
                    Op::Decrypt,
                    key_id_for_audit(&sealed.recipient_key_id),
                    None,
                    EvidenceState::Unavailable,
                    "invalid_actor_proof",
                ));
            return Err(unauthorized_invocation());
        };

        // Freshness (SPEC rev 4, step 4): consume the single-use challenge
        // after the outer signature verified and the thumbprint is known,
        // and before subject resolution, the per-run quota hook
        // (basil-jjgi.3.4 slots in after subject resolution below),
        // authorization, or any backend use of the requested operation. A
        // denial is answered as a sealed non-retryable `CHALLENGE_UNKNOWN`
        // without decrypting the request body.
        if let Err(denial) = self.consume_freshness_challenge(
            generation_id,
            &sealed.claims,
            proof_public.as_ref(),
            &policy_verifier,
        )? {
            tracing::debug!(reason = %denial, "sealed invocation freshness challenge denied");
            self.state
                .record_decision(&DecisionRecord::from_resolution_error(
                    generation_id,
                    &peer,
                    Op::Decrypt,
                    key_id_for_audit(&sealed.recipient_key_id),
                    None,
                    EvidenceState::NoMatch,
                    &format!("freshness_challenge_denied: {denial}"),
                ));
            let response_subject = sealed
                .claims
                .response_subject
                .as_ref()
                .map(ResponseSubject::as_str)
                .map(str::to_string);
            return Ok(PreparedRequest::Denied(DeniedInvocation {
                generation,
                denial: SealedDenial::ChallengeUnknown,
                response_recipient,
                response_subject,
                request_message_id: sealed.claims.message_id.clone(),
                request_message: message.message.clone(),
            }));
        }

        // Captured before the evidence moves into the actor below; charged
        // at the quota step (SPEC rev 4, step 6) after subject resolution.
        let run_quota_charge = provider_evidence.as_ref().map(|provider| RunQuotaCharge {
            key: crate::ci_federation::RunQuotaKey {
                rule_id: provider.rule_id.clone(),
                run_id: provider.claims.run_id(),
                run_attempt: provider.claims.run_attempt(),
            },
            limit: provider.max_operations_per_run,
            retention_secs: provider.run_bucket_retention_secs,
        });

        let actor = if let Some(provider) = provider_evidence {
            let Some(mut actor) = generation.pdp().resolve_subject_actor(&provider.subject) else {
                return Err(unauthorized_invocation());
            };
            actor.authenticated_by.push(ProofSummary {
                kind: ProofKind::ProviderJwt,
                subject: provider.subject,
                fingerprint: Some(encode_id(provider.claims.token_digest())),
            });
            actor.presenter = PresenterInfo::from(&peer);
            actor.transport = TransportInfo::default();
            actor
        } else {
            let mut evidence = host_process_snapshot(&config, &peer, uid);
            evidence.invocation_signature_key =
                EvidenceValue::Available(policy_verifier.verified_key()?);
            resolve_evidence_actor(&policy, &evidence, &peer).map_err(|error| {
                self.state
                    .record_decision(&DecisionRecord::from_subject_resolution_error(
                        generation_id,
                        &peer,
                        Op::Decrypt,
                        key_id_for_audit(&sealed.recipient_key_id),
                        &error,
                        "invalid_actor_proof",
                    ));
                unauthorized_invocation()
            })?
        };
        if sealed
            .claims
            .issuer
            .as_ref()
            .is_some_and(|issuer| issuer.as_str() != actor.subject)
        {
            self.state
                .record_decision(&DecisionRecord::from_actor_evidence_denial(
                    generation_id,
                    &actor,
                    Op::Decrypt,
                    key_id_for_audit(&sealed.recipient_key_id),
                    EvidenceState::NoMatch,
                    "actor_claim_mismatch",
                ));
            return Err(unauthorized_invocation());
        }

        // Per-run quota (SPEC rev 4, step 6): charge one typed operation
        // against `(rule, run_id, run_attempt)` after subject resolution and
        // before authorization or any backend use. Genuine exhaustion (and
        // the fail-closed missing-limit case) is answered as the sealed
        // retryable-never `PER_RUN_QUOTA_EXCEEDED`; bucket-table pressure
        // (`Untracked`) as the sealed retryable `RUN_QUOTA_UNTRACKED` —
        // both without decrypting the request body. The counter is
        // in-memory and generation-scoped, so restart or reload resets it
        // (stated behavior), and a denied charge consumes no quota.
        if let Some(charge) = run_quota_charge {
            let outcome = self
                .invocation_tables
                .lock()
                .map_err(|_| challenge_table_unavailable(INVOKE_OP))?
                .charge_run_quota(
                    generation_id,
                    &charge.key,
                    charge.limit,
                    charge.retention_secs,
                    i64::from(self.invocation_now_unix()),
                );
            if let Err(denied) = outcome {
                tracing::debug!(
                    reason = %denied,
                    rule = %charge.key.rule_id,
                    "sealed invocation per-run quota denied",
                );
                self.state
                    .record_decision(&DecisionRecord::from_actor_evidence_denial(
                        generation_id,
                        &actor,
                        Op::Decrypt,
                        key_id_for_audit(&sealed.recipient_key_id),
                        EvidenceState::Match,
                        &format!("per_run_quota_denied: {denied}"),
                    ));
                let response_subject = sealed
                    .claims
                    .response_subject
                    .as_ref()
                    .map(ResponseSubject::as_str)
                    .map(str::to_string);
                let denial = match denied {
                    crate::ci_federation::RunQuotaDenied::Untracked => {
                        SealedDenial::RunQuotaUntracked
                    }
                    crate::ci_federation::RunQuotaDenied::Exhausted
                    | crate::ci_federation::RunQuotaDenied::QuotaUnavailable => {
                        SealedDenial::PerRunQuotaExceeded
                    }
                };
                return Ok(PreparedRequest::Denied(DeniedInvocation {
                    generation,
                    denial,
                    response_recipient,
                    response_subject,
                    request_message_id: sealed.claims.message_id.clone(),
                    request_message: message.message.clone(),
                }));
            }
        }

        let recipient_key_id = catalog_key_id(&sealed.recipient_key_id, "recipient key id")?;
        self.validate_request_recipient_key(recipient_key_id)?;
        let decision = generation
            .pdp()
            .decide(&actor, Op::Decrypt, recipient_key_id);
        self.state
            .record_decision(&DecisionRecord::from_actor_decision(
                generation.id(),
                &actor,
                Op::Decrypt,
                recipient_key_id,
                &decision,
            ));
        if decision.is_deny() {
            return Err(unauthorized_invocation());
        }

        if response_recipient.is_catalog() {
            self.validate_catalog_response_encryption_key_material(response_recipient.key_id())
                .await?;
        }

        let opened = sealed
            .open(
                &ManagerRecipient {
                    key_id: sealed.recipient_key_id.clone(),
                    manager: self.state.manager(),
                },
                &ExternalAad::empty(),
                Some(&KdfParties::anonymous()),
            )
            .await
            .map_err(|e| open_status(&e))?;
        if opened.content_type != sealed.content_type {
            return Err(invalid_request(INVOKE_OP, "opened content type mismatch"));
        }

        let response_subject = sealed
            .claims
            .response_subject
            .as_ref()
            .map(ResponseSubject::as_str)
            .map(str::to_string);
        Ok(PreparedRequest::Proceed(Box::new(PreparedInvocation {
            generation,
            actor,
            recipient_key_id: recipient_key_id.to_string(),
            response_recipient,
            response_subject,
            content_type: sealed.content_type.as_str().to_string(),
            claims: sealed.claims,
            request_message: message.message.clone(),
            body: DecryptedInvocationBody::new(opened.plaintext),
        })))
    }

    /// Consume the request's single-use freshness challenge.
    ///
    /// Proof-bound requests (an ephemeral proof key in the signer headers)
    /// must present a challenge. Subject-key requests may — and must when the
    /// broker is configured with `invocation.require-challenge` (courier
    /// deployments); when present it is enforced identically, bound to the
    /// verified Ed25519 subject key's RFC 7638 thumbprint. `Ok(Err(_))` is a
    /// freshness denial that surfaces as the sealed non-retryable
    /// `CHALLENGE_UNKNOWN`; `Err(_)` is an envelope error.
    fn consume_freshness_challenge(
        &self,
        generation_id: u64,
        claims: &Claims,
        proof_public: Option<&[u8; 32]>,
        verifier: &PolicyVerifier<'_>,
    ) -> Result<Result<(), ChallengeDenial>, Status> {
        let Some(challenge) = claims.freshness_challenge else {
            if proof_public.is_some() || self.invocation.require_challenge {
                return Ok(Err(ChallengeDenial::Missing));
            }
            return Ok(Ok(()));
        };
        let jkt = if let Some(public) = proof_public {
            crate::ci_federation::proof_key_thumbprint(public)
        } else {
            let evidence = verifier.verified_key()?;
            if evidence.algorithm != SignatureKeyAlgorithm::Ed25519 {
                return Err(invalid_request(
                    INVOKE_OP,
                    "freshness challenge requires an Ed25519 invocation signature key",
                ));
            }
            let public = decode_ed25519_public(&evidence.public)
                .ok_or_else(|| invalid_request(INVOKE_OP, "verified signature key is malformed"))?;
            crate::ci_federation::proof_key_thumbprint(&public)
        };
        let now = i64::from(self.invocation_now_unix());
        let outcome = self
            .invocation_tables
            .lock()
            .map_err(|_| challenge_table_unavailable(INVOKE_OP))?
            .consume(challenge.as_bytes(), &jkt, generation_id, now);
        Ok(outcome.map_err(ChallengeDenial::Denied))
    }

    /// Protect the sealed non-retryable denial (`CHALLENGE_UNKNOWN` or
    /// `PER_RUN_QUOTA_EXCEEDED`) for a request rejected in preflight.
    async fn protect_denied_invocation(
        &self,
        denied: &DeniedInvocation,
    ) -> Result<pb::SealedResponse, ResponseProtectionError> {
        let body = SignInvocationResponse {
            status: denied.denial.status(),
            policy_generation: denied.generation.id(),
            signature: None,
        };
        self.protect_response(
            &denied.envelope(),
            CONTENT_TYPE_SIGN_RESPONSE,
            &body.to_cbor_bytes(),
        )
        .await
    }

    async fn execute_invocation(
        &self,
        prepared: PreparedInvocation,
    ) -> Result<pb::SealedResponse, ResponseProtectionError> {
        if prepared_content_type(&prepared) == CONTENT_TYPE_SIGN_REQUEST {
            self.execute_sign_invocation(prepared).await
        } else {
            let body = SignInvocationResponse {
                status: InvocationStatus::invalid_request("UNSUPPORTED_CONTENT_TYPE"),
                policy_generation: prepared.generation.id(),
                signature: None,
            };
            self.protect_response(
                &prepared.envelope(),
                CONTENT_TYPE_SIGN_RESPONSE,
                &body.to_cbor_bytes(),
            )
            .await
        }
    }

    async fn execute_sign_invocation(
        &self,
        prepared: PreparedInvocation,
    ) -> Result<pb::SealedResponse, ResponseProtectionError> {
        let request_body = match SignInvocationRequest::from_cbor_bytes(prepared.body.0.as_slice())
        {
            Ok(body) => body,
            Err(error) => {
                let policy_generation = prepared.generation.id();
                tracing::debug!(%error, "sealed sign invocation body rejected");
                return self
                    .protect_sign_status_response(
                        &prepared,
                        InvocationStatus::invalid_request("INVALID_REQUEST_BODY"),
                        policy_generation,
                    )
                    .await;
            }
        };
        if let Err(error) = crate::service::shared::ensure_supported_signing_algorithm(
            request_body.algorithm,
            INVOKE_OP,
        ) {
            let policy_generation = prepared.generation.id();
            tracing::debug!(%error, "sealed sign invocation algorithm rejected");
            return self
                .protect_sign_status_response(
                    &prepared,
                    InvocationStatus::invalid_request("UNSUPPORTED_SIGNING_ALGORITHM"),
                    policy_generation,
                )
                .await;
        }
        let generation = &prepared.generation;
        let policy_generation = generation.id();
        let decision = generation
            .pdp()
            .decide(&prepared.actor, Op::Sign, &request_body.key_id);
        self.state
            .record_decision(&DecisionRecord::from_actor_decision(
                policy_generation,
                &prepared.actor,
                Op::Sign,
                &request_body.key_id,
                &decision,
            ));
        if decision.is_deny() {
            return self
                .protect_sign_status_response(
                    &prepared,
                    InvocationStatus::denied(),
                    policy_generation,
                )
                .await;
        }
        let signature = match self
            .state
            .manager()
            .sign(&request_body.key_id, &request_body.message)
            .await
        {
            Ok(signature) => signature,
            Err(error) => {
                tracing::warn!(%error, "sealed sign invocation operation failed");
                return self
                    .protect_sign_status_response(
                        &prepared,
                        InvocationStatus::internal_error(),
                        policy_generation,
                    )
                    .await;
            }
        };
        let body = SignInvocationResponse {
            status: InvocationStatus::ok(),
            policy_generation,
            signature: Some(signature),
        };
        self.protect_response(
            &prepared.envelope(),
            CONTENT_TYPE_SIGN_RESPONSE,
            &body.to_cbor_bytes(),
        )
        .await
    }

    async fn protect_sign_status_response(
        &self,
        prepared: &PreparedInvocation,
        status: InvocationStatus,
        policy_generation: u64,
    ) -> Result<pb::SealedResponse, ResponseProtectionError> {
        let body = SignInvocationResponse {
            status,
            policy_generation,
            signature: None,
        };
        self.protect_response(
            &prepared.envelope(),
            CONTENT_TYPE_SIGN_RESPONSE,
            &body.to_cbor_bytes(),
        )
        .await
    }

    fn validate_request_recipient_key(&self, recipient_key_id: &str) -> Result<(), Status> {
        let Some(expected) = self.invocation.request_encryption_key_id.as_deref() else {
            return Err(invalid_request(
                INVOKE_OP,
                "no invocation request encryption key configured",
            ));
        };
        if recipient_key_id == expected {
            Ok(())
        } else {
            Err(invalid_request(
                INVOKE_OP,
                "sealed request recipient key mismatch",
            ))
        }
    }

    fn resolve_response_recipient(
        generation: &crate::state::Generation,
        claims: &Claims,
        provider_verified: bool,
    ) -> Result<ResponseRecipient, Status> {
        let key_id = required_response_key_id(claims)?;
        match (provider_verified, claims.response_public_key_cose) {
            (true, Some(public)) => {
                // The COSE profile already enforces this relation while
                // decoding. Recheck at the trust-boundary selection seam so
                // this function remains correct for typed callers and future
                // construction paths too.
                if key_id.as_bytes() != public.thumbprint().as_bytes() {
                    return Err(invalid_request(
                        INVOKE_OP,
                        "response key id does not match ephemeral response public key",
                    ));
                }
                Ok(ResponseRecipient::Ephemeral {
                    key_id: key_id.to_string(),
                    public: *public.as_public_bytes(),
                })
            }
            (true, None) => Err(invalid_request(
                INVOKE_OP,
                "provider-proof request is missing an ephemeral response public key",
            )),
            (false, Some(_)) => Err(invalid_request(
                INVOKE_OP,
                "ephemeral response public key requires verified provider proof",
            )),
            (false, None) => {
                Self::validate_catalog_response_encryption_key(generation, key_id)?;
                Ok(ResponseRecipient::Catalog {
                    key_id: key_id.to_string(),
                })
            }
        }
    }

    fn validate_catalog_response_encryption_key(
        generation: &crate::state::Generation,
        key_id: &str,
    ) -> Result<(), Status> {
        let Some(key) = generation.catalog().keys.get(key_id) else {
            return Err(invalid_request(
                INVOKE_OP,
                format!("unknown response encryption key `{key_id}`"),
            ));
        };
        if key.class != Class::Sealing {
            return Err(invalid_request(
                INVOKE_OP,
                "response encryption key must be class `sealing`",
            ));
        }
        match key.labels.get(BROKER_KEY_USE_LABEL) {
            Some(actual) if actual == BROKER_RESPONSE_ENCRYPTION_USE => {}
            _ => {
                return Err(invalid_request(
                    INVOKE_OP,
                    "response encryption key missing expected `broker_key_use`",
                ));
            }
        }
        Ok(())
    }

    async fn validate_catalog_response_encryption_key_material(
        &self,
        key_id: &str,
    ) -> Result<(), Status> {
        self.state
            .manager()
            .sealing_public_key(key_id)
            .await
            .map(|_| ())
            .map_err(|e| manager_status(INVOKE_OP, &e))
    }

    async fn protect_response(
        &self,
        envelope: &ResponseEnvelope<'_>,
        content_type: &str,
        plaintext_body: &[u8],
    ) -> Result<pb::SealedResponse, ResponseProtectionError> {
        let identity = self
            .invocation
            .broker_identity
            .as_ref()
            .ok_or(ResponseProtectionError::MissingBrokerIdentity)?;
        let recipient_public = match envelope.response_recipient {
            ResponseRecipient::Catalog { key_id } => self
                .state
                .manager()
                .sealing_public_key(key_id)
                .await
                .map_err(ResponseProtectionError::Manager)?,
            ResponseRecipient::Ephemeral { public, .. } => *public,
        };
        let now = self.invocation_now_unix();
        let response_message_id = MessageId::from_bytes(uuid::Uuid::new_v4().as_bytes().to_vec())?;
        let signer_key_id = KeyId::from_text(&identity.response_signing_key_id)?;
        let claims = Claims {
            issuer: Some(Subject::new(identity.id.clone())?),
            audience: None,
            expires_at: Some(UnixTime(i64::from(
                now.saturating_add(DEFAULT_EXPIRES_AFTER_SECS),
            ))),
            issued_at: UnixTime(i64::from(now)),
            message_id: response_message_id,
            sender_key_id: Some(signer_key_id.clone()),
            response_key_id: None,
            response_subject: None,
            in_reply_to: Some(envelope.request_message_id.clone()),
            request_hash: Some(request_hash(envelope.request_message)),
            freshness_challenge: None,
            response_public_key_cose: None,
        };
        let message = build_sealed(
            &SealParams {
                content_type: ContentType::new(content_type.to_string())?,
                plaintext: plaintext_body,
                claims,
                role: MessageRole::Response,
                recipient: X25519RecipientPublic {
                    key_id: KeyId::from_text(envelope.response_recipient.key_id())?,
                    public: recipient_public,
                },
                content_algorithm: ContentAlgorithm::A256Gcm,
                aad: SealedAad::empty(),
                kdf_parties: KdfParties::anonymous(),
            },
            &ManagerSigner {
                key_id: signer_key_id,
                manager: self.state.manager(),
            },
        )
        .await?;
        Ok(pb::SealedResponse {
            message: message.into_vec(),
            response_subject: envelope.response_subject.map(str::to_string),
        })
    }

    fn request_validation_params(
        &self,
        allow_provider_audience: bool,
    ) -> Result<ValidationParams, Status> {
        let mut allowed_audiences = BTreeSet::new();
        for audience in &self.invocation.audiences {
            allowed_audiences.insert(
                Subject::new(audience.clone())
                    .map_err(|e| invalid_request(INVOKE_OP, e.to_string()))?,
            );
        }
        if allow_provider_audience {
            allowed_audiences.clear();
        }
        Ok(ValidationParams {
            now: UnixTime(i64::from(self.invocation_now_unix())),
            max_clock_skew: Duration::from_secs(u64::from(self.invocation.clock_skew_secs)),
            max_ttl: Duration::from_secs(u64::from(self.invocation.max_ttl_secs)),
            default_ttl: Duration::from_secs(u64::from(DEFAULT_EXPIRES_AFTER_SECS)),
            allowed_audiences,
            role: MessageRole::Request,
        })
    }

    /// Resolve the JWKS to verify against for one federation rule.
    ///
    /// Classifies the presented key ID under one cache lock (fresh hit,
    /// positive-TTL expiry needing revalidation, or unknown key ID), then
    /// performs at most one bounded fetch per cooldown window; any admitted
    /// refresh attempt is recorded before the fetch so a failed fetch still
    /// consumes it. Past `max_age`, a cached key ID serves the stale set only
    /// within `stale_if_error`, after which the rule fails closed until a
    /// fetch succeeds — so a provider-side key rotation (its only revocation
    /// mechanism) takes effect boundedly instead of persisting for the
    /// generation lifetime. `Ok(None)` means this rule cannot serve the key
    /// ID right now: no generation cache entry (never fetches, fails closed),
    /// cooldown-gated, fetch failed, or staleness bound exceeded.
    async fn resolve_rule_jwks(
        &self,
        generation: &std::sync::Arc<crate::state::Generation>,
        rule_id: &str,
        provider: &crate::core::ci_federation::ProviderConfig,
        client: &reqwest::Client,
        token_kid: &str,
        now: std::time::SystemTime,
    ) -> Result<Option<crate::core::ci_federation::GenerationJwks>, Status> {
        let generation_id = generation.id();
        resolve_rule_jwks_via(generation, rule_id, token_kid, now, &mut || {
            let client = client.clone();
            let provider = provider.clone();
            async move {
                crate::ci_federation::fetch_generation_jwks(&client, generation_id, &provider).await
            }
        })
        .await
    }

    async fn verify_provider_evidence(
        &self,
        generation: &std::sync::Arc<crate::state::Generation>,
        tokens: &[String],
        proof_key: Option<&[u8]>,
        claims: &Claims,
    ) -> Result<crate::core::ci_federation::VerifiedProviderEvidence, Status> {
        let proof_key = proof_key.ok_or_else(|| invalid_request(INVOKE_OP, "missing proof key"))?;
        let public = crate::ci_federation::decode_proof_key_cose(proof_key)
            .map_err(|_| invalid_request(INVOKE_OP, "malformed proof key"))?;
        if claims.audience.as_ref().map(Subject::as_str)
            != Some(crate::ci_federation::proof_audience(&public).as_str())
        {
            return Err(invalid_request(INVOKE_OP, "proof key audience mismatch"));
        }
        let catalog = generation
            .federation()
            .ok_or_else(unauthorized_invocation)?;
        let token = tokens
            .first()
            .ok_or_else(|| invalid_request(INVOKE_OP, "missing signer certificate"))?;
        if tokens.len() != 1 {
            return Err(invalid_request(INVOKE_OP, "multiple signer certificates"));
        }
        crate::ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| unauthorized_invocation())?;
        let now = std::time::UNIX_EPOCH
            .checked_add(Duration::from_secs(u64::from(self.invocation_now_unix())))
            .ok_or_else(unauthorized_invocation)?;
        let token_kid = jsonwebtoken::decode_header(token)
            .ok()
            .and_then(|header| header.kid)
            .ok_or_else(unauthorized_invocation)?;
        let correlation = token_correlation_key()?;
        for rule in catalog.rules() {
            let Some(keys) = self
                .resolve_rule_jwks(
                    generation,
                    &rule.id,
                    &rule.provider,
                    &client,
                    &token_kid,
                    now,
                )
                .await?
            else {
                continue;
            };
            let verified = match &rule.provider {
                crate::core::ci_federation::ProviderConfig::GithubActions(github) => {
                    crate::core::ci_federation::verify_github(
                        github,
                        &keys,
                        token,
                        &public,
                        correlation,
                        now,
                    )
                    .map(crate::core::ci_federation::ProviderClaimEvidence::GithubActions)
                }
                crate::core::ci_federation::ProviderConfig::ForgejoActions(forgejo) => {
                    crate::core::ci_federation::verify_forgejo(
                        forgejo,
                        &keys,
                        token,
                        &public,
                        correlation,
                        now,
                    )
                    .map(crate::core::ci_federation::ProviderClaimEvidence::ForgejoActions)
                }
            };
            if let Ok(claims) = verified {
                return Ok(crate::core::ci_federation::VerifiedProviderEvidence {
                    provider: rule.provider.kind(),
                    rule_id: rule.id.clone(),
                    subject: rule.subject.clone(),
                    max_operations_per_run: rule.max_operations_per_run,
                    run_bucket_retention_secs: rule
                        .max_token_age_secs
                        .saturating_add(rule.clock_skew_secs),
                    claims,
                });
            }
        }
        Err(unauthorized_invocation())
    }
}

/// Serving-path JWKS resolution for one federation rule (the body of
/// [`BrokerGrpc::resolve_rule_jwks`], which documents the contract).
///
/// Generic over the fetch so the wiring is testable with a stub: `fetch` is
/// invoked only after the cache decision admits a refresh (fresh hits never
/// fetch, a missing generation cache entry never fetches and fails closed,
/// and the cooldown gate records the attempt before the fetch so a failed
/// fetch still consumes it). Production supplies the bounded HTTPS
/// discovery + JWKS fetch.
async fn resolve_rule_jwks_via<F, Fut>(
    generation: &std::sync::Arc<crate::state::Generation>,
    rule_id: &str,
    token_kid: &str,
    now: std::time::SystemTime,
    fetch: &mut F,
) -> Result<Option<crate::core::ci_federation::GenerationJwks>, Status>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<
            Output = Result<
                crate::core::ci_federation::GenerationJwks,
                crate::core::ci_federation::FederationError,
            >,
        >,
{
    use crate::core::ci_federation::ServeDecision;
    let decision = generation
        .jwks_caches()
        .lock()
        .map_err(|_| unauthorized_invocation())?
        .get_mut(rule_id)
        .map(|cache| cache.serve_or_revalidate(token_kid, now));
    let Some(decision) = decision else {
        return Ok(None);
    };
    match decision {
        ServeDecision::Fresh(keys) => Ok(Some(keys)),
        ServeDecision::Revalidate {
            refresh_allowed,
            stale,
        } => {
            let fetched = if refresh_allowed {
                fetch().await.ok()
            } else {
                None
            };
            match fetched {
                Some(keys) => {
                    install_generation_jwks(generation, rule_id, &keys, now)?;
                    Ok(Some(keys))
                }
                None => Ok(stale),
            }
        }
        ServeDecision::UnknownKid { refresh_allowed } => {
            if !refresh_allowed {
                return Ok(None);
            }
            let Ok(keys) = fetch().await else {
                return Ok(None);
            };
            install_generation_jwks(generation, rule_id, &keys, now)?;
            Ok(Some(keys))
        }
    }
}

/// Install a freshly fetched JWKS into the generation's cache for one rule.
fn install_generation_jwks(
    generation: &std::sync::Arc<crate::state::Generation>,
    rule_id: &str,
    keys: &crate::core::ci_federation::GenerationJwks,
    now: std::time::SystemTime,
) -> Result<(), Status> {
    let mut cache_map = generation
        .jwks_caches()
        .lock()
        .map_err(|_| unauthorized_invocation())?;
    if let Some(cache) = cache_map.get_mut(rule_id) {
        cache.install(keys.clone(), now);
    }
    drop(cache_map);
    Ok(())
}

/// The broker-local key for CI token/`jti` correlation digests.
///
/// A fresh random key per broker process: correlation identity is only
/// meaningful within one audit stream, and keeping the key ephemeral means a
/// captured audit record can never be matched against a raw token offline
/// after the process exits. Fails closed if entropy is unavailable.
fn token_correlation_key()
-> Result<&'static crate::core::ci_federation::TokenCorrelationKey, Status> {
    static KEY: std::sync::OnceLock<crate::core::ci_federation::TokenCorrelationKey> =
        std::sync::OnceLock::new();
    if let Some(key) = KEY.get() {
        return Ok(key);
    }
    // Zeroizing end-to-end: the generated bytes move into the key (or are
    // scrubbed on the race-loser path) without leaving a plain stack copy.
    let mut bytes = zeroize::Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *bytes).map_err(|_| unauthorized_invocation())?;
    Ok(KEY.get_or_init(move || crate::core::ci_federation::TokenCorrelationKey::new(bytes)))
}

fn prepared_content_type(prepared: &PreparedInvocation) -> &str {
    &prepared.content_type
}

fn catalog_key_id<'a>(key_id: &'a KeyId, field: &str) -> Result<&'a str, Status> {
    key_id
        .as_catalog_name()
        .ok_or_else(|| invalid_request(INVOKE_OP, format!("{field} must be UTF-8")))
}

fn key_id_for_audit(key_id: &KeyId) -> &str {
    key_id.as_catalog_name().unwrap_or("non-utf8-key-id")
}

fn encode_id(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Parse the required response-encryption key ID out of the request claims.
fn required_response_key_id(claims: &Claims) -> Result<&str, Status> {
    let response_key_id = claims
        .response_key_id
        .as_ref()
        .ok_or_else(|| invalid_request(INVOKE_OP, "missing response encryption key"))?;
    catalog_key_id(response_key_id, "response encryption key")
}

/// The stable, retryable decline for challenge issuance under capacity or
/// rate-limit pressure. The same request may be retried after backoff.
fn challenge_issuance_declined() -> Status {
    broker_status(
        Code::ResourceExhausted,
        "CHALLENGE_ISSUANCE_DECLINED",
        CHALLENGE_OP,
        "challenge issuance declined; retry after backoff",
    )
}

/// Internal broker fault: the challenge-table mutex is poisoned. Unreachable
/// under the no-panic rule, and honestly labeled as a server error rather
/// than a client error or a retryable decline (a poisoned mutex never
/// recovers).
fn challenge_table_unavailable(op: &'static str) -> Status {
    broker_status(
        Code::Internal,
        "CHALLENGE_TABLE_UNAVAILABLE",
        op,
        "challenge table unavailable",
    )
}

struct PolicyVerifier<'a> {
    policy: &'a ResolvedPolicy,
    verified_key: Mutex<Option<SignatureKeyEvidence>>,
}

impl<'a> PolicyVerifier<'a> {
    const fn new(policy: &'a ResolvedPolicy) -> Self {
        Self {
            policy,
            verified_key: Mutex::new(None),
        }
    }

    fn verified_key(&self) -> Result<SignatureKeyEvidence, Status> {
        self.verified_key
            .lock()
            .map_err(|_| invalid_request(INVOKE_OP, "signature verifier state unavailable"))
            .and_then(|verified| {
                verified
                    .clone()
                    .ok_or_else(|| invalid_request(INVOKE_OP, "signature was not verified"))
            })
    }
}

impl Verifier for PolicyVerifier<'_> {
    async fn verify(
        &self,
        key_id: &KeyId,
        algorithm: SignatureAlgorithm,
        protected_headers: &basil_cose::ProtectedHeaders,
        sig_structure: &[u8],
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        if let Some(proof_key) = &protected_headers.signer_public_key_cose {
            let public = crate::ci_federation::decode_proof_key_cose(proof_key)
                .map_err(|_| VerifyError::SignatureInvalid)?;
            let expected_kid = crate::ci_federation::proof_key_kid(&public);
            if key_id.as_bytes() != expected_kid.as_bytes()
                || algorithm != SignatureAlgorithm::EdDsa
                || !crate::ed25519_sign::verify(&public, sig_structure, signature.as_bytes())
                    .unwrap_or(false)
            {
                return Err(VerifyError::SignatureInvalid);
            }
            let mut verified = self
                .verified_key
                .lock()
                .map_err(|_| VerifyError::Provider {
                    message: "signature verifier state unavailable".to_string(),
                })?;
            *verified = Some(SignatureKeyEvidence {
                algorithm: SignatureKeyAlgorithm::Ed25519,
                public: URL_SAFE_NO_PAD.encode(public),
            });
            drop(verified);
            return Ok(());
        }
        // The broker verifies invocation signatures against EdDSA subject keys
        // only; any other wire algorithm fails closed.
        if algorithm != SignatureAlgorithm::EdDsa {
            return Err(VerifyError::AlgorithmMismatch);
        }
        let mut verified_key = None;
        for definition in self.policy.subjects.values() {
            if let Some(key) =
                expression_signature_verifies(&definition.match_, key_id, sig_structure, signature)
            {
                verified_key = Some(key);
                break;
            }
        }
        let Some(verified_key) = verified_key else {
            return Err(VerifyError::SignatureInvalid);
        };
        let mut verified = self
            .verified_key
            .lock()
            .map_err(|_| VerifyError::Provider {
                message: "signature verifier state unavailable".to_string(),
            })?;
        *verified = Some(verified_key);
        drop(verified);
        Ok(())
    }
}

struct ManagerRecipient<'a> {
    key_id: KeyId,
    manager: &'a crate::manager::BackendManager,
}

impl basil_cose::Recipient for ManagerRecipient<'_> {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    async fn open(
        &self,
        request: &basil_cose::OpenRequest<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, basil_cose::OpenError> {
        let key_id = self
            .key_id
            .as_catalog_name()
            .ok_or(basil_cose::OpenError::RecipientKeyMismatch)?;
        self.manager
            .unseal_cose(
                key_id,
                request.cose_encrypt,
                request.external_aad.as_bytes(),
            )
            .await
            .map_err(|_| basil_cose::OpenError::OpenFailed)
    }
}

struct ManagerSigner<'a> {
    key_id: KeyId,
    manager: &'a crate::manager::BackendManager,
}

impl Signer for ManagerSigner<'_> {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EdDsa
    }

    async fn sign(&self, sig_structure: &[u8]) -> Result<Signature, SignError> {
        let key_id = self
            .key_id
            .as_catalog_name()
            .ok_or_else(|| SignError::Provider {
                message: "signing key id is not UTF-8".to_string(),
            })?;
        let signature = self
            .manager
            .sign(key_id, sig_structure)
            .await
            .map_err(|e| SignError::Provider {
                message: e.to_string(),
            })?;
        Signature::from_bytes(signature).map_err(|e| SignError::Provider {
            message: e.to_string(),
        })
    }
}

/// One pending per-run quota charge, captured from verified provider
/// evidence before it moves into the resolved actor.
#[derive(Debug)]
struct RunQuotaCharge {
    key: crate::ci_federation::RunQuotaKey,
    /// The selected rule's `max_operations_per_run`; `None` (unreachable for
    /// a loaded rule) fails closed at the charge.
    limit: Option<u64>,
    /// The rule's bucket retention window (`max_token_age_secs +
    /// clock_skew_secs`), bounding how long an idle bucket stays tracked.
    retention_secs: u64,
}

/// The invocation freshness-challenge table and per-run quota table, behind
/// the one broker mutex.
///
/// There is no message-ID replay cache (SPEC rev 4 Freshness): the COSE
/// message ID is correlation-only, and freshness rests on server-issued
/// single-use challenges held in the [`ChallengeTable`]
/// ([`crate::core::challenge`]); the per-run operation quota (SPEC rev 4,
/// Per-run quota and kill switch) shares the same in-memory,
/// restart-resetting lifecycle and therefore the same lock. The broker
/// adapter (`service/broker.rs`) constructs this from the
/// `invocation.challenge_table` and `invocation.run_quota_buckets_per_rule`
/// runtime settings.
///
/// [`ChallengeTable`]: crate::core::challenge::ChallengeTable
#[derive(Debug)]
pub(super) struct InvocationTables {
    challenges: crate::core::challenge::ChallengeTable,
    run_quota: crate::ci_federation::RunQuotaTable,
}

impl InvocationTables {
    /// Build the invocation state tables; `challenge_table` shapes the
    /// freshness-challenge table (`[invocation.challenge]`) and
    /// `run_quota_buckets_per_rule` bounds the distinct tracked per-run
    /// quota buckets for each federation rule
    /// (`invocation.run-quota-buckets-per-rule`).
    pub(super) fn new(
        challenge_table: crate::core::challenge::ChallengeTableConfig,
        run_quota_buckets_per_rule: usize,
    ) -> Self {
        Self {
            challenges: crate::core::challenge::ChallengeTable::with_config(challenge_table),
            run_quota: crate::ci_federation::RunQuotaTable::new(run_quota_buckets_per_rule),
        }
    }

    /// Issue a single-use freshness challenge
    /// ([`ChallengeTable::issue`][crate::core::challenge::ChallengeTable::issue]).
    fn issue(
        &mut self,
        jkt: [u8; 32],
        source: Option<&str>,
        generation: u64,
        now_unix: i64,
    ) -> Result<crate::core::challenge::IssuedChallenge, crate::core::challenge::IssueDecline> {
        self.challenges.issue(jkt, source, generation, now_unix)
    }

    /// Atomically consume a freshness challenge
    /// ([`ChallengeTable::consume`][crate::core::challenge::ChallengeTable::consume]).
    fn consume(
        &mut self,
        challenge: &[u8],
        jkt: &[u8; 32],
        generation: u64,
        now_unix: i64,
    ) -> Result<(), crate::core::challenge::ConsumeDenied> {
        self.challenges
            .consume(challenge, jkt, generation, now_unix)
    }

    /// Charge one typed operation against the per-run quota
    /// ([`RunQuotaTable::charge`][crate::ci_federation::RunQuotaTable::charge]).
    fn charge_run_quota(
        &mut self,
        generation: u64,
        key: &crate::ci_federation::RunQuotaKey,
        limit: Option<u64>,
        retention_secs: u64,
        now_unix: i64,
    ) -> Result<(), crate::ci_federation::RunQuotaDenied> {
        self.run_quota
            .charge(generation, key, limit, retention_secs, now_unix)
    }
}

fn expression_signature_verifies(
    expression: &crate::catalog::EvidenceExpression,
    key_id: &KeyId,
    sig_structure: &[u8],
    signature: &Signature,
) -> Option<SignatureKeyEvidence> {
    let mut verified = None;
    expression.visit_leaves(&mut |predicate| {
        if verified.is_none() {
            verified = predicate_signature_verifies(predicate, key_id, sig_structure, signature);
        }
    });
    verified
}

fn predicate_signature_verifies(
    predicate: &EvidencePredicate,
    key_id: &KeyId,
    sig_structure: &[u8],
    signature: &Signature,
) -> Option<SignatureKeyEvidence> {
    let EvidencePredicate::InvocationSignatureKey { algorithm, public } = predicate else {
        return None;
    };
    let valid = match algorithm {
        SignatureKeyAlgorithm::Ed25519 => decode_ed25519_public(public).is_some_and(|public| {
            let _ = key_id;
            crate::ed25519_sign::verify(&public, sig_structure, signature.as_bytes())
                .unwrap_or(false)
        }),
        SignatureKeyAlgorithm::NatsNkey => {
            key_id.as_catalog_name().is_some_and(|kid| kid == public)
                && basil_nats::verify_public_signature(public, sig_structure, signature.as_bytes())
                    .unwrap_or(false)
        }
    };
    valid.then(|| SignatureKeyEvidence {
        algorithm: *algorithm,
        public: public.clone(),
    })
}

fn decode_ed25519_public(public: &str) -> Option<[u8; crate::ed25519_sign::PUBLIC_KEY_LEN]> {
    let bytes = URL_SAFE_NO_PAD.decode(public.as_bytes()).ok()?;
    bytes.try_into().ok()
}

fn unauthorized_invocation() -> Status {
    broker_status(
        Code::PermissionDenied,
        "UNAUTHORIZED",
        INVOKE_OP,
        "not authorized",
    )
}

fn verify_status(error: &VerifyError) -> Status {
    match error {
        VerifyError::SignatureInvalid
        | VerifyError::UnknownKeyId
        | VerifyError::AlgorithmMismatch => unauthorized_invocation(),
        VerifyError::Decode(_)
        | VerifyError::Claims(_)
        | VerifyError::SenderKeyMismatch
        | VerifyError::ClaimsPresenceMismatch
        | VerifyError::Provider { .. } => invalid_request(INVOKE_OP, error.to_string()),
    }
}

fn open_status(error: &basil_cose::OpenError) -> Status {
    invalid_request(INVOKE_OP, error.to_string())
}

fn response_protection_failed() -> Status {
    broker_status(
        Code::Internal,
        "INVOCATION_RESPONSE_PROTECTION_FAILED",
        INVOKE_OP,
        "invocation response protection failed",
    )
}

#[derive(Debug, thiserror::Error)]
enum ResponseProtectionError {
    #[error("missing broker identity")]
    MissingBrokerIdentity,
    #[error("{0}")]
    CoseProfile(#[from] basil_cose::ProfileError),
    #[error("{0}")]
    CoseBuild(#[from] basil_cose::BuildError),
    #[error("{0}")]
    Manager(#[from] crate::manager::ManagerError),
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use crate::backend::{Backend, BackendError, KvValue, NewKey};
    use crate::catalog::loader::load;
    use crate::manager::BackendManager;
    use crate::service::broker::{BrokerIdentityRuntimeConfig, InvocationRuntimeConfig};
    use crate::state::BrokerState;
    use basil_cose::{
        Ed25519Signer, Ed25519Verifier, SignParams, VerifiedSealed, X25519Recipient,
        X25519ResponsePublicKey, build_signed,
    };
    use basil_proto::KeyType;
    use ed25519_dalek::{Signer as _, SigningKey};
    use minicbor::Encoder;

    const NOW: u32 = 1_010;
    const ISSUED_AT: i64 = 1_000;
    const CLIENT_SUBJECT: &str = "client";
    const BROKER_SUBJECT: &str = "broker";
    const CLIENT_SIGNING_KEY: &str = "client.signing";
    const MALLORY_SIGNING_KEY: &str = "mallory.signing";
    const REQUEST_SEALING_KEY: &str = "request.sealing";
    const RESPONSE_SEALING_KEY: &str = "response.sealing";
    const RESPONSE_SIGNING_KEY: &str = "response.signing";
    const TARGET_SIGNING_KEY: &str = "target.signing";

    struct Fixture {
        service: BrokerGrpc,
        client_signer: Ed25519Signer,
        mallory_signer: Ed25519Signer,
        broker_verifier: Ed25519Verifier,
        request_public: X25519RecipientPublic,
        response_recipient: X25519Recipient,
    }

    #[derive(Debug)]
    struct TestBackend {
        response_signing_seed: [u8; 32],
        target_signing_seed: [u8; 32],
        kv: BTreeMap<String, Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl Backend for TestBackend {
        fn kind(&self) -> &'static str {
            "test"
        }

        async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
            let _ = key_type;
            Err(BackendError::Unsupported("new_key"))
        }

        async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
            self.kv
                .get(key_id)
                .cloned()
                .ok_or_else(|| BackendError::KeyNotFound(key_id.to_string()))
        }

        async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
            let seed = match key_id {
                "response-signing" => self.response_signing_seed,
                "target-signing" => self.target_signing_seed,
                other => return Err(BackendError::KeyNotFound(other.to_string())),
            };
            let key = SigningKey::from_bytes(&seed);
            Ok(key.sign(message).to_bytes().to_vec())
        }

        async fn verify(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, BackendError> {
            let _ = (key_id, message, signature);
            Ok(false)
        }

        async fn kv_get(
            &self,
            key_id: &str,
            version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            let _ = version;
            self.kv
                .get(key_id)
                .cloned()
                .map(|value| KvValue { value, version: 1 })
                .ok_or_else(|| BackendError::KeyNotFound(key_id.to_string()))
        }

        async fn kv_get_secret(
            &self,
            key_id: &str,
            version: Option<u32>,
        ) -> Result<crate::backend::KvSecret, BackendError> {
            let _ = version;
            self.kv
                .get(key_id)
                .cloned()
                .map(|value| crate::backend::KvSecret {
                    value: Zeroizing::new(value),
                    version: 1,
                })
                .ok_or_else(|| BackendError::KeyNotFound(key_id.to_string()))
        }
    }

    fn key_id(name: &str) -> KeyId {
        KeyId::from_text(name).unwrap()
    }

    fn subject(name: &str) -> Subject {
        Subject::new(name.to_string()).unwrap()
    }

    fn message_id(bytes: &[u8]) -> MessageId {
        MessageId::from_bytes(bytes.to_vec()).unwrap()
    }

    fn content_type(value: &str) -> ContentType {
        ContentType::new(value.to_string()).unwrap()
    }

    fn signer(name: &str, seed: [u8; 32]) -> Ed25519Signer {
        Ed25519Signer::from_secret_bytes(key_id(name), &Zeroizing::new(seed))
    }

    fn verifier_for(signer: &Ed25519Signer) -> Ed25519Verifier {
        Ed25519Verifier::from_key(signer.key_id().clone(), &signer.public_key_bytes()).unwrap()
    }

    fn policy_public(signer: &Ed25519Signer) -> String {
        URL_SAFE_NO_PAD.encode(signer.public_key_bytes())
    }

    fn fixture() -> Fixture {
        let client_signer = signer(CLIENT_SIGNING_KEY, [7; 32]);
        let mallory_signer = signer(MALLORY_SIGNING_KEY, [8; 32]);
        let response_signer = signer(RESPONSE_SIGNING_KEY, [9; 32]);
        let response_signing_seed = [9; 32];
        let target_signing_seed = [10; 32];

        let request_private = Zeroizing::new([0x11; 32]);
        let response_private = Zeroizing::new([0x22; 32]);
        let request_public_bytes = crate::x25519_seal::public_from_private(&request_private);
        let response_private_bytes = response_private.to_vec();
        let request_public = X25519RecipientPublic {
            key_id: key_id(REQUEST_SEALING_KEY),
            public: request_public_bytes,
        };
        let response_recipient =
            X25519Recipient::new(key_id(RESPONSE_SEALING_KEY), response_private);
        let response_public_bytes = response_recipient.public().public;

        let mut kv = BTreeMap::new();
        kv.insert(
            "secret/request/x25519".to_string(),
            request_private.to_vec(),
        );
        kv.insert(
            "secret/request/x25519-public".to_string(),
            request_public_bytes.to_vec(),
        );
        kv.insert("secret/response/x25519".to_string(), response_private_bytes);
        kv.insert(
            "secret/response/x25519-public".to_string(),
            response_public_bytes.to_vec(),
        );

        let catalog = catalog_json();
        let policy = policy_json(&client_signer, &mallory_signer);
        let (catalog, resolved, config, warnings) = load(&catalog, &policy).unwrap();
        assert!(warnings.is_empty(), "fixture warnings: {warnings:?}");

        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert(
            "test".to_string(),
            Box::new(TestBackend {
                response_signing_seed,
                target_signing_seed,
                kv,
            }),
        );
        let manager = BackendManager::new(catalog.clone(), backends).unwrap();
        let state = Arc::new(BrokerState::new(catalog, resolved, config, manager, "test"));
        let service = BrokerGrpc::new_with_invocation_config(
            state,
            InvocationRuntimeConfig {
                enabled: true,
                broker_identity: Some(BrokerIdentityRuntimeConfig {
                    id: BROKER_SUBJECT.to_string(),
                    response_signing_key_id: RESPONSE_SIGNING_KEY.to_string(),
                }),
                audiences: vec![BROKER_SUBJECT.to_string()],
                request_encryption_key_id: Some(REQUEST_SEALING_KEY.to_string()),
                max_ttl_secs: DEFAULT_EXPIRES_AFTER_SECS,
                clock_skew_secs: 5,
                challenge_table: crate::core::challenge::ChallengeTableConfig {
                    global_capacity: 16,
                    ..Default::default()
                },
                run_quota_buckets_per_rule: 16,
                require_challenge: false,
                now_unix_override: Some(NOW),
            },
        );

        Fixture {
            service,
            client_signer,
            mallory_signer,
            broker_verifier: verifier_for(&response_signer),
            request_public,
            response_recipient,
        }
    }

    fn catalog_json() -> String {
        format!(
            r#"{{
              "schema": "catalog",
              "backends": {{
                "test": {{ "kind": "vault", "addr": "https://127.0.0.1:8200" }}
              }},
              "keys": {{
                "{REQUEST_SEALING_KEY}": {{
                  "class": "sealing", "keyType": "x25519", "backend": "test", "engine": "kv2",
                  "path": "secret/request/x25519", "publicPath": "secret/request/x25519-public",
                  "writable": false, "missing": "error",
                  "labels": ["broker_key_use=request-encryption"],
                  "description": "request sealing key"
                }},
                "{RESPONSE_SEALING_KEY}": {{
                  "class": "sealing", "keyType": "x25519", "backend": "test", "engine": "kv2",
                  "path": "secret/response/x25519", "publicPath": "secret/response/x25519-public",
                  "writable": false, "missing": "error",
                  "labels": ["broker_key_use=response-encryption"],
                  "description": "response sealing key"
                }},
                "{RESPONSE_SIGNING_KEY}": {{
                  "class": "asymmetric", "keyType": "ed25519", "backend": "test",
                  "path": "response-signing", "writable": false, "missing": "error",
                  "labels": ["broker_key_use=response-signing"],
                  "description": "response signing key"
                }},
                "{TARGET_SIGNING_KEY}": {{
                  "class": "asymmetric", "keyType": "ed25519", "backend": "test",
                  "path": "target-signing", "writable": true, "missing": "error",
                  "description": "target signing key"
                }}
              }}
            }}"#
        )
    }

    fn policy_json(client_signer: &Ed25519Signer, mallory_signer: &Ed25519Signer) -> String {
        let client_public = policy_public(client_signer);
        let mallory_public = policy_public(mallory_signer);
        format!(
            r#"{{
              "schema": "policy",
              "subjects": {{
                "{CLIENT_SUBJECT}": {{
                  "domain": "host-process",
                  "match": {{ "all": [
                    {{ "process.uid": 42 }},
                    {{ "invocation.signature-key": {{ "algorithm": "ed25519", "public": "{client_public}" }} }}
                  ] }}
                }},
                "mallory": {{
                  "domain": "host-process",
                  "match": {{ "all": [
                    {{ "process.uid": 42 }},
                    {{ "invocation.signature-key": {{ "algorithm": "ed25519", "public": "{mallory_public}" }} }}
                  ] }}
                }}
              }},
              "roles": {{
                "invoker": ["decrypt"],
                "signer": ["sign"]
              }},
              "rules": [
                {{ "id": "client-invoke", "subjects": ["{CLIENT_SUBJECT}"], "action": ["role:invoker"], "target": ["{REQUEST_SEALING_KEY}"] }},
                {{ "id": "client-sign", "subjects": ["{CLIENT_SUBJECT}"], "action": ["role:signer"], "target": ["{TARGET_SIGNING_KEY}"] }}
              ],
              "config": {{ "names": {{ "users": {{}}, "groups": {{}} }}, "memberships": {{}} }}
            }}"#
        )
    }

    fn request_claims(message_id: &[u8]) -> Claims {
        Claims {
            issuer: Some(subject(CLIENT_SUBJECT)),
            audience: Some(subject(BROKER_SUBJECT)),
            expires_at: Some(UnixTime(1_050)),
            issued_at: UnixTime(ISSUED_AT),
            message_id: self::message_id(message_id),
            sender_key_id: Some(key_id(CLIENT_SIGNING_KEY)),
            response_key_id: Some(key_id(RESPONSE_SEALING_KEY)),
            response_subject: Some(ResponseSubject::new("reply.client".to_string()).unwrap()),
            in_reply_to: None,
            request_hash: None,
            freshness_challenge: None,
            response_public_key_cose: None,
        }
    }

    fn ephemeral_response_recipient(seed: u8) -> (X25519Recipient, X25519ResponsePublicKey) {
        let private = Zeroizing::new([seed; 32]);
        let provisional = X25519Recipient::new(key_id("provisional"), private);
        let public = X25519ResponsePublicKey::from_public_bytes(provisional.public().public)
            .expect("contributory response public key");
        let recipient = X25519Recipient::new(
            KeyId::from_text(&public.thumbprint()).expect("thumbprint key id"),
            Zeroizing::new([seed; 32]),
        );
        (recipient, public)
    }

    fn sign_body() -> Vec<u8> {
        SignInvocationRequest {
            key_id: TARGET_SIGNING_KEY.to_string(),
            message: b"sign me".to_vec(),
            algorithm: pb::SigningAlgorithm::Ed25519 as i32,
        }
        .to_cbor_bytes()
    }

    async fn sealed_request_with(
        fixture: &Fixture,
        claims: Claims,
        content_type: &str,
        plaintext: &[u8],
    ) -> Vec<u8> {
        sealed_request_with_signer(
            fixture,
            claims,
            content_type,
            plaintext,
            &fixture.client_signer,
        )
        .await
    }

    async fn sealed_request_with_signer(
        fixture: &Fixture,
        claims: Claims,
        content_type: &str,
        plaintext: &[u8],
        signer: &Ed25519Signer,
    ) -> Vec<u8> {
        build_sealed(
            &SealParams {
                content_type: self::content_type(content_type),
                plaintext,
                claims,
                role: MessageRole::Request,
                recipient: fixture.request_public.clone(),
                content_algorithm: ContentAlgorithm::A256Gcm,
                aad: SealedAad::empty(),
                kdf_parties: KdfParties::anonymous(),
            },
            signer,
        )
        .await
        .unwrap()
        .into_vec()
    }

    async fn sealed_request_to(
        fixture: &Fixture,
        claims: Claims,
        recipient: X25519RecipientPublic,
    ) -> Vec<u8> {
        build_sealed(
            &SealParams {
                content_type: self::content_type(CONTENT_TYPE_SIGN_REQUEST),
                plaintext: &sign_body(),
                claims,
                role: MessageRole::Request,
                recipient,
                content_algorithm: ContentAlgorithm::A256Gcm,
                aad: SealedAad::empty(),
                kdf_parties: KdfParties::anonymous(),
            },
            &fixture.client_signer,
        )
        .await
        .unwrap()
        .into_vec()
    }

    async fn valid_request(fixture: &Fixture) -> Vec<u8> {
        sealed_request_with(
            fixture,
            request_claims(b"msg-1"),
            CONTENT_TYPE_SIGN_REQUEST,
            &sign_body(),
        )
        .await
    }

    fn request(message: Vec<u8>) -> Request<pb::SealedRequest> {
        let mut request = Request::new(pb::SealedRequest { message });
        request.extensions_mut().insert(crate::peer::PeerInfo {
            uid: Some(42),
            gid: Some(42),
            ..crate::peer::PeerInfo::default()
        });
        request
    }

    async fn prepare_err(fixture: &Fixture, message: Vec<u8>) -> Status {
        fixture
            .service
            .prepare_invocation(&request(message))
            .await
            .unwrap_err()
    }

    async fn assert_prepare_code(fixture: &Fixture, message: Vec<u8>, code: Code) -> Status {
        let status = prepare_err(fixture, message).await;
        assert_eq!(status.code(), code);
        status
    }

    fn response_validation() -> ValidationParams {
        ValidationParams {
            now: UnixTime(i64::from(NOW)),
            max_clock_skew: Duration::from_secs(5),
            max_ttl: Duration::from_secs(u64::from(DEFAULT_EXPIRES_AFTER_SECS)),
            default_ttl: Duration::from_secs(u64::from(DEFAULT_EXPIRES_AFTER_SECS)),
            allowed_audiences: BTreeSet::new(),
            role: MessageRole::Response,
        }
    }

    async fn verify_response(
        fixture: &Fixture,
        response: &pb::SealedResponse,
        original_request: &[u8],
    ) -> (VerifiedSealed, SignInvocationResponse) {
        verify_response_with_recipient(
            fixture,
            response,
            original_request,
            &fixture.response_recipient,
        )
        .await
    }

    async fn verify_response_with_recipient(
        fixture: &Fixture,
        response: &pb::SealedResponse,
        original_request: &[u8],
        recipient: &X25519Recipient,
    ) -> (VerifiedSealed, SignInvocationResponse) {
        let validation = response_validation();
        let verified = verify_sealed(
            &response.message,
            &fixture.broker_verifier,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            verified.claims.request_hash.as_ref(),
            Some(&request_hash(original_request))
        );
        let opened = verified
            .open(
                recipient,
                &ExternalAad::empty(),
                Some(&KdfParties::anonymous()),
            )
            .await
            .unwrap();
        let body = SignInvocationResponse::from_cbor_bytes(opened.plaintext.as_slice()).unwrap();
        (verified, body)
    }

    fn cbor_sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        e.array(4).unwrap();
        e.str("Signature1").unwrap();
        e.bytes(protected).unwrap();
        e.bytes(&[]).unwrap();
        e.bytes(payload).unwrap();
        out
    }

    async fn assemble_sign1(protected: &[u8], payload: &[u8], signer: &Ed25519Signer) -> Vec<u8> {
        let sig_structure = cbor_sig_structure(protected, payload);
        let signature = signer.sign(&sig_structure).await.unwrap();
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        e.tag(minicbor::data::Tag::new(18)).unwrap();
        e.array(4).unwrap();
        e.bytes(protected).unwrap();
        e.map(0).unwrap();
        e.bytes(payload).unwrap();
        e.bytes(signature.as_bytes()).unwrap();
        out
    }

    fn sealed_outer_protected(alg: i64, kid: &KeyId) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        e.map(2).unwrap();
        e.i64(1).unwrap();
        e.i64(alg).unwrap();
        e.i64(4).unwrap();
        e.bytes(kid.as_bytes()).unwrap();
        out
    }

    fn protected_with_crit(kid: &KeyId) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        e.map(3).unwrap();
        e.i64(1).unwrap();
        e.i64(-8).unwrap();
        e.i64(2).unwrap();
        e.array(1).unwrap();
        e.i64(-70_003).unwrap();
        e.i64(4).unwrap();
        e.bytes(kid.as_bytes()).unwrap();
        out
    }

    fn raw_sign1(protected: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut e = Encoder::new(&mut out);
        e.tag(minicbor::data::Tag::new(18)).unwrap();
        e.array(4).unwrap();
        e.bytes(protected).unwrap();
        e.map(0).unwrap();
        e.bytes(b"payload").unwrap();
        e.bytes(&[0u8; 64]).unwrap();
        out
    }

    fn read_bstr_range(bytes: &[u8], offset: usize) -> (std::ops::Range<usize>, usize) {
        let head = bytes[offset];
        let major = head >> 5;
        assert_eq!(major, 2);
        let add = head & 0x1f;
        let (len, start) = match add {
            n @ 0..=23 => (usize::from(n), offset + 1),
            24 => (usize::from(bytes[offset + 1]), offset + 2),
            25 => {
                let len = u16::from_be_bytes([bytes[offset + 1], bytes[offset + 2]]);
                (usize::from(len), offset + 3)
            }
            other => panic!("unsupported bstr additional info {other}"),
        };
        (start..start + len, start + len)
    }

    fn sign1_payload(bytes: &[u8]) -> Vec<u8> {
        assert_eq!(bytes[0], 0xD2);
        assert_eq!(bytes[1], 0x84);
        let (_, next) = read_bstr_range(bytes, 2);
        assert_eq!(bytes[next], 0xA0);
        let (payload, _) = read_bstr_range(bytes, next + 1);
        bytes[payload].to_vec()
    }

    fn flip_last_byte(mut bytes: Vec<u8>) -> Vec<u8> {
        let last = bytes.last_mut().unwrap();
        *last ^= 0x01;
        bytes
    }

    #[test]
    fn request_hash_uses_complete_request_bytes() {
        let h1 = request_hash(b"request-a");
        let h2 = request_hash(b"request-b");
        assert_ne!(h1, h2);
    }

    #[tokio::test]
    async fn sealed_invocation_happy_path_signs_and_protects_response() {
        let fixture = fixture();
        let request_message = valid_request(&fixture).await;
        let response = fixture
            .service
            .invoke(request(request_message.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.response_subject, Some("reply.client".to_string()));

        let (verified, body) = verify_response(&fixture, &response, &request_message).await;
        assert_eq!(verified.claims.issuer, Some(subject(BROKER_SUBJECT)));
        assert_eq!(verified.claims.in_reply_to, Some(message_id(b"msg-1")));
        assert_eq!(body.status, InvocationStatus::ok());
        assert_eq!(body.signature.as_ref().unwrap().len(), 64);
    }

    #[test]
    fn response_recipient_admission_matrix_is_strict_and_disjoint() {
        let fixture = fixture();
        let generation = fixture.service.state.load_generation();

        let missing = request_claims(b"provider-missing-response-key");
        let status = BrokerGrpc::resolve_response_recipient(&generation, &missing, true)
            .expect_err("verified provider proof requires an ephemeral response key");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("missing an ephemeral response"));

        let (_, public) = ephemeral_response_recipient(0x31);
        let mut injected = request_claims(b"subject-key-injection");
        injected.response_key_id = Some(key_id(&public.thumbprint()));
        injected.response_public_key_cose = Some(public);
        let status = BrokerGrpc::resolve_response_recipient(&generation, &injected, false)
            .expect_err("subject-key mode forbids an ephemeral response key");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(
            status
                .message()
                .contains("requires verified provider proof")
        );

        let mut substituted = injected.clone();
        substituted.response_key_id = Some(key_id(RESPONSE_SEALING_KEY));
        let status = BrokerGrpc::resolve_response_recipient(&generation, &substituted, true)
            .expect_err("provider response key substitution must fail closed");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("does not match"));

        let ephemeral = BrokerGrpc::resolve_response_recipient(&generation, &injected, true)
            .expect("verified provider selects the request key");
        assert_eq!(
            ephemeral,
            ResponseRecipient::Ephemeral {
                key_id: public.thumbprint(),
                public: *public.as_public_bytes(),
            }
        );

        let catalog = BrokerGrpc::resolve_response_recipient(
            &generation,
            &request_claims(b"legacy-catalog"),
            false,
        )
        .expect("subject-key mode retains the catalog response key");
        assert_eq!(
            catalog,
            ResponseRecipient::Catalog {
                key_id: RESPONSE_SEALING_KEY.to_string(),
            }
        );
    }

    #[tokio::test]
    async fn subject_key_request_cannot_inject_an_ephemeral_response_recipient() {
        let fixture = fixture();
        let (_, public) = ephemeral_response_recipient(0x37);
        let mut claims = request_claims(b"subject-key-ephemeral-injection");
        claims.response_key_id = Some(key_id(&public.thumbprint()));
        claims.response_public_key_cose = Some(public);
        let message =
            sealed_request_with(&fixture, claims, CONTENT_TYPE_SIGN_REQUEST, &sign_body()).await;
        let status = prepare_err(&fixture, message).await;
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(
            status
                .message()
                .contains("requires verified provider proof")
        );
    }

    #[tokio::test]
    async fn failed_response_recipient_admission_does_not_consume_challenge() {
        let fixture = fixture();
        let generation = fixture.service.state.load_generation().to_owned();
        let proof_public = fixture.client_signer.public_key_bytes();
        let challenge = issue_challenge(&fixture, client_jkt(&fixture)).await;
        let mut claims = request_claims(b"admission-before-challenge");
        claims.freshness_challenge = Some(basil_cose::FreshnessChallenge::new(challenge));

        BrokerGrpc::resolve_response_recipient(&generation, &claims, true)
            .expect_err("missing provider response key is rejected");

        let policy = generation.policy().clone();
        let verifier = PolicyVerifier::new(&policy);
        fixture
            .service
            .consume_freshness_challenge(generation.id(), &claims, Some(&proof_public), &verifier)
            .expect("no envelope error")
            .expect("recipient admission failure must leave challenge unconsumed");
    }

    #[tokio::test]
    async fn ephemeral_recipient_protects_success_and_denial_without_catalog_lookup() {
        let fixture = fixture();
        let (ephemeral_private, ephemeral_public) = ephemeral_response_recipient(0x41);
        let recipient = ResponseRecipient::Ephemeral {
            key_id: ephemeral_public.thumbprint(),
            public: *ephemeral_public.as_public_bytes(),
        };
        let request_message = valid_request(&fixture).await;
        let request_message_id = message_id(b"ephemeral-response");
        let envelope = ResponseEnvelope {
            response_recipient: &recipient,
            response_subject: Some("reply.ephemeral"),
            request_message: &request_message,
            request_message_id: &request_message_id,
        };
        let success_body = SignInvocationResponse {
            status: InvocationStatus::ok(),
            policy_generation: fixture.service.state.load_generation().id(),
            signature: Some(vec![0x5a; 64]),
        };
        let response = fixture
            .service
            .protect_response(
                &envelope,
                CONTENT_TYPE_SIGN_RESPONSE,
                &success_body.to_cbor_bytes(),
            )
            .await
            .expect("ephemeral response protection does not need a catalog entry");
        let (_, opened) = verify_response_with_recipient(
            &fixture,
            &response,
            &request_message,
            &ephemeral_private,
        )
        .await;
        assert_eq!(opened, success_body);

        let validation = response_validation();
        let verified = verify_sealed(
            &response.message,
            &fixture.broker_verifier,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation,
            },
        )
        .await
        .expect("broker signature remains independently pinned");
        assert!(
            verified
                .open(
                    &fixture.response_recipient,
                    &ExternalAad::empty(),
                    Some(&KdfParties::anonymous()),
                )
                .await
                .is_err(),
            "catalog private key must not open an ephemeral response",
        );

        let denied = DeniedInvocation {
            generation: fixture.service.state.load_generation().to_owned(),
            denial: SealedDenial::ChallengeUnknown,
            response_recipient: recipient,
            response_subject: Some("reply.ephemeral".to_string()),
            request_message_id,
            request_message: request_message.clone(),
        };
        let denial = fixture
            .service
            .protect_denied_invocation(&denied)
            .await
            .expect("freshness denial uses the same ephemeral recipient");
        let (_, opened) =
            verify_response_with_recipient(&fixture, &denial, &request_message, &ephemeral_private)
                .await;
        assert_eq!(opened.status, InvocationStatus::challenge_unknown());
        assert!(opened.signature.is_none());
    }

    fn client_jkt(fixture: &Fixture) -> [u8; 32] {
        crate::ci_federation::proof_key_thumbprint(&fixture.client_signer.public_key_bytes())
    }

    async fn issue_challenge(fixture: &Fixture, jkt: [u8; 32]) -> [u8; 32] {
        let issued = fixture
            .service
            .get_invocation_challenge(Request::new(pb::GetInvocationChallengeRequest {
                jkt: jkt.to_vec(),
                courier_observed_source: None,
            }))
            .await
            .expect("challenge issues")
            .into_inner();
        assert_eq!(issued.expires_at_unix, i64::from(NOW) + 60);
        issued.challenge.as_slice().try_into().expect("32 bytes")
    }

    async fn challenged_request(fixture: &Fixture, message_id: &[u8]) -> Vec<u8> {
        let challenge = issue_challenge(fixture, client_jkt(fixture)).await;
        let mut claims = request_claims(message_id);
        claims.freshness_challenge = Some(basil_cose::FreshnessChallenge::new(challenge));
        sealed_request_with(fixture, claims, CONTENT_TYPE_SIGN_REQUEST, &sign_body()).await
    }

    #[tokio::test]
    async fn challenged_request_consumes_exactly_once_and_replay_is_sealed_unknown() {
        let fixture = fixture();
        let message = challenged_request(&fixture, b"challenged").await;
        let first = fixture
            .service
            .invoke(request(message.clone()))
            .await
            .unwrap()
            .into_inner();
        let (_, body) = verify_response(&fixture, &first, &message).await;
        assert_eq!(body.status, InvocationStatus::ok());

        // The identical message replays as a sealed non-retryable
        // CHALLENGE_UNKNOWN: the challenge was consumed exactly once.
        let replayed = fixture
            .service
            .invoke(request(message.clone()))
            .await
            .unwrap()
            .into_inner();
        let (verified, body) = verify_response(&fixture, &replayed, &message).await;
        assert_eq!(body.status, InvocationStatus::challenge_unknown());
        assert!(body.signature.is_none());
        assert_eq!(verified.claims.in_reply_to, Some(message_id(b"challenged")));
    }

    #[tokio::test]
    async fn challenge_bound_to_another_key_is_denied_sealed() {
        let fixture = fixture();
        let mallory_jkt =
            crate::ci_federation::proof_key_thumbprint(&fixture.mallory_signer.public_key_bytes());
        let challenge = issue_challenge(&fixture, mallory_jkt).await;
        let mut claims = request_claims(b"stolen-challenge");
        claims.freshness_challenge = Some(basil_cose::FreshnessChallenge::new(challenge));
        let message =
            sealed_request_with(&fixture, claims, CONTENT_TYPE_SIGN_REQUEST, &sign_body()).await;
        let response = fixture
            .service
            .invoke(request(message.clone()))
            .await
            .unwrap()
            .into_inner();
        let (_, body) = verify_response(&fixture, &response, &message).await;
        assert_eq!(body.status, InvocationStatus::challenge_unknown());
    }

    #[tokio::test]
    async fn foreign_instance_challenge_is_denied_sealed() {
        let fixture = fixture();
        // A challenge from a different agent instance (or a pre-restart one)
        // has an unknown instance-ID prefix and denies without table state.
        let mut claims = request_claims(b"foreign-instance");
        claims.freshness_challenge = Some(basil_cose::FreshnessChallenge::new([0x5A; 32]));
        let message =
            sealed_request_with(&fixture, claims, CONTENT_TYPE_SIGN_REQUEST, &sign_body()).await;
        let response = fixture
            .service
            .invoke(request(message.clone()))
            .await
            .unwrap()
            .into_inner();
        let (_, body) = verify_response(&fixture, &response, &message).await;
        assert_eq!(body.status, InvocationStatus::challenge_unknown());
    }

    #[tokio::test]
    async fn without_a_challenge_the_message_id_is_correlation_only() {
        // SPEC rev 4 removed the message-ID replay table: a subject-key
        // request that presents no challenge is accepted, and its message ID
        // is correlation-only (a duplicate is not rejected on that basis).
        let fixture = fixture();
        let message = valid_request(&fixture).await;
        for _ in 0..2 {
            let response = fixture
                .service
                .invoke(request(message.clone()))
                .await
                .unwrap()
                .into_inner();
            let (_, body) = verify_response(&fixture, &response, &message).await;
            assert_eq!(body.status, InvocationStatus::ok());
        }
    }

    #[tokio::test]
    async fn courier_denies_challenge_less_subject_key_requests() {
        // A Courier listener forces require-challenge even when the global
        // compatibility setting is false. A bare subject-key request receives
        // sealed CHALLENGE_UNKNOWN, while a challenged request still succeeds.
        let fixture = fixture();
        assert!(!fixture.service.invocation.require_challenge);
        let strict = BrokerGrpc::new_with_invocation_config_for_listener(
            Arc::clone(&fixture.service.state),
            fixture.service.invocation.clone(),
            crate::transport::grpc_server::ListenerType::Courier,
        );
        assert!(strict.invocation.require_challenge);

        let bare = valid_request(&fixture).await;
        let response = strict
            .invoke(request(bare.clone()))
            .await
            .unwrap()
            .into_inner();
        let (_, body) = verify_response(&fixture, &response, &bare).await;
        assert_eq!(body.status, InvocationStatus::challenge_unknown());
        assert!(body.signature.is_none());

        // The challenge must come from the strict service instance: the
        // table (and its instance ID) is per-BrokerGrpc.
        let issued = strict
            .get_invocation_challenge(Request::new(pb::GetInvocationChallengeRequest {
                jkt: client_jkt(&fixture).to_vec(),
                courier_observed_source: None,
            }))
            .await
            .expect("challenge issues")
            .into_inner();
        let challenge: [u8; 32] = issued.challenge.as_slice().try_into().expect("32 bytes");
        let mut claims = request_claims(b"strict-challenged");
        claims.freshness_challenge = Some(basil_cose::FreshnessChallenge::new(challenge));
        let challenged =
            sealed_request_with(&fixture, claims, CONTENT_TYPE_SIGN_REQUEST, &sign_body()).await;
        let response = strict
            .invoke(request(challenged.clone()))
            .await
            .unwrap()
            .into_inner();
        let (_, body) = verify_response(&fixture, &response, &challenged).await;
        assert_eq!(body.status, InvocationStatus::ok());
    }

    #[tokio::test]
    async fn proof_bound_requests_must_present_a_challenge() {
        let fixture = fixture();
        let generation = fixture.service.state.load_generation().to_owned();
        let policy = generation.policy().clone();
        let verifier = PolicyVerifier::new(&policy);
        let claims = request_claims(b"no-challenge");
        let outcome = fixture
            .service
            .consume_freshness_challenge(generation.id(), &claims, Some(&[9; 32]), &verifier)
            .expect("no envelope error");
        assert!(matches!(outcome, Err(ChallengeDenial::Missing)));
    }

    #[tokio::test]
    async fn per_run_quota_denial_seals_the_retryable_never_status() {
        // The quota denial rides the same sealed denial envelope as a
        // freshness denial: status code 6 `PER_RUN_QUOTA_EXCEEDED`,
        // `retryable = false`, no signature, correlated to the request.
        let fixture = fixture();
        let message = valid_request(&fixture).await;
        let denied = DeniedInvocation {
            generation: fixture.service.state.load_generation().to_owned(),
            denial: SealedDenial::PerRunQuotaExceeded,
            response_recipient: ResponseRecipient::Catalog {
                key_id: RESPONSE_SEALING_KEY.to_string(),
            },
            response_subject: Some("reply.client".to_string()),
            request_message_id: message_id(b"msg-1"),
            request_message: message.clone(),
        };
        let response = fixture
            .service
            .protect_denied_invocation(&denied)
            .await
            .expect("denial seals");
        let (verified, body) = verify_response(&fixture, &response, &message).await;
        assert_eq!(body.status, InvocationStatus::per_run_quota_exceeded());
        assert!(!body.status.retryable);
        assert!(body.signature.is_none());
        assert_eq!(verified.claims.in_reply_to, Some(message_id(b"msg-1")));
    }

    #[tokio::test]
    async fn run_quota_untracked_denial_seals_a_retryable_status() {
        // Bucket-table pressure is not quota exhaustion: the sealed status
        // must be retryable so a legitimate run denied by unrelated
        // pressure retries after expired buckets are reclaimed, and the
        // reason must be distinguishable from `PER_RUN_QUOTA_EXCEEDED`.
        let fixture = fixture();
        let message = valid_request(&fixture).await;
        let denied = DeniedInvocation {
            generation: fixture.service.state.load_generation().to_owned(),
            denial: SealedDenial::RunQuotaUntracked,
            response_recipient: ResponseRecipient::Catalog {
                key_id: RESPONSE_SEALING_KEY.to_string(),
            },
            response_subject: Some("reply.client".to_string()),
            request_message_id: message_id(b"msg-2"),
            request_message: message.clone(),
        };
        let response = fixture
            .service
            .protect_denied_invocation(&denied)
            .await
            .expect("denial seals");
        let (verified, body) = verify_response(&fixture, &response, &message).await;
        assert_eq!(body.status, InvocationStatus::run_quota_untracked());
        assert!(body.status.retryable);
        assert!(body.signature.is_none());
        assert_eq!(verified.claims.in_reply_to, Some(message_id(b"msg-2")));
    }

    #[test]
    fn invocation_tables_charge_the_generation_scoped_run_quota() {
        // The broker-held table delegates to the generation-scoped quota
        // counters: exhaustion denies, a reload (new generation) resets.
        const RETENTION: u64 = 630;
        const QUOTA_NOW: i64 = 1_700_000_000;
        let mut cache =
            InvocationTables::new(crate::core::challenge::ChallengeTableConfig::default(), 16);
        let key = crate::ci_federation::RunQuotaKey {
            rule_id: "release".to_string(),
            run_id: 900,
            run_attempt: 1,
        };
        cache
            .charge_run_quota(7, &key, Some(1), RETENTION, QUOTA_NOW)
            .expect("admitted");
        assert_eq!(
            cache.charge_run_quota(7, &key, Some(1), RETENTION, QUOTA_NOW),
            Err(crate::ci_federation::RunQuotaDenied::Exhausted)
        );
        cache
            .charge_run_quota(8, &key, Some(1), RETENTION, QUOTA_NOW)
            .expect("reload resets the counters");
        // Fail closed when the rule somehow carries no quota value.
        assert_eq!(
            cache.charge_run_quota(8, &key, None, RETENTION, QUOTA_NOW),
            Err(crate::ci_federation::RunQuotaDenied::QuotaUnavailable)
        );
    }

    /// One valid GitHub federation rule for serving-path JWKS tests.
    fn federation_rule(id: &str) -> crate::core::ci_federation::ProviderRule {
        use crate::core::ci_federation::{GithubActionsRule, ProviderConfig, ProviderRule};
        const ISSUER: &str = "https://token.actions.githubusercontent.com";
        ProviderRule {
            id: id.to_string(),
            subject: "ci/release".to_string(),
            audience: "urn:basil:ci".to_string(),
            operation_profiles: vec!["artifact-sign".to_string()],
            max_token_age_secs: 900,
            clock_skew_secs: 30,
            max_operations_per_run: Some(64),
            provider: ProviderConfig::GithubActions(GithubActionsRule {
                issuer: ISSUER.to_string(),
                discovery_url: format!("{ISSUER}/.well-known/openid-configuration"),
                jwks_url: format!("{ISSUER}/.well-known/jwks"),
                audience_prefix: "urn:basil:ci:jkt:".to_string(),
                repository_id: 42,
                repository_owner_id: 7,
                job_workflow_ref: "openbasil/basil/.github/workflows/release.yml@refs/heads/main"
                    .to_string(),
                job_workflow_sha: "a".repeat(40),
                protected_refs: vec!["refs/heads/main".to_string()],
                events: vec!["push".to_string()],
                runner_environments: vec!["github-hosted".to_string()],
                environment: None,
                max_token_age_secs: 900,
                clock_skew_secs: 30,
            }),
        }
    }

    /// A generation carrying one federation rule, so its constructor builds
    /// the per-rule JWKS cache map the serving path resolves against.
    fn federation_generation(id: u64) -> Arc<crate::state::Generation> {
        let client_signer = signer(CLIENT_SIGNING_KEY, [7; 32]);
        let mallory_signer = signer(MALLORY_SIGNING_KEY, [8; 32]);
        let (catalog, resolved, config, warnings) = load(
            &catalog_json(),
            &policy_json(&client_signer, &mallory_signer),
        )
        .expect("fixture inputs load");
        assert!(warnings.is_empty(), "fixture warnings: {warnings:?}");
        let rules =
            crate::core::ci_federation::ProviderCatalog::new(vec![federation_rule("release")])
                .expect("rule validates");
        Arc::new(
            crate::state::Generation::new_with_overrides_oci_listeners_and_federation(
                id,
                catalog,
                resolved,
                config,
                Vec::new(),
                None,
                crate::transport::listener::ListenerConfigSet::default(),
                Some(Arc::new(rules)),
            ),
        )
    }

    fn parsed_jwks(generation: u64, kid: &str) -> crate::core::ci_federation::GenerationJwks {
        let modulus = URL_SAFE_NO_PAD.encode([0x80; 256]);
        let body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB"}}]}}"#
        );
        crate::core::ci_federation::GenerationJwks::parse(generation, body.as_bytes())
            .expect("test JWKS parses")
    }

    /// Pins the serving-path wiring of `resolve_rule_jwks_via` (the body of
    /// `resolve_rule_jwks`) against a stub fetch: a rule without a generation
    /// cache entry never fetches and fails closed; an unknown key ID admits
    /// at most one fetch per cooldown window with a failed fetch consuming
    /// the attempt; a fresh hit never fetches; past `max_age` the stale set
    /// serves only within `stale_if_error` while revalidation fails; and a
    /// successful revalidation reinstalls fresh serving.
    #[tokio::test]
    async fn resolve_rule_jwks_pins_refresh_gating_stale_service_and_fail_closed() {
        use std::cell::{Cell, RefCell};
        use std::collections::VecDeque;
        use std::time::{Duration, UNIX_EPOCH};

        use crate::core::ci_federation::{FederationError, GenerationJwks};

        // Default cache policy (what `Generation` installs): max_age 300s,
        // stale_if_error 30s, refresh_cooldown 1s.
        let generation = federation_generation(1);
        let calls = Cell::new(0_u32);
        let script: RefCell<VecDeque<Result<GenerationJwks, FederationError>>> =
            RefCell::new(VecDeque::new());
        let mut fetch = || {
            calls.set(calls.get() + 1);
            std::future::ready(
                script
                    .borrow_mut()
                    .pop_front()
                    .unwrap_or(Err(FederationError::FetchRejected)),
            )
        };
        let t0 = UNIX_EPOCH + Duration::from_secs(1_000_000);

        // A rule with no generation cache entry fails closed without a fetch.
        let absent = resolve_rule_jwks_via(&generation, "absent", "kid-a", t0, &mut fetch)
            .await
            .expect("no envelope error");
        assert!(absent.is_none(), "unknown rule must fail closed");
        assert_eq!(calls.get(), 0, "no cache entry must mean no fetch");

        // Unknown key ID: the cooldown admits one fetch; the failure consumes
        // the attempt, so an immediate retry does not fetch again.
        let miss = resolve_rule_jwks_via(&generation, "release", "kid-a", t0, &mut fetch)
            .await
            .expect("no envelope error");
        assert!(miss.is_none(), "failed refresh serves nothing");
        assert_eq!(calls.get(), 1);
        let gated = resolve_rule_jwks_via(&generation, "release", "kid-a", t0, &mut fetch)
            .await
            .expect("no envelope error");
        assert!(gated.is_none());
        assert_eq!(calls.get(), 1, "failed fetch must consume the attempt");

        // Past the cooldown a successful fetch installs the key set.
        let install_now = t0 + Duration::from_secs(2);
        script.borrow_mut().push_back(Ok(parsed_jwks(1, "kid-a")));
        let installed =
            resolve_rule_jwks_via(&generation, "release", "kid-a", install_now, &mut fetch)
                .await
                .expect("no envelope error")
                .expect("fetched set serves");
        assert!(installed.key("kid-a").is_some());
        assert_eq!(calls.get(), 2);

        // A cached key ID inside max_age serves fresh with no fetch.
        let fresh_now = install_now + Duration::from_secs(100);
        let fresh = resolve_rule_jwks_via(&generation, "release", "kid-a", fresh_now, &mut fetch)
            .await
            .expect("no envelope error")
            .expect("fresh hit serves");
        assert!(fresh.key("kid-a").is_some());
        assert_eq!(calls.get(), 2, "fresh hits must never fetch");

        // Past max_age: revalidation is attempted; on failure the stale set
        // still serves within stale_if_error, and the cooldown gates the
        // second attempt without losing stale service.
        let stale_now = install_now + Duration::from_secs(301);
        let stale = resolve_rule_jwks_via(&generation, "release", "kid-a", stale_now, &mut fetch)
            .await
            .expect("no envelope error")
            .expect("stale set serves inside the window");
        assert!(stale.key("kid-a").is_some());
        assert_eq!(calls.get(), 3);
        let stale_gated =
            resolve_rule_jwks_via(&generation, "release", "kid-a", stale_now, &mut fetch)
                .await
                .expect("no envelope error")
                .expect("cooldown-gated revalidation still serves stale");
        assert!(stale_gated.key("kid-a").is_some());
        assert_eq!(calls.get(), 3, "cooldown must gate the second attempt");

        // Beyond max_age + stale_if_error the rule fails closed while the
        // fetch keeps failing.
        let expired_now = install_now + Duration::from_secs(331);
        let expired =
            resolve_rule_jwks_via(&generation, "release", "kid-a", expired_now, &mut fetch)
                .await
                .expect("no envelope error");
        assert!(expired.is_none(), "stale set must not outlive its window");
        assert_eq!(calls.get(), 4);

        // A successful revalidation restores fresh serving.
        let recover_now = install_now + Duration::from_secs(333);
        script.borrow_mut().push_back(Ok(parsed_jwks(1, "kid-a")));
        let recovered =
            resolve_rule_jwks_via(&generation, "release", "kid-a", recover_now, &mut fetch)
                .await
                .expect("no envelope error")
                .expect("successful revalidation serves");
        assert!(recovered.key("kid-a").is_some());
        assert_eq!(calls.get(), 5);
        let fresh_again = resolve_rule_jwks_via(
            &generation,
            "release",
            "kid-a",
            recover_now + Duration::from_secs(1),
            &mut fetch,
        )
        .await
        .expect("no envelope error")
        .expect("reinstalled set serves fresh");
        assert!(fresh_again.key("kid-a").is_some());
        assert_eq!(calls.get(), 5, "reinstalled set must serve without a fetch");
    }

    #[tokio::test]
    async fn challenge_issuance_validates_the_wire_shape() {
        let fixture = fixture();
        let bad_jkt = fixture
            .service
            .get_invocation_challenge(Request::new(pb::GetInvocationChallengeRequest {
                jkt: vec![0x22; 31],
                courier_observed_source: None,
            }))
            .await
            .expect_err("31-byte jkt rejected");
        assert_eq!(bad_jkt.code(), Code::InvalidArgument);

        let oversized_source = fixture
            .service
            .get_invocation_challenge(Request::new(pb::GetInvocationChallengeRequest {
                jkt: vec![0x22; 32],
                courier_observed_source: Some("s".repeat(129)),
            }))
            .await
            .expect_err("129-byte source rejected");
        assert_eq!(oversized_source.code(), Code::InvalidArgument);

        let disabled = BrokerGrpc::new_with_invocation_config(
            Arc::clone(&fixture.service.state),
            InvocationRuntimeConfig {
                enabled: false,
                ..fixture.service.invocation.clone()
            },
        );
        let status = disabled
            .get_invocation_challenge(Request::new(pb::GetInvocationChallengeRequest {
                jkt: vec![0x22; 32],
                courier_observed_source: None,
            }))
            .await
            .expect_err("disabled service declines issuance");
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn challenge_issuance_pressure_is_resource_exhausted() {
        let fixture = fixture();
        let jkt = [0x33_u8; 32];
        for _ in 0..8 {
            issue_challenge(&fixture, jkt).await;
        }
        let status = fixture
            .service
            .get_invocation_challenge(Request::new(pb::GetInvocationChallengeRequest {
                jkt: jkt.to_vec(),
                courier_observed_source: None,
            }))
            .await
            .expect_err("ninth outstanding challenge for one jkt declines");
        assert_eq!(status.code(), Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn expiry_ttl_skew_and_audience_claims_fail_closed() {
        let fixture = fixture();

        let mut expired = request_claims(b"expired");
        expired.expires_at = Some(UnixTime(900));
        assert_prepare_code(
            &fixture,
            sealed_request_with(&fixture, expired, CONTENT_TYPE_SIGN_REQUEST, &sign_body()).await,
            Code::InvalidArgument,
        )
        .await;

        let mut long_ttl = request_claims(b"long-ttl");
        long_ttl.expires_at = Some(UnixTime(
            ISSUED_AT + i64::from(DEFAULT_EXPIRES_AFTER_SECS) + 1,
        ));
        assert_prepare_code(
            &fixture,
            sealed_request_with(&fixture, long_ttl, CONTENT_TYPE_SIGN_REQUEST, &sign_body()).await,
            Code::InvalidArgument,
        )
        .await;

        let mut future_iat = request_claims(b"future");
        future_iat.issued_at = UnixTime(i64::from(NOW) + 6);
        future_iat.expires_at = Some(UnixTime(i64::from(NOW) + 30));
        assert_prepare_code(
            &fixture,
            sealed_request_with(
                &fixture,
                future_iat,
                CONTENT_TYPE_SIGN_REQUEST,
                &sign_body(),
            )
            .await,
            Code::InvalidArgument,
        )
        .await;

        let mut wrong_audience = request_claims(b"audience");
        wrong_audience.audience = Some(subject("other-broker"));
        assert_prepare_code(
            &fixture,
            sealed_request_with(
                &fixture,
                wrong_audience,
                CONTENT_TYPE_SIGN_REQUEST,
                &sign_body(),
            )
            .await,
            Code::InvalidArgument,
        )
        .await;
    }

    #[tokio::test]
    async fn request_claim_key_and_subject_mismatches_fail_closed() {
        let fixture = fixture();

        let mut unknown_response_key = request_claims(b"unknown-response-key");
        unknown_response_key.response_key_id = Some(key_id("unknown.response"));
        let status = assert_prepare_code(
            &fixture,
            sealed_request_with(
                &fixture,
                unknown_response_key,
                CONTENT_TYPE_SIGN_REQUEST,
                &sign_body(),
            )
            .await,
            Code::InvalidArgument,
        )
        .await;
        assert!(status.message().contains("unknown response encryption key"));

        let mut wrong_response_class = request_claims(b"wrong-response-class");
        wrong_response_class.response_key_id = Some(key_id(TARGET_SIGNING_KEY));
        let status = assert_prepare_code(
            &fixture,
            sealed_request_with(
                &fixture,
                wrong_response_class,
                CONTENT_TYPE_SIGN_REQUEST,
                &sign_body(),
            )
            .await,
            Code::InvalidArgument,
        )
        .await;
        assert!(status.message().contains("must be class `sealing`"));

        let mut wrong_recipient = fixture.request_public.clone();
        wrong_recipient.key_id = key_id("other.request.sealing");
        let status = assert_prepare_code(
            &fixture,
            sealed_request_to(
                &fixture,
                request_claims(b"wrong-recipient"),
                wrong_recipient,
            )
            .await,
            Code::InvalidArgument,
        )
        .await;
        assert!(status.message().contains("recipient key mismatch"));

        let mut unauthorized_unknown_response_key =
            request_claims(b"unauthorized-unknown-response-key");
        unauthorized_unknown_response_key.issuer = Some(subject("mallory"));
        unauthorized_unknown_response_key.sender_key_id = Some(key_id(MALLORY_SIGNING_KEY));
        unauthorized_unknown_response_key.response_key_id = Some(key_id("unknown.response"));
        let status = assert_prepare_code(
            &fixture,
            sealed_request_with_signer(
                &fixture,
                unauthorized_unknown_response_key,
                CONTENT_TYPE_SIGN_REQUEST,
                &sign_body(),
                &fixture.mallory_signer,
            )
            .await,
            Code::InvalidArgument,
        )
        .await;
        assert!(status.message().contains("unknown response encryption key"));

        let mut forged_subject = request_claims(b"forged-subject");
        forged_subject.issuer = Some(subject("mallory"));
        assert_prepare_code(
            &fixture,
            sealed_request_with(
                &fixture,
                forged_subject,
                CONTENT_TYPE_SIGN_REQUEST,
                &sign_body(),
            )
            .await,
            Code::PermissionDenied,
        )
        .await;
    }

    #[tokio::test]
    async fn disabled_service_rejects_before_decoding_message() {
        let fixture = fixture();
        let disabled = BrokerGrpc::new_with_invocation_config(
            Arc::clone(&fixture.service.state),
            InvocationRuntimeConfig {
                enabled: false,
                ..fixture.service.invocation.clone()
            },
        );
        let status = disabled
            .invoke(request(Vec::new()))
            .await
            .expect_err("disabled service rejects");
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn unknown_signer_and_bad_signature_are_indistinguishable() {
        let fixture = fixture();
        let unknown_signer = signer("unknown.signing", [12; 32]);
        let protected = sealed_outer_protected(-8, unknown_signer.key_id());
        let payload = sign1_payload(&valid_request(&fixture).await);
        let unknown = assemble_sign1(&protected, &payload, &unknown_signer).await;
        let unknown_status = assert_prepare_code(&fixture, unknown, Code::PermissionDenied).await;

        let bad_signature = flip_last_byte(valid_request(&fixture).await);
        let bad_status = assert_prepare_code(&fixture, bad_signature, Code::PermissionDenied).await;

        assert_eq!(unknown_status.message(), bad_status.message());
    }

    #[tokio::test]
    async fn malformed_sign_body_and_unsupported_content_type_return_status_responses() {
        let fixture = fixture();
        let malformed_request = sealed_request_with(
            &fixture,
            request_claims(b"bad-body"),
            CONTENT_TYPE_SIGN_REQUEST,
            b"not a sign request body",
        )
        .await;
        let malformed_response = fixture
            .service
            .invoke(request(malformed_request.clone()))
            .await
            .unwrap()
            .into_inner();
        let (_, malformed_body) =
            verify_response(&fixture, &malformed_response, &malformed_request).await;
        assert_eq!(
            malformed_body.status,
            InvocationStatus::invalid_request("INVALID_REQUEST_BODY")
        );

        let unsupported_request = sealed_request_with(
            &fixture,
            request_claims(b"unsupported-content"),
            "application/basil.unsupported",
            b"ignored",
        )
        .await;
        let unsupported_response = fixture
            .service
            .invoke(request(unsupported_request.clone()))
            .await
            .unwrap()
            .into_inner();
        let (_, unsupported_body) =
            verify_response(&fixture, &unsupported_response, &unsupported_request).await;
        assert_eq!(
            unsupported_body.status,
            InvocationStatus::invalid_request("UNSUPPORTED_CONTENT_TYPE")
        );
    }

    #[tokio::test]
    async fn strip_and_resign_fails_sender_key_cross_check() {
        let fixture = fixture();
        let payload = sign1_payload(&valid_request(&fixture).await);
        let protected = sealed_outer_protected(-8, fixture.mallory_signer.key_id());
        let resigned = assemble_sign1(&protected, &payload, &fixture.mallory_signer).await;
        let status = assert_prepare_code(&fixture, resigned, Code::InvalidArgument).await;
        assert!(status.message().contains("sender key"));
    }

    #[tokio::test]
    async fn algorithm_confusion_in_outer_header_is_rejected() {
        // The outer header claims ES256 (-7) but the signature is Ed25519.
        // ES256 is a valid profile algorithm, so strict decode accepts the
        // header; the broker's verifier pins EdDSA subject keys and fails the
        // mismatched signature closed (algorithm mismatch -> PermissionDenied).
        let fixture = fixture();
        let payload = sign1_payload(&valid_request(&fixture).await);
        let protected = sealed_outer_protected(-7, fixture.client_signer.key_id());
        let confused = assemble_sign1(&protected, &payload, &fixture.client_signer).await;
        assert_prepare_code(&fixture, confused, Code::PermissionDenied).await;
    }

    #[tokio::test]
    async fn nesting_confusion_payload_must_be_tagged_cose_encrypt() {
        let fixture = fixture();
        let inner = build_signed(
            &SignParams {
                content_type: content_type(CONTENT_TYPE_SIGN_REQUEST),
                payload: b"not a COSE_Encrypt",
                claims: Some(request_claims(b"nested-sign1")),
                external_aad: ExternalAad::empty(),
            },
            &fixture.client_signer,
        )
        .await
        .unwrap()
        .into_vec();
        let protected = sealed_outer_protected(-8, fixture.client_signer.key_id());
        let nested = assemble_sign1(&protected, &inner, &fixture.client_signer).await;
        assert_prepare_code(&fixture, nested, Code::InvalidArgument).await;
    }

    #[tokio::test]
    async fn tampered_embedded_ciphertext_fails_aead_after_resign() {
        let fixture = fixture();
        let mut payload = sign1_payload(&valid_request(&fixture).await);
        let last = payload.last_mut().unwrap();
        *last ^= 0x01;
        let protected = sealed_outer_protected(-8, fixture.client_signer.key_id());
        let tampered = assemble_sign1(&protected, &payload, &fixture.client_signer).await;
        assert_prepare_code(&fixture, tampered, Code::InvalidArgument).await;
    }

    #[tokio::test]
    async fn crit_header_on_outer_layer_is_rejected() {
        let fixture = fixture();
        let protected = protected_with_crit(fixture.client_signer.key_id());
        let payload = sign1_payload(&valid_request(&fixture).await);
        let with_crit = assemble_sign1(&protected, &payload, &fixture.client_signer).await;
        assert_prepare_code(&fixture, with_crit, Code::InvalidArgument).await;
    }

    #[tokio::test]
    async fn strict_encoding_rejects_untagged_indefinite_duplicate_and_nondeterministic() {
        let fixture = fixture();
        let valid = valid_request(&fixture).await;

        assert_prepare_code(&fixture, valid[1..].to_vec(), Code::InvalidArgument).await;

        let mut indefinite = valid.clone();
        assert_eq!(indefinite[1], 0x84);
        indefinite[1] = 0x9F;
        indefinite.push(0xFF);
        assert_prepare_code(&fixture, indefinite, Code::InvalidArgument).await;

        let mut duplicate_protected = Vec::new();
        let mut e = Encoder::new(&mut duplicate_protected);
        e.map(2).unwrap();
        e.i64(1).unwrap();
        e.i64(-8).unwrap();
        e.i64(1).unwrap();
        e.i64(-8).unwrap();
        assert_prepare_code(
            &fixture,
            raw_sign1(&duplicate_protected),
            Code::InvalidArgument,
        )
        .await;

        let mut nondeterministic = Vec::new();
        let mut e = Encoder::new(&mut nondeterministic);
        e.map(2).unwrap();
        e.i64(4).unwrap();
        e.bytes(fixture.client_signer.key_id().as_bytes()).unwrap();
        e.i64(1).unwrap();
        e.i64(-8).unwrap();
        assert_prepare_code(
            &fixture,
            raw_sign1(&nondeterministic),
            Code::InvalidArgument,
        )
        .await;

        let mut nonminimal = vec![valid[0], 0x98, 0x04];
        nonminimal.extend_from_slice(&valid[2..]);
        assert_prepare_code(&fixture, nonminimal, Code::InvalidArgument).await;
    }

    #[tokio::test]
    async fn clear_response_subject_tampering_does_not_change_verified_response() {
        let fixture = fixture();
        let request_message = valid_request(&fixture).await;
        let mut response = fixture
            .service
            .invoke(request(request_message.clone()))
            .await
            .unwrap()
            .into_inner();
        response.response_subject = Some("attacker.reply".to_string());

        let (verified, body) = verify_response(&fixture, &response, &request_message).await;
        assert_eq!(body.status, InvocationStatus::ok());
        assert_eq!(verified.claims.response_subject, None);
        assert_eq!(verified.claims.in_reply_to, Some(message_id(b"msg-1")));
    }
}
