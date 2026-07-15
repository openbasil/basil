#![allow(clippy::result_large_err)]

// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashMap, VecDeque};
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
        let prepared = self.prepare_invocation(&request).await?;
        tracing::debug!(
            sender_subject = %prepared.actor.subject,
            recipient_key_id = %prepared.recipient_key_id,
            plaintext_len = prepared.body.len(),
            "sealed invocation preflight accepted",
        );
        self.execute_invocation(prepared)
            .await
            .map(Response::new)
            .map_err(|error| {
                tracing::warn!(%error, "sealed invocation response protection failed");
                response_protection_failed()
            })
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

#[derive(Debug)]
struct PreparedInvocation {
    actor: AuthenticatedActor,
    recipient_key_id: String,
    response_key_id: String,
    response_subject: Option<String>,
    content_type: String,
    claims: Claims,
    request_message: Vec<u8>,
    body: DecryptedInvocationBody,
}

impl BrokerGrpc {
    #[allow(
        clippy::too_many_lines,
        reason = "ordered security preflight is kept linear"
    )]
    async fn prepare_invocation(
        &self,
        request: &Request<pb::SealedRequest>,
    ) -> Result<PreparedInvocation, Status> {
        let message = request.get_ref();
        if message.message.is_empty() {
            return Err(invalid_request(INVOKE_OP, "missing sealed COSE message"));
        }

        let peer = peer_from_request(request);
        let generation = self.state.load_generation();
        let generation_id = generation.id();
        let policy = generation.policy().clone();
        let config = generation.config().clone();
        drop(generation);

        let policy_verifier = PolicyVerifier::new(&policy);
        let validation = self.request_validation_params()?;
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
        let mut evidence = host_process_snapshot(&config, &peer, uid);
        evidence.invocation_signature_key =
            EvidenceValue::Available(policy_verifier.verified_key()?);
        let actor = resolve_evidence_actor(&policy, &evidence, &peer).map_err(|error| {
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
        })?;
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

        let recipient_key_id = catalog_key_id(&sealed.recipient_key_id, "recipient key id")?;
        self.validate_request_recipient_key(recipient_key_id)?;
        let response_key_id = sealed
            .claims
            .response_key_id
            .as_ref()
            .ok_or_else(|| invalid_request(INVOKE_OP, "missing response encryption key"))?;
        let response_key_id = catalog_key_id(response_key_id, "response encryption key")?;

        let generation = self.state.load_generation();
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
        drop(generation);

        self.validate_response_encryption_key(response_key_id)
            .await?;
        self.check_replay(
            &sealed.signer_key_id,
            &sealed.claims.message_id,
            effective_expires_at_unix(&sealed.claims)?,
        )?;

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
        Ok(PreparedInvocation {
            actor,
            recipient_key_id: recipient_key_id.to_string(),
            response_key_id: response_key_id.to_string(),
            response_subject,
            content_type: sealed.content_type.as_str().to_string(),
            claims: sealed.claims,
            request_message: message.message.clone(),
            body: DecryptedInvocationBody::new(opened.plaintext),
        })
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
                policy_generation: self.state.load_generation().id(),
                signature: None,
            };
            self.protect_response(&prepared, CONTENT_TYPE_SIGN_RESPONSE, &body.to_cbor_bytes())
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
                let policy_generation = self.state.load_generation().id();
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
            let policy_generation = self.state.load_generation().id();
            tracing::debug!(%error, "sealed sign invocation algorithm rejected");
            return self
                .protect_sign_status_response(
                    &prepared,
                    InvocationStatus::invalid_request("UNSUPPORTED_SIGNING_ALGORITHM"),
                    policy_generation,
                )
                .await;
        }
        let generation = self.state.load_generation();
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
            drop(generation);
            return self
                .protect_sign_status_response(
                    &prepared,
                    InvocationStatus::denied(),
                    policy_generation,
                )
                .await;
        }
        drop(generation);

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
        self.protect_response(&prepared, CONTENT_TYPE_SIGN_RESPONSE, &body.to_cbor_bytes())
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
        self.protect_response(prepared, CONTENT_TYPE_SIGN_RESPONSE, &body.to_cbor_bytes())
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

    async fn validate_response_encryption_key(&self, key_id: &str) -> Result<(), Status> {
        let generation = self.state.load_generation();
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
        drop(generation);
        self.state
            .manager()
            .sealing_public_key(key_id)
            .await
            .map(|_| ())
            .map_err(|e| manager_status(INVOKE_OP, &e))
    }

    async fn protect_response(
        &self,
        prepared: &PreparedInvocation,
        content_type: &str,
        plaintext_body: &[u8],
    ) -> Result<pb::SealedResponse, ResponseProtectionError> {
        let identity = self
            .invocation
            .broker_identity
            .as_ref()
            .ok_or(ResponseProtectionError::MissingBrokerIdentity)?;
        let recipient_public = self
            .state
            .manager()
            .sealing_public_key(&prepared.response_key_id)
            .await
            .map_err(ResponseProtectionError::Manager)?;
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
            in_reply_to: Some(prepared.claims.message_id.clone()),
            request_hash: Some(request_hash(&prepared.request_message)),
        };
        let message = build_sealed(
            &SealParams {
                content_type: ContentType::new(content_type.to_string())?,
                plaintext: plaintext_body,
                claims,
                role: MessageRole::Response,
                recipient: X25519RecipientPublic {
                    key_id: KeyId::from_text(&prepared.response_key_id)?,
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
            response_subject: prepared.response_subject.clone(),
        })
    }

    fn request_validation_params(&self) -> Result<ValidationParams, Status> {
        let mut allowed_audiences = BTreeSet::new();
        for audience in &self.invocation.audiences {
            allowed_audiences.insert(
                Subject::new(audience.clone())
                    .map_err(|e| invalid_request(INVOKE_OP, e.to_string()))?,
            );
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

    fn check_replay(
        &self,
        sender_sign_id: &KeyId,
        message_id: &MessageId,
        expires_at_unix: u32,
    ) -> Result<(), Status> {
        let sender = encode_id(sender_sign_id.as_bytes());
        let message = encode_id(message_id.as_bytes());
        let mut cache = self
            .invocation_replay_cache
            .lock()
            .map_err(|_| invalid_request(INVOKE_OP, "invocation replay cache unavailable"))?;
        cache
            .check_and_insert(
                &sender,
                &message,
                expires_at_unix,
                self.invocation.clock_skew_secs,
                self.invocation_now_unix(),
            )
            .map_err(|e| invalid_request(INVOKE_OP, e.to_string()))
    }
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

fn effective_expires_at_unix(claims: &Claims) -> Result<u32, Status> {
    let effective = match claims.expires_at {
        Some(UnixTime(exp)) => exp,
        None => claims
            .issued_at
            .0
            .saturating_add(i64::from(DEFAULT_EXPIRES_AFTER_SECS)),
    };
    u32::try_from(effective).map_err(|_| invalid_request(INVOKE_OP, "claim expiry out of range"))
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
        _protected_headers: &basil_cose::ProtectedHeaders,
        sig_structure: &[u8],
        signature: &Signature,
    ) -> Result<(), VerifyError> {
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

#[derive(Debug)]
pub(super) struct InvocationReplayCache {
    capacity: usize,
    order: VecDeque<(String, String)>,
    entries: HashMap<(String, String), u32>,
}

impl InvocationReplayCache {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    fn check_and_insert(
        &mut self,
        sender_sign_id: &str,
        message_id: &str,
        expires_at_unix: u32,
        clock_skew_secs: u32,
        now_unix: u32,
    ) -> Result<(), ReplayError> {
        self.evict_expired(now_unix);
        let key = (sender_sign_id.to_string(), message_id.to_string());
        if self.entries.contains_key(&key) {
            return Err(ReplayError::ReplayedMessageId);
        }
        while self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        self.order.push_back(key.clone());
        self.entries
            .insert(key, expires_at_unix.saturating_add(clock_skew_secs));
        Ok(())
    }

    fn evict_expired(&mut self, now_unix: u32) {
        self.entries.retain(|_, expires_at| *expires_at >= now_unix);
        self.order.retain(|key| self.entries.contains_key(key));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum ReplayError {
    #[error("replayed `message_id`")]
    ReplayedMessageId,
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
        Ed25519Signer, Ed25519Verifier, SignParams, VerifiedSealed, X25519Recipient, build_signed,
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
                replay_cache_capacity: 16,
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
        }
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
                &fixture.response_recipient,
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
    fn replay_cache_rejects_duplicate_sender_message_pair() {
        let mut cache = InvocationReplayCache::new(8);
        assert_eq!(cache.check_and_insert("s", "m", 20, 0, 10), Ok(()));
        assert_eq!(
            cache.check_and_insert("s", "m", 20, 0, 10),
            Err(ReplayError::ReplayedMessageId)
        );
        assert_eq!(cache.check_and_insert("s", "other", 20, 0, 10), Ok(()));
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

    #[tokio::test]
    async fn replay_is_rejected_before_second_open() {
        let fixture = fixture();
        let request_message = valid_request(&fixture).await;
        fixture
            .service
            .prepare_invocation(&request(request_message.clone()))
            .await
            .unwrap();
        let status = assert_prepare_code(&fixture, request_message, Code::InvalidArgument).await;
        assert!(status.message().contains("replayed"));
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
        assert_prepare_code(
            &fixture,
            sealed_request_with_signer(
                &fixture,
                unauthorized_unknown_response_key,
                CONTENT_TYPE_SIGN_REQUEST,
                &sign_body(),
                &fixture.mallory_signer,
            )
            .await,
            Code::PermissionDenied,
        )
        .await;

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
