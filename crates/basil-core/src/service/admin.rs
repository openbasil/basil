#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use basil_proto::broker::v1 as pb;
use basil_proto::broker::v1::admin_service_server::AdminService;
use tonic::{Code, Request, Response};

use crate::actor::SubjectResolutionError;
use crate::audit::ReloadActor;
use crate::catalog::policy::Op;
use crate::catalog::{
    ADMIN_EXPLAIN_TARGET, ADMIN_RELOAD_TARGET, ADMIN_REVOKE_TARGET, AllowVia, Decision, DenyReason,
    Explanation, MatchedRule,
};
use crate::decision::DecisionRecord;
use crate::reload::{ReloadError, check_reload, reload_generation};
use crate::service::broker::{BoxStream, BrokerGrpc, GrpcResult};
use crate::service::shared::{event_allowed, proto_event};
use crate::state::{ReadinessOutcome, ReadinessState};
use crate::transport::{broker_status, peer_from_request};
use tracing::warn;

/// The reload op's stable wire token, used in the `BrokerErrorInfo.op` field of a
/// denial status so the CLI/automation can attribute it.
const RELOAD_OP_TOKEN: &str = "reload";
const EXPLAIN_OP_TOKEN: &str = "explain";
const REVOKE_OP_TOKEN: &str = "revoke";

fn admin_resolution_status(op: &'static str, err: &SubjectResolutionError) -> tonic::Status {
    match err {
        SubjectResolutionError::MissingPeerCredentials => broker_status(
            Code::Unauthenticated,
            "UNAUTHENTICATED",
            op,
            "missing peer credentials",
        ),
        SubjectResolutionError::NoSubject { .. }
        | SubjectResolutionError::AmbiguousSubject { .. }
        | SubjectResolutionError::InvalidUnauthenticatedSubject { .. } => {
            broker_status(Code::PermissionDenied, "UNAUTHORIZED", op, "not authorized")
        }
    }
}

#[tonic::async_trait]
impl AdminService for BrokerGrpc {
    type WatchStream = BoxStream<pb::Event>;

    async fn status(&self, _request: Request<pb::StatusRequest>) -> GrpcResult<pb::StatusResponse> {
        Ok(Response::new(pb::StatusResponse {
            backend: self.state.backend_label().to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol: 1,
        }))
    }

    /// Liveness: the broker process is up and serving the socket.
    ///
    /// Producing a response *is* the liveness signal: reaching this handler means
    /// the accept loop and the gRPC stack are alive. It does **no** backend I/O,
    /// so it is cheap and always-answerable, and it is ungated. Liveness reveals
    /// nothing an authenticated socket peer cannot already infer from connecting.
    async fn health(&self, _request: Request<pb::HealthRequest>) -> GrpcResult<pb::HealthResponse> {
        Ok(Response::new(pb::HealthResponse {
            alive: true,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }

    /// Readiness: can the broker actually serve data-plane ops?
    ///
    /// Runs the read-only [`BackendManager::check`] existence probe over every
    /// catalog key: it is bounded (one metadata/KV read per key, each carrying the
    /// client's connect timeout) and never panics. The broker is **not ready** when
    /// the probe fails closed for serving:
    ///
    /// - a backend was **unreachable** (or rejecting), so `check` returns a fatal
    ///   [`ReconcileError::Probe`], surfaced as
    ///   [`ReadinessReason::BackendUnreachable`]; or
    /// - a `missing=error` key's material is **absent**
    ///   ([`CheckReport::should_fail_required`]), so its ops would fail closed,
    ///   surfaced as [`ReadinessReason::RequiredKeyMissing`].
    ///
    /// The response is a non-secret **summary**: counts plus a coarse reason and
    /// the active generation id. It never returns key names, key material, or the
    /// catalog inventory, so it is safe to leave ungated for any socket peer.
    async fn readiness(
        &self,
        _request: Request<pb::ReadinessRequest>,
    ) -> GrpcResult<pb::ReadinessResponse> {
        // Serve a recent probe from the TTL cache if one exists for the current
        // generation (`basil-8nwy`): a burst of ungated `Readiness` calls then
        // re-fans-out to the backend at most once per `READINESS_CACHE_TTL` instead
        // of one metadata/KV read per catalog key per call. A cache miss
        // (cold/expired/generation-changed) runs the probe and refreshes the cache.
        let outcome = if let Some(cached) = self.state.cached_readiness() {
            cached
        } else {
            let fresh = self.probe_readiness().await;
            self.state
                .cache_readiness(self.state.active_generation_id(), fresh);
            fresh
        };
        // Stamp the *current* generation id on the wire response; the cached outcome
        // is generation-independent and is only reused while the generation matches.
        Ok(Response::new(readiness_response(
            outcome,
            self.state.active_generation_id(),
        )))
    }

    async fn watch(&self, request: Request<pb::WatchRequest>) -> GrpcResult<Self::WatchStream> {
        let peer = peer_from_request(&request);
        let generation = self.state.load_generation();
        let Ok(actor) = generation.pdp().resolve_local_actor(&peer) else {
            return Err(broker_status(
                Code::Unauthenticated,
                "UNAUTHENTICATED",
                "watch",
                "missing or unresolved peer credentials",
            ));
        };
        let kinds = request.get_ref().kinds.clone();
        let state = Arc::clone(&self.state);
        let rx = state.events().subscribe();
        let stream = futures::stream::unfold(
            (state, rx, kinds, actor),
            |(state, mut rx, kinds, actor)| async move {
                loop {
                    match rx.recv().await {
                        Ok(event) => {
                            if event_allowed(&state, &actor, &kinds, &event) {
                                return Some((Ok(proto_event(event)), (state, rx, kinds, actor)));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    }
                }
            },
        );
        Ok(Response::new(Box::pin(stream)))
    }

    /// Hot-reload the catalog/policy generation from disk: the first **gated**
    /// admin RPC (`basil-atq`).
    ///
    /// Authorization is the dedicated, broker-wide `reload` op
    /// ([`Op::Reload`]) over the reserved admin target, **never** implied by any
    /// data-plane grant (not even root's `* / *`, since `reload` is excluded from
    /// the `*` expansion). The caller is peer-cred attested; the decision (allow or
    /// deny) is audited via [`BrokerState::record_decision`], and a successful
    /// generation change is additionally audited via
    /// [`BrokerState::record_reload`].
    ///
    /// On `check = true` this is a **dry-run**: it runs the identical validation a
    /// real reload runs ([`check_reload`] and [`reload_generation`] share one
    /// `validate_candidate`) and reports the would-be outcome **without** swapping.
    /// On a validation/routing rejection the previous generation keeps serving and
    /// the RPC returns `OK` with a [`pb::ReloadRejection`]. The trust boundary holds
    /// by construction: [`pb::ReloadRequest`] has no field for config bytes, so the
    /// candidate can only come from the configured on-disk paths.
    async fn reload(&self, request: Request<pb::ReloadRequest>) -> GrpcResult<pb::ReloadResponse> {
        let check = request.get_ref().check;

        // --- 1. Attest + authorize (fail-closed, audited on both paths) -------
        let peer = peer_from_request(&request);
        let generation = self.state.load_generation();
        let actor = generation
            .pdp()
            .resolve_local_actor(&peer)
            .map_err(|err| admin_resolution_status(RELOAD_OP_TOKEN, &err))?;
        let uid = Self::require_unix_uid(&actor, RELOAD_OP_TOKEN)?;

        let decision = generation.pdp().decide_admin(&actor, Op::Reload);
        self.state
            .record_decision(&DecisionRecord::from_actor_decision(
                generation.id(),
                &actor,
                Op::Reload,
                ADMIN_RELOAD_TARGET,
                &decision,
            ));
        // Drop the generation pin before the reload swaps it (avoid holding an old
        // snapshot across the validate-then-swap).
        drop(generation);

        if matches!(decision, Decision::Deny { .. }) {
            return Err(broker_status(
                Code::PermissionDenied,
                "UNAUTHORIZED",
                RELOAD_OP_TOKEN,
                "not authorized to reload",
            ));
        }

        // --- 2. Authorized: validate (and, unless dry-run, swap) --------------
        let result = if check {
            check_reload(&self.state)
        } else {
            reload_generation(&self.state)
        };

        match result {
            Ok(outcome) => {
                // Audit the (real) generation change; a dry-run is non-mutating, so
                // it records a no-op reload audit line for traceability.
                if check {
                    self.state.record_reload(
                        outcome.previous_generation,
                        outcome.previous_generation,
                        "checked",
                        "admin_rpc",
                        ReloadActor::Caller(uid),
                    );
                } else {
                    self.state.record_reload(
                        outcome.previous_generation,
                        outcome.new_generation,
                        "applied",
                        "admin_rpc",
                        ReloadActor::Caller(uid),
                    );
                    if let Err(err) = self.state.refresh_jwt_revocations().await {
                        warn!(
                            error = %err,
                            generation = outcome.new_generation,
                            "admin reload: JWT-SVID revocation deny-list refresh failed; previous in-memory set still serving",
                        );
                        self.state.record_reload(
                            outcome.new_generation,
                            outcome.new_generation,
                            "revocation_refresh_failed",
                            "admin_rpc",
                            ReloadActor::Caller(uid),
                        );
                    }
                }
                let key_count = u32::try_from(outcome.key_count).unwrap_or(u32::MAX);
                let grant_count = u32::try_from(outcome.grant_count).unwrap_or(u32::MAX);
                Ok(Response::new(pb::ReloadResponse {
                    applied: !check,
                    checked: check,
                    previous_generation: outcome.previous_generation,
                    new_generation: outcome.new_generation,
                    key_count,
                    grant_count,
                    rejection: None,
                }))
            }
            Err(err) => {
                // A rejection is NOT a wire error: the previous generation keeps
                // serving and the broker returns a structured rejection. Audit it.
                let active = self.state.active_generation_id();
                self.state.record_reload(
                    active,
                    active,
                    "rejected",
                    err.audit_reason(),
                    ReloadActor::Caller(uid),
                );
                Ok(Response::new(pb::ReloadResponse {
                    applied: false,
                    checked: check,
                    previous_generation: active,
                    new_generation: active,
                    key_count: 0,
                    grant_count: 0,
                    rejection: Some(reload_rejection(&err)),
                }))
            }
        }
    }

    /// Explain a policy decision against the currently serving generation.
    ///
    /// This is permission-gated by the dedicated broker-admin `explain` op over
    /// [`ADMIN_EXPLAIN_TARGET`]. The caller is authorized by peer credentials, but
    /// the request may name any subject to evaluate; that reachability view is
    /// why this RPC is not ungated like health/readiness.
    async fn explain(
        &self,
        request: Request<pb::ExplainRequest>,
    ) -> GrpcResult<pb::ExplainResponse> {
        let subject = request.get_ref().subject.trim().to_string();
        validate_subject(&subject)?;
        let requested_key = request.get_ref().key.clone();
        let requested_op = Op::parse(&request.get_ref().op).map_err(|err| {
            broker_status(
                Code::InvalidArgument,
                "INVALID_ARGUMENT",
                EXPLAIN_OP_TOKEN,
                err.to_string(),
            )
        })?;

        let peer = peer_from_request(&request);
        let generation = self.state.load_generation();
        let actor = generation
            .pdp()
            .resolve_local_actor(&peer)
            .map_err(|err| admin_resolution_status(EXPLAIN_OP_TOKEN, &err))?;

        let decision = generation.pdp().decide_admin(&actor, Op::Explain);
        self.state
            .record_decision(&DecisionRecord::from_actor_decision(
                generation.id(),
                &actor,
                Op::Explain,
                ADMIN_EXPLAIN_TARGET,
                &decision,
            ));

        if matches!(decision, Decision::Deny { .. }) {
            return Err(broker_status(
                Code::PermissionDenied,
                "UNAUTHORIZED",
                EXPLAIN_OP_TOKEN,
                "not authorized to explain policy",
            ));
        }

        let explanation = generation
            .pdp()
            .explain_subject(&subject, requested_op, &requested_key);
        Ok(Response::new(explain_response(
            &subject,
            requested_op,
            &requested_key,
            &explanation,
        )))
    }

    /// Revoke a JWT-SVID by adding its `jti` to the persistent deny-list.
    async fn revoke(&self, request: Request<pb::RevokeRequest>) -> GrpcResult<pb::RevokeResponse> {
        let body = request.get_ref();
        let trust_domain = body.trust_domain.trim();
        let jti = body.jti.trim();
        let expires_at_unix = body.expires_at_unix;
        validate_revoke_request(trust_domain, jti, expires_at_unix)?;

        let peer = peer_from_request(&request);
        let generation = self.state.load_generation();
        let actor = generation
            .pdp()
            .resolve_local_actor(&peer)
            .map_err(|err| admin_resolution_status(REVOKE_OP_TOKEN, &err))?;

        let decision = generation.pdp().decide_admin(&actor, Op::Revoke);
        self.state
            .record_decision(&DecisionRecord::from_actor_decision(
                generation.id(),
                &actor,
                Op::Revoke,
                ADMIN_REVOKE_TARGET,
                &decision,
            ));
        drop(generation);

        if matches!(decision, Decision::Deny { .. }) {
            return Err(broker_status(
                Code::PermissionDenied,
                "UNAUTHORIZED",
                REVOKE_OP_TOKEN,
                "not authorized to revoke JWT-SVIDs",
            ));
        }

        let has_store = self
            .state
            .jwt_revocations()
            .has_persistent_store()
            .map_err(|err| {
                broker_status(Code::Internal, "INTERNAL", REVOKE_OP_TOKEN, err.to_string())
            })?;
        if !has_store {
            return Err(broker_status(
                Code::FailedPrecondition,
                "NO_REVOCATION_STORE",
                REVOKE_OP_TOKEN,
                "JWT-SVID revoke requires a configured revocation_store=jwt-svid value key",
            ));
        }

        self.state
            .revoke_jwt_svid(trust_domain, jti, expires_at_unix)
            .await
            .map_err(|err| {
                broker_status(
                    Code::Unavailable,
                    "BACKEND_UNAVAILABLE",
                    REVOKE_OP_TOKEN,
                    err.to_string(),
                )
            })?;

        Ok(Response::new(pb::RevokeResponse {
            trust_domain: trust_domain.to_string(),
            jti: jti.to_string(),
            expires_at_unix,
            persisted: true,
        }))
    }
}

impl BrokerGrpc {
    /// Run the read-only [`BackendManager::check`] existence probe over every
    /// catalog key and reduce it to a non-secret [`ReadinessOutcome`] (`basil-8nwy`).
    ///
    /// This is the **fan-out** the TTL cache exists to throttle: it performs one
    /// backend metadata/KV read per catalog key. It never panics; an unreachable or
    /// rejecting backend is fail-closed to [`ReadinessState::BackendUnreachable`]
    /// (counts zero, error string never surfaced: it can carry a backend path).
    async fn probe_readiness(&self) -> ReadinessOutcome {
        match self.state.manager().check().await {
            Ok(report) => {
                let keys_total = u32::try_from(report.keys.len()).unwrap_or(u32::MAX);
                let keys_present = u32::try_from(report.present_count()).unwrap_or(u32::MAX);
                let required_missing = report.required_missing().len();
                let keys_required_missing = u32::try_from(required_missing).unwrap_or(u32::MAX);
                // Absent keys total minus the required (`error`) ones = the
                // warn/generate-absent keys that do not block readiness.
                let optional_missing = report.missing().count().saturating_sub(required_missing);
                let keys_optional_missing = u32::try_from(optional_missing).unwrap_or(u32::MAX);

                let state = if required_missing == 0 {
                    ReadinessState::Ready
                } else {
                    ReadinessState::RequiredKeyMissing
                };
                ReadinessOutcome {
                    state,
                    keys_total,
                    keys_present,
                    keys_required_missing,
                    keys_optional_missing,
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    generation = self.state.active_generation_id(),
                    "readiness probe: backend unreachable; reporting not ready"
                );
                ReadinessOutcome {
                    state: ReadinessState::BackendUnreachable,
                    keys_total: 0,
                    keys_present: 0,
                    keys_required_missing: 0,
                    keys_optional_missing: 0,
                }
            }
        }
    }
}

/// Build the wire [`pb::ReadinessResponse`] from a non-secret [`ReadinessOutcome`]
/// and the **current** serving generation id (`basil-8nwy`). The outcome is
/// generation-independent (cached across calls within the TTL); the generation id
/// is always stamped fresh so a hot reload's id is reflected immediately.
fn readiness_response(outcome: ReadinessOutcome, generation: u64) -> pb::ReadinessResponse {
    let reason = match outcome.state {
        ReadinessState::Ready => pb::ReadinessReason::Ready,
        ReadinessState::RequiredKeyMissing => pb::ReadinessReason::RequiredKeyMissing,
        ReadinessState::BackendUnreachable => pb::ReadinessReason::BackendUnreachable,
    };
    pb::ReadinessResponse {
        ready: outcome.ready(),
        reason: reason.into(),
        generation,
        keys_total: outcome.keys_total,
        keys_present: outcome.keys_present,
        keys_required_missing: outcome.keys_required_missing,
        keys_optional_missing: outcome.keys_optional_missing,
    }
}

/// Build a non-secret [`pb::ReloadRejection`] from a [`ReloadError`]. The reason
/// is the stable audit token; the message is the error's `Display` (which carries
/// only structural/config detail and the configured on-disk path, never key
/// material or a secret value).
fn reload_rejection(err: &ReloadError) -> pb::ReloadRejection {
    pb::ReloadRejection {
        reason: err.audit_reason().to_string(),
        message: err.to_string(),
    }
}

fn explain_response(
    subject: &str,
    op: Op,
    key: &str,
    explanation: &Explanation,
) -> pb::ExplainResponse {
    match &explanation.decision {
        Decision::Allow { via } => pb::ExplainResponse {
            subject: subject.to_string(),
            op: op.token().to_string(),
            key: key.to_string(),
            decision: "allow".to_string(),
            via: allow_via_token(via),
            reason: String::new(),
            matched_rule: explanation.matched.as_ref().map(matched_rule),
        },
        Decision::Deny { reason } => pb::ExplainResponse {
            subject: subject.to_string(),
            op: op.token().to_string(),
            key: key.to_string(),
            decision: "deny".to_string(),
            via: String::new(),
            reason: deny_reason_token(*reason),
            matched_rule: None,
        },
    }
}

fn validate_subject(subject: &str) -> Result<(), tonic::Status> {
    if subject.is_empty() {
        return Err(broker_status(
            Code::InvalidArgument,
            "INVALID_ARGUMENT",
            EXPLAIN_OP_TOKEN,
            "subject is required",
        ));
    }
    Ok(())
}

fn validate_revoke_request(
    trust_domain: &str,
    jti: &str,
    expires_at_unix: u64,
) -> Result<(), tonic::Status> {
    if trust_domain.is_empty() {
        return Err(broker_status(
            Code::InvalidArgument,
            "INVALID_ARGUMENT",
            REVOKE_OP_TOKEN,
            "trust_domain is required",
        ));
    }
    if jti.is_empty() {
        return Err(broker_status(
            Code::InvalidArgument,
            "INVALID_ARGUMENT",
            REVOKE_OP_TOKEN,
            "jti is required",
        ));
    }
    if expires_at_unix <= unix_now_secs() {
        return Err(broker_status(
            Code::InvalidArgument,
            "INVALID_ARGUMENT",
            REVOKE_OP_TOKEN,
            "expires_at_unix must be in the future",
        ));
    }
    Ok(())
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn matched_rule(rule: &MatchedRule) -> pb::MatchedRule {
    pb::MatchedRule {
        rule: rule.rule_id.clone(),
        via: allow_via_token(&rule.via),
        action: rule.action.clone(),
        target: rule.target.clone(),
        subject: rule.subject.clone(),
    }
}

fn allow_via_token(via: &AllowVia) -> String {
    match via {
        AllowVia::Subject(subject) => format!("subject:{subject}"),
        AllowVia::PublicClass => "public_class".to_string(),
    }
}

fn deny_reason_token(reason: DenyReason) -> String {
    match reason {
        DenyReason::UnknownKey => "unknown_key",
        DenyReason::NotWritable => "not_writable",
        DenyReason::NotPermitted => "not_permitted",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use basil_proto::KeyType;
    use basil_proto::broker::v1::admin_service_server::AdminService;
    use tonic::Request;

    use super::*;
    use crate::backend::{Backend, BackendError, KeyMetadata, KvValue, NewKey, PublicKey};
    use crate::catalog::load;
    use crate::event::BrokerEventKind;
    use crate::manager::BackendManager;
    use crate::state::BrokerState;

    /// How the mock backend answers an existence probe.
    #[derive(Clone, Copy)]
    enum Probe {
        /// Material exists: probes return `Ok`.
        Present,
        /// Material is absent, so probes return `KeyNotFound` (a backend 404).
        Absent,
        /// An unreachable backend makes probes return a transport error (fatal).
        Unreachable,
    }

    const SECRET_PROBE_ERROR: &str =
        "Authorization: Bearer vault-token-s.123 /run/credentials/basil/passphrase";

    /// A minimal probe-only backend: every existence probe answers per `probe` and
    /// bumps `probes` (so a test can count the per-key backend reads a readiness
    /// fan-out drives, and assert the TTL cache collapses a burst to one pass).
    struct ProbeBackend {
        probe: Probe,
        probes: Arc<AtomicUsize>,
    }

    struct RevocationBackend {
        stored: std::sync::Mutex<Option<Vec<u8>>>,
    }

    #[async_trait]
    impl Backend for ProbeBackend {
        fn kind(&self) -> &'static str {
            "mock"
        }

        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }

        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("public_key"))
        }

        async fn public_key_with_meta(&self, _key_id: &str) -> Result<PublicKey, BackendError> {
            Err(BackendError::Unsupported("public_key_with_meta"))
        }

        async fn key_metadata(&self, _key_id: &str) -> Result<KeyMetadata, BackendError> {
            self.probes.fetch_add(1, Ordering::Relaxed);
            match self.probe {
                Probe::Present => Ok(KeyMetadata {
                    key_type: Some(KeyType::Ed25519),
                    latest_version: 1,
                }),
                Probe::Absent => Err(BackendError::KeyNotFound("absent".into())),
                Probe::Unreachable => Err(BackendError::Transport(SECRET_PROBE_ERROR.into())),
            }
        }

        async fn kv_get(
            &self,
            _key_id: &str,
            _version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            self.probes.fetch_add(1, Ordering::Relaxed);
            match self.probe {
                Probe::Present => Ok(KvValue {
                    value: b"present".to_vec(),
                    version: 1,
                }),
                Probe::Absent => Err(BackendError::KeyNotFound("absent".into())),
                Probe::Unreachable => Err(BackendError::Transport(SECRET_PROBE_ERROR.into())),
            }
        }

        async fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("sign"))
        }

        async fn verify(
            &self,
            _key_id: &str,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, BackendError> {
            Err(BackendError::Unsupported("verify"))
        }
    }

    #[async_trait]
    impl Backend for RevocationBackend {
        fn kind(&self) -> &'static str {
            "mock"
        }

        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }

        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("public_key"))
        }

        async fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("sign"))
        }

        async fn verify(
            &self,
            _key_id: &str,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, BackendError> {
            Err(BackendError::Unsupported("verify"))
        }

        async fn kv_get(
            &self,
            _key_id: &str,
            _version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            let stored = self
                .stored
                .lock()
                .map_err(|_| BackendError::Backend("revocation store lock poisoned".into()))?;
            stored.as_ref().map_or_else(
                || Err(BackendError::KeyNotFound("revocations".into())),
                |value| {
                    Ok(KvValue {
                        value: value.clone(),
                        version: 1,
                    })
                },
            )
        }

        async fn kv_put(&self, _key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
            let mut stored = self
                .stored
                .lock()
                .map_err(|_| BackendError::Backend("revocation store lock poisoned".into()))?;
            *stored = Some(value.to_vec());
            drop(stored);
            Ok(1)
        }
    }

    // One key of each blocking/non-blocking shape so readiness counts are
    // unambiguous: req.signer (missing=error → blocks), warn.value (missing=warn
    // → does not block), gen.signer (missing=generate → does not block).
    const CATALOG: &str = r#"{
      "schemaVersion": 1,
      "backends": { "b": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
      "keys": {
        "req.signer": {
          "class": "asymmetric", "keyType": "ed25519", "backend": "b",
          "path": "req-signer", "writable": true, "missing": "error",
          "description": "a required signing key"
        },
        "warn.value": {
          "class": "value", "backend": "b", "engine": "kv2",
          "path": "secret/data/warn/value", "writable": true, "missing": "warn",
          "description": "a warn-on-missing value"
        },
        "gen.signer": {
          "class": "asymmetric", "keyType": "ed25519", "backend": "b",
          "path": "gen-signer", "writable": true, "missing": "generate",
          "description": "a generate-on-missing signing key"
        }
      }
    }"#;

    const EMPTY_POLICY: &str = r#"{
      "roles": {},
      "rules": [],
      "config": { "names": { "users": {}, "groups": {} }, "memberships": {} }
    }"#;

    /// Build an admin gRPC over the readiness fixture catalog. Returns the grpc and
    /// the shared probe counter (the number of per-key backend reads a readiness
    /// fan-out has driven so far).
    fn grpc_with_counter(probe: Probe) -> (BrokerGrpc, Arc<AtomicUsize>) {
        let (catalog, policy, config, _warnings) = load(CATALOG, EMPTY_POLICY).expect("fixture");
        let probes = Arc::new(AtomicUsize::new(0));
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert(
            "b".into(),
            Box::new(ProbeBackend {
                probe,
                probes: Arc::clone(&probes),
            }),
        );
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        let state = BrokerState::new(catalog, policy, config, manager, "vault");
        (BrokerGrpc::new(Arc::new(state)), probes)
    }

    fn grpc_with(probe: Probe) -> BrokerGrpc {
        grpc_with_counter(probe).0
    }

    /// Liveness is always-ok and does no backend I/O: even an unreachable backend
    /// returns `alive == true` (the process is up; readiness is the I/O probe).
    #[tokio::test]
    async fn health_is_always_alive_without_backend_io() {
        let grpc = grpc_with(Probe::Unreachable);
        let resp = grpc
            .health(Request::new(pb::HealthRequest {}))
            .await
            .expect("health never errs")
            .into_inner();
        assert!(resp.alive);
        assert_eq!(resp.version, env!("CARGO_PKG_VERSION"));
    }

    /// Every key present ⇒ ready, reason READY, present == total, no missing.
    #[tokio::test]
    async fn readiness_is_ready_when_all_keys_present() {
        let grpc = grpc_with(Probe::Present);
        let resp = grpc
            .readiness(Request::new(pb::ReadinessRequest {}))
            .await
            .expect("readiness never errs")
            .into_inner();
        assert!(resp.ready);
        assert_eq!(resp.reason(), pb::ReadinessReason::Ready);
        assert_eq!(resp.generation, 1);
        assert_eq!(resp.keys_total, 3);
        assert_eq!(resp.keys_present, 3);
        assert_eq!(resp.keys_required_missing, 0);
        assert_eq!(resp.keys_optional_missing, 0);
    }

    /// A `missing=error` key absent ⇒ NOT ready (its ops would fail closed). The
    /// warn/generate-absent keys are counted as optional and do NOT block.
    #[tokio::test]
    async fn readiness_not_ready_when_required_key_absent() {
        let grpc = grpc_with(Probe::Absent);
        let resp = grpc
            .readiness(Request::new(pb::ReadinessRequest {}))
            .await
            .expect("readiness never errs")
            .into_inner();
        assert!(!resp.ready);
        assert_eq!(resp.reason(), pb::ReadinessReason::RequiredKeyMissing);
        assert_eq!(resp.keys_total, 3);
        assert_eq!(resp.keys_present, 0);
        // Only req.signer is missing=error; warn.value + gen.signer are optional.
        assert_eq!(resp.keys_required_missing, 1);
        assert_eq!(resp.keys_optional_missing, 2);
    }

    /// An unreachable backend is fail-closed: NOT ready, reason `BACKEND_UNREACHABLE`,
    /// and the per-key counts stay zero (the probe yields no key detail). The
    /// generation id is still surfaced.
    #[tokio::test]
    async fn readiness_not_ready_when_backend_unreachable() {
        let grpc = grpc_with(Probe::Unreachable);
        let resp = grpc
            .readiness(Request::new(pb::ReadinessRequest {}))
            .await
            .expect("readiness never errs")
            .into_inner();
        assert!(!resp.ready);
        assert_eq!(resp.reason(), pb::ReadinessReason::BackendUnreachable);
        assert_eq!(resp.generation, 1);
        assert_eq!(resp.keys_total, 0);
        assert_eq!(resp.keys_present, 0);
        assert_eq!(resp.keys_required_missing, 0);
        assert_eq!(resp.keys_optional_missing, 0);
        let visible = format!("{resp:?}");
        assert!(!visible.contains("vault-token-s.123"));
        assert!(!visible.contains("/run/credentials/basil/passphrase"));
    }

    // ---- Readiness TTL cache (basil-8nwy) -----------------------------------

    /// Two `Readiness` calls within the TTL fan out to the backend **once**: the
    /// fixture has 3 catalog keys, so a single probe pass is 3 backend reads, and
    /// the cached second call adds none. The two responses are identical: a
    /// hostile peer hammering `basil ready` cannot amplify backend load per call.
    #[tokio::test]
    async fn readiness_caches_probe_within_ttl() {
        let (grpc, probes) = grpc_with_counter(Probe::Present);

        let first = grpc
            .readiness(Request::new(pb::ReadinessRequest {}))
            .await
            .expect("readiness never errs")
            .into_inner();
        // 3 catalog keys → 3 backend probes for the cold (uncached) pass.
        assert_eq!(probes.load(Ordering::Relaxed), 3);

        let second = grpc
            .readiness(Request::new(pb::ReadinessRequest {}))
            .await
            .expect("readiness never errs")
            .into_inner();
        // The second call is served from the cache: NO additional backend reads.
        assert_eq!(probes.load(Ordering::Relaxed), 3);
        // Same answer both times.
        assert_eq!(first, second);
        assert!(second.ready);
        assert_eq!(second.keys_present, 3);
    }

    /// A generation change (a hot reload) invalidates the cache regardless of the
    /// TTL: the next `Readiness` re-probes the backend and surfaces the new
    /// generation id: a label/key-set change can never be masked by a stale cache.
    #[tokio::test]
    async fn readiness_cache_is_invalidated_by_generation_change() {
        let (grpc, probes) = grpc_with_counter(Probe::Present);

        let first = grpc
            .readiness(Request::new(pb::ReadinessRequest {}))
            .await
            .expect("readiness never errs")
            .into_inner();
        assert_eq!(first.generation, 1);
        assert_eq!(probes.load(Ordering::Relaxed), 3);

        // Swap in a fresh generation (id 2), as a hot reload does. The cached
        // outcome was stamped for generation 1, so it must NOT be reused.
        let (catalog, policy, config, _w) = load(CATALOG, EMPTY_POLICY).expect("fixture");
        grpc.state
            .swap_generation(Arc::new(crate::state::Generation::new(
                2,
                Arc::new(catalog),
                policy,
                config,
            )));

        let second = grpc
            .readiness(Request::new(pb::ReadinessRequest {}))
            .await
            .expect("readiness never errs")
            .into_inner();
        // Re-probed: another full pass (3 more reads), and the new generation id.
        assert_eq!(probes.load(Ordering::Relaxed), 6);
        assert_eq!(second.generation, 2);
    }

    /// An expired cache entry (TTL elapsed) re-probes the backend. Exercised at the
    /// `BrokerState` seam to avoid sleeping the full TTL: a manually back-dated
    /// entry is treated as a miss, so the RPC re-fans-out.
    #[tokio::test]
    async fn readiness_reprobes_after_ttl_expiry() {
        let (grpc, probes) = grpc_with_counter(Probe::Present);

        grpc.readiness(Request::new(pb::ReadinessRequest {}))
            .await
            .expect("readiness never errs");
        assert_eq!(probes.load(Ordering::Relaxed), 3);

        // The fixture's READINESS_CACHE_TTL is short; wait it out so the cached
        // entry is past its deadline, then a second call must re-probe.
        tokio::time::sleep(
            crate::state::READINESS_CACHE_TTL + std::time::Duration::from_millis(50),
        )
        .await;

        grpc.readiness(Request::new(pb::ReadinessRequest {}))
            .await
            .expect("readiness never errs");
        assert_eq!(probes.load(Ordering::Relaxed), 6);
    }

    // ---- Admin reload RPC (basil-atq) ---------------------------------------

    use crate::peer::PeerInfo;
    use crate::reload::ReloadInputs;

    /// A reload-test catalog: one signing key whose routing shape stays fixed
    /// across `writable` flips (the reloadable dimension we edit).
    fn reload_catalog(writable: bool) -> String {
        format!(
            r#"{{
              "schemaVersion": 1,
              "backends": {{ "b": {{ "kind": "vault", "addr": "http://127.0.0.1:8200" }} }},
              "keys": {{
                "web.signer": {{
                  "class": "asymmetric", "keyType": "ed25519", "backend": "b",
                  "path": "signer", "writable": {writable}, "missing": "warn",
                  "description": "a signer"
                }}
              }}
            }}"#
        )
    }

    /// A reload-test catalog whose key routes to a DIFFERENT path: a restart-only
    /// change the reload engine must reject (previous generation keeps serving).
    fn reload_catalog_repathed() -> String {
        r#"{
          "schemaVersion": 1,
          "backends": { "b": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "web.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "b",
              "path": "signer-v2", "writable": true, "missing": "warn",
              "description": "a signer"
            }
          }
        }"#
        .to_string()
    }

    fn reload_spiffe_catalog(trust_domain: &str) -> String {
        format!(
            r#"{{
              "schemaVersion": 1,
              "backends": {{ "b": {{ "kind": "vault", "addr": "http://127.0.0.1:8200" }} }},
              "keys": {{
                "web.signer": {{
                  "class": "asymmetric", "keyType": "ed25519", "backend": "b",
                  "path": "signer", "writable": false, "missing": "warn",
                  "description": "a signer"
                }},
                "spiffe.jwt": {{
                  "class": "asymmetric", "keyType": "rsa-2048", "backend": "b",
                  "path": "jwt", "writable": false, "missing": "warn",
                  "labels": ["svid_kind=jwt", "trust_domain={trust_domain}"],
                  "description": "JWT-SVID issuer"
                }}
              }}
            }}"#
        )
    }

    /// Policy: uid 4242 may `reload`, uid 4243 may `explain`, uid 4244 may
    /// `revoke`, and uid 7 is a data-plane signer over web.signer with NO admin
    /// grants.
    const RELOAD_POLICY: &str = r#"{
      "schemaVersion": 2,
      "subjects": {
        "svc.admin": { "allOf": [ { "kind": "unix", "uid": 4242 } ] },
        "svc.explain": { "allOf": [ { "kind": "unix", "uid": 4243 } ] },
        "svc.revoke": { "allOf": [ { "kind": "unix", "uid": 4244 } ] },
        "svc.app": { "allOf": [ { "kind": "unix", "uid": 7 } ] }
      },
      "roles": { "signer": ["sign", "verify", "get_public_key"] },
      "rules": [
        { "id": "admin-reload", "subjects": ["svc.admin"],   "action": ["op:reload"], "target": ["broker.reload"] },
        { "id": "admin-explain", "subjects": ["svc.explain"], "action": ["op:explain"], "target": ["broker.explain"] },
        { "id": "admin-revoke", "subjects": ["svc.revoke"],   "action": ["op:revoke"], "target": ["broker.revoke"] },
        { "id": "data-signer",  "subjects": ["svc.app"],      "action": ["role:signer"], "target": ["web.signer"] }
      ],
      "config": {
        "names": { "users": { "4242": "svc-admin", "4243": "svc-explain", "4244": "svc-revoke", "7": "svc-app" }, "groups": {} },
        "memberships": { "4242": [4242], "4243": [4243], "4244": [4244], "7": [7] }
      }
    }"#;

    /// Build a [`BrokerGrpc`] whose state has reload inputs pointing at temp files,
    /// so the admin reload RPC re-reads the candidate from disk. Returns the grpc
    /// plus the on-disk inputs (so a test can rewrite the candidate).
    fn reload_grpc() -> (BrokerGrpc, ReloadInputs) {
        reload_grpc_with_catalog(&reload_catalog(false))
    }

    fn reload_grpc_with_catalog(catalog_json: &str) -> (BrokerGrpc, ReloadInputs) {
        let dir = std::env::temp_dir().join(format!(
            "basil-admin-reload-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let catalog_path = dir.join("catalog.json");
        let policy_path = dir.join("policy.json");
        std::fs::write(&catalog_path, catalog_json).expect("write catalog");
        std::fs::write(&policy_path, RELOAD_POLICY).expect("write policy");

        let (catalog, policy, config, _w) =
            load(catalog_json, RELOAD_POLICY).expect("reload fixture loads");
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert(
            "b".into(),
            Box::new(ProbeBackend {
                probe: Probe::Present,
                probes: Arc::new(AtomicUsize::new(0)),
            }),
        );
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        let inputs = ReloadInputs {
            catalog_path,
            policy_path,
        };
        let state = BrokerState::new(catalog, policy, config, manager, "vault")
            .with_reload_inputs(inputs.clone());
        (BrokerGrpc::new(Arc::new(state)), inputs)
    }

    async fn revoke_grpc() -> BrokerGrpc {
        let catalog_json = r#"{
          "schemaVersion": 1,
          "backends": { "b": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "revocations.jwt": {
              "class": "value", "backend": "b", "engine": "kv2",
              "path": "secret/data/revocations/jwt", "writable": true,
              "missing": "warn", "labels": ["revocation_store=jwt-svid"],
              "description": "JWT-SVID revocation store"
            }
          }
        }"#;
        let policy_json = r#"{
          "schemaVersion": 2,
          "subjects": {
            "svc.revoke": { "allOf": [ { "kind": "unix", "uid": 4244 } ] }
          },
          "roles": {},
          "rules": [
            { "id": "admin-revoke", "subjects": ["svc.revoke"], "action": ["op:revoke"], "target": ["broker.revoke"] }
          ],
          "config": {
            "names": { "users": { "4244": "svc-revoke" }, "groups": {} },
            "memberships": { "4244": [4244] }
          }
        }"#;
        let (catalog, policy, config, _warnings) =
            load(catalog_json, policy_json).expect("revocation fixture loads");
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert(
            "b".into(),
            Box::new(RevocationBackend {
                stored: std::sync::Mutex::new(None),
            }),
        );
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        let jwt_revocations = crate::revocation::JwtRevocationStore::load_from_manager(&manager)
            .await
            .expect("revocation store loads");
        let state = BrokerState::new(catalog, policy, config, manager, "vault")
            .with_jwt_revocations(jwt_revocations);
        BrokerGrpc::new(Arc::new(state))
    }

    fn reload_request(uid: u32, check: bool) -> Request<pb::ReloadRequest> {
        let mut req = Request::new(pb::ReloadRequest { check });
        req.extensions_mut().insert(PeerInfo {
            uid: Some(uid),
            ..PeerInfo::default()
        });
        req
    }

    fn explain_request(
        caller_uid: u32,
        subject: &str,
        op: &str,
        key: &str,
    ) -> Request<pb::ExplainRequest> {
        let mut req = Request::new(pb::ExplainRequest {
            subject: subject.to_string(),
            op: op.to_string(),
            key: key.to_string(),
        });
        req.extensions_mut().insert(PeerInfo {
            uid: Some(caller_uid),
            ..PeerInfo::default()
        });
        req
    }

    fn revoke_request(
        uid: u32,
        trust_domain: &str,
        jti: &str,
        expires_at_unix: u64,
    ) -> Request<pb::RevokeRequest> {
        let mut req = Request::new(pb::RevokeRequest {
            trust_domain: trust_domain.to_string(),
            jti: jti.to_string(),
            expires_at_unix,
        });
        req.extensions_mut().insert(PeerInfo {
            uid: Some(uid),
            ..PeerInfo::default()
        });
        req
    }

    fn assert_status_omits_admin_canaries(status: &tonic::Status) {
        let visible = format!("{} {:?}", status.message(), status.details());
        for canary in [
            "vault-token-s.123",
            "Authorization: Bearer secret",
            "/run/credentials/basil/passphrase",
        ] {
            assert!(
                !visible.contains(canary),
                "admin status leaked secret canary `{canary}` in `{visible}`"
            );
        }
    }

    /// An authorized caller (granted the dedicated `reload` op) reloads and gets
    /// the reload outcome; the serving generation bumps.
    #[tokio::test]
    async fn authorized_reload_applies_and_bumps_generation() {
        let (grpc, inputs) = reload_grpc();
        assert_eq!(grpc.state.active_generation_id(), 1);
        // Edit a reloadable dimension (flip writable).
        std::fs::write(&inputs.catalog_path, reload_catalog(true)).expect("rewrite");

        let resp = grpc
            .reload(reload_request(4242, false))
            .await
            .expect("authorized reload returns Ok")
            .into_inner();
        assert!(resp.applied);
        assert!(!resp.checked);
        assert_eq!(resp.previous_generation, 1);
        assert_eq!(resp.new_generation, 2);
        assert_eq!(resp.key_count, 1);
        assert!(resp.rejection.is_none());
        assert_eq!(grpc.state.active_generation_id(), 2);
    }

    /// A real, applied admin reload emits `BundleChanged` for affected `SPIFFE`
    /// trust domains. `Watch` delivery/filtering is covered separately; this test
    /// pins the production emitter path.
    #[tokio::test]
    async fn authorized_reload_publishes_bundle_changed_event() {
        let (grpc, inputs) = reload_grpc_with_catalog(&reload_spiffe_catalog("example.org"));
        let mut events = grpc.state.events().subscribe();
        std::fs::write(&inputs.catalog_path, reload_spiffe_catalog("other.org"))
            .expect("rewrite catalog");

        let resp = grpc
            .reload(reload_request(4242, false))
            .await
            .expect("authorized reload returns Ok")
            .into_inner();
        assert!(resp.applied);

        let mut domains = BTreeSet::new();
        for _ in 0..2 {
            let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
                .await
                .expect("bundle event arrives")
                .expect("event ok");
            let BrokerEventKind::BundleChanged { trust_domain } = event.kind else {
                panic!("BundleChanged event expected");
            };
            domains.insert(trust_domain);
        }

        assert_eq!(
            domains,
            BTreeSet::from(["example.org".to_string(), "other.org".to_string()])
        );
    }

    /// An UNAUTHORIZED caller is denied fail-closed (`PermissionDenied`) and the
    /// serving generation is unchanged. NO data-plane (sign) grant authorizes
    /// reload. The denial is audited (`record_decision` runs on the deny path).
    #[tokio::test]
    async fn unauthorized_caller_is_denied_and_nothing_reloads() {
        let (grpc, inputs) = reload_grpc();
        std::fs::write(&inputs.catalog_path, reload_catalog(true)).expect("rewrite");

        // uid 7 is a data-plane signer over web.signer, but has NO reload grant.
        let mut request = reload_request(7, false);
        request.metadata_mut().insert(
            "authorization",
            "Bearer vault-token-s.123".parse().expect("metadata"),
        );
        let status = grpc
            .reload(request)
            .await
            .expect_err("data-plane signer must be denied reload");
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_status_omits_admin_canaries(&status);
        // Previous generation still serving (nothing swapped).
        assert_eq!(grpc.state.active_generation_id(), 1);

        // A caller with no grant at all is likewise denied.
        let status = grpc
            .reload(reload_request(9999, false))
            .await
            .expect_err("ungranted caller denied");
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_status_omits_admin_canaries(&status);
        assert_eq!(grpc.state.active_generation_id(), 1);
    }

    /// A missing peer uid (no `SO_PEERCRED`) is rejected Unauthenticated, fail-closed.
    #[tokio::test]
    async fn missing_peer_uid_is_unauthenticated() {
        let (grpc, _inputs) = reload_grpc();
        let status = grpc
            .reload(Request::new(pb::ReloadRequest { check: false }))
            .await
            .expect_err("no peer uid");
        assert_eq!(status.code(), Code::Unauthenticated);
        assert_eq!(grpc.state.active_generation_id(), 1);
    }

    /// `--check` (dry-run) validates the candidate WITHOUT swapping: the serving
    /// generation id is unchanged and the response reports the would-be outcome.
    #[tokio::test]
    async fn check_validates_without_swapping() {
        let (grpc, inputs) = reload_grpc();
        std::fs::write(&inputs.catalog_path, reload_catalog(true)).expect("rewrite");

        let resp = grpc
            .reload(reload_request(4242, true))
            .await
            .expect("authorized dry-run returns Ok")
            .into_inner();
        assert!(resp.checked);
        assert!(!resp.applied);
        assert_eq!(resp.previous_generation, 1);
        assert_eq!(resp.new_generation, 2); // would-be
        assert!(resp.rejection.is_none());
        // The serving generation is UNCHANGED by the dry-run.
        assert_eq!(grpc.state.active_generation_id(), 1);
    }

    /// A rejected reload (a restart-only repath) leaves the previous generation
    /// serving: the RPC returns Ok with a rejection, not a wire error, and does NOT
    /// swap. Authorization still ran first (the rejection is a post-authz outcome).
    #[tokio::test]
    async fn rejected_candidate_keeps_previous_generation() {
        let (grpc, inputs) = reload_grpc();
        std::fs::write(&inputs.catalog_path, reload_catalog_repathed()).expect("rewrite");

        let resp = grpc
            .reload(reload_request(4242, false))
            .await
            .expect("rejection is Ok-with-rejection, not a wire error")
            .into_inner();
        assert!(!resp.applied);
        let rej = resp.rejection.expect("a rejection is present");
        assert_eq!(rej.reason, "routing_shape_changed");
        assert_eq!(resp.previous_generation, 1);
        assert_eq!(resp.new_generation, 1);
        // Previous generation still serving.
        assert_eq!(grpc.state.active_generation_id(), 1);
    }

    /// An authorized explain admin can ask the running broker why a subject would
    /// be allowed or denied against the currently serving generation.
    #[tokio::test]
    async fn authorized_explain_returns_rule_provenance() {
        let (grpc, _inputs) = reload_grpc();
        let resp = grpc
            .explain(explain_request(4243, "svc.app", "sign", "web.signer"))
            .await
            .expect("authorized explain")
            .into_inner();

        assert_eq!(resp.subject, "svc.app");
        assert_eq!(resp.op, "sign");
        assert_eq!(resp.key, "web.signer");
        assert_eq!(resp.decision, "allow");
        assert_eq!(resp.via, "subject:svc.app");
        assert_eq!(resp.reason, "");
        let matched = resp.matched_rule.expect("matched rule");
        assert_eq!(matched.rule, "data-signer");
        assert_eq!(matched.via, "subject:svc.app");
        assert_eq!(matched.action, "role:signer");
        assert_eq!(matched.target, "web.signer");
    }

    /// A data-plane grant does not authorize live explain.
    #[tokio::test]
    async fn unauthorized_explain_is_denied() {
        let (grpc, _inputs) = reload_grpc();
        let status = grpc
            .explain(explain_request(7, "svc.app", "sign", "web.signer"))
            .await
            .expect_err("data-plane signer denied explain");
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_status_omits_admin_canaries(&status);

        let status = grpc
            .explain(explain_request(4242, "svc.app", "sign", "web.signer"))
            .await
            .expect_err("reload admin denied explain");
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_status_omits_admin_canaries(&status);
    }

    #[test]
    fn validate_revoke_request_rejects_missing_and_expired_inputs() {
        let future = unix_now_secs().saturating_add(300);
        assert!(validate_revoke_request("example.org", "jti-1", future).is_ok());
        assert!(validate_revoke_request("", "jti-1", future).is_err());
        assert!(validate_revoke_request("example.org", "", future).is_err());
        assert!(validate_revoke_request("example.org", "jti-1", 1).is_err());
    }

    #[tokio::test]
    async fn authorized_revoke_requires_persistent_store() {
        let (grpc, _inputs) = reload_grpc();
        let future = unix_now_secs().saturating_add(300);
        let status = grpc
            .revoke(revoke_request(4244, "example.org", "jti-1", future))
            .await
            .expect_err("no store configured");
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn unauthorized_revoke_is_denied() {
        let (grpc, _inputs) = reload_grpc();
        let future = unix_now_secs().saturating_add(300);
        let status = grpc
            .revoke(revoke_request(7, "example.org", "jti-1", future))
            .await
            .expect_err("data-plane grant must not imply revoke");
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_status_omits_admin_canaries(&status);

        let status = grpc
            .revoke(revoke_request(4242, "example.org", "jti-1", future))
            .await
            .expect_err("reload admin must not imply revoke");
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_status_omits_admin_canaries(&status);
    }

    #[tokio::test]
    async fn authorized_revoke_persists_and_publishes_event() {
        use futures::StreamExt as _;

        let grpc = revoke_grpc().await;
        let mut watch = grpc
            .watch(revoke_request(4244, "", "", 1).map(|_| pb::WatchRequest {
                kinds: vec![i32::from(pb::EventKind::Revoked)],
            }))
            .await
            .expect("watch opens")
            .into_inner();
        let future = unix_now_secs().saturating_add(300);
        let resp = grpc
            .revoke(revoke_request(4244, "example.org", "jti-1", future))
            .await
            .expect("authorized revoke")
            .into_inner();
        assert_eq!(resp.trust_domain, "example.org");
        assert_eq!(resp.jti, "jti-1");
        assert_eq!(resp.expires_at_unix, future);
        assert!(resp.persisted);
        assert!(
            grpc.state
                .jwt_revocations()
                .is_revoked("example.org", "jti-1")
        );

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), watch.next())
            .await
            .expect("event arrives")
            .expect("stream item")
            .expect("event ok");
        assert_eq!(event.kind, i32::from(pb::EventKind::Revoked));
        let Some(pb::event::Detail::Revoked(revoked)) = event.detail else {
            panic!("revoked detail expected");
        };
        assert_eq!(revoked.trust_domain, "example.org");
        assert_eq!(revoked.id, "jti-1");
    }

    #[tokio::test]
    async fn explain_rejects_unknown_op_token() {
        let (grpc, _inputs) = reload_grpc();
        let status = grpc
            .explain(explain_request(4243, "svc.app", "nope", "web.signer"))
            .await
            .expect_err("unknown op");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn explain_rejects_missing_subject() {
        let (grpc, _inputs) = reload_grpc();
        let status = grpc
            .explain(explain_request(4243, " ", "sign", "web.signer"))
            .await
            .expect_err("blank subject");
        assert_eq!(status.code(), Code::InvalidArgument);
    }
}
