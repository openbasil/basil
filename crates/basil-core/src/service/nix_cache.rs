// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Purpose-specific Nix binary-cache identity and signing service.

use std::sync::Arc;

use basil_proto::broker::v1 as pb;
use basil_proto::broker::v1::nix_cache_service_server::NixCacheService;
use tonic::{Code, Request, Response, Status};

use crate::catalog::policy::Op;
use crate::catalog::{NixCacheIdentity, NixCacheState};
use crate::core::nix_cache_audit::{NixCacheAuditEvent, NixCacheAuditOp, NixCacheAuditOutcome};
use crate::core::nix_cache_fingerprint::PathInfoV1;
use crate::grpc::BrokerGrpc;
use crate::manager::{ManagerError, NixCacheEnrollmentDisposition};
use crate::service::shared::{invalid_request, manager_status};
use crate::state::Generation;
use crate::transport::broker_status;
use crate::transport::{authorize_in_generation_detailed, peer_from_request};

const PROFILE: &str = "PATH_INFO_V1";

#[tonic::async_trait]
#[allow(clippy::too_many_lines)]
impl NixCacheService for BrokerGrpc {
    async fn describe_nix_cache_key(
        &self,
        request: Request<pb::DescribeNixCacheKeyRequest>,
    ) -> Result<Response<pb::DescribeNixCacheKeyResponse>, Status> {
        let generation = pin_generation(self);
        let input = request.get_ref();
        let batch_id = correlation_id(&input.batch_id, "describe_nix_cache_key", "batch_id")?;
        let request_id = correlation_id(&input.request_id, "describe_nix_cache_key", "request_id")?;
        let identity = nix_identity(&generation, &input.key_id);
        let actor = authorize_nix(
            self,
            &generation,
            &request,
            Op::SignNixCacheFingerprint,
            NixCacheAuditOp::Describe,
            &input.key_id,
            identity.as_ref(),
            batch_id,
            request_id,
        )?;
        let input = request.into_inner();
        let Some(identity) = identity else {
            self.audit_nix(
                &generation,
                NixCacheAuditOp::Describe,
                &actor,
                &input.key_id,
                None,
                batch_id,
                request_id,
                None,
                NixCacheAuditOutcome::Deny,
                "identity_not_configured",
            );
            return Err(invalid_request(
                "describe_nix_cache_key",
                "key has no Nix cache identity",
            ));
        };
        if identity.state != NixCacheState::Enrolled {
            self.audit_nix(
                &generation,
                NixCacheAuditOp::Describe,
                &actor,
                &input.key_id,
                Some(&identity),
                batch_id,
                request_id,
                None,
                NixCacheAuditOutcome::Deny,
                "identity_not_enrolled",
            );
            return Err(broker_status(
                Code::FailedPrecondition,
                "NIX_CACHE_KEY_PENDING",
                "describe_nix_cache_key",
                "Nix cache key is pending enrollment",
            ));
        }

        match self
            .state
            .manager()
            .describe_nix_cache_key(&input.key_id, identity.clone())
            .await
        {
            Ok(description) => {
                self.audit_nix(
                    &generation,
                    NixCacheAuditOp::Describe,
                    &actor,
                    &input.key_id,
                    Some(&identity),
                    batch_id,
                    request_id,
                    None,
                    NixCacheAuditOutcome::Success,
                    "ok",
                );
                Ok(Response::new(pb::DescribeNixCacheKeyResponse {
                    key_name: description.key_name,
                    public_key: description.public_key.as_bytes().to_vec(),
                    backend_version: description.backend_version,
                    batch_id: input.batch_id,
                    request_id: input.request_id,
                }))
            }
            Err(error) => {
                self.audit_nix(
                    &generation,
                    NixCacheAuditOp::Describe,
                    &actor,
                    &input.key_id,
                    Some(&identity),
                    batch_id,
                    request_id,
                    None,
                    NixCacheAuditOutcome::Failure,
                    manager_audit_reason(&error),
                );
                Err(manager_status("describe_nix_cache_key", &error))
            }
        }
    }

    async fn enroll_nix_cache_key(
        &self,
        request: Request<pb::EnrollNixCacheKeyRequest>,
    ) -> Result<Response<pb::EnrollNixCacheKeyResponse>, Status> {
        let generation = pin_generation(self);
        let input = request.get_ref();
        let batch_id = correlation_id(&input.batch_id, "enroll_nix_cache_key", "batch_id")?;
        let request_id = correlation_id(&input.request_id, "enroll_nix_cache_key", "request_id")?;
        let identity = nix_identity(&generation, &input.key_id);
        let actor = authorize_nix(
            self,
            &generation,
            &request,
            Op::EnrollNixCacheKey,
            NixCacheAuditOp::Enroll,
            &input.key_id,
            identity.as_ref(),
            batch_id,
            request_id,
        )?;
        let input = request.into_inner();
        let Some(identity) = identity else {
            self.audit_nix(
                &generation,
                NixCacheAuditOp::Enroll,
                &actor,
                &input.key_id,
                None,
                batch_id,
                request_id,
                None,
                NixCacheAuditOutcome::Deny,
                "identity_not_configured",
            );
            return Err(invalid_request(
                "enroll_nix_cache_key",
                "key has no Nix cache identity",
            ));
        };
        match self
            .state
            .manager()
            .enroll_nix_cache_key(&input.key_id, identity.clone())
            .await
        {
            Ok(enrollment) => {
                self.audit_nix(
                    &generation,
                    NixCacheAuditOp::Enroll,
                    &actor,
                    &input.key_id,
                    Some(&identity),
                    batch_id,
                    request_id,
                    None,
                    NixCacheAuditOutcome::Success,
                    "ok",
                );
                let disposition = match enrollment.disposition {
                    NixCacheEnrollmentDisposition::Created => {
                        pb::NixCacheEnrollmentDisposition::Created
                    }
                    NixCacheEnrollmentDisposition::Existing => {
                        pb::NixCacheEnrollmentDisposition::Existing
                    }
                };
                Ok(Response::new(pb::EnrollNixCacheKeyResponse {
                    key_name: enrollment.key_name,
                    public_key: enrollment.public_key.as_bytes().to_vec(),
                    backend_version: enrollment.backend_version,
                    disposition: disposition.into(),
                    batch_id: input.batch_id,
                    request_id: input.request_id,
                }))
            }
            Err(error) => {
                self.audit_nix(
                    &generation,
                    NixCacheAuditOp::Enroll,
                    &actor,
                    &input.key_id,
                    Some(&identity),
                    batch_id,
                    request_id,
                    None,
                    NixCacheAuditOutcome::Failure,
                    manager_audit_reason(&error),
                );
                Err(manager_status("enroll_nix_cache_key", &error))
            }
        }
    }

    async fn sign_nix_cache_fingerprint(
        &self,
        request: Request<pb::SignNixCacheFingerprintRequest>,
    ) -> Result<Response<pb::SignNixCacheFingerprintResponse>, Status> {
        let generation = pin_generation(self);
        let input = request.get_ref();
        let batch_id = correlation_id(&input.batch_id, "sign_nix_cache_fingerprint", "batch_id")?;
        let request_id = correlation_id(
            &input.request_id,
            "sign_nix_cache_fingerprint",
            "request_id",
        )?;
        let identity = nix_identity(&generation, &input.key_id);
        let actor = authorize_nix(
            self,
            &generation,
            &request,
            Op::SignNixCacheFingerprint,
            NixCacheAuditOp::Sign,
            &input.key_id,
            identity.as_ref(),
            batch_id,
            request_id,
        )?;
        let input = request.into_inner();
        let Some(identity) = identity else {
            self.audit_nix(
                &generation,
                NixCacheAuditOp::Sign,
                &actor,
                &input.key_id,
                None,
                batch_id,
                request_id,
                None,
                NixCacheAuditOutcome::Deny,
                "identity_not_configured",
            );
            return Err(invalid_request(
                "sign_nix_cache_fingerprint",
                "key has no Nix cache identity",
            ));
        };
        if identity.state != NixCacheState::Enrolled {
            self.audit_nix(
                &generation,
                NixCacheAuditOp::Sign,
                &actor,
                &input.key_id,
                Some(&identity),
                batch_id,
                request_id,
                None,
                NixCacheAuditOutcome::Deny,
                "identity_not_enrolled",
            );
            return Err(invalid_request(
                "sign_nix_cache_fingerprint",
                "Nix cache identity is not enrolled",
            ));
        }
        if input.profile != PROFILE {
            self.audit_nix(
                &generation,
                NixCacheAuditOp::Sign,
                &actor,
                &input.key_id,
                Some(&identity),
                batch_id,
                request_id,
                None,
                NixCacheAuditOutcome::Failure,
                "profile_invalid",
            );
            return Err(invalid_request(
                "sign_nix_cache_fingerprint",
                "profile must be exactly PATH_INFO_V1",
            ));
        }
        let fingerprint = PathInfoV1::parse(&input.fingerprint).map_err(|_| {
            self.audit_nix(
                &generation,
                NixCacheAuditOp::Sign,
                &actor,
                &input.key_id,
                Some(&identity),
                batch_id,
                request_id,
                None,
                NixCacheAuditOutcome::Failure,
                "fingerprint_invalid",
            );
            invalid_request(
                "sign_nix_cache_fingerprint",
                "fingerprint is not canonical PATH_INFO_V1",
            )
        })?;
        let fingerprint_digest = fingerprint.sha256_hex();

        match self
            .state
            .manager()
            .sign_nix_cache_fingerprint(&input.key_id, identity.clone(), fingerprint.as_bytes())
            .await
        {
            Ok(signed) => {
                self.audit_nix(
                    &generation,
                    NixCacheAuditOp::Sign,
                    &actor,
                    &input.key_id,
                    Some(&identity),
                    batch_id,
                    request_id,
                    Some(&fingerprint_digest),
                    NixCacheAuditOutcome::Success,
                    "ok",
                );
                Ok(Response::new(pb::SignNixCacheFingerprintResponse {
                    key_name: signed.identity.key_name,
                    public_key: signed.identity.public_key.as_bytes().to_vec(),
                    backend_version: signed.identity.backend_version,
                    signature: signed.signature.to_vec(),
                    batch_id: input.batch_id,
                    request_id: input.request_id,
                }))
            }
            Err(error) => {
                self.audit_nix(
                    &generation,
                    NixCacheAuditOp::Sign,
                    &actor,
                    &input.key_id,
                    Some(&identity),
                    batch_id,
                    request_id,
                    Some(&fingerprint_digest),
                    NixCacheAuditOutcome::Failure,
                    manager_audit_reason(&error),
                );
                Err(manager_status("sign_nix_cache_fingerprint", &error))
            }
        }
    }
}

fn pin_generation(service: &BrokerGrpc) -> Arc<Generation> {
    let generation = service.state.load_generation();
    Arc::clone(&generation)
}

fn nix_identity(generation: &Generation, key_id: &str) -> Option<NixCacheIdentity> {
    generation
        .catalog()
        .keys
        .get(key_id)
        .and_then(|entry| entry.nix_cache.clone())
}

fn correlation_id(bytes: &[u8], op: &'static str, field: &'static str) -> Result<[u8; 16], Status> {
    let id: [u8; 16] = bytes
        .try_into()
        .map_err(|_| invalid_request(op, format!("{field} must be exactly 16 bytes")))?;
    if id == [0; 16] {
        return Err(invalid_request(op, format!("{field} must be nonzero")));
    }
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
fn authorize_nix<T>(
    service: &BrokerGrpc,
    generation: &Generation,
    request: &Request<T>,
    policy_op: Op,
    audit_op: NixCacheAuditOp,
    key_id: &str,
    identity: Option<&NixCacheIdentity>,
    batch_id: [u8; 16],
    request_id: [u8; 16],
) -> Result<crate::actor::AuthenticatedActor, Status> {
    match authorize_in_generation_detailed(&service.state, generation, request, policy_op, key_id) {
        Ok(actor) => Ok(actor),
        Err(failure) => {
            if let Some(actor) = failure.actor() {
                service.audit_nix(
                    generation,
                    audit_op,
                    actor,
                    key_id,
                    identity,
                    batch_id,
                    request_id,
                    None,
                    NixCacheAuditOutcome::Deny,
                    "authorization_denied",
                );
            } else {
                let peer = peer_from_request(request);
                service.audit_nix_fields(
                    generation,
                    audit_op,
                    None,
                    peer.pid,
                    peer.uid,
                    key_id,
                    identity,
                    batch_id,
                    request_id,
                    None,
                    NixCacheAuditOutcome::Deny,
                    "subject_unresolved",
                );
            }
            Err(failure.into_status())
        }
    }
}

impl BrokerGrpc {
    #[allow(clippy::too_many_arguments)]
    fn audit_nix(
        &self,
        generation: &Generation,
        op: NixCacheAuditOp,
        actor: &crate::actor::AuthenticatedActor,
        key_id: &str,
        identity: Option<&NixCacheIdentity>,
        batch_id: [u8; 16],
        request_id: [u8; 16],
        fingerprint_sha256: Option<&str>,
        outcome: NixCacheAuditOutcome,
        reason: &'static str,
    ) {
        self.audit_nix_fields(
            generation,
            op,
            Some(&actor.subject),
            actor.presenter.pid,
            actor.presenter.uid,
            key_id,
            identity,
            batch_id,
            request_id,
            fingerprint_sha256,
            outcome,
            reason,
        );
    }

    #[allow(clippy::similar_names, clippy::too_many_arguments)]
    fn audit_nix_fields(
        &self,
        generation: &Generation,
        op: NixCacheAuditOp,
        policy_subject: Option<&str>,
        presenter_pid: Option<u32>,
        presenter_uid: Option<u32>,
        key_id: &str,
        identity: Option<&NixCacheIdentity>,
        batch_id: [u8; 16],
        request_id: [u8; 16],
        fingerprint_sha256: Option<&str>,
        outcome: NixCacheAuditOutcome,
        reason: &'static str,
    ) {
        self.state.record_nix_cache_event(&NixCacheAuditEvent {
            op,
            policy_subject,
            presenter_pid,
            presenter_uid,
            generation: generation.id(),
            key_id,
            key_name: identity.map(|value| value.key_name.as_str()),
            backend_version: identity.map(|value| value.backend_version),
            batch_id,
            request_id,
            fingerprint_sha256,
            outcome,
            reason,
        });
    }
}

const fn manager_audit_reason(error: &ManagerError) -> &'static str {
    match error {
        ManagerError::NixCacheEnrollment { .. } => "identity_or_posture_mismatch",
        ManagerError::Backend(_) => "backend_failure",
        ManagerError::UnknownKey(_) => "key_not_routable",
        _ => "manager_failure",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use basil_proto::KeyType;
    use basil_proto::broker::v1::nix_cache_service_server::NixCacheService as _;
    use basil_proto::broker::v1::{BrokerErrorInfo, SignNixCacheFingerprintRequest};
    use basil_proto::google::rpc::Status as RpcStatus;
    use prost::Message as _;
    use tonic::{Code, Request};
    use zeroize::Zeroizing;

    use super::*;
    use crate::audit::AuditLog;
    use crate::backend::{
        Backend, BackendError, NewKey, NixCacheBackendSignature, NixCacheKeyPosture,
    };
    use crate::catalog::load;
    use crate::manager::BackendManager;
    use crate::peer::PeerInfo;
    use crate::state::BrokerState;
    use crate::transport::connection::ListenerConnectInfo;
    use crate::transport::grpc_server::ListenerType;

    const FINGERPRINT: &str = concat!(
        "1;/nix/store/00000000000000000000000000000000-package;",
        "sha256:0000000000000000000000000000000000000000000000000000;1;"
    );

    struct SigningBackend {
        seed: Zeroizing<[u8; 32]>,
        block_sign: AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        paths: Mutex<Vec<String>>,
        missing: AtomicBool,
        create_calls: AtomicUsize,
        sign_calls: AtomicUsize,
    }

    impl SigningBackend {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seed: Zeroizing::new([9u8; 32]),
                block_sign: AtomicBool::new(false),
                entered: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                paths: Mutex::new(Vec::new()),
                missing: AtomicBool::new(false),
                create_calls: AtomicUsize::new(0),
                sign_calls: AtomicUsize::new(0),
            })
        }

        fn posture(&self) -> NixCacheKeyPosture {
            NixCacheKeyPosture {
                public_key: crate::ed25519_sign::public_from_seed(&self.seed),
                key_type: KeyType::Ed25519,
                latest_version: 1,
                min_decryption_version: 1,
                derived: false,
                exportable: false,
                allow_plaintext_backup: false,
                deletion_allowed: false,
                auto_rotation_disabled: true,
            }
        }
    }

    struct SigningHandle(Arc<SigningBackend>);

    #[async_trait]
    impl Backend for SigningHandle {
        fn kind(&self) -> &'static str {
            "nix-service-test"
        }

        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }

        async fn nix_cache_key_posture(
            &self,
            key_id: &str,
        ) -> Result<NixCacheKeyPosture, BackendError> {
            self.0
                .paths
                .lock()
                .expect("path lock")
                .push(key_id.to_string());
            if self.0.missing.load(Ordering::SeqCst) {
                Err(BackendError::KeyNotFound(key_id.to_string()))
            } else {
                Ok(self.0.posture())
            }
        }

        async fn create_nix_cache_key(&self, _key_id: &str) -> Result<(), BackendError> {
            self.0.create_calls.fetch_add(1, Ordering::SeqCst);
            self.0.missing.store(false, Ordering::SeqCst);
            Ok(())
        }

        async fn sign_nix_cache_fingerprint(
            &self,
            _key_id: &str,
            fingerprint: &[u8],
        ) -> Result<NixCacheBackendSignature, BackendError> {
            self.0.sign_calls.fetch_add(1, Ordering::SeqCst);
            if self.0.block_sign.load(Ordering::SeqCst) {
                self.0.entered.notify_one();
                self.0.release.notified().await;
            }
            Ok(NixCacheBackendSignature {
                backend_version: 1,
                signature: crate::ed25519_sign::sign(&self.0.seed, fingerprint),
            })
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
    }

    fn documents(state: NixCacheState, allow: bool, backend: &SigningBackend) -> (String, String) {
        let mut identity = serde_json::json!({
            "keyName": "cache.example-1",
            "state": if state == NixCacheState::Enrolled { "enrolled" } else { "pending" },
            "backendVersion": 1,
        });
        if state == NixCacheState::Enrolled {
            identity["publicKey"] =
                serde_json::json!(STANDARD.encode(backend.posture().public_key));
        }
        let catalog = serde_json::json!({
            "schema": "catalog",
            "backends": { "primary": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
            "keys": {
                "cache.signer": {
                    "class": "asymmetric", "keyType": "ed25519", "backend": "primary",
                    "engine": "transit", "path": "cache-key", "writable": true,
                    "nixCache": identity, "description": "Nix cache signer"
                }
            }
        })
        .to_string();
        let actions = if allow {
            serde_json::json!(["op:enroll_nix_cache_key", "op:sign_nix_cache_fingerprint"])
        } else {
            serde_json::json!(["*"])
        };
        let policy = serde_json::json!({
            "schema": "policy",
            "subjects": {
                "svc.builder": {
                    "domain": "host-process",
                    "match": { "all": [{ "process.uid": 1000 }] }
                }
            },
            "roles": {},
            "rules": [{
                "id": "builder-nix", "subjects": ["svc.builder"],
                "action": actions, "target": ["cache.signer"]
            }],
            "config": { "memberships": { "1000": [1000] } }
        })
        .to_string();
        (catalog, policy)
    }

    fn fixture(
        state: NixCacheState,
        audit: Option<Arc<AuditLog>>,
    ) -> (BrokerGrpc, Arc<BrokerState>, Arc<SigningBackend>) {
        let backend = SigningBackend::new();
        let (catalog_json, policy_json) = documents(state, true, &backend);
        let (catalog, policy, config, warnings) =
            load(&catalog_json, &policy_json).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert(
            "primary".into(),
            Box::new(SigningHandle(Arc::clone(&backend))),
        );
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager");
        let mut state = BrokerState::new(catalog, policy, config, manager, "test");
        if let Some(audit) = audit {
            state = state.with_audit_log(audit);
        }
        let state = Arc::new(state);
        (BrokerGrpc::new(Arc::clone(&state)), state, backend)
    }

    fn denied_fixture(state: NixCacheState) -> (BrokerGrpc, Arc<SigningBackend>) {
        let backend = SigningBackend::new();
        let (catalog_json, policy_json) = documents(state, false, &backend);
        let (catalog, policy, config, warnings) =
            load(&catalog_json, &policy_json).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert(
            "primary".into(),
            Box::new(SigningHandle(Arc::clone(&backend))),
        );
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager");
        let state = Arc::new(BrokerState::new(catalog, policy, config, manager, "test"));
        (BrokerGrpc::new(state), backend)
    }

    fn sign_request() -> Request<SignNixCacheFingerprintRequest> {
        let mut request = Request::new(SignNixCacheFingerprintRequest {
            key_id: "cache.signer".into(),
            profile: PROFILE.into(),
            fingerprint: FINGERPRINT.as_bytes().to_vec(),
            batch_id: vec![0xabu8; 16],
            request_id: vec![0xcdu8; 16],
        });
        insert_peer(&mut request);
        request
    }

    fn describe_request() -> Request<pb::DescribeNixCacheKeyRequest> {
        let mut request = Request::new(pb::DescribeNixCacheKeyRequest {
            key_id: "cache.signer".into(),
            batch_id: vec![0xabu8; 16],
            request_id: vec![0xcdu8; 16],
        });
        insert_peer(&mut request);
        request
    }

    fn enroll_request() -> Request<pb::EnrollNixCacheKeyRequest> {
        let mut request = Request::new(pb::EnrollNixCacheKeyRequest {
            key_id: "cache.signer".into(),
            batch_id: vec![0xabu8; 16],
            request_id: vec![0xcdu8; 16],
        });
        insert_peer(&mut request);
        request
    }

    fn insert_peer<T>(request: &mut Request<T>) {
        request
            .extensions_mut()
            .insert(ListenerConnectInfo::for_test(
                "host",
                ListenerType::Host,
                PeerInfo {
                    pid: Some(4321),
                    uid: Some(1000),
                    gid: Some(1000),
                    ..PeerInfo::default()
                },
            ));
    }

    #[tokio::test]
    async fn sign_echoes_exact_ids_and_locally_verified_identity() {
        let (service, _, backend) = fixture(NixCacheState::Enrolled, None);
        let response = service
            .sign_nix_cache_fingerprint(sign_request())
            .await
            .expect("sign succeeds")
            .into_inner();
        assert_eq!(response.batch_id, vec![0xabu8; 16]);
        assert_eq!(response.request_id, vec![0xcdu8; 16]);
        assert_eq!(response.backend_version, 1);
        assert_eq!(response.public_key, backend.posture().public_key);
        assert!(
            crate::ed25519_sign::verify(
                &backend.posture().public_key,
                FINGERPRINT.as_bytes(),
                &response.signature,
            )
            .expect("well-formed signature")
        );
    }

    #[tokio::test]
    async fn describe_enrolled_echoes_identity_and_exact_ids() {
        let (service, _, backend) = fixture(NixCacheState::Enrolled, None);
        let response = service
            .describe_nix_cache_key(describe_request())
            .await
            .expect("describe succeeds")
            .into_inner();
        assert_eq!(response.key_name, "cache.example-1");
        assert_eq!(response.public_key, backend.posture().public_key);
        assert_eq!(response.backend_version, 1);
        assert_eq!(response.batch_id, vec![0xabu8; 16]);
        assert_eq!(response.request_id, vec![0xcdu8; 16]);
    }

    #[tokio::test]
    async fn enroll_maps_pending_created_and_enrolled_compare_only_existing() {
        let (pending_service, _, pending_backend) = fixture(NixCacheState::Pending, None);
        pending_backend.missing.store(true, Ordering::SeqCst);
        let created = pending_service
            .enroll_nix_cache_key(enroll_request())
            .await
            .expect("pending enrollment creates")
            .into_inner();
        assert_eq!(
            created.disposition,
            i32::from(pb::NixCacheEnrollmentDisposition::Created)
        );
        assert_eq!(created.batch_id, vec![0xabu8; 16]);
        assert_eq!(created.request_id, vec![0xcdu8; 16]);
        assert_eq!(pending_backend.create_calls.load(Ordering::SeqCst), 1);

        let (enrolled_service, _, enrolled_backend) = fixture(NixCacheState::Enrolled, None);
        let existing = enrolled_service
            .enroll_nix_cache_key(enroll_request())
            .await
            .expect("enrolled identity is compare-only")
            .into_inner();
        assert_eq!(
            existing.disposition,
            i32::from(pb::NixCacheEnrollmentDisposition::Existing)
        );
        assert_eq!(existing.batch_id, vec![0xabu8; 16]);
        assert_eq!(existing.request_id, vec![0xcdu8; 16]);
        assert_eq!(enrolled_backend.create_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn wildcard_policy_denies_dedicated_ops_before_backend_access() {
        let (service, backend) = denied_fixture(NixCacheState::Enrolled);
        let sign_status = service
            .sign_nix_cache_fingerprint(sign_request())
            .await
            .expect_err("wildcard must not grant Nix sign");
        assert_eq!(sign_status.code(), Code::PermissionDenied);
        let enroll_status = service
            .enroll_nix_cache_key(enroll_request())
            .await
            .expect_err("wildcard must not grant Nix enrollment");
        assert_eq!(enroll_status.code(), Code::PermissionDenied);
        assert!(backend.paths.lock().expect("path lock").is_empty());
        assert_eq!(backend.sign_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.create_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn malformed_profile_and_fingerprint_never_reach_backend() {
        let (service, _, backend) = fixture(NixCacheState::Enrolled, None);
        let mut bad_profile = sign_request();
        bad_profile.get_mut().profile = "path_info_v1".into();
        assert_eq!(
            service
                .sign_nix_cache_fingerprint(bad_profile)
                .await
                .expect_err("profile is exact")
                .code(),
            Code::InvalidArgument
        );

        let mut bad_fingerprint = sign_request();
        bad_fingerprint.get_mut().fingerprint = b"not-a-fingerprint".to_vec();
        assert_eq!(
            service
                .sign_nix_cache_fingerprint(bad_fingerprint)
                .await
                .expect_err("fingerprint is canonical")
                .code(),
            Code::InvalidArgument
        );
        assert!(backend.paths.lock().expect("path lock").is_empty());
        assert_eq!(backend.sign_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn describe_pending_returns_stable_pending_reason() {
        let (service, _, _) = fixture(NixCacheState::Pending, None);
        let sign = sign_request().into_inner();
        let mut request = Request::new(pb::DescribeNixCacheKeyRequest {
            key_id: sign.key_id,
            batch_id: sign.batch_id,
            request_id: sign.request_id,
        });
        insert_peer(&mut request);
        let status = service
            .describe_nix_cache_key(request)
            .await
            .expect_err("pending describe fails");
        assert_eq!(status.code(), Code::FailedPrecondition);
        let rpc = RpcStatus::decode(status.details()).expect("status details");
        let detail = rpc.details.first().expect("error info detail");
        let info = BrokerErrorInfo::decode(detail.value.as_slice()).expect("error info");
        assert_eq!(info.reason, "NIX_CACHE_KEY_PENDING");
    }

    #[tokio::test]
    async fn sign_keeps_one_generation_pinned_across_backend_await() {
        let (service, state, backend) = fixture(NixCacheState::Enrolled, None);
        backend.block_sign.store(true, Ordering::SeqCst);
        let task =
            tokio::spawn(async move { service.sign_nix_cache_fingerprint(sign_request()).await });
        backend.entered.notified().await;

        let (catalog_json, policy_json) = documents(NixCacheState::Enrolled, false, &backend);
        let (catalog, policy, config, warnings) =
            load(&catalog_json, &policy_json).expect("deny generation loads");
        assert!(warnings.is_empty());
        state.swap_generation(Arc::new(Generation::new(2, catalog, policy, config)));
        backend.release.notify_one();

        assert!(
            task.await.expect("task joins").is_ok(),
            "in-flight request must retain its pinned allow generation"
        );
    }

    #[tokio::test]
    async fn audit_uses_transport_actor_digest_and_redacts_payload() {
        let path = std::env::temp_dir().join(format!(
            "basil-nix-audit-{}-{}.jsonl",
            std::process::id(),
            rand::random::<u64>()
        ));
        let audit = Arc::new(AuditLog::open(&path).expect("audit log"));
        let (service, state, _) = fixture(NixCacheState::Enrolled, Some(Arc::clone(&audit)));
        service
            .sign_nix_cache_fingerprint(sign_request())
            .await
            .expect("sign succeeds");
        drop(service);
        drop(state);
        drop(audit);

        let body = std::fs::read_to_string(&path).expect("audit body");
        let event = body
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|value| value["event"]["kind"] == "basil.audit.nix_cache_operation")
            .expect("Nix audit event");
        assert_eq!(event["actor"]["pid"], 4321);
        assert_eq!(event["actor"]["uid"], 1000);
        assert_eq!(event["policy_subject"], "svc.builder");
        assert_eq!(event["batch_id"], "abababababababababababababababab");
        assert_eq!(event["request_id"], "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
        assert_eq!(
            event["fingerprint_sha256"],
            PathInfoV1::parse(FINGERPRINT.as_bytes())
                .expect("canonical fixture")
                .sha256_hex()
        );
        let rendered = event.to_string();
        assert!(!rendered.contains(FINGERPRINT));
        for forbidden in ["signature", "private", "installed", "nix_caller"] {
            assert!(!rendered.contains(forbidden));
        }
        let _ = std::fs::remove_file(path);
    }
}
