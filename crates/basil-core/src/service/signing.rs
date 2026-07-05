#![allow(clippy::result_large_err)]

// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use basil_proto::broker::v1 as pb;
use basil_proto::broker::v1::signing_service_server::SigningService;
use tonic::{Request, Response};

use crate::catalog::policy::Op;
use crate::core::crypto_provider::{ProviderAuditEvent, ProviderAuditOutcome, ProviderError};
use crate::manager::{ManagerError, ProviderDispatch, ProviderGate};
use crate::service::broker::{BrokerGrpc, GrpcResult};
use crate::service::shared::{
    ensure_ml_dsa_key_type_matches, ensure_ml_kem_key_type_matches,
    ensure_supported_signing_algorithm, invalid_request, key_material, key_type, manager_status,
    material_len, payload_too_large, proto_key_type,
};

impl BrokerGrpc {
    /// Resolve the caller-scoped provider gate: whether policy grants this caller
    /// (kernel-attested `uid`) use of the local-software crypto provider for
    /// `key` via an explicit `op:use_software_custody` grant.
    pub(super) fn provider_gate(
        &self,
        actor: &crate::actor::AuthenticatedActor,
        key: &str,
    ) -> ProviderGate {
        let generation = self.state.load_generation();
        let local_software_allowed = generation
            .pdp()
            .decide(actor, Op::UseSoftwareCustody, key)
            .is_allow();
        ProviderGate {
            local_software_allowed,
        }
    }

    /// Audit a successful provider-dispatched operation (carries the selected
    /// provider + algorithm; never any key/signature/plaintext bytes).
    pub(super) fn audit_provider_success(
        &self,
        uid: u32,
        op: &'static str,
        key: &str,
        dispatch: ProviderDispatch,
    ) {
        self.state.record_provider_event(&ProviderAuditEvent {
            op,
            key_id: key,
            key_version: None,
            algorithm: dispatch.algorithm,
            provider: dispatch.provider,
            custody: dispatch.custody,
            caller_uid: uid,
            outcome: ProviderAuditOutcome::Success,
            reason: "ok",
        });
    }

    /// Audit a failed/denied provider-dispatched operation, deriving the provider
    /// and a stable, secret-free reason token from the error.
    pub(super) fn audit_provider_failure(
        &self,
        uid: u32,
        op: &'static str,
        key: &str,
        algorithm: &'static str,
        err: &ManagerError,
    ) {
        let (provider, outcome, reason) = provider_failure_audit(err);
        self.state.record_provider_event(&ProviderAuditEvent {
            op,
            key_id: key,
            key_version: None,
            algorithm,
            provider,
            custody: provider.custody_mode(),
            caller_uid: uid,
            outcome,
            reason,
        });
    }
}

/// Derive `(provider, outcome, reason)` for a provider-op audit from a manager
/// error. A policy denial is an explicit `deny`; everything else is a `failure`.
const fn provider_failure_audit(
    err: &ManagerError,
) -> (
    crate::core::crypto_provider::CryptoProviderId,
    ProviderAuditOutcome,
    &'static str,
) {
    use crate::core::crypto_provider::CryptoProviderId;
    match err {
        ManagerError::Provider(ProviderError::PolicyDenied { reason, .. }) => (
            CryptoProviderId::LocalSoftware,
            ProviderAuditOutcome::Deny,
            reason,
        ),
        ManagerError::Provider(ProviderError::Unsupported { provider, .. }) => {
            (*provider, ProviderAuditOutcome::Failure, "unsupported")
        }
        ManagerError::Provider(ProviderError::CryptoFailed {
            provider, reason, ..
        }) => (*provider, ProviderAuditOutcome::Failure, reason),
        ManagerError::Provider(ProviderError::Backend(_)) => (
            CryptoProviderId::LocalSoftware,
            ProviderAuditOutcome::Failure,
            "backend_error",
        ),
        _ => (
            CryptoProviderId::LocalSoftware,
            ProviderAuditOutcome::Failure,
            "error",
        ),
    }
}

#[tonic::async_trait]
impl SigningService for BrokerGrpc {
    async fn new_key(&self, request: Request<pb::NewKeyRequest>) -> GrpcResult<pb::NewKeyResponse> {
        let body = request.get_ref();
        let actor = self.authorize(&request, Op::NewKey, &body.key_id)?;
        let uid = Self::require_unix_uid(&actor, "new_key")?;
        // ML-DSA software-custody keys are provisioned through the crypto provider
        // (generate keypair → seal seed → write custody record), gated by the
        // explicit local-software policy grant. The algorithm comes from the
        // catalog keyType; the wire key_type must name the same ML-DSA level.
        if let Some(algorithm) = self.state.manager().ml_dsa_algorithm_for(&body.key_id) {
            ensure_ml_dsa_key_type_matches(body.key_type, algorithm, "new_key")?;
            let gate = self.provider_gate(&actor, &body.key_id);
            let (created, dispatch) = self
                .state
                .manager()
                .provider_generate(&body.key_id, gate)
                .await
                .inspect_err(|e| {
                    self.audit_provider_failure(uid, "new_key", &body.key_id, algorithm.token(), e);
                })
                .map_err(|e| manager_status("new_key", &e))?;
            self.audit_provider_success(uid, "new_key", &body.key_id, dispatch);
            return Ok(Response::new(pb::NewKeyResponse {
                key_id: created.key_id,
                public_key: created.public_key,
            }));
        }
        // ML-KEM software-custody sealing keys provision the same way (generate
        // seed → seal → write custody record), gated by the local-software grant.
        // The KEM parameter set comes from the catalog keyType; the wire key_type
        // must name the same ML-KEM level.
        if let Some(kem) = self.state.manager().ml_kem_algorithm_for(&body.key_id) {
            ensure_ml_kem_key_type_matches(body.key_type, kem, "new_key")?;
            let gate = self.provider_gate(&actor, &body.key_id);
            let (created, dispatch) = self
                .state
                .manager()
                .provider_generate_sealing(&body.key_id, kem, gate)
                .await
                .inspect_err(|e| {
                    self.audit_provider_failure(uid, "new_key", &body.key_id, kem.token(), e);
                })
                .map_err(|e| manager_status("new_key", &e))?;
            self.audit_provider_success(uid, "new_key", &body.key_id, dispatch);
            return Ok(Response::new(pb::NewKeyResponse {
                key_id: created.key_id,
                public_key: created.public_key,
            }));
        }
        let key_type = key_type(body.key_type, "new_key")?;
        let created = self
            .state
            .manager()
            .new_key(&body.key_id, key_type)
            .await
            .map_err(|e| manager_status("new_key", &e))?;
        Ok(Response::new(pb::NewKeyResponse {
            key_id: created.key_id,
            public_key: created.public_key,
        }))
    }

    async fn import(&self, request: Request<pb::ImportRequest>) -> GrpcResult<pb::NewKeyResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Import, &body.key_id)?;
        let material = body
            .material
            .as_ref()
            .ok_or_else(|| {
                crate::service::shared::invalid_request("import", "missing key material")
            })
            .and_then(|material| key_material(material, "import"))?;
        if material_len(&material) > self.state.limits().max_payload_size {
            return Err(payload_too_large(
                "import",
                "import payload exceeds configured cap",
            ));
        }
        let imported = self
            .state
            .manager()
            .import(&body.key_id, key_type(body.key_type, "import")?, &material)
            .await
            .map_err(|e| manager_status("import", &e))?;
        Ok(Response::new(pb::NewKeyResponse {
            key_id: imported.key_id,
            public_key: imported.public_key,
        }))
    }

    async fn import_set(
        &self,
        request: Request<pb::ImportSetRequest>,
    ) -> GrpcResult<pb::ImportSetResponse> {
        let body = request.get_ref();
        if body.entries.is_empty() {
            return Err(invalid_request("import_set", "import set has no entries"));
        }
        // Authorize and validate every entry BEFORE importing any: a default-deny
        // miss or bad material on one entry rejects the whole set (atomic authz).
        // The imports themselves are sequential and not transactional across the
        // backend. A later failure leaves earlier keys provisioned.
        let mut parsed = Vec::with_capacity(body.entries.len());
        let mut total: usize = 0;
        for entry in &body.entries {
            self.authorize(&request, Op::Import, &entry.key_id)?;
            let material = entry
                .material
                .as_ref()
                .ok_or_else(|| invalid_request("import_set", "missing key material"))
                .and_then(|material| key_material(material, "import_set"))?;
            total = total.saturating_add(material_len(&material));
            parsed.push((
                entry.key_id.clone(),
                key_type(entry.key_type, "import_set")?,
                material,
            ));
        }
        if total > self.state.limits().max_payload_size {
            return Err(payload_too_large(
                "import_set",
                "import set payload exceeds configured cap",
            ));
        }
        let mut keys = Vec::with_capacity(parsed.len());
        for (key_id, kt, material) in &parsed {
            let imported = self
                .state
                .manager()
                .import(key_id, *kt, material)
                .await
                .map_err(|e| manager_status("import_set", &e))?;
            keys.push(pb::ImportedKey {
                key_id: imported.key_id,
                public_key: imported.public_key,
            });
        }
        Ok(Response::new(pb::ImportSetResponse { keys }))
    }

    async fn sign(&self, request: Request<pb::SignRequest>) -> GrpcResult<pb::SignResponse> {
        let body = request.get_ref();
        let actor = self.authorize(&request, Op::Sign, &body.key_id)?;
        let uid = Self::require_unix_uid(&actor, "sign")?;
        ensure_supported_signing_algorithm(body.algorithm, "sign")?;
        // An ML-DSA key dispatches through the crypto provider (software custody);
        // every other key signs in place through the classical manager path.
        if let Some(algorithm) = self.state.manager().ml_dsa_algorithm_for(&body.key_id) {
            let gate = self.provider_gate(&actor, &body.key_id);
            let (signature, dispatch) = self
                .state
                .manager()
                .provider_sign(&body.key_id, &body.message, gate)
                .await
                .inspect_err(|e| {
                    self.audit_provider_failure(uid, "sign", &body.key_id, algorithm.token(), e);
                })
                .map_err(|e| manager_status("sign", &e))?;
            self.audit_provider_success(uid, "sign", &body.key_id, dispatch);
            return Ok(Response::new(pb::SignResponse { signature }));
        }
        let signature = self
            .state
            .manager()
            .sign(&body.key_id, &body.message)
            .await
            .map_err(|e| manager_status("sign", &e))?;
        Ok(Response::new(pb::SignResponse { signature }))
    }

    async fn verify(&self, request: Request<pb::VerifyRequest>) -> GrpcResult<pb::VerifyResponse> {
        let body = request.get_ref();
        let actor = self.authorize(&request, Op::Verify, &body.key_id)?;
        let uid = Self::require_unix_uid(&actor, "verify")?;
        ensure_supported_signing_algorithm(body.algorithm, "verify")?;
        if let Some(algorithm) = self.state.manager().ml_dsa_algorithm_for(&body.key_id) {
            let gate = self.provider_gate(&actor, &body.key_id);
            let (valid, dispatch) = self
                .state
                .manager()
                .provider_verify(&body.key_id, &body.message, &body.signature, gate)
                .await
                .inspect_err(|e| {
                    self.audit_provider_failure(uid, "verify", &body.key_id, algorithm.token(), e);
                })
                .map_err(|e| manager_status("verify", &e))?;
            self.audit_provider_success(uid, "verify", &body.key_id, dispatch);
            return Ok(Response::new(pb::VerifyResponse { valid }));
        }
        let valid = self
            .state
            .manager()
            .verify(&body.key_id, &body.message, &body.signature)
            .await
            .map_err(|e| manager_status("verify", &e))?;
        Ok(Response::new(pb::VerifyResponse { valid }))
    }

    async fn get_public_key(
        &self,
        request: Request<pb::GetPublicKeyRequest>,
    ) -> GrpcResult<pb::GetPublicKeyResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::GetPublicKey, &body.key_id)?;
        let public_key = self
            .state
            .manager()
            .get_public_key(&body.key_id)
            .await
            .map_err(|e| manager_status("get_public_key", &e))?;
        Ok(Response::new(pb::GetPublicKeyResponse {
            key_id: body.key_id.clone(),
            key_type: proto_key_type(public_key.key_type),
            public_key: public_key.public_key,
            version: public_key.version,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use basil_proto::broker::v1 as pb;
    use basil_proto::broker::v1::signing_service_server::SigningService;
    use basil_proto::{AeadAlgorithm, CiphertextEnvelope, KeyType};
    use tonic::{Code, Request};

    use super::BrokerGrpc;
    use crate::backend::{Backend, BackendError, KvValue, NewKey};
    use crate::catalog::load;
    use crate::manager::BackendManager;
    use crate::peer::PeerInfo;
    use crate::state::BrokerState;

    /// Stateful in-memory backend that round-trips a software-custodied ML-DSA
    /// key through generate (seal + write) and sign (read + unseal). `encrypt`
    /// length-prefixes the AAD so `decrypt` authenticates it; records sit at a
    /// fixed version 1.
    #[derive(Default)]
    struct PqcBackend {
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl Backend for PqcBackend {
        fn kind(&self) -> &'static str {
            "pqc-service-test"
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

        async fn encrypt(
            &self,
            _key_id: &str,
            algorithm: AeadAlgorithm,
            plaintext: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<CiphertextEnvelope, BackendError> {
            let aad = aad.unwrap_or(&[]);
            let mut ciphertext = vec![u8::try_from(aad.len()).unwrap_or(u8::MAX)];
            ciphertext.extend_from_slice(aad);
            ciphertext.extend_from_slice(plaintext);
            Ok(CiphertextEnvelope {
                alg: algorithm,
                key_version: 1,
                nonce: Vec::new(),
                ciphertext,
            })
        }

        async fn decrypt(
            &self,
            _key_id: &str,
            envelope: &CiphertextEnvelope,
            aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, BackendError> {
            let aad = aad.unwrap_or(&[]);
            let ct = &envelope.ciphertext;
            let aad_len = *ct.first().ok_or(BackendError::DecryptFailed)? as usize;
            let bound = ct.get(1..1 + aad_len).ok_or(BackendError::DecryptFailed)?;
            if bound != aad {
                return Err(BackendError::DecryptFailed);
            }
            Ok(ct
                .get(1 + aad_len..)
                .ok_or(BackendError::DecryptFailed)?
                .to_vec())
        }

        async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
            self.store
                .lock()
                .map_err(|_| BackendError::Unsupported("kv_put"))?
                .insert(key_id.to_string(), value.to_vec());
            Ok(1)
        }

        async fn kv_get(
            &self,
            key_id: &str,
            _version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            let value = self
                .store
                .lock()
                .map_err(|_| BackendError::Unsupported("kv_get"))?
                .get(key_id)
                .cloned();
            value
                .map(|value| KvValue { value, version: 1 })
                .ok_or(BackendError::Unsupported("kv_get"))
        }
    }

    const CATALOG: &str = r#"{
      "schemaVersion": 1,
      "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
      "keys": {
        "pqc.signer": {
          "class": "asymmetric", "keyType": "ml-dsa-65", "backend": "bao",
          "path": "secret/data/pqc/signer", "writable": true, "missing": "error",
          "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software",
                     "pqc_custody=software-encrypted", "pqc_storage_key=pqc/aead",
                     "crypto_provider_version=1"],
          "description": "ml-dsa-65 software-custodied signer"
        },
        "pqc.sealer": {
          "class": "sealing", "keyType": "ml-kem-768", "backend": "bao", "engine": "kv2",
          "path": "secret/data/pqc/sealer", "writable": true, "missing": "error",
          "publicPath": "secret/data/pqc/sealer-public",
          "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software",
                     "pqc_custody=software-encrypted", "pqc_storage_key=pqc/aead",
                     "crypto_provider_version=1"],
          "description": "ml-kem-768 software-custodied sealer"
        }
      }
    }"#;

    // uid 42 holds the local-software grant; uid 43 holds sign/new_key but NOT
    // op:use_software_custody, so it cannot drive the local-software provider.
    const POLICY: &str = r#"{
      "schemaVersion": 2,
      "subjects": {
        "svc.granted": { "allOf": [ { "kind": "unix", "uid": 42 } ] },
        "svc.ungranted": { "allOf": [ { "kind": "unix", "uid": 43 } ] }
      },
      "roles": {},
      "rules": [
        { "id": "granted", "subjects": ["svc.granted"],
          "action": ["op:sign", "op:verify", "op:new_key", "op:get_public_key",
                     "op:use_software_custody"],
          "target": ["pqc.*"] },
        { "id": "ungranted", "subjects": ["svc.ungranted"],
          "action": ["op:sign", "op:verify", "op:new_key"],
          "target": ["pqc.*"] }
      ],
      "config": {
        "names": { "users": { "42": "svc-granted", "43": "svc-ungranted" }, "groups": {} },
        "memberships": { "42": [42], "43": [43] }
      }
    }"#;

    fn service() -> BrokerGrpc {
        let (catalog, policy, config, warnings) = load(CATALOG, POLICY).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".to_string(), Box::new(PqcBackend::default()));
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        BrokerGrpc::new(Arc::new(BrokerState::new(
            catalog,
            policy,
            config,
            manager,
            "pqc-svc-test",
        )))
    }

    fn request<T>(uid: u32, body: T) -> Request<T> {
        let mut request = Request::new(body);
        request.extensions_mut().insert(PeerInfo {
            uid: Some(uid),
            ..PeerInfo::default()
        });
        request
    }

    // The full round trip generates and signs through the local-software
    // provider; the deny/validation tests below fail closed before the provider
    // runs.
    #[tokio::test]
    async fn ml_dsa_generate_sign_verify_through_grpc_with_grant() {
        let svc = service();
        let created = svc
            .new_key(request(
                42,
                pb::NewKeyRequest {
                    key_id: "pqc.signer".to_string(),
                    key_type: pb::KeyType::MlDsa65.into(),
                },
            ))
            .await
            .expect("provision ml-dsa key")
            .into_inner();
        assert!(!created.public_key.is_empty());

        let signature = svc
            .sign(request(
                42,
                pb::SignRequest {
                    key_id: "pqc.signer".to_string(),
                    message: b"grpc payload".to_vec(),
                    algorithm: pb::SigningAlgorithm::MlDsa65.into(),
                },
            ))
            .await
            .expect("sign succeeds with grant")
            .into_inner()
            .signature;
        assert!(!signature.is_empty());

        let valid = svc
            .verify(request(
                42,
                pb::VerifyRequest {
                    key_id: "pqc.signer".to_string(),
                    message: b"grpc payload".to_vec(),
                    signature,
                    algorithm: pb::SigningAlgorithm::MlDsa65.into(),
                },
            ))
            .await
            .expect("verify succeeds")
            .into_inner()
            .valid;
        assert!(valid, "broker-produced ML-DSA signature verifies");
    }

    // get_public_key for a software-custodied ML-DSA key returns the real
    // verifying key (basil-a36l): it equals the public new_key returned (which was
    // derived from the seed), and a broker-produced signature verifies against it.
    #[tokio::test]
    async fn ml_dsa_get_public_key_returns_seed_derived_public() {
        use crate::core::ml_dsa_sign;

        let svc = service();
        let provisioned = svc
            .new_key(request(
                42,
                pb::NewKeyRequest {
                    key_id: "pqc.signer".to_string(),
                    key_type: pb::KeyType::MlDsa65.into(),
                },
            ))
            .await
            .expect("provision ml-dsa key")
            .into_inner()
            .public_key;

        let fetched = svc
            .get_public_key(request(
                42,
                pb::GetPublicKeyRequest {
                    key_id: "pqc.signer".to_string(),
                    version: None,
                },
            ))
            .await
            .expect("get_public_key on ml-dsa key")
            .into_inner();
        assert_eq!(fetched.key_type, pb::KeyType::MlDsa65 as i32);
        assert_eq!(fetched.version, 1);
        assert_eq!(
            fetched.public_key, provisioned,
            "get_public_key returns the same public new_key derived from the seed"
        );

        let signature = svc
            .sign(request(
                42,
                pb::SignRequest {
                    key_id: "pqc.signer".to_string(),
                    message: b"a36l".to_vec(),
                    algorithm: pb::SigningAlgorithm::MlDsa65.into(),
                },
            ))
            .await
            .expect("sign")
            .into_inner()
            .signature;
        // Independent verification with the get_public_key-returned public proves
        // it is the real ML-DSA verifying key, not Ed25519/garbage.
        assert!(
            ml_dsa_sign::verify(
                ml_dsa_sign::MlDsaAlgorithm::MlDsa65,
                &fetched.public_key,
                b"a36l",
                &signature,
            )
            .expect("verify input well formed"),
            "broker signature verifies under the get_public_key public"
        );
    }

    // ML-KEM sealing keys are provisioned through the same GenerateKey RPC
    // (basil-o5qx): generate seed → derive encapsulation key → seal → write record.
    // The response carries the public encapsulation key (1184 bytes for ml-kem-768)
    // and no private material.
    #[tokio::test]
    async fn ml_kem_generate_sealing_key_through_grpc_with_grant() {
        let svc = service();
        let created = svc
            .new_key(request(
                42,
                pb::NewKeyRequest {
                    key_id: "pqc.sealer".to_string(),
                    key_type: pb::KeyType::MlKem768.into(),
                },
            ))
            .await
            .expect("provision ml-kem sealing key")
            .into_inner();
        assert_eq!(created.key_id, "pqc.sealer");
        assert_eq!(
            created.public_key.len(),
            1184,
            "ml-kem-768 encapsulation key is 1184 bytes"
        );
    }

    #[tokio::test]
    async fn ml_kem_new_key_without_local_software_grant_is_denied() {
        let svc = service();
        // uid 43 may new_key but lacks op:use_software_custody: fail closed.
        let status = svc
            .new_key(request(
                43,
                pb::NewKeyRequest {
                    key_id: "pqc.sealer".to_string(),
                    key_type: pb::KeyType::MlKem768.into(),
                },
            ))
            .await
            .expect_err("ml-kem provisioning denied without grant");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn ml_kem_new_key_rejects_mismatched_wire_key_type() {
        let svc = service();
        let status = svc
            .new_key(request(
                42,
                pb::NewKeyRequest {
                    key_id: "pqc.sealer".to_string(),
                    // Catalog declares ml-kem-768; a mismatched wire type is rejected.
                    key_type: pb::KeyType::MlKem512.into(),
                },
            ))
            .await
            .expect_err("wire key type must match the catalog ml-kem level");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn ml_dsa_sign_without_local_software_grant_is_denied() {
        let svc = service();
        // uid 43 may Sign (authorize passes) but lacks op:use_software_custody, so
        // the local-software provider is denied, fail closed as PermissionDenied.
        let status = svc
            .sign(request(
                43,
                pb::SignRequest {
                    key_id: "pqc.signer".to_string(),
                    message: b"m".to_vec(),
                    algorithm: pb::SigningAlgorithm::MlDsa65.into(),
                },
            ))
            .await
            .expect_err("local-software sign denied without grant");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn ml_dsa_new_key_rejects_mismatched_wire_key_type() {
        let svc = service();
        let status = svc
            .new_key(request(
                42,
                pb::NewKeyRequest {
                    key_id: "pqc.signer".to_string(),
                    // Catalog declares ml-dsa-65; a mismatched wire type is rejected.
                    key_type: pb::KeyType::MlDsa87.into(),
                },
            ))
            .await
            .expect_err("wire key type must match the catalog ml-dsa level");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    /// A counting BYOK backend: `import` records each committed catalog PATH (in
    /// order) and succeeds for any material, returning that path plus a one-byte
    /// public stand-in. The commit log lets a test assert exactly which keys were
    /// provisioned (and, crucially, that a rejected batch provisioned NONE).
    #[derive(Default)]
    struct ImportBackend {
        imported: Mutex<Vec<String>>,
    }

    impl ImportBackend {
        fn imported(&self) -> Vec<String> {
            self.imported.lock().expect("import log").clone()
        }
    }

    /// Newtype so the same `Arc<ImportBackend>` is both boxed into the manager and
    /// kept by the test to inspect the commit log.
    struct ImportHandle(Arc<ImportBackend>);

    #[async_trait]
    impl Backend for ImportHandle {
        fn kind(&self) -> &'static str {
            "import-count-test"
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
        async fn import(
            &self,
            key_id: &str,
            _key_type: KeyType,
            _material: &basil_proto::KeyMaterial,
        ) -> Result<NewKey, BackendError> {
            self.0
                .imported
                .lock()
                .map_err(|_| BackendError::Unsupported("import"))?
                .push(key_id.to_string());
            Ok(NewKey {
                key_id: key_id.to_string(),
                public_key: vec![0x01],
            })
        }
    }

    const IMPORT_CATALOG: &str = r#"{
      "schemaVersion": 1,
      "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
      "keys": {
        "byok.ed": {
          "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
          "path": "byok/ed", "writable": true, "missing": "error",
          "description": "BYOK ed25519 signer"
        },
        "byok.rsa": {
          "class": "asymmetric", "keyType": "rsa-2048", "backend": "bao",
          "path": "byok/rsa", "writable": true, "missing": "error",
          "description": "BYOK rsa-2048 signer"
        },
        "byok.ecdsa": {
          "class": "asymmetric", "keyType": "ecdsa-p256", "backend": "bao",
          "path": "byok/ecdsa", "writable": true, "missing": "error",
          "description": "BYOK ecdsa-p256 signer"
        }
      }
    }"#;

    const IMPORT_POLICY: &str = r#"{
      "schemaVersion": 2,
      "subjects": {
        "svc.importer": { "allOf": [ { "kind": "unix", "uid": 42 } ] }
      },
      "roles": {},
      "rules": [
        { "id": "importer", "subjects": ["svc.importer"],
          "action": ["op:import"], "target": ["byok.*"] }
      ],
      "config": {
        "names": { "users": { "42": "svc-importer" }, "groups": {} },
        "memberships": { "42": [42] }
      }
    }"#;

    /// Build the import service plus a handle onto the backend's commit log.
    fn import_service() -> (BrokerGrpc, Arc<ImportBackend>) {
        let (catalog, policy, config, warnings) =
            load(IMPORT_CATALOG, IMPORT_POLICY).expect("fixture loads");
        assert!(warnings.is_empty());
        let backend = Arc::new(ImportBackend::default());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert(
            "bao".to_string(),
            Box::new(ImportHandle(Arc::clone(&backend))),
        );
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        let service = BrokerGrpc::new(Arc::new(BrokerState::new(
            catalog,
            policy,
            config,
            manager,
            "import-svc-test",
        )));
        (service, backend)
    }

    fn ed25519_entry() -> pb::ImportEntry {
        pb::ImportEntry {
            key_id: "byok.ed".to_string(),
            key_type: pb::KeyType::Ed25519.into(),
            material: Some(pb::KeyMaterial {
                material: Some(pb::key_material::Material::Ed25519Seed(vec![7u8; 32])),
            }),
        }
    }

    fn rsa_entry() -> pb::ImportEntry {
        pb::ImportEntry {
            key_id: "byok.rsa".to_string(),
            key_type: pb::KeyType::Rsa2048.into(),
            material: Some(pb::KeyMaterial {
                material: Some(pb::key_material::Material::Pkcs8Der(vec![1u8; 64])),
            }),
        }
    }

    fn ecdsa_entry() -> pb::ImportEntry {
        pb::ImportEntry {
            key_id: "byok.ecdsa".to_string(),
            key_type: pb::KeyType::EcdsaP256.into(),
            material: Some(pb::KeyMaterial {
                material: Some(pb::key_material::Material::Pkcs8Der(vec![2u8; 64])),
            }),
        }
    }

    /// A fully-valid Ed25519 + RSA-2048 + ECDSA P-256 batch imports ALL three
    /// keys, in request order, through the real `import_set` RPC.
    #[tokio::test]
    async fn import_set_valid_batch_imports_all_three_types() {
        let (svc, backend) = import_service();
        let resp = SigningService::import_set(
            &svc,
            request(
                42,
                pb::ImportSetRequest {
                    entries: vec![ed25519_entry(), rsa_entry(), ecdsa_entry()],
                },
            ),
        )
        .await
        .expect("valid batch imports")
        .into_inner();

        assert_eq!(resp.keys.len(), 3, "one result per imported key");
        assert_eq!(
            backend.imported(),
            ["byok/ed", "byok/rsa", "byok/ecdsa"],
            "every entry committed to the backend, in request order"
        );
    }

    /// A batch with one invalid entry (missing key material) imports NONE: the
    /// all-or-nothing validation phase rejects the whole set BEFORE any backend
    /// import runs, even though the two preceding entries validated cleanly.
    #[tokio::test]
    async fn import_set_one_invalid_entry_imports_none() {
        let (svc, backend) = import_service();
        let bad = pb::ImportEntry {
            key_id: "byok.ecdsa".to_string(),
            key_type: pb::KeyType::EcdsaP256.into(),
            material: None, // invalid: no key material supplied
        };
        let status = SigningService::import_set(
            &svc,
            request(
                42,
                pb::ImportSetRequest {
                    entries: vec![ed25519_entry(), rsa_entry(), bad],
                },
            ),
        )
        .await
        .expect_err("a batch with an invalid entry is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(
            backend.imported().is_empty(),
            "no key from the rejected batch was committed"
        );
    }
}
