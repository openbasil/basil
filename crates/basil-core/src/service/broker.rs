// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! gRPC broker service adapters.
//!
//! This module is intentionally a thin transport adapter over the existing
//! [`BrokerState`] + [`BackendManager`] core. It preserves the same PDP gating
//! model as the JSON handler: every key-scoped RPC authorizes the
//! kernel-attested peer uid before dispatching.

#![allow(clippy::result_large_err)]

use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;
use std::sync::Mutex;
use tonic::{Code, Request, Response, Status};

use crate::actor::AuthenticatedActor;
use crate::catalog::policy::Op;
use crate::state::BrokerState;
use crate::transport::{authorize, broker_status};

pub(super) type GrpcResult<T> = Result<Response<T>, Status>;
pub(super) type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

/// Broker identity and response-signing key settings for sealed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerIdentityRuntimeConfig {
    /// Stable broker audience / identity URI.
    pub id: String,
    /// Catalog key id used to sign invocation responses.
    pub response_signing_key_id: String,
}

/// Runtime settings for the sealed invocation service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationRuntimeConfig {
    /// Whether `InvocationService.Invoke` accepts requests.
    pub enabled: bool,
    /// Broker identity and response-signing key. Required when enabled.
    pub broker_identity: Option<BrokerIdentityRuntimeConfig>,
    /// Accepted broker audiences. An omitted header audience may be derived only
    /// when this contains exactly one value.
    pub audiences: Vec<String>,
    /// Catalog key id whose public half receives sealed invocation requests.
    pub request_encryption_key_id: Option<String>,
    /// Maximum accepted signed request TTL in seconds.
    pub max_ttl_secs: u32,
    /// Allowed clock skew in seconds for issue and expiry timestamps.
    pub clock_skew_secs: u32,
    /// Maximum replay-cache entries retained in memory.
    pub replay_cache_capacity: usize,
    /// Fixed current time override for deterministic tests. Leave unset in
    /// production.
    pub now_unix_override: Option<u32>,
}

impl Default for InvocationRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            broker_identity: None,
            audiences: Vec::new(),
            request_encryption_key_id: None,
            max_ttl_secs: basil_proto::invocation::DEFAULT_EXPIRES_AFTER_SECS,
            clock_skew_secs: 30,
            replay_cache_capacity: 4096,
            now_unix_override: None,
        }
    }
}

/// Shared implementation for all broker gRPC services.
#[derive(Debug, Clone)]
pub struct BrokerGrpc {
    pub(super) state: Arc<BrokerState>,
    pub(super) invocation: InvocationRuntimeConfig,
    pub(super) invocation_replay_cache:
        Arc<Mutex<crate::service::invocation::InvocationReplayCache>>,
}

impl BrokerGrpc {
    /// Build a gRPC service adapter over shared broker state.
    #[must_use]
    pub fn new(state: Arc<BrokerState>) -> Self {
        Self::new_with_invocation(state, false)
    }

    /// Build a gRPC service adapter and explicitly configure invocation serving.
    #[must_use]
    pub fn new_with_invocation(state: Arc<BrokerState>, invocation_enabled: bool) -> Self {
        Self::new_with_invocation_config(
            state,
            InvocationRuntimeConfig {
                enabled: invocation_enabled,
                ..InvocationRuntimeConfig::default()
            },
        )
    }

    /// Build a gRPC service adapter with full invocation runtime settings.
    #[must_use]
    pub fn new_with_invocation_config(
        state: Arc<BrokerState>,
        invocation: InvocationRuntimeConfig,
    ) -> Self {
        let capacity = invocation.replay_cache_capacity;
        Self {
            state,
            invocation,
            invocation_replay_cache: Arc::new(Mutex::new(
                crate::service::invocation::InvocationReplayCache::new(capacity),
            )),
        }
    }

    pub(super) fn invocation_now_unix(&self) -> u32 {
        if let Some(now) = self.invocation.now_unix_override {
            return now;
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| {
                u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
            })
    }

    pub(super) fn authorize<T>(
        &self,
        request: &Request<T>,
        op: Op,
        key: &str,
    ) -> Result<AuthenticatedActor, Status> {
        authorize(&self.state, request, op, key)
    }

    pub(super) fn visible(&self, actor: &AuthenticatedActor, key: &str) -> bool {
        let generation = self.state.load_generation();
        let pdp = generation.pdp();
        pdp.decide(actor, Op::List, key).is_allow()
            || pdp.decide(actor, Op::GetPublicKey, key).is_allow()
            || pdp.decide(actor, Op::Get, key).is_allow()
    }

    pub(super) fn require_unix_uid(
        actor: &AuthenticatedActor,
        op: &'static str,
    ) -> Result<u32, Status> {
        actor.unix_uid().ok_or_else(|| {
            broker_status(
                Code::Unauthenticated,
                "UNAUTHENTICATED",
                op,
                "operation requires local peer credentials",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use async_trait::async_trait;
    use base64::Engine as _;
    use basil_proto::KeyType;
    use basil_proto::broker::v1 as pb;
    use basil_proto::broker::v1::BrokerErrorInfo;
    use basil_proto::broker::v1::admin_service_server::AdminService;
    use basil_proto::broker::v1::minting_service_server::MintingService;
    use basil_proto::broker::v1::nats_service_server::NatsService;
    use basil_proto::broker::v1::signing_service_server::SigningService;
    use basil_proto::google::rpc::Status as RpcStatus;
    use nkeys::{KeyPair, XKey};
    use prost::Message;
    use prost_types::{Duration, Struct, Value as ProstValue, value::Kind as ProstKind};
    use serde_json::Value as JsonValue;
    use tonic::{Code, Request, Status};

    use super::BrokerGrpc;
    use crate::backend::{Backend, BackendError, KvValue, NewKey, PublicKey};
    use crate::catalog::load;
    use crate::manager::{BackendManager, ManagerError};
    use crate::peer::PeerInfo;
    use crate::service::minting::nats_mint_status;
    use crate::service::shared::*;
    use crate::state::BrokerState;
    use zeroize::Zeroizing;

    fn error_info(status: &Status) -> BrokerErrorInfo {
        let rpc = RpcStatus::decode(status.details()).expect("status details decode");
        let detail = rpc.details.first().expect("broker detail present");
        BrokerErrorInfo::decode(detail.value.as_slice()).expect("broker error info decodes")
    }

    fn assert_status_omits(status: &Status, canaries: &[&str]) {
        let info = error_info(status);
        let visible = format!(
            "{} {} {} {:?}",
            status.message(),
            info.reason,
            info.op,
            status.details()
        );
        for canary in canaries {
            assert!(
                !visible.contains(canary),
                "status leaked secret canary `{canary}` in `{visible}`"
            );
        }
    }

    #[test]
    fn unsupported_algorithm_maps_to_unimplemented_detail() {
        let status = backend_status(
            "encrypt",
            &BackendError::UnsupportedAlgorithm(basil_proto::AeadAlgorithm::Aes256Gcm),
        );
        let info = error_info(&status);
        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(info.reason, "UNSUPPORTED_ALGORITHM");
        assert_eq!(info.op, "encrypt");
    }

    #[test]
    fn invalid_request_maps_to_invalid_argument_detail() {
        let status = key_type(0, "new_key").expect_err("unspecified key type is invalid");
        let info = error_info(&status);
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(info.reason, "INVALID_REQUEST");
        assert_eq!(info.op, "new_key");
    }

    #[test]
    fn pqc_key_types_map_to_unimplemented_detail() {
        let status = key_type(pb::KeyType::MlDsa65.into(), "new_key")
            .expect_err("ML-DSA generation is not implemented yet");
        let info = error_info(&status);
        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(info.reason, "UNSUPPORTED_ALGORITHM");
        assert_eq!(info.op, "new_key");

        let status = key_type(pb::KeyType::MlKem768.into(), "new_key")
            .expect_err("ML-KEM generation is not implemented yet");
        let info = error_info(&status);
        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(info.reason, "UNSUPPORTED_ALGORITHM");
        assert_eq!(info.op, "new_key");
    }

    #[test]
    fn signing_algorithms_are_accepted_at_the_wire_layer() {
        ensure_supported_signing_algorithm(pb::SigningAlgorithm::Ed25519.into(), "sign")
            .expect("legacy signing remains supported");
        // ML-DSA is now serviceable: the wire validation accepts it and the
        // manager dispatches a software-custodied ML-DSA key through the provider.
        for algorithm in [
            pb::SigningAlgorithm::MlDsa44,
            pb::SigningAlgorithm::MlDsa65,
            pb::SigningAlgorithm::MlDsa87,
        ] {
            ensure_supported_signing_algorithm(algorithm.into(), "sign")
                .expect("ML-DSA signing is serviceable");
        }
    }

    #[test]
    fn kem_envelope_algorithms_are_validated() {
        // X25519 and ML-KEM are recognized KEMs for envelope unwrap. Broker-side
        // wrap remains X25519-only and is rejected in the AEAD service.
        ensure_supported_kem_algorithm(pb::KemAlgorithm::X25519.into(), "wrap_envelope")
            .expect("X25519 KEM is serviceable");
        ensure_supported_kem_algorithm(pb::KemAlgorithm::MlKem1024.into(), "unwrap_envelope")
            .expect("ML-KEM unwrap is serviceable");
        ensure_supported_envelope_algorithm(
            pb::EnvelopeAlgorithm::Aes256Gcm.into(),
            "wrap_envelope",
        )
        .expect("envelope AEAD contract value is recognized");

        let status = ensure_supported_kem_algorithm(0, "wrap_envelope")
            .expect_err("missing KEM algorithm is invalid");
        let info = error_info(&status);
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(info.reason, "INVALID_REQUEST");
        assert_eq!(info.op, "wrap_envelope");
    }

    #[test]
    fn payload_cap_maps_to_resource_exhausted_detail() {
        let status = payload_too_large("set", "too large");
        let info = error_info(&status);
        assert_eq!(status.code(), Code::ResourceExhausted);
        assert_eq!(info.reason, "PAYLOAD_TOO_LARGE");
        assert_eq!(info.op, "set");
    }

    #[test]
    fn backend_transport_maps_to_unavailable_detail() {
        let status = backend_status("sign", &BackendError::Transport("down".to_string()));
        let info = error_info(&status);
        assert_eq!(status.code(), Code::Unavailable);
        assert_eq!(status.message(), "backend unavailable");
        assert_eq!(info.reason, "BACKEND_UNAVAILABLE");
        assert_eq!(info.op, "sign");
    }

    #[test]
    fn backend_status_omits_secret_bearing_upstream_details() {
        let canaries = [
            "vault-token-s.123",
            "Authorization: Bearer secret",
            "/run/credentials/basil/passphrase",
            "-----BEGIN PRIVATE KEY-----",
            "upstream-response-body-with-credential",
        ];
        for err in [
            BackendError::Transport(canaries[1].to_string()),
            BackendError::Backend(canaries[4].to_string()),
            BackendError::Protocol(canaries[3].to_string()),
        ] {
            let status = backend_status("sign", &err);
            assert_status_omits(&status, &canaries);
        }
    }

    #[test]
    fn decrypt_failure_is_fixed_opaque_invalid_argument() {
        let status = backend_status("decrypt", &BackendError::DecryptFailed);
        let info = error_info(&status);
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "decrypt failed");
        assert_eq!(info.reason, "DECRYPT_FAILED");
        assert_eq!(info.op, "decrypt");
    }

    #[test]
    fn unknown_key_on_gated_manager_path_is_unauthorized_not_not_found() {
        let status = manager_status("sign", &ManagerError::UnknownKey("hidden.key".to_string()));
        let info = error_info(&status);
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), "not authorized");
        assert_eq!(info.reason, "UNAUTHORIZED");
        assert_eq!(info.op, "sign");
    }

    #[test]
    fn duration_conversion_rejects_negative_and_rounds_fraction_up() {
        let ttl = ttl_seconds(
            Some(&Duration {
                seconds: 4,
                nanos: 1,
            }),
            "mint",
        )
        .expect("ttl converts");
        assert_eq!(ttl, Some(5));

        let status = ttl_seconds(
            Some(&Duration {
                seconds: -1,
                nanos: 0,
            }),
            "mint",
        )
        .expect_err("negative ttl rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(error_info(&status).reason, "INVALID_REQUEST");
    }

    #[test]
    fn struct_claims_convert_to_json_and_reject_non_finite_numbers() {
        let claims = Struct {
            fields: [
                (
                    "scope".to_string(),
                    ProstValue {
                        kind: Some(ProstKind::StringValue("read".to_string())),
                    },
                ),
                (
                    "version".to_string(),
                    ProstValue {
                        kind: Some(ProstKind::NumberValue(2.0)),
                    },
                ),
                (
                    "ratio".to_string(),
                    ProstValue {
                        kind: Some(ProstKind::NumberValue(2.5)),
                    },
                ),
            ]
            .into(),
        };
        let json = claims_json(Some(&claims), "mint").expect("claims convert");
        assert_eq!(json["scope"], JsonValue::String("read".to_string()));
        assert_eq!(json["version"], JsonValue::Number(2.into()));
        assert_eq!(
            json["ratio"],
            JsonValue::Number(serde_json::Number::from_f64(2.5).expect("finite"))
        );

        let claims = Struct {
            fields: [(
                "bad".to_string(),
                ProstValue {
                    kind: Some(ProstKind::NumberValue(f64::NAN)),
                },
            )]
            .into(),
        };
        let status = claims_json(Some(&claims), "mint").expect_err("nan rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(error_info(&status).reason, "INVALID_REQUEST");
    }

    #[test]
    fn bad_subject_nkey_maps_to_invalid_argument() {
        let status = nats_mint_status(
            "mint_nats_user",
            &BackendError::Protocol("invalid subject user nkey: bad".to_string()),
        );
        let info = error_info(&status);
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(info.reason, "INVALID_REQUEST");
        assert_eq!(info.op, "mint_nats_user");
    }

    struct MintBackend;

    #[async_trait]
    impl Backend for MintBackend {
        fn kind(&self) -> &'static str {
            "mint-test"
        }

        async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
            let _ = key_type;
            Err(BackendError::Unsupported("new_key"))
        }

        async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
            let _ = key_id;
            Ok(vec![7; 32])
        }

        async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
            let _ = (key_id, message);
            Ok(vec![9; 64])
        }

        async fn verify(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, BackendError> {
            let _ = (key_id, message, signature);
            Ok(true)
        }

        async fn kv_get(
            &self,
            key_id: &str,
            version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            let _ = version;
            match key_id {
                "nats/curve-box-public" => {
                    let private = Zeroizing::new([0x55; 32]);
                    Ok(KvValue {
                        value: basil_nats::xkey_public_from_private(&private).to_vec(),
                        version: 1,
                    })
                }
                _ => Err(BackendError::KeyNotFound(key_id.to_string())),
            }
        }

        async fn kv_get_secret(
            &self,
            key_id: &str,
            version: Option<u32>,
        ) -> Result<crate::backend::KvSecret, BackendError> {
            let _ = version;
            match key_id {
                "nats/curve-box" => Ok(crate::backend::KvSecret {
                    value: Zeroizing::new(vec![0x55; 32]),
                    version: 1,
                }),
                _ => Err(BackendError::KeyNotFound(key_id.to_string())),
            }
        }
    }

    /// Real NATS-key signer used to prove `SigningService.Sign` can complete a
    /// caller-assembled rich NATS JWT without exposing the issuer seed.
    struct NatsSignBackend(KeyPair);

    #[async_trait]
    impl Backend for NatsSignBackend {
        fn kind(&self) -> &'static str {
            "nkey-sign-test"
        }

        async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
            let _ = key_type;
            Err(BackendError::Unsupported("new_key"))
        }

        async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
            let _ = key_id;
            let (_, public) = basil_nats::decode_public(&self.0.public_key())
                .map_err(|e| BackendError::Protocol(e.to_string()))?;
            Ok(public.to_vec())
        }

        async fn public_key_with_meta(&self, key_id: &str) -> Result<PublicKey, BackendError> {
            Ok(PublicKey {
                public_key: self.public_key(key_id).await?,
                key_type: KeyType::Ed25519Nkey,
                version: 1,
            })
        }

        async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
            let _ = key_id;
            self.0
                .sign(message)
                .map_err(|e| BackendError::Backend(e.to_string()))
        }

        async fn verify(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, BackendError> {
            let _ = key_id;
            Ok(self.0.verify(message, signature).is_ok())
        }
    }

    fn state_with_backend(backend: Box<dyn Backend>) -> Arc<BrokerState> {
        let catalog = r#"{
          "schemaVersion": 1,
          "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
          "keys": {
            "issuer.account": {
              "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
              "path": "issuer/account", "writable": true, "missing": "error",
              "labels": ["nats_type=A"], "description": "NATS account issuer"
            },
            "issuer.operator": {
              "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
              "path": "issuer/operator", "writable": true, "missing": "error",
              "labels": ["nats_type=O"], "description": "NATS operator issuer"
            },
            "issuer.server": {
              "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
              "path": "issuer/server", "writable": true, "missing": "error",
              "labels": ["nats_type=N"], "description": "NATS server issuer"
            },
            "issuer.curve": {
              "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
              "path": "issuer/curve", "writable": true, "missing": "error",
              "labels": ["nats_type=X"], "description": "NATS curve issuer"
            },
            "nats.curve_box": {
              "class": "sealing", "keyType": "x25519", "backend": "bao",
              "path": "nats/curve-box", "publicPath": "nats/curve-box-public",
              "writable": false, "missing": "error",
              "description": "NATS xkey box custody"
            }
          }
        }"#;
        let policy = r#"{
          "schemaVersion": 2,
          "subjects": {
            "svc.mint": { "allOf": [ { "kind": "unix", "uid": 42 } ] }
          },
          "roles": {
            "minter": ["mint", "sign_nats_jwt", "validate_nats_jwt"],
            "reader": ["get", "list", "get_public_key"],
            "signer": ["sign", "verify"],
            "nats_box": ["encrypt_nats_curve", "decrypt_nats_curve"]
          },
          "rules": [
            { "id": "mint", "subjects": ["svc.mint"], "action": ["role:minter", "role:reader", "role:signer"], "target": ["issuer.*"] },
            { "id": "nats-box", "subjects": ["svc.mint"], "action": ["role:nats_box"], "target": ["nats.curve_box"] },
            { "id": "watch", "subjects": ["svc.mint"], "action": ["op:watch"], "target": ["broker.watch"] }
          ],
          "config": {
            "names": { "users": { "42": "svc-mint" }, "groups": {} },
            "memberships": { "42": [42] }
          }
        }"#;
        let (catalog, policy, config, warnings) = load(catalog, policy).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".to_string(), backend);
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        Arc::new(BrokerState::new(
            catalog,
            policy,
            config,
            manager,
            "mint-test",
        ))
    }

    fn mint_state() -> Arc<BrokerState> {
        state_with_backend(Box::new(MintBackend))
    }

    fn authed_request<T>(body: T) -> Request<T> {
        let mut request = Request::new(body);
        request.extensions_mut().insert(PeerInfo {
            uid: Some(42),
            ..PeerInfo::default()
        });
        request
    }

    fn ttl() -> Duration {
        Duration {
            seconds: 60,
            nanos: 0,
        }
    }

    fn rich_account_import(exporting: &KeyPair) -> basil_nats::AccountImport {
        basil_nats::AccountImport {
            name: "control-read".to_string(),
            subject: "$JS.API.CONSUMER.MSG.NEXT.control_delivery".to_string(),
            account: exporting.public_key(),
            token: String::new(),
            to: String::new(),
            local_subject: "R3.$JS.API.CONSUMER.MSG.NEXT.control_delivery".to_string(),
            kind: basil_nats::ExportType::Service,
            share: true,
            allow_trace: true,
        }
    }

    fn rich_account_export(revocations: BTreeMap<String, i64>) -> basil_nats::AccountExport {
        basil_nats::AccountExport {
            name: "device-messages".to_string(),
            subject: "dev.*.*.>".to_string(),
            kind: basil_nats::ExportType::Stream,
            token_req: true,
            revocations,
            response_type: None,
            response_threshold: 0,
            service_latency: None,
            account_token_position: 2,
            advertise: true,
            allow_trace: true,
            description: "realm device delivery".to_string(),
            info_url: "https://basil.example.test/nats".to_string(),
        }
    }

    fn rich_account_limits() -> basil_nats::OperatorLimits {
        basil_nats::OperatorLimits {
            nats: basil_nats::NatsLimits {
                subs: 512,
                data: 1_048_576,
                payload: 262_144,
            },
            account: basil_nats::AccountLimits {
                imports: 32,
                exports: 32,
                wildcards: true,
                disallow_bearer: true,
                conn: 256,
                leaf: 8,
            },
            jetstream: basil_nats::JetStreamLimits {
                mem_storage: 67_108_864,
                disk_storage: 1_073_741_824,
                streams: 64,
                consumer: 512,
                max_ack_pending: 10_000,
                mem_max_stream_bytes: 8_388_608,
                disk_max_stream_bytes: 134_217_728,
                max_bytes_required: true,
            },
            tiered_limits: BTreeMap::new(),
        }
    }

    fn rich_account_default_permissions() -> basil_nats::Permissions {
        basil_nats::Permissions {
            publish: basil_nats::Permission {
                allow: vec!["dev.realm.device.>".to_string()],
                deny: vec!["dev.realm.device.private.>".to_string()],
            },
            sub: basil_nats::Permission {
                allow: vec!["dist.>".to_string(), "dev.realm.device.>".to_string()],
                deny: Vec::new(),
            },
            resp: Some(basil_nats::ResponsePermission {
                max: 1,
                ttl: 2_000_000_000,
            }),
        }
    }

    fn rich_account_claims(exporting: &KeyPair, user: &KeyPair) -> basil_nats::AccountClaims {
        let mut revocations = BTreeMap::new();
        revocations.insert(user.public_key(), 1_782_000_001);
        let mut export_revocations = BTreeMap::new();
        export_revocations.insert("*".to_string(), 1_782_000_002);
        basil_nats::AccountClaims {
            imports: vec![rich_account_import(exporting)],
            exports: vec![rich_account_export(export_revocations)],
            limits: rich_account_limits(),
            signing_keys: Vec::new(),
            revocations,
            default_permissions: Some(rich_account_default_permissions()),
            mappings: BTreeMap::new(),
            authorization: basil_nats::ExternalAuthorization::default(),
            trace: Some(basil_nats::MsgTrace {
                dest: "trace.realm".to_string(),
                sampling: 25,
            }),
            cluster_traffic: Some(basil_nats::ClusterTraffic::System),
        }
    }

    fn rich_account_jwt(
        issuer_nkey: String,
        account: &KeyPair,
        signing: &KeyPair,
        exporting: &KeyPair,
        user: &KeyPair,
    ) -> basil_nats::AccountJwt {
        basil_nats::AccountJwt {
            issuer: issuer_nkey,
            subject_account: account.public_key(),
            name: "basil-realm".to_string(),
            issued_at: 1_782_000_000,
            expires: None,
            signing_keys: vec![signing.public_key()],
            claims: rich_account_claims(exporting, user),
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn grpc_minting_methods_return_credentials() {
        let service = BrokerGrpc::new(mint_state());
        let generic = service
            .mint_jwt(authed_request(pb::MintJwtRequest {
                key_id: "issuer.account".to_string(),
                subject: Some("subject".to_string()),
                ttl: Some(ttl()),
                claims: None,
            }))
            .await
            .expect("generic mint succeeds")
            .into_inner();
        assert!(!generic.token.is_empty());
        assert!(generic.expires_at.is_some());

        let user_nkey = basil_nats::encode_public(basil_nats::NkeyType::User, &[2; 32])
            .expect("test user public key encodes");
        let user = service
            .mint_nats_user(authed_request(pb::MintNatsUserRequest {
                key_id: "issuer.account".to_string(),
                subject_user_nkey: user_nkey,
                issuer_account: None,
                name: "user".to_string(),
                ttl: Some(ttl()),
                pub_allow: Vec::new(),
                pub_deny: Vec::new(),
                sub_allow: Vec::new(),
                sub_deny: Vec::new(),
            }))
            .await
            .expect("user mint succeeds")
            .into_inner();
        assert!(!user.token.is_empty());

        let signed_nats = service
            .sign_nats_jwt(authed_request(pb::SignNatsJwtRequest {
                key_id: "issuer.account".to_string(),
                claims_json: serde_json::to_vec(&serde_json::json!({
                    "sub": basil_nats::encode_public(basil_nats::NkeyType::User, &[8; 32])
                        .expect("test user public key encodes"),
                    "name": "rich-user",
                    "nats": { "type": "user", "version": 2 }
                }))
                .expect("claims json"),
                expected_type: pb::NatsJwtType::User.into(),
                ttl: Some(ttl()),
                expires_at: None,
                issued_at: None,
                jti_mode: pb::NatsJtiMode::RequireValid.into(),
            }))
            .await
            .expect("validated nats jwt sign succeeds")
            .into_inner();
        assert!(!signed_nats.token.is_empty());
        assert!(signed_nats.expires_at.is_some());

        let account_nkey = basil_nats::encode_public(basil_nats::NkeyType::Account, &[3; 32])
            .expect("test account public key encodes");
        let account = service
            .mint_nats_account(authed_request(pb::MintNatsAccountRequest {
                key_id: "issuer.operator".to_string(),
                subject_account_nkey: account_nkey,
                name: "account".to_string(),
                ttl: Some(ttl()),
                signing_keys: Vec::new(),
            }))
            .await
            .expect("account mint succeeds")
            .into_inner();
        assert!(!account.token.is_empty());

        let operator = service
            .mint_nats_operator(authed_request(pb::MintNatsOperatorRequest {
                key_id: "issuer.operator".to_string(),
                subject_operator_nkey: None,
                name: "operator".to_string(),
                ttl: Some(ttl()),
                signing_keys: Vec::new(),
                account_server_url: None,
                system_account: None,
            }))
            .await
            .expect("operator mint succeeds")
            .into_inner();
        assert!(!operator.token.is_empty());

        let signer = service
            .mint_nats_signer(authed_request(pb::MintNatsSignerRequest {
                key_id: "issuer.account".to_string(),
                subject_nkey: basil_nats::encode_public(basil_nats::NkeyType::Account, &[4; 32])
                    .expect("test account signer public key encodes"),
                name: "signer".to_string(),
                ttl: Some(ttl()),
            }))
            .await
            .expect("signer mint succeeds")
            .into_inner();
        assert!(!signer.token.is_empty());

        let server = service
            .mint_nats_server(authed_request(pb::MintNatsServerRequest {
                key_id: "issuer.server".to_string(),
                subject_server_nkey: basil_nats::encode_public(
                    basil_nats::NkeyType::Server,
                    &[5; 32],
                )
                .expect("test server public key encodes"),
                name: "server".to_string(),
                ttl: Some(ttl()),
            }))
            .await
            .expect("server mint succeeds")
            .into_inner();
        assert!(!server.token.is_empty());

        let curve = service
            .mint_nats_curve(authed_request(pb::MintNatsCurveRequest {
                key_id: "issuer.curve".to_string(),
                subject_curve_nkey: basil_nats::encode_public(
                    basil_nats::NkeyType::Curve,
                    &[6; 32],
                )
                .expect("test curve public key encodes"),
                name: "curve".to_string(),
                ttl: Some(ttl()),
            }))
            .await
            .expect("curve mint succeeds")
            .into_inner();
        assert!(!curve.token.is_empty());
    }

    #[tokio::test]
    async fn sign_nats_jwt_ttl_uses_claim_iat_as_base() {
        let account = KeyPair::new_account();
        let user = KeyPair::new_user();
        let service = BrokerGrpc::new(state_with_backend(Box::new(NatsSignBackend(account))));
        let token = service
            .sign_nats_jwt(authed_request(pb::SignNatsJwtRequest {
                key_id: "issuer.account".to_string(),
                claims_json: serde_json::to_vec(&serde_json::json!({
                    "iat": 1_700_000_000_u64,
                    "sub": user.public_key(),
                    "nats": { "type": "user", "version": 2 }
                }))
                .expect("claims json"),
                expected_type: pb::NatsJwtType::User.into(),
                ttl: Some(Duration {
                    seconds: 60,
                    nanos: 0,
                }),
                expires_at: None,
                issued_at: None,
                jti_mode: pb::NatsJtiMode::RequireValid.into(),
            }))
            .await
            .expect("sign succeeds")
            .into_inner()
            .token;

        let parts: Vec<&str> = token.split('.').collect();
        let claims: JsonValue = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .expect("claims decode"),
        )
        .expect("claims json");
        assert_eq!(claims["iat"], 1_700_000_000_u64);
        assert_eq!(claims["exp"], 1_700_000_060_u64);
    }

    #[tokio::test]
    async fn grpc_nats_curve_encrypt_decrypt_interops_with_nkeys() {
        let service = BrokerGrpc::new(mint_state());
        let broker_private = [0x55; 32];
        let broker_xkey = XKey::new_from_raw(broker_private);
        let peer = XKey::new_from_raw([0x66; 32]);

        let encrypted = service
            .encrypt_nats_curve(authed_request(pb::EncryptNatsCurveRequest {
                key_id: "nats.curve_box".to_string(),
                recipient_public_xkey: peer.public_key(),
                plaintext: b"broker-to-peer".to_vec(),
            }))
            .await
            .expect("encrypt succeeds")
            .into_inner()
            .ciphertext;
        let opened_by_peer = peer
            .open(&encrypted, &broker_xkey)
            .expect("nkeys opens broker ciphertext");
        assert_eq!(opened_by_peer, b"broker-to-peer");

        let peer_box = peer
            .seal(b"peer-to-broker", &broker_xkey)
            .expect("nkeys seals");
        let decrypted = service
            .decrypt_nats_curve(authed_request(pb::DecryptNatsCurveRequest {
                key_id: "nats.curve_box".to_string(),
                sender_public_xkey: peer.public_key(),
                ciphertext: peer_box,
            }))
            .await
            .expect("decrypt succeeds")
            .into_inner()
            .plaintext;
        assert_eq!(decrypted, b"peer-to-broker");

        let denied = service
            .encrypt_nats_curve(authed_request(pb::EncryptNatsCurveRequest {
                key_id: "issuer.account".to_string(),
                recipient_public_xkey: peer.public_key(),
                plaintext: b"wrong class".to_vec(),
            }))
            .await
            .expect_err("policy denies ungranted target");
        assert_eq!(denied.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn grpc_sign_on_issuer_key_is_hard_capped_but_rich_jwt_mints_via_sign_nats_jwt() {
        // Raw `sign` on a NATS operator/account key would let a caller assemble
        // the JWT signing input off-broker and bypass every validation the
        // dedicated `sign_nats_jwt` op enforces (kind, jti mode, ttl/expiry),
        // so the PDP hard-caps it even though the policy grants role:signer
        // over `issuer.*`. The same rich claims still mint through the
        // validated op: rejecting the bypass loses no legitimate capability.
        let operator = KeyPair::new_operator();
        let operator_public = operator.public_key();
        let account = KeyPair::new_account();
        let signing = KeyPair::new_account();
        let exporting = KeyPair::new_account();
        let user = KeyPair::new_user();
        let service = BrokerGrpc::new(state_with_backend(Box::new(NatsSignBackend(operator))));

        let public = service
            .get_public_key(authed_request(pb::GetPublicKeyRequest {
                key_id: "issuer.operator".to_string(),
                version: None,
            }))
            .await
            .expect("public key read succeeds")
            .into_inner()
            .public_key;
        let issuer_nkey = basil_nats::encode_public(basil_nats::NkeyType::Operator, &public)
            .expect("issuer public encodes as operator nkey");
        assert_eq!(issuer_nkey, operator_public);

        let jwt = rich_account_jwt(issuer_nkey, &account, &signing, &exporting, &user);
        let signing_input = jwt.signing_input().expect("rich signing input builds");

        let denied = service
            .sign(authed_request(pb::SignRequest {
                key_id: "issuer.operator".to_string(),
                message: signing_input.as_bytes().to_vec(),
                algorithm: pb::SigningAlgorithm::Ed25519Nkey.into(),
            }))
            .await
            .expect_err("raw sign on an issuer key is hard-capped");
        assert_eq!(denied.code(), Code::PermissionDenied);

        // Route the identical rich claims through the validated minting op.
        let claims_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signing_input.split('.').nth(1).expect("claims part"))
            .expect("claims decode");
        let token = service
            .sign_nats_jwt(authed_request(pb::SignNatsJwtRequest {
                key_id: "issuer.operator".to_string(),
                claims_json,
                expected_type: pb::NatsJwtType::Account.into(),
                ttl: Some(ttl()),
                expires_at: None,
                issued_at: None,
                jti_mode: pb::NatsJtiMode::Rewrite.into(),
            }))
            .await
            .expect("rich account JWT mints through the validated op")
            .into_inner()
            .token;

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: JsonValue = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .expect("claims decode"),
        )
        .expect("claims json");
        let nats = &claims["nats"];
        assert_eq!(
            nats["imports"][0]["local_subject"],
            "R3.$JS.API.CONSUMER.MSG.NEXT.control_delivery"
        );
        assert_eq!(nats["exports"][0]["token_req"], true);
        assert_eq!(nats["limits"]["disk_storage"], 1_073_741_824);
        assert_eq!(nats["default_permissions"]["resp"]["max"], 1);
        assert_eq!(nats["trace"]["dest"], "trace.realm");

        let issuer = KeyPair::from_public_key(claims["iss"].as_str().expect("issuer claim"))
            .expect("issuer public key parses");
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("signature decodes");
        issuer
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .expect("Basil signature verifies under issuer nkey");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn grpc_validate_nats_jwt_reports_authoritative_reasons() {
        let account = KeyPair::new_account();
        let account_public = account.public_key();
        let user = KeyPair::new_user();
        let service = BrokerGrpc::new(state_with_backend(Box::new(NatsSignBackend(account))));

        let token = service
            .sign_nats_jwt(authed_request(pb::SignNatsJwtRequest {
                key_id: "issuer.account".to_string(),
                claims_json: serde_json::to_vec(&serde_json::json!({
                    "sub": user.public_key(),
                    "name": "valid-user",
                    "nats": { "type": "user", "version": 2 }
                }))
                .expect("claims json"),
                expected_type: pb::NatsJwtType::User.into(),
                ttl: Some(ttl()),
                expires_at: None,
                issued_at: None,
                jti_mode: pb::NatsJtiMode::RequireValid.into(),
            }))
            .await
            .expect("sign succeeds")
            .into_inner()
            .token;

        let by_key = service
            .validate_nats_jwt(authed_request(pb::ValidateNatsJwtRequest {
                jwt: token.clone(),
                allowed_signers: vec![pb::AllowedNatsSigner {
                    signer: Some(pb::allowed_nats_signer::Signer::KeyId(
                        "issuer.account".to_string(),
                    )),
                }],
                expected_type: pb::NatsJwtType::User.into(),
            }))
            .await
            .expect("validate by key succeeds")
            .into_inner();
        assert!(by_key.valid);
        assert_eq!(by_key.reason, i32::from(pb::NatsJwtValidationReason::Valid));
        assert_eq!(by_key.issuer, account_public.as_str());
        assert_eq!(by_key.subject, user.public_key());
        assert_eq!(by_key.matched_signer_key_id, "issuer.account");

        let by_public_nkey = service
            .validate_nats_jwt(authed_request(pb::ValidateNatsJwtRequest {
                jwt: token.clone(),
                allowed_signers: vec![pb::AllowedNatsSigner {
                    signer: Some(pb::allowed_nats_signer::Signer::NatsPublicKey(
                        account_public.clone(),
                    )),
                }],
                expected_type: pb::NatsJwtType::User.into(),
            }))
            .await
            .expect("validate by nkey succeeds")
            .into_inner();
        assert!(by_public_nkey.valid);
        assert!(by_public_nkey.matched_signer_key_id.is_empty());

        let wrong_type = service
            .validate_nats_jwt(authed_request(pb::ValidateNatsJwtRequest {
                jwt: token.clone(),
                allowed_signers: Vec::new(),
                expected_type: pb::NatsJwtType::Account.into(),
            }))
            .await
            .expect("wrong type is authoritative")
            .into_inner();
        assert!(!wrong_type.valid);
        assert_eq!(
            wrong_type.reason,
            i32::from(pb::NatsJwtValidationReason::WrongType)
        );

        let unknown = service
            .validate_nats_jwt(authed_request(pb::ValidateNatsJwtRequest {
                jwt: token,
                allowed_signers: vec![pb::AllowedNatsSigner {
                    signer: Some(pb::allowed_nats_signer::Signer::NatsPublicKey(
                        KeyPair::new_operator().public_key(),
                    )),
                }],
                expected_type: pb::NatsJwtType::User.into(),
            }))
            .await
            .expect("unknown signer is authoritative")
            .into_inner();
        assert!(!unknown.valid);
        assert_eq!(
            unknown.reason,
            i32::from(pb::NatsJwtValidationReason::UnknownSigner)
        );

        let malformed = service
            .validate_nats_jwt(authed_request(pb::ValidateNatsJwtRequest {
                jwt: "not-a-jwt".to_string(),
                allowed_signers: Vec::new(),
                expected_type: pb::NatsJwtType::Unspecified.into(),
            }))
            .await
            .expect("malformed is authoritative")
            .into_inner();
        assert!(!malformed.valid);
        assert_eq!(
            malformed.reason,
            i32::from(pb::NatsJwtValidationReason::Malformed)
        );
    }

    #[tokio::test]
    async fn grpc_validate_nats_jwt_requires_a_resolved_subject() {
        let service = BrokerGrpc::new(mint_state());
        // uid 7 resolves to no policy subject: the RPC must fail closed at
        // entry, before the caller-supplied-nkey arm can run (finding 16).
        let mut request = Request::new(pb::ValidateNatsJwtRequest {
            jwt: "not-a-jwt".to_string(),
            allowed_signers: vec![pb::AllowedNatsSigner {
                signer: Some(pb::allowed_nats_signer::Signer::NatsPublicKey(
                    KeyPair::new_account().public_key(),
                )),
            }],
            expected_type: pb::NatsJwtType::Unspecified.into(),
        });
        request.extensions_mut().insert(PeerInfo {
            uid: Some(7),
            ..PeerInfo::default()
        });
        let status = service
            .validate_nats_jwt(request)
            .await
            .expect_err("unresolved peer rejected");
        assert_eq!(status.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn grpc_validate_nats_jwt_caps_jwt_length() {
        let service = BrokerGrpc::new(mint_state());
        let oversized = "a".repeat(service.state.limits().max_payload_size + 1);
        let status = service
            .validate_nats_jwt(authed_request(pb::ValidateNatsJwtRequest {
                jwt: oversized,
                allowed_signers: Vec::new(),
                expected_type: pb::NatsJwtType::Unspecified.into(),
            }))
            .await
            .expect_err("oversized jwt rejected");
        assert_eq!(status.code(), Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn grpc_sign_verify_and_nats_curve_enforce_payload_caps() {
        let service = BrokerGrpc::new(mint_state());
        let over_payload = vec![0u8; service.state.limits().max_payload_size + 1];
        let over_encrypt = vec![0u8; service.state.limits().max_encrypt_size + 1];

        // `issuer.server` (nats_type=N): not a credential issuer, so raw
        // sign/verify pass the PDP hard cap and reach the payload cap.
        let status = service
            .sign(authed_request(pb::SignRequest {
                key_id: "issuer.server".to_string(),
                message: over_payload.clone(),
                algorithm: pb::SigningAlgorithm::Ed25519Nkey.into(),
            }))
            .await
            .expect_err("oversized sign message rejected");
        assert_eq!(status.code(), Code::ResourceExhausted);

        let status = service
            .verify(authed_request(pb::VerifyRequest {
                key_id: "issuer.server".to_string(),
                message: Vec::new(),
                signature: over_payload,
                algorithm: pb::SigningAlgorithm::Ed25519Nkey.into(),
            }))
            .await
            .expect_err("oversized verify signature rejected");
        assert_eq!(status.code(), Code::ResourceExhausted);

        let status = service
            .encrypt_nats_curve(authed_request(pb::EncryptNatsCurveRequest {
                key_id: "nats.curve_box".to_string(),
                recipient_public_xkey: String::new(),
                plaintext: over_encrypt.clone(),
            }))
            .await
            .expect_err("oversized curve plaintext rejected");
        assert_eq!(status.code(), Code::ResourceExhausted);

        let status = service
            .decrypt_nats_curve(authed_request(pb::DecryptNatsCurveRequest {
                key_id: "nats.curve_box".to_string(),
                sender_public_xkey: String::new(),
                ciphertext: over_encrypt,
            }))
            .await
            .expect_err("oversized curve ciphertext rejected");
        assert_eq!(status.code(), Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn grpc_nats_unsupported_issuer_role_is_invalid_argument() {
        let service = BrokerGrpc::new(mint_state());
        let status = service
            .mint_nats_server(authed_request(pb::MintNatsServerRequest {
                key_id: "issuer.operator".to_string(),
                subject_server_nkey: basil_nats::encode_public(
                    basil_nats::NkeyType::Server,
                    &[5; 32],
                )
                .expect("test server public key encodes"),
                name: "server".to_string(),
                ttl: Some(ttl()),
            }))
            .await
            .expect_err("operator issuer is invalid for server mint");
        let info = error_info(&status);
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(info.reason, "INVALID_REQUEST");
        assert_eq!(info.op, "mint_nats_server");
    }

    #[tokio::test]
    async fn watch_requires_peer_uid() {
        let service = BrokerGrpc::new(mint_state());
        let Err(status) = service
            .watch(Request::new(pb::WatchRequest { kinds: Vec::new() }))
            .await
        else {
            panic!("missing uid should be rejected");
        };
        assert_eq!(status.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn watch_filters_key_rotation_and_allows_public_events() {
        use futures::StreamExt as _;

        let state = mint_state();
        let service = BrokerGrpc::new(Arc::clone(&state));
        let mut stream = service
            .watch(authed_request(pb::WatchRequest { kinds: Vec::new() }))
            .await
            .expect("watch opens")
            .into_inner();

        state.events().key_rotated("hidden.key", 2);
        state.events().bundle_changed("example.org");

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .expect("event arrives")
            .expect("stream item")
            .expect("event ok");
        assert_eq!(event.kind, i32::from(pb::EventKind::BundleChanged));
        assert!(matches!(
            event.detail,
            Some(pb::event::Detail::BundleChanged(_))
        ));

        state.events().key_rotated("issuer.account", 3);
        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .expect("event arrives")
            .expect("stream item")
            .expect("event ok");
        assert_eq!(event.kind, i32::from(pb::EventKind::KeyRotated));
        assert!(matches!(
            event.detail,
            Some(pb::event::Detail::KeyRotated(_))
        ));
    }

    #[tokio::test]
    async fn watch_emits_revocation_events() {
        use futures::StreamExt as _;

        let state = mint_state();
        let service = BrokerGrpc::new(Arc::clone(&state));
        let mut stream = service
            .watch(authed_request(pb::WatchRequest {
                kinds: vec![i32::from(pb::EventKind::Revoked)],
            }))
            .await
            .expect("watch opens")
            .into_inner();

        state
            .revoke_jwt_svid(
                "example.org",
                "test-jti",
                jsonwebtoken::get_current_timestamp().saturating_add(300),
            )
            .await
            .expect("revoked jti stored");

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), stream.next())
            .await
            .expect("event arrives")
            .expect("stream item")
            .expect("event ok");
        assert_eq!(event.kind, i32::from(pb::EventKind::Revoked));
        let Some(pb::event::Detail::Revoked(revoked)) = event.detail else {
            panic!("revoked detail expected");
        };
        assert_eq!(revoked.trust_domain, "example.org");
        assert_eq!(revoked.id, "test-jti");
    }
}
