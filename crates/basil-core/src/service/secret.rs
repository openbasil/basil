#![allow(clippy::result_large_err)]

// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use basil_proto::broker::v1 as pb;
use basil_proto::broker::v1::secret_service_server::SecretService;
use tonic::{Request, Response};

use crate::catalog::policy::Op;
use crate::service::broker::{BoxStream, BrokerGrpc, GrpcResult};
use crate::service::shared::{catalog_entry, manager_status, payload_too_large};
use crate::transport::peer_from_request;

#[tonic::async_trait]
impl SecretService for BrokerGrpc {
    type ListCatalogStream = BoxStream<pb::CatalogEntry>;

    async fn get_secret(
        &self,
        request: Request<pb::GetSecretRequest>,
    ) -> GrpcResult<pb::GetSecretResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Get, &body.secret_id)?;
        let mut secret = self
            .state
            .manager()
            .get(&body.secret_id, body.version)
            .await
            .map_err(|e| manager_status("get_secret", &e))?;
        Ok(Response::new(pb::GetSecretResponse {
            // Move (never copy) the bytes out of the `Zeroizing` chain: the
            // proto field is then the only plain copy, and the response
            // zeroizes it on drop after tonic encodes it (finding 17).
            value: std::mem::take(&mut *secret.value),
            version: secret.version,
        }))
    }

    async fn set_secret(
        &self,
        request: Request<pb::SetSecretRequest>,
    ) -> GrpcResult<pb::SetSecretResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Set, &body.secret_id)?;
        if body.value.len() > self.state.limits().max_payload_size {
            return Err(payload_too_large(
                "set_secret",
                "set payload exceeds configured cap",
            ));
        }
        let version = self
            .state
            .manager()
            .set(&body.secret_id, &body.value)
            .await
            .map_err(|e| manager_status("set_secret", &e))?;
        Ok(Response::new(pb::SetSecretResponse { version }))
    }

    async fn rotate_secret(
        &self,
        request: Request<pb::RotateSecretRequest>,
    ) -> GrpcResult<pb::RotateSecretResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Rotate, &body.secret_id)?;
        let version = self
            .state
            .manager()
            .rotate(&body.secret_id, self.state.limits())
            .await
            .map_err(|e| manager_status("rotate_secret", &e))?;
        self.state.events().key_rotated(&body.secret_id, version);
        Ok(Response::new(pb::RotateSecretResponse { version }))
    }

    async fn list_catalog(
        &self,
        request: Request<pb::ListCatalogRequest>,
    ) -> GrpcResult<Self::ListCatalogStream> {
        let peer = peer_from_request(&request);
        let generation = self.state.load_generation();
        let Ok(actor) = generation.pdp().resolve_local_actor(&peer) else {
            return Ok(Response::new(Box::pin(futures::stream::empty())));
        };
        let body = request.get_ref();
        let entries = self
            .state
            .manager()
            .list(body.prefix.as_deref(), |key| self.visible(&actor, key))
            .await
            .map_err(|e| manager_status("list_catalog", &e))?
            .into_iter()
            .map(|entry| Ok(catalog_entry(entry)));
        Ok(Response::new(Box::pin(futures::stream::iter(entries))))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use async_trait::async_trait;
    use basil_proto::KeyType;
    use basil_proto::broker::v1 as pb;
    use basil_proto::broker::v1::secret_service_server::SecretService;
    use tonic::Request;

    use crate::backend::{Backend, BackendError, NewKey};
    use crate::catalog::load;
    use crate::event::BrokerEventKind;
    use crate::manager::BackendManager;
    use crate::peer::PeerInfo;
    use crate::service::broker::BrokerGrpc;
    use crate::state::BrokerState;

    /// A minimal crypto backend that supports `rotate`, bumping and returning an
    /// incrementing version (mirroring a transit version bump), so the real
    /// `rotate_secret` RPC completes and reaches its event-emission line. Every
    /// material-bearing method errors: the rotate-event path needs none of them,
    /// and `configure_versions` is left at its `Unsupported` default (the manager
    /// treats that as a no-op grace application).
    struct RotateBackend {
        version: AtomicU32,
    }

    #[async_trait]
    impl Backend for RotateBackend {
        fn kind(&self) -> &'static str {
            "rotate-test"
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
        async fn rotate(&self, _key_id: &str) -> Result<u32, BackendError> {
            // Bump v_n -> v_{n+1} and report the new latest version.
            Ok(self.version.fetch_add(1, Ordering::SeqCst) + 1)
        }
    }

    /// A broker state whose only key is a writable asymmetric key routed to the
    /// rotate-capable backend, with a policy that grants `uid 42` the `rotate` op
    /// over it.
    fn rotate_state() -> Arc<BrokerState> {
        let catalog = r#"{
          "schemaVersion": 1,
          "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
          "keys": {
            "app.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
              "path": "app/signer", "writable": true, "missing": "error",
              "description": "a rotatable signing key"
            }
          }
        }"#;
        let policy = r#"{
          "schemaVersion": 2,
          "subjects": {
            "svc.ops": { "allOf": [ { "kind": "unix", "uid": 42 } ] }
          },
          "roles": { "rotator": ["rotate"] },
          "rules": [
            { "id": "rot", "subjects": ["svc.ops"], "action": ["role:rotator"], "target": ["app.*"] }
          ],
          "config": {
            "names": { "users": { "42": "svc-ops" }, "groups": {} },
            "memberships": { "42": [42] }
          }
        }"#;
        let (catalog, policy, config, warnings) = load(catalog, policy).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert(
            "bao".to_string(),
            Box::new(RotateBackend {
                version: AtomicU32::new(1),
            }),
        );
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        Arc::new(BrokerState::new(
            catalog,
            policy,
            config,
            manager,
            "rotate-test",
        ))
    }

    fn authed_request<T>(body: T) -> Request<T> {
        let mut request = Request::new(body);
        request.extensions_mut().insert(PeerInfo {
            uid: Some(42),
            ..PeerInfo::default()
        });
        request
    }

    /// The REAL `rotate_secret` RPC publishes a `KeyRotated` broker event carrying
    /// the rotated key id and its new version. This is the emission side of the
    /// Watch `KeyRotated` feed. The delivery side (a subscribed Watch stream
    /// receiving `KeyRotated`/`BundleChanged`) is covered by `broker.rs`'s
    /// `watch_filters_key_rotation_and_allows_public_events`.
    #[tokio::test]
    async fn rotate_secret_publishes_key_rotated_event() {
        let state = rotate_state();
        let service = BrokerGrpc::new(Arc::clone(&state));
        let mut events = state.events().subscribe();

        let resp = SecretService::rotate_secret(
            &service,
            authed_request(pb::RotateSecretRequest {
                secret_id: "app.signer".to_string(),
            }),
        )
        .await
        .expect("authorized rotate succeeds")
        .into_inner();
        assert_eq!(resp.version, 2, "rotate bumps v1 -> v2");

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
            .await
            .expect("event arrives within timeout")
            .expect("event received");
        assert_eq!(
            event.kind,
            BrokerEventKind::KeyRotated {
                key_id: "app.signer".to_string(),
                new_version: 2,
            },
            "rotate_secret emits KeyRotated with the new version"
        );
    }
}
