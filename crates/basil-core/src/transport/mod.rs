//! Shared tonic transport helpers for broker services.
//!
//! The tonic server stores peer identity in request extensions before service
//! adapters authorize an operation. Tests may inject [`PeerInfo`] directly;
//! production UDS requests are converted from tonic's captured Unix credentials.

#![allow(clippy::result_large_err)]

pub mod grpc_server;

use prost::Message;
use tonic::codegen::Bytes;
use tonic::codegen::http::Extensions;
use tonic::transport::server::UdsConnectInfo;
use tonic::{Code, Request, Status};

use crate::actor::{AuthenticatedActor, SubjectResolutionError};
use crate::catalog::policy::Op;
use crate::decision::{DecisionRecord, op_token};
use crate::peer::PeerInfo;
use crate::state::BrokerState;

/// Resolve the attested peer from a tonic request.
#[must_use]
pub fn peer_from_request<T>(request: &Request<T>) -> PeerInfo {
    peer_from_extensions(request.extensions())
}

/// Authorize one key-scoped operation using the shared broker PDP.
///
/// # Errors
///
/// Returns `UNAUTHENTICATED` when no peer uid is present and
/// `PERMISSION_DENIED` when policy denies the operation.
pub fn authorize<T>(
    state: &BrokerState,
    request: &Request<T>,
    op: Op,
    key: &str,
) -> Result<AuthenticatedActor, Status> {
    authorize_extensions(state, request.extensions(), op, key)
}

fn peer_from_extensions(extensions: &Extensions) -> PeerInfo {
    if let Some(peer) = extensions.get::<PeerInfo>() {
        return peer.clone();
    }

    extensions
        .get::<UdsConnectInfo>()
        .and_then(|info| info.peer_cred.as_ref())
        .map_or_else(PeerInfo::default, |cred| {
            PeerInfo::from_unix_cred(cred.pid().map(i32::cast_unsigned), cred.uid(), cred.gid())
        })
}

fn authorize_extensions(
    state: &BrokerState,
    extensions: &Extensions,
    op: Op,
    key: &str,
) -> Result<AuthenticatedActor, Status> {
    // Pin one generation snapshot for the whole authorization decision so a
    // concurrent reload can never mix an old catalog with a new policy.
    let generation = state.load_generation();
    let peer = peer_from_extensions(extensions);
    let actor = generation.pdp().resolve_local_actor(&peer).map_err(|err| {
        record_resolution_error(state, generation.id(), &peer, op, key, &err);
        resolution_status(op, &err)
    })?;

    let decision = generation.pdp().decide(&actor, op, key);
    state.record_decision(&DecisionRecord::from_actor_decision(
        generation.id(),
        &actor,
        op,
        key,
        &decision,
    ));
    if decision.is_deny() {
        return Err(broker_status(
            Code::PermissionDenied,
            "UNAUTHORIZED",
            op_token(op),
            "not authorized",
        ));
    }

    Ok(actor)
}

fn record_resolution_error(
    state: &BrokerState,
    generation: u64,
    peer: &PeerInfo,
    op: Op,
    key: &str,
    err: &SubjectResolutionError,
) {
    let reason = match err {
        SubjectResolutionError::MissingPeerCredentials => "no_actor_subject".to_string(),
        SubjectResolutionError::NoSubject { uid } => {
            format!("no_actor_subject:{uid}")
        }
        SubjectResolutionError::AmbiguousSubject { uid, .. } => {
            format!("ambiguous_actor_subject:{uid}")
        }
        SubjectResolutionError::InvalidUnauthenticatedSubject { subject } => {
            format!("invalid_unauthenticated_subject:{subject}")
        }
    };
    state.record_decision(&DecisionRecord::from_resolution_error(
        generation, peer, op, key, reason,
    ));
}

fn resolution_status(op: Op, err: &SubjectResolutionError) -> Status {
    match err {
        SubjectResolutionError::MissingPeerCredentials => broker_status(
            Code::Unauthenticated,
            "UNAUTHENTICATED",
            op_token(op),
            "missing peer credentials",
        ),
        SubjectResolutionError::NoSubject { .. }
        | SubjectResolutionError::AmbiguousSubject { .. }
        | SubjectResolutionError::InvalidUnauthenticatedSubject { .. } => broker_status(
            Code::PermissionDenied,
            "UNAUTHORIZED",
            op_token(op),
            "not authorized",
        ),
    }
}

/// Build a tonic status with Basil's machine-readable broker error detail.
#[must_use]
pub fn broker_status(
    code: Code,
    reason: &'static str,
    op: &'static str,
    message: impl Into<String>,
) -> Status {
    let info = basil_proto::broker::v1::BrokerErrorInfo {
        reason: reason.to_string(),
        op: op.to_string(),
    };
    let detail = prost_types::Any {
        type_url: "type.googleapis.com/basil.broker.v1.BrokerErrorInfo".to_string(),
        value: info.encode_to_vec(),
    };
    let status = basil_proto::google::rpc::Status {
        code: code as i32,
        message: message.into(),
        details: vec![detail],
    };
    Status::with_details(
        code,
        status.message.clone(),
        Bytes::from(status.encode_to_vec()),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use async_trait::async_trait;
    use basil_proto::KeyType;
    use basil_proto::broker::v1::BrokerErrorInfo;
    use basil_proto::google::rpc::Status as RpcStatus;
    use prost::Message;
    use tonic::Code;

    use super::*;
    use crate::backend::{Backend, BackendError, NewKey};
    use crate::catalog::load;
    use crate::manager::BackendManager;

    const CATALOG: &str = r#"{
      "schemaVersion": 1,
      "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
      "keys": {
        "app.secret": {
          "class": "value", "backend": "bao", "engine": "kv2",
          "path": "secret/data/app", "writable": true,
          "missing": "error", "description": "application secret"
        }
      }
    }"#;

    const POLICY: &str = r#"{
      "schemaVersion": 2,
      "subjects": {
        "svc.app": { "allOf": [ { "kind": "unix", "uid": 42 } ] }
      },
      "roles": { "reader": ["get"] },
      "rules": [
        { "id": "reader", "subjects": ["svc.app"], "action": ["role:reader"], "target": ["app.secret"] }
      ],
      "config": {
        "names": { "users": { "42": "svc-app" }, "groups": {} },
        "memberships": { "42": [42] }
      }
    }"#;

    struct DummyBackend;

    #[async_trait]
    impl Backend for DummyBackend {
        fn kind(&self) -> &'static str {
            "dummy"
        }

        async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
            let _ = key_type;
            Err(BackendError::Unsupported("new_key"))
        }

        async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
            let _ = key_id;
            Err(BackendError::Unsupported("public_key"))
        }

        async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
            let _ = (key_id, message);
            Err(BackendError::Unsupported("sign"))
        }

        async fn verify(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, BackendError> {
            let _ = (key_id, message, signature);
            Err(BackendError::Unsupported("verify"))
        }
    }

    fn state() -> BrokerState {
        let (catalog, policy, config, warnings) = load(CATALOG, POLICY).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".to_string(), Box::new(DummyBackend));
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        BrokerState::new(catalog, policy, config, manager, "dummy")
    }

    fn request_with_uid(uid: u32) -> Request<()> {
        let mut request = Request::new(());
        request.extensions_mut().insert(PeerInfo {
            uid: Some(uid),
            ..PeerInfo::default()
        });
        request
    }

    #[test]
    fn authorize_allows_policy_visible_peer() {
        let state = state();
        let request = request_with_uid(42);
        let actor = authorize(&state, &request, Op::Get, "app.secret").expect("authorized");
        assert_eq!(actor.subject, "svc.app");
        assert_eq!(actor.unix_uid(), Some(42));
    }

    #[test]
    fn authorize_denies_policy_miss() {
        let state = state();
        let request = request_with_uid(7);
        let status = authorize(&state, &request, Op::Get, "app.secret").expect_err("denied");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[test]
    fn authorize_rejects_missing_peer_uid() {
        let state = state();
        let request = Request::new(());
        let status = authorize(&state, &request, Op::Get, "app.secret").expect_err("no uid");
        assert_eq!(status.code(), Code::Unauthenticated);
    }

    #[test]
    fn peer_from_request_prefers_inserted_peerinfo() {
        let request = request_with_uid(99);
        assert_eq!(peer_from_request(&request).uid, Some(99));
    }

    #[test]
    fn broker_status_carries_error_info_detail() {
        let status = broker_status(Code::InvalidArgument, "INVALID_REQUEST", "sign", "bad");
        let rpc = RpcStatus::decode(status.details()).expect("details decode");
        assert_eq!(rpc.code, Code::InvalidArgument as i32);
        assert_eq!(rpc.message, "bad");
        let detail = rpc.details.first().expect("detail present");
        assert_eq!(
            detail.type_url,
            "type.googleapis.com/basil.broker.v1.BrokerErrorInfo"
        );
        let info = BrokerErrorInfo::decode(detail.value.as_slice()).expect("info decodes");
        assert_eq!(info.reason, "INVALID_REQUEST");
        assert_eq!(info.op, "sign");
    }
}
