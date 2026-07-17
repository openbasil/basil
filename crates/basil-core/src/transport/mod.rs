// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared tonic transport helpers for broker services.
//!
//! The tonic server stores peer identity in request extensions before service
//! adapters authorize an operation. Tests may inject [`PeerInfo`] directly;
//! production UDS requests are converted from tonic's captured Unix credentials.

#![allow(clippy::result_large_err)]

pub mod connection;
pub mod grpc_server;
pub mod listener;
pub mod listener_manager;

use prost::Message;
use rand::Rng as _;
use tonic::codegen::Bytes;
use tonic::codegen::http::Extensions;
use tonic::transport::server::UdsConnectInfo;
use tonic::{Code, Request, Status};

use crate::actor::{AuthenticatedActor, SubjectResolutionError};
use crate::catalog::policy::Op;
use crate::catalog::{AuthorizationDomain, EvidenceState};
use crate::decision::{DecisionRecord, op_token};
use crate::peer::PeerInfo;
use crate::state::{BrokerState, Generation};
use connection::ListenerConnectInfo;

// Wire-exact private encoding of the standard `google.rpc.RetryInfo` message.
// Keeping this local avoids expanding Basil's generated protocol surface; the
// standard type URL lets clients decode it with their Google RPC library.
#[derive(Clone, PartialEq, Message)]
struct RetryInfoDetail {
    #[prost(message, optional, tag = "1")]
    retry_delay: Option<prost_types::Duration>,
}

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
    let generation = state.load_generation();
    authorize_extensions_in_generation(state, &generation, request.extensions(), op, key)
}

/// Authorize one key-scoped operation against a caller-pinned generation.
///
/// Use this when a multi-entry operation must validate every entry against the
/// same catalog/policy/config snapshot even if reload swaps the active
/// generation while the operation is still validating.
///
/// # Errors
///
/// Returns `UNAUTHENTICATED` when no peer uid is present and
/// `PERMISSION_DENIED` when policy denies the operation.
pub fn authorize_in_generation<T>(
    state: &BrokerState,
    generation: &Generation,
    request: &Request<T>,
    op: Op,
    key: &str,
) -> Result<AuthenticatedActor, Status> {
    authorize_extensions_in_generation(state, generation, request.extensions(), op, key)
}

fn peer_from_extensions(extensions: &Extensions) -> PeerInfo {
    if let Some(peer) = extensions.get::<PeerInfo>() {
        return peer.clone();
    }
    if let Some(info) = extensions.get::<ListenerConnectInfo>() {
        return info.peer().clone();
    }
    extensions
        .get::<UdsConnectInfo>()
        .and_then(|info| info.peer_cred.as_ref())
        .map_or_else(PeerInfo::default, |cred| {
            PeerInfo::from_unix_cred(cred.pid().map(i32::cast_unsigned), cred.uid(), cred.gid())
        })
}

fn authorize_extensions_in_generation(
    state: &BrokerState,
    generation: &Generation,
    extensions: &Extensions,
    op: Op,
    key: &str,
) -> Result<AuthenticatedActor, Status> {
    let peer = peer_from_extensions(extensions);
    let actor = generation.pdp().resolve_local_actor(&peer).map_err(|err| {
        record_resolution_error(state, generation.id(), &peer, op, key, &err);
        resolution_status(op, &err)
    })?;
    enforce_listener_domain_extensions(state, generation.id(), extensions, &actor, op, key)?;

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

/// Enforce typed-listener domain admission for a previously resolved actor.
///
/// Services with custom authorization flows use this before their first policy
/// decision.
pub(crate) fn enforce_listener_domain<T>(
    state: &BrokerState,
    generation: u64,
    request: &Request<T>,
    actor: &AuthenticatedActor,
    op: Op,
    key: &str,
) -> Result<(), Status> {
    enforce_listener_domain_extensions(state, generation, request.extensions(), actor, op, key)
}

fn enforce_listener_domain_extensions(
    state: &BrokerState,
    generation: u64,
    extensions: &Extensions,
    actor: &AuthenticatedActor,
    op: Op,
    key: &str,
) -> Result<(), Status> {
    let Some(listener) = extensions.get::<ListenerConnectInfo>() else {
        state.record_decision(&DecisionRecord::from_actor_evidence_denial(
            generation,
            actor,
            op,
            key,
            EvidenceState::Unavailable,
            "listener_context_unavailable",
        ));
        return Err(broker_status(
            Code::Unavailable,
            "LISTENER_CONTEXT_UNAVAILABLE",
            op_token(op),
            "listener context unavailable",
        ));
    };
    state
        .connections()
        .record_actor(listener.connection_id(), actor);
    let admitted = match listener.listener_type() {
        grpc_server::ListenerType::Host => matches!(
            actor.domain,
            AuthorizationDomain::HostProcess | AuthorizationDomain::SystemdUnit
        ),
        grpc_server::ListenerType::Container => actor.domain == AuthorizationDomain::Container,
    };
    if admitted {
        return Ok(());
    }

    state.record_decision(&DecisionRecord::from_actor_evidence_denial(
        generation,
        actor,
        op,
        key,
        EvidenceState::NoMatch,
        "listener_domain_mismatch",
    ));
    Err(broker_status(
        Code::PermissionDenied,
        "LISTENER_DOMAIN_MISMATCH",
        op_token(op),
        "listener does not admit resolved workload domain",
    ))
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
        SubjectResolutionError::MissingPeerCredentials
        | SubjectResolutionError::NoSubject { .. } => "no_actor_subject".to_string(),
        SubjectResolutionError::DomainUnavailable => "workload_domain_unavailable".to_string(),
        SubjectResolutionError::AmbiguousSubject { .. } => "ambiguous_actor_subject".to_string(),
        SubjectResolutionError::EvidenceUnavailable { .. } => "attestation_unavailable".to_string(),
    };
    state.record_decision(&DecisionRecord::from_subject_resolution_error(
        generation, peer, op, key, err, &reason,
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
        SubjectResolutionError::DomainUnavailable
        | SubjectResolutionError::EvidenceUnavailable { .. } => {
            attestation_unavailable_status(op_token(op))
        }
        SubjectResolutionError::NoSubject { .. }
        | SubjectResolutionError::AmbiguousSubject { .. } => broker_status(
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
    broker_status_with_details(code, reason, op, message, Vec::new())
}

/// Build a transient attestation status with bounded, server-jittered retry
/// guidance.
#[must_use]
pub fn attestation_unavailable_status(op: &'static str) -> Status {
    let retry_millis = rand::thread_rng().gen_range(100_i32..=500_i32);
    let retry = RetryInfoDetail {
        retry_delay: Some(prost_types::Duration {
            seconds: 0,
            nanos: retry_millis * 1_000_000,
        }),
    };
    let detail = prost_types::Any {
        type_url: "type.googleapis.com/google.rpc.RetryInfo".to_string(),
        value: retry.encode_to_vec(),
    };
    broker_status_with_details(
        Code::Unavailable,
        "ATTESTATION_UNAVAILABLE",
        op,
        "attestation unavailable",
        vec![detail],
    )
}

fn broker_status_with_details(
    code: Code,
    reason: &'static str,
    op: &'static str,
    message: impl Into<String>,
    mut extra_details: Vec<prost_types::Any>,
) -> Status {
    let info = basil_proto::broker::v1::BrokerErrorInfo {
        reason: reason.to_string(),
        op: op.to_string(),
    };
    let detail = prost_types::Any {
        type_url: "type.googleapis.com/basil.broker.v1.BrokerErrorInfo".to_string(),
        value: info.encode_to_vec(),
    };
    let mut details = vec![detail];
    details.append(&mut extra_details);
    let status = basil_proto::google::rpc::Status {
        code: code as i32,
        message: message.into(),
        details,
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
    use std::sync::Arc;

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

    #[derive(Clone, PartialEq, Message)]
    struct StandardRetryInfo {
        #[prost(message, optional, tag = "1")]
        retry_delay: Option<prost_types::Duration>,
    }

    const CATALOG: &str = r#"{
      "schema": "catalog",
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
      "schema": "policy",
      "subjects": {
        "svc.app": { "domain": "host-process", "match": { "all": [ { "process.uid": 42 } ] } }
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

    const DENY_POLICY: &str = r#"{
      "schema": "policy",
      "subjects": {
        "svc.app": { "domain": "host-process", "match": { "all": [ { "process.uid": 42 } ] } }
      },
      "roles": {},
      "rules": [],
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
        request
            .extensions_mut()
            .insert(ListenerConnectInfo::for_test(
                "host",
                grpc_server::ListenerType::Host,
                PeerInfo {
                    uid: Some(uid),
                    ..PeerInfo::default()
                },
            ));
        request
    }

    fn request_on_listener(uid: u32, listener_type: grpc_server::ListenerType) -> Request<()> {
        let mut request = Request::new(());
        request
            .extensions_mut()
            .insert(ListenerConnectInfo::for_test(
                "test",
                listener_type,
                PeerInfo {
                    uid: Some(uid),
                    ..PeerInfo::default()
                },
            ));
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
    fn container_listener_rejects_resolved_host_domain_before_policy() {
        let state = state();
        let request = request_on_listener(42, grpc_server::ListenerType::Container);
        let status = authorize(&state, &request, Op::Get, "app.secret")
            .expect_err("host domain must not enter container-listener policy");
        assert_eq!(status.code(), Code::PermissionDenied);
        let rpc = RpcStatus::decode(status.details()).expect("details decode");
        let detail = rpc.details.first().expect("detail present");
        let info = BrokerErrorInfo::decode(detail.value.as_slice()).expect("info decodes");
        assert_eq!(info.reason, "LISTENER_DOMAIN_MISMATCH");
    }

    #[test]
    fn authorize_in_generation_uses_pinned_policy_after_active_swap() {
        let state = state();
        let request = request_with_uid(42);
        let pinned = state.load_generation();

        let (catalog, policy, config, warnings) =
            load(CATALOG, DENY_POLICY).expect("deny fixture loads");
        assert!(warnings.is_empty());
        state.swap_generation(Arc::new(Generation::new(2, catalog, policy, config)));

        let actor = authorize_in_generation(&state, &pinned, &request, Op::Get, "app.secret")
            .expect("pinned allow generation still authorizes");
        assert_eq!(actor.subject, "svc.app");

        let status = authorize(&state, &request, Op::Get, "app.secret")
            .expect_err("fresh active generation denies");
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
    fn authorize_fails_closed_when_listener_context_is_missing() {
        let state = state();
        let mut request = Request::new(());
        request.extensions_mut().insert(PeerInfo {
            uid: Some(42),
            ..PeerInfo::default()
        });
        let status = authorize(&state, &request, Op::Get, "app.secret")
            .expect_err("missing listener context must fail closed");
        assert_eq!(status.code(), Code::Unavailable);
        let rpc = RpcStatus::decode(status.details()).expect("details decode");
        let detail = rpc.details.first().expect("detail present");
        let info = BrokerErrorInfo::decode(detail.value.as_slice()).expect("info decodes");
        assert_eq!(info.reason, "LISTENER_CONTEXT_UNAVAILABLE");
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

    #[test]
    fn attestation_unavailable_carries_bounded_retry_info() {
        let status = attestation_unavailable_status("get");
        assert_eq!(status.code(), Code::Unavailable);
        let rpc = RpcStatus::decode(status.details()).expect("details decode");
        assert_eq!(rpc.details.len(), 2);
        let info_detail = rpc.details.first().expect("error info");
        let info = BrokerErrorInfo::decode(info_detail.value.as_slice()).expect("info decodes");
        assert_eq!(info.reason, "ATTESTATION_UNAVAILABLE");
        let retry =
            StandardRetryInfo::decode(rpc.details.get(1).expect("retry detail").value.as_slice())
                .expect("standard retry info wire shape decodes");
        let delay = retry.retry_delay.expect("retry delay");
        assert_eq!(delay.seconds, 0);
        assert!((100_000_000..=500_000_000).contains(&delay.nanos));
    }
}
