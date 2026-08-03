// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]
#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::time::Duration;

use basil_courier::{
    CourierCallError, CourierConnectError, InvocationCourierClient, TrustedUdsPolicy,
};
use basil_proto::broker::v1::invocation_service_server::{
    InvocationService, InvocationServiceServer,
};
use basil_proto::broker::v1::{
    GetInvocationCapabilitiesRequest, GetInvocationCapabilitiesResponse,
    GetInvocationChallengeRequest, GetInvocationChallengeResponse, ListenerProfile, SealedRequest,
    SealedResponse,
};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

#[tokio::test]
async fn https_backend_rejects_host_and_container_capabilities() {
    for profile in [ListenerProfile::Host, ListenerProfile::Container] {
        let service = TestInvocation::new(profile);
        let mut fixture = SocketFixture::bind();
        let policy = fixture.policy();
        let server = fixture.serve(service);
        let result = InvocationCourierClient::connect(
            policy,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await;
        assert!(matches!(
            result,
            Err(CourierConnectError::CapabilityMismatch)
        ));
        server.abort();
    }
}

#[tokio::test]
async fn https_backend_rechecks_capability_before_each_forward() {
    let service = TestInvocation::new(ListenerProfile::Courier);
    let profile = Arc::clone(&service.profile);
    let forwards = Arc::clone(&service.forwards);
    let mut fixture = SocketFixture::bind();
    let policy = fixture.policy();
    let server = fixture.serve(service);
    let client =
        InvocationCourierClient::connect(policy, Duration::from_secs(2), Duration::from_secs(2))
            .await
            .unwrap();

    profile.store(ListenerProfile::Host as i32, Ordering::SeqCst);
    let challenge = client
        .get_challenge(
            GetInvocationChallengeRequest {
                jkt: vec![7; 32],
                courier_observed_source: None,
            },
            "192.0.2.1",
        )
        .await;
    assert_eq!(challenge.unwrap_err(), CourierCallError::CapabilityMismatch);
    let invoke = client
        .invoke(SealedRequest {
            message: b"opaque".to_vec(),
        })
        .await;
    assert_eq!(invoke.unwrap_err(), CourierCallError::CapabilityMismatch);
    assert_eq!(forwards.load(Ordering::SeqCst), 0);
    server.abort();
}

struct SocketFixture {
    root: PathBuf,
    listener: Option<UnixListener>,
    uid: u32,
}

impl SocketFixture {
    fn bind() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        let uid = rustix::process::geteuid().as_raw();
        let root = PathBuf::from(format!("/run/user/{uid}")).join(format!(
            ".https-capability-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("socket")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(root.join("socket"), fs::Permissions::from_mode(0o750)).unwrap();
        let path = root.join("socket/basil.sock");
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        Self {
            root,
            listener: Some(listener),
            uid,
        }
    }

    fn policy(&self) -> TrustedUdsPolicy {
        TrustedUdsPolicy {
            socket_path: self.root.join("socket/basil.sock"),
            service_owner_uid: self.uid,
            directory_owner_uid: self.uid,
            directory_mode: 0o750,
            socket_owner_uid: self.uid,
            socket_mode: 0o660,
            expected_peer_uid: self.uid,
        }
    }

    fn serve(&mut self, service: TestInvocation) -> tokio::task::JoinHandle<()> {
        let listener = self.listener.take().unwrap();
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(InvocationServiceServer::new(service))
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await;
        })
    }
}

impl Drop for SocketFixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.root.join("socket/basil.sock"));
        let _ = fs::remove_dir(self.root.join("socket"));
        let _ = fs::remove_dir(&self.root);
    }
}

#[derive(Clone)]
struct TestInvocation {
    profile: Arc<AtomicI32>,
    forwards: Arc<AtomicUsize>,
}

impl TestInvocation {
    fn new(profile: ListenerProfile) -> Self {
        Self {
            profile: Arc::new(AtomicI32::new(profile as i32)),
            forwards: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[tonic::async_trait]
impl InvocationService for TestInvocation {
    async fn invoke(
        &self,
        request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        self.forwards.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(SealedResponse {
            message: request.into_inner().message,
            response_subject: None,
        }))
    }

    async fn get_invocation_challenge(
        &self,
        _request: Request<GetInvocationChallengeRequest>,
    ) -> Result<Response<GetInvocationChallengeResponse>, Status> {
        self.forwards.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(GetInvocationChallengeResponse {
            challenge: vec![3; 32],
            generation: 1,
            expires_at_unix: 60,
        }))
    }

    async fn get_invocation_capabilities(
        &self,
        _request: Request<GetInvocationCapabilitiesRequest>,
    ) -> Result<Response<GetInvocationCapabilitiesResponse>, Status> {
        Ok(Response::new(GetInvocationCapabilitiesResponse {
            listener_profile: self.profile.load(Ordering::SeqCst),
            require_challenge: true,
            courier_protocol_version: 1,
        }))
    }
}
