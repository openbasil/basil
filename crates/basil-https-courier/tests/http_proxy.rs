// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

use std::fs;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use basil_https_courier::{BasilSocketConfig, Config, Limits, ListenerConfig, run};
use basil_proto::broker::v1::invocation_service_server::{
    InvocationService, InvocationServiceServer,
};
use basil_proto::broker::v1::{
    GetInvocationCapabilitiesRequest, GetInvocationCapabilitiesResponse,
    GetInvocationChallengeRequest, GetInvocationChallengeResponse, ListenerProfile, SealedRequest,
    SealedResponse,
};
use prost::Message;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsConnector;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

const TEST_WAIT: Duration = Duration::from_secs(2);

struct TestTask<T> {
    handle: Option<tokio::task::JoinHandle<T>>,
}

impl<T> TestTask<T> {
    const fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    #[allow(clippy::panic)]
    async fn join(mut self) -> T {
        let result = tokio::time::timeout(TEST_WAIT, self.handle.as_mut().unwrap()).await;
        if let Ok(result) = result {
            self.handle.take();
            return result.expect("test task panicked");
        }

        let _aborted = self.abort_and_reap().await;
        panic!("test task join timed out");
    }

    async fn abort_and_join(mut self) {
        let result = self.abort_and_reap().await;
        if let Err(error) = result {
            assert!(error.is_cancelled(), "test task panicked: {error}");
        }
    }

    async fn abort_and_reap(&mut self) -> Result<T, tokio::task::JoinError> {
        let handle = self.handle.as_mut().unwrap();
        handle.abort();
        let result = tokio::time::timeout(TEST_WAIT, &mut *handle).await;
        if let Ok(result) = result {
            self.handle.take();
            return result;
        }

        // All guarded tasks are cooperative async futures. If an aborted task
        // cannot be reaped, terminating the test process is the only way to
        // guarantee it is not detached.
        std::process::abort();
    }
}

impl<T> Drop for TestTask<T> {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

async fn within<F: Future>(future: F) -> F::Output {
    tokio::time::timeout(TEST_WAIT, future)
        .await
        .expect("test operation timed out")
}

#[tokio::test]
async fn proxy_http_surface_is_bounded_sanitized_and_byte_preserving() {
    let mut fixture = Fixture::new();
    let server = fixture.serve();
    let address = unused_loopback_address();
    let courier = tokio::spawn(run(fixture.config(address)));
    assert!(
        wait_for_listener(address).await,
        "courier listener did not start"
    );

    let sealed = b"\xd2\x84opaque-response\x00\xff";
    let invoke = request(
        address,
        "/v1/invoke",
        "application/cose",
        sealed,
        &[
            "Authorization: Bearer test-courier-secret",
            "X-Forwarded-For: 192.0.2.9",
        ],
    )
    .await;
    assert_eq!(invoke.status, 200);
    assert_eq!(invoke.content_type, "application/cose");
    assert_eq!(invoke.cache_control, "no-store");
    assert_eq!(invoke.body, sealed);

    let challenge_request = GetInvocationChallengeRequest {
        jkt: vec![4; 32],
        courier_observed_source: None,
    }
    .encode_to_vec();
    let challenge = request(
        address,
        "/v1/challenge",
        "application/protobuf",
        &challenge_request,
        &[
            "Authorization: Bearer test-courier-secret",
            "X-Forwarded-For: 2001:db8::7",
        ],
    )
    .await;
    assert_eq!(challenge.status, 200);
    assert_eq!(challenge.cache_control, "no-store");
    let decoded = GetInvocationChallengeResponse::decode(challenge.body.as_slice()).unwrap();
    assert_eq!(decoded.challenge, vec![8; 32]);

    let unauthenticated = request(
        address,
        "/v1/invoke",
        "application/cose",
        sealed,
        &["X-Forwarded-For: 192.0.2.9"],
    )
    .await;
    assert_problem(&unauthenticated, 401, "UNAUTHENTICATED", false);
    assert!(!String::from_utf8_lossy(&unauthenticated.body).contains("test-courier-secret"));

    let compressed = request(
        address,
        "/v1/invoke",
        "application/cose",
        sealed,
        &[
            "Authorization: Bearer test-courier-secret",
            "X-Forwarded-For: 192.0.2.9",
            "Content-Encoding: gzip",
        ],
    )
    .await;
    assert_problem(&compressed, 415, "UNSUPPORTED_MEDIA_TYPE", false);

    let missing = request(
        address,
        "/health",
        "application/cose",
        b"x",
        &[
            "Authorization: Bearer test-courier-secret",
            "X-Forwarded-For: 192.0.2.9",
        ],
    )
    .await;
    assert_problem(&missing, 404, "NOT_FOUND", false);

    let oversized = raw_request(
        address,
        b"POST /v1/invoke HTTP/1.1\r\nHost: courier.test\r\nContent-Type: application/cose\r\nContent-Length: 1048577\r\nAuthorization: Bearer test-courier-secret\r\nX-Forwarded-For: 192.0.2.9\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_problem(&oversized, 413, "MESSAGE_TOO_LARGE", false);

    let malformed = raw_request(address, b"POST /v1/invoke HTTP/1.1\r\nBad Header\r\n\r\n").await;
    assert_problem(&malformed, 400, "MALFORMED_REQUEST", false);

    courier.abort();
    server.abort();
}

#[tokio::test]
async fn proxy_rejects_non_origin_targets_and_forwarding_near_misses() {
    let mut fixture = Fixture::new();
    let server = fixture.serve();
    let address = unused_loopback_address();
    let courier = tokio::spawn(run(fixture.config(address)));
    assert!(wait_for_listener(address).await);

    for target in [
        "/v1/invoke?debug=true",
        "http://courier.test/v1/invoke",
        "//courier.test/v1/invoke",
    ] {
        let raw =
            format!("POST {target} HTTP/1.1\r\nHost: courier.test\r\nContent-Length: 0\r\n\r\n");
        let response = raw_request(address, raw.as_bytes()).await;
        assert_problem(&response, 400, "MALFORMED_REQUEST", false);
    }

    for forwarded in [
        "",
        "X-Forwarded-For: 192.0.2.1, 192.0.2.2\r\n",
        "X-Forwarded-For: 192.0.2.01\r\n",
        "Forwarded: for=192.0.2.1\r\nX-Forwarded-For: 192.0.2.1\r\n",
        "X-Forwarded-For: 192.0.2.1\r\nX-Forwarded-For: 192.0.2.2\r\n",
    ] {
        let raw = format!(
            "POST /v1/invoke HTTP/1.1\r\nHost: courier.test\r\nContent-Type: application/cose\r\nContent-Length: 0\r\nAuthorization: Bearer test-courier-secret\r\n{forwarded}\r\n"
        );
        let response = raw_request(address, raw.as_bytes()).await;
        assert_problem(&response, 400, "MALFORMED_REQUEST", false);
    }

    courier.abort();
    server.abort();
}

#[tokio::test]
async fn direct_rustls_surface_forwards_and_rejects_forwarding_headers() {
    let mut fixture = Fixture::new();
    let server = fixture.serve();
    let address = unused_loopback_address();
    let courier = tokio::spawn(run(fixture.direct_config(address)));
    assert!(wait_for_listener(address).await);

    let success = tls_request(
        address,
        "/v1/invoke",
        b"direct-sealed",
        &["Authorization: Bearer test-courier-secret"],
    )
    .await;
    assert_eq!(success.status, 200);
    assert_eq!(success.body, b"direct-sealed");
    assert_eq!(success.cache_control, "no-store");

    let rejected = tls_request(
        address,
        "/v1/invoke",
        b"direct-sealed",
        &[
            "Authorization: Bearer test-courier-secret",
            "X-Forwarded-For: 192.0.2.9",
        ],
    )
    .await;
    assert_problem(&rejected, 400, "MALFORMED_REQUEST", false);

    courier.abort();
    server.abort();
}

#[tokio::test]
async fn post_forward_failure_is_sanitized_and_not_retryable() {
    let mut fixture = Fixture::new();
    let server = fixture.serve_with(FailingInvocation);
    let address = unused_loopback_address();
    let courier = tokio::spawn(run(fixture.config(address)));
    assert!(wait_for_listener(address).await);

    let response = request(
        address,
        "/v1/invoke",
        "application/cose",
        b"sealed",
        &[
            "Authorization: Bearer test-courier-secret",
            "X-Forwarded-For: 192.0.2.9",
        ],
    )
    .await;
    assert_problem(&response, 503, "BASIL_UNAVAILABLE", false);
    assert!(!String::from_utf8_lossy(&response.body).contains("vault-secret"));

    courier.abort();
    server.abort();
}

#[tokio::test]
async fn inflight_and_connection_saturation_fail_without_queueing() {
    let mut fixture = Fixture::new();
    let (blocking, mut entered, release) = BlockingInvocation::new();
    let server = TestTask::new(fixture.serve_with(blocking));
    let address = unused_loopback_address();
    let mut config = fixture.config(address);
    config.limits.connections = 3;
    config.limits.in_flight = 1;
    let courier = TestTask::new(tokio::spawn(run(config)));
    assert!(wait_for_listener(address).await);

    let first = TestTask::new(tokio::spawn(invoke_request(address)));
    within(entered.recv())
        .await
        .expect("first invocation never entered the broker");
    let overloaded = within(invoke_request(address)).await;
    assert_problem(&overloaded, 429, "OVERLOADED", true);
    release.add_permits(1);
    assert_eq!(first.join().await.status, 200);

    courier.abort_and_join().await;
    server.abort_and_join().await;

    let mut fixture = Fixture::new();
    let (blocking, mut entered, release) = BlockingInvocation::new();
    let server = TestTask::new(fixture.serve_with(blocking));
    let address = unused_loopback_address();
    let mut config = fixture.config(address);
    config.limits.connections = 2;
    let courier = TestTask::new(tokio::spawn(run(config)));
    assert!(wait_for_listener(address).await);
    let first = TestTask::new(tokio::spawn(invoke_request(address)));
    within(entered.recv())
        .await
        .expect("first connection was not retained in forwarding");
    let overloaded = within(invoke_request(address)).await;
    assert_problem(&overloaded, 429, "OVERLOADED", true);
    release.add_permits(1);
    assert_eq!(first.join().await.status, 200);

    courier.abort_and_join().await;
    server.abort_and_join().await;
}

async fn invoke_request(address: SocketAddr) -> HttpResponse {
    request(
        address,
        "/v1/invoke",
        "application/cose",
        b"sealed",
        &[
            "Authorization: Bearer test-courier-secret",
            "X-Forwarded-For: 192.0.2.9",
        ],
    )
    .await
}

fn assert_problem(response: &HttpResponse, status: u16, code: &str, retryable: bool) {
    assert_eq!(response.status, status);
    assert_eq!(response.content_type, "application/problem+json");
    assert_eq!(response.cache_control, "no-store");
    assert!(response.body.len() <= 128);
    let body = String::from_utf8(response.body.clone()).unwrap();
    assert_eq!(
        body,
        format!("{{\"code\":\"{code}\",\"retryable\":{retryable}}}")
    );
}

async fn request(
    address: SocketAddr,
    path: &str,
    content_type: &str,
    body: &[u8],
    extra_headers: &[&str],
) -> HttpResponse {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut headers = String::new();
    for header in extra_headers {
        headers.push_str(header);
        headers.push_str("\r\n");
    }
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: courier.test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    HttpResponse::parse(&response)
}

async fn raw_request(address: SocketAddr, request: &[u8]) -> HttpResponse {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    HttpResponse::parse(&response)
}

async fn tls_request(
    address: SocketAddr,
    path: &str,
    body: &[u8],
    extra_headers: &[&str],
) -> HttpResponse {
    let testdata = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../basil-core/testdata");
    let authority = fs::read(testdata.join("registry_tls_ca.pem")).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut std::io::Cursor::new(authority)) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client));
    let stream = TcpStream::connect(address).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap().to_owned();
    let mut stream = connector.connect(server_name, stream).await.unwrap();
    let mut headers = String::new();
    for header in extra_headers {
        headers.push_str(header);
        headers.push_str("\r\n");
    }
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/cose\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    HttpResponse::parse(&response)
}

struct HttpResponse {
    status: u16,
    content_type: String,
    cache_control: String,
    body: Vec<u8>,
}

impl HttpResponse {
    fn parse(bytes: &[u8]) -> Self {
        let split = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let head = std::str::from_utf8(&bytes[..split]).unwrap();
        let mut lines = head.lines();
        let status = lines
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let mut content_type = String::new();
        let mut cache_control = String::new();
        for line in lines {
            if let Some(value) = line.strip_prefix("content-type: ") {
                value.clone_into(&mut content_type);
            }
            if let Some(value) = line.strip_prefix("cache-control: ") {
                value.clone_into(&mut cache_control);
            }
        }
        Self {
            status,
            content_type,
            cache_control,
            body: bytes[split + 4..].to_vec(),
        }
    }
}

async fn wait_for_listener(address: SocketAddr) -> bool {
    for _ in 0..100 {
        if TcpStream::connect(address).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

fn unused_loopback_address() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

struct Fixture {
    root: PathBuf,
    socket: PathBuf,
    bearer: PathBuf,
    tls_key: PathBuf,
    listener: Option<UnixListener>,
    uid: u32,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        let uid = rustix::process::geteuid().as_raw();
        let root = PathBuf::from(format!("/run/user/{uid}")).join(format!(
            ".https-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("socket")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(root.join("socket"), fs::Permissions::from_mode(0o750)).unwrap();
        let socket = root.join("socket/basil.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        let bearer = root.join("bearer");
        fs::write(&bearer, b"test-courier-secret\n").unwrap();
        fs::set_permissions(&bearer, fs::Permissions::from_mode(0o600)).unwrap();
        let tls_key = root.join("tls-key.pem");
        let testdata = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../basil-core/testdata");
        fs::copy(testdata.join("registry_tls_key.pem"), &tls_key).unwrap();
        fs::set_permissions(&tls_key, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            root,
            socket,
            bearer,
            tls_key,
            listener: Some(listener),
            uid,
        }
    }

    fn config(&self, bind: SocketAddr) -> Config {
        Config {
            bind,
            listener: ListenerConfig::TrustedProxy {
                proxy_address: "127.0.0.1".parse::<IpAddr>().unwrap(),
            },
            basil: BasilSocketConfig {
                socket_path: self.socket.clone(),
                service_owner_uid: self.uid,
                directory_owner_uid: self.uid,
                directory_mode: 0o750,
                socket_owner_uid: self.uid,
                socket_mode: 0o660,
                expected_peer_uid: self.uid,
            },
            bearer_file: Some(self.bearer.clone()),
            limits: Limits::default(),
        }
    }

    fn direct_config(&self, bind: SocketAddr) -> Config {
        let mut config = self.config(bind);
        config.listener = ListenerConfig::DirectTls {
            certificate_file: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../basil-core/testdata/registry_tls_cert.pem"),
            private_key_file: self.tls_key.clone(),
        };
        config
    }

    fn serve(&mut self) -> tokio::task::JoinHandle<()> {
        self.serve_with(TestInvocation)
    }

    fn serve_with<S>(&mut self, service: S) -> tokio::task::JoinHandle<()>
    where
        S: InvocationService + Send + Sync + 'static,
    {
        let listener = self.listener.take().unwrap();
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(InvocationServiceServer::new(service))
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await;
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.bearer);
        let _ = fs::remove_file(&self.tls_key);
        let _ = fs::remove_file(&self.socket);
        let _ = fs::remove_dir(self.root.join("socket"));
        let _ = fs::remove_dir(&self.root);
    }
}

#[derive(Clone, Copy)]
struct TestInvocation;

#[tonic::async_trait]
impl InvocationService for TestInvocation {
    async fn invoke(
        &self,
        request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        Ok(Response::new(SealedResponse {
            message: request.into_inner().message,
            response_subject: None,
        }))
    }

    async fn get_invocation_challenge(
        &self,
        request: Request<GetInvocationChallengeRequest>,
    ) -> Result<Response<GetInvocationChallengeResponse>, Status> {
        assert_eq!(
            request.into_inner().courier_observed_source.as_deref(),
            Some("2001:db8::7")
        );
        Ok(Response::new(GetInvocationChallengeResponse {
            challenge: vec![8; 32],
            generation: 2,
            expires_at_unix: 60,
        }))
    }

    async fn get_invocation_capabilities(
        &self,
        _request: Request<GetInvocationCapabilitiesRequest>,
    ) -> Result<Response<GetInvocationCapabilitiesResponse>, Status> {
        Ok(Response::new(GetInvocationCapabilitiesResponse {
            listener_profile: ListenerProfile::Courier as i32,
            require_challenge: true,
            courier_protocol_version: 1,
        }))
    }
}

#[derive(Clone, Copy)]
struct FailingInvocation;

#[tonic::async_trait]
impl InvocationService for FailingInvocation {
    async fn invoke(
        &self,
        _request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        Err(Status::unavailable("vault-secret must never escape"))
    }

    async fn get_invocation_challenge(
        &self,
        _request: Request<GetInvocationChallengeRequest>,
    ) -> Result<Response<GetInvocationChallengeResponse>, Status> {
        Err(Status::unavailable("vault-secret must never escape"))
    }

    async fn get_invocation_capabilities(
        &self,
        _request: Request<GetInvocationCapabilitiesRequest>,
    ) -> Result<Response<GetInvocationCapabilitiesResponse>, Status> {
        TestInvocation
            .get_invocation_capabilities(Request::new(GetInvocationCapabilitiesRequest {}))
            .await
    }
}

#[derive(Clone)]
struct BlockingInvocation {
    entered: mpsc::UnboundedSender<()>,
    release: Arc<Semaphore>,
}

impl BlockingInvocation {
    fn new() -> (Self, mpsc::UnboundedReceiver<()>, Arc<Semaphore>) {
        let (entered, entered_rx) = mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        (
            Self {
                entered,
                release: Arc::clone(&release),
            },
            entered_rx,
            release,
        )
    }
}

#[tonic::async_trait]
impl InvocationService for BlockingInvocation {
    async fn invoke(
        &self,
        request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        self.entered
            .send(())
            .map_err(|_| Status::internal("test entry barrier closed"))?;
        self.release
            .acquire()
            .await
            .map_err(|_| Status::internal("test release barrier closed"))?
            .forget();
        TestInvocation.invoke(request).await
    }

    async fn get_invocation_challenge(
        &self,
        request: Request<GetInvocationChallengeRequest>,
    ) -> Result<Response<GetInvocationChallengeResponse>, Status> {
        TestInvocation.get_invocation_challenge(request).await
    }

    async fn get_invocation_capabilities(
        &self,
        request: Request<GetInvocationCapabilitiesRequest>,
    ) -> Result<Response<GetInvocationCapabilitiesResponse>, Status> {
        TestInvocation.get_invocation_capabilities(request).await
    }
}
