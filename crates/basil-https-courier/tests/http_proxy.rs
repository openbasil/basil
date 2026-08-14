// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

use std::collections::HashSet;
use std::fs;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use basil_courier::{
    CourierConnectError, InvocationCourierClient, MAX_COURIER_GRPC_MESSAGE_BYTES, TrustedUdsError,
    TrustedUdsPolicy,
};
use basil_https_courier::{
    BasilSocketConfig, Config, Limits, ListenerConfig, MAX_INVOCATION_BYTES, run,
};
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
use tokio::net::{TcpSocket, TcpStream, UnixListener};
use tokio::sync::{Barrier, Notify, Semaphore, mpsc};
use tokio_rustls::TlsConnector;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

const TEST_WAIT: Duration = Duration::from_secs(4);
const INVOKE_ONE_REQUEST: &[u8] = b"POST /v1/invoke HTTP/1.1\r\nHost: courier.test\r\nContent-Type: application/cose\r\nContent-Length: 1\r\nAuthorization: Bearer test-courier-secret\r\nX-Forwarded-For: 192.0.2.9\r\nConnection: close\r\n\r\nx";

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
        let deadline = tokio::time::Instant::now() + TEST_WAIT;
        let result = tokio::time::timeout_at(deadline, self.handle.as_mut().unwrap()).await;
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
        let deadline = tokio::time::Instant::now() + TEST_WAIT;
        let result = tokio::time::timeout_at(deadline, &mut *handle).await;
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
    let deadline = tokio::time::Instant::now() + TEST_WAIT;
    tokio::time::timeout_at(deadline, future)
        .await
        .expect("test operation timed out")
}

async fn within_network<F: Future>(future: F) -> F::Output {
    let deadline = tokio::time::Instant::now() + TEST_WAIT;
    tokio::time::timeout_at(deadline, future)
        .await
        .expect("network operation timed out")
}

#[tokio::test]
async fn proxy_http_surface_is_bounded_sanitized_and_byte_preserving() {
    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve());
    let address = unused_loopback_address();
    let courier = TestTask::new(tokio::spawn(run(fixture.config(address))));
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

    courier.abort_and_join().await;
    server.abort_and_join().await;
}

#[tokio::test]
async fn proxy_rejects_non_origin_targets_and_forwarding_near_misses() {
    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve());
    let address = unused_loopback_address();
    let courier = TestTask::new(tokio::spawn(run(fixture.config(address))));
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

    courier.abort_and_join().await;
    server.abort_and_join().await;
}

#[tokio::test]
async fn direct_rustls_surface_forwards_and_rejects_forwarding_headers() {
    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve());
    let address = unused_loopback_address();
    let courier = TestTask::new(tokio::spawn(run(fixture.direct_config(address))));
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

    courier.abort_and_join().await;
    server.abort_and_join().await;
}

#[tokio::test]
async fn post_forward_failure_is_sanitized_and_not_retryable() {
    let mut fixture = Fixture::new();
    let failure = FailingInvocation::default();
    let calls = Arc::clone(&failure.calls);
    let effects = Arc::clone(&failure.effects);
    let server = TestTask::new(fixture.serve_with(failure));
    let address = unused_loopback_address();
    let courier = TestTask::new(tokio::spawn(run(fixture.config(address))));
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
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);

    courier.abort_and_join().await;
    server.abort_and_join().await;
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

#[tokio::test]
async fn duplicate_mutation_replay_and_reorder_preserve_transport_bytes() {
    let mut fixture = Fixture::new();
    let (service, oracle, reorder_entered, reorder_release) = AtomicBroker::new();
    let server = TestTask::new(fixture.serve_with(service));
    let address = unused_loopback_address();
    let courier = TestTask::new(tokio::spawn(run(fixture.config(address))));
    assert!(wait_for_listener(address).await);

    let first = TestTask::new(tokio::spawn(invoke_body(address, b"request-a")));
    let duplicate = TestTask::new(tokio::spawn(invoke_body(address, b"request-a")));
    let mut duplicate_responses = vec![first.join().await.body, duplicate.join().await.body];
    duplicate_responses.sort_unstable();
    assert_eq!(
        duplicate_responses,
        [
            b"sealed-challenge-unknown".to_vec(),
            b"sealed-success-a".to_vec(),
        ]
    );
    assert_eq!(oracle.lock().unwrap().effects, 1);

    let mutated = invoke_body(address, b"request-A").await;
    assert_eq!(mutated.status, 200);
    assert_eq!(mutated.body, b"sealed-invalid-request");
    let replayed = invoke_body(address, b"request-a").await;
    assert_eq!(replayed.status, 200);
    assert_eq!(replayed.body, b"sealed-challenge-unknown");
    assert_eq!(oracle.lock().unwrap().effects, 1);

    let delayed = TestTask::new(tokio::spawn(invoke_body(address, b"request-b")));
    within(reorder_entered.notified()).await;
    let overtaking = invoke_body(address, b"request-c").await;
    assert_eq!(overtaking.body, b"sealed-success-c");
    reorder_release.add_permits(1);
    assert_eq!(delayed.join().await.body, b"sealed-success-b");

    {
        let state = oracle.lock().unwrap();
        assert_eq!(state.effects, 3);
        assert_eq!(
            state.completed,
            [
                b"request-a".to_vec(),
                b"request-c".to_vec(),
                b"request-b".to_vec(),
            ]
        );
        drop(state);
    }

    courier.abort_and_join().await;
    server.abort_and_join().await;
}

#[tokio::test]
async fn invocation_response_above_the_configured_limit_is_rejected() {
    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve_with(OversizedInvocationResponse));
    let address = unused_loopback_address();
    let mut config = fixture.config(address);
    config.limits.invocation_response_bytes = 8;
    let courier = TestTask::new(tokio::spawn(run(config)));
    assert!(wait_for_listener(address).await);

    let response = invoke_body(address, b"sealed").await;
    assert_problem(&response, 413, "MESSAGE_TOO_LARGE", false);

    courier.abort_and_join().await;
    server.abort_and_join().await;
}

#[tokio::test]
async fn challenge_response_above_the_configured_limit_is_rejected() {
    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve_with(OversizedChallengeResponse));
    let address = unused_loopback_address();
    let mut config = fixture.config(address);
    config.limits.challenge_body_bytes = 40;
    let courier = TestTask::new(tokio::spawn(run(config)));
    assert!(wait_for_listener(address).await);

    let body = GetInvocationChallengeRequest {
        jkt: vec![4; 32],
        courier_observed_source: None,
    }
    .encode_to_vec();
    assert!(body.len() <= 40, "request must fit the shared body limit");
    let response = request(
        address,
        "/v1/challenge",
        "application/protobuf",
        &body,
        &[
            "Authorization: Bearer test-courier-secret",
            "X-Forwarded-For: 192.0.2.9",
        ],
    )
    .await;
    assert_problem(&response, 500, "INTERNAL", false);

    courier.abort_and_join().await;
    server.abort_and_join().await;
}

#[tokio::test]
async fn exact_maximum_and_framing_adversaries_fail_before_forwarding() {
    let service = CountingInvocation::default();
    let forwards = Arc::clone(&service.forwards);
    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve_with(service));
    let address = unused_loopback_address();
    let mut config = fixture.config(address);
    config.limits.invocation_request_bytes = MAX_INVOCATION_BYTES;
    config.limits.invocation_response_bytes = MAX_INVOCATION_BYTES;
    let courier = TestTask::new(tokio::spawn(run(config)));
    assert!(wait_for_listener(address).await);

    let exact = vec![0xa5; MAX_INVOCATION_BYTES];
    let accepted = within(invoke_body(address, &exact)).await;
    assert_eq!(accepted.status, 200);
    assert_eq!(accepted.body, exact);
    assert_eq!(forwards.load(Ordering::SeqCst), 1);

    let oversized = raw_request(
        address,
        b"POST /v1/invoke HTTP/1.1\r\nHost: courier.test\r\nContent-Type: application/cose\r\nContent-Length: 4194305\r\nAuthorization: Bearer test-courier-secret\r\nX-Forwarded-For: 192.0.2.9\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_problem(&oversized, 413, "MESSAGE_TOO_LARGE", false);

    for adversary in [
        b"POST /v1/invoke HTTP/1.1\r\nHost: courier.test\r\nContent-Type: application/cose\r\nTransfer-Encoding: chunked\r\nAuthorization: Bearer test-courier-secret\r\nX-Forwarded-For: 192.0.2.9\r\nConnection: close\r\n\r\n0\r\n\r\n".as_slice(),
        b"POST /v1/invoke HTTP/1.1\r\nHost: courier.test\r\nContent-Type: application/cose\r\nContent-Length: 0\r\nUpgrade: websocket\r\nConnection: upgrade\r\nAuthorization: Bearer test-courier-secret\r\nX-Forwarded-For: 192.0.2.9\r\n\r\n".as_slice(),
    ] {
        let response = raw_request(address, adversary).await;
        assert_problem(&response, 400, "MALFORMED_REQUEST", false);
    }

    for encoding in ["gzip", "br", "deflate"] {
        let response = request(
            address,
            "/v1/invoke",
            "application/cose",
            b"opaque",
            &[
                "Authorization: Bearer test-courier-secret",
                "X-Forwarded-For: 192.0.2.9",
                &format!("Content-Encoding: {encoding}"),
            ],
        )
        .await;
        assert_problem(&response, 415, "UNSUPPORTED_MEDIA_TYPE", false);
    }

    for target in [
        "/v1/invoke?next=/v1/invoke",
        "https://courier.test/v1/invoke",
        "//courier.test/v1/invoke",
    ] {
        let raw = format!(
            "POST {target} HTTP/1.1\r\nHost: courier.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let response = raw_request(address, raw.as_bytes()).await;
        assert_problem(&response, 400, "MALFORMED_REQUEST", false);
        assert!(!(300..400).contains(&response.status));
    }

    let truncated = raw_request_then_shutdown(
        address,
        b"POST /v1/invoke HTTP/1.1\r\nHost: courier.test\r\nContent-Type: application/cose\r\nContent-Length: 8\r\nAuthorization: Bearer test-courier-secret\r\nX-Forwarded-For: 192.0.2.9\r\nConnection: close\r\n\r\ncut",
    )
    .await;
    assert_problem(&truncated, 400, "MALFORMED_REQUEST", false);
    assert_eq!(forwards.load(Ordering::SeqCst), 1);

    courier.abort_and_join().await;
    server.abort_and_join().await;
}

#[tokio::test]
async fn rate_deadline_and_slowloris_pressure_are_bounded() {
    let mut fixture = Fixture::new();
    let (blocking, mut entered, release) = BlockingInvocation::new();
    let server = TestTask::new(fixture.serve_with(blocking));
    let address = unused_loopback_address();
    let mut config = fixture.config(address);
    config.limits.per_source_rate = 1;
    config.limits.per_source_burst = 1;
    config.limits.global_rate = 10;
    config.limits.global_burst = 10;
    let courier = TestTask::new(tokio::spawn(run(config)));
    assert!(wait_for_listener(address).await);
    let admitted = TestTask::new(tokio::spawn(invoke_request(address)));
    within(entered.recv())
        .await
        .expect("rate-test request did not reach the broker");
    let rate_limited = within(invoke_request(address)).await;
    assert_problem(&rate_limited, 429, "OVERLOADED", true);
    release.add_permits(1);
    assert_eq!(admitted.join().await.status, 200);
    courier.abort_and_join().await;
    server.abort_and_join().await;

    let mut fixture = Fixture::new();
    let (blocking, mut entered, release) = BlockingInvocation::new();
    let server = TestTask::new(fixture.serve_with(blocking));
    let address = unused_loopback_address();
    let mut config = fixture.config(address);
    config.limits.invocation_deadline_seconds = 1;
    let courier = TestTask::new(tokio::spawn(run(config)));
    assert!(wait_for_listener(address).await);
    let timed_out = TestTask::new(tokio::spawn(invoke_request(address)));
    within(entered.recv())
        .await
        .expect("deadline-test request did not reach the broker");
    assert_problem(&timed_out.join().await, 504, "TIMEOUT", false);
    release.close();
    courier.abort_and_join().await;
    server.abort_and_join().await;

    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve());
    let address = unused_loopback_address();
    let mut config = fixture.config(address);
    config.limits.io_deadline_seconds = 1;
    let courier = TestTask::new(tokio::spawn(run(config)));
    assert!(wait_for_listener(address).await);
    let response = slowloris_request(address).await;
    assert_problem(&response, 504, "TIMEOUT", true);
    courier.abort_and_join().await;
    server.abort_and_join().await;
}

#[tokio::test]
async fn slow_reader_cannot_retain_a_response_past_the_io_deadline() {
    let (service, mut response_ready, response_release) = LargeResponseInvocation::new();
    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve_with(service));
    let address = unused_loopback_address();
    let mut config = fixture.config(address);
    config.limits.invocation_response_bytes = MAX_INVOCATION_BYTES;
    config.limits.io_deadline_seconds = 1;
    config.limits.connections = 1;
    let courier = TestTask::new(tokio::spawn(run(config)));

    let stream = open_slow_reader(address).await;
    within(response_ready.recv())
        .await
        .expect("large response did not reach the retained-write barrier");
    assert!(
        try_raw_exchange(address, INVOKE_ONE_REQUEST)
            .await
            .is_empty()
    );
    response_release.add_permits(1);

    let recovered = wait_for_http_response(address, INVOKE_ONE_REQUEST).await;
    assert_eq!(recovered.status, 200);
    assert_eq!(recovered.body, b"probe-response");

    let received = read_stream_to_end(stream).await;
    let response = HttpResponse::parse(&received);
    assert_eq!(response.status, 200);
    assert_eq!(response.cache_control, "no-store");
    assert!(response.body.len() < MAX_INVOCATION_BYTES);

    courier.abort_and_join().await;
    server.abort_and_join().await;
}

#[tokio::test]
async fn courier_outage_replacement_and_uid_trust_fail_closed() {
    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve());
    let address = unused_loopback_address();
    let courier = TestTask::new(tokio::spawn(run(fixture.config(address))));
    assert!(wait_for_listener(address).await);
    server.abort_and_join().await;

    let outage = invoke_request(address).await;
    assert_problem(&outage, 503, "BASIL_UNAVAILABLE", true);

    let replacement = CountingInvocation::with_profile(ListenerProfile::Host);
    let replacement_forwards = Arc::clone(&replacement.forwards);
    let replacement_server = TestTask::new(fixture.replace_and_serve(replacement));
    let rejected = invoke_request(address).await;
    assert_problem(&rejected, 503, "CAPABILITY_MISMATCH", false);
    assert_eq!(replacement_forwards.load(Ordering::SeqCst), 0);
    courier.abort_and_join().await;
    replacement_server.abort_and_join().await;

    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve());
    let address = unused_loopback_address();
    let correct = fixture.config(address);
    let courier = TestTask::new(tokio::spawn(run(correct.clone())));
    assert!(wait_for_listener(address).await);
    assert_eq!(invoke_request(address).await.status, 200);
    courier.abort_and_join().await;

    let mut wrong_uid = TrustedUdsPolicy::from(&correct.basil);
    wrong_uid.expected_peer_uid = wrong_uid.expected_peer_uid.checked_add(1).unwrap();
    let error = within_network(InvocationCourierClient::connect(
        wrong_uid,
        Duration::from_secs(1),
        Duration::from_secs(1),
    ))
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        CourierConnectError::TrustedUds(TrustedUdsError::InvalidPolicy)
    ));
    server.abort_and_join().await;
}

#[tokio::test(flavor = "current_thread")]
async fn spoofed_sources_bearer_near_misses_and_log_bursts_leak_no_secrets() {
    let capture = LogCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_target(false)
        .with_thread_names(true)
        .with_writer(capture.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve_with(FailingInvocation::default()));
    let address = unused_loopback_address();
    let courier = TestTask::new(tokio::spawn(run(fixture.config(address))));
    assert!(wait_for_listener(address).await);
    let burst_started = std::time::Instant::now();

    for authorization in [
        "Authorization: Bearer test-courier-secreu",
        "Authorization: Bearer test-courier-secretx",
        "Authorization: bearer test-courier-secret",
        "Authorization: Basic test-courier-secret",
        "Authorization: Bearer  test-courier-secret",
    ] {
        let response = request(
            address,
            "/v1/invoke",
            "application/cose",
            b"unique-sealed-secret",
            &[authorization, "X-Forwarded-For: 192.0.2.9"],
        )
        .await;
        assert_eq!(
            response.status,
            401,
            "bearer near miss: {authorization}; body={}",
            String::from_utf8_lossy(&response.body)
        );
        assert_problem(&response, 401, "UNAUTHENTICATED", false);
    }

    let duplicated = raw_request(
        address,
        b"POST /v1/invoke HTTP/1.1\r\nHost: courier.test\r\nContent-Type: application/cose\r\nContent-Length: 0\r\nAuthorization: Bearer test-courier-secret\r\nAuthorization: Bearer test-courier-secret\r\nX-Forwarded-For: 192.0.2.9\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_problem(&duplicated, 401, "UNAUTHENTICATED", false);

    for _ in 0..24 {
        let response = request(
            address,
            "/v1/invoke",
            "application/cose",
            b"unique-sealed-secret",
            &[
                "Authorization: Bearer definitely-wrong",
                "X-Forwarded-For: 192.0.2.9",
            ],
        )
        .await;
        assert_problem(&response, 401, "UNAUTHENTICATED", false);
    }

    let broker_failure = invoke_request(address).await;
    assert_problem(&broker_failure, 503, "BASIL_UNAVAILABLE", false);
    assert_eq!(
        broker_failure.body,
        b"{\"code\":\"BASIL_UNAVAILABLE\",\"retryable\":false}"
    );

    let spoofed_peer = request_from(
        address,
        "127.0.0.2".parse().unwrap(),
        b"POST /v1/invoke HTTP/1.1\r\nHost: courier.test\r\nContent-Type: application/cose\r\nContent-Length: 0\r\nAuthorization: Bearer test-courier-secret\r\nX-Forwarded-For: 192.0.2.9\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        spoofed_peer.is_empty(),
        "untrusted proxy peer received a response"
    );

    courier.abort_and_join().await;
    server.abort_and_join().await;
    let logs = capture.rendered();
    let rejection_count = logs
        .lines()
        .filter(|line| {
            line.contains("spoofed_sources_bearer_near_misses_and_log_bursts_leak_no_secrets")
                && line.contains("courier request rejected")
        })
        .count();
    let refill_allowance = usize::try_from(burst_started.elapsed().as_secs())
        .unwrap()
        .saturating_add(1)
        .saturating_mul(10);
    assert!(rejection_count > 0);
    assert!(rejection_count <= 20 + refill_allowance);
    assert_logs_redacted(&logs);
}

#[tokio::test]
async fn direct_mode_rejects_every_forwarding_header_family() {
    let mut fixture = Fixture::new();
    let server = TestTask::new(fixture.serve());
    let address = unused_loopback_address();
    let courier = TestTask::new(tokio::spawn(run(fixture.direct_config(address))));
    assert!(wait_for_listener(address).await);
    for header in [
        "X-Forwarded-For: 192.0.2.9",
        "Forwarded: for=192.0.2.9",
        "X-Real-IP: 192.0.2.9",
    ] {
        let response = tls_request(
            address,
            "/v1/invoke",
            b"direct-sealed",
            &["Authorization: Bearer test-courier-secret", header],
        )
        .await;
        assert_problem(&response, 400, "MALFORMED_REQUEST", false);
    }
    courier.abort_and_join().await;
    server.abort_and_join().await;
}

async fn invoke_request(address: SocketAddr) -> HttpResponse {
    within_network(invoke_body(address, b"sealed")).await
}

async fn invoke_body(address: SocketAddr, body: &[u8]) -> HttpResponse {
    within_network(request(
        address,
        "/v1/invoke",
        "application/cose",
        body,
        &[
            "Authorization: Bearer test-courier-secret",
            "X-Forwarded-For: 192.0.2.9",
        ],
    ))
    .await
}

async fn slowloris_request(address: SocketAddr) -> HttpResponse {
    within_network(async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"POST /v1/invoke HTTP/1.1\r\nHost: courier.test\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        HttpResponse::parse(&response)
    })
    .await
}

async fn open_slow_reader(address: SocketAddr) -> TcpStream {
    within_network(async {
        loop {
            let socket = TcpSocket::new_v4().unwrap();
            socket.set_recv_buffer_size(1024).unwrap();
            if let Ok(mut stream) = socket.connect(address).await {
                stream.write_all(INVOKE_ONE_REQUEST).await.unwrap();
                return stream;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

async fn read_stream_to_end(mut stream: TcpStream) -> Vec<u8> {
    within_network(async {
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    })
    .await
}

async fn try_raw_exchange(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    within_network(async {
        let Ok(mut stream) = TcpStream::connect(address).await else {
            return Vec::new();
        };
        if stream.write_all(request).await.is_err() {
            return Vec::new();
        }
        let mut response = Vec::new();
        let _read_result = stream.read_to_end(&mut response).await;
        response
    })
    .await
}

async fn wait_for_http_response(address: SocketAddr, request: &[u8]) -> HttpResponse {
    within_network(async {
        loop {
            let Ok(mut stream) = TcpStream::connect(address).await else {
                tokio::task::yield_now().await;
                continue;
            };
            if stream.write_all(request).await.is_err() {
                tokio::task::yield_now().await;
                continue;
            }
            let mut response = Vec::new();
            if stream.read_to_end(&mut response).await.is_ok()
                && response.windows(4).any(|window| window == b"\r\n\r\n")
            {
                return HttpResponse::parse(&response);
            }
            tokio::task::yield_now().await;
        }
    })
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

fn assert_logs_redacted(logs: &str) {
    for forbidden in [
        "test-courier-secret",
        "definitely-wrong",
        "unique-sealed-secret",
        "vault-secret",
        "authorization",
    ] {
        assert!(
            !logs.contains(forbidden),
            "logs exposed {forbidden}: {logs}"
        );
    }
}

async fn request(
    address: SocketAddr,
    path: &str,
    content_type: &str,
    body: &[u8],
    extra_headers: &[&str],
) -> HttpResponse {
    within_network(async {
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
    })
    .await
}

async fn raw_request(address: SocketAddr, request: &[u8]) -> HttpResponse {
    within_network(async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        HttpResponse::parse(&response)
    })
    .await
}

async fn raw_request_then_shutdown(address: SocketAddr, request: &[u8]) -> HttpResponse {
    within_network(async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        HttpResponse::parse(&response)
    })
    .await
}

async fn request_from(address: SocketAddr, source: IpAddr, request: &[u8]) -> Vec<u8> {
    within_network(async {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddr::new(source, 0)).unwrap();
        let mut stream = socket.connect(address).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        let _read_result = stream.read_to_end(&mut response).await;
        response
    })
    .await
}

#[derive(Clone, Default)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl LogCapture {
    fn rendered(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for LogCapture {
    type Writer = LogWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        LogWriter(Arc::clone(&self.0))
    }
}

async fn tls_request(
    address: SocketAddr,
    path: &str,
    body: &[u8],
    extra_headers: &[&str],
) -> HttpResponse {
    within_network(async {
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
    })
    .await
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
    let deadline = tokio::time::Instant::now() + TEST_WAIT;
    tokio::time::timeout_at(deadline, async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok()
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
                .add_service(
                    InvocationServiceServer::new(service)
                        .max_decoding_message_size(MAX_COURIER_GRPC_MESSAGE_BYTES)
                        .max_encoding_message_size(MAX_COURIER_GRPC_MESSAGE_BYTES),
                )
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await;
        })
    }

    fn replace_and_serve<S>(&self, service: S) -> tokio::task::JoinHandle<()>
    where
        S: InvocationService + Send + Sync + 'static,
    {
        fs::remove_file(&self.socket).unwrap();
        let listener = UnixListener::bind(&self.socket).unwrap();
        fs::set_permissions(&self.socket, fs::Permissions::from_mode(0o660)).unwrap();
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(
                    InvocationServiceServer::new(service)
                        .max_decoding_message_size(MAX_COURIER_GRPC_MESSAGE_BYTES)
                        .max_encoding_message_size(MAX_COURIER_GRPC_MESSAGE_BYTES),
                )
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

#[derive(Clone, Default)]
struct FailingInvocation {
    calls: Arc<AtomicUsize>,
    effects: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl InvocationService for FailingInvocation {
    async fn invoke(
        &self,
        _request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.effects.fetch_add(1, Ordering::SeqCst);
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

#[derive(Default)]
struct BrokerOracle {
    seen: HashSet<Vec<u8>>,
    completed: Vec<Vec<u8>>,
    effects: usize,
}

#[derive(Clone)]
struct AtomicBroker {
    oracle: Arc<Mutex<BrokerOracle>>,
    duplicate_barrier: Arc<Barrier>,
    duplicate_arrivals: Arc<AtomicUsize>,
    reorder_entered: Arc<Notify>,
    reorder_release: Arc<Semaphore>,
}

impl AtomicBroker {
    fn new() -> (Self, Arc<Mutex<BrokerOracle>>, Arc<Notify>, Arc<Semaphore>) {
        let oracle = Arc::new(Mutex::new(BrokerOracle::default()));
        let reorder_entered = Arc::new(Notify::new());
        let reorder_release = Arc::new(Semaphore::new(0));
        (
            Self {
                oracle: Arc::clone(&oracle),
                duplicate_barrier: Arc::new(Barrier::new(2)),
                duplicate_arrivals: Arc::new(AtomicUsize::new(0)),
                reorder_entered: Arc::clone(&reorder_entered),
                reorder_release: Arc::clone(&reorder_release),
            },
            oracle,
            reorder_entered,
            reorder_release,
        )
    }
}

#[tonic::async_trait]
impl InvocationService for AtomicBroker {
    async fn invoke(
        &self,
        request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        let message = request.into_inner().message;
        if message == b"request-a" && self.duplicate_arrivals.fetch_add(1, Ordering::SeqCst) < 2 {
            self.duplicate_barrier.wait().await;
        }
        if message == b"request-b" {
            self.reorder_entered.notify_one();
            self.reorder_release
                .acquire()
                .await
                .map_err(|_| Status::internal("test reorder barrier closed"))?
                .forget();
        }

        let mut oracle = self.oracle.lock().unwrap();
        let response = if !matches!(
            message.as_slice(),
            b"request-a" | b"request-b" | b"request-c"
        ) {
            b"sealed-invalid-request".to_vec()
        } else if !oracle.seen.insert(message.clone()) {
            b"sealed-challenge-unknown".to_vec()
        } else {
            oracle.effects += 1;
            oracle.completed.push(message.clone());
            if message == b"request-a" {
                b"sealed-success-a".to_vec()
            } else if message == b"request-b" {
                b"sealed-success-b".to_vec()
            } else {
                b"sealed-success-c".to_vec()
            }
        };
        drop(oracle);
        Ok(Response::new(SealedResponse {
            message: response,
            response_subject: None,
        }))
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

#[derive(Clone)]
struct CountingInvocation {
    forwards: Arc<AtomicUsize>,
    profile: ListenerProfile,
}

#[derive(Clone, Copy)]
struct OversizedInvocationResponse;

#[tonic::async_trait]
impl InvocationService for OversizedInvocationResponse {
    async fn invoke(
        &self,
        _request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        Ok(Response::new(SealedResponse {
            message: vec![0x5a; 9],
            response_subject: None,
        }))
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

#[derive(Clone, Copy)]
struct OversizedChallengeResponse;

#[tonic::async_trait]
impl InvocationService for OversizedChallengeResponse {
    async fn invoke(
        &self,
        request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        TestInvocation.invoke(request).await
    }

    async fn get_invocation_challenge(
        &self,
        _request: Request<GetInvocationChallengeRequest>,
    ) -> Result<Response<GetInvocationChallengeResponse>, Status> {
        Ok(Response::new(GetInvocationChallengeResponse {
            challenge: vec![0x5a; 64],
            generation: 2,
            expires_at_unix: 60,
        }))
    }

    async fn get_invocation_capabilities(
        &self,
        request: Request<GetInvocationCapabilitiesRequest>,
    ) -> Result<Response<GetInvocationCapabilitiesResponse>, Status> {
        TestInvocation.get_invocation_capabilities(request).await
    }
}

impl CountingInvocation {
    fn with_profile(profile: ListenerProfile) -> Self {
        Self {
            forwards: Arc::new(AtomicUsize::new(0)),
            profile,
        }
    }
}

impl Default for CountingInvocation {
    fn default() -> Self {
        Self::with_profile(ListenerProfile::Courier)
    }
}

#[tonic::async_trait]
impl InvocationService for CountingInvocation {
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
        request: Request<GetInvocationChallengeRequest>,
    ) -> Result<Response<GetInvocationChallengeResponse>, Status> {
        TestInvocation.get_invocation_challenge(request).await
    }

    async fn get_invocation_capabilities(
        &self,
        _request: Request<GetInvocationCapabilitiesRequest>,
    ) -> Result<Response<GetInvocationCapabilitiesResponse>, Status> {
        Ok(Response::new(GetInvocationCapabilitiesResponse {
            listener_profile: self.profile as i32,
            require_challenge: true,
            courier_protocol_version: 1,
        }))
    }
}

#[derive(Clone)]
struct LargeResponseInvocation {
    response_ready: mpsc::UnboundedSender<()>,
    response_release: Arc<Semaphore>,
    calls: Arc<AtomicUsize>,
}

impl LargeResponseInvocation {
    fn new() -> (Self, mpsc::UnboundedReceiver<()>, Arc<Semaphore>) {
        let (response_ready, receiver) = mpsc::unbounded_channel();
        let response_release = Arc::new(Semaphore::new(0));
        (
            Self {
                response_ready,
                response_release: Arc::clone(&response_release),
                calls: Arc::new(AtomicUsize::new(0)),
            },
            receiver,
            response_release,
        )
    }
}

#[tonic::async_trait]
impl InvocationService for LargeResponseInvocation {
    async fn invoke(
        &self,
        _request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        if self.calls.fetch_add(1, Ordering::SeqCst) > 0 {
            return Ok(Response::new(SealedResponse {
                message: b"probe-response".to_vec(),
                response_subject: None,
            }));
        }
        self.response_ready
            .send(())
            .map_err(|_| Status::internal("test response observer closed"))?;
        self.response_release
            .acquire()
            .await
            .map_err(|_| Status::internal("test response release closed"))?
            .forget();
        Ok(Response::new(SealedResponse {
            message: vec![0x5a; MAX_INVOCATION_BYTES],
            response_subject: None,
        }))
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
