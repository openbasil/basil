// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::fs;
use std::net::{IpAddr, SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use basil_core::ci_federation::proof_key_thumbprint;
use basil_cose::{
    Claims, ContentAlgorithm, ContentType, Ed25519Signer, Ed25519Verifier, ExternalAad,
    FreshnessChallenge, KdfParties, KeyId, MessageId, MessageRole, SealParams, SealedAad, Signer,
    Subject, UnixTime, ValidationParams, VerifySealedParams, X25519Recipient,
    X25519RecipientPublic, Zeroizing, build_sealed, verify_sealed,
};
use basil_https_courier::{BasilSocketConfig, Config, Limits, ListenerConfig, run};
use basil_proto::broker::v1::{
    GetInvocationChallengeRequest, GetInvocationChallengeResponse, SigningAlgorithm,
};
use basil_proto::invocation::{
    CONTENT_TYPE_SIGN_REQUEST, InvocationStatusCode, SignInvocationRequest, SignInvocationResponse,
};
use basil_tests::{
    Engine, INVOCATION_AUDIENCE, INVOCATION_REQUEST_KEY_ID, INVOCATION_RESPONSE_KEY_ID,
    INVOCATION_SIGNING_KEY_ID, InvocationBootSpec, ProviderArm, alloc_addr, boot_basil_invocation,
    on_path,
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use prost::Message;
use reqwest::{Client, Response, StatusCode};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::Barrier;

const TEST_WAIT: Duration = Duration::from_secs(15);
const RACERS: usize = 4;
const SUBJECT_SEED: [u8; 32] = [0x33; 32];
const RESPONSE_PRIVATE: [u8; 32] = [0x66; 32];
const SIGNING_KEY_ID: &str = "web.tls.signing_key";
const SIGNED_MESSAGE: &[u8] = b"https courier atomic challenge effect";
const FAIR_SOURCE_A: &str = "192.0.2.10";
const FAIR_SOURCE_B: &str = "192.0.2.11";
const INVOKE_SOURCE: &str = "192.0.2.20";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn https_courier_preserves_atomic_production_challenge_consumption() {
    if !on_path("bao") {
        eprintln!("SKIP: `bao` not on PATH; skipping HTTPS courier challenge atomicity");
        return;
    }

    let subject = Ed25519Signer::from_secret_bytes(
        text_key("https-courier-subject"),
        &Zeroizing::new(SUBJECT_SEED),
    );
    let response_recipient = X25519Recipient::new(
        text_key(INVOCATION_RESPONSE_KEY_ID),
        Zeroizing::new(RESPONSE_PRIVATE),
    );
    let spec = InvocationBootSpec {
        provider: ProviderArm::GithubActions,
        require_challenge: true,
        subject_signature_key: URL_SAFE_NO_PAD.encode(subject.public_key_bytes()),
        second_subject_signature_key: None,
        response_public: response_recipient.public().public,
        request_private: Some(RESPONSE_PRIVATE),
        operation_signing_key_id: Some(SIGNING_KEY_ID.to_string()),
        courier_listener: true,
        challenge: None,
    };
    let harness = boot_basil_invocation(
        "https-challenge-atomicity",
        Engine::OpenBao,
        &alloc_addr(),
        &spec,
    );
    let broker_verifier = transit_verifier(harness.backend_addr(), INVOCATION_SIGNING_KEY_ID);
    let operation_public = transit_public_key(harness.backend_addr(), "web-tls");

    let bearer = harness.fixtures().join("https-courier-bearer");
    fs::write(&bearer, b"https-courier-test-bearer\n").expect("write bearer fixture");
    fs::set_permissions(&bearer, fs::Permissions::from_mode(0o600))
        .expect("set bearer fixture mode");
    let client = Client::builder()
        .timeout(TEST_WAIT)
        .build()
        .expect("build HTTP client");

    let fairness_address = unused_loopback_address();
    let mut fairness_config = courier_config(fairness_address, harness.socket(), bearer.clone());
    fairness_config.limits.per_source_rate = 1;
    fairness_config.limits.per_source_burst = 2;
    fairness_config.limits.global_rate = 1;
    fairness_config.limits.global_burst = 4;
    let fairness_courier = tokio::spawn(run(fairness_config));
    wait_for_listener(fairness_address).await;
    assert!(
        spoofed_proxy_request(fairness_address).await.is_empty(),
        "a non-proxy peer cannot inject a forwarded source"
    );
    assert_eq!(
        embedded_source_spoof(&client, fairness_address)
            .await
            .status(),
        StatusCode::BAD_REQUEST,
        "the public client cannot override the courier-observed source"
    );
    let fairness_barrier = Arc::new(Barrier::new(4));
    let source_a_first = tokio::spawn(blocked_challenge_post(
        client.clone(),
        fairness_address,
        FAIR_SOURCE_A,
        0xa1,
        Arc::clone(&fairness_barrier),
    ));
    let source_a_second = tokio::spawn(blocked_challenge_post(
        client.clone(),
        fairness_address,
        FAIR_SOURCE_A,
        0xa2,
        Arc::clone(&fairness_barrier),
    ));
    let source_b = tokio::spawn(blocked_challenge_post(
        client.clone(),
        fairness_address,
        FAIR_SOURCE_B,
        0xb1,
        Arc::clone(&fairness_barrier),
    ));
    fairness_barrier.wait().await;
    let mut source_a_statuses = [
        source_a_first
            .await
            .expect("source A fairness task did not panic")
            .status(),
        source_a_second
            .await
            .expect("source A fairness task did not panic")
            .status(),
    ];
    source_a_statuses.sort_unstable();
    assert_eq!(
        source_b
            .await
            .expect("source B fairness task did not panic")
            .status(),
        StatusCode::OK,
        "source A exhaustion leaves the remaining global reservation for source B"
    );
    assert_eq!(
        source_a_statuses,
        [StatusCode::OK, StatusCode::TOO_MANY_REQUESTS],
        "one source A request is admitted and one exhausts only its source partition"
    );
    stop_courier(fairness_courier).await;

    let rate_reserve_address = unused_loopback_address();
    let mut rate_reserve_config =
        courier_config(rate_reserve_address, harness.socket(), bearer.clone());
    rate_reserve_config.limits.global_rate = 1;
    rate_reserve_config.limits.global_burst = 2;
    rate_reserve_config.limits.per_source_rate = 1;
    rate_reserve_config.limits.per_source_burst = 2;
    rate_reserve_config.limits.source_buckets = 2;
    let rate_reserve_courier = tokio::spawn(run(rate_reserve_config));
    wait_for_listener(rate_reserve_address).await;
    let rate_source = "192.0.2.30";
    let preissued = challenge_post_for_jkt(
        &client,
        rate_reserve_address,
        rate_source,
        proof_key_thumbprint(&subject.public_key_bytes()),
    )
    .await;
    assert_eq!(preissued.status(), StatusCode::OK);
    let rate_challenge = GetInvocationChallengeResponse::decode(
        preissued
            .bytes()
            .await
            .expect("read rate-reserve challenge")
            .as_ref(),
    )
    .expect("decode rate-reserve challenge")
    .challenge;
    let rate_invoke = build_request(&subject, &rate_challenge, 199).await;

    let rate_barrier = Arc::new(Barrier::new(RACERS + 1));
    let mut pressure = Vec::with_capacity(RACERS);
    for marker in 0..RACERS {
        pressure.push(tokio::spawn(blocked_challenge_post(
            client.clone(),
            rate_reserve_address,
            rate_source,
            u8::try_from(marker).expect("rate marker fits in one byte"),
            Arc::clone(&rate_barrier),
        )));
    }
    rate_barrier.wait().await;
    let mut overloaded = 0;
    for request in pressure {
        let status = request
            .await
            .expect("rate-pressure task did not panic")
            .status();
        assert!(
            matches!(status, StatusCode::OK | StatusCode::TOO_MANY_REQUESTS),
            "rate-pressure challenge returned {status}"
        );
        if status == StatusCode::TOO_MANY_REQUESTS {
            overloaded += 1;
        }
    }
    assert!(
        overloaded > 0,
        "same-source challenge pressure reaches the reserved token boundary"
    );
    let rate_response = post(
        &client,
        rate_reserve_address,
        "/v1/invoke",
        "application/cose",
        rate_invoke,
        rate_source,
    )
    .await;
    assert_eq!(rate_response.status(), StatusCode::OK);
    let rate_sealed = rate_response
        .bytes()
        .await
        .expect("read rate-reserve Invoke response");
    let rate_body = open_response(&broker_verifier, &response_recipient, &rate_sealed).await;
    assert_eq!(rate_body.status.code, InvocationStatusCode::Ok);
    let signature = Signature::from_slice(
        &rate_body
            .signature
            .expect("rate-reserved Invoke carries a signature"),
    )
    .expect("rate-reserved Ed25519 signature");
    VerifyingKey::from_bytes(&operation_public)
        .expect("operation public key")
        .verify(SIGNED_MESSAGE, &signature)
        .expect("rate-reserved Invoke reaches the real backend signer");
    stop_courier(rate_reserve_courier).await;

    let saturation_address = unused_loopback_address();
    let mut saturation_config =
        courier_config(saturation_address, harness.socket(), bearer.clone());
    saturation_config.limits.connections = 5;
    saturation_config.limits.in_flight = 2;
    saturation_config.limits.challenge_deadline_seconds = 10;
    let saturation_courier = tokio::spawn(run(saturation_config));
    wait_for_listener(saturation_address).await;
    let preissued = challenge_post_for_jkt(
        &client,
        saturation_address,
        "192.0.2.19",
        proof_key_thumbprint(&subject.public_key_bytes()),
    )
    .await;
    assert_eq!(preissued.status(), StatusCode::OK);
    let preissued_challenge = GetInvocationChallengeResponse::decode(
        preissued
            .bytes()
            .await
            .expect("read preissued challenge")
            .as_ref(),
    )
    .expect("decode preissued challenge")
    .challenge;
    let preissued_invoke = build_request(&subject, &preissued_challenge, 200).await;

    let mut stopped = StoppedAgent::new(harness.agent_pid().expect("agent is running"));
    wait_for_stopped_agent(stopped.pid()).await;
    let barrier = Arc::new(Barrier::new(3));
    let mut challenge_a = tokio::spawn(blocked_challenge_post(
        client.clone(),
        saturation_address,
        "192.0.2.21",
        0xd1,
        Arc::clone(&barrier),
    ));
    let mut challenge_b = tokio::spawn(blocked_challenge_post(
        client.clone(),
        saturation_address,
        "192.0.2.22",
        0xd2,
        Arc::clone(&barrier),
    ));
    barrier.wait().await;
    let (overloaded, pending_challenge) = tokio::select! {
        result = &mut challenge_a => (result, challenge_b),
        result = &mut challenge_b => (result, challenge_a),
    };
    assert_eq!(
        overloaded
            .expect("challenge saturation task did not panic")
            .status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the bounded challenge lane rejects without entering the Invoke reserve"
    );
    let invoke_client = client.clone();
    let mut reserved_invoke = tokio::spawn(async move {
        post(
            &invoke_client,
            saturation_address,
            "/v1/invoke",
            "application/cose",
            preissued_invoke,
            INVOKE_SOURCE,
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_secs(1), &mut reserved_invoke)
            .await
            .is_err(),
        "the preissued Invoke is admitted and waits on the stopped broker"
    );
    stopped.resume();
    let reserved_response = tokio::time::timeout(TEST_WAIT, reserved_invoke)
        .await
        .expect("reserved Invoke completed after broker resume")
        .expect("reserved Invoke task did not panic");
    assert_eq!(reserved_response.status(), StatusCode::OK);
    let reserved_sealed = reserved_response
        .bytes()
        .await
        .expect("read reserved Invoke response");
    let reserved_body =
        open_response(&broker_verifier, &response_recipient, &reserved_sealed).await;
    assert_eq!(reserved_body.status.code, InvocationStatusCode::Ok);
    assert!(reserved_body.signature.is_some());
    assert_eq!(
        tokio::time::timeout(TEST_WAIT, pending_challenge)
            .await
            .expect("forwarded challenge completed after broker resume")
            .expect("forwarded challenge task did not panic")
            .status(),
        StatusCode::OK
    );
    stop_courier(saturation_courier).await;

    let address = unused_loopback_address();
    let config = courier_config(address, harness.socket(), bearer);
    let courier = tokio::spawn(run(config));
    wait_for_listener(address).await;
    let audit_path = harness.audit_log_path();
    let audit_offset = fs::read(&audit_path).map_or(0, |bytes| bytes.len());
    let challenge_request = GetInvocationChallengeRequest {
        jkt: proof_key_thumbprint(&subject.public_key_bytes()).to_vec(),
        courier_observed_source: None,
    }
    .encode_to_vec();
    let challenge_response = post(
        &client,
        address,
        "/v1/challenge",
        "application/protobuf",
        challenge_request,
        "192.0.2.9",
    )
    .await;
    assert_eq!(challenge_response.status(), StatusCode::OK);
    let challenge = GetInvocationChallengeResponse::decode(
        challenge_response
            .bytes()
            .await
            .expect("read challenge response")
            .as_ref(),
    )
    .expect("decode challenge response")
    .challenge;

    let barrier = Arc::new(Barrier::new(RACERS + 1));
    let mut calls = Vec::with_capacity(RACERS);
    for index in 0..RACERS {
        let body = build_request(&subject, &challenge, index).await;
        let client = client.clone();
        let barrier = Arc::clone(&barrier);
        calls.push(tokio::spawn(async move {
            barrier.wait().await;
            post(
                &client,
                address,
                "/v1/invoke",
                "application/cose",
                body,
                "192.0.2.9",
            )
            .await
        }));
    }
    barrier.wait().await;

    let mut success_signatures = Vec::new();
    let mut freshness_denials = 0;
    for call in calls {
        let response = tokio::time::timeout(TEST_WAIT, call)
            .await
            .expect("HTTP invocation completed before the deadline")
            .expect("HTTP invocation task did not panic");
        assert_eq!(response.status(), StatusCode::OK);
        let sealed = response.bytes().await.expect("read sealed response");
        let body = open_response(&broker_verifier, &response_recipient, &sealed).await;
        match body.status.code {
            InvocationStatusCode::Ok => {
                success_signatures.push(body.signature.expect("success carries a signature"));
            }
            InvocationStatusCode::ChallengeUnknown => {
                assert!(body.signature.is_none(), "freshness denial has no effect");
                freshness_denials += 1;
            }
            other => panic!("unexpected invocation status: {other:?}"),
        }
    }

    assert_eq!(
        success_signatures.len(),
        1,
        "exactly one backend sign succeeds"
    );
    assert_eq!(
        freshness_denials,
        RACERS - 1,
        "every loser is denied freshness"
    );
    let signature = Signature::from_slice(&success_signatures[0]).expect("Ed25519 signature");
    VerifyingKey::from_bytes(&operation_public)
        .expect("operation public key")
        .verify(SIGNED_MESSAGE, &signature)
        .expect("the single success is a real backend signature");

    let audit = wait_for_operation_audit(&audit_path, audit_offset).await;
    let allowed_signs = audit
        .iter()
        .filter(|line| {
            line["event_kind"] == "basil.audit.authz"
                && line["op"] == "sign"
                && line["target_id"] == SIGNING_KEY_ID
                && line["decision"] == "allow"
        })
        .count();
    assert_eq!(
        allowed_signs, 1,
        "exactly one raced request is admitted to the target signing key: {audit:?}"
    );
    let provider_successes = audit
        .iter()
        .filter(|line| {
            line["event"]["kind"] == "basil.audit.provider_operation"
                && line["op"] == "sign"
                && line["target"]["id"] == SIGNING_KEY_ID
                && line["outcome"] == "success"
        })
        .count();
    assert!(
        provider_successes <= 1,
        "the target key cannot report an additional successful provider effect: {audit:?}"
    );

    courier.abort();
    let result = tokio::time::timeout(TEST_WAIT, courier)
        .await
        .expect("courier task reaped before the deadline");
    assert!(
        result
            .expect_err("aborted courier task cannot complete")
            .is_cancelled()
    );
}

async fn wait_for_operation_audit(path: &std::path::Path, offset: usize) -> Vec<serde_json::Value> {
    tokio::time::timeout(TEST_WAIT, async {
        let mut stable_reads = 0_u8;
        let mut previous_len = 0_usize;
        loop {
            let bytes = fs::read(path).unwrap_or_default();
            let fresh = bytes.get(offset..).unwrap_or_default();
            let complete = fresh
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |position| position + 1);
            let lines = fresh[..complete]
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
                .collect::<Vec<_>>();
            let target_allow_visible = lines.iter().any(|line| {
                line["event_kind"] == "basil.audit.authz"
                    && line["op"] == "sign"
                    && line["target_id"] == SIGNING_KEY_ID
                    && line["decision"] == "allow"
            });
            if target_allow_visible && complete == previous_len {
                stable_reads = stable_reads.saturating_add(1);
                if stable_reads == 32 {
                    return lines;
                }
            } else {
                stable_reads = 0;
                previous_len = complete;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("operation audit became visible before the deadline")
}

fn courier_config(
    bind: SocketAddr,
    socket_path: std::path::PathBuf,
    bearer: std::path::PathBuf,
) -> Config {
    let directory = socket_path.parent().expect("socket has a parent");
    let directory_meta = fs::metadata(directory).expect("read socket directory metadata");
    let socket_meta = fs::metadata(&socket_path).expect("read socket metadata");
    let uid = rustix::process::geteuid().as_raw();
    Config {
        bind,
        listener: ListenerConfig::TrustedProxy {
            proxy_address: "127.0.0.1".parse::<IpAddr>().expect("loopback address"),
        },
        basil: BasilSocketConfig {
            socket_path,
            service_owner_uid: uid,
            directory_owner_uid: directory_meta.uid(),
            directory_mode: directory_meta.mode() & 0o7777,
            socket_owner_uid: socket_meta.uid(),
            socket_mode: socket_meta.mode() & 0o7777,
            expected_peer_uid: uid,
        },
        bearer_file: Some(bearer),
        limits: Limits::default(),
    }
}

async fn post(
    client: &Client,
    address: SocketAddr,
    path: &str,
    content_type: &'static str,
    body: Vec<u8>,
    source: &str,
) -> Response {
    client
        .post(format!("http://{address}{path}"))
        .header("content-type", content_type)
        .header("authorization", "Bearer https-courier-test-bearer")
        .header("x-forwarded-for", source)
        .body(body)
        .send()
        .await
        .expect("send HTTP courier request")
}

async fn challenge_post(
    client: &Client,
    address: SocketAddr,
    source: &str,
    jkt_marker: u8,
) -> Response {
    challenge_post_for_jkt(client, address, source, [jkt_marker; 32]).await
}

async fn challenge_post_for_jkt(
    client: &Client,
    address: SocketAddr,
    source: &str,
    jkt: [u8; 32],
) -> Response {
    let body = GetInvocationChallengeRequest {
        jkt: jkt.to_vec(),
        courier_observed_source: None,
    }
    .encode_to_vec();
    post(
        client,
        address,
        "/v1/challenge",
        "application/protobuf",
        body,
        source,
    )
    .await
}

async fn embedded_source_spoof(client: &Client, address: SocketAddr) -> Response {
    let body = GetInvocationChallengeRequest {
        jkt: vec![0xc1; 32],
        courier_observed_source: Some("attacker-selected-source".to_owned()),
    }
    .encode_to_vec();
    post(
        client,
        address,
        "/v1/challenge",
        "application/protobuf",
        body,
        "192.0.2.12",
    )
    .await
}

async fn blocked_challenge_post(
    client: Client,
    address: SocketAddr,
    source: &'static str,
    jkt_marker: u8,
    barrier: Arc<Barrier>,
) -> Response {
    barrier.wait().await;
    challenge_post(&client, address, source, jkt_marker).await
}

async fn spoofed_proxy_request(address: SocketAddr) -> Vec<u8> {
    let socket = tokio::net::TcpSocket::new_v4().expect("create spoof-test TCP socket");
    socket
        .bind("127.0.0.2:0".parse().expect("spoof-test source address"))
        .expect("bind spoof-test source address");
    let mut stream = socket
        .connect(address)
        .await
        .expect("connect spoof-test source");
    stream
        .write_all(
            b"POST /v1/challenge HTTP/1.1\r\nHost: courier.test\r\nContent-Type: application/protobuf\r\nContent-Length: 0\r\nAuthorization: Bearer https-courier-test-bearer\r\nX-Forwarded-For: 192.0.2.99\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("write spoof-test request");
    stream.shutdown().await.expect("shutdown spoof-test write");
    let mut response = Vec::new();
    let read = tokio::time::timeout(TEST_WAIT, stream.read_to_end(&mut response))
        .await
        .expect("spoof-test peer was closed before the deadline");
    if let Err(error) = read {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset,
            "read spoof-test rejection"
        );
    }
    response
}

struct StoppedAgent {
    pid: i32,
    stopped: bool,
}

impl StoppedAgent {
    fn new(pid: i32) -> Self {
        let status = Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .status()
            .expect("send SIGSTOP to Basil agent");
        assert!(status.success(), "SIGSTOP Basil agent");
        Self { pid, stopped: true }
    }

    const fn pid(&self) -> i32 {
        self.pid
    }

    fn resume(&mut self) {
        let status = Command::new("kill")
            .args(["-CONT", &self.pid.to_string()])
            .status()
            .expect("send SIGCONT to Basil agent");
        assert!(status.success(), "SIGCONT Basil agent");
        self.stopped = false;
    }
}

impl Drop for StoppedAgent {
    fn drop(&mut self) {
        if self.stopped {
            let _ = Command::new("kill")
                .args(["-CONT", &self.pid.to_string()])
                .status();
        }
    }
}

async fn wait_for_stopped_agent(pid: i32) {
    let status_path = format!("/proc/{pid}/status");
    tokio::time::timeout(TEST_WAIT, async {
        loop {
            let status = fs::read_to_string(&status_path).unwrap_or_default();
            if status
                .lines()
                .any(|line| line.starts_with("State:") && line.contains("T (stopped)"))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Basil agent entered the stopped state before the deadline");
}

async fn stop_courier(courier: tokio::task::JoinHandle<Result<(), basil_https_courier::RunError>>) {
    courier.abort();
    let result = tokio::time::timeout(TEST_WAIT, courier)
        .await
        .expect("courier task reaped before the deadline");
    assert!(
        result
            .expect_err("aborted courier task cannot complete")
            .is_cancelled()
    );
}

async fn build_request(signer: &Ed25519Signer, challenge: &[u8], index: usize) -> Vec<u8> {
    let mut message_id = vec![0_u8; 16];
    message_id[15] = u8::try_from(index).expect("racer index fits in one byte");
    let claims = Claims {
        issuer: None,
        audience: Some(Subject::new(INVOCATION_AUDIENCE.to_string()).expect("broker audience")),
        expires_at: None,
        issued_at: UnixTime(now_unix()),
        message_id: MessageId::from_bytes(message_id).expect("message id"),
        sender_key_id: Some(signer.key_id().clone()),
        response_key_id: Some(text_key(INVOCATION_RESPONSE_KEY_ID)),
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
        freshness_challenge: Some(
            FreshnessChallenge::from_bytes(challenge).expect("32-byte challenge"),
        ),
        response_public_key_cose: None,
    };
    let plaintext = SignInvocationRequest {
        key_id: SIGNING_KEY_ID.to_string(),
        message: SIGNED_MESSAGE.to_vec(),
        algorithm: SigningAlgorithm::Ed25519 as i32,
    }
    .to_cbor_bytes();
    build_sealed(
        &SealParams {
            content_type: ContentType::new(CONTENT_TYPE_SIGN_REQUEST.to_string())
                .expect("content type"),
            plaintext: &plaintext,
            claims,
            role: MessageRole::Request,
            recipient: X25519RecipientPublic {
                key_id: text_key(INVOCATION_REQUEST_KEY_ID),
                public: X25519Recipient::new(
                    text_key(INVOCATION_REQUEST_KEY_ID),
                    Zeroizing::new(RESPONSE_PRIVATE),
                )
                .public()
                .public,
            },
            content_algorithm: ContentAlgorithm::A256Gcm,
            aad: SealedAad::empty(),
            kdf_parties: KdfParties::anonymous(),
        },
        signer,
    )
    .await
    .expect("build challenged request")
    .into_vec()
}

async fn open_response(
    verifier: &Ed25519Verifier,
    recipient: &X25519Recipient,
    message: &[u8],
) -> SignInvocationResponse {
    let validation = ValidationParams {
        now: UnixTime(now_unix()),
        max_clock_skew: Duration::from_secs(30),
        max_ttl: Duration::from_mins(5),
        default_ttl: Duration::from_mins(2),
        allowed_audiences: std::collections::BTreeSet::new(),
        role: MessageRole::Response,
    };
    let verified_message = verify_sealed(
        message,
        verifier,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation,
        },
    )
    .await
    .expect("verify broker response");
    let opened = verified_message
        .open(
            recipient,
            &ExternalAad::empty(),
            Some(&KdfParties::anonymous()),
        )
        .await
        .expect("open broker response");
    SignInvocationResponse::from_cbor_bytes(opened.plaintext.as_slice())
        .expect("decode broker response")
}

fn transit_verifier(addr: &str, key_id: &str) -> Ed25519Verifier {
    Ed25519Verifier::from_key(
        text_key(key_id),
        &transit_public_key(addr, "ci-broker-signing"),
    )
    .expect("build transit verifier")
}

fn transit_public_key(addr: &str, transit_path: &str) -> [u8; 32] {
    let output = Command::new("bao")
        .args([
            "read",
            "-format=json",
            &format!("transit/keys/{transit_path}"),
        ])
        .env("VAULT_ADDR", addr)
        .env("VAULT_TOKEN", "root")
        .output()
        .expect("read transit public key");
    assert!(output.status.success(), "transit public-key read failed");
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse transit key JSON");
    let encoded = json["data"]["keys"]["1"]["public_key"]
        .as_str()
        .expect("transit key carries a version-1 public key");
    STANDARD
        .decode(encoded)
        .expect("decode transit public key")
        .try_into()
        .expect("transit Ed25519 public key is 32 bytes")
}

async fn wait_for_listener(address: SocketAddr) {
    tokio::time::timeout(TEST_WAIT, async {
        loop {
            if TcpStream::connect(address).await.is_ok() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("HTTPS courier listener started before the deadline");
}

fn unused_loopback_address() -> SocketAddr {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral address")
        .local_addr()
        .expect("read ephemeral address")
}

fn text_key(name: &str) -> KeyId {
    KeyId::from_text(name).expect("key id is text")
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("unix seconds fit in i64")
}
