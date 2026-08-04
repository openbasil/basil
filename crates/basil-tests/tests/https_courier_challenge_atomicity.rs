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
use tokio::net::TcpStream;
use tokio::sync::Barrier;

const TEST_WAIT: Duration = Duration::from_secs(15);
const RACERS: usize = 4;
const SUBJECT_SEED: [u8; 32] = [0x33; 32];
const RESPONSE_PRIVATE: [u8; 32] = [0x66; 32];
const SIGNING_KEY_ID: &str = "web.tls.signing_key";
const SIGNED_MESSAGE: &[u8] = b"https courier atomic challenge effect";

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
    let address = unused_loopback_address();
    let config = courier_config(address, harness.socket(), bearer);
    let courier = tokio::spawn(run(config));
    wait_for_listener(address).await;

    let client = Client::builder()
        .timeout(TEST_WAIT)
        .build()
        .expect("build HTTP client");
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
            post(&client, address, "/v1/invoke", "application/cose", body).await
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
) -> Response {
    client
        .post(format!("http://{address}{path}"))
        .header("content-type", content_type)
        .header("authorization", "Bearer https-courier-test-bearer")
        .header("x-forwarded-for", "192.0.2.9")
        .body(body)
        .send()
        .await
        .expect("send HTTP courier request")
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
