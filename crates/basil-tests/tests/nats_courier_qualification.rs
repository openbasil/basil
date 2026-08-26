// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Live qualification of the NATS federation courier against a real
//! `nats-server` with `JetStream` enabled.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeSet;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH};

use async_nats::jetstream::kv::{self, Operation};
use async_nats::jetstream::stream::StorageType;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil_cose::{
    Claims, ContentAlgorithm, ContentType, Ed25519Signer, Ed25519Verifier, ExternalAad,
    FreshnessChallenge, KdfParties, KeyId, MessageId, MessageRole, Recipient, RequestHash,
    SealParams, SealedAad, Signer, Subject, UnixTime, ValidationParams, VerifySealedParams,
    X25519Recipient, X25519RecipientPublic, Zeroizing, build_sealed, request_hash, verify_sealed,
};
use basil_nats_bridge::{BasilConfig, BridgeConfig, Config, NatsConfig, RuntimeError};
use basil_proto::broker::v1::invocation_service_server::{
    InvocationService, InvocationServiceServer,
};
use basil_proto::broker::v1::{
    GetInvocationCapabilitiesRequest, GetInvocationCapabilitiesResponse,
    GetInvocationChallengeRequest, GetInvocationChallengeResponse, ListenerProfile, SealedRequest,
    SealedResponse,
};
use basil_tests::alloc_addr;
use bytes::Bytes;
use prost::Message as _;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::task::JoinHandle;
use tonic::{Request, Response, Status};

const REQUEST_SUBJECT: &str = "basil.qualify.invoke";
const CHALLENGE_SUBJECT: &str = "basil.qualify.challenge";
const SOURCE_PARTITION: &str = "qualification-runner";
const MAX_MESSAGE_BYTES: usize = 4 * 1024;
const REQUIRED_NATS_VERSION: &str = "nats-server: v2.14.5";
const ASYNC_BOUND: Duration = Duration::from_secs(5);
const PROCESS_REAP_BOUND: Duration = Duration::from_secs(2);
const HEARTBEAT_EXCLUSION_BOUND: Duration = Duration::from_secs(4);
const CHALLENGE: [u8; 32] = [0x5c; 32];
const JKT: [u8; 32] = [0x7a; 32];
const SATURATED_CHALLENGE_JKT: [u8; 32] = [0x2a; 32];
const DEADLINE_JKT: [u8; 32] = [0x6d; 32];
const DECLINED_JKT: [u8; 32] = [0x4d; 32];
const SLOW_REQUEST: &[u8] = b"opaque-slow-request";
const FAST_REQUEST: &[u8] = b"opaque-fast-request";
const SLOW_RESPONSE: &[u8] = b"opaque-slow-response";
const FAST_RESPONSE: &[u8] = b"opaque-fast-response";
const RECOVERY_REQUEST: &[u8] = b"opaque-recovery-request";
const RECOVERY_RESPONSE: &[u8] = b"opaque-recovery-response";
const DEADLINE_REQUEST: &[u8] = b"force-deadline";
const REJECTED_REQUEST: &[u8] = b"force-broker-rejection";
const BOUNDARY_RESPONSE: &[u8] = b"exact-boundary-response";

static QUALIFICATION_SERIAL: Mutex<()> = Mutex::const_new(());

struct NatsServer {
    child: Child,
    storage: PathBuf,
}

impl Drop for NatsServer {
    fn drop(&mut self) {
        let _ = kill_and_reap(&mut self.child, PROCESS_REAP_BOUND);
        let _ = std::fs::remove_dir_all(&self.storage);
    }
}

impl NatsServer {
    fn stop_bounded(&mut self) {
        assert!(
            kill_and_reap(&mut self.child, PROCESS_REAP_BOUND),
            "nats-server did not terminate within the reap deadline"
        );
    }
}

struct TaskGuard<T> {
    task: Option<JoinHandle<T>>,
}

impl<T> TaskGuard<T> {
    const fn new(task: JoinHandle<T>) -> Self {
        Self { task: Some(task) }
    }

    async fn result_bounded(
        &mut self,
        bound: Duration,
        context: &str,
    ) -> Result<T, tokio::task::JoinError> {
        let outcome = {
            let task = self.task.as_mut().expect("task guard contains a task");
            tokio::time::timeout(bound, &mut *task).await
        };
        if let Ok(result) = outcome {
            self.task.take();
            result
        } else {
            self.abort_and_reap().await;
            panic!("{context} exceeded its bounded join deadline");
        }
    }

    async fn result_before(
        &mut self,
        deadline: tokio::time::Instant,
        context: &str,
    ) -> Result<T, tokio::task::JoinError> {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .unwrap_or(Duration::ZERO);
        self.result_bounded(remaining, context).await
    }

    async fn abort_and_reap(&mut self) {
        let Some(mut task) = self.task.take() else {
            return;
        };
        task.abort();
        let _ = tokio::time::timeout(ASYNC_BOUND, &mut task)
            .await
            .expect("aborted task reaped within the cleanup deadline");
    }
}

impl<T> Drop for TaskGuard<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct SocketGuard {
    directory: PathBuf,
    socket: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

#[derive(Clone, Default)]
struct ReplayScenario {
    request: Vec<u8>,
    success: Vec<u8>,
    denial: Vec<u8>,
}

struct IngressGate {
    arrivals: AtomicUsize,
    arrived: Notify,
    release: Semaphore,
}

impl Default for IngressGate {
    fn default() -> Self {
        Self {
            arrivals: AtomicUsize::new(0),
            arrived: Notify::new(),
            release: Semaphore::new(0),
        }
    }
}

impl IngressGate {
    async fn hold(&self) {
        self.arrivals.fetch_add(1, Ordering::SeqCst);
        self.arrived.notify_one();
        let permit = tokio::time::timeout(ASYNC_BOUND, self.release.acquire())
            .await
            .expect("qualification ingress gate released within its deadline")
            .expect("qualification ingress gate remains open");
        permit.forget();
    }

    fn release(&self, permits: usize) {
        self.release.add_permits(permits);
    }
}

struct ServiceState {
    replay: Mutex<ReplayScenario>,
    effects: AtomicUsize,
    invocation_calls: AtomicUsize,
    challenge_calls: AtomicUsize,
    completions: StdMutex<Vec<&'static str>>,
    duplicate_gate: IngressGate,
    slow_gate: IngressGate,
    fast_gate: IngressGate,
    challenge_gate: IngressGate,
    lease_forward_gate: Mutex<Option<Arc<IngressGate>>>,
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            replay: Mutex::new(ReplayScenario::default()),
            effects: AtomicUsize::new(0),
            invocation_calls: AtomicUsize::new(0),
            challenge_calls: AtomicUsize::new(0),
            completions: StdMutex::new(Vec::new()),
            duplicate_gate: IngressGate::default(),
            slow_gate: IngressGate::default(),
            fast_gate: IngressGate::default(),
            challenge_gate: IngressGate::default(),
            lease_forward_gate: Mutex::new(None),
        }
    }
}

#[derive(Clone, Default)]
struct QualificationService {
    state: Arc<ServiceState>,
}

impl QualificationService {
    async fn set_replay_scenario(&self, request: Vec<u8>, success: Vec<u8>, denial: Vec<u8>) {
        *self.state.replay.lock().await = ReplayScenario {
            request,
            success,
            denial,
        };
    }

    async fn set_lease_forward_gate(&self, gate: Arc<IngressGate>) {
        *self.state.lease_forward_gate.lock().await = Some(gate);
    }
}

#[tonic::async_trait]
impl InvocationService for QualificationService {
    async fn invoke(
        &self,
        request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        self.state.invocation_calls.fetch_add(1, Ordering::SeqCst);
        let message = request.into_inner().message;
        let replay = self.state.replay.lock().await.clone();
        let response = if message == replay.request {
            if self.state.duplicate_gate.arrivals.load(Ordering::SeqCst) < 2 {
                self.state.duplicate_gate.hold().await;
            }
            if self
                .state
                .effects
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                replay.success
            } else {
                replay.denial
            }
        } else if message == SLOW_REQUEST {
            self.state.slow_gate.hold().await;
            self.state.completions.lock().unwrap().push("slow");
            SLOW_RESPONSE.to_vec()
        } else if message == FAST_REQUEST {
            self.state.fast_gate.hold().await;
            self.state.completions.lock().unwrap().push("fast");
            FAST_RESPONSE.to_vec()
        } else if message == RECOVERY_REQUEST {
            let gate = self.state.lease_forward_gate.lock().await.clone();
            if let Some(gate) = gate {
                gate.hold().await;
            }
            RECOVERY_RESPONSE.to_vec()
        } else if message.len() == MAX_MESSAGE_BYTES && message.iter().all(|byte| *byte == 0x55) {
            BOUNDARY_RESPONSE.to_vec()
        } else if message == DEADLINE_REQUEST {
            return Err(Status::deadline_exceeded(
                "provider JWT and private broker deadline detail",
            ));
        } else if message == REJECTED_REQUEST {
            return Err(Status::internal(
                "provider JWT and private broker rejection detail",
            ));
        } else {
            return Err(Status::invalid_argument("unknown qualification request"));
        };
        Ok(Response::new(SealedResponse {
            message: response,
            response_subject: None,
        }))
    }

    async fn get_invocation_challenge(
        &self,
        request: Request<GetInvocationChallengeRequest>,
    ) -> Result<Response<GetInvocationChallengeResponse>, Status> {
        let request = request.into_inner();
        if request.courier_observed_source.as_deref() != Some(SOURCE_PARTITION) {
            return Err(Status::invalid_argument(
                "challenge source partition mismatch",
            ));
        }
        if request.jkt == DEADLINE_JKT {
            return Err(Status::deadline_exceeded(
                "provider JWT and private challenge deadline detail",
            ));
        }
        if request.jkt == DECLINED_JKT {
            return Err(Status::resource_exhausted("CHALLENGE_ISSUANCE_DECLINED"));
        }
        if request.jkt != JKT && request.jkt != SATURATED_CHALLENGE_JKT {
            return Err(Status::invalid_argument("challenge thumbprint mismatch"));
        }
        self.state.challenge_calls.fetch_add(1, Ordering::SeqCst);
        if request.jkt == SATURATED_CHALLENGE_JKT {
            self.state.challenge_gate.hold().await;
        }
        Ok(Response::new(GetInvocationChallengeResponse {
            challenge: CHALLENGE.to_vec(),
            generation: 41,
            expires_at_unix: now_unix().0 + 60,
        }))
    }

    async fn get_invocation_capabilities(
        &self,
        _request: Request<GetInvocationCapabilitiesRequest>,
    ) -> Result<Response<GetInvocationCapabilitiesResponse>, Status> {
        Ok(Response::new(federation_capabilities()))
    }
}

#[derive(Clone)]
struct CapabilityService {
    capabilities: GetInvocationCapabilitiesResponse,
}

#[tonic::async_trait]
impl InvocationService for CapabilityService {
    async fn invoke(
        &self,
        _request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        Err(Status::internal("invoke must not be reached"))
    }

    async fn get_invocation_challenge(
        &self,
        _request: Request<GetInvocationChallengeRequest>,
    ) -> Result<Response<GetInvocationChallengeResponse>, Status> {
        Err(Status::internal("challenge must not be reached"))
    }

    async fn get_invocation_capabilities(
        &self,
        _request: Request<GetInvocationCapabilitiesRequest>,
    ) -> Result<Response<GetInvocationCapabilitiesResponse>, Status> {
        Ok(Response::new(self.capabilities))
    }
}

const fn federation_capabilities() -> GetInvocationCapabilitiesResponse {
    GetInvocationCapabilitiesResponse {
        listener_profile: ListenerProfile::Courier as i32,
        require_challenge: true,
        courier_protocol_version: 1,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn federation_qualifies_freshness_fidelity_replay_reorder_and_failures() {
    let _serial_guard = QUALIFICATION_SERIAL.lock().await;
    require_nats_server_2_14_5();

    let port = port_from(&alloc_addr());
    let (mut nats_server, nats_url) = start_nats_server(port).await;
    let nats = tokio::time::timeout(ASYNC_BOUND, async_nats::connect(&nats_url))
        .await
        .expect("qualification NATS connection completed within its deadline")
        .expect("connect qualification NATS client");
    let bucket = format!("BASILQ{port}");
    create_lease_bucket(&nats, &bucket).await;

    let service = QualificationService::default();
    let (socket_guard, listener, server_uid) = bind_test_socket(port, "matrix");
    let mut server = spawn_service(listener, service.clone());
    let config = federation_config(&nats_url, &socket_guard.socket, server_uid, &bucket);
    let mut bridge = TaskGuard::new(tokio::spawn(basil_nats_bridge::run(config)));

    let challenge_request = GetInvocationChallengeRequest {
        jkt: JKT.to_vec(),
        courier_observed_source: None,
    };
    let challenge_reply =
        request_until_ready(&nats, CHALLENGE_SUBJECT, challenge_request.encode_to_vec()).await;
    assert_no_bridge_error(&challenge_reply);
    let challenge = GetInvocationChallengeResponse::decode(challenge_reply.payload.as_ref())
        .expect("decode challenge response carried through NATS");
    assert_eq!(challenge.challenge, CHALLENGE);
    assert_eq!(challenge.generation, 41);
    assert_eq!(service.state.challenge_calls.load(Ordering::SeqCst), 1);

    let client_signer = signer("qualification.client", [0x11; 32]);
    let broker_signer = signer("qualification.broker", [0x22; 32]);
    let broker_verifier = Ed25519Verifier::from_key(
        broker_signer.key_id().clone(),
        &broker_signer.public_key_bytes(),
    )
    .expect("broker verifier");
    let request_recipient = recipient("qualification.request", [0x33; 32]);
    let response_recipient = recipient("qualification.response", [0x44; 32]);
    let now = now_unix();
    let request_id =
        MessageId::from_bytes(b"nats-qualification-request".to_vec()).expect("request message id");
    let request_bytes = seal_request(
        &client_signer,
        request_recipient.public(),
        response_recipient.key_id().clone(),
        request_id.clone(),
        now,
        &challenge.challenge,
    )
    .await;
    let success_bytes = seal_response(
        b"qualified-success",
        &broker_signer,
        response_recipient.public(),
        request_id.clone(),
        request_hash(&request_bytes),
        b"nats-qualification-success",
        now,
    )
    .await;
    let denial_bytes = seal_response(
        b"freshness-denied",
        &broker_signer,
        response_recipient.public(),
        request_id.clone(),
        request_hash(&request_bytes),
        b"nats-qualification-denial",
        now,
    )
    .await;
    service
        .set_replay_scenario(
            request_bytes.clone(),
            success_bytes.clone(),
            denial_bytes.clone(),
        )
        .await;

    let first_client = nats.clone();
    let first_request = request_bytes.clone();
    let mut first = TaskGuard::new(tokio::spawn(async move {
        bounded_request(&first_client, REQUEST_SUBJECT, first_request).await
    }));
    let second_client = nats.clone();
    let second_request = request_bytes.clone();
    let mut second = TaskGuard::new(tokio::spawn(async move {
        bounded_request(&second_client, REQUEST_SUBJECT, second_request).await
    }));
    wait_for_arrivals(&service.state.duplicate_gate, 2, "duplicate requests").await;
    assert_eq!(
        service.state.duplicate_gate.arrivals.load(Ordering::SeqCst),
        2,
        "both duplicate requests are held in flight before either completes"
    );
    service.state.duplicate_gate.release(2);
    let first = first
        .result_bounded(ASYNC_BOUND, "first duplicate request")
        .await
        .expect("first duplicate request task joined");
    let second = second
        .result_bounded(ASYNC_BOUND, "second duplicate request")
        .await
        .expect("second duplicate request task joined");
    let payloads = [first.payload.as_ref(), second.payload.as_ref()];
    assert_eq!(payloads.iter().filter(|p| **p == success_bytes).count(), 1);
    assert_eq!(payloads.iter().filter(|p| **p == denial_bytes).count(), 1);
    assert_eq!(service.state.effects.load(Ordering::SeqCst), 1);

    let replay = bounded_request(&nats, REQUEST_SUBJECT, request_bytes.clone()).await;
    assert_eq!(replay.payload.as_ref(), denial_bytes);
    assert_eq!(service.state.effects.load(Ordering::SeqCst), 1);

    let success_reply = [first, second]
        .into_iter()
        .find(|message| message.payload.as_ref() == success_bytes)
        .expect("one duplicate receives the successful sealed response");
    let verified = verify_sealed(
        &success_reply.payload,
        &broker_verifier,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &ValidationParams {
                now,
                max_clock_skew: Duration::from_mins(1),
                max_ttl: Duration::from_mins(5),
                default_ttl: Duration::from_mins(5),
                allowed_audiences: BTreeSet::new(),
                role: MessageRole::Response,
            },
        },
    )
    .await
    .expect("broker-signed response survives the NATS courier byte-exact");
    let opened = verified
        .open(
            &response_recipient,
            &ExternalAad::empty(),
            Some(&KdfParties::anonymous()),
        )
        .await
        .expect("open the qualified sealed response");
    assert_eq!(opened.plaintext.as_slice(), b"qualified-success");

    let slow_client = nats.clone();
    let mut slow = TaskGuard::new(tokio::spawn(async move {
        bounded_request(&slow_client, REQUEST_SUBJECT, SLOW_REQUEST.to_vec()).await
    }));
    wait_for_arrivals(&service.state.slow_gate, 1, "slow reorder request").await;
    let fast_client = nats.clone();
    let mut fast = TaskGuard::new(tokio::spawn(async move {
        bounded_request(&fast_client, REQUEST_SUBJECT, FAST_REQUEST.to_vec()).await
    }));
    wait_for_arrivals(&service.state.fast_gate, 1, "fast reorder request").await;
    assert_eq!(service.state.slow_gate.arrivals.load(Ordering::SeqCst), 1);
    assert_eq!(service.state.fast_gate.arrivals.load(Ordering::SeqCst), 1);
    service.state.fast_gate.release(1);
    let fast = fast
        .result_bounded(ASYNC_BOUND, "fast reorder request")
        .await
        .expect("fast reorder request task joined");
    assert_eq!(fast.payload.as_ref(), FAST_RESPONSE);
    assert_eq!(
        service.state.completions.lock().unwrap().as_slice(),
        ["fast"],
        "slow request remains held while the fast request completes"
    );
    service.state.slow_gate.release(1);
    let slow = slow
        .result_bounded(ASYNC_BOUND, "slow reorder request")
        .await
        .expect("slow request task joined");
    assert_eq!(slow.payload.as_ref(), SLOW_RESPONSE);
    assert_eq!(
        service.state.completions.lock().unwrap().as_slice(),
        ["fast", "slow"]
    );

    let calls_before_boundary = service.state.invocation_calls.load(Ordering::SeqCst);
    let boundary = bounded_request(&nats, REQUEST_SUBJECT, vec![0x55; MAX_MESSAGE_BYTES]).await;
    assert_no_bridge_error(&boundary);
    assert_eq!(boundary.payload.as_ref(), BOUNDARY_RESPONSE);
    assert_eq!(
        service.state.invocation_calls.load(Ordering::SeqCst),
        calls_before_boundary + 1,
        "an invocation at the exact configured bound is forwarded"
    );
    let calls_before_oversize = service.state.invocation_calls.load(Ordering::SeqCst);
    let oversized =
        bounded_request(&nats, REQUEST_SUBJECT, vec![0x55; MAX_MESSAGE_BYTES + 1]).await;
    assert_bridge_error(&oversized, "MESSAGE_TOO_LARGE", false);
    assert_eq!(
        service.state.invocation_calls.load(Ordering::SeqCst),
        calls_before_oversize
    );

    let challenge_calls_before_boundary = service.state.challenge_calls.load(Ordering::SeqCst);
    let exact_challenge = padded_challenge_request(MAX_MESSAGE_BYTES);
    assert_eq!(exact_challenge.len(), MAX_MESSAGE_BYTES);
    let exact_challenge = bounded_request(&nats, CHALLENGE_SUBJECT, exact_challenge).await;
    assert_no_bridge_error(&exact_challenge);
    GetInvocationChallengeResponse::decode(exact_challenge.payload.as_ref())
        .expect("exact-boundary challenge response is valid protobuf");
    assert_eq!(
        service.state.challenge_calls.load(Ordering::SeqCst),
        challenge_calls_before_boundary + 1,
        "a challenge at the exact fixed bound is forwarded"
    );
    let challenge_calls_before_oversize = service.state.challenge_calls.load(Ordering::SeqCst);
    let oversized_challenge =
        bounded_request(&nats, CHALLENGE_SUBJECT, vec![0x66; MAX_MESSAGE_BYTES + 1]).await;
    assert_bridge_error(&oversized_challenge, "MESSAGE_TOO_LARGE", false);
    assert_eq!(
        service.state.challenge_calls.load(Ordering::SeqCst),
        challenge_calls_before_oversize
    );

    let malformed = GetInvocationChallengeRequest {
        jkt: JKT.to_vec(),
        courier_observed_source: Some("caller-spoof".to_string()),
    };
    let malformed = bounded_request(&nats, CHALLENGE_SUBJECT, malformed.encode_to_vec()).await;
    assert_bridge_error(&malformed, "MALFORMED_REQUEST", false);

    let challenge_deadline = GetInvocationChallengeRequest {
        jkt: DEADLINE_JKT.to_vec(),
        courier_observed_source: None,
    };
    let challenge_deadline =
        bounded_request(&nats, CHALLENGE_SUBJECT, challenge_deadline.encode_to_vec()).await;
    assert_bridge_error(&challenge_deadline, "TIMEOUT", true);
    assert_sanitized(&challenge_deadline);
    let declined = GetInvocationChallengeRequest {
        jkt: DECLINED_JKT.to_vec(),
        courier_observed_source: None,
    };
    let declined = bounded_request(&nats, CHALLENGE_SUBJECT, declined.encode_to_vec()).await;
    assert_bridge_error(&declined, "CHALLENGE_ISSUANCE_DECLINED", true);

    let deadline = bounded_request(&nats, REQUEST_SUBJECT, DEADLINE_REQUEST.to_vec()).await;
    assert_bridge_error(&deadline, "TIMEOUT", false);
    assert_sanitized(&deadline);
    let rejected = bounded_request(&nats, REQUEST_SUBJECT, REJECTED_REQUEST.to_vec()).await;
    assert_bridge_error(&rejected, "BASIL_REJECTED", false);
    assert_sanitized(&rejected);

    server.abort_and_reap().await;
    std::fs::remove_file(&socket_guard.socket).expect("remove stopped Basil socket");
    let unavailable = bounded_request(&nats, REQUEST_SUBJECT, RECOVERY_REQUEST.to_vec()).await;
    assert_bridge_error(&unavailable, "BASIL_UNAVAILABLE", true);
    let restarted_listener = bind_existing_socket(&socket_guard.socket);
    let mut restarted = spawn_service(restarted_listener, service.clone());
    let recovered = bounded_request(&nats, REQUEST_SUBJECT, RECOVERY_REQUEST.to_vec()).await;
    assert_no_bridge_error(&recovered);
    assert_eq!(recovered.payload.as_ref(), RECOVERY_RESPONSE);

    restarted.abort_and_reap().await;
    bridge.abort_and_reap().await;
    drop(nats);
    nats_server.stop_bounded();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn challenge_workers_are_partition_bounded_and_preserve_invoke_capacity() {
    let _serial_guard = QUALIFICATION_SERIAL.lock().await;
    require_nats_server_2_14_5();

    let port = port_from(&alloc_addr());
    let (mut nats_server, nats_url) = start_nats_server(port).await;
    let nats = tokio::time::timeout(ASYNC_BOUND, async_nats::connect(&nats_url))
        .await
        .expect("challenge-capacity NATS connection completed within its deadline")
        .expect("connect challenge-capacity qualification client");
    let bucket = format!("BASILQ{port}");
    create_lease_bucket(&nats, &bucket).await;

    let service = QualificationService::default();
    let (socket_guard, listener, server_uid) = bind_test_socket(port, "challenge-capacity");
    let mut server = spawn_service(listener, service.clone());
    let mut config = federation_config(&nats_url, &socket_guard.socket, server_uid, &bucket);
    config.bridge.concurrency_limit = 1;
    config.bridge.challenge_concurrency_limit = 2;
    let mut bridge = TaskGuard::new(tokio::spawn(basil_nats_bridge::run(config)));

    request_until_ready(
        &nats,
        CHALLENGE_SUBJECT,
        GetInvocationChallengeRequest {
            jkt: JKT.to_vec(),
            courier_observed_source: None,
        }
        .encode_to_vec(),
    )
    .await;
    let challenge_calls_before_saturation = service.state.challenge_calls.load(Ordering::SeqCst);

    let saturated = GetInvocationChallengeRequest {
        jkt: SATURATED_CHALLENGE_JKT.to_vec(),
        courier_observed_source: None,
    }
    .encode_to_vec();
    let first_client = nats.clone();
    let mut first = TaskGuard::new(tokio::spawn(async move {
        bounded_request(&first_client, CHALLENGE_SUBJECT, saturated).await
    }));
    let saturated = GetInvocationChallengeRequest {
        jkt: SATURATED_CHALLENGE_JKT.to_vec(),
        courier_observed_source: None,
    }
    .encode_to_vec();
    let second_client = nats.clone();
    let mut second = TaskGuard::new(tokio::spawn(async move {
        bounded_request(&second_client, CHALLENGE_SUBJECT, saturated).await
    }));
    wait_for_arrivals(
        &service.state.challenge_gate,
        2,
        "saturated challenge workers",
    )
    .await;

    let overloaded = bounded_request(
        &nats,
        CHALLENGE_SUBJECT,
        GetInvocationChallengeRequest {
            jkt: SATURATED_CHALLENGE_JKT.to_vec(),
            courier_observed_source: None,
        }
        .encode_to_vec(),
    )
    .await;
    assert_bridge_error(&overloaded, "OVERLOADED", true);

    let forwarded = bounded_request(&nats, REQUEST_SUBJECT, RECOVERY_REQUEST.to_vec()).await;
    assert_no_bridge_error(&forwarded);
    assert_eq!(forwarded.payload.as_ref(), RECOVERY_RESPONSE);
    assert_eq!(service.state.invocation_calls.load(Ordering::SeqCst), 1);

    service.state.challenge_gate.release(2);
    for (task, name) in [
        (&mut first, "first saturated challenge"),
        (&mut second, "second saturated challenge"),
    ] {
        let reply = task
            .result_bounded(ASYNC_BOUND, name)
            .await
            .expect("saturated challenge task joined");
        assert_no_bridge_error(&reply);
    }
    assert_eq!(
        service.state.challenge_calls.load(Ordering::SeqCst),
        challenge_calls_before_saturation + 2
    );

    bridge.abort_and_reap().await;
    server.abort_and_reap().await;
    drop(nats);
    nats_server.stop_bounded();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jetstream_lease_is_exclusive_renewed_before_forward_and_stops_intake_on_loss() {
    let _serial_guard = QUALIFICATION_SERIAL.lock().await;
    require_nats_server_2_14_5();

    let port = port_from(&alloc_addr());
    let (mut nats_server, nats_url) = start_nats_server(port).await;
    let nats = tokio::time::timeout(ASYNC_BOUND, async_nats::connect(&nats_url))
        .await
        .expect("lease NATS connection completed within its deadline")
        .expect("connect lease qualification NATS client");
    let bucket = format!("BASILQ{port}");
    let store = create_lease_bucket(&nats, &bucket).await;
    let service = QualificationService::default();
    let lease_forward_gate = Arc::new(IngressGate::default());
    service
        .set_lease_forward_gate(Arc::clone(&lease_forward_gate))
        .await;
    let (socket_guard, listener, server_uid) = bind_test_socket(port, "lease");
    let mut server = spawn_service(listener, service.clone());
    let config = federation_config(&nats_url, &socket_guard.socket, server_uid, &bucket);
    let heartbeat_exclusion_deadline = tokio::time::Instant::now() + HEARTBEAT_EXCLUSION_BOUND;
    let mut bridge = TaskGuard::new(tokio::spawn(basil_nats_bridge::run(config.clone())));

    let ready = GetInvocationChallengeRequest {
        jkt: JKT.to_vec(),
        courier_observed_source: None,
    };
    request_until_ready(&nats, CHALLENGE_SUBJECT, ready.encode_to_vec()).await;

    let key = lease_key(CHALLENGE_SUBJECT, REQUEST_SUBJECT);
    let before = tokio::time::timeout(ASYNC_BOUND, store.entry(&key))
        .await
        .expect("lease read completed within its deadline")
        .expect("read lease before forward")
        .expect("active bridge lease exists");
    let forward_client = nats.clone();
    let mut forward = TaskGuard::new(tokio::spawn(async move {
        bounded_request(&forward_client, REQUEST_SUBJECT, RECOVERY_REQUEST.to_vec()).await
    }));
    wait_for_arrivals(&lease_forward_gate, 1, "lease-qualified forward").await;
    let after = tokio::time::timeout_at(heartbeat_exclusion_deadline, store.entry(&key))
        .await
        .expect("post-forward lease read completed before the heartbeat exclusion deadline")
        .expect("read lease after forward")
        .expect("active bridge lease remains");
    assert!(
        tokio::time::Instant::now() < heartbeat_exclusion_deadline,
        "post-forward lease revision was observed before the heartbeat exclusion deadline"
    );
    assert_eq!(
        after.revision,
        before.revision + 1,
        "exactly one ingress CAS occurs before the held invocation reaches Basil"
    );
    lease_forward_gate.release(1);
    let response = forward
        .result_bounded(ASYNC_BOUND, "lease-qualified invocation")
        .await
        .expect("lease-qualified invocation task joined");
    assert_eq!(response.payload.as_ref(), RECOVERY_RESPONSE);
    assert_eq!(service.state.invocation_calls.load(Ordering::SeqCst), 1);

    let mut competitor = TaskGuard::new(tokio::spawn(basil_nats_bridge::run(config)));
    let competitor_result = competitor
        .result_bounded(ASYNC_BOUND, "competing bridge")
        .await
        .expect("competing bridge task joined");
    assert!(matches!(competitor_result, Err(RuntimeError::LeaseSetup)));

    tokio::time::timeout_at(
        heartbeat_exclusion_deadline,
        store.update(
            &key,
            Bytes::from_static(b"replacement-owner"),
            after.revision,
        ),
    )
    .await
    .expect("lease theft CAS completed before the heartbeat exclusion deadline")
    .expect("replace the bridge's lease at its owned revision");
    assert!(
        tokio::time::Instant::now() < heartbeat_exclusion_deadline,
        "lease theft completed before the heartbeat exclusion deadline"
    );
    let no_reply = tokio::time::timeout(
        Duration::from_secs(2),
        nats.request(REQUEST_SUBJECT, Bytes::from_static(RECOVERY_REQUEST)),
    )
    .await;
    assert!(
        !matches!(no_reply, Ok(Ok(_))),
        "a bridge that lost its lease must not forward or reply"
    );
    let bridge_result = bridge
        .result_bounded(ASYNC_BOUND, "lease-losing bridge")
        .await
        .expect("lease-losing bridge task joined");
    assert!(matches!(bridge_result, Err(RuntimeError::LeaseLost)));
    assert_eq!(service.state.invocation_calls.load(Ordering::SeqCst), 1);

    server.abort_and_reap().await;
    drop(nats);
    nats_server.stop_bounded();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jetstream_graceful_shutdown_deletes_only_the_owned_revision() {
    let _serial_guard = QUALIFICATION_SERIAL.lock().await;
    require_nats_server_2_14_5();

    let port = port_from(&alloc_addr());
    let (mut nats_server, nats_url) = start_nats_server(port).await;
    let nats = tokio::time::timeout(ASYNC_BOUND, async_nats::connect(&nats_url))
        .await
        .expect("shutdown NATS connection completed within its deadline")
        .expect("connect shutdown qualification NATS client");
    let bucket = format!("BASILQ{port}");
    let store = create_lease_bucket(&nats, &bucket).await;
    let service = QualificationService::default();
    let (socket_guard, listener, server_uid) = bind_test_socket(port, "shutdown");
    let mut server = spawn_service(listener, service);

    let owned_request = "basil.qualify.shutdown.owned.invoke";
    let owned_challenge = "basil.qualify.shutdown.owned.challenge";
    let owned_config = federation_config_for_subjects(
        &nats_url,
        &socket_guard.socket,
        server_uid,
        &bucket,
        owned_request,
        owned_challenge,
    );
    let owned_heartbeat_deadline = tokio::time::Instant::now() + HEARTBEAT_EXCLUSION_BOUND;
    let mut owned_bridge = TaskGuard::new(tokio::spawn(basil_nats_bridge::run(owned_config)));
    request_until_ready(
        &nats,
        owned_challenge,
        valid_challenge_request().encode_to_vec(),
    )
    .await;
    let owned_key = lease_key(owned_challenge, owned_request);
    let owned = tokio::time::timeout_at(owned_heartbeat_deadline, store.entry(&owned_key))
        .await
        .expect("owned lease read completed before the heartbeat exclusion deadline")
        .expect("read owned shutdown lease")
        .expect("owned lease exists before graceful shutdown");
    assert_eq!(owned.operation, Operation::Put);

    signal_graceful_shutdown();
    let owned_result = owned_bridge
        .result_before(owned_heartbeat_deadline, "owned graceful-shutdown bridge")
        .await
        .expect("owned graceful-shutdown bridge task joined");
    assert!(tokio::time::Instant::now() < owned_heartbeat_deadline);
    assert!(owned_result.is_ok(), "owned lease shutdown succeeds");
    let deleted = bounded_entry(&store, &owned_key, "deleted shutdown lease")
        .await
        .expect("graceful shutdown leaves a JetStream delete marker");
    assert_eq!(deleted.operation, Operation::Delete);
    assert_eq!(
        deleted.revision,
        owned.revision + 1,
        "expected-revision deletion is the next write for the owned lease"
    );

    let stale_request = "basil.qualify.shutdown.stale.invoke";
    let stale_challenge = "basil.qualify.shutdown.stale.challenge";
    let stale_config = federation_config_for_subjects(
        &nats_url,
        &socket_guard.socket,
        server_uid,
        &bucket,
        stale_request,
        stale_challenge,
    );
    let stale_heartbeat_deadline = tokio::time::Instant::now() + HEARTBEAT_EXCLUSION_BOUND;
    let mut stale_bridge = TaskGuard::new(tokio::spawn(basil_nats_bridge::run(stale_config)));
    request_until_ready(
        &nats,
        stale_challenge,
        valid_challenge_request().encode_to_vec(),
    )
    .await;
    let stale_key = lease_key(stale_challenge, stale_request);
    let stale_owned = tokio::time::timeout_at(stale_heartbeat_deadline, store.entry(&stale_key))
        .await
        .expect("stale lease read completed before the heartbeat exclusion deadline")
        .expect("read stale shutdown lease")
        .expect("stale bridge owns a lease before replacement");
    let replacement = Bytes::from_static(b"replacement-owner-instance");
    let replacement_revision = tokio::time::timeout_at(
        stale_heartbeat_deadline,
        store.update(&stale_key, replacement.clone(), stale_owned.revision),
    )
    .await
    .expect("replacement CAS completed before the heartbeat exclusion deadline")
    .expect("replace the stale bridge lease revision");
    assert!(tokio::time::Instant::now() < stale_heartbeat_deadline);

    signal_graceful_shutdown();
    let stale_result = stale_bridge
        .result_before(stale_heartbeat_deadline, "stale graceful-shutdown bridge")
        .await
        .expect("stale graceful-shutdown bridge task joined");
    assert!(tokio::time::Instant::now() < stale_heartbeat_deadline);
    assert!(matches!(stale_result, Err(RuntimeError::LeaseLost)));
    let preserved = bounded_entry(&store, &stale_key, "preserved replacement lease")
        .await
        .expect("replacement lease remains after stale shutdown");
    assert_eq!(preserved.operation, Operation::Put);
    assert_eq!(preserved.revision, replacement_revision);
    assert_eq!(preserved.value, replacement);

    server.abort_and_reap().await;
    drop(nats);
    nats_server.stop_bounded();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn jetstream_real_bucket_bounds_expiry_and_distinct_subject_pairs() {
    let _serial_guard = QUALIFICATION_SERIAL.lock().await;
    require_nats_server_2_14_5();

    let port = port_from(&alloc_addr());
    let (mut nats_server, nats_url) = start_nats_server(port).await;
    let nats = tokio::time::timeout(ASYNC_BOUND, async_nats::connect(&nats_url))
        .await
        .expect("bucket-matrix NATS connection completed within its deadline")
        .expect("connect bucket-matrix NATS client");
    let qualified_bucket = format!("BASILQ{port}");
    let store = create_lease_bucket(&nats, &qualified_bucket).await;
    let wrong_history = format!("BASILH{port}");
    create_bucket(&nats, &wrong_history, 2, Duration::from_secs(15)).await;
    let wrong_age = format!("BASILA{port}");
    create_bucket(&nats, &wrong_age, 1, Duration::from_secs(14)).await;
    let missing_bucket = format!("BASILM{port}");

    let service = QualificationService::default();
    let (socket_guard, listener, server_uid) = bind_test_socket(port, "bucket-matrix");
    let mut server = spawn_service(listener, service);
    for (bucket, context) in [
        (wrong_history.as_str(), "wrong-history bucket"),
        (wrong_age.as_str(), "wrong-max-age bucket"),
        (missing_bucket.as_str(), "unavailable bucket"),
    ] {
        let config = federation_config(&nats_url, &socket_guard.socket, server_uid, bucket);
        assert_lease_setup_failure(config, context).await;
    }

    let request_a = "basil.qualify.distinct.a.invoke";
    let challenge_a = "basil.qualify.distinct.a.challenge";
    let request_b = "basil.qualify.distinct.b.invoke";
    let challenge_b = "basil.qualify.distinct.b.challenge";
    let config_a = federation_config_for_subjects(
        &nats_url,
        &socket_guard.socket,
        server_uid,
        &qualified_bucket,
        request_a,
        challenge_a,
    );
    let config_b = federation_config_for_subjects(
        &nats_url,
        &socket_guard.socket,
        server_uid,
        &qualified_bucket,
        request_b,
        challenge_b,
    );
    let mut bridge_a = TaskGuard::new(tokio::spawn(basil_nats_bridge::run(config_a.clone())));
    let mut bridge_b = TaskGuard::new(tokio::spawn(basil_nats_bridge::run(config_b)));
    request_until_ready(
        &nats,
        challenge_a,
        valid_challenge_request().encode_to_vec(),
    )
    .await;
    request_until_ready(
        &nats,
        challenge_b,
        valid_challenge_request().encode_to_vec(),
    )
    .await;
    let key_a = lease_key(challenge_a, request_a);
    let key_b = lease_key(challenge_b, request_b);
    assert_ne!(key_a, key_b);
    let lease_a = bounded_entry(&store, &key_a, "distinct lease A")
        .await
        .expect("first subject pair has an independent lease");
    let lease_b = bounded_entry(&store, &key_b, "distinct lease B")
        .await
        .expect("second subject pair has an independent lease");
    assert_eq!(lease_a.operation, Operation::Put);
    assert_eq!(lease_b.operation, Operation::Put);

    bridge_a.abort_and_reap().await;
    bridge_b.abort_and_reap().await;
    wait_for_key_expiry(&store, &key_a).await;
    assert!(
        bounded_entry(&store, &key_a, "expired lease A")
            .await
            .is_none(),
        "an ungracefully abandoned real lease expires from JetStream"
    );

    let mut reacquired = TaskGuard::new(tokio::spawn(basil_nats_bridge::run(config_a)));
    request_until_ready(
        &nats,
        challenge_a,
        valid_challenge_request().encode_to_vec(),
    )
    .await;
    let lease_a_reacquired = bounded_entry(&store, &key_a, "reacquired lease A")
        .await
        .expect("expired subject-pair lease can be acquired again");
    assert_eq!(lease_a_reacquired.operation, Operation::Put);

    reacquired.abort_and_reap().await;
    server.abort_and_reap().await;
    drop(nats);
    nats_server.stop_bounded();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_mode_rejects_a_listener_that_claims_remote_freshness() {
    let _serial_guard = QUALIFICATION_SERIAL.lock().await;
    require_nats_server_2_14_5();

    let port = port_from(&alloc_addr());
    let (mut nats_server, nats_url) = start_nats_server(port).await;
    let (socket_guard, listener, server_uid) = bind_test_socket(port, "legacy");
    let mut server = spawn_service(
        listener,
        CapabilityService {
            capabilities: federation_capabilities(),
        },
    );
    let config = Config {
        nats: NatsConfig {
            url: nats_url,
            creds: None,
        },
        basil: basil_config(&socket_guard.socket, server_uid),
        bridge: BridgeConfig {
            request_subject: REQUEST_SUBJECT.to_string(),
            challenge_subject: None,
            source_partition: None,
            lease_bucket: None,
            queue_group: None,
            max_message_bytes: MAX_MESSAGE_BYTES,
            concurrency_limit: 4,
            challenge_concurrency_limit: 1,
        },
    };
    let result = tokio::time::timeout(Duration::from_secs(5), basil_nats_bridge::run(config))
        .await
        .expect("legacy bridge rejected the courier listener promptly");
    assert!(matches!(result, Err(RuntimeError::BasilConnect)));
    server.abort_and_reap().await;
    nats_server.stop_bounded();
}

async fn start_nats_server(port: u16) -> (NatsServer, String) {
    let storage = std::env::temp_dir().join(format!("basil-nats-qualification-{port}"));
    let _ = std::fs::remove_dir_all(&storage);
    std::fs::create_dir(&storage).expect("create JetStream storage directory");
    let child = Command::new("nats-server")
        .args(["-a", "127.0.0.1", "-p", &port.to_string(), "-js", "-sd"])
        .arg(&storage)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn JetStream-enabled nats-server");
    let server = NatsServer { child, storage };
    let url = format!("nats://127.0.0.1:{port}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(Ok(client)) =
            tokio::time::timeout(Duration::from_millis(500), async_nats::connect(&url)).await
        {
            drop(client);
            return (server, url);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "JetStream nats-server never became reachable at {url}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn create_lease_bucket(nats: &async_nats::Client, bucket: &str) -> kv::Store {
    create_bucket(nats, bucket, 1, Duration::from_secs(15)).await
}

async fn create_bucket(
    nats: &async_nats::Client,
    bucket: &str,
    history: i64,
    max_age: Duration,
) -> kv::Store {
    let context = async_nats::jetstream::new(nats.clone());
    tokio::time::timeout(
        ASYNC_BOUND,
        context.create_key_value(kv::Config {
            bucket: bucket.to_string(),
            history,
            max_age,
            storage: StorageType::Memory,
            ..Default::default()
        }),
    )
    .await
    .expect("lease bucket creation completed within its deadline")
    .expect("create exact federation lease bucket")
}

async fn wait_for_arrivals(gate: &IngressGate, expected: usize, context: &str) {
    let deadline = tokio::time::Instant::now() + ASYNC_BOUND;
    while gate.arrivals.load(Ordering::SeqCst) < expected {
        tokio::time::timeout_at(deadline, gate.arrived.notified())
            .await
            .unwrap_or_else(|_| panic!("{context} did not reach the service barrier in time"));
    }
}

fn padded_challenge_request(target_len: usize) -> Vec<u8> {
    let mut message = GetInvocationChallengeRequest {
        jkt: JKT.to_vec(),
        courier_observed_source: None,
    }
    .encode_to_vec();
    let padding = (0..target_len)
        .find(|padding| message.len() + 1 + encoded_varint_len(*padding) + padding == target_len)
        .expect("target length accommodates one ignored protobuf field");
    message.push(0x7a);
    push_varint(&mut message, padding);
    message.resize(target_len, 0);
    message
}

const fn encoded_varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

fn push_varint(output: &mut Vec<u8>, mut value: usize) {
    while value >= 0x80 {
        output.push(u8::try_from(value & 0x7f).expect("seven varint bits fit u8") | 0x80);
        value >>= 7;
    }
    output.push(u8::try_from(value).expect("final varint byte fits u8"));
}

fn require_nats_server_2_14_5() {
    let mut child = Command::new("nats-server")
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the dedicated qualification lane requires nats-server on PATH");
    let status = wait_for_exit(&mut child, PROCESS_REAP_BOUND).unwrap_or_else(|| {
        assert!(
            kill_and_reap(&mut child, PROCESS_REAP_BOUND),
            "hung nats-server version probe could not be reaped"
        );
        panic!("nats-server version probe exceeded its deadline");
    });
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .expect("capture nats-server version stdout")
        .read_to_string(&mut stdout)
        .expect("read nats-server version stdout");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("capture nats-server version stderr")
        .read_to_string(&mut stderr)
        .expect("read nats-server version stderr");
    assert!(status.success(), "nats-server --version failed: {stderr}");
    assert_eq!(
        stdout.trim(),
        REQUIRED_NATS_VERSION,
        "the qualification contract pins the real NATS server version"
    );
}

fn wait_for_exit(child: &mut Child, bound: Duration) -> Option<std::process::ExitStatus> {
    let deadline = StdInstant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if StdInstant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => return None,
        }
    }
}

fn kill_and_reap(child: &mut Child, bound: Duration) -> bool {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return true;
    }
    let _ = child.kill();
    wait_for_exit(child, bound).is_some()
}

fn bind_test_socket(port: u16, label: &str) -> (SocketGuard, tokio::net::UnixListener, u32) {
    let directory = std::env::current_dir()
        .expect("current directory")
        .join(format!(".bnq-{label}-{port}"));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create trusted socket directory");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o750))
        .expect("set trusted socket directory mode");
    let socket = directory.join("broker.sock");
    let listener = bind_existing_socket(&socket);
    let uid = std::fs::metadata(&socket).expect("stat Basil UDS").uid();
    (SocketGuard { directory, socket }, listener, uid)
}

fn bind_existing_socket(socket: &Path) -> tokio::net::UnixListener {
    let listener = tokio::net::UnixListener::bind(socket).expect("bind Basil UDS");
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))
        .expect("set Basil UDS mode");
    listener
}

fn spawn_service<T>(listener: tokio::net::UnixListener, service: T) -> TaskGuard<()>
where
    T: InvocationService + Clone + Send + Sync + 'static,
{
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
    TaskGuard::new(tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(InvocationServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .expect("serve qualification InvocationService");
    }))
}

fn federation_config(nats_url: &str, socket: &Path, uid: u32, bucket: &str) -> Config {
    federation_config_for_subjects(
        nats_url,
        socket,
        uid,
        bucket,
        REQUEST_SUBJECT,
        CHALLENGE_SUBJECT,
    )
}

fn federation_config_for_subjects(
    nats_url: &str,
    socket: &Path,
    uid: u32,
    bucket: &str,
    request_subject: &str,
    challenge_subject: &str,
) -> Config {
    Config {
        nats: NatsConfig {
            url: nats_url.to_string(),
            creds: None,
        },
        basil: basil_config(socket, uid),
        bridge: BridgeConfig {
            request_subject: request_subject.to_string(),
            challenge_subject: Some(challenge_subject.to_string()),
            source_partition: Some(SOURCE_PARTITION.to_string()),
            lease_bucket: Some(bucket.to_string()),
            queue_group: None,
            max_message_bytes: MAX_MESSAGE_BYTES,
            concurrency_limit: 8,
            challenge_concurrency_limit: 2,
        },
    }
}

fn basil_config(socket: &Path, uid: u32) -> BasilConfig {
    BasilConfig {
        socket: socket.to_path_buf(),
        service_owner_uid: uid,
        directory_owner_uid: uid,
        directory_mode: 0o750,
        server_uid: uid,
        socket_mode: 0o660,
    }
}

fn valid_challenge_request() -> GetInvocationChallengeRequest {
    GetInvocationChallengeRequest {
        jkt: JKT.to_vec(),
        courier_observed_source: None,
    }
}

async fn assert_lease_setup_failure(config: Config, context: &str) {
    let mut bridge = TaskGuard::new(tokio::spawn(basil_nats_bridge::run(config)));
    let result = bridge
        .result_bounded(ASYNC_BOUND, context)
        .await
        .expect("lease setup bridge task joined");
    assert!(matches!(result, Err(RuntimeError::LeaseSetup)));
}

async fn bounded_entry(store: &kv::Store, key: &str, context: &str) -> Option<kv::Entry> {
    tokio::time::timeout(ASYNC_BOUND, store.entry(key))
        .await
        .unwrap_or_else(|_| panic!("{context} read exceeded its deadline"))
        .unwrap_or_else(|error| panic!("{context} read failed: {error}"))
}

async fn wait_for_key_expiry(store: &kv::Store, key: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut poll = tokio::time::interval(Duration::from_millis(100));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::time::timeout_at(deadline, poll.tick())
            .await
            .expect("real JetStream lease expired within its deadline");
        if tokio::time::timeout_at(deadline, store.entry(key))
            .await
            .expect("expiry observation completed within its deadline")
            .expect("read expiring lease")
            .is_none()
        {
            return;
        }
    }
}

fn signal_graceful_shutdown() {
    let raw_pid = i32::try_from(std::process::id()).expect("test process ID fits i32");
    let pid = rustix::process::Pid::from_raw(raw_pid).expect("test process ID is nonzero");
    rustix::process::kill_process(pid, rustix::process::Signal::INT)
        .expect("send SIGINT to the production bridge shutdown path");
}

async fn request_until_ready(
    nats: &async_nats::Client,
    subject: &str,
    payload: Vec<u8>,
) -> async_nats::Message {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(Ok(message)) = tokio::time::timeout(
            Duration::from_secs(1),
            nats.request(subject.to_string(), Bytes::from(payload.clone())),
        )
        .await
        {
            return message;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "bridge did not become ready on {subject}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn bounded_request(
    nats: &async_nats::Client,
    subject: &str,
    payload: Vec<u8>,
) -> async_nats::Message {
    tokio::time::timeout(
        Duration::from_secs(12),
        nats.request(subject.to_string(), Bytes::from(payload)),
    )
    .await
    .expect("NATS request completed within the qualification bound")
    .expect("NATS request received a bridge reply")
}

fn assert_no_bridge_error(message: &async_nats::Message) {
    assert!(
        message
            .headers
            .as_ref()
            .is_none_or(|headers| headers.get("Basil-Bridge-Error").is_none()),
        "unexpected bridge error headers: {:?}",
        message.headers
    );
}

fn assert_bridge_error(message: &async_nats::Message, code: &str, retryable: bool) {
    assert!(message.payload.is_empty());
    let headers = message.headers.as_ref().expect("bridge error headers");
    assert_eq!(headers.len(), 2, "bridge errors expose exactly two headers");
    assert_eq!(
        headers
            .get("Basil-Bridge-Error")
            .expect("stable bridge error code")
            .as_str(),
        code
    );
    assert_eq!(
        headers
            .get("Basil-Bridge-Retryable")
            .expect("stable retryability marker")
            .as_str(),
        retryable.to_string()
    );
}

fn assert_sanitized(message: &async_nats::Message) {
    let rendered = format!("{:?}{:?}", message.headers, message.payload);
    assert!(!rendered.contains("provider JWT"));
    assert!(!rendered.contains("private broker"));
}

fn lease_key(challenge_subject: &str, request_subject: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"basil-courier-nats-v1\0");
    digest.update(challenge_subject.as_bytes());
    digest.update(b"\0");
    digest.update(request_subject.as_bytes());
    format!("lease.{}", URL_SAFE_NO_PAD.encode(digest.finalize()))
}

fn signer(name: &str, seed: [u8; 32]) -> Ed25519Signer {
    Ed25519Signer::from_secret_bytes(
        KeyId::from_text(name).expect("key id"),
        &Zeroizing::new(seed),
    )
}

fn recipient(name: &str, seed: [u8; 32]) -> X25519Recipient {
    X25519Recipient::new(
        KeyId::from_text(name).expect("key id"),
        Zeroizing::new(seed),
    )
}

async fn seal_request(
    signer: &Ed25519Signer,
    recipient: X25519RecipientPublic,
    response_key_id: KeyId,
    message_id: MessageId,
    now: UnixTime,
    challenge: &[u8],
) -> Vec<u8> {
    let claims = Claims {
        issuer: Some(Subject::new("qualification-client".to_string()).expect("subject")),
        audience: None,
        expires_at: Some(UnixTime(now.0 + 120)),
        issued_at: now,
        message_id,
        sender_key_id: Some(signer.key_id().clone()),
        response_key_id: Some(response_key_id),
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
        freshness_challenge: Some(
            FreshnessChallenge::from_bytes(challenge).expect("32-byte freshness challenge"),
        ),
        response_public_key_cose: None,
    };
    seal(
        b"freshness-qualified request",
        claims,
        MessageRole::Request,
        recipient,
        signer,
    )
    .await
}

async fn seal_response(
    plaintext: &[u8],
    signer: &Ed25519Signer,
    recipient: X25519RecipientPublic,
    in_reply_to: MessageId,
    request_hash: RequestHash,
    message_id: &[u8],
    now: UnixTime,
) -> Vec<u8> {
    let claims = Claims {
        issuer: Some(Subject::new("qualification-broker".to_string()).expect("subject")),
        audience: None,
        expires_at: Some(UnixTime(now.0 + 120)),
        issued_at: now,
        message_id: MessageId::from_bytes(message_id.to_vec()).expect("response message id"),
        sender_key_id: Some(signer.key_id().clone()),
        response_key_id: None,
        response_subject: None,
        in_reply_to: Some(in_reply_to),
        request_hash: Some(request_hash),
        freshness_challenge: None,
        response_public_key_cose: None,
    };
    seal(plaintext, claims, MessageRole::Response, recipient, signer).await
}

async fn seal(
    plaintext: &[u8],
    claims: Claims,
    role: MessageRole,
    recipient: X25519RecipientPublic,
    signer: &Ed25519Signer,
) -> Vec<u8> {
    build_sealed(
        &SealParams {
            content_type: ContentType::new("application/basil.nats-qualification".to_string())
                .expect("content type"),
            plaintext,
            claims,
            role,
            recipient,
            content_algorithm: ContentAlgorithm::A256Gcm,
            aad: SealedAad::empty(),
            kdf_parties: KdfParties::anonymous(),
        },
        signer,
    )
    .await
    .expect("build sealed qualification message")
    .into_vec()
}

fn now_unix() -> UnixTime {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    UnixTime(i64::try_from(seconds).expect("Unix seconds fit i64"))
}

fn port_from(address: &str) -> u16 {
    address
        .rsplit(':')
        .next()
        .and_then(|port| port.parse().ok())
        .expect("alloc_addr yields a host and port")
}
