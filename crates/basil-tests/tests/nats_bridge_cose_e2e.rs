//! LIVE e2e round-trips through the `basil-nats-bridge` COSE courier over a
//! real `nats-server`.
//!
//! Bridge coverage was unit-level only (`basil-nats-bridge` lib tests: config
//! parsing + `handle_request` shape with a `FakeBasil`). What was missing is an
//! actual round-trip through the production courier over a real NATS server: a
//! sealed COSE request published on NATS, forwarded to Basil, and the sealed COSE
//! response delivered back and opened/verified.
//!
//! This test drives the REAL bridge `run()` loop:
//!   1. spawn a real `nats-server`;
//!   2. stand up a minimal in-process `InvocationService` gRPC server over a unix
//!      socket that returns a genuine sealed COSE response (built with `basil-cose`);
//!   3. run `basil_nats_bridge::run()` connecting the two;
//!   4. a NATS client publishes a genuine sealed COSE request (built with
//!      `basil-cose`) to the bridge's request subject and awaits the reply;
//!   5. the reply is the sealed COSE response: we verify the broker signature and
//!      open it, and the courier is proven to carry the request bytes byte-exact
//!      (the gRPC server only replies when the forwarded bytes match).
//!
//! The first leg is Rust-only (basil-cq25). The second leg runs the Go client
//! helper/example against the same real bridge so a Go-built sealed request and
//! Go-opened sealed response prove cross-language courier interop. GATING:
//! missing `go` or `nats-server` prints an explicit skip line.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::significant_drop_tightening,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use basil_cose::{
    Claims, ContentAlgorithm, ContentType, Ed25519Signer, Ed25519Verifier, ExternalAad, KdfParties,
    KeyId, MessageId, MessageRole, RequestHash, SealParams, SealedAad, Signer, Subject, UnixTime,
    ValidationParams, VerifySealedParams, Zeroizing, build_sealed, request_hash, verify_sealed,
};
use basil_cose::{X25519Recipient, X25519RecipientPublic};
use basil_nats_bridge::{BasilConfig, BridgeConfig, Config, NatsConfig};
use basil_proto::broker::v1::invocation_service_server::{
    InvocationService, InvocationServiceServer,
};
use basil_proto::broker::v1::{SealedRequest, SealedResponse};
use tonic::{Request, Response, Status};

use basil_tests::{alloc_addr, on_path};

const REQUEST_SUBJECT: &str = "basil.invoke.roundtrip";
const REQUEST_BODY: &[u8] = b"sealed-cose round-trip request";
const RESPONSE_BODY: &[u8] = b"sealed-cose round-trip response";
const GO_REQUEST_CONTENT_TYPE: &str = "application/basil.go-nats-bridge-request";
const GO_RESPONSE_CONTENT_TYPE: &str = "application/basil.go-nats-bridge-response";

/// A minimal Basil `InvocationService`: it replies with a pre-built sealed COSE
/// response ONLY when the courier forwarded the exact sealed request bytes,
/// proving the inbound NATS leg is byte-exact. The response leg is proven by the
/// client opening + verifying the returned sealed COSE.
#[derive(Clone)]
struct FakeInvocationService {
    expected_request: Vec<u8>,
    response_bytes: Vec<u8>,
}

#[tonic::async_trait]
impl InvocationService for FakeInvocationService {
    async fn invoke(
        &self,
        request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        let message = &request.get_ref().message;
        if message != &self.expected_request {
            return Err(Status::invalid_argument(
                "courier forwarded unexpected request bytes",
            ));
        }
        Ok(Response::new(SealedResponse {
            message: self.response_bytes.clone(),
            // No response_subject => the bridge replies on the NATS reply subject.
            response_subject: None,
        }))
    }
}

/// A minimal Basil `InvocationService` for the Go interop leg. Unlike
/// `FakeInvocationService`, this verifies and opens the Go-built request before
/// sealing a fresh response back to the Go-held response key.
#[derive(Clone)]
struct VerifyingInvocationService {
    client_verifier: Arc<Ed25519Verifier>,
    request_recipient: Arc<X25519Recipient>,
    broker_signer: Arc<Ed25519Signer>,
    response_recipient: X25519RecipientPublic,
    now: UnixTime,
}

#[tonic::async_trait]
impl InvocationService for VerifyingInvocationService {
    async fn invoke(
        &self,
        request: Request<SealedRequest>,
    ) -> Result<Response<SealedResponse>, Status> {
        let message = &request.get_ref().message;
        let validation = ValidationParams {
            now: self.now,
            max_clock_skew: Duration::from_secs(60),
            max_ttl: Duration::from_secs(300),
            default_ttl: Duration::from_secs(300),
            allowed_audiences: BTreeSet::new(),
            role: MessageRole::Request,
        };
        let verified = verify_sealed(
            message,
            self.client_verifier.as_ref(),
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation,
            },
        )
        .await
        .map_err(|e| Status::invalid_argument(format!("go request verify failed: {e}")))?;
        if verified.content_type.as_str() != GO_REQUEST_CONTENT_TYPE {
            return Err(Status::invalid_argument(format!(
                "go request content type = {}, want {GO_REQUEST_CONTENT_TYPE}",
                verified.content_type.as_str()
            )));
        }
        let opened = verified
            .open(
                self.request_recipient.as_ref(),
                &ExternalAad::empty(),
                Some(&KdfParties::anonymous()),
            )
            .await
            .map_err(|e| Status::invalid_argument(format!("go request open failed: {e}")))?;
        if opened.plaintext.as_slice() != REQUEST_BODY {
            return Err(Status::invalid_argument(
                "go request plaintext did not match",
            ));
        }

        let response_bytes = seal_with_content_type(
            RESPONSE_BODY,
            GO_RESPONSE_CONTENT_TYPE,
            response_claims(
                self.broker_signer.as_ref(),
                verified.claims.message_id,
                request_hash(message),
                self.now,
            ),
            MessageRole::Response,
            self.response_recipient.clone(),
            self.broker_signer.as_ref(),
        )
        .await;
        Ok(Response::new(SealedResponse {
            message: response_bytes,
            response_subject: None,
        }))
    }
}

/// RAII guard that reaps the spawned `nats-server` on drop (incl. on panic).
struct NatsServer {
    child: Child,
}

impl Drop for NatsServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn now_unix() -> UnixTime {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    UnixTime(i64::try_from(secs).expect("unix seconds fit i64"))
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

/// A `Request`-shaped claim set: requires `sender_key_id` + `response_key_id`.
fn request_claims(
    sender_key: &Ed25519Signer,
    response_key: &KeyId,
    message_id: MessageId,
    now: UnixTime,
) -> Claims {
    Claims {
        issuer: Some(Subject::new("client".to_string()).expect("subject")),
        audience: None,
        expires_at: Some(UnixTime(now.0 + 120)),
        issued_at: now,
        message_id,
        sender_key_id: Some(sender_key.key_id().clone()),
        response_key_id: Some(response_key.clone()),
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
    }
}

/// A `Response`-shaped claim set: requires `in_reply_to` + `request_hash` and
/// forbids `response_key_id`/`response_subject`.
fn response_claims(
    sender_key: &Ed25519Signer,
    in_reply_to: MessageId,
    request_hash: RequestHash,
    now: UnixTime,
) -> Claims {
    Claims {
        issuer: Some(Subject::new("broker".to_string()).expect("subject")),
        audience: None,
        expires_at: Some(UnixTime(now.0 + 120)),
        issued_at: now,
        message_id: MessageId::from_bytes(b"roundtrip-response".to_vec()).expect("message id"),
        sender_key_id: Some(sender_key.key_id().clone()),
        response_key_id: None,
        response_subject: None,
        in_reply_to: Some(in_reply_to),
        request_hash: Some(request_hash),
    }
}

async fn seal(
    plaintext: &[u8],
    claim_set: Claims,
    role: MessageRole,
    recipient_public: X25519RecipientPublic,
    signer: &Ed25519Signer,
) -> Vec<u8> {
    seal_with_content_type(
        plaintext,
        "application/basil.roundtrip",
        claim_set,
        role,
        recipient_public,
        signer,
    )
    .await
}

async fn seal_with_content_type(
    plaintext: &[u8],
    content_type: &str,
    claim_set: Claims,
    role: MessageRole,
    recipient_public: X25519RecipientPublic,
    signer: &Ed25519Signer,
) -> Vec<u8> {
    build_sealed(
        &SealParams {
            content_type: ContentType::new(content_type.to_string()).expect("content type"),
            plaintext,
            claims: claim_set,
            role,
            recipient: recipient_public,
            content_algorithm: ContentAlgorithm::A256Gcm,
            aad: SealedAad::empty(),
            kdf_parties: KdfParties::anonymous(),
        },
        signer,
    )
    .await
    .expect("build sealed COSE")
    .into_vec()
}

/// Spawn `nats-server` on `port` and wait until a client can connect.
async fn start_nats_server(port: u16) -> (NatsServer, String) {
    let child = Command::new("nats-server")
        .args(["-a", "127.0.0.1", "-p", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nats-server");
    let server = NatsServer { child };
    let url = format!("nats://127.0.0.1:{port}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(client) = async_nats::connect(&url).await {
            drop(client);
            return (server, url);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "nats-server never became reachable on {url}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nats_bridge_round_trips_sealed_cose() {
    if !on_path("nats-server") {
        eprintln!("SKIP nats bridge COSE round-trip e2e: nats-server not on PATH");
        return;
    }

    // --- COSE identities: client signs the request; broker signs the response.
    let client_signer = signer("client.signing", [7u8; 32]);
    let broker_signer = signer("broker.signing", [9u8; 32]);
    let broker_verifier = Ed25519Verifier::from_key(
        broker_signer.key_id().clone(),
        &broker_signer.public_key_bytes(),
    )
    .expect("broker verifier");

    // Request sealed TO the broker's request key; response sealed TO the client's
    // response key (the client holds that recipient private half).
    let request_recipient = recipient("request.sealing", [0x11u8; 32]);
    let response_recipient = recipient("response.sealing", [0x22u8; 32]);

    let now = now_unix();
    let response_key_id = KeyId::from_text("response.sealing").expect("key id");
    let request_id = MessageId::from_bytes(b"roundtrip-request".to_vec()).expect("message id");
    let request_bytes = seal(
        REQUEST_BODY,
        request_claims(&client_signer, &response_key_id, request_id.clone(), now),
        MessageRole::Request,
        request_recipient.public(),
        &client_signer,
    )
    .await;
    let response_bytes = seal(
        RESPONSE_BODY,
        response_claims(
            &broker_signer,
            request_id,
            request_hash(&request_bytes),
            now,
        ),
        MessageRole::Response,
        response_recipient.public(),
        &broker_signer,
    )
    .await;

    // --- real nats-server on a disjoint port.
    let port = port_from(&alloc_addr());
    let (_nats, nats_url) = start_nats_server(port).await;

    // --- minimal in-process Basil InvocationService gRPC server over a unix socket.
    let socket: PathBuf = std::env::temp_dir().join(format!(
        "basil-nats-bridge-e2e-{}-{}.sock",
        std::process::id(),
        port
    ));
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind basil uds");
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
    let service = FakeInvocationService {
        expected_request: request_bytes.clone(),
        response_bytes: response_bytes.clone(),
    };
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(InvocationServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
    });

    // --- run the REAL bridge courier connecting NATS <-> the Basil socket.
    let config = Config {
        nats: NatsConfig {
            url: nats_url.clone(),
            creds: None,
        },
        basil: BasilConfig {
            socket: socket.clone(),
        },
        bridge: BridgeConfig {
            request_subject: REQUEST_SUBJECT.to_string(),
            queue_group: None,
            max_message_bytes: 1024 * 1024,
        },
    };
    let bridge = tokio::spawn(async move { basil_nats_bridge::run(config).await });

    // --- publish the sealed COSE request through NATS and await the sealed reply.
    let nats = async_nats::connect(&nats_url)
        .await
        .expect("connect nats request client");
    let reply = request_with_retry(&nats, &request_bytes).await;

    // The reply must be the sealed COSE response (no bridge error headers), and it
    // must verify + open to the expected plaintext.
    assert!(
        reply
            .headers
            .as_ref()
            .is_none_or(|h| h.get("Basil-Bridge-Error").is_none()),
        "reply carried a bridge error header: {:?}",
        reply.headers
    );
    assert_eq!(
        reply.payload.as_ref(),
        response_bytes.as_slice(),
        "courier delivered the exact sealed COSE response bytes"
    );

    let validation = ValidationParams {
        now,
        max_clock_skew: Duration::from_secs(60),
        max_ttl: Duration::from_secs(300),
        default_ttl: Duration::from_secs(300),
        allowed_audiences: BTreeSet::new(),
        role: MessageRole::Response,
    };
    let verified = verify_sealed(
        &reply.payload,
        &broker_verifier,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation,
        },
    )
    .await
    .expect("broker-signed sealed response verifies");
    let opened = verified
        .open(
            &response_recipient,
            &ExternalAad::empty(),
            Some(&KdfParties::anonymous()),
        )
        .await
        .expect("open sealed response with the client's response key");
    assert_eq!(
        opened.plaintext.as_slice(),
        RESPONSE_BODY,
        "opened response plaintext matches what the broker sealed"
    );

    bridge.abort();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_client_round_trips_sealed_cose_through_nats_bridge() {
    if !on_path("go") {
        eprintln!("SKIP nats bridge Go COSE interop e2e: go not on PATH");
        return;
    }
    if !on_path("nats-server") {
        eprintln!("SKIP nats bridge Go COSE interop e2e: nats-server not on PATH");
        return;
    }

    let client_signer = signer("client.signing", [7u8; 32]);
    let client_verifier = Arc::new(
        Ed25519Verifier::from_key(
            client_signer.key_id().clone(),
            &client_signer.public_key_bytes(),
        )
        .expect("client verifier"),
    );
    let broker_signer = Arc::new(signer("broker.signing", [9u8; 32]));
    let request_recipient = Arc::new(recipient("request.sealing", [0x11u8; 32]));
    let response_recipient = recipient("response.sealing", [0x22u8; 32]);
    let response_public = response_recipient.public();

    let port = port_from(&alloc_addr());
    let (_nats, nats_url) = start_nats_server(port).await;

    let socket: PathBuf = std::env::temp_dir().join(format!(
        "basil-nats-bridge-go-e2e-{}-{}.sock",
        std::process::id(),
        port
    ));
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).expect("bind basil uds");
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);
    let service = VerifyingInvocationService {
        client_verifier,
        request_recipient: Arc::clone(&request_recipient),
        broker_signer: Arc::clone(&broker_signer),
        response_recipient: response_public,
        now: now_unix(),
    };
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(InvocationServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
    });

    let config = Config {
        nats: NatsConfig {
            url: nats_url.clone(),
            creds: None,
        },
        basil: BasilConfig {
            socket: socket.clone(),
        },
        bridge: BridgeConfig {
            request_subject: REQUEST_SUBJECT.to_string(),
            queue_group: None,
            max_message_bytes: 1024 * 1024,
        },
    };
    let bridge = tokio::spawn(async move { basil_nats_bridge::run(config).await });

    let go_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("clients/go");
    let go_output = tokio::task::spawn_blocking(move || {
        Command::new("go")
            .args(["run", "./examples/nats-cose-courier"])
            .current_dir(go_dir)
            .env("BASIL_NATS_URL", nats_url)
            .env("BASIL_NATS_SUBJECT", REQUEST_SUBJECT)
            .env(
                "BASIL_REQUEST_RECIPIENT_PUBLIC_HEX",
                hex(&request_recipient.public().public),
            )
            .env(
                "BASIL_BROKER_SIGNING_PUBLIC_HEX",
                hex(&broker_signer.public_key_bytes()),
            )
            .output()
            .expect("run go nats COSE courier example")
    })
    .await
    .expect("join go runner");
    assert!(
        go_output.status.success(),
        "go nats COSE courier example failed\nstatus: {:?}\nstdout:\n{}\nstderr:\n{}",
        go_output.status,
        String::from_utf8_lossy(&go_output.stdout),
        String::from_utf8_lossy(&go_output.stderr)
    );

    bridge.abort();
    server.abort();
}

/// Parse the `127.0.0.1:<port>` port out of an `alloc_addr()` `http://` URL.
fn port_from(addr: &str) -> u16 {
    addr.rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .expect("alloc_addr yields a host:port URL")
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(TABLE[usize::from(b >> 4)]));
        out.push(char::from(TABLE[usize::from(b & 0x0f)]));
    }
    out
}

/// Publish the sealed request via NATS request/reply, retrying while the bridge's
/// subscription is still coming up (a fresh subject has no responders until then).
async fn request_with_retry(nats: &async_nats::Client, payload: &[u8]) -> async_nats::Message {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        match nats
            .request(REQUEST_SUBJECT, bytes::Bytes::copy_from_slice(payload))
            .await
        {
            Ok(message) => return message,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "bridge never answered a sealed-invocation request: {error}"
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
}
