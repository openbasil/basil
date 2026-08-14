// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Real RPC-to-JSONL acceptance for the terminal federated-CI invocation audit.

#![cfg(all(feature = "live-e2e", target_os = "linux"))]
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::fmt::Write as _;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use basil_core::ci_federation::{proof_audience, proof_key_kid, proof_key_thumbprint};
use basil_cose::{
    Claims, ContentAlgorithm, ContentType, Ed25519Signer, Ed25519Verifier, ExternalAad,
    FreshnessChallenge, KdfParties, KeyId, MessageId, MessageRole, ProtectedHeaders, SealParams,
    SealedAad, Signer as _, Subject, UnixTime, ValidationParams, VerifySealedParams,
    X25519Recipient, X25519RecipientPublic, X25519ResponsePublicKey, Zeroizing,
    build_sealed_with_headers, request_hash, verify_sealed,
};
use basil_proto::broker::v1::invocation_service_client::InvocationServiceClient;
use basil_proto::broker::v1::{
    GetInvocationChallengeRequest, GetInvocationChallengeResponse, SealedRequest, SigningAlgorithm,
};
use basil_proto::invocation::{
    CONTENT_TYPE_SIGN_REQUEST, InvocationStatusCode, SignInvocationRequest, SignInvocationResponse,
};
use basil_tests::{
    Engine, INVOCATION_AUDIENCE, INVOCATION_REQUEST_KEY_ID, INVOCATION_SIGNING_KEY_ID,
    InvocationBootSpec, ProviderArm, alloc_addr, boot_basil_invocation, on_path,
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

const WAIT: Duration = Duration::from_secs(20);
const REQUEST_PRIVATE: [u8; 32] = [0x66; 32];
const PROOF_PRIVATE: [u8; 32] = [0x29; 32];
const SUBJECT_PRIVATE: [u8; 32] = [0x33; 32];
const JWT_KID: &str = "audit-correlation-key";
const RULE_ID: &str = "forgejo-audit-correlation";
const PROVIDER_SUBJECT: &str = "ci/release";
const REPOSITORY: &str = "forge/basil";
const REPOSITORY_ID: u64 = 42;
const REPOSITORY_OWNER_ID: u64 = 7;
const ACTOR_ID: u64 = 12_345;
const WORKFLOW_REF: &str = "forge/basil/.forgejo/workflows/release.yml@refs/heads/main";
const REF_NAME: &str = "refs/heads/main";
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RUN_ID: u64 = 998_877;
const RUN_ATTEMPT: u64 = 1;
const RAW_JTI: &str = "eync-raw-jti-must-not-reach-audit";
const PAYLOAD_MARKER: &[u8] = b"eync-payload-must-not-reach-audit";
static NEXT_TRUST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TrustedDirectory(PathBuf);

impl TrustedDirectory {
    fn create() -> Self {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("test crate lives below the workspace root");
        let parent = workspace.join("target/test-tmp");
        fs::create_dir_all(&parent).expect("create trusted test root");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("protect trusted test root");
        let sequence = NEXT_TRUST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            "basil-ci-audit-trust-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create trusted CA directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("protect trusted CA directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TrustedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TrustKey {
    signer: EncodingKey,
    modulus: String,
}

fn trust_key() -> TrustKey {
    use rand::SeedableRng as _;
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    use rsa::traits::PublicKeyParts as _;

    let mut rng = rand::rngs::StdRng::seed_from_u64(8_019);
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate Forgejo trust key");
    let der = key.to_pkcs1_der().expect("encode Forgejo trust key");
    TrustKey {
        signer: EncodingKey::from_rsa_der(der.as_bytes()),
        modulus: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
    }
}

struct TlsMaterial {
    ca: String,
    server_chain: String,
    server_key: String,
}

fn tls_material() -> TlsMaterial {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let ca_key = KeyPair::generate().expect("generate test CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("test CA parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("self-sign test CA");
    let server_key = KeyPair::generate().expect("generate test server key");
    let server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server parameters");
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("sign test server certificate");
    TlsMaterial {
        ca: ca.pem(),
        server_chain: server.pem(),
        server_key: server_key.serialize_pem(),
    }
}

struct HttpsOrigin {
    issuer: String,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl HttpsOrigin {
    async fn start(material: &TlsMaterial, modulus: String) -> Self {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        basil_tests::ensure_crypto_provider();
        let certificates = CertificateDer::pem_reader_iter(&mut std::io::Cursor::new(
            material.server_chain.as_bytes(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .expect("parse server certificate");
        let key = PrivateKeyDer::from_pem_reader(&mut std::io::Cursor::new(
            material.server_key.as_bytes(),
        ))
        .expect("parse server key");
        let config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .expect("TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .expect("TLS server configuration");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("bind local Forgejo HTTPS origin");
        let address = listener.local_addr().expect("read HTTPS origin address");
        let issuer = format!("https://localhost:{}/api/actions", address.port());
        let served_issuer = issuer.clone();
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => accepted,
                };
                let Ok((stream, _peer)) = accepted else {
                    break;
                };
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                while let Ok(read) = stream.read(&mut chunk).await {
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let first_line = request
                    .split(|byte| *byte == b'\n')
                    .next()
                    .unwrap_or_default();
                let body = if first_line
                    .windows(b"/.well-known/openid-configuration".len())
                    .any(|window| window == b"/.well-known/openid-configuration")
                {
                    json!({
                        "issuer": served_issuer.as_str(),
                        "jwks_uri": format!("{served_issuer}/.well-known/jwks"),
                    })
                    .to_string()
                } else {
                    format!(
                        r#"{{"keys":[{{"kty":"RSA","kid":"{JWT_KID}","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB"}}]}}"#
                    )
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        Self { issuer, stop, task }
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        self.task.await.expect("reap Forgejo HTTPS origin task");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_provider_invocations_emit_correlated_secret_free_terminal_jsonl() {
    if !on_path("bao") {
        eprintln!("SKIP: `bao` not on PATH; skipping CI invocation audit correlation");
        return;
    }

    let trust = trust_key();
    let tls = tls_material();
    let origin = HttpsOrigin::start(&tls, trust.modulus.clone()).await;
    let provisional = Ed25519Signer::from_secret_bytes(
        text_key("proof-bootstrap"),
        &Zeroizing::new(PROOF_PRIVATE),
    );
    let proof_public = provisional.public_key_bytes();
    let proof = Ed25519Signer::from_secret_bytes(
        text_key(&proof_key_kid(&proof_public)),
        &Zeroizing::new(PROOF_PRIVATE),
    );
    let (response_recipient, response_public) = ephemeral_response_recipient(0x75);
    let subject = Ed25519Signer::from_secret_bytes(
        text_key("unused-subject-lane"),
        &Zeroizing::new(SUBJECT_PRIVATE),
    );
    let spec = InvocationBootSpec {
        provider: ProviderArm::ForgejoActions,
        require_challenge: true,
        subject_signature_key: URL_SAFE_NO_PAD.encode(subject.public_key_bytes()),
        second_subject_signature_key: None,
        response_public: *response_public.as_public_bytes(),
        request_private: Some(REQUEST_PRIVATE),
        operation_signing_key_id: Some(INVOCATION_SIGNING_KEY_ID.to_string()),
        courier_listener: false,
        challenge: None,
    };
    let harness = boot_basil_invocation(
        "ci-audit-correlation",
        Engine::OpenBao,
        &alloc_addr(),
        &spec,
    );
    // Provider trust validation rejects writable path ancestors, including
    // `/tmp`; keep this fixture under the repository's protected test root.
    let ca_directory = TrustedDirectory::create();
    let ca_path = ca_directory.path().join("forgejo-audit-ca.pem");
    fs::write(&ca_path, &tls.ca).expect("write local Forgejo CA");
    fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))
        .expect("protect local Forgejo CA");
    install_provider_subject(&harness.policy_path());

    let now = now_u64();
    install_federation_config(&harness.config_path(), &origin.issuer, &ca_path, now);
    let mut client = InvocationServiceClient::new(uds_channel(&harness.socket()).await);
    let old_generation = issue_challenge(&mut client, [0xf0; 32]).await.generation;
    harness.sighup_agent();
    let generation = await_new_generation(&mut client, old_generation, 0xd0).await;

    let token = forgejo_token(&origin.issuer, &trust, &proof_public, now);
    let broker_verifier = transit_verifier(harness.backend_addr(), INVOCATION_SIGNING_KEY_ID);
    let operation_public = transit_public_key(harness.backend_addr(), "ci-broker-signing");
    let audit_path = harness.audit_log_path();
    let audit_offset = fs::read(&audit_path).map_or(0, |bytes| bytes.len());

    let first_challenge = issue_challenge(&mut client, proof_key_thumbprint(&proof_public)).await;
    assert_eq!(first_challenge.generation, generation);
    let first_message_id = [0x11; 16];
    let first_request = build_request(
        &proof,
        &token,
        &response_public,
        &first_challenge.challenge,
        first_message_id,
        PAYLOAD_MARKER,
    )
    .await;
    let first_sealed = client
        .invoke(SealedRequest {
            message: first_request.clone(),
        })
        .await
        .expect("valid provider-bound invocation RPC succeeds")
        .into_inner()
        .message;
    let first_opened = open_response(
        &broker_verifier,
        &response_recipient,
        &first_sealed,
        &first_request,
        first_message_id,
    )
    .await;
    assert_eq!(first_opened.status.code, InvocationStatusCode::Ok);
    assert_eq!(first_opened.policy_generation, generation);
    let signature = first_opened
        .signature
        .as_deref()
        .expect("successful invocation carries the backend signature");
    VerifyingKey::from_bytes(&operation_public)
        .expect("target operation public key")
        .verify(
            PAYLOAD_MARKER,
            &Signature::from_slice(signature).expect("target Ed25519 signature"),
        )
        .expect("the backend signed the exact decrypted request message");

    let second_challenge = issue_challenge(&mut client, proof_key_thumbprint(&proof_public)).await;
    let second_message_id = [0x22; 16];
    let second_request = build_request(
        &proof,
        &token,
        &response_public,
        &second_challenge.challenge,
        second_message_id,
        b"eync-second-payload-must-not-reach-audit",
    )
    .await;
    let second_sealed = client
        .invoke(SealedRequest {
            message: second_request.clone(),
        })
        .await
        .expect("quota exhaustion is returned as a protected RPC success")
        .into_inner()
        .message;
    let second_opened = open_response(
        &broker_verifier,
        &response_recipient,
        &second_sealed,
        &second_request,
        second_message_id,
    )
    .await;
    assert_eq!(
        second_opened.status.code,
        InvocationStatusCode::PerRunQuotaExceeded
    );
    assert!(!second_opened.status.retryable);
    assert!(second_opened.signature.is_none());

    let first_slice = wait_for_ci_audit(&audit_path, audit_offset, 2).await;
    assert_eq!(
        first_slice.events.len(),
        2,
        "each real RPC emits exactly one terminal CI event"
    );
    let first_digest = digest(&first_request);
    let second_digest = digest(&second_request);
    let success = event_by_digest(&first_slice.events, &first_digest);
    let exhausted = event_by_digest(&first_slice.events, &second_digest);
    assert_common_identity(success, &origin.issuer, generation, &proof_public);
    assert_common_identity(exhausted, &origin.issuer, generation, &proof_public);
    assert_eq!(
        success["correlation"]["message_id"],
        encode(first_message_id)
    );
    assert_eq!(success["freshness"], "accepted");
    assert_eq!(success["quota"]["state"], "charged");
    assert_eq!(success["quota"]["limit"], 1);
    assert_eq!(success["quota"]["charged_count"], 1);
    assert_eq!(success["quota"]["remaining"], 0);
    assert_eq!(success["decrypt_authorization"], "allowed");
    assert_eq!(success["sign_authorization"], "allowed");
    assert_eq!(success["backend_execution"], "succeeded");
    assert_eq!(success["response_delivery"], "succeeded");
    assert_eq!(success["stage"], "complete");
    assert_eq!(success["outcome"], "success");
    assert_eq!(success["reason"], "completed");

    assert_eq!(
        exhausted["correlation"]["message_id"],
        encode(second_message_id)
    );
    assert_eq!(exhausted["freshness"], "accepted");
    assert_eq!(exhausted["quota"]["state"], "exhausted");
    assert_eq!(exhausted["quota"]["limit"], 1);
    assert!(exhausted["quota"].get("charged_count").is_none());
    assert!(exhausted["quota"].get("remaining").is_none());
    assert_eq!(exhausted["decrypt_authorization"], "not_reached");
    assert_eq!(exhausted["sign_authorization"], "not_reached");
    assert_eq!(exhausted["backend_execution"], "not_reached");
    assert_eq!(exhausted["response_delivery"], "succeeded");
    assert_eq!(exhausted["stage"], "quota");
    assert_eq!(exhausted["outcome"], "denied");
    assert_eq!(exhausted["reason"], "quota_exhausted");
    assert_eq!(
        success["correlation"]["token_digest"], exhausted["correlation"]["token_digest"],
        "the same token has stable keyed correlation within the broker"
    );
    assert_eq!(
        success["correlation"]["jti_digest"],
        exhausted["correlation"]["jti_digest"]
    );
    assert_ne!(
        success["correlation"]["token_digest"], success["correlation"]["jti_digest"],
        "the raw token and its JTI remain separately keyed correlation inputs"
    );
    assert_secret_markers_absent(
        &first_slice.raw,
        &token,
        &proof_public,
        &first_challenge.challenge,
        &second_challenge.challenge,
        signature,
    );

    remove_provider_sign_grant(&harness.policy_path());
    let deny_offset = fs::read(&audit_path)
        .expect("read audit before deny reload")
        .len();
    harness.sighup_agent();
    let deny_generation = await_new_generation(&mut client, generation, 0xc0).await;
    let deny_challenge = issue_challenge(&mut client, proof_key_thumbprint(&proof_public)).await;
    let deny_message_id = [0x33; 16];
    let deny_request = build_request(
        &proof,
        &token,
        &response_public,
        &deny_challenge.challenge,
        deny_message_id,
        b"eync-sign-deny-payload-must-not-reach-backend",
    )
    .await;
    let denied_sealed = client
        .invoke(SealedRequest {
            message: deny_request.clone(),
        })
        .await
        .expect("sign policy denial is returned in a protected response")
        .into_inner()
        .message;
    let denied = open_response(
        &broker_verifier,
        &response_recipient,
        &denied_sealed,
        &deny_request,
        deny_message_id,
    )
    .await;
    assert_eq!(denied.status.code, InvocationStatusCode::Denied);
    assert!(denied.signature.is_none());
    let deny_slice = wait_for_ci_audit(&audit_path, deny_offset, 1).await;
    assert_eq!(deny_slice.events.len(), 1);
    let deny_event = event_by_digest(&deny_slice.events, &digest(&deny_request));
    assert_common_identity(deny_event, &origin.issuer, deny_generation, &proof_public);
    assert_eq!(deny_event["quota"]["state"], "charged");
    assert_eq!(deny_event["decrypt_authorization"], "allowed");
    assert_eq!(deny_event["sign_authorization"], "denied");
    assert_eq!(deny_event["backend_execution"], "not_reached");
    assert_eq!(deny_event["response_delivery"], "succeeded");
    assert_eq!(deny_event["stage"], "sign_authorization");
    assert_eq!(deny_event["outcome"], "denied");
    assert_eq!(deny_event["reason"], "sign_denied");
    assert_secret_markers_absent(
        &deny_slice.raw,
        &token,
        &proof_public,
        &deny_challenge.challenge,
        &deny_challenge.challenge,
        signature,
    );
    assert!(
        !deny_slice
            .raw
            .contains("eync-sign-deny-payload-must-not-reach-backend"),
        "sign-denial audit exposed the undecrypted request payload"
    );
    assert!(
        !deny_slice.lines.iter().any(|line| {
            line["event"]["kind"] == "basil.audit.provider_operation"
                && line["target"]["id"] == INVOCATION_SIGNING_KEY_ID
                && line["outcome"] == "success"
        }),
        "the PDP-denied request has no target-backend success effect"
    );

    origin.shutdown().await;
}

fn install_provider_subject(path: &Path) {
    let mut policy: Value = serde_json::from_slice(&fs::read(path).expect("read live policy"))
        .expect("parse live policy");
    let template = policy["subjects"]["ci.invoker"].clone();
    policy["subjects"]
        .as_object_mut()
        .expect("policy subjects object")
        .insert(PROVIDER_SUBJECT.to_string(), template);
    let rules = policy["rules"].as_array_mut().expect("policy rules array");
    rules.push(json!({
        "id": "ci-provider-decrypt",
        "subjects": [PROVIDER_SUBJECT],
        "action": ["op:decrypt"],
        "target": [INVOCATION_REQUEST_KEY_ID]
    }));
    rules.push(json!({
        "id": "ci-provider-sign",
        "subjects": [PROVIDER_SUBJECT],
        "action": ["op:sign"],
        "target": [INVOCATION_SIGNING_KEY_ID]
    }));
    fs::write(
        path,
        serde_json::to_vec_pretty(&policy).expect("serialize provider policy"),
    )
    .expect("write provider policy");
}

fn remove_provider_sign_grant(path: &Path) {
    let mut policy: Value = serde_json::from_slice(&fs::read(path).expect("read provider policy"))
        .expect("parse provider policy");
    policy["rules"]
        .as_array_mut()
        .expect("policy rules array")
        .retain(|rule| rule["id"] != "ci-provider-sign");
    fs::write(
        path,
        serde_json::to_vec_pretty(&policy).expect("serialize sign-deny policy"),
    )
    .expect("write sign-deny policy");
}

fn install_federation_config(path: &Path, issuer: &str, ca_path: &Path, now: u64) {
    let mut config = fs::read_to_string(path).expect("read live agent config");
    let start = config
        .find("\n[federation]\n")
        .expect("invocation harness has a federation section");
    config.truncate(start);
    writeln!(
        &mut config,
        r#"
[federation]
enable = true
experimental-providers = ["forgejoActions"]

[[federation.providers]]
id = "{RULE_ID}"
subject = "{PROVIDER_SUBJECT}"
audience = "{INVOCATION_AUDIENCE}"
operationProfiles = ["artifact-sign"]
artifactSignKeyIds = ["{INVOCATION_SIGNING_KEY_ID}"]
maxTokenAgeSecs = 300
clockSkewSecs = 30
maxOperationsPerRun = 1

[federation.providers.provider]
kind = "forgejoActions"
issuer = "{issuer}"
discoveryUrl = "{issuer}/.well-known/openid-configuration"
jwksUrl = "{issuer}/.well-known/jwks"
caBundlePath = "{ca}"
audiencePrefix = "urn:basil:ci:jkt:"
repositoryId = {REPOSITORY_ID}
repositoryOwnerId = {REPOSITORY_OWNER_ID}
workflowRef = "{WORKFLOW_REF}"
ref = "{REF_NAME}"
refType = "branch"
sha = "{SHA}"
runId = {RUN_ID}
runAttempt = {RUN_ATTEMPT}
notBeforeUnix = {not_before}
expiresAtUnix = {expires_at}
maxTokenAgeSecs = 300
clockSkewSecs = 30"#,
        ca = ca_path.display(),
        not_before = now.saturating_sub(30),
        expires_at = now + 600,
    )
    .expect("render local Forgejo federation config");
    fs::write(path, config).expect("install local Forgejo federation config");
}

fn forgejo_token(issuer: &str, trust: &TrustKey, proof_public: &[u8; 32], now: u64) -> String {
    let claims = json!({
        "iss": issuer,
        "aud": proof_audience(proof_public),
        "sub": format!("repo:{REPOSITORY}:ref:{REF_NAME}"),
        "repository": REPOSITORY,
        "repository_id": REPOSITORY_ID.to_string(),
        "repository_owner_id": REPOSITORY_OWNER_ID.to_string(),
        "actor_id": ACTOR_ID.to_string(),
        "event_name": "push",
        "ref": REF_NAME,
        "ref_type": "branch",
        "sha": SHA,
        "workflow_ref": WORKFLOW_REF,
        "run_id": RUN_ID.to_string(),
        "run_attempt": RUN_ATTEMPT.to_string(),
        "jti": RAW_JTI,
        "iat": now.saturating_sub(5),
        "exp": now + 240,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(JWT_KID.to_string());
    jsonwebtoken::encode(&header, &claims, &trust.signer).expect("sign local Forgejo token")
}

async fn build_request(
    proof: &Ed25519Signer,
    token: &str,
    response_public: &X25519ResponsePublicKey,
    challenge: &[u8],
    message_id: [u8; 16],
    message: &[u8],
) -> Vec<u8> {
    let plaintext = SignInvocationRequest {
        key_id: INVOCATION_SIGNING_KEY_ID.to_string(),
        message: message.to_vec(),
        algorithm: SigningAlgorithm::Ed25519 as i32,
    }
    .to_cbor_bytes();
    let claims = Claims {
        issuer: Some(Subject::new(PROVIDER_SUBJECT.to_string()).expect("provider subject")),
        audience: Some(Subject::new(INVOCATION_AUDIENCE.to_string()).expect("broker audience")),
        expires_at: None,
        issued_at: UnixTime(now_i64()),
        message_id: MessageId::from_bytes(message_id.to_vec()).expect("16-byte message ID"),
        sender_key_id: Some(proof.key_id().clone()),
        response_key_id: Some(text_key(&response_public.thumbprint())),
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
        freshness_challenge: Some(
            FreshnessChallenge::from_bytes(challenge).expect("32-byte live challenge"),
        ),
        response_public_key_cose: Some(*response_public),
    };
    let recipient = X25519Recipient::new(
        text_key(INVOCATION_REQUEST_KEY_ID),
        Zeroizing::new(REQUEST_PRIVATE),
    );
    build_sealed_with_headers(
        &SealParams {
            content_type: ContentType::new(CONTENT_TYPE_SIGN_REQUEST.to_string())
                .expect("sign request content type"),
            plaintext: &plaintext,
            claims,
            role: MessageRole::Request,
            recipient: X25519RecipientPublic {
                key_id: text_key(INVOCATION_REQUEST_KEY_ID),
                public: recipient.public().public,
            },
            content_algorithm: ContentAlgorithm::A256Gcm,
            aad: SealedAad::empty(),
            kdf_parties: KdfParties::anonymous(),
        },
        &ProtectedHeaders {
            signer_certificates_jwt: vec![token.to_string()],
            signer_public_key_cose: Some(proof_key_cose(&proof.public_key_bytes())),
            operation_target_key_id: Some(text_key(INVOCATION_SIGNING_KEY_ID)),
        },
        proof,
    )
    .await
    .expect("build provider-bound invocation")
    .into_vec()
}

async fn open_response(
    verifier: &Ed25519Verifier,
    recipient: &X25519Recipient,
    message: &[u8],
    request: &[u8],
    message_id: [u8; 16],
) -> SignInvocationResponse {
    let validation = ValidationParams {
        now: UnixTime(now_i64()),
        max_clock_skew: Duration::from_secs(30),
        max_ttl: Duration::from_mins(5),
        default_ttl: Duration::from_mins(2),
        allowed_audiences: std::collections::BTreeSet::new(),
        role: MessageRole::Response,
    };
    let sealed_response = verify_sealed(
        message,
        verifier,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation,
        },
    )
    .await
    .expect("verify broker response");
    assert_eq!(
        sealed_response
            .claims
            .in_reply_to
            .as_ref()
            .map(MessageId::as_bytes),
        Some(message_id.as_slice()),
        "response correlates to the exact request message ID"
    );
    assert_eq!(
        sealed_response.claims.request_hash,
        Some(request_hash(request)),
        "response correlates to the complete sealed request"
    );
    let opened = sealed_response
        .open(
            recipient,
            &ExternalAad::empty(),
            Some(&KdfParties::anonymous()),
        )
        .await
        .expect("open broker response");
    SignInvocationResponse::from_cbor_bytes(opened.plaintext.as_slice())
        .expect("decode sign invocation response")
}

fn ephemeral_response_recipient(seed: u8) -> (X25519Recipient, X25519ResponsePublicKey) {
    let provisional = X25519Recipient::new(text_key("provisional"), Zeroizing::new([seed; 32]));
    let public = X25519ResponsePublicKey::from_public_bytes(provisional.public().public)
        .expect("valid ephemeral response public key");
    let recipient =
        X25519Recipient::new(text_key(&public.thumbprint()), Zeroizing::new([seed; 32]));
    (recipient, public)
}

fn proof_key_cose(public: &[u8; 32]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .map(3)
        .and_then(|e| e.i8(1))
        .and_then(|e| e.i8(1))
        .and_then(|e| e.i8(-1))
        .and_then(|e| e.i8(6))
        .and_then(|e| e.i8(-2))
        .and_then(|e| e.bytes(public))
        .expect("encode proof COSE key");
    encoder.into_writer()
}

async fn uds_channel(path: &Path) -> Channel {
    let path = path.to_path_buf();
    Endpoint::try_from("http://[::]:50051")
        .expect("static endpoint")
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .expect("connect to broker Unix socket")
}

async fn issue_challenge(
    client: &mut InvocationServiceClient<Channel>,
    jkt: [u8; 32],
) -> GetInvocationChallengeResponse {
    client
        .get_invocation_challenge(GetInvocationChallengeRequest {
            jkt: jkt.to_vec(),
            courier_observed_source: None,
        })
        .await
        .expect("issue live invocation challenge")
        .into_inner()
}

async fn await_new_generation(
    client: &mut InvocationServiceClient<Channel>,
    old: u64,
    prefix: u8,
) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut attempt = 0_u8;
    loop {
        let mut jkt = [prefix; 32];
        jkt[31] = attempt;
        let issued = issue_challenge(client, jkt).await;
        if issued.generation > old {
            return issued.generation;
        }
        assert!(
            Instant::now() < deadline,
            "SIGHUP reload did not become visible"
        );
        attempt = attempt.wrapping_add(1);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

struct AuditSlice {
    raw: String,
    lines: Vec<Value>,
    events: Vec<Value>,
}

async fn wait_for_ci_audit(path: &Path, offset: usize, expected: usize) -> AuditSlice {
    tokio::time::timeout(WAIT, async {
        let mut stable = 0_u8;
        let mut previous_complete = 0_usize;
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
                .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
                .collect::<Vec<_>>();
            let events = lines
                .iter()
                .filter(|line| line["event"]["kind"] == "basil.audit.ci_invocation")
                .cloned()
                .collect::<Vec<_>>();
            if events.len() >= expected && complete == previous_complete {
                stable = stable.saturating_add(1);
                if stable == 5 {
                    return AuditSlice {
                        raw: String::from_utf8_lossy(&fresh[..complete]).into_owned(),
                        lines,
                        events,
                    };
                }
            } else {
                stable = 0;
                previous_complete = complete;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("terminal CI audit events became visible before the deadline")
}

fn assert_common_identity(event: &Value, issuer: &str, generation: u64, public: &[u8; 32]) {
    assert_eq!(event["event"]["kind"], "basil.audit.ci_invocation");
    assert_eq!(event["event"]["version"], 1);
    assert_eq!(event["generation"], generation);
    assert_eq!(event["identity_state"], "verified");
    assert_eq!(event["identity"]["provider"], "forgejoActions");
    assert_eq!(event["identity"]["issuer"], issuer);
    assert_eq!(event["identity"]["rule_id"], RULE_ID);
    assert_eq!(event["identity"]["subject"], PROVIDER_SUBJECT);
    assert_eq!(event["identity"]["repository_id"], REPOSITORY_ID);
    assert_eq!(
        event["identity"]["repository_owner_id"],
        REPOSITORY_OWNER_ID
    );
    assert_eq!(event["identity"]["repository"], REPOSITORY);
    assert_eq!(event["identity"]["actor_id"], ACTOR_ID);
    assert_eq!(event["identity"]["workflow_ref"], WORKFLOW_REF);
    assert_eq!(event["identity"]["ref_name"], REF_NAME);
    assert_eq!(event["identity"]["ref_type"], "branch");
    assert_eq!(event["identity"]["sha"], SHA);
    assert_eq!(event["identity"]["event_name"], "push");
    assert_eq!(event["identity"]["run_id"], RUN_ID);
    assert_eq!(event["identity"]["run_attempt"], RUN_ATTEMPT);
    assert_eq!(event["accepted_operation"]["profile"], "artifact-sign");
    assert_eq!(
        event["accepted_operation"]["target"],
        INVOCATION_SIGNING_KEY_ID
    );
    assert_eq!(
        event["correlation"]["proof_jkt"],
        encode(proof_key_thumbprint(public))
    );
    for name in ["invocation_id", "token_digest", "jti_digest", "proof_jkt"] {
        let value = event["correlation"][name]
            .as_str()
            .unwrap_or_else(|| panic!("correlation.{name} is text"));
        assert_eq!(
            value.len(),
            43,
            "correlation.{name} has a fixed digest bound"
        );
        assert!(
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
            "correlation.{name} is unpadded base64url"
        );
    }
}

fn assert_secret_markers_absent(
    raw: &str,
    token: &str,
    proof_public: &[u8; 32],
    first_challenge: &[u8],
    second_challenge: &[u8],
    signature: &[u8],
) {
    for (name, marker) in [
        ("raw provider JWT", token.to_string()),
        ("raw token JTI", RAW_JTI.to_string()),
        ("proof public key", URL_SAFE_NO_PAD.encode(proof_public)),
        ("proof public key (standard)", STANDARD.encode(proof_public)),
        ("proof public key (hex)", hex::encode(proof_public)),
        ("first challenge", URL_SAFE_NO_PAD.encode(first_challenge)),
        (
            "first challenge (standard)",
            STANDARD.encode(first_challenge),
        ),
        ("first challenge (hex)", hex::encode(first_challenge)),
        ("second challenge", URL_SAFE_NO_PAD.encode(second_challenge)),
        (
            "second challenge (standard)",
            STANDARD.encode(second_challenge),
        ),
        ("second challenge (hex)", hex::encode(second_challenge)),
        (
            "request payload",
            String::from_utf8_lossy(PAYLOAD_MARKER).into_owned(),
        ),
        (
            "second request payload",
            "eync-second-payload-must-not-reach-audit".to_string(),
        ),
        ("backend signature", STANDARD.encode(signature)),
        (
            "backend signature (base64url)",
            URL_SAFE_NO_PAD.encode(signature),
        ),
        ("backend signature (hex)", hex::encode(signature)),
    ] {
        assert!(!raw.contains(&marker), "audit JSONL exposed {name}");
    }
}

fn event_by_digest<'a>(events: &'a [Value], expected: &str) -> &'a Value {
    events
        .iter()
        .find(|event| event["correlation"]["invocation_id"] == expected)
        .unwrap_or_else(|| panic!("no terminal event correlated to invocation ID {expected}"))
}

fn digest(request: &[u8]) -> String {
    encode(request_hash(request).0)
}

fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn transit_verifier(addr: &str, key_id: &str) -> Ed25519Verifier {
    Ed25519Verifier::from_key(
        text_key(key_id),
        &transit_public_key(addr, "ci-broker-signing"),
    )
    .expect("build broker response verifier")
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
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse transit key JSON");
    let encoded = json["data"]["keys"]["1"]["public_key"]
        .as_str()
        .expect("transit key carries a version-1 public key");
    STANDARD
        .decode(encoded)
        .expect("decode transit public key")
        .try_into()
        .expect("transit Ed25519 public key is 32 bytes")
}

fn text_key(name: &str) -> KeyId {
    KeyId::from_text(name).expect("key ID is valid text")
}

fn now_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the Unix epoch")
        .as_secs()
}

fn now_i64() -> i64 {
    i64::try_from(now_u64()).expect("Unix seconds fit in i64")
}
