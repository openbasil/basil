// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Live qualification of the fixed-purpose CI artifact-sign adapter.

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
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use basil_cose::{KeyId, X25519Recipient, Zeroizing};
use basil_https_courier::{BasilSocketConfig, Config as CourierConfig, Limits, ListenerConfig};
use basil_proto::broker::v1::GetInvocationChallengeRequest;
use basil_proto::broker::v1::invocation_service_client::InvocationServiceClient;
use basil_tests::{
    Engine, INVOCATION_AUDIENCE, INVOCATION_REQUEST_KEY_ID, INVOCATION_SIGNING_KEY_ID,
    InvocationBootSpec, ProviderArm, alloc_addr, boot_basil_invocation, ensure_crypto_provider,
    on_path,
};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::process::{Child as TokioChild, Command as TokioCommand};
use tokio::task::{JoinHandle, JoinSet};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

const WAIT: Duration = Duration::from_secs(30);
const CHILD_REAP_WAIT: Duration = Duration::from_mins(6);
const CHILD_MODE: &str = "BASIL_CI_ARTIFACT_SIGN_QUALIFICATION_CHILD";
const TRUST_ROOT: &str = "BASIL_CI_QUALIFICATION_TRUST_ROOT";
const TOKEN_BEARER: &str = "qualification-token-request-bearer-must-not-leak";
const ENV_SECRET: &str = "qualification-environment-secret-must-not-leak";
const STATEMENT_DOMAIN: &[u8] = b"basil-ci-artifact-sign-qualification-v1\0";
const JWT_KID: &str = "qualification-provider-key";
const ARTIFACT_SIGN_KEY_ID: &str = "web.tls.signing_key";
const ARTIFACT_SIGN_TRANSIT_PATH: &str = "web-tls";
const WRONG_TARGET_KEY_ID: &str = INVOCATION_SIGNING_KEY_ID;
const ADAPTER_NAME: &str = "artifact-sign-qualification";
const ADAPTER_REQUEST: &[u8] = br#"{"version":1,"operation":"artifact-sign-qualification"}"#;
const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
const GITHUB_REPOSITORY: &str = "openbasil/basil";
const GITHUB_WORKFLOW: &str = "openbasil/basil/.github/workflows/release.yml@refs/heads/main";
const GITHUB_WORKFLOW_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GITHUB_RULE_ID: &str = "github-artifact-sign-qualification";
const FORGEJO_REPOSITORY: &str = "forge/basil";
const FORGEJO_WORKFLOW: &str = "forge/basil/.forgejo/workflows/release.yml@refs/heads/main";
const FORGEJO_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const FORGEJO_RULE_ID: &str = "forgejo-artifact-sign-qualification";
const PROVIDER_SUBJECT: &str = "ci/release";
const REF_NAME: &str = "refs/heads/main";
const RUN_ATTEMPT: u64 = 1;
const GITHUB_RUN_ID: u64 = 88_001;
const FORGEJO_RUN_ID: u64 = 88_002;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
    Github,
    Forgejo,
}

impl Provider {
    const ALL: [Self; 2] = [Self::Github, Self::Forgejo];

    const fn arm(self) -> ProviderArm {
        match self {
            Self::Github => ProviderArm::GithubActions,
            Self::Forgejo => ProviderArm::ForgejoActions,
        }
    }

    const fn bootstrap_name(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Forgejo => "forgejoActions",
        }
    }

    const fn config_name(self) -> &'static str {
        self.bootstrap_name()
    }

    const fn rule_id(self) -> &'static str {
        match self {
            Self::Github => GITHUB_RULE_ID,
            Self::Forgejo => FORGEJO_RULE_ID,
        }
    }

    const fn run_id(self) -> u64 {
        match self {
            Self::Github => GITHUB_RUN_ID,
            Self::Forgejo => FORGEJO_RUN_ID,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Forgejo => "forgejo",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenShape {
    Matching,
    Confused,
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Self {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("test crate is below the workspace root");
        let parent = workspace.join("target/test-tmp");
        fs::create_dir_all(&parent).expect("create qualification test root");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
            .expect("protect qualification test root");
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            "ci-artifact-sign-qualification-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create qualification directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("protect qualification directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct EvidenceItem {
    label: String,
    bytes: Vec<u8>,
}

impl EvidenceItem {
    fn new(label: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            bytes,
        }
    }
}

struct SecretEvidence {
    secrets: Vec<SecretMarker>,
    evidence: Vec<EvidenceItem>,
}

struct SecretMarker {
    label: String,
    bytes: Vec<u8>,
    source_evidence: Option<String>,
}

impl SecretEvidence {
    fn new(
        provider: Provider,
        material: &TlsMaterial,
        trust: &TrustKey,
        request_private: &[u8; 32],
    ) -> Self {
        let mut evidence = Self {
            secrets: Vec::new(),
            evidence: Vec::new(),
        };
        evidence.add_secret("token request bearer", TOKEN_BEARER.as_bytes());
        evidence.add_secret(
            "provider JTI",
            format!("{}-qualification-jti-must-not-leak", provider.label()).as_bytes(),
        );
        evidence.add_secret("environment sentinel", ENV_SECRET.as_bytes());
        evidence.add_secret("adapter request payload", ADAPTER_REQUEST);
        evidence.add_secret("qualification statement domain", STATEMENT_DOMAIN);
        evidence.add_secret("request private key", request_private);
        evidence.add_secret("TLS CA private key", material.ca_key.as_bytes());
        evidence.add_secret("TLS server private key", material.server_key.as_bytes());
        evidence.add_secret("OIDC RSA private key", &trust.private_der);
        evidence
    }

    fn add_secret(&mut self, label: &str, value: &[u8]) {
        self.add_secret_except_source(label, value, None);
    }

    fn add_secret_except_source(&mut self, label: &str, value: &[u8], source: Option<&str>) {
        assert!(
            value.len() >= 12,
            "secret marker {label} is too short for an authoritative scan"
        );
        self.secrets.push(SecretMarker {
            label: label.to_string(),
            bytes: value.to_vec(),
            source_evidence: source.map(str::to_string),
        });
    }

    fn add_jwt(&mut self, token: &str) {
        self.add_secret("full provider JWT", token.as_bytes());
        let components = token.split('.').collect::<Vec<_>>();
        assert_eq!(components.len(), 3, "provider JWT has three components");
        for (index, component) in components.into_iter().enumerate() {
            self.add_secret(
                &format!("provider JWT component {index}"),
                component.as_bytes(),
            );
        }
    }

    fn capture(&mut self, label: impl Into<String>, bytes: impl Into<Vec<u8>>) {
        self.evidence.push(EvidenceItem::new(label, bytes.into()));
    }

    fn capture_json(&mut self, label: &str, value: &Value) {
        self.capture(
            label,
            serde_json::to_vec(value).expect("serialize retained evidence"),
        );
    }

    fn extend(&mut self, evidence: Vec<EvidenceItem>) {
        self.evidence.extend(evidence);
    }

    fn assert_absent(&self) {
        let total = self
            .evidence
            .iter()
            .map(|item| item.bytes.len())
            .sum::<usize>();
        assert!(total > 1_024, "secret scan evidence corpus is non-vacuous");
        for required in [
            "session-startup-output-",
            "session-stderr-",
            "session-runtime-tree-live",
            "session-runtime-tree-after-cleanup",
            "receipt-",
            "audit-jsonl-",
            "broker-log",
            "stalling-courier-request",
        ] {
            assert!(
                self.evidence
                    .iter()
                    .any(|item| item.label.starts_with(required)),
                "secret scan is missing evidence category {required}"
            );
        }

        let scanner_canary = b"qualification-scanner-canary-not-in-live-evidence";
        assert!(
            encoded_secret_forms(scanner_canary)
                .iter()
                .any(|form| contains_bytes(
                    b"prefixqualification-scanner-canary-not-in-live-evidence",
                    form
                )),
            "secret scanner self-check failed"
        );
        for secret in &self.secrets {
            for (form_index, form) in encoded_secret_forms(&secret.bytes).into_iter().enumerate() {
                for item in &self.evidence {
                    if secret.source_evidence.as_deref() == Some(item.label.as_str()) {
                        continue;
                    }
                    assert!(
                        !contains_bytes(&item.bytes, &form),
                        "{} exposed encoded form {form_index} of {}",
                        item.label,
                        secret.label,
                    );
                }
            }
        }
    }
}

fn encoded_secret_forms(secret: &[u8]) -> Vec<Vec<u8>> {
    let mut forms = vec![
        secret.to_vec(),
        hex::encode(secret).into_bytes(),
        STANDARD.encode(secret).into_bytes(),
        STANDARD_NO_PAD.encode(secret).into_bytes(),
        URL_SAFE.encode(secret).into_bytes(),
        URL_SAFE_NO_PAD.encode(secret).into_bytes(),
        serde_json::to_vec(secret).expect("JSON-encode secret bytes"),
        url::form_urlencoded::byte_serialize(secret)
            .collect::<String>()
            .into_bytes(),
    ];
    if let Ok(text) = std::str::from_utf8(secret) {
        forms.push(serde_json::to_vec(text).expect("JSON-encode secret text"));
    }
    forms.sort();
    forms.dedup();
    forms
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

struct TrustKey {
    signer: EncodingKey,
    modulus: String,
    private_der: Vec<u8>,
}

fn trust_key() -> TrustKey {
    use rand::SeedableRng as _;
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    use rsa::traits::PublicKeyParts as _;

    let mut rng = rand::rngs::StdRng::seed_from_u64(0x51_4749);
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate provider trust key");
    let der = key.to_pkcs1_der().expect("encode provider trust key");
    TrustKey {
        signer: EncodingKey::from_rsa_der(der.as_bytes()),
        modulus: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        private_der: der.as_bytes().to_vec(),
    }
}

struct TlsMaterial {
    ca: String,
    ca_key: String,
    server_chain: String,
    server_key: String,
}

fn tls_material() -> TlsMaterial {
    let ca_key = KeyPair::generate().expect("generate qualification CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params
        .self_signed(&ca_key)
        .expect("self-sign qualification CA");
    let server_key = KeyPair::generate().expect("generate qualification TLS key");
    let server_params = CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "token.actions.githubusercontent.com".to_string(),
    ])
    .expect("qualification server parameters");
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("sign qualification server certificate");
    TlsMaterial {
        ca: ca.pem(),
        ca_key: ca_key.serialize_pem(),
        server_chain: server.pem(),
        server_key: server_key.serialize_pem(),
    }
}

fn tls_acceptor(material: &TlsMaterial) -> tokio_rustls::TlsAcceptor {
    ensure_crypto_provider();
    let certificates = CertificateDer::pem_reader_iter(&mut std::io::Cursor::new(
        material.server_chain.as_bytes(),
    ))
    .collect::<Result<Vec<_>, _>>()
    .expect("parse qualification server certificate");
    let key =
        PrivateKeyDer::from_pem_reader(&mut std::io::Cursor::new(material.server_key.as_bytes()))
            .expect("parse qualification server key");
    let config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("qualification TLS protocol versions")
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .expect("qualification TLS server configuration");
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

struct OidcOrigin {
    address: SocketAddr,
    issuer: String,
    shape: Arc<tokio::sync::RwLock<TokenShape>>,
    run_id: Arc<tokio::sync::RwLock<u64>>,
    issued_tokens: Arc<tokio::sync::Mutex<Vec<String>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl OidcOrigin {
    async fn start(provider: Provider, material: &TlsMaterial, trust: Arc<TrustKey>) -> Self {
        let bind = if provider == Provider::Github {
            "127.0.0.1:443"
        } else {
            "127.0.0.1:0"
        };
        let listener = TcpListener::bind(bind)
            .await
            .expect("bind qualification OIDC origin");
        let address = listener.local_addr().expect("OIDC origin address");
        let issuer = match provider {
            Provider::Github => GITHUB_ISSUER.to_string(),
            Provider::Forgejo => format!("https://localhost:{}/api/actions", address.port()),
        };
        let served_issuer = issuer.clone();
        let acceptor = tls_acceptor(material);
        let shape = Arc::new(tokio::sync::RwLock::new(TokenShape::Matching));
        let served_shape = Arc::clone(&shape);
        let run_id = Arc::new(tokio::sync::RwLock::new(provider.run_id()));
        let served_run_id = Arc::clone(&run_id);
        let issued_tokens = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let served_tokens = Arc::clone(&issued_tokens);
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = &mut stopped => break,
                    completed = connections.join_next(), if !connections.is_empty() => {
                        let _ = completed;
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _peer)) = accepted else { break };
                        let acceptor = acceptor.clone();
                        let issuer = served_issuer.clone();
                        let shape = Arc::clone(&served_shape);
                        let run_id = Arc::clone(&served_run_id);
                        let issued_tokens = Arc::clone(&served_tokens);
                        let trust = Arc::clone(&trust);
                        connections.spawn(async move {
                            let _ = tokio::time::timeout(
                                Duration::from_secs(5),
                                serve_oidc_connection(
                                    stream, acceptor, provider, &issuer, shape, &trust,
                                    run_id, issued_tokens,
                                ),
                            )
                            .await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            address,
            issuer,
            shape,
            run_id,
            issued_tokens,
            stop: Some(stop),
            task,
        }
    }

    async fn set_shape(&self, shape: TokenShape) {
        *self.shape.write().await = shape;
    }

    async fn set_run_id(&self, run_id: u64) {
        *self.run_id.write().await = run_id;
    }

    async fn issued_tokens(&self) -> Vec<String> {
        self.issued_tokens.lock().await.clone()
    }

    async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        tokio::time::timeout(WAIT, &mut self.task)
            .await
            .expect("OIDC origin stopped before the deadline")
            .expect("OIDC origin task did not panic");
    }
}

impl Drop for OidcOrigin {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.task.abort();
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_oidc_connection(
    stream: TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    provider: Provider,
    issuer: &str,
    shape: Arc<tokio::sync::RwLock<TokenShape>>,
    trust: &TrustKey,
    run_id: Arc<tokio::sync::RwLock<u64>>,
    issued_tokens: Arc<tokio::sync::Mutex<Vec<String>>>,
) -> Result<(), std::io::Error> {
    let mut stream = acceptor
        .accept(stream)
        .await
        .map_err(std::io::Error::other)?;
    let request = read_http_head(&mut stream, 32 * 1024).await?;
    let text = String::from_utf8_lossy(&request);
    let target = text
        .lines()
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .unwrap_or("/");
    let (status, body) = if target.contains("/.well-known/openid-configuration") {
        (
            "200 OK",
            json!({
                "issuer": issuer,
                "jwks_uri": format!("{issuer}/.well-known/jwks"),
            })
            .to_string(),
        )
    } else if target.contains("/.well-known/jwks") {
        (
            "200 OK",
            format!(
                r#"{{"keys":[{{"kty":"RSA","kid":"{JWT_KID}","alg":"RS256","use":"sig","n":"{}","e":"AQAB"}}]}}"#,
                trust.modulus
            ),
        )
    } else if target.starts_with("/token?")
        && text
            .lines()
            .any(|line| line.eq_ignore_ascii_case(&format!("authorization: Bearer {TOKEN_BEARER}")))
    {
        let parsed = url::Url::parse(&format!("https://localhost{target}"))
            .map_err(std::io::Error::other)?;
        let audience = parsed
            .query_pairs()
            .find_map(|(name, value)| (name == "audience").then(|| value.into_owned()))
            .unwrap_or_default();
        let token = provider_token(
            provider,
            *shape.read().await,
            issuer,
            &audience,
            trust,
            *run_id.read().await,
        );
        issued_tokens.lock().await.push(token.clone());
        ("200 OK", json!({"value": token}).to_string())
    } else {
        ("404 Not Found", "{}".to_string())
    };
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

fn provider_token(
    provider: Provider,
    shape: TokenShape,
    issuer: &str,
    audience: &str,
    trust: &TrustKey,
    run_id: u64,
) -> String {
    let now = unix_seconds();
    let token_provider = if shape == TokenShape::Matching {
        provider
    } else {
        match provider {
            Provider::Github => Provider::Forgejo,
            Provider::Forgejo => Provider::Github,
        }
    };
    let common = json!({
        "iss": issuer,
        "aud": audience,
        "sub": format!("repo:{}:ref:{REF_NAME}", match token_provider {
            Provider::Github => GITHUB_REPOSITORY,
            Provider::Forgejo => FORGEJO_REPOSITORY,
        }),
        "actor_id": "12345",
        "event_name": "push",
        "ref": REF_NAME,
        "run_attempt": RUN_ATTEMPT.to_string(),
        "jti": format!("{}-qualification-jti-must-not-leak", provider.label()),
        "iat": now.saturating_sub(5),
        "exp": now + 240,
    });
    let mut claims = common.as_object().expect("common claims object").clone();
    match token_provider {
        Provider::Github => {
            claims.insert("repository".to_string(), json!(GITHUB_REPOSITORY));
            claims.insert("repository_id".to_string(), json!("4242"));
            claims.insert("repository_owner_id".to_string(), json!("77"));
            claims.insert("job_workflow_ref".to_string(), json!(GITHUB_WORKFLOW));
            claims.insert("job_workflow_sha".to_string(), json!(GITHUB_WORKFLOW_SHA));
            claims.insert("runner_environment".to_string(), json!("github-hosted"));
            claims.insert("run_id".to_string(), json!(run_id.to_string()));
        }
        Provider::Forgejo => {
            claims.insert("repository".to_string(), json!(FORGEJO_REPOSITORY));
            claims.insert("repository_id".to_string(), json!("11"));
            claims.insert("repository_owner_id".to_string(), json!("3"));
            claims.insert("ref_type".to_string(), json!("branch"));
            claims.insert("sha".to_string(), json!(FORGEJO_SHA));
            claims.insert("workflow_ref".to_string(), json!(FORGEJO_WORKFLOW));
            claims.insert("run_id".to_string(), json!(run_id.to_string()));
        }
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(JWT_KID.to_string());
    jsonwebtoken::encode(&header, &claims, &trust.signer).expect("sign provider token")
}

async fn read_http_head<S>(stream: &mut S, limit: usize) -> Result<Vec<u8>, std::io::Error>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    while request.len() < limit {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "bounded HTTP request head is incomplete",
    ))
}

async fn read_http_request<S>(stream: &mut S, limit: usize) -> Result<Vec<u8>, std::io::Error>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        if request.len() >= limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bounded HTTP request exceeds limit",
            ));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP request ended before its headers",
            ));
        }
        request.extend_from_slice(&chunk[..read]);
        if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let total = header_end
        .checked_add(content_length)
        .filter(|total| *total <= limit)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bounded HTTP body exceeds limit",
            )
        })?;
    while request.len() < total {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP request ended before its body",
            ));
        }
        request.extend_from_slice(&chunk[..read]);
        if request.len() > total {
            request.truncate(total);
        }
    }
    request.truncate(total);
    Ok(request)
}

#[test]
fn live_ci_artifact_sign_qualification() {
    if !on_path("bao") || !on_path("unshare") {
        eprintln!("SKIP: `bao` and `unshare` are required for CI artifact qualification");
        return;
    }
    if std::env::var_os(CHILD_MODE).is_some() {
        return;
    }
    let directory = TestDirectory::create();
    let trust_root = PathBuf::from("/tmp/qualification-ca.pem");
    let run = directory.path().join("run");
    let run_user = run.join("user");
    let runtime = run_user.join("0");
    let current_system = run.join("current-system");
    for path in [&run, &run_user, &runtime, &current_system] {
        fs::create_dir_all(path).expect("create namespace-owned runtime tree");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("protect namespace-owned runtime tree");
    }
    let hosts = directory.path().join("hosts");
    write_private(
        &hosts,
        b"127.0.0.1 localhost token.actions.githubusercontent.com\n::1 localhost ip6-localhost\n",
        0o644,
    );
    let executable = std::env::current_exe().expect("resolve qualification test executable");
    let mut child = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--net",
            "--",
            "sh",
            "-c",
            concat!(
                "set -eu\n",
                "mount --make-rprivate /\n",
                "mount --bind \"$1/hosts\" /etc/hosts\n",
                "mount --bind \"$1\" /tmp\n",
                "mount --rbind /run/current-system \"$1/run/current-system\"\n",
                "mount --rbind \"$1/run\" /run\n",
                "/run/current-system/sw/bin/ip link set lo up\n",
                "exec \"$2\" --exact qualification_matrix_child ",
                "--nocapture --test-threads=1\n",
            ),
            "sh",
        ])
        .arg(directory.path())
        .arg(executable)
        .env(CHILD_MODE, "1")
        .env(TRUST_ROOT, &trust_root)
        .env("NO_PROXY", "localhost,127.0.0.1")
        .env("SSL_CERT_FILE", &trust_root)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn isolated qualification child");
    let status = wait_for_child(&mut child, CHILD_REAP_WAIT);
    assert!(status.success(), "isolated qualification child failed");
}

#[test]
fn qualification_matrix_child() {
    if std::env::var_os(CHILD_MODE).is_none() {
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("build qualification runtime")
        .block_on(run_qualification_matrix());
}

fn wait_for_child(child: &mut Child, bound: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + bound;
    loop {
        if let Some(status) = child.try_wait().expect("poll qualification child") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return child.wait().expect("reap timed-out qualification child");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn run_qualification_matrix() {
    ensure_crypto_provider();
    let directory = PathBuf::from("/tmp/q");
    fs::create_dir(&directory).expect("create trusted matrix directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("protect trusted matrix directory");
    let material = tls_material();
    let trust_root = PathBuf::from(std::env::var_os(TRUST_ROOT).expect("trust-root child input"));
    write_private(&trust_root, material.ca.as_bytes(), 0o400);
    let trust = Arc::new(trust_key());
    let github_origin = OidcOrigin::start(Provider::Github, &material, Arc::clone(&trust)).await;

    for provider in Provider::ALL {
        let origin = if provider == Provider::Github {
            None
        } else {
            Some(OidcOrigin::start(provider, &material, Arc::clone(&trust)).await)
        };
        let active_origin = origin.as_ref().unwrap_or(&github_origin);
        run_provider_matrix(
            provider,
            active_origin,
            &material,
            trust.as_ref(),
            &trust_root,
            &directory,
        )
        .await;
        if let Some(origin) = origin {
            origin.shutdown().await;
        }
    }

    github_origin.shutdown().await;
}

async fn run_provider_matrix(
    provider: Provider,
    origin: &OidcOrigin,
    material: &TlsMaterial,
    trust: &TrustKey,
    trust_root: &Path,
    parent: &Path,
) {
    let provider_started = Instant::now();
    let request_private = [0x66; 32];
    let mut secret_evidence = SecretEvidence::new(provider, material, trust, &request_private);
    let request_public = X25519Recipient::new(
        text_key(INVOCATION_REQUEST_KEY_ID),
        Zeroizing::new(request_private),
    )
    .public()
    .public;
    let spec = InvocationBootSpec {
        provider: provider.arm(),
        require_challenge: true,
        subject_signature_key: URL_SAFE_NO_PAD.encode([0x39; 32]),
        second_subject_signature_key: None,
        response_public: [0x75; 32],
        request_private: Some(request_private),
        operation_signing_key_id: Some(ARTIFACT_SIGN_KEY_ID.to_string()),
        courier_listener: true,
        challenge: None,
    };
    let harness = boot_basil_invocation(
        &format!("ci-artifact-sign-{}", provider.label()),
        Engine::OpenBao,
        &alloc_addr(),
        &spec,
    );
    let provider_ca = harness
        .config_path()
        .parent()
        .expect("agent config has a parent")
        .join("qualification-ca.pem");
    fs::copy(trust_root, &provider_ca).expect("copy provider CA into trusted agent corpus");
    fs::set_permissions(&provider_ca, fs::Permissions::from_mode(0o400))
        .expect("protect provider CA");
    install_provider_subject(&harness.policy_path());
    install_federation_config(
        &harness.config_path(),
        provider,
        &origin.issuer,
        &provider_ca,
        provider.run_id(),
    );
    let audit_path = harness.audit_log_path();
    let broker_log_path = harness
        .config_path()
        .parent()
        .expect("agent config has a parent")
        .join("broker.log");
    let reload_diagnostic_paths = [
        harness.config_path(),
        harness.catalog_path(),
        harness.policy_path(),
        provider_ca.clone(),
        audit_path.clone(),
        broker_log_path.clone(),
    ];
    let mut challenge_client = challenge_client(&harness.socket()).await;
    let old_generation = issue_generation_probe(&mut challenge_client, [0xa0; 32]).await;
    harness.sighup_agent();
    let generation = await_new_generation(
        &mut challenge_client,
        old_generation,
        &reload_diagnostic_paths,
    )
    .await;

    let response_public = transit_public_key(harness.backend_addr(), "ci-broker-signing");
    let artifact_public = transit_public_key(harness.backend_addr(), ARTIFACT_SIGN_TRANSIT_PATH);
    let courier = Courier::start(provider, material, harness.socket(), parent).await;

    origin.set_shape(TokenShape::Matching).await;
    let success_offset = audit_len(&audit_path);
    let mut success = SessionProcess::start(
        provider,
        origin,
        parent,
        &courier.origin(),
        request_public,
        response_public,
        ARTIFACT_SIGN_KEY_ID,
        artifact_public,
        "success",
    )
    .await;
    let control_status = success.status().await.unwrap_or_else(|error| {
        panic!(
            "session control status failed ({error}); {}",
            success.namespace_diagnostics
        )
    });
    assert_eq!(control_status, json!({"status": "running"}));
    assert!(
        success
            .child
            .try_wait()
            .expect("poll session before adapter invoke")
            .is_none(),
        "session exited before adapter invoke; {}",
        success.namespace_diagnostics
    );
    eprintln!("session namespace check: {}", success.namespace_diagnostics);
    let receipt = success.invoke(ADAPTER_REQUEST).await;
    let receipt_bytes = serde_json::to_vec(&receipt).expect("serialize success receipt");
    secret_evidence.capture("receipt-success", receipt_bytes.clone());
    secret_evidence.add_secret_except_source(
        "raw successful adapter response",
        &receipt_bytes,
        Some("receipt-success"),
    );
    if receipt["status"] != "ok" {
        let session_stderr = fs::read_to_string(&success.stderr_path).unwrap_or_default();
        secret_evidence.extend(success.shutdown().await);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let audit = fs::read_to_string(&audit_path).unwrap_or_default();
        let broker_log = fs::read_to_string(&broker_log_path).unwrap_or_default();
        panic!(
            "success adapter rejected: {receipt}\nsession stderr:\n{session_stderr}\n\
             audit since request:\n{}\nbroker log:\n{broker_log}",
            audit.get(success_offset..).unwrap_or(&audit)
        );
    }
    let value = &receipt["value"];
    assert_eq!(value["version"], 1);
    assert_eq!(value["result"], "signed");
    assert_eq!(value["policy-generation"], generation);
    assert_eq!(value["target-key-id"], ARTIFACT_SIGN_KEY_ID);
    assert_eq!(value["signature-verified"], true);
    assert!(value["denial-code"].is_null());
    assert!(value["denial-retryable"].is_null());
    assert_hex(value, "config-sha256");
    assert_hex(value, "ca-sha256");
    assert_hex(value, "statement-sha256");
    assert_hex(value, "signature-sha256");
    assert_eq!(value["config-sha256"], success.config_sha256);
    assert_eq!(
        value["ca-sha256"],
        hex::encode(Sha256::digest(material.ca.as_bytes()))
    );
    let invocation_id = value["invocation-id"]
        .as_str()
        .expect("receipt invocation ID")
        .to_string();
    let replay = success.invoke(ADAPTER_REQUEST).await;
    secret_evidence.capture_json("receipt-replay", &replay);
    assert_eq!(replay, json!({"status": "rejected"}));
    secret_evidence.extend(success.shutdown().await);

    let success_audit = wait_for_ci_audit(&audit_path, success_offset, 1).await;
    assert_eq!(success_audit.events.len(), 1);
    let success_event = &success_audit.events[0];
    assert_eq!(success_event["correlation"]["invocation_id"], invocation_id);
    assert_verified_identity(success_event, provider, &origin.issuer);
    assert_eq!(
        success_event["accepted_operation"]["target"],
        ARTIFACT_SIGN_KEY_ID
    );
    assert_eq!(success_event["freshness"], "accepted");
    assert_eq!(success_event["quota"]["state"], "charged");
    assert_eq!(success_event["decrypt_authorization"], "allowed");
    assert_eq!(success_event["sign_authorization"], "allowed");
    assert_eq!(success_event["backend_execution"], "succeeded");
    assert_eq!(success_event["response_delivery"], "succeeded");
    assert_eq!(success_event["outcome"], "success");
    assert_eq!(success_event["reason"], "completed");
    assert_eq!(
        success_audit.events.len(),
        1,
        "the exact local request replay is stopped by the one-shot adapter"
    );
    secret_evidence.capture("audit-jsonl-success", success_audit.raw.as_bytes().to_vec());

    let target_offset = audit_len(&audit_path);
    let mut target_denial = SessionProcess::start(
        provider,
        origin,
        parent,
        &courier.origin(),
        request_public,
        response_public,
        WRONG_TARGET_KEY_ID,
        response_public,
        "success",
    )
    .await;
    let target_receipt = target_denial.invoke(ADAPTER_REQUEST).await;
    secret_evidence.capture_json("receipt-wrong-target", &target_receipt);
    assert_eq!(target_receipt, json!({"status": "rejected"}));
    secret_evidence.extend(target_denial.shutdown().await);
    let target_audit = wait_for_ci_audit(&audit_path, target_offset, 1).await;
    assert_eq!(target_audit.events.len(), 1);
    let target_event = &target_audit.events[0];
    assert_verified_identity(target_event, provider, &origin.issuer);
    assert!(target_event["accepted_operation"].is_null());
    assert_eq!(target_event["freshness"], "not_reached");
    assert_eq!(target_event["quota"]["state"], "not_reached");
    assert_eq!(target_event["backend_execution"], "not_reached");
    assert_eq!(target_event["stage"], "envelope_authority");
    assert_eq!(target_event["outcome"], "denied");
    assert_eq!(target_event["reason"], "envelope_rejected");
    secret_evidence.capture(
        "audit-jsonl-wrong-target",
        target_audit.raw.as_bytes().to_vec(),
    );

    let denied_run_id = provider.run_id() + 1;
    origin.set_run_id(denied_run_id).await;
    remove_provider_sign_grant(&harness.policy_path());
    install_federation_config(
        &harness.config_path(),
        provider,
        &origin.issuer,
        &provider_ca,
        denied_run_id,
    );
    let old_generation = issue_generation_probe(&mut challenge_client, [0xb0; 32]).await;
    harness.sighup_agent();
    let denial_generation = await_new_generation(
        &mut challenge_client,
        old_generation,
        &reload_diagnostic_paths,
    )
    .await;
    let denial_offset = audit_len(&audit_path);
    let mut sign_denial = SessionProcess::start(
        provider,
        origin,
        parent,
        &courier.origin(),
        request_public,
        response_public,
        ARTIFACT_SIGN_KEY_ID,
        artifact_public,
        "sealed-denied",
    )
    .await;
    let denial = sign_denial.invoke(ADAPTER_REQUEST).await;
    let denial_bytes = serde_json::to_vec(&denial).expect("serialize denial receipt");
    secret_evidence.capture("receipt-sign-denial", denial_bytes.clone());
    secret_evidence.add_secret_except_source(
        "raw protected-denial adapter response",
        &denial_bytes,
        Some("receipt-sign-denial"),
    );
    assert_eq!(denial["status"], "ok");
    let denial_value = &denial["value"];
    assert_eq!(denial_value["result"], "sealed-denied");
    assert_eq!(denial_value["policy-generation"], denial_generation);
    assert_eq!(denial_value["target-key-id"], ARTIFACT_SIGN_KEY_ID);
    assert_eq!(denial_value["signature-verified"], false);
    assert_eq!(denial_value["denial-code"], 2);
    assert_eq!(denial_value["denial-retryable"], false);
    assert!(denial_value["signature-sha256"].is_null());
    let denial_invocation = denial_value["invocation-id"]
        .as_str()
        .expect("denial receipt invocation ID")
        .to_string();
    secret_evidence.extend(sign_denial.shutdown().await);
    let denial_audit = wait_for_ci_audit(&audit_path, denial_offset, 1).await;
    assert_eq!(denial_audit.events.len(), 1);
    let denial_event = &denial_audit.events[0];
    assert_eq!(
        denial_event["correlation"]["invocation_id"],
        denial_invocation
    );
    assert_verified_identity_run(denial_event, provider, &origin.issuer, denied_run_id);
    assert_eq!(
        denial_event["accepted_operation"]["target"],
        ARTIFACT_SIGN_KEY_ID
    );
    assert_eq!(denial_event["freshness"], "accepted");
    assert_eq!(denial_event["quota"]["state"], "charged");
    assert_eq!(denial_event["decrypt_authorization"], "allowed");
    assert_eq!(denial_event["sign_authorization"], "denied");
    assert_eq!(denial_event["backend_execution"], "not_reached");
    assert_eq!(denial_event["response_delivery"], "succeeded");
    assert_eq!(denial_event["stage"], "sign_authorization");
    assert_eq!(denial_event["outcome"], "denied");
    assert_eq!(denial_event["reason"], "sign_denied");
    secret_evidence.capture(
        "audit-jsonl-sign-denial",
        denial_audit.raw.as_bytes().to_vec(),
    );

    origin.set_shape(TokenShape::Confused).await;
    let confusion_offset = audit_len(&audit_path);
    let mut confusion = SessionProcess::start(
        provider,
        origin,
        parent,
        &courier.origin(),
        request_public,
        response_public,
        ARTIFACT_SIGN_KEY_ID,
        artifact_public,
        "success",
    )
    .await;
    let confusion_receipt = confusion.invoke(ADAPTER_REQUEST).await;
    secret_evidence.capture_json("receipt-provider-confusion", &confusion_receipt);
    assert_eq!(confusion_receipt, json!({"status": "rejected"}));
    secret_evidence.extend(confusion.shutdown().await);
    origin.set_shape(TokenShape::Matching).await;
    let confusion_audit = wait_for_ci_audit(&audit_path, confusion_offset, 1).await;
    assert_eq!(confusion_audit.events.len(), 1);
    let confusion_event = &confusion_audit.events[0];
    assert_eq!(confusion_event["identity_state"], "presented_unverified");
    assert!(confusion_event["identity"].is_null());
    assert_eq!(confusion_event["freshness"], "not_reached");
    assert_eq!(confusion_event["quota"]["state"], "not_reached");
    assert_eq!(confusion_event["backend_execution"], "not_reached");
    assert_eq!(confusion_event["stage"], "identity_verification");
    assert_eq!(confusion_event["outcome"], "denied");
    assert_eq!(confusion_event["reason"], "identity_rejected");
    secret_evidence.capture(
        "audit-jsonl-provider-confusion",
        confusion_audit.raw.as_bytes().to_vec(),
    );

    let cancellation_offset = audit_len(&audit_path);
    let mut stalling = StallingCourier::start(material).await;
    let mut cancellation = SessionProcess::start(
        provider,
        origin,
        parent,
        &stalling.origin(),
        request_public,
        response_public,
        ARTIFACT_SIGN_KEY_ID,
        artifact_public,
        "success",
    )
    .await;
    let adapter_path = cancellation.adapter.clone();
    let mut cancelled =
        tokio::spawn(async move { invoke_adapter(&adapter_path, ADAPTER_REQUEST).await });
    let stalled_request = stalling.accepted_request().await;
    let request_line = stalled_request
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_string())
        .expect("stalling courier request has a request line");
    assert_eq!(request_line, "POST /v1/challenge HTTP/1.1");
    secret_evidence.capture("stalling-courier-request", stalled_request.clone());
    secret_evidence.add_secret_except_source(
        "raw stalled challenge request",
        &stalled_request,
        Some("stalling-courier-request"),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut cancelled)
            .await
            .is_err(),
        "adapter completed while the accepted challenge request was stalled"
    );
    secret_evidence.extend(cancellation.shutdown().await);
    let cancelled_result = tokio::time::timeout(WAIT, cancelled)
        .await
        .expect("cancelled adapter task joined before the deadline")
        .expect("cancelled adapter task did not panic");
    secret_evidence.capture(
        "receipt-cancelled-adapter",
        format!("{cancelled_result:?}").into_bytes(),
    );
    assert!(cancelled_result.is_err() || cancelled_result == Ok(json!({"status": "rejected"})));
    assert!(
        cancellation.runtime_is_empty(),
        "session cancellation removes its owned runtime tree"
    );
    let unexpected_requests = stalling.shutdown().await;
    assert!(
        unexpected_requests.is_empty(),
        "cancelled qualification attempted a request after the stalled challenge: {unexpected_requests:?}"
    );
    secret_evidence.capture(
        "audit-jsonl-cancellation",
        assert_no_audit_growth(&audit_path, cancellation_offset).await,
    );

    courier.shutdown().await;
    for token in origin.issued_tokens().await {
        secret_evidence.add_jwt(&token);
    }
    secret_evidence.capture(
        "audit-jsonl-complete",
        fs::read(&audit_path).unwrap_or_default(),
    );
    secret_evidence.capture("broker-log", fs::read(&broker_log_path).unwrap_or_default());
    // The successful challenge, sealed request/response, proof private key, raw target signature,
    // and OpenBao-held target private key stay inside the adapter, courier, or backend. This scan
    // covers their published digests, but does not claim access to deliberately hidden values.
    secret_evidence.assert_absent();
    eprintln!(
        "{} qualification matrix completed in {:?}",
        provider.label(),
        provider_started.elapsed()
    );
}

struct Courier {
    address: SocketAddr,
    task: JoinHandle<Result<(), basil_https_courier::RunError>>,
}

impl Courier {
    async fn start(
        provider: Provider,
        material: &TlsMaterial,
        socket_path: PathBuf,
        parent: &Path,
    ) -> Self {
        let address = unused_loopback_address();
        let certificate = parent.join(format!("{}-courier-chain.pem", provider.label()));
        let private_key = parent.join(format!("{}-courier-key.pem", provider.label()));
        write_private(&certificate, material.server_chain.as_bytes(), 0o400);
        write_private(&private_key, material.server_key.as_bytes(), 0o400);
        let directory = socket_path.parent().expect("courier socket has a parent");
        let directory_meta = fs::metadata(directory).expect("courier socket directory metadata");
        let socket_meta = fs::metadata(&socket_path).expect("courier socket metadata");
        let uid = rustix::process::geteuid().as_raw();
        let root_uid = fs::metadata("/").expect("root directory metadata").uid();
        let config = CourierConfig {
            bind: address,
            listener: ListenerConfig::DirectTls {
                certificate_file: certificate,
                private_key_file: private_key,
            },
            basil: BasilSocketConfig {
                socket_path,
                service_owner_uid: root_uid,
                directory_owner_uid: directory_meta.uid(),
                directory_mode: directory_meta.mode() & 0o7777,
                socket_owner_uid: socket_meta.uid(),
                socket_mode: socket_meta.mode() & 0o7777,
                expected_peer_uid: uid,
            },
            bearer_file: None,
            limits: Limits::default(),
        };
        let mut task = tokio::spawn(basil_https_courier::run(config));
        wait_for_courier_listener(address, &mut task).await;
        Self { address, task }
    }

    fn origin(&self) -> String {
        format!("https://127.0.0.1:{}", self.address.port())
    }

    async fn shutdown(mut self) {
        self.task.abort();
        let joined = tokio::time::timeout(WAIT, &mut self.task)
            .await
            .expect("HTTPS courier task reaped before the deadline");
        assert!(
            joined
                .expect_err("aborted HTTPS courier cannot complete normally")
                .is_cancelled()
        );
    }
}

impl Drop for Courier {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct StallingCourier {
    address: SocketAddr,
    accepted: Option<tokio::sync::oneshot::Receiver<Vec<u8>>>,
    release: Option<tokio::sync::oneshot::Sender<()>>,
    task: JoinHandle<Result<Vec<Vec<u8>>, std::io::Error>>,
}

impl StallingCourier {
    async fn start(material: &TlsMaterial) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalling qualification courier");
        let address = listener.local_addr().expect("stalling courier address");
        let acceptor = tls_acceptor(material);
        let (accepted_tx, accepted) = tokio::sync::oneshot::channel();
        let (release, mut released) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut stream = tokio::time::timeout(Duration::from_secs(5), acceptor.accept(stream))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "stalling courier TLS handshake timed out",
                    )
                })?
                .map_err(std::io::Error::other)?;
            let first = read_http_request(&mut stream, 64 * 1024).await?;
            let _ = accepted_tx.send(first);
            let mut unexpected = Vec::new();
            loop {
                tokio::select! {
                    _ = &mut released => {
                        let _ = stream.shutdown().await;
                        return Ok(unexpected);
                    }
                    accepted = listener.accept() => {
                        let (extra, _) = accepted?;
                        let mut extra = tokio::time::timeout(
                            Duration::from_secs(5),
                            acceptor.accept(extra),
                        )
                        .await
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "extra stalling courier TLS handshake timed out",
                            )
                        })?
                        .map_err(std::io::Error::other)?;
                        unexpected.push(read_http_request(&mut extra, 64 * 1024).await?);
                    }
                }
            }
        });
        Self {
            address,
            accepted: Some(accepted),
            release: Some(release),
            task,
        }
    }

    fn origin(&self) -> String {
        format!("https://127.0.0.1:{}", self.address.port())
    }

    async fn accepted_request(&mut self) -> Vec<u8> {
        tokio::time::timeout(
            WAIT,
            self.accepted
                .take()
                .expect("stalling courier acceptance is awaited once"),
        )
        .await
        .expect("stalling courier accepted a request before the deadline")
        .expect("stalling courier retained the accepted request")
    }

    async fn shutdown(mut self) -> Vec<Vec<u8>> {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        tokio::time::timeout(WAIT, &mut self.task)
            .await
            .expect("stalling courier stopped before the deadline")
            .expect("stalling courier task did not panic")
            .expect("stalling courier completed without I/O failure")
    }
}

impl Drop for StallingCourier {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        self.task.abort();
    }
}

async fn wait_for_courier_listener(
    address: SocketAddr,
    task: &mut JoinHandle<Result<(), basil_https_courier::RunError>>,
) {
    tokio::time::timeout(WAIT, async {
        loop {
            tokio::select! {
                outcome = &mut *task => {
                    panic!("HTTPS courier exited before binding: {outcome:?}");
                }
                connected = TcpStream::connect(address) => {
                    if connected.is_ok() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        }
    })
    .await
    .expect("listener started before the deadline");
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
        "id": "qualification-provider-decrypt",
        "subjects": [PROVIDER_SUBJECT],
        "action": ["op:decrypt"],
        "target": [INVOCATION_REQUEST_KEY_ID]
    }));
    rules.push(json!({
        "id": "qualification-provider-sign",
        "subjects": [PROVIDER_SUBJECT],
        "action": ["op:sign"],
        "target": [ARTIFACT_SIGN_KEY_ID]
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
        .retain(|rule| rule["id"] != "qualification-provider-sign");
    fs::write(
        path,
        serde_json::to_vec_pretty(&policy).expect("serialize sign-denial policy"),
    )
    .expect("write sign-denial policy");
}

fn install_federation_config(
    path: &Path,
    provider: Provider,
    issuer: &str,
    ca_path: &Path,
    run_id: u64,
) {
    let mut config = fs::read_to_string(path).expect("read live agent config");
    let start = config
        .find("\n[federation]\n")
        .expect("invocation harness has a federation section");
    config.truncate(start);
    let now = unix_seconds();
    let opt_in = if provider == Provider::Forgejo {
        "experimental-providers = [\"forgejoActions\"]\n"
    } else {
        ""
    };
    writeln!(
        &mut config,
        "\n[federation]\nenable = true\n{opt_in}\n\
         [[federation.providers]]\n\
         id = \"{}\"\n\
         subject = \"{PROVIDER_SUBJECT}\"\n\
         audience = \"{INVOCATION_AUDIENCE}\"\n\
         operationProfiles = [\"artifact-sign\"]\n\
         artifactSignKeyIds = [\"{ARTIFACT_SIGN_KEY_ID}\"]\n\
         maxTokenAgeSecs = 300\n\
         clockSkewSecs = 30\n\
         maxOperationsPerRun = 1\n\n\
         [federation.providers.provider]",
        provider.rule_id()
    )
    .expect("render federation rule");
    match provider {
        Provider::Github => writeln!(
            &mut config,
            "kind = \"githubActions\"\n\
             issuer = \"{GITHUB_ISSUER}\"\n\
             discoveryUrl = \"{GITHUB_ISSUER}/.well-known/openid-configuration\"\n\
             jwksUrl = \"{GITHUB_ISSUER}/.well-known/jwks\"\n\
             caBundlePath = \"{}\"\n\
             audiencePrefix = \"urn:basil:ci:jkt:\"\n\
             repositoryId = 4242\n\
             repositoryOwnerId = 77\n\
             jobWorkflowRef = \"{GITHUB_WORKFLOW}\"\n\
             jobWorkflowSha = \"{GITHUB_WORKFLOW_SHA}\"\n\
             protectedRefs = [\"{REF_NAME}\"]\n\
             events = [\"push\"]\n\
             runnerEnvironments = [\"github-hosted\"]\n\
             maxTokenAgeSecs = 300\n\
             clockSkewSecs = 30",
            ca_path.display()
        ),
        Provider::Forgejo => writeln!(
            &mut config,
            "kind = \"forgejoActions\"\n\
             issuer = \"{issuer}\"\n\
             discoveryUrl = \"{issuer}/.well-known/openid-configuration\"\n\
             jwksUrl = \"{issuer}/.well-known/jwks\"\n\
             caBundlePath = \"{}\"\n\
             audiencePrefix = \"urn:basil:ci:jkt:\"\n\
             repositoryId = 11\n\
             repositoryOwnerId = 3\n\
             workflowRef = \"{FORGEJO_WORKFLOW}\"\n\
             ref = \"{REF_NAME}\"\n\
             refType = \"branch\"\n\
             sha = \"{FORGEJO_SHA}\"\n\
             runId = {run_id}\n\
             runAttempt = {RUN_ATTEMPT}\n\
             notBeforeUnix = {}\n\
             expiresAtUnix = {}\n\
             maxTokenAgeSecs = 300\n\
             clockSkewSecs = 30",
            ca_path.display(),
            now.saturating_sub(30),
            now + 600
        ),
    }
    .expect("render provider configuration");
    fs::write(path, config).expect("install provider configuration");
}

struct SessionProcess {
    child: TokioChild,
    root: PathBuf,
    runtime: PathBuf,
    adapter: PathBuf,
    control: PathBuf,
    stderr_path: PathBuf,
    namespace_diagnostics: String,
    startup_output: String,
    config_sha256: String,
}

impl SessionProcess {
    #[allow(clippy::too_many_arguments)]
    async fn start(
        provider: Provider,
        origin: &OidcOrigin,
        parent: &Path,
        courier_origin: &str,
        request_public: [u8; 32],
        response_public: [u8; 32],
        target_key_id: &str,
        target_public: [u8; 32],
        expected_result: &str,
    ) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let provider_prefix = if provider == Provider::Github {
            "g"
        } else {
            "f"
        };
        let root = parent.join(format!("{provider_prefix}-{sequence}"));
        for path in [
            root.clone(),
            root.join("nix"),
            root.join("nix/store"),
            root.join("proc"),
            root.join("qualification"),
            root.join("runtime"),
        ] {
            fs::create_dir_all(&path)
                .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .unwrap_or_else(|error| panic!("protect {}: {error}", path.display()));
        }
        let placeholder = root.join("basil");
        write_private(&placeholder, b"mount point", 0o500);
        let ca_host = root.join("qualification/ca.pem");
        let trust_root =
            PathBuf::from(std::env::var_os(TRUST_ROOT).expect("trust-root child input"));
        fs::copy(&trust_root, &ca_host).expect("copy session-exclusive courier CA");
        fs::set_permissions(&ca_host, fs::Permissions::from_mode(0o400))
            .expect("protect session courier CA");
        let token_origin = if origin.address.port() == 443 {
            "https://127.0.0.1".to_string()
        } else {
            format!("https://127.0.0.1:{}", origin.address.port())
        };
        let config = json!({
            "version": 1,
            "providerKind": provider.config_name(),
            "expectedTokenRequestOrigin": token_origin,
            "ruleMaxTokenAgeSeconds": 300,
            "courierOrigin": courier_origin,
            "courierCaBundlePath": "/qualification/ca.pem",
            "brokerAudience": INVOCATION_AUDIENCE,
            "requestEncryptionKeyId": INVOCATION_REQUEST_KEY_ID,
            "requestEncryptionPublicKey": URL_SAFE_NO_PAD.encode(request_public),
            "responseSigningKeyId": INVOCATION_SIGNING_KEY_ID,
            "responseSigningPublicKey": URL_SAFE_NO_PAD.encode(response_public),
            "artifactSignKeyId": target_key_id,
            "artifactSignPublicKey": URL_SAFE_NO_PAD.encode(target_public),
            "expectedResult": expected_result,
        });
        let config_bytes = serde_json::to_vec(&config).expect("serialize qualification config");
        let config_sha256 = hex::encode(Sha256::digest(&config_bytes));
        write_private(
            &root.join("qualification/config.json"),
            &config_bytes,
            0o400,
        );

        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("test crate is below workspace root");
        let basil = workspace.join("target/debug/basil");
        let executable_sha256 = hash_file(&basil);
        let stderr_path = parent.join(format!("{}-session-{sequence}.stderr", provider.label()));
        let stderr = fs::File::create(&stderr_path).expect("create session stderr capture");
        let script = concat!(
            "set -eu\n",
            "mount --make-rprivate /\n",
            "mount --rbind /nix/store \"$1/nix/store\"\n",
            "mount --bind \"$2\" \"$1/basil\"\n",
            "mount --rbind /proc \"$1/proc\"\n",
            "exec chroot \"$1\" /basil ci session ",
            "--basil-executable /proc/self/exe ",
            "--basil-executable-sha256 \"$3\" ",
            "--rule-max-token-age-seconds 300 ",
            "--runtime-parent /runtime ",
            "--qualification-config /qualification/config.json\n",
        );
        let mut command = TokioCommand::new("unshare");
        command
            .args([
                "--mount",
                "--pid",
                "--fork",
                "--kill-child=TERM",
                "sh",
                "-c",
                script,
                "sh",
            ])
            .arg(&root)
            .arg(&basil)
            .arg(&executable_sha256)
            .env("SSL_CERT_FILE", "/qualification/ca.pem")
            .env("NO_PROXY", "localhost,127.0.0.1")
            .env("BASIL_QUALIFICATION_SECRET_SENTINEL", ENV_SECRET)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .kill_on_drop(true);
        let mut child = command.spawn().expect("spawn isolated Basil CI session");
        let mut stdin = child.stdin.take().expect("session bootstrap stdin");
        let stdout = child.stdout.take().expect("session startup stdout");
        stdin
            .write_all(&bootstrap_frame(
                provider.bootstrap_name(),
                &token_origin,
                &format!("{token_origin}/token"),
                TOKEN_BEARER,
            ))
            .await
            .expect("write session bootstrap frame");
        stdin.flush().await.expect("flush session bootstrap frame");
        let mut lines = BufReader::new(stdout).lines();
        let line = tokio::time::timeout(WAIT, lines.next_line())
            .await
            .expect("session published outputs before the deadline")
            .expect("read session outputs")
            .unwrap_or_else(|| {
                let diagnostics = fs::read_to_string(&stderr_path).unwrap_or_default();
                panic!("session exited before outputs: {diagnostics}")
            });
        let outputs: Value = serde_json::from_str(&line).expect("parse session outputs");
        let adapter_namespace = outputs["adapter-sockets"][ADAPTER_NAME]
            .as_str()
            .expect("artifact-sign adapter is published");
        let control_namespace = outputs["session-control-socket"]
            .as_str()
            .expect("session control socket is published");
        stdin
            .write_all(&[1])
            .await
            .expect("commit session bootstrap");
        stdin
            .shutdown()
            .await
            .expect("close session bootstrap input");
        let adapter = namespace_path(&root, adapter_namespace);
        let control = namespace_path(&root, control_namespace);
        for socket in [&adapter, &control] {
            assert!(
                socket.as_os_str().as_bytes().len() < 108,
                "host-visible session socket path exceeds Linux sun_path: {}",
                socket.display()
            );
        }
        wait_for_unix_socket(&adapter).await;
        let namespace_diagnostics = namespace_diagnostics(child.id());
        Self {
            child,
            runtime: root.join("runtime"),
            root,
            adapter,
            control,
            stderr_path,
            namespace_diagnostics,
            startup_output: line,
            config_sha256,
        }
    }

    async fn status(&self) -> Result<Value, String> {
        framed_json(&self.control, br#"{"operation":"status"}"#).await
    }

    async fn invoke(&self, request: &[u8]) -> Value {
        invoke_adapter(&self.adapter, request)
            .await
            .unwrap_or_else(|frame_error| {
                let diagnostics = fs::read_to_string(&self.stderr_path).unwrap_or_default();
                panic!("adapter returned no bounded response ({frame_error}): {diagnostics}")
            })
    }

    async fn shutdown(&mut self) -> Vec<EvidenceItem> {
        let mut evidence = self.evidence("live");
        if self.child.id().is_none() {
            evidence.extend(self.evidence("after-cleanup"));
            return evidence;
        }
        let _ = framed_json(&self.control, br#"{"operation":"shutdown"}"#).await;
        let status = tokio::time::timeout(WAIT, self.child.wait()).await;
        if status.is_err() {
            let _ = self.child.start_kill();
            let _ = tokio::time::timeout(WAIT, self.child.wait()).await;
            panic!("Basil CI session did not stop before the deadline");
        }
        assert!(
            status
                .expect("session wait timeout handled")
                .expect("wait for session process")
                .success(),
            "Basil CI session exited unsuccessfully"
        );
        assert!(
            self.child
                .try_wait()
                .expect("poll reaped Basil CI session")
                .is_some(),
            "Basil CI session was not reaped"
        );
        assert!(
            fs::symlink_metadata(&self.adapter).is_err()
                && fs::symlink_metadata(&self.control).is_err(),
            "session sockets remain after shutdown"
        );
        evidence.extend(self.evidence("after-cleanup"));
        evidence
    }

    fn runtime_is_empty(&self) -> bool {
        fs::read_dir(&self.runtime).is_ok_and(|mut entries| entries.next().is_none())
    }

    fn evidence(&self, phase: &str) -> Vec<EvidenceItem> {
        vec![
            EvidenceItem::new(
                format!("session-startup-output-{phase}"),
                self.startup_output.as_bytes().to_vec(),
            ),
            EvidenceItem::new(
                format!("session-stderr-{phase}"),
                fs::read(&self.stderr_path).unwrap_or_default(),
            ),
            EvidenceItem::new(
                format!("session-runtime-tree-{phase}"),
                snapshot_tree(&self.runtime),
            ),
            EvidenceItem::new(
                format!("session-diagnostics-{phase}"),
                self.namespace_diagnostics.as_bytes().to_vec(),
            ),
            EvidenceItem::new(
                format!("session-config-digest-{phase}"),
                self.config_sha256.as_bytes().to_vec(),
            ),
        ]
    }
}

impl Drop for SessionProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self.child.try_wait().is_ok_and(|status| status.is_some()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn snapshot_tree(root: &Path) -> Vec<u8> {
    const LIMIT: usize = 1024 * 1024;

    let mut snapshot = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        writeln!(snapshot, "{}", path.display()).expect("write runtime-tree path");
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            snapshot.extend_from_slice(b"<missing>\n");
            continue;
        };
        if metadata.is_dir() {
            let mut children = fs::read_dir(&path)
                .unwrap_or_else(|error| panic!("read runtime tree {}: {error}", path.display()))
                .map(|entry| {
                    entry
                        .unwrap_or_else(|error| {
                            panic!("read runtime-tree entry {}: {error}", path.display())
                        })
                        .path()
                })
                .collect::<Vec<_>>();
            children.sort();
            pending.extend(children.into_iter().rev());
        } else if metadata.is_file() {
            let bytes = fs::read(&path)
                .unwrap_or_else(|error| panic!("read runtime file {}: {error}", path.display()));
            snapshot.extend_from_slice(&bytes);
            snapshot.push(b'\n');
        } else {
            snapshot.extend_from_slice(b"<non-regular>\n");
        }
        assert!(
            snapshot.len() <= LIMIT,
            "runtime-tree evidence exceeds its one-megabyte bound"
        );
    }
    snapshot
}

fn namespace_path(root: &Path, namespace_path: &str) -> PathBuf {
    let relative = Path::new(namespace_path)
        .strip_prefix("/")
        .expect("session output path is absolute");
    root.join(relative)
}

fn namespace_diagnostics(child_id: Option<u32>) -> String {
    let self_namespace = fs::read_link("/proc/self/ns/user")
        .map_or_else(|error| error.to_string(), |path| path.display().to_string());
    let self_uid = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .map(str::to_string)
        })
        .unwrap_or_else(|| "Uid: unavailable".to_string());
    let Some(child_id) = child_id else {
        return format!(
            "matrix euid={} user_ns={self_namespace} {self_uid}; session pid unavailable",
            rustix::process::geteuid().as_raw()
        );
    };
    let child_namespace = fs::read_link(format!("/proc/{child_id}/ns/user"))
        .map_or_else(|error| error.to_string(), |path| path.display().to_string());
    let session_uid_line = fs::read_to_string(format!("/proc/{child_id}/status"))
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .map(str::to_string)
        })
        .unwrap_or_else(|| "Uid: unavailable".to_string());
    format!(
        "matrix euid={} user_ns={self_namespace} {self_uid}; session pid={child_id} \
         user_ns={child_namespace} {session_uid_line}",
        rustix::process::geteuid().as_raw()
    )
}

fn bootstrap_frame(provider: &str, origin: &str, request_url: &str, bearer: &str) -> Vec<u8> {
    let fields = [
        provider.as_bytes(),
        origin.as_bytes(),
        request_url.as_bytes(),
        bearer.as_bytes(),
    ];
    let mut frame = Vec::new();
    frame.extend_from_slice(b"BASILCI\0");
    frame.push(1);
    for field in fields {
        frame.extend_from_slice(
            &u32::try_from(field.len())
                .expect("bootstrap field fits u32")
                .to_be_bytes(),
        );
    }
    for field in fields {
        frame.extend_from_slice(field);
    }
    frame
}

async fn invoke_adapter(path: &Path, request: &[u8]) -> Result<Value, String> {
    framed_json(path, request).await
}

async fn framed_json(path: &Path, request: &[u8]) -> Result<Value, String> {
    let mut stream = tokio::time::timeout(WAIT, UnixStream::connect(path))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|error| format!("connect failed: {error}"))?;
    stream
        .write_u32(
            u32::try_from(request.len()).map_err(|_| "request length exceeds u32".to_string())?,
        )
        .await
        .map_err(|error| format!("write length failed: {error}"))?;
    stream
        .write_all(request)
        .await
        .map_err(|error| format!("write body failed: {error}"))?;
    let length = tokio::time::timeout(WAIT, stream.read_u32())
        .await
        .map_err(|_| "read length timed out".to_string())?
        .map_err(|error| format!("read length failed: {error}"))?;
    let length =
        usize::try_from(length).map_err(|_| "response length exceeds usize".to_string())?;
    if length == 0 || length > 64 * 1024 {
        return Err(format!("response length {length} is outside bounds"));
    }
    let mut response = vec![0_u8; length];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|error| format!("read body failed: {error}"))?;
    serde_json::from_slice(&response).map_err(|error| format!("response JSON failed: {error}"))
}

async fn wait_for_unix_socket(path: &Path) {
    tokio::time::timeout(WAIT, async {
        loop {
            if fs::symlink_metadata(path).is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("session socket appeared before the deadline");
}

fn hash_file(path: &Path) -> String {
    let mut file = fs::File::open(path).expect("open Basil executable for hashing");
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).expect("hash Basil executable");
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    hex::encode(digest.finalize())
}

async fn challenge_client(path: &Path) -> InvocationServiceClient<Channel> {
    let path = path.to_path_buf();
    let channel = Endpoint::try_from("http://[::]:50051")
        .expect("static broker endpoint")
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .expect("connect to broker courier socket");
    InvocationServiceClient::new(channel)
}

async fn issue_generation_probe(
    client: &mut InvocationServiceClient<Channel>,
    jkt: [u8; 32],
) -> u64 {
    let (generation, retries) = tokio::time::timeout(WAIT, async {
        let mut retries = 0_u32;
        loop {
            match client
                .get_invocation_challenge(GetInvocationChallengeRequest {
                    jkt: jkt.to_vec(),
                    courier_observed_source: Some("qualification-generation-probe".to_string()),
                })
                .await
            {
                Ok(response) => return (response.into_inner().generation, retries),
                Err(status) if status.code() == tonic::Code::ResourceExhausted => {
                    retries = retries.saturating_add(1);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(status) => panic!("issue generation probe: {status}"),
            }
        }
    })
    .await
    .expect("generation probe accepted before the deadline");
    if retries != 0 {
        eprintln!("generation probe accepted after {retries} retryable declines");
    }
    generation
}

async fn await_new_generation(
    client: &mut InvocationServiceClient<Channel>,
    old_generation: u64,
    diagnostic_paths: &[PathBuf],
) -> u64 {
    let generation = tokio::time::timeout(WAIT, async {
        let mut marker = 0_u8;
        loop {
            let generation = issue_generation_probe(client, [marker; 32]).await;
            if generation > old_generation {
                return generation;
            }
            marker = marker.wrapping_add(1);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    generation.unwrap_or_else(|_| {
        panic!(
            "provider reload did not become visible before the deadline:\n{}",
            reload_diagnostics(diagnostic_paths)
        )
    })
}

fn reload_diagnostics(paths: &[PathBuf]) -> String {
    let mut diagnostics = String::new();
    for path in paths {
        match fs::metadata(path) {
            Ok(metadata) => {
                writeln!(
                    diagnostics,
                    "{} uid={} gid={} mode={:o} nlink={} len={} sha256={}",
                    path.display(),
                    metadata.uid(),
                    metadata.gid(),
                    metadata.mode() & 0o7777,
                    metadata.nlink(),
                    metadata.len(),
                    hash_file(path),
                )
                .expect("write reload metadata diagnostic");
            }
            Err(error) => {
                writeln!(diagnostics, "{} metadata error: {error}", path.display())
                    .expect("write reload metadata error");
                continue;
            }
        }
        let name = path.file_name().and_then(|name| name.to_str());
        if matches!(name, Some("audit.jsonl" | "broker.log")) {
            let contents = fs::read_to_string(path).unwrap_or_else(|error| error.to_string());
            writeln!(diagnostics, "--- {} ---\n{contents}", path.display())
                .expect("write reload log diagnostic");
        }
    }
    diagnostics
}

struct AuditSlice {
    raw: String,
    events: Vec<Value>,
}

fn audit_len(path: &Path) -> usize {
    fs::read(path).map_or(0, |bytes| bytes.len())
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
    .expect("CI invocation audit became visible before the deadline")
}

async fn assert_no_audit_growth(path: &Path, offset: usize) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        let bytes = fs::read(path).unwrap_or_default();
        let fresh = bytes.get(offset..).unwrap_or_default();
        assert!(
            fresh.is_empty(),
            "cancelled pre-send adapter produced broker audit/backend evidence: {}",
            String::from_utf8_lossy(fresh)
        );
        if Instant::now() >= deadline {
            return fresh.to_vec();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn assert_verified_identity(event: &Value, provider: Provider, issuer: &str) {
    assert_verified_identity_run(event, provider, issuer, provider.run_id());
}

fn assert_verified_identity_run(event: &Value, provider: Provider, issuer: &str, run_id: u64) {
    assert_eq!(event["identity_state"], "verified");
    assert_eq!(event["identity"]["provider"], provider.arm().config_name());
    assert_eq!(event["identity"]["issuer"], issuer);
    assert_eq!(event["identity"]["rule_id"], provider.rule_id());
    assert_eq!(event["identity"]["subject"], PROVIDER_SUBJECT);
    assert_eq!(event["identity"]["run_id"], run_id);
    assert_eq!(event["identity"]["run_attempt"], RUN_ATTEMPT);
}

fn assert_hex(value: &Value, field: &str) {
    let text = value[field]
        .as_str()
        .unwrap_or_else(|| panic!("receipt {field} is text"));
    assert_eq!(text.len(), 64, "receipt {field} is SHA-256 hex");
    assert!(
        text.bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "receipt {field} is lowercase hexadecimal"
    );
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
    let document: Value =
        serde_json::from_slice(&output.stdout).expect("parse transit key response");
    let encoded = document["data"]["keys"]["1"]["public_key"]
        .as_str()
        .expect("transit key has a version-1 public key");
    STANDARD
        .decode(encoded)
        .expect("decode transit public key")
        .try_into()
        .expect("transit Ed25519 public key is 32 bytes")
}

fn text_key(value: &str) -> KeyId {
    KeyId::from_text(value).expect("test key ID is valid text")
}

fn unused_loopback_address() -> SocketAddr {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral loopback address")
        .local_addr()
        .expect("read ephemeral loopback address")
}

fn write_private(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|error| panic!("protect {}: {error}", path.display()));
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the Unix epoch")
        .as_secs()
}
