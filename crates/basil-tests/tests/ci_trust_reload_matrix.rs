// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Acceptance row (`basil-jjgi.3.3.3`, `docs/ci-oidc-federation/SPEC.md`
//! "Required acceptance"): *reload from generation A to changed JWKS or TLS
//! trust with the same issuer and `kid`, proving generation B cannot reuse
//! generation A's cache*.
//!
//! The scenario is a provider-side trust rotation that keeps every identifier
//! stable: the issuer, the discovery and JWKS URLs, and the JWKS `kid` are
//! byte-identical before and after — only the RSA key *material* behind the
//! `kid` changes. A verifier cache that leaks across the reload boundary
//! would keep accepting tokens signed by the retired key for as long as the
//! entry lived, with nothing observable in any identifier. The acceptance
//! property is therefore stated at the `verify_github` level, not just at
//! cache shape:
//!
//! - generation A fetches trust v1 and verifies a token signed by key 1;
//! - the provider rotates to trust v2 (same issuer, same `kid`, new key);
//! - generation B, built from the SAME rule configuration by the same
//!   [`Generation`] constructor the reload path uses, must classify the
//!   presented `kid` as unknown (never `Fresh` — that would be generation
//!   A's material), fetch v2, ACCEPT a key-2 token, and REJECT a key-1
//!   token;
//! - generation A, still pinned by in-flight requests, keeps serving its own
//!   v1 trust until dropped, and never observes v2.
//!
//! The matrix exercises both layers of that boundary. A deterministic table
//! fetcher isolates cache and signature behavior. A loopback `tokio-rustls`
//! origin then rotates independently generated CA, server, and JWKS key
//! material at the same issuer and URLs. Those requests use the production
//! generation-owned `reqwest` clients and fetch function, including exclusive
//! custom roots, redirect denial, strict discovery binding, and bounded stale
//! serving during an outage. The wire-side reload rows (generation pinning,
//! kill switch, and policy separation) live in `ci_reload_policy_matrix.rs`.

#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil_core::catalog::loader::load;
use basil_core::ci_federation::{
    FederationError, FetchedDocument, ForgejoActionsRule, GenerationJwksCache, GithubActionsRule,
    ProviderCatalog, ProviderConfig, ProviderDocumentFetcher, ProviderKind,
    ProviderOperationProfile, ProviderRule, ServeDecision, TokenCorrelationKey,
    fetch_generation_jwks, proof_audience, verify_forgejo, verify_github,
};
use basil_core::state::Generation;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use url::Url;
use zeroize::Zeroizing;

/// GitHub's pinned issuer (the only accepted `githubActions` issuer).
const ISSUER: &str = "https://token.actions.githubusercontent.com";
/// The single stable rule id.
const RULE_ID: &str = "release";
/// The `kid` that stays IDENTICAL across the trust rotation.
const KID: &str = "rotating-kid";
/// Fixed verification instant, comfortably inside every freshness window.
const NOW_SECS: u64 = 1_700_000_000;
/// Exact workflow identity pinned by the rule.
const WORKFLOW_REF: &str = "openbasil/basil/.github/workflows/release.yml@refs/heads/main";
/// The remote workload's Ed25519 proof public key (audience binding only).
const PROOF_KEY: [u8; 32] = [0x11; 32];
static NEXT_TLS_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW_SECS)
}

/// One deterministic RSA-2048 signing key: the JWT encoder plus the base64url
/// modulus its JWKS entry carries (`e` = 65537). Generated at runtime so no
/// key blobs live in source; seeded so every run is identical.
struct TrustKey {
    signer: EncodingKey,
    modulus: String,
}

fn generate_trust_key(seed: u64) -> TrustKey {
    use rand::SeedableRng as _;
    use rsa::pkcs1::EncodeRsaPrivateKey as _;
    use rsa::traits::PublicKeyParts as _;
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("trust keygen");
    let der = key.to_pkcs1_der().expect("trust key encodes");
    TrustKey {
        signer: EncodingKey::from_rsa_der(der.as_bytes()),
        modulus: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
    }
}

/// The two trust epochs, generated once per test binary.
fn trust_epochs() -> &'static (TrustKey, TrustKey) {
    static KEYS: std::sync::OnceLock<(TrustKey, TrustKey)> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| (generate_trust_key(1001), generate_trust_key(1002)))
}

fn github_rule() -> GithubActionsRule {
    GithubActionsRule {
        issuer: ISSUER.to_string(),
        discovery_url: format!("{ISSUER}/.well-known/openid-configuration"),
        jwks_url: format!("{ISSUER}/.well-known/jwks"),
        ca_bundle_path: None,
        audience_prefix: "urn:basil:ci:jkt:".to_string(),
        repository_id: 42,
        repository_owner_id: 7,
        job_workflow_ref: WORKFLOW_REF.to_string(),
        job_workflow_sha: "a".repeat(40),
        protected_refs: vec!["refs/heads/main".to_string()],
        events: vec!["push".to_string()],
        runner_environments: vec!["github-hosted".to_string()],
        environment: None,
        max_token_age_secs: 300,
        clock_skew_secs: 30,
    }
}

fn provider_catalog() -> Arc<ProviderCatalog> {
    let rule = ProviderRule {
        id: RULE_ID.to_string(),
        subject: "ci/release".to_string(),
        audience: "basil://ci.test/invocation".to_string(),
        operation_profiles: vec![ProviderOperationProfile::ArtifactSign],
        artifact_sign_key_ids: vec!["release-signing".to_string()],
        max_token_age_secs: 300,
        clock_skew_secs: 30,
        max_operations_per_run: Some(64),
        provider: ProviderConfig::GithubActions(github_rule()),
    };
    Arc::new(ProviderCatalog::new(vec![rule]).expect("valid federation catalog"))
}

/// Build one serving generation the way the reload path builds it, carrying
/// the federation catalog (and therefore one freshly constructed empty JWKS
/// cache per rule).
fn generation(id: u64) -> Generation {
    generation_with_catalog(id, provider_catalog())
}

fn generation_with_catalog(id: u64, federation: Arc<ProviderCatalog>) -> Generation {
    let catalog = r#"{
      "schema": "catalog",
      "backends": { "test": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
      "keys": {}
    }"#;
    let policy = r#"{
      "schema": "policy",
      "subjects": {},
      "roles": {},
      "rules": [],
      "config": { "names": { "users": {}, "groups": {} }, "memberships": {} }
    }"#;
    let (catalog, resolved, config, warnings) = load(catalog, policy).expect("fixture loads");
    assert!(warnings.is_empty(), "fixture warnings: {warnings:?}");
    Generation::new_with_overrides_listeners_and_federation(
        id,
        catalog,
        resolved,
        config,
        Vec::new(),
        Arc::new(basil_core::transport::listener::ListenerConfigSet::default()),
        Some(federation),
    )
    .expect("federation generation")
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create() -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crate lives below workspace root");
        let parent = workspace.join("target/test-tmp");
        std::fs::create_dir_all(&parent).expect("create trusted test root");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("protect trusted test root");
        let sequence = NEXT_TLS_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = parent.join(format!("basil-ci-tls-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&path).expect("create TLS fixture directory");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("protect TLS fixture directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct TlsMaterial {
    ca: String,
    server_chain: String,
    server_key: String,
}

fn tls_material() -> TlsMaterial {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let ca_key = KeyPair::generate().expect("generate CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("self-sign CA");
    let server_key = KeyPair::generate().expect("generate server key");
    let server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server parameters");
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("sign server certificate");
    TlsMaterial {
        ca: ca.pem(),
        server_chain: server.pem(),
        server_key: server_key.serialize_pem(),
    }
}

struct HttpsOrigin {
    address: SocketAddr,
    issuer: String,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Copy)]
enum DiscoveryMode {
    Exact,
    Redirect,
    WrongIssuer,
    Malformed,
}

impl HttpsOrigin {
    async fn start(
        address: Option<SocketAddr>,
        material: &TlsMaterial,
        modulus: String,
        discovery_mode: DiscoveryMode,
    ) -> Self {
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
        let listener = tokio::net::TcpListener::bind(
            address.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0))),
        )
        .await
        .expect("bind HTTPS origin");
        let address = listener.local_addr().expect("HTTPS origin address");
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
                    let Some(bytes) = chunk.get(..read) else {
                        break;
                    };
                    request.extend_from_slice(bytes);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let first_line = request
                    .split(|byte| *byte == b'\n')
                    .next()
                    .unwrap_or_default();
                let (status, extra_headers, body) = if first_line
                    .windows(b"/.well-known/openid-configuration".len())
                    .any(|window| window == b"/.well-known/openid-configuration")
                {
                    match discovery_mode {
                        DiscoveryMode::Exact => (
                            "200 OK",
                            "",
                            json!({
                                "issuer": served_issuer.as_str(),
                                "jwks_uri": format!("{served_issuer}/.well-known/jwks"),
                            })
                            .to_string(),
                        ),
                        DiscoveryMode::Redirect => (
                            "302 Found",
                            "location: https://redirect.invalid/discovery\r\n",
                            String::new(),
                        ),
                        DiscoveryMode::WrongIssuer => (
                            "200 OK",
                            "",
                            json!({
                                "issuer": "https://retired.invalid/api/actions",
                                "jwks_uri": format!("{served_issuer}/.well-known/jwks"),
                            })
                            .to_string(),
                        ),
                        DiscoveryMode::Malformed => ("200 OK", "", "{not-json".to_string()),
                    }
                } else {
                    (
                        "200 OK",
                        "",
                        format!(
                            r#"{{"keys":[{{"kty":"RSA","kid":"{KID}","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB"}}]}}"#
                        ),
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\n{extra_headers}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        Self {
            address,
            issuer,
            stop,
            task,
        }
    }

    async fn shutdown(self) {
        let _ = self.stop.send(());
        self.task.await.expect("HTTPS origin task");
    }
}

fn forgejo_catalog(issuer: &str, ca_bundle_path: PathBuf) -> Arc<ProviderCatalog> {
    let rule = ProviderRule {
        id: RULE_ID.to_string(),
        subject: "ci/release".to_string(),
        audience: "basil://ci.test/invocation".to_string(),
        operation_profiles: vec![ProviderOperationProfile::ArtifactSign],
        artifact_sign_key_ids: vec!["release-signing".to_string()],
        max_token_age_secs: 300,
        clock_skew_secs: 30,
        max_operations_per_run: Some(64),
        provider: ProviderConfig::ForgejoActions(ForgejoActionsRule {
            issuer: issuer.to_string(),
            discovery_url: format!("{issuer}/.well-known/openid-configuration"),
            jwks_url: format!("{issuer}/.well-known/jwks"),
            ca_bundle_path: Some(ca_bundle_path),
            audience_prefix: "urn:basil:ci:jkt:".to_string(),
            repository_id: 42,
            repository_owner_id: 7,
            workflow_ref: WORKFLOW_REF.to_string(),
            ref_name: "refs/heads/main".to_string(),
            ref_type: "branch".to_string(),
            sha: "a".repeat(40),
            run_id: 998_877,
            run_attempt: 1,
            not_before_unix: NOW_SECS - 30,
            expires_at_unix: NOW_SECS + 300,
            max_token_age_secs: 300,
            clock_skew_secs: 30,
        }),
    };
    Arc::new(
        ProviderCatalog::with_experimental_providers(vec![rule], &[ProviderKind::ForgejoActions])
            .expect("valid Forgejo TLS catalog"),
    )
}

/// A provider whose documents are an in-test table: same issuer, same URLs,
/// same `kid` in every epoch — only the key material differs.
struct TableFetcher {
    /// Which trust epoch the provider currently serves (0 = v1, 1 = v2).
    epoch: usize,
    /// Fetches served, so the test can prove who fetched and how often.
    fetches: usize,
}

impl TableFetcher {
    const fn serving(epoch: usize) -> Self {
        Self { epoch, fetches: 0 }
    }

    fn jwks_body(&self) -> String {
        let epochs = trust_epochs();
        let modulus = if self.epoch == 0 {
            &epochs.0.modulus
        } else {
            &epochs.1.modulus
        };
        format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"{KID}","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB"}}]}}"#
        )
    }
}

impl ProviderDocumentFetcher for TableFetcher {
    fn fetch(
        &mut self,
        url: &Url,
        _max_body_bytes: usize,
    ) -> Result<FetchedDocument, FederationError> {
        self.fetches += 1;
        let rule = github_rule();
        let body = if url.as_str() == rule.discovery_url {
            json!({ "issuer": ISSUER, "jwks_uri": rule.jwks_url }).to_string()
        } else if url.as_str() == rule.jwks_url {
            self.jwks_body()
        } else {
            return Err(FederationError::InvalidUrl);
        };
        FetchedDocument::new(url.as_str(), 200, false, body.into_bytes())
    }
}

/// A token satisfying every rule pin, signed by the requested trust key.
fn token_signed_by(key: &TrustKey, jti: &str) -> String {
    let claims: Value = json!({
        "iss": ISSUER,
        "aud": proof_audience(&PROOF_KEY),
        "sub": "repo:openbasil/basil:ref:refs/heads/main",
        "repository": "openbasil/basil",
        "repository_id": "42",
        "repository_owner_id": "7",
        "event_name": "push",
        "ref": "refs/heads/main",
        "job_workflow_ref": WORKFLOW_REF,
        "job_workflow_sha": "a".repeat(40),
        "runner_environment": "github-hosted",
        "jti": jti,
        "iat": NOW_SECS - 10,
        "exp": NOW_SECS + 300,
        "run_id": "998877",
        "run_attempt": "1",
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());
    jsonwebtoken::encode(&header, &claims, &key.signer).expect("token signs")
}

fn forgejo_token(rule: &ForgejoActionsRule, key: &TrustKey, jti: &str) -> String {
    let claims = json!({
        "iss": rule.issuer,
        "aud": proof_audience(&PROOF_KEY),
        "sub": "repo:openbasil/basil:ref:refs/heads/main",
        "repository": "openbasil/basil",
        "repository_id": rule.repository_id.to_string(),
        "repository_owner_id": rule.repository_owner_id.to_string(),
        "event_name": "push",
        "ref": rule.ref_name,
        "ref_type": rule.ref_type,
        "sha": rule.sha,
        "workflow_ref": rule.workflow_ref,
        "run_id": rule.run_id.to_string(),
        "run_attempt": rule.run_attempt.to_string(),
        "jti": jti,
        "iat": NOW_SECS - 10,
        "exp": NOW_SECS + 300,
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_string());
    jsonwebtoken::encode(&header, &claims, &key.signer).expect("Forgejo token signs")
}

/// Run one classify-then-refresh pass the way the serving path does: an
/// unknown `kid` must admit a cooldown-gated refresh, after which the cache
/// serves whatever the provider handed THIS generation.
fn refresh_for_kid(cache: &mut GenerationJwksCache, fetcher: &mut TableFetcher) {
    match cache.serve_or_revalidate(KID, now()) {
        ServeDecision::UnknownKid { refresh_allowed } => {
            assert!(refresh_allowed, "first unknown-kid classify admits a fetch");
        }
        other => panic!("a new generation cache must not serve `{KID}`: {other:?}"),
    }
    cache
        .refresh(fetcher, now())
        .expect("bounded provider refresh succeeds");
}

#[test]
fn rotated_trust_with_same_issuer_and_kid_never_crosses_a_reload() {
    let correlation = TokenCorrelationKey::new(Zeroizing::new([7; 32]));
    let (v1, v2) = trust_epochs();
    let rule = github_rule();
    let token_v1 = token_signed_by(v1, "epoch-1-token");
    let token_v2 = token_signed_by(v2, "epoch-2-token");

    // --- Generation A serves trust v1.
    let generation_a = generation(1);
    let mut fetcher_a = TableFetcher::serving(0);
    {
        let mut caches = generation_a.jwks_caches().lock().expect("cache lock");
        let cache = caches.get_mut(RULE_ID).expect("rule cache exists");
        assert_eq!(cache.generation(), 1);
        refresh_for_kid(cache, &mut fetcher_a);
        let keys = cache.cached_keys().expect("generation A installed v1");
        verify_github(&rule, &keys, &token_v1, &PROOF_KEY, &correlation, now())
            .expect("generation A accepts the epoch-1 token");
        assert_eq!(
            verify_github(&rule, &keys, &token_v2, &PROOF_KEY, &correlation, now()),
            Err(FederationError::TokenRejected),
            "generation A has never seen epoch-2 trust"
        );
    }
    let fetch_count_before_b = fetcher_a.fetches;
    assert!(
        fetch_count_before_b > 0,
        "generation A fetched its own trust"
    );

    // --- The provider rotates: SAME issuer, SAME URLs, SAME kid, new key.
    // --- A reload builds generation B from the same rule configuration.
    let generation_b = generation(2);
    let mut fetcher_b = TableFetcher::serving(1);
    {
        let mut caches = generation_b.jwks_caches().lock().expect("cache lock");
        let cache = caches.get_mut(RULE_ID).expect("rule cache exists");
        assert_eq!(cache.generation(), 2, "the cache is generation B's own");
        // The critical classify: `kid` and issuer are identical to what
        // generation A verified seconds ago, and generation B must still
        // treat the kid as UNKNOWN. `refresh_for_kid` panics on any `Fresh`
        // serve — the exact cross-generation reuse this row forbids.
        refresh_for_kid(cache, &mut fetcher_b);
        let keys = cache.cached_keys().expect("generation B installed v2");
        verify_github(&rule, &keys, &token_v2, &PROOF_KEY, &correlation, now())
            .expect("generation B accepts the epoch-2 token");
        assert_eq!(
            verify_github(&rule, &keys, &token_v1, &PROOF_KEY, &correlation, now()),
            Err(FederationError::TokenRejected),
            "the retired epoch-1 key must stop verifying at the reload boundary \
             even though issuer and kid never changed"
        );
    }
    assert!(fetcher_b.fetches > 0, "generation B fetched its own trust");

    // --- Generation A stays pinned for its in-flight requests: it still
    // serves ITS v1 trust (fresh, no new fetch), and never observed v2.
    {
        let mut caches = generation_a.jwks_caches().lock().expect("cache lock");
        let cache = caches.get_mut(RULE_ID).expect("rule cache exists");
        let keys = match cache.serve_or_revalidate(KID, now()) {
            ServeDecision::Fresh(keys) => keys,
            other => panic!("generation A serves its pinned fresh trust: {other:?}"),
        };
        verify_github(&rule, &keys, &token_v1, &PROOF_KEY, &correlation, now())
            .expect("in-flight generation A work still completes under v1 trust");
        assert_eq!(
            verify_github(&rule, &keys, &token_v2, &PROOF_KEY, &correlation, now()),
            Err(FederationError::TokenRejected),
            "generation B's trust must not leak backwards either"
        );
    }
    assert_eq!(
        fetcher_a.fetches, fetch_count_before_b,
        "generation A never fetched again after generation B took over"
    );
}

#[tokio::test]
async fn generation_clients_pin_exclusive_ca_across_real_https_rotation() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = TestDirectory::create();
    let ca_a = fixture.path().join("ca-a.pem");
    let ca_b = fixture.path().join("ca-b.pem");
    let material_a = tls_material();
    let material_b = tls_material();
    std::fs::write(&ca_a, material_a.ca.as_bytes()).expect("write CA A");
    std::fs::write(&ca_b, material_b.ca.as_bytes()).expect("write CA B");
    std::fs::set_permissions(&ca_a, std::fs::Permissions::from_mode(0o600)).expect("protect CA A");
    std::fs::set_permissions(&ca_b, std::fs::Permissions::from_mode(0o600)).expect("protect CA B");

    let (signer_a, signer_b) = trust_epochs();
    let origin_a = HttpsOrigin::start(
        None,
        &material_a,
        signer_a.modulus.clone(),
        DiscoveryMode::Exact,
    )
    .await;
    let issuer = origin_a.issuer.clone();
    let catalog_a = forgejo_catalog(&issuer, ca_a.clone());
    let generation_a = generation_with_catalog(11, Arc::clone(&catalog_a));
    let provider_a = &catalog_a
        .rules()
        .first()
        .expect("generation A rule")
        .provider;
    let client_a = generation_a
        .provider_client(RULE_ID)
        .expect("generation A client");
    let jwks_a = fetch_generation_jwks(client_a, generation_a.id(), provider_a)
        .await
        .expect("generation A trusts CA A");
    assert_eq!(
        jwks_a.key(KID).expect("epoch A key").n,
        signer_a.modulus,
        "generation A receives key A over CA A"
    );
    let address = origin_a.address;
    origin_a.shutdown().await;

    let origin_b = HttpsOrigin::start(
        Some(address),
        &material_b,
        signer_b.modulus.clone(),
        DiscoveryMode::Exact,
    )
    .await;
    assert_eq!(origin_b.issuer, issuer, "issuer and URLs remain exact");
    let catalog_b = forgejo_catalog(&issuer, ca_b);
    let generation_b = generation_with_catalog(12, Arc::clone(&catalog_b));
    let provider_b = &catalog_b
        .rules()
        .first()
        .expect("generation B rule")
        .provider;
    let client_b = generation_b
        .provider_client(RULE_ID)
        .expect("generation B client");
    let jwks_b = fetch_generation_jwks(client_b, generation_b.id(), provider_b)
        .await
        .expect("generation B trusts CA B");
    assert_eq!(
        jwks_b.key(KID).expect("epoch B key").n,
        signer_b.modulus,
        "same kid resolves only to generation B's key"
    );
    assert_ne!(
        jwks_b.key(KID).expect("epoch B key").n,
        jwks_a.key(KID).expect("epoch A key").n,
        "retired key material cannot leak into generation B"
    );
    let ProviderConfig::ForgejoActions(rule_b) = provider_b else {
        panic!("TLS fixture uses Forgejo")
    };
    let correlation = TokenCorrelationKey::new(Zeroizing::new([9; 32]));
    let token_b = forgejo_token(rule_b, signer_b, "tls-epoch-b");
    let retired_token = forgejo_token(rule_b, signer_a, "tls-retired-a");
    verify_forgejo(rule_b, &jwks_b, &token_b, &PROOF_KEY, &correlation, now())
        .expect("generation B accepts the new provider key");
    assert_eq!(
        verify_forgejo(
            rule_b,
            &jwks_b,
            &retired_token,
            &PROOF_KEY,
            &correlation,
            now(),
        ),
        Err(FederationError::TokenRejected),
        "generation B rejects the retired provider key"
    );

    assert!(
        matches!(
            fetch_generation_jwks(client_a, generation_a.id(), provider_a).await,
            Err(FederationError::FetchRejected)
        ),
        "generation A's pinned CA rejects the replacement TLS identity"
    );
    let wrong_ca_catalog = forgejo_catalog(&issuer, fixture.path().join("ca-a.pem"));
    let wrong_ca_generation = generation_with_catalog(13, Arc::clone(&wrong_ca_catalog));
    assert!(
        matches!(
            fetch_generation_jwks(
                wrong_ca_generation
                    .provider_client(RULE_ID)
                    .expect("wrong-CA generation client"),
                wrong_ca_generation.id(),
                &wrong_ca_catalog
                    .rules()
                    .first()
                    .expect("wrong-CA rule")
                    .provider,
            )
            .await,
            Err(FederationError::FetchRejected)
        ),
        "exclusive roots do not fall back to system or retired roots"
    );
    let fetched_at = UNIX_EPOCH + Duration::from_secs(NOW_SECS);
    generation_b
        .jwks_caches()
        .lock()
        .expect("generation B cache lock")
        .get_mut(RULE_ID)
        .expect("generation B cache")
        .install(jwks_b.clone(), fetched_at);
    origin_b.shutdown().await;

    let stale_now = fetched_at + Duration::from_secs(301);
    let stale = generation_b
        .jwks_caches()
        .lock()
        .expect("generation B cache lock")
        .get_mut(RULE_ID)
        .map(|cache| cache.serve_or_revalidate(KID, stale_now))
        .expect("generation B cache");
    assert!(matches!(
        stale,
        ServeDecision::Revalidate {
            refresh_allowed: true,
            stale: Some(_),
        }
    ));
    assert!(matches!(
        fetch_generation_jwks(client_b, generation_b.id(), provider_b).await,
        Err(FederationError::FetchRejected)
    ));
    let expired_now = fetched_at + Duration::from_secs(331);
    let expired = generation_b
        .jwks_caches()
        .lock()
        .expect("generation B cache lock")
        .get_mut(RULE_ID)
        .map(|cache| cache.serve_or_revalidate(KID, expired_now))
        .expect("generation B cache");
    assert!(matches!(
        expired,
        ServeDecision::Revalidate { stale: None, .. }
    ));
}

#[tokio::test]
async fn live_https_discovery_failures_are_closed_before_jwks() {
    use std::os::unix::fs::PermissionsExt as _;

    for (index, mode) in [
        DiscoveryMode::Redirect,
        DiscoveryMode::WrongIssuer,
        DiscoveryMode::Malformed,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = TestDirectory::create();
        let material = tls_material();
        let ca = fixture.path().join(format!("ca-{index}.pem"));
        std::fs::write(&ca, material.ca.as_bytes()).expect("write discovery CA");
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o600))
            .expect("protect discovery CA");
        let origin =
            HttpsOrigin::start(None, &material, trust_epochs().0.modulus.clone(), mode).await;
        let catalog = forgejo_catalog(&origin.issuer, ca);
        let generation = generation_with_catalog(20 + index as u64, Arc::clone(&catalog));
        let result = fetch_generation_jwks(
            generation
                .provider_client(RULE_ID)
                .expect("generation client"),
            generation.id(),
            &catalog.rules().first().expect("discovery rule").provider,
        )
        .await;
        match mode {
            DiscoveryMode::Redirect => {
                assert!(matches!(result, Err(FederationError::FetchRejected)));
            }
            DiscoveryMode::WrongIssuer => {
                assert!(matches!(result, Err(FederationError::ProviderRejected)));
            }
            DiscoveryMode::Malformed => {
                assert!(matches!(result, Err(FederationError::Malformed)));
            }
            DiscoveryMode::Exact => assert!(result.is_ok(), "exact discovery succeeds"),
        }
        origin.shutdown().await;
    }
}
