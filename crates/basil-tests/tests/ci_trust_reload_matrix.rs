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
//! This is hermetic (no broker, no network): the fetch boundary is the
//! [`ProviderDocumentFetcher`] seam the cache exposes, and the RSA keys are
//! deterministic runtime-generated material (no key blobs in source). The
//! live-broker rendition of the same boundary is blocked on the hermetic
//! provider-origin seam (`basil-abdh`): a `kid`-bearing token makes the
//! serving path fetch the PINNED GitHub origin, which a test cannot
//! redirect. The wire-side reload rows (generation pinning, kill switch,
//! policy separation) live in `ci_reload_policy_matrix.rs`.

#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil_core::catalog::loader::load;
use basil_core::ci_federation::{
    FederationError, FetchedDocument, GenerationJwksCache, GithubActionsRule, ProviderCatalog,
    ProviderConfig, ProviderDocumentFetcher, ProviderRule, ServeDecision, TokenCorrelationKey,
    proof_audience, verify_github,
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
        audience: "urn:basil:ci".to_string(),
        operation_profiles: vec!["artifact-sign".to_string()],
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
    Generation::new_with_overrides_oci_listeners_and_federation(
        id,
        catalog,
        resolved,
        config,
        Vec::new(),
        None,
        Arc::new(basil_core::transport::listener::ListenerConfigSet::default()),
        Some(provider_catalog()),
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
