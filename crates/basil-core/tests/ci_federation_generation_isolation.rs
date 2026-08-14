// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Generation-pinning tests for the CI federation catalog and JWKS caches.
//!
//! A reload builds a new [`Generation`]; its JWKS cache must start empty even
//! when the previous generation had verified keys for the same issuer and key
//! IDs, so no key material or trust decision crosses a reload boundary.

#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::significant_drop_tightening,
    clippy::unwrap_used
)]

use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil_core::catalog::loader::load;
use basil_core::ci_federation::{
    ForgejoActionsRule, GenerationJwks, GithubActionsRule, ProviderCatalog, ProviderConfig,
    ProviderKind, ProviderOperationProfile, ProviderRule,
};
use basil_core::state::Generation;

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const RULE_ID: &str = "release";

fn provider_catalog_with_target(target: &str) -> Arc<ProviderCatalog> {
    let rule = ProviderRule {
        id: RULE_ID.to_string(),
        subject: "ci/release".to_string(),
        audience: "basil://ci.test/invocation".to_string(),
        operation_profiles: vec![ProviderOperationProfile::ArtifactSign],
        artifact_sign_key_ids: vec![target.to_string()],
        max_token_age_secs: 900,
        clock_skew_secs: 30,
        max_operations_per_run: Some(64),
        provider: ProviderConfig::GithubActions(GithubActionsRule {
            issuer: ISSUER.to_string(),
            discovery_url: format!("{ISSUER}/.well-known/openid-configuration"),
            jwks_url: format!("{ISSUER}/.well-known/jwks"),
            ca_bundle_path: None,
            audience_prefix: "urn:basil:ci:jkt:".to_string(),
            repository_id: 42,
            repository_owner_id: 7,
            job_workflow_ref: "openbasil/basil/.github/workflows/release.yml@refs/heads/main"
                .to_string(),
            job_workflow_sha: "a".repeat(40),
            protected_refs: vec!["refs/heads/main".to_string()],
            events: vec!["push".to_string()],
            runner_environments: vec!["github-hosted".to_string()],
            environment: None,
            max_token_age_secs: 900,
            clock_skew_secs: 30,
        }),
    };
    Arc::new(ProviderCatalog::new(vec![rule]).expect("valid federation catalog"))
}

fn provider_catalog() -> Arc<ProviderCatalog> {
    provider_catalog_with_target("release-signing")
}

fn generation(id: u64, federation: Option<Arc<ProviderCatalog>>) -> Generation {
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
        federation,
    )
    .expect("federation generation")
}

fn jwks_body(kid: &str) -> Vec<u8> {
    let modulus = URL_SAFE_NO_PAD.encode([0x80; 256]);
    format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB"}}]}}"#
    )
    .into_bytes()
}

#[test]
fn each_generation_owns_an_empty_cache_per_configured_rule() {
    let first = generation(1, Some(provider_catalog()));
    assert!(first.federation().is_some());
    let caches = first.jwks_caches().lock().expect("cache lock");
    let cache = caches.get(RULE_ID).expect("rule cache exists");
    assert_eq!(cache.generation(), 1);
    assert!(cache.cached_key("rotated").is_none(), "new cache is empty");
    assert_eq!(caches.len(), 1, "exactly one cache per configured rule");
}

#[test]
fn reload_never_carries_verified_keys_into_the_next_generation() {
    let first = generation(1, Some(provider_catalog()));
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    {
        let mut caches = first.jwks_caches().lock().expect("cache lock");
        let cache = caches.get_mut(RULE_ID).expect("rule cache exists");
        let keys = GenerationJwks::parse(1, &jwks_body("live-key")).expect("keys parse");
        cache.install(keys, now);
        assert!(cache.cached_key("live-key").is_some());
    }

    // Same configuration, next generation: the cache must start empty and
    // carry the new generation identity even though issuer and kid match.
    let second = generation(2, Some(provider_catalog()));
    let caches = second.jwks_caches().lock().expect("cache lock");
    let cache = caches.get(RULE_ID).expect("rule cache exists");
    assert_eq!(cache.generation(), 2);
    assert!(cache.cached_key("live-key").is_none());

    // The first generation keeps serving its pinned keys until dropped.
    assert!(
        first
            .jwks_caches()
            .lock()
            .expect("cache lock")
            .get(RULE_ID)
            .expect("rule cache exists")
            .cached_key("live-key")
            .is_some()
    );
}

#[test]
fn a_generation_without_federation_config_exposes_no_providers_or_caches() {
    let plain = generation(3, None);
    assert!(plain.federation().is_none());
    assert!(plain.jwks_caches().lock().expect("cache lock").is_empty());
}

#[test]
fn reload_keeps_provider_target_authority_pinned_to_each_generation() {
    let first = generation(5, Some(provider_catalog_with_target("release-v1")));
    let second = generation(6, Some(provider_catalog_with_target("release-v2")));

    let first_rules = first.federation().expect("first catalog");
    let second_rules = second.federation().expect("second catalog");
    let first_rule = first_rules.rules().first().expect("first rule");
    let second_rule = second_rules.rules().first().expect("second rule");
    assert_eq!(first_rule.artifact_sign_key_ids, ["release-v1"]);
    assert_eq!(second_rule.artifact_sign_key_ids, ["release-v2"]);
    assert_eq!(first_rule.artifact_sign_key_ids, ["release-v1"]);
}

#[test]
fn forgejo_rules_get_their_own_empty_generation_cache() {
    let forgejo_issuer = "https://forge.example.com/api/actions";
    let rule = ProviderRule {
        id: "forgejo-nightly".to_string(),
        subject: "ci/forgejo-release".to_string(),
        audience: "basil://ci.test/invocation".to_string(),
        operation_profiles: vec![ProviderOperationProfile::ArtifactSign],
        artifact_sign_key_ids: vec!["release-signing".to_string()],
        max_token_age_secs: 300,
        clock_skew_secs: 30,
        max_operations_per_run: Some(64),
        provider: ProviderConfig::ForgejoActions(ForgejoActionsRule {
            issuer: forgejo_issuer.to_string(),
            discovery_url: format!("{forgejo_issuer}/.well-known/openid-configuration"),
            jwks_url: format!("{forgejo_issuer}/.well-known/jwks"),
            ca_bundle_path: None,
            audience_prefix: "urn:basil:ci:jkt:".to_string(),
            repository_id: 11,
            repository_owner_id: 3,
            workflow_ref: "forge/basil/.forgejo/workflows/release.yml@refs/heads/main".to_string(),
            ref_name: "refs/heads/main".to_string(),
            ref_type: "branch".to_string(),
            sha: "b".repeat(40),
            run_id: 900,
            run_attempt: 1,
            not_before_unix: 1_700_000_000,
            expires_at_unix: 1_700_000_000 + 900,
            max_token_age_secs: 300,
            clock_skew_secs: 30,
        }),
    };
    let catalog = Arc::new(
        ProviderCatalog::with_experimental_providers(vec![rule], &[ProviderKind::ForgejoActions])
            .expect("opted-in forgejo catalog"),
    );
    let generation = generation(4, Some(catalog));
    let caches = generation.jwks_caches().lock().expect("cache lock");
    let cache = caches.get("forgejo-nightly").expect("forgejo rule cache");
    assert_eq!(cache.generation(), 4);
    assert!(cache.cached_key("any").is_none(), "new cache starts empty");
}
