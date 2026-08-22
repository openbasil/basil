// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Acceptance and rejection corpus for the strict GitHub Actions verifier.
//!
//! Every case round-trips a real `RS256`-signed token through
//! [`basil_core::ci_federation::verify_github`] against a fixed test JWKS, so
//! the corpus exercises the exact production code path: header checks, JWKS
//! key lookup, signature verification, and the typed claim rules. The rule's
//! `clock_skew_secs` is asserted as the single time-boundary authority
//! (library leeway is zero).

#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::unwrap_used
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil_core::ci_federation::{
    FederationError, GenerationJwks, GithubActionsRule, TokenCorrelationKey, proof_audience,
    verify_github,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const KID: &str = "corpus-key";
const NOW_SECS: u64 = 1_700_000_000;
const SKEW: u64 = 30;
const MAX_AGE: u64 = 900;
const WORKFLOW_REF: &str = "openbasil/basil/.github/workflows/release.yml@refs/heads/main";
const PROOF_KEY: [u8; 32] = [7; 32];

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW_SECS)
}

/// Test-only deterministic RSA-2048 corpus keys, generated once per binary.
///
/// Runtime generation (seeded, reproducible) keeps base64 key blobs out of
/// the source while still exercising real `RS256` signatures.
struct CorpusKeys {
    /// The trusted JWKS signing key.
    signer: EncodingKey,
    /// Base64url modulus of `signer` for the corpus JWKS (e = 65537).
    signer_n: String,
    /// An unrelated key for wrong-signer cases.
    impostor: EncodingKey,
}

fn corpus_keys() -> &'static CorpusKeys {
    static KEYS: std::sync::OnceLock<CorpusKeys> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        use rand::SeedableRng as _;
        use rsa::pkcs1::EncodeRsaPrivateKey as _;
        use rsa::traits::PublicKeyParts as _;
        let generate = |seed: u64| {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("corpus keygen");
            let der = key.to_pkcs1_der().expect("corpus key encodes");
            let n = URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
            (EncodingKey::from_rsa_der(der.as_bytes()), n)
        };
        let (signer, signer_n) = generate(7);
        let (impostor, _) = generate(8);
        CorpusKeys {
            signer,
            signer_n,
            impostor,
        }
    })
}

fn rule() -> GithubActionsRule {
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
        max_token_age_secs: MAX_AGE,
        clock_skew_secs: SKEW,
    }
}

fn jwks() -> GenerationJwks {
    let modulus = &corpus_keys().signer_n;
    let body = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"{KID}","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB"}}]}}"#
    );
    GenerationJwks::parse(1, body.as_bytes()).expect("corpus JWKS parses")
}

fn base_claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": proof_audience(&PROOF_KEY),
        "sub": "repo:openbasil/basil:ref:refs/heads/main",
        "repository": "openbasil/basil",
        "repository_id": "42",
        "repository_owner_id": "7",
        "actor_id": "12345",
        "event_name": "push",
        "ref": "refs/heads/main",
        "job_workflow_ref": WORKFLOW_REF,
        "job_workflow_sha": "a".repeat(40),
        "runner_environment": "github-hosted",
        "jti": "example-token-id",
        "iat": NOW_SECS - 10,
        "exp": NOW_SECS + 300,
        // The per-run quota partitions on the attested run identity, so
        // `run_id` and `run_attempt` are required claims.
        "run_id": "998877",
        "run_attempt": "1",
        // Real GitHub tokens carry many additional claims; the strict
        // verifier must tolerate (and ignore) them.
        "run_number": "7",
    })
}

fn sign(claims: &Value, kid: &str, key: &EncodingKey) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(&header, claims, key).expect("corpus token signs")
}

fn token_with(mutate: impl FnOnce(&mut serde_json::Map<String, Value>)) -> String {
    let mut claims = base_claims();
    let map = claims.as_object_mut().expect("claims are an object");
    mutate(map);
    sign(&claims, KID, &corpus_keys().signer)
}

fn correlation() -> TokenCorrelationKey {
    TokenCorrelationKey::new(Zeroizing::new([9; 32]))
}

fn verify_token(token: &str) -> Result<basil_core::ci_federation::GithubEvidence, FederationError> {
    verify_github(&rule(), &jwks(), token, &PROOF_KEY, &correlation(), now())
}

#[test]
fn exact_token_is_accepted_with_typed_evidence_and_keyed_digests() {
    let token = token_with(|_| {});
    let evidence = verify_token(&token).expect("exact token accepted");
    assert_eq!(evidence.repository_id, 42);
    assert_eq!(evidence.repository_owner_id, 7);
    assert_eq!(evidence.repository, "openbasil/basil");
    assert_eq!(evidence.actor_id, Some(12_345));
    assert_eq!(evidence.workflow_ref, WORKFLOW_REF);
    assert_eq!(evidence.workflow_sha, "a".repeat(40));
    assert_eq!(evidence.ref_name, "refs/heads/main");
    assert_eq!(evidence.event_name, "push");
    assert_eq!(evidence.runner_environment, "github-hosted");
    assert_eq!(evidence.environment, None);
    assert_ne!(evidence.jti_digest, evidence.token_digest);

    // The digests are deterministic under one key and keyed: a different
    // broker key yields different correlation identities for the same token.
    let again = verify_token(&token).expect("verification is deterministic");
    assert_eq!(again.jti_digest, evidence.jti_digest);
    assert_eq!(again.token_digest, evidence.token_digest);
    let other_key = TokenCorrelationKey::new(Zeroizing::new([1; 32]));
    let rekeyed = verify_github(&rule(), &jwks(), &token, &PROOF_KEY, &other_key, now())
        .expect("token accepted under another correlation key");
    assert_ne!(rekeyed.jti_digest, evidence.jti_digest);
    assert_ne!(rekeyed.token_digest, evidence.token_digest);
}

#[test]
fn time_boundaries_are_exactly_the_rule_clock_skew() {
    // `iat` in the future is accepted at exactly the skew and rejected past it.
    let at_boundary = token_with(|c| {
        c.insert("iat".into(), json!(NOW_SECS + SKEW));
    });
    assert!(verify_token(&at_boundary).is_ok());
    let past_boundary = token_with(|c| {
        c.insert("iat".into(), json!(NOW_SECS + SKEW + 1));
    });
    assert_eq!(
        verify_token(&past_boundary),
        Err(FederationError::ProviderRejected)
    );

    // `exp` already passed is accepted within the skew and rejected past it.
    // With the library's default 60-second leeway this boundary would move;
    // leeway is pinned to zero so the rule is the single authority.
    let expired_within_skew = token_with(|c| {
        c.insert("iat".into(), json!(NOW_SECS - 300));
        c.insert("exp".into(), json!(NOW_SECS - SKEW));
    });
    assert!(verify_token(&expired_within_skew).is_ok());
    let expired_past_skew = token_with(|c| {
        c.insert("iat".into(), json!(NOW_SECS - 300));
        c.insert("exp".into(), json!(NOW_SECS - SKEW - 1));
    });
    assert_eq!(
        verify_token(&expired_past_skew),
        Err(FederationError::ProviderRejected)
    );

    // `nbf` is optional; when present it is bounded by the same skew.
    let nbf_at_boundary = token_with(|c| {
        c.insert("nbf".into(), json!(NOW_SECS + SKEW));
    });
    assert!(verify_token(&nbf_at_boundary).is_ok());
    let nbf_past_boundary = token_with(|c| {
        c.insert("nbf".into(), json!(NOW_SECS + SKEW + 1));
    });
    assert_eq!(
        verify_token(&nbf_past_boundary),
        Err(FederationError::ProviderRejected)
    );
}

#[test]
fn token_age_and_ordering_bounds_fail_closed() {
    let at_max_age = token_with(|c| {
        c.insert("iat".into(), json!(NOW_SECS - MAX_AGE));
    });
    assert!(verify_token(&at_max_age).is_ok());
    let too_old = token_with(|c| {
        c.insert("iat".into(), json!(NOW_SECS - MAX_AGE - 1));
    });
    assert_eq!(
        verify_token(&too_old),
        Err(FederationError::ProviderRejected)
    );

    // `exp` before `iat` is rejected even when both are individually in range.
    let inverted = token_with(|c| {
        c.insert("iat".into(), json!(NOW_SECS + 20));
        c.insert("exp".into(), json!(NOW_SECS + 10));
    });
    assert_eq!(
        verify_token(&inverted),
        Err(FederationError::ProviderRejected)
    );

    let missing_exp = token_with(|c| {
        c.remove("exp");
    });
    assert_eq!(
        verify_token(&missing_exp),
        Err(FederationError::TokenRejected)
    );
}

#[test]
fn numeric_repository_identity_is_matched_exactly() {
    let wrong_repository = token_with(|c| {
        c.insert("repository_id".into(), json!("43"));
    });
    assert_eq!(
        verify_token(&wrong_repository),
        Err(FederationError::ProviderRejected)
    );

    let wrong_owner = token_with(|c| {
        c.insert("repository_owner_id".into(), json!("8"));
    });
    assert_eq!(
        verify_token(&wrong_owner),
        Err(FederationError::ProviderRejected)
    );

    // A rename cannot substitute for the numeric identity: the name is audit
    // context, and an empty name is rejected outright.
    let renamed = token_with(|c| {
        c.insert("repository".into(), json!("other-owner/basil"));
    });
    assert!(verify_token(&renamed).is_ok());
    let empty_name = token_with(|c| {
        c.insert("repository".into(), json!(""));
    });
    assert_eq!(
        verify_token(&empty_name),
        Err(FederationError::ProviderRejected)
    );

    // Non-decimal identities are malformed, not coerced.
    for bad in ["42abc", "-42", "", "4 2"] {
        let token = token_with(|c| {
            c.insert("repository_id".into(), json!(bad));
        });
        assert_eq!(
            verify_token(&token),
            Err(FederationError::Malformed),
            "{bad:?}"
        );
    }
    let numeric_json = token_with(|c| {
        c.insert("repository_id".into(), json!(42));
    });
    assert_eq!(
        verify_token(&numeric_json),
        Err(FederationError::TokenRejected),
        "JSON-number identity is not the GitHub string shape"
    );
}

#[test]
fn protected_environment_must_match_the_rule_exactly() {
    // Rule without an environment rejects any token-supplied environment.
    let unexpected = token_with(|c| {
        c.insert("environment".into(), json!("production"));
    });
    assert_eq!(
        verify_token(&unexpected),
        Err(FederationError::ProviderRejected)
    );

    // Rule with an environment requires exactly that environment.
    let mut environment_rule = rule();
    environment_rule.environment = Some("production".to_string());
    let matching = token_with(|c| {
        c.insert("environment".into(), json!("production"));
    });
    assert!(
        verify_github(
            &environment_rule,
            &jwks(),
            &matching,
            &PROOF_KEY,
            &correlation(),
            now()
        )
        .is_ok()
    );
    for token in [
        token_with(|_| {}),
        token_with(|c| {
            c.insert("environment".into(), json!("staging"));
        }),
    ] {
        assert_eq!(
            verify_github(
                &environment_rule,
                &jwks(),
                &token,
                &PROOF_KEY,
                &correlation(),
                now()
            ),
            Err(FederationError::ProviderRejected)
        );
    }
}

#[test]
fn workflow_ref_event_and_runner_selectors_are_exact() {
    let cases: [(&str, Value); 5] = [
        (
            "job_workflow_ref",
            json!("openbasil/basil/.github/workflows/other.yml@refs/heads/main"),
        ),
        ("job_workflow_sha", json!("b".repeat(40))),
        ("ref", json!("refs/heads/feature")),
        ("event_name", json!("workflow_dispatch")),
        ("runner_environment", json!("self-hosted")),
    ];
    for (claim, value) in cases {
        let token = token_with(|c| {
            c.insert(claim.to_string(), value.clone());
        });
        assert_eq!(
            verify_token(&token),
            Err(FederationError::ProviderRejected),
            "{claim} must match exactly"
        );
    }
}

#[test]
fn jti_is_required_and_nonempty() {
    let empty = token_with(|c| {
        c.insert("jti".into(), json!(""));
    });
    assert_eq!(verify_token(&empty), Err(FederationError::ProviderRejected));
    let missing = token_with(|c| {
        c.remove("jti");
    });
    assert_eq!(verify_token(&missing), Err(FederationError::TokenRejected));
}

#[test]
fn issuer_audience_and_proof_key_binding_fail_closed() {
    let wrong_issuer = token_with(|c| {
        c.insert("iss".into(), json!("https://token.actions.example.com"));
    });
    assert_eq!(
        verify_token(&wrong_issuer),
        Err(FederationError::TokenRejected)
    );

    let wrong_audience = token_with(|c| {
        c.insert("aud".into(), json!(proof_audience(&[8; 32])));
    });
    assert_eq!(
        verify_token(&wrong_audience),
        Err(FederationError::TokenRejected)
    );

    // The same token never verifies for a different proof key: the audience
    // is bound to the exact Ed25519 key that signs the invocation.
    let token = token_with(|_| {});
    assert_eq!(
        verify_github(&rule(), &jwks(), &token, &[8; 32], &correlation(), now()),
        Err(FederationError::TokenRejected)
    );
}

#[test]
fn signature_and_key_selection_fail_closed() {
    // Signed by an unrelated key while claiming the trusted kid.
    let forged = sign(&base_claims(), KID, &corpus_keys().impostor);
    assert_eq!(verify_token(&forged), Err(FederationError::TokenRejected));

    // Unknown kid never verifies, even with a valid signature.
    let unknown_kid = sign(&base_claims(), "other-key", &corpus_keys().signer);
    assert_eq!(
        verify_token(&unknown_kid),
        Err(FederationError::TokenRejected)
    );

    // Tampered payload breaks the signature.
    let token = token_with(|_| {});
    let mut parts = token.split('.');
    let header = parts.next().expect("header");
    let _payload = parts.next().expect("payload");
    let signature = parts.next().expect("signature");
    let tampered_claims = {
        let mut claims = base_claims();
        claims
            .as_object_mut()
            .expect("object")
            .insert("repository_id".into(), json!("999"));
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("serializes"))
    };
    let tampered = format!("{header}.{tampered_claims}.{signature}");
    assert_eq!(verify_token(&tampered), Err(FederationError::TokenRejected));

    // An algorithm-substituted token is rejected before key lookup.
    let hs256 = jsonwebtoken::encode(
        &{
            let mut header = Header::new(Algorithm::HS256);
            header.kid = Some(KID.to_string());
            header
        },
        &base_claims(),
        &EncodingKey::from_secret(b"guessable"),
    )
    .expect("HS256 token encodes");
    assert_eq!(verify_token(&hs256), Err(FederationError::TokenRejected));
}

#[test]
fn oversized_tokens_are_rejected_before_parsing() {
    let padding = "x".repeat(33 * 1024);
    let token = token_with(|c| {
        c.insert("padding".into(), json!(padding));
    });
    assert_eq!(
        verify_token(&token),
        Err(FederationError::Oversized("token"))
    );
}
