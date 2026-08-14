// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Acceptance and rejection corpus for the strict Forgejo Actions verifier.
//!
//! Every case round-trips a real `RS256`-signed token through
//! [`basil_core::ci_federation::verify_forgejo`] against a fixed test JWKS, so
//! the corpus exercises the exact production code path: header checks, JWKS
//! key lookup, signature verification, the typed claim rules, and the
//! operator-installed run-specific grant window. The tier is experimental:
//! tokens attest no runner, environment, or reusable-callee identity, so the
//! corpus proves those authorities are denied rather than trusted.

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
    FederationError, ForgejoActionsRule, GenerationJwks, TokenCorrelationKey, proof_audience,
    verify_forgejo,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const ISSUER: &str = "https://forge.example.com/api/actions";
const KID: &str = "forgejo-corpus-key";
const NOW_SECS: u64 = 1_700_000_000;
const SKEW: u64 = 30;
const MAX_AGE: u64 = 300;
const REPOSITORY: &str = "openbasil/basil";
const WORKFLOW_REF: &str = "openbasil/basil/.forgejo/workflows/release.yml@refs/heads/main";
const RUN_ID: u64 = 998_877;
const RUN_ATTEMPT: u64 = 2;
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
        let (signer, signer_n) = generate(17);
        let (impostor, _) = generate(18);
        CorpusKeys {
            signer,
            signer_n,
            impostor,
        }
    })
}

/// The operator-installed run-specific grant: the run and attempt IDs are
/// known, and the window spans exactly the 15-minute maximum around `now`.
fn rule() -> ForgejoActionsRule {
    ForgejoActionsRule {
        issuer: ISSUER.to_string(),
        discovery_url: format!("{ISSUER}/.well-known/openid-configuration"),
        jwks_url: format!("{ISSUER}/.well-known/jwks"),
        ca_bundle_path: None,
        audience_prefix: "urn:basil:ci:jkt:".to_string(),
        repository_id: 42,
        repository_owner_id: 7,
        workflow_ref: WORKFLOW_REF.to_string(),
        ref_name: "refs/heads/main".to_string(),
        ref_type: "branch".to_string(),
        sha: "a".repeat(40),
        run_id: RUN_ID,
        run_attempt: RUN_ATTEMPT,
        not_before_unix: NOW_SECS - 60,
        expires_at_unix: NOW_SECS + 840,
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
        "sub": format!("repo:{REPOSITORY}:ref:refs/heads/main"),
        "repository": REPOSITORY,
        "repository_id": "42",
        "repository_owner_id": "7",
        "actor_id": "12345",
        "event_name": "push",
        "ref": "refs/heads/main",
        "ref_type": "branch",
        "sha": "a".repeat(40),
        "workflow_ref": WORKFLOW_REF,
        "run_id": RUN_ID.to_string(),
        "run_attempt": RUN_ATTEMPT.to_string(),
        // Forgejo 16 initializes `ref_protected` without consulting
        // repository protection; the verifier must ignore it entirely.
        "ref_protected": false,
        "jti": "example-token-id",
        "iat": NOW_SECS - 10,
        "exp": NOW_SECS + 300,
        // Real tokens carry additional claims; the strict verifier must
        // tolerate (and ignore) them.
        "run_number": "12",
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

fn verify_token(
    token: &str,
) -> Result<basil_core::ci_federation::ForgejoEvidence, FederationError> {
    verify_forgejo(&rule(), &jwks(), token, &PROOF_KEY, &correlation(), now())
}

fn verify_with_rule(
    rule: &ForgejoActionsRule,
    token: &str,
) -> Result<basil_core::ci_federation::ForgejoEvidence, FederationError> {
    verify_forgejo(rule, &jwks(), token, &PROOF_KEY, &correlation(), now())
}

#[test]
fn exact_token_is_accepted_with_typed_evidence_and_keyed_digests() {
    let token = token_with(|_| {});
    let evidence = verify_token(&token).expect("exact token accepted");
    assert_eq!(evidence.repository_id, 42);
    assert_eq!(evidence.repository_owner_id, 7);
    assert_eq!(evidence.repository, REPOSITORY);
    assert_eq!(evidence.actor_id, Some(12_345));
    assert_eq!(evidence.workflow_ref, WORKFLOW_REF);
    assert_eq!(evidence.ref_name, "refs/heads/main");
    assert_eq!(evidence.ref_type, "branch");
    assert_eq!(evidence.sha, "a".repeat(40));
    assert_eq!(evidence.run_id, RUN_ID);
    assert_eq!(evidence.run_attempt, RUN_ATTEMPT);
    assert_eq!(evidence.event_name, "push");
    assert_ne!(evidence.jti_digest, evidence.token_digest);

    // The digests are deterministic under one key and keyed: a different
    // broker key yields different correlation identities for the same token.
    let again = verify_token(&token).expect("verification is deterministic");
    assert_eq!(again.jti_digest, evidence.jti_digest);
    assert_eq!(again.token_digest, evidence.token_digest);
    let other_key = TokenCorrelationKey::new(Zeroizing::new([1; 32]));
    let rekeyed = verify_forgejo(&rule(), &jwks(), &token, &PROOF_KEY, &other_key, now())
        .expect("token accepted under another correlation key");
    assert_ne!(rekeyed.jti_digest, evidence.jti_digest);
    assert_ne!(rekeyed.token_digest, evidence.token_digest);
}

#[test]
fn only_the_push_event_is_supported() {
    for event in [
        "pull_request",
        "pull_request_target",
        "workflow_call",
        "workflow_dispatch",
        "schedule",
        "release",
        "",
    ] {
        let token = token_with(|c| {
            c.insert("event_name".into(), json!(event));
        });
        assert_eq!(
            verify_token(&token),
            Err(FederationError::ProviderRejected),
            "event {event:?} must be rejected"
        );
    }
    let missing = token_with(|c| {
        c.remove("event_name");
    });
    assert_eq!(verify_token(&missing), Err(FederationError::TokenRejected));
}

#[test]
fn run_commit_and_ref_selectors_are_exact() {
    let cases: [(&str, Value); 6] = [
        ("run_id", json!("998878")),
        // A rerun increments `run_attempt` and requires another grant.
        ("run_attempt", json!("3")),
        ("sha", json!("b".repeat(40))),
        (
            "workflow_ref",
            json!("openbasil/basil/.forgejo/workflows/other.yml@refs/heads/main"),
        ),
        ("ref", json!("refs/heads/feature")),
        ("ref_type", json!("tag")),
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
        "JSON-number identity is not the string claim shape"
    );
}

#[test]
fn the_workflow_must_belong_to_the_tokens_own_repository() {
    // A renamed or different repository no longer owns the pinned workflow
    // identity, so the same-repository requirement fails closed even though
    // the numeric IDs and workflow selector still match the rule.
    for repository in ["other-owner/basil", "openbasil/basil2", "openbasil/bas"] {
        let token = token_with(|c| {
            c.insert("repository".into(), json!(repository));
        });
        assert_eq!(
            verify_token(&token),
            Err(FederationError::ProviderRejected),
            "repository {repository:?} does not own the workflow"
        );
    }
    let empty_name = token_with(|c| {
        c.insert("repository".into(), json!(""));
    });
    assert_eq!(
        verify_token(&empty_name),
        Err(FederationError::ProviderRejected)
    );
}

#[test]
fn environment_and_reusable_callee_authority_are_denied() {
    // Forgejo publishes no environment or reusable-callee identity; a token
    // presenting either is denied instead of silently ignored.
    for claim in ["environment", "job_workflow_ref", "job_workflow_sha"] {
        let token = token_with(|c| {
            c.insert(claim.to_string(), json!("anything"));
        });
        assert_eq!(
            verify_token(&token),
            Err(FederationError::ProviderRejected),
            "{claim} must deny"
        );
    }
}

#[test]
fn ref_protected_carries_no_protection_meaning() {
    // Forgejo 16 initializes the claim without consulting repository
    // protection, so no value of it may select or deny authority.
    let absent = token_with(|c| {
        c.remove("ref_protected");
    });
    assert!(verify_token(&absent).is_ok());
    let explicit_false = token_with(|_| {});
    assert!(verify_token(&explicit_false).is_ok());
    let explicit_true = token_with(|c| {
        c.insert("ref_protected".into(), json!(true));
    });
    assert!(verify_token(&explicit_true).is_ok());
}

#[test]
fn the_grant_window_bounds_authority_exactly() {
    let token = token_with(|_| {});

    // The window is inclusive at both ends against broker time.
    let mut at_start = rule();
    at_start.not_before_unix = NOW_SECS;
    assert!(verify_with_rule(&at_start, &token).is_ok());
    let mut not_yet = rule();
    not_yet.not_before_unix = NOW_SECS + 1;
    not_yet.expires_at_unix = NOW_SECS + 300;
    assert_eq!(
        verify_with_rule(&not_yet, &token),
        Err(FederationError::ProviderRejected)
    );

    let mut at_expiry = rule();
    at_expiry.not_before_unix = NOW_SECS - 60;
    at_expiry.expires_at_unix = NOW_SECS;
    assert!(verify_with_rule(&at_expiry, &token).is_ok());
    let mut expired = rule();
    expired.not_before_unix = NOW_SECS - 120;
    expired.expires_at_unix = NOW_SECS - 1;
    assert_eq!(
        verify_with_rule(&expired, &token),
        Err(FederationError::ProviderRejected)
    );
}

#[test]
fn grant_lifetime_is_capped_at_fifteen_minutes() {
    // The maximum span is exactly 900 seconds; one more fails the rule
    // itself, so no token can be verified against an over-long grant.
    let token = token_with(|_| {});
    let mut at_cap = rule();
    at_cap.not_before_unix = NOW_SECS - 60;
    at_cap.expires_at_unix = NOW_SECS - 60 + 900;
    assert!(verify_with_rule(&at_cap, &token).is_ok());

    let mut over_cap = rule();
    over_cap.not_before_unix = NOW_SECS - 60;
    over_cap.expires_at_unix = NOW_SECS - 60 + 901;
    assert_eq!(
        verify_with_rule(&over_cap, &token),
        Err(FederationError::ProviderRejected)
    );

    let mut inverted = rule();
    inverted.not_before_unix = NOW_SECS + 10;
    inverted.expires_at_unix = NOW_SECS + 10;
    assert_eq!(
        verify_with_rule(&inverted, &token),
        Err(FederationError::ProviderRejected)
    );
}

#[test]
fn rule_shape_is_validated_before_any_token_is_trusted() {
    let token = token_with(|_| {});

    // The issuer must be the instance's Actions API root.
    let mut wrong_issuer_path = rule();
    wrong_issuer_path.issuer = "https://forge.example.com/oidc".to_string();
    assert_eq!(
        verify_with_rule(&wrong_issuer_path, &token),
        Err(FederationError::ProviderRejected)
    );

    // The ref type is closed and must be consistent with the ref.
    let mut tag_type_branch_ref = rule();
    tag_type_branch_ref.ref_type = "tag".to_string();
    assert_eq!(
        verify_with_rule(&tag_type_branch_ref, &token),
        Err(FederationError::ProviderRejected)
    );
    let mut unknown_type = rule();
    unknown_type.ref_type = "commit".to_string();
    assert_eq!(
        verify_with_rule(&unknown_type, &token),
        Err(FederationError::ProviderRejected)
    );

    // The pinned commit is exact lowercase hex, 40 or 64 digits.
    for sha in ["A".repeat(40), "a".repeat(39), "g".repeat(40)] {
        let mut bad_sha = rule();
        bad_sha.sha = sha;
        assert_eq!(
            verify_with_rule(&bad_sha, &token),
            Err(FederationError::ProviderRejected)
        );
    }

    // Zero run identity or repository identity never validates.
    let mut zero_run = rule();
    zero_run.run_id = 0;
    assert_eq!(
        verify_with_rule(&zero_run, &token),
        Err(FederationError::ProviderRejected)
    );
    let mut zero_attempt = rule();
    zero_attempt.run_attempt = 0;
    assert_eq!(
        verify_with_rule(&zero_attempt, &token),
        Err(FederationError::ProviderRejected)
    );
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
    let expired_within_skew = token_with(|c| {
        c.insert("iat".into(), json!(NOW_SECS - 200));
        c.insert("exp".into(), json!(NOW_SECS - SKEW));
    });
    assert!(verify_token(&expired_within_skew).is_ok());
    let expired_past_skew = token_with(|c| {
        c.insert("iat".into(), json!(NOW_SECS - 200));
        c.insert("exp".into(), json!(NOW_SECS - SKEW - 1));
    });
    assert_eq!(
        verify_token(&expired_past_skew),
        Err(FederationError::ProviderRejected)
    );

    // `nbf` is optional; when present it is bounded by the same skew.
    let nbf_past_boundary = token_with(|c| {
        c.insert("nbf".into(), json!(NOW_SECS + SKEW + 1));
    });
    assert_eq!(
        verify_token(&nbf_past_boundary),
        Err(FederationError::ProviderRejected)
    );

    // Token age is bounded independently of the grant window.
    let too_old = token_with(|c| {
        c.insert("iat".into(), json!(NOW_SECS - MAX_AGE - 1));
    });
    assert_eq!(
        verify_token(&too_old),
        Err(FederationError::ProviderRejected)
    );
}

#[test]
fn issuer_audience_and_proof_key_binding_fail_closed() {
    let wrong_issuer = token_with(|c| {
        c.insert("iss".into(), json!("https://other.example.com/api/actions"));
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
        verify_forgejo(&rule(), &jwks(), &token, &[8; 32], &correlation(), now()),
        Err(FederationError::TokenRejected)
    );

    let empty_jti = token_with(|c| {
        c.insert("jti".into(), json!(""));
    });
    assert_eq!(
        verify_token(&empty_jti),
        Err(FederationError::ProviderRejected)
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
