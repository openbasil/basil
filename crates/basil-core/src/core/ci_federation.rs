// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Closed provider-specific evidence for CI workload federation.
//!
//! This module deliberately does not deserialize provider claims into a map.
//! The provider, issuer, key locations, and claim selectors are trusted
//! configuration; the token supplies evidence only.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

const MAX_TOKEN_BYTES: usize = 32 * 1024;
const MAX_CLAIM_BYTES: usize = 8 * 1024;
const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Trusted configuration for one GitHub Actions identity rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GithubActionsRule {
    /// Exact issuer URL.
    pub issuer: String,
    /// Exact discovery URL.
    pub discovery_url: String,
    /// Exact JWKS URL.
    pub jwks_url: String,
    /// The proof-bound Basil audience prefix.
    pub audience_prefix: String,
    /// Exact repository ID.
    pub repository_id: u64,
    /// Exact repository owner ID.
    pub repository_owner_id: u64,
    /// Exact workflow identity (`job_workflow_ref`).
    pub job_workflow_ref: String,
    /// Exact workflow commit (`job_workflow_sha`).
    pub job_workflow_sha: String,
    /// Allowed protected refs.
    pub protected_refs: Vec<String>,
    /// Allowed GitHub event names.
    pub events: Vec<String>,
    /// Allowed runner environments.
    pub runner_environments: Vec<String>,
    /// Maximum accepted token age in seconds.
    pub max_token_age_secs: u64,
}

/// A validated, typed GitHub Actions certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubEvidence {
    /// Stable numeric repository ID.
    pub repository_id: u64,
    /// Stable numeric owner ID.
    pub repository_owner_id: u64,
    /// Source repository name, for audit context only.
    pub repository: String,
    /// Actor ID, for audit correlation only.
    pub actor_id: Option<u64>,
    /// Exact workflow identity.
    pub workflow_ref: String,
    /// Exact workflow commit.
    pub workflow_sha: String,
    /// Protected ref or tag.
    pub ref_name: String,
    /// Provider event.
    pub event_name: String,
    /// Runner trust class.
    pub runner_environment: String,
    /// Required non-empty GitHub token ID.
    pub jti_digest: [u8; 32],
    /// Keyed-independent token correlation digest (never the raw token).
    pub token_digest: [u8; 32],
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct GithubClaims {
    iss: String,
    aud: String,
    sub: String,
    repository: String,
    repository_id: String,
    repository_owner_id: String,
    actor_id: Option<String>,
    event_name: String,
    #[serde(rename = "ref")]
    ref_field: String,
    job_workflow_ref: String,
    job_workflow_sha: String,
    runner_environment: String,
    jti: String,
    iat: u64,
    exp: u64,
}

/// A single RSA key accepted from a configured provider JWKS.
#[derive(Debug, Clone)]
pub struct RsaJwk {
    /// Key identifier.
    pub kid: String,
    /// Base64url RSA modulus.
    pub n: String,
    /// Base64url RSA exponent.
    pub e: String,
}

/// Generation-owned verified key material. It must never be shared across a
/// reload, even when issuer and key IDs happen to be unchanged.
#[derive(Debug, Clone)]
pub struct GenerationJwks {
    generation: u64,
    keys: BTreeMap<String, RsaJwk>,
}

impl GenerationJwks {
    /// Parse a strict RSA signing JWKS for one immutable serving generation.
    pub fn parse(generation: u64, body: &[u8]) -> Result<Self, FederationError> {
        if body.len() > MAX_CLAIM_BYTES {
            return Err(FederationError::Oversized("JWKS"));
        }
        let root: Value = serde_json::from_slice(body).map_err(|_| FederationError::Malformed)?;
        let keys = root
            .as_object()
            .and_then(|o| o.get("keys"))
            .and_then(Value::as_array)
            .ok_or(FederationError::Malformed)?;
        let mut out = BTreeMap::new();
        for key in keys {
            let object = key.as_object().ok_or(FederationError::Malformed)?;
            let allowed = ["kty", "kid", "alg", "use", "key_ops", "n", "e"];
            if object.keys().any(|name| !allowed.contains(&name.as_str()))
                || object.get("kty").and_then(Value::as_str) != Some("RSA")
                || object.get("alg").and_then(Value::as_str) != Some("RS256")
                || object.get("use").and_then(Value::as_str) != Some("sig")
            {
                return Err(FederationError::InvalidKey);
            }
            if let Some(ops) = object.get("key_ops")
                && !ops.as_array().is_some_and(|values| {
                    values.len() == 1 && values.first().and_then(Value::as_str) == Some("verify")
                })
            {
                return Err(FederationError::InvalidKey);
            }
            let kid = string_field(object, "kid")?;
            let jwk = RsaJwk {
                kid: kid.clone(),
                n: string_field(object, "n")?,
                e: string_field(object, "e")?,
            };
            if out.insert(kid, jwk).is_some() {
                return Err(FederationError::DuplicateKid);
            }
        }
        Ok(Self {
            generation,
            keys: out,
        })
    }

    /// Return the key only if it belongs to this generation's exact JWKS.
    #[must_use]
    pub fn key(&self, kid: &str) -> Option<&RsaJwk> {
        self.keys.get(kid)
    }

    /// Return the immutable generation identifier.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Errors from closed CI federation parsing and verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FederationError {
    /// A bounded input exceeded its protocol limit.
    #[error("oversized {0}")]
    Oversized(&'static str),
    /// Input was not the exact supported shape.
    #[error("malformed federation input")]
    Malformed,
    /// Provider configuration or claims selected the wrong provider.
    #[error("provider identity rejected")]
    ProviderRejected,
    /// The configured key set contained a duplicate ID.
    #[error("duplicate JWKS key ID")]
    DuplicateKid,
    /// A key was not an RS256 verification key.
    #[error("invalid JWKS key")]
    InvalidKey,
    /// JWT cryptographic or temporal verification failed.
    #[error("token verification failed")]
    TokenRejected,
    /// Configuration URL validation failed.
    #[error("invalid provider URL")]
    InvalidUrl,
}

fn string_field(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<String, FederationError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .ok_or(FederationError::Malformed)
}

fn decimal(value: &str) -> Result<u64, FederationError> {
    (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
        .ok_or(FederationError::Malformed)
}

fn thumbprint(public_key: &[u8]) -> String {
    let jwk = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(public_key)
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.as_bytes()))
}

/// Construct the only audience accepted for an ephemeral Ed25519 proof key.
#[must_use]
pub fn proof_audience(public_key: &[u8; 32]) -> String {
    format!("urn:basil:ci:jkt:{}", thumbprint(public_key))
}

/// Verify a GitHub Actions token against one trusted rule and one generation's
/// isolated JWKS cache.
pub fn verify_github(
    rule: &GithubActionsRule,
    jwks: &GenerationJwks,
    token: &str,
    proof_public_key: &[u8; 32],
    now: SystemTime,
) -> Result<GithubEvidence, FederationError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(FederationError::Oversized("token"));
    }
    validate_github_rule(rule)?;
    validate_urls(&rule.issuer, &rule.discovery_url, &rule.jwks_url)?;
    let header = decode_header(token).map_err(|_| FederationError::TokenRejected)?;
    if header.alg != Algorithm::RS256 {
        return Err(FederationError::TokenRejected);
    }
    let kid = header.kid.ok_or(FederationError::TokenRejected)?;
    let key = jwks.key(&kid).ok_or(FederationError::TokenRejected)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[proof_audience(proof_public_key)]);
    validation.set_issuer(&[rule.issuer.as_str()]);
    let data = decode::<Value>(
        token,
        &DecodingKey::from_rsa_components(&key.n, &key.e)
            .map_err(|_| FederationError::TokenRejected)?,
        &validation,
    )
    .map_err(|_| FederationError::TokenRejected)?;
    let claims: GithubClaims =
        serde_json::from_value(data.claims).map_err(|_| FederationError::TokenRejected)?;
    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FederationError::TokenRejected)?
        .as_secs();
    if claims.iss != rule.issuer
        || claims.aud != proof_audience(proof_public_key)
        || claims.sub.is_empty()
        || decimal(&claims.repository_id)? != rule.repository_id
        || decimal(&claims.repository_owner_id)? != rule.repository_owner_id
        || claims.exp < claims.iat
        || now_secs.saturating_sub(claims.iat) > rule.max_token_age_secs
        || !rule.protected_refs.iter().any(|v| v == &claims.ref_field)
        || !rule.events.iter().any(|v| v == &claims.event_name)
        || !rule
            .runner_environments
            .iter()
            .any(|v| v == &claims.runner_environment)
        || claims.job_workflow_ref != rule.job_workflow_ref
        || claims.job_workflow_sha != rule.job_workflow_sha
    {
        return Err(FederationError::ProviderRejected);
    }
    let jti = (!claims.jti.is_empty())
        .then(|| Sha256::digest(claims.jti.as_bytes()).into())
        .ok_or(FederationError::ProviderRejected)?;
    Ok(GithubEvidence {
        repository_id: decimal(&claims.repository_id)?,
        repository_owner_id: decimal(&claims.repository_owner_id)?,
        repository: claims.repository,
        actor_id: claims.actor_id.as_deref().map(decimal).transpose()?,
        workflow_ref: claims.job_workflow_ref,
        workflow_sha: claims.job_workflow_sha,
        ref_name: claims.ref_field,
        event_name: claims.event_name,
        runner_environment: claims.runner_environment,
        jti_digest: jti,
        token_digest: Sha256::digest(token.as_bytes()).into(),
    })
}

fn validate_github_rule(rule: &GithubActionsRule) -> Result<(), FederationError> {
    if rule.issuer != GITHUB_ISSUER
        || rule.audience_prefix != "urn:basil:ci:jkt:"
        || rule.repository_id == 0
        || rule.repository_owner_id == 0
        || rule.job_workflow_ref.is_empty()
        || rule.job_workflow_sha.is_empty()
        || rule.protected_refs.is_empty()
        || rule.events.is_empty()
        || rule.runner_environments.is_empty()
        || rule.max_token_age_secs == 0
        || rule.max_token_age_secs > 15 * 60
    {
        return Err(FederationError::ProviderRejected);
    }
    Ok(())
}

fn validate_urls(issuer: &str, discovery: &str, jwks: &str) -> Result<(), FederationError> {
    let issuer_url = Url::parse(issuer).map_err(|_| FederationError::InvalidUrl)?;
    let discovery_url = Url::parse(discovery).map_err(|_| FederationError::InvalidUrl)?;
    let jwks_url = Url::parse(jwks).map_err(|_| FederationError::InvalidUrl)?;
    if [&issuer_url, &discovery_url, &jwks_url].iter().any(|url| {
        url.scheme() != "https"
            || url.username() != ""
            || url.query().is_some()
            || url.fragment().is_some()
    }) || issuer_url.origin() != discovery_url.origin()
        || discovery_url.origin() != jwks_url.origin()
        || issuer.trim_end_matches('/') != issuer_url.as_str().trim_end_matches('/')
    {
        return Err(FederationError::InvalidUrl);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_audience_is_rfc7638_thumbprint() {
        let audience = proof_audience(&[7; 32]);
        assert_eq!(audience.len(), "urn:basil:ci:jkt:".len() + 43);
        assert!(audience.starts_with("urn:basil:ci:jkt:"));
    }

    #[test]
    fn jwks_rejects_duplicate_and_wrong_metadata() {
        let duplicate = br#"{"keys":[{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"n","e":"e"},{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"n","e":"e"}]}"#;
        assert!(matches!(
            GenerationJwks::parse(1, duplicate),
            Err(FederationError::DuplicateKid)
        ));
        let wrong =
            br#"{"keys":[{"kty":"EC","kid":"a","alg":"ES256","use":"sig","n":"n","e":"e"}]}"#;
        assert!(matches!(
            GenerationJwks::parse(1, wrong),
            Err(FederationError::InvalidKey)
        ));
    }

    #[test]
    fn generation_is_part_of_cache_identity() {
        let body = br#"{"keys":[]}"#;
        assert_ne!(
            GenerationJwks::parse(1, body).unwrap().generation(),
            GenerationJwks::parse(2, body).unwrap().generation()
        );
    }
}
