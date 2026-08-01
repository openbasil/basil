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
const MAX_RULE_ID_BYTES: usize = 128;
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_AUDIENCE_BYTES: usize = 256;
const MAX_OPERATION_PROFILES: usize = 32;
const MIN_RSA_MODULUS_BYTES: usize = 256;
const MAX_RSA_MODULUS_BYTES: usize = 512;

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
    /// Maximum clock skew allowed for `iat`, `nbf`, and `exp`.
    pub clock_skew_secs: u64,
}

/// The provider families understood by this closed federation interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderKind {
    /// GitHub Actions OIDC.
    GithubActions,
}

/// A typed provider rule in the trusted federation catalog.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRule {
    /// Stable operator-selected rule identifier.
    pub id: String,
    /// Fixed Basil subject granted by this rule.
    pub subject: String,
    /// Broker audience accepted by this rule.
    pub audience: String,
    /// Typed operation profiles enabled by this rule.
    pub operation_profiles: Vec<String>,
    /// Maximum accepted token age in seconds for this rule.
    pub max_token_age_secs: u64,
    /// Allowed clock skew in seconds for this rule.
    pub clock_skew_secs: u64,
    /// Provider-specific configuration.
    pub provider: ProviderConfig,
}

/// Closed provider-specific configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ProviderConfig {
    /// GitHub Actions configuration.
    GithubActions(GithubActionsRule),
}

impl ProviderConfig {
    /// Return the closed provider kind without consulting token claims.
    #[must_use]
    pub const fn kind(&self) -> ProviderKind {
        match self {
            Self::GithubActions(_) => ProviderKind::GithubActions,
        }
    }

    const fn github(&self) -> &GithubActionsRule {
        match self {
            Self::GithubActions(rule) => rule,
        }
    }
}

/// A trusted, validated catalog of provider rules.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct ProviderCatalog {
    rules: Vec<ProviderRule>,
}

impl<'de> Deserialize<'de> for ProviderCatalog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let rules = Vec::<ProviderRule>::deserialize(deserializer)?;
        Self::new(rules).map_err(serde::de::Error::custom)
    }
}

/// Typed evidence used to select one GitHub provider rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubSelection<'a> {
    /// Stable numeric repository ID from the verified token.
    pub repository_id: u64,
    /// Stable numeric owner ID from the verified token.
    pub repository_owner_id: u64,
    /// Exact reusable workflow identity from the verified token.
    pub workflow_ref: &'a str,
    /// Exact workflow commit from the verified token.
    pub workflow_sha: &'a str,
    /// Protected ref or tag from the verified token.
    pub ref_name: &'a str,
    /// Event name from the verified token.
    pub event_name: &'a str,
    /// Runner environment from the verified token.
    pub runner_environment: &'a str,
}

/// One unambiguous selected provider rule.
#[derive(Debug, Clone, Copy)]
pub struct SelectedProvider<'a> {
    /// The catalog rule selected by trusted typed evidence.
    pub rule: &'a ProviderRule,
}

impl ProviderCatalog {
    /// Validate and construct a catalog before it can be used for selection.
    pub fn new(rules: Vec<ProviderRule>) -> Result<Self, FederationError> {
        let mut ids = std::collections::BTreeSet::new();
        for rule in &rules {
            validate_common_rule(rule)?;
            if !ids.insert(rule.id.as_str()) {
                return Err(FederationError::DuplicateRuleId);
            }
            let github = rule.provider.github();
            validate_github_rule(github)?;
            validate_urls(&github.issuer, &github.discovery_url, &github.jwks_url)?;
            if rule.max_token_age_secs != github.max_token_age_secs
                || rule.clock_skew_secs != github.clock_skew_secs
            {
                return Err(FederationError::ProviderRejected);
            }
        }
        for (index, left) in rules.iter().enumerate() {
            for right in rules.iter().skip(index + 1) {
                if rules_overlap(left, right) {
                    return Err(FederationError::OverlappingRules);
                }
            }
        }
        Ok(Self { rules })
    }

    /// Return the validated rules in deterministic catalog order.
    #[must_use]
    pub fn rules(&self) -> &[ProviderRule] {
        &self.rules
    }

    /// Select exactly one GitHub rule from already typed and verified evidence.
    pub fn select_github(
        &self,
        selection: &GithubSelection<'_>,
    ) -> Result<SelectedProvider<'_>, FederationError> {
        let mut matches = self.rules.iter().filter(|rule| {
            let github = rule.provider.github();
            let repository_matches = github.repository_id == selection.repository_id
                && github.repository_owner_id == selection.repository_owner_id;
            let workflow_matches = github.job_workflow_ref == selection.workflow_ref
                && github.job_workflow_sha == selection.workflow_sha;
            repository_matches
                && workflow_matches
                && github
                    .protected_refs
                    .iter()
                    .any(|value| value == selection.ref_name)
                && github
                    .events
                    .iter()
                    .any(|value| value == selection.event_name)
                && github
                    .runner_environments
                    .iter()
                    .any(|value| value == selection.runner_environment)
        });
        let Some(rule) = matches.next() else {
            return Err(FederationError::NoMatchingRule);
        };
        if matches.next().is_some() {
            return Err(FederationError::AmbiguousRule);
        }
        Ok(SelectedProvider { rule })
    }
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
    nbf: Option<u64>,
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
            validate_rsa_jwk(&jwk)?;
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
    /// Two catalog rules used the same trusted identifier.
    #[error("duplicate provider rule ID")]
    DuplicateRuleId,
    /// Two catalog rules could authorize the same typed evidence.
    #[error("overlapping provider rules")]
    OverlappingRules,
    /// No trusted rule matched the typed evidence.
    #[error("no provider rule matched")]
    NoMatchingRule,
    /// More than one trusted rule matched the typed evidence.
    #[error("ambiguous provider rule selection")]
    AmbiguousRule,
}

fn validate_common_rule(rule: &ProviderRule) -> Result<(), FederationError> {
    if rule.id.is_empty()
        || rule.id.len() > MAX_RULE_ID_BYTES
        || rule.subject.is_empty()
        || rule.subject.len() > MAX_SUBJECT_BYTES
        || rule.audience.is_empty()
        || rule.audience.len() > MAX_AUDIENCE_BYTES
        || rule.operation_profiles.is_empty()
        || rule.operation_profiles.len() > MAX_OPERATION_PROFILES
        || rule.max_token_age_secs == 0
        || rule.max_token_age_secs > 15 * 60
        || rule.clock_skew_secs > 5 * 60
    {
        return Err(FederationError::ProviderRejected);
    }
    let mut profiles = std::collections::BTreeSet::new();
    for profile in &rule.operation_profiles {
        if profile.is_empty() || profile.len() > MAX_RULE_ID_BYTES || !profiles.insert(profile) {
            return Err(FederationError::ProviderRejected);
        }
    }
    Ok(())
}

fn rules_overlap(left: &ProviderRule, right: &ProviderRule) -> bool {
    if left.provider.kind() != right.provider.kind() {
        return false;
    }
    let left = left.provider.github();
    let right = right.provider.github();
    left.repository_id == right.repository_id
        && left.repository_owner_id == right.repository_owner_id
        && left.job_workflow_ref == right.job_workflow_ref
        && left.job_workflow_sha == right.job_workflow_sha
        && left
            .protected_refs
            .iter()
            .any(|value| right.protected_refs.iter().any(|other| other == value))
        && left
            .events
            .iter()
            .any(|value| right.events.iter().any(|other| other == value))
        && left
            .runner_environments
            .iter()
            .any(|value| right.runner_environments.iter().any(|other| other == value))
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

fn validate_rsa_jwk(jwk: &RsaJwk) -> Result<(), FederationError> {
    let modulus = URL_SAFE_NO_PAD
        .decode(&jwk.n)
        .map_err(|_| FederationError::InvalidKey)?;
    let exponent = URL_SAFE_NO_PAD
        .decode(&jwk.e)
        .map_err(|_| FederationError::InvalidKey)?;
    if !(MIN_RSA_MODULUS_BYTES..=MAX_RSA_MODULUS_BYTES).contains(&modulus.len())
        || modulus.first().is_none_or(|byte| byte & 0x80 == 0)
        || exponent != [1, 0, 1]
    {
        return Err(FederationError::InvalidKey);
    }
    Ok(())
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

/// Return the RFC 7638 thumbprint (`jkt`) for an Ed25519 proof key.
#[must_use]
pub fn proof_key_kid(public_key: &[u8; 32]) -> String {
    thumbprint(public_key)
}

/// Decode the only `COSE_Key` shape accepted for a remote proof key.
///
/// The input must be deterministic CBOR for exactly `{1: 1, -1: 6, -2: x}`;
/// unknown members, alternate encodings, and wrong key sizes are rejected.
pub fn decode_proof_key_cose(bytes: &[u8]) -> Result<[u8; 32], FederationError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let Some(length) = decoder.map().map_err(|_| FederationError::Malformed)? else {
        return Err(FederationError::Malformed);
    };
    if length != 3 {
        return Err(FederationError::InvalidKey);
    }
    let mut key_type = None;
    let mut curve = None;
    let mut public = None;
    let mut previous = None;
    for _ in 0..length {
        let label = decoder.i64().map_err(|_| FederationError::Malformed)?;
        let order = |value: i64| {
            if value >= 0 {
                (0_u8, value.cast_unsigned())
            } else {
                (1_u8, !value.cast_unsigned())
            }
        };
        if previous.is_some_and(|prior| order(label) <= order(prior)) {
            return Err(FederationError::Malformed);
        }
        previous = Some(label);
        match label {
            1 => key_type = Some(decoder.i64().map_err(|_| FederationError::Malformed)?),
            -1 => curve = Some(decoder.i64().map_err(|_| FederationError::Malformed)?),
            -2 => {
                let value = decoder.bytes().map_err(|_| FederationError::Malformed)?;
                public = Some(value.to_vec());
            }
            _ => return Err(FederationError::InvalidKey),
        }
    }
    if decoder.position() != bytes.len() {
        return Err(FederationError::Malformed);
    }
    if key_type != Some(1) || curve != Some(6) {
        return Err(FederationError::InvalidKey);
    }
    public
        .ok_or(FederationError::InvalidKey)?
        .try_into()
        .map_err(|_| FederationError::InvalidKey)
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
        || claims.repository.is_empty()
        || decimal(&claims.repository_id)? != rule.repository_id
        || decimal(&claims.repository_owner_id)? != rule.repository_owner_id
        || claims.exp < claims.iat
        || claims.iat > now_secs.saturating_add(rule.clock_skew_secs)
        || claims
            .nbf
            .is_some_and(|nbf| nbf > now_secs.saturating_add(rule.clock_skew_secs))
        || claims.exp.saturating_add(rule.clock_skew_secs) < now_secs
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
        || rule.clock_skew_secs > 5 * 60
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

    fn github_rule(id: &str, refs: &[&str], events: &[&str]) -> ProviderRule {
        ProviderRule {
            id: id.to_string(),
            subject: "ci/release".to_string(),
            audience: "urn:basil:ci".to_string(),
            operation_profiles: vec!["artifact-sign".to_string()],
            max_token_age_secs: 900,
            clock_skew_secs: 30,
            provider: ProviderConfig::GithubActions(GithubActionsRule {
                issuer: GITHUB_ISSUER.to_string(),
                discovery_url: format!("{GITHUB_ISSUER}/.well-known/openid-configuration"),
                jwks_url: format!("{GITHUB_ISSUER}/.well-known/jwks"),
                audience_prefix: "urn:basil:ci:jkt:".to_string(),
                repository_id: 42,
                repository_owner_id: 7,
                job_workflow_ref: "openbasil/basil/.github/workflows/release.yml@refs/heads/main"
                    .to_string(),
                job_workflow_sha: "a".repeat(40),
                protected_refs: refs.iter().map(ToString::to_string).collect(),
                events: events.iter().map(ToString::to_string).collect(),
                runner_environments: vec!["github-hosted".to_string()],
                max_token_age_secs: 900,
                clock_skew_secs: 30,
            }),
        }
    }

    #[test]
    fn proof_audience_is_rfc7638_thumbprint() {
        let audience = proof_audience(&[7; 32]);
        assert_eq!(audience.len(), "urn:basil:ci:jkt:".len() + 43);
        assert!(audience.starts_with("urn:basil:ci:jkt:"));
    }

    #[test]
    fn proof_key_decoder_rejects_substitution_and_noncanonical_shapes() {
        let mut canonical = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut canonical);
        encoder
            .map(3)
            .unwrap()
            .i64(1)
            .unwrap()
            .i64(1)
            .unwrap()
            .i64(-1)
            .unwrap()
            .i64(6)
            .unwrap()
            .i64(-2)
            .unwrap()
            .bytes(&[7; 32])
            .unwrap();
        assert_eq!(decode_proof_key_cose(&canonical), Ok([7; 32]));

        let mut substituted = canonical.clone();
        substituted.pop();
        assert!(matches!(
            decode_proof_key_cose(&substituted),
            Err(FederationError::Malformed | FederationError::InvalidKey)
        ));

        let mut unknown = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut unknown);
        encoder.map(4).unwrap();
        encoder.i64(1).unwrap().i64(1).unwrap();
        encoder.i64(-1).unwrap().i64(6).unwrap();
        encoder.i64(-2).unwrap().bytes(&[7; 32]).unwrap();
        encoder.i64(-3).unwrap().i64(0).unwrap();
        assert!(matches!(
            decode_proof_key_cose(&unknown),
            Err(FederationError::InvalidKey)
        ));
    }

    #[test]
    fn jwks_rejects_duplicate_and_wrong_metadata() {
        let modulus = URL_SAFE_NO_PAD.encode([0x80; 256]);
        let duplicate = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB"}},{{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB"}}]}}"#
        );
        assert!(matches!(
            GenerationJwks::parse(1, duplicate.as_bytes()),
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

    #[test]
    fn catalog_selects_one_exact_typed_rule() {
        let catalog = ProviderCatalog::new(vec![github_rule("release", &["main"], &["push"])])
            .expect("valid catalog");
        let selected = catalog
            .select_github(&GithubSelection {
                repository_id: 42,
                repository_owner_id: 7,
                workflow_ref: "openbasil/basil/.github/workflows/release.yml@refs/heads/main",
                workflow_sha: &"a".repeat(40),
                ref_name: "main",
                event_name: "push",
                runner_environment: "github-hosted",
            })
            .expect("exact rule selected");
        assert_eq!(selected.rule.id, "release");
    }

    #[test]
    fn catalog_denies_no_match_and_near_miss() {
        let catalog = ProviderCatalog::new(vec![github_rule("release", &["main"], &["push"])])
            .expect("valid catalog");
        let near_miss = GithubSelection {
            repository_id: 42,
            repository_owner_id: 7,
            workflow_ref: "openbasil/basil/.github/workflows/release.yml@refs/heads/main",
            workflow_sha: &"b".repeat(40),
            ref_name: "main",
            event_name: "push",
            runner_environment: "github-hosted",
        };
        assert!(matches!(
            catalog.select_github(&near_miss),
            Err(FederationError::NoMatchingRule)
        ));
    }

    #[test]
    fn catalog_denies_duplicate_and_overlapping_rules() {
        let duplicate_id = ProviderCatalog::new(vec![
            github_rule("same", &["main"], &["push"]),
            github_rule("same", &["tag"], &["push"]),
        ]);
        assert!(matches!(
            duplicate_id,
            Err(FederationError::DuplicateRuleId)
        ));

        let overlap = ProviderCatalog::new(vec![
            github_rule("one", &["main", "tag"], &["push"]),
            github_rule("two", &["tag"], &["push", "workflow_dispatch"]),
        ]);
        assert!(matches!(overlap, Err(FederationError::OverlappingRules)));
    }

    #[test]
    fn catalog_allows_disjoint_rules_but_never_unions_them() {
        let catalog = ProviderCatalog::new(vec![
            github_rule("push", &["main"], &["push"]),
            github_rule("dispatch", &["main"], &["workflow_dispatch"]),
        ])
        .expect("disjoint rules");
        assert_eq!(catalog.rules().len(), 2);
        let unknown = GithubSelection {
            repository_id: 42,
            repository_owner_id: 7,
            workflow_ref: "openbasil/basil/.github/workflows/release.yml@refs/heads/main",
            workflow_sha: &"a".repeat(40),
            ref_name: "main",
            event_name: "schedule",
            runner_environment: "github-hosted",
        };
        assert!(matches!(
            catalog.select_github(&unknown),
            Err(FederationError::NoMatchingRule)
        ));
    }
}
