// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Closed provider-specific evidence for CI workload federation.
//!
//! This module deliberately does not deserialize provider claims into a map.
//! The provider, issuer, key locations, and claim selectors are trusted
//! configuration; the token supplies evidence only.

// The freshness-challenge table lives beside this module as
// `core/challenge.rs`; it is mounted here (rather than in `core/mod.rs`) so
// the whole challenge subsystem stays within the CI-federation ownership
// boundary. Public path: `crate::ci_federation::challenge`.
#[path = "challenge.rs"]
pub mod challenge;

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::digest::KeyInit as _;
use hmac::{Hmac, Mac as _};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const MAX_TOKEN_BYTES: usize = 32 * 1024;
const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
/// Forgejo issues Actions tokens from the instance's Actions API root.
const FORGEJO_ISSUER_PATH: &str = "/api/actions";
/// The only event a `forgejoActions` rule can authorize.
const FORGEJO_EVENT: &str = "push";
/// Upper bound on a Forgejo run-specific grant window (15 minutes).
const MAX_FORGEJO_GRANT_SECS: u64 = 15 * 60;
const MAX_RULE_ID_BYTES: usize = 128;
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_AUDIENCE_BYTES: usize = 256;
const MAX_OPERATION_PROFILES: usize = 32;
const MIN_RSA_MODULUS_BYTES: usize = 256;
const MAX_RSA_MODULUS_BYTES: usize = 512;
/// GitHub's production JWKS carries `x5c` certificate chains per key and is
/// above 5 KiB before any rotation overlap; 64 KiB bounds the fetch while
/// leaving headroom for overlapping key sets.
const MAX_JWKS_BODY_BYTES: usize = 64 * 1024;

/// The only redirect behavior accepted by the federation fetch boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// Reject redirects so configured endpoint identity remains exact.
    Reject,
}

/// Bounds and outage behavior for one provider cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwksCachePolicy {
    /// Maximum response body size for either discovery or JWKS.
    pub max_body_bytes: usize,
    /// Minimum interval between refresh attempts for an unknown key ID.
    pub refresh_cooldown: Duration,
    /// Positive freshness window: maximum age of a fetched key set before a
    /// cached (known) key ID must revalidate against the provider. Rotating a
    /// key out of the provider JWKS is the provider's only revocation
    /// mechanism, so this bounds how long a revoked key keeps verifying.
    pub max_age: Duration,
    /// Grace beyond `max_age` during which the existing key set may still
    /// serve while revalidation fails or is cooldown-gated (fetch outage).
    pub stale_if_error: Duration,
    /// Redirect behavior enforced for every fetched document.
    pub redirect_policy: RedirectPolicy,
}

impl Default for JwksCachePolicy {
    fn default() -> Self {
        Self {
            max_body_bytes: MAX_JWKS_BODY_BYTES,
            refresh_cooldown: Duration::from_secs(1),
            // Five minutes (`Duration::from_mins` needs 1.91; MSRV is 1.88).
            max_age: Duration::from_secs(300),
            stale_if_error: Duration::from_secs(30),
            redirect_policy: RedirectPolicy::Reject,
        }
    }
}

/// A response supplied by a provider document fetcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedDocument {
    /// URL reached by the request.
    pub url: Url,
    /// HTTP status code.
    pub status: u16,
    /// Whether the HTTP client followed a redirect.
    pub redirected: bool,
    /// Response body, bounded again by the cache before parsing.
    pub body: Vec<u8>,
}

/// Construct a typed response for the cache boundary.
impl FetchedDocument {
    pub fn new(
        url: &str,
        status: u16,
        redirected: bool,
        body: Vec<u8>,
    ) -> Result<Self, FederationError> {
        let url = Url::parse(url).map_err(|_| FederationError::InvalidUrl)?;
        if url.scheme() != "https"
            || url.username() != ""
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(FederationError::InvalidUrl);
        }
        Ok(Self {
            url,
            status,
            redirected,
            body,
        })
    }
}

/// Minimal provider fetch contract. Network clients remain outside this module.
pub trait ProviderDocumentFetcher {
    /// Fetch one exact configured HTTPS endpoint.
    fn fetch(
        &mut self,
        url: &Url,
        max_body_bytes: usize,
    ) -> Result<FetchedDocument, FederationError>;
}

/// Result of refreshing a generation-owned key set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// A newly fetched key set is active.
    Fresh,
    /// The previous key set remains active inside its outage grace period.
    Stale,
}

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
    /// Optional exact protected deployment environment.
    #[serde(default)]
    pub environment: Option<String>,
    /// Maximum accepted token age in seconds.
    pub max_token_age_secs: u64,
    /// Maximum clock skew allowed for `iat`, `nbf`, and `exp`.
    pub clock_skew_secs: u64,
}

/// Trusted configuration for one Forgejo Actions identity rule.
///
/// The tier is experimental: the token cannot attest runner identity,
/// executor isolation, or repository protection, so what remains as
/// authorization evidence is this operator-installed run-specific grant. The
/// rule explicitly trusts the configured Forgejo server and its scheduler.
/// The supported event is closed to `push`; environment, reusable-workflow,
/// and `ref_protected` selectors do not exist in this schema, and tokens
/// presenting environment or reusable-callee authority are denied.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ForgejoActionsRule {
    /// Exact issuer URL (`https://<instance>/api/actions`).
    pub issuer: String,
    /// Exact discovery URL on the issuer's origin.
    pub discovery_url: String,
    /// Exact JWKS URL on the issuer's origin.
    pub jwks_url: String,
    /// The proof-bound Basil audience prefix.
    pub audience_prefix: String,
    /// Exact numeric repository ID.
    pub repository_id: u64,
    /// Exact numeric repository owner ID.
    pub repository_owner_id: u64,
    /// Exact same-repository workflow identity (`workflow_ref`).
    pub workflow_ref: String,
    /// Exact triggering ref (`refs/heads/...` or `refs/tags/...`).
    #[serde(rename = "ref")]
    pub ref_name: String,
    /// Exact ref type (`branch` or `tag`), consistent with `ref`.
    pub ref_type: String,
    /// Exact triggering commit (40 or 64 lowercase hex).
    pub sha: String,
    /// Exact run ID the grant authorizes.
    pub run_id: u64,
    /// Exact run attempt; a rerun increments it and needs another grant.
    pub run_attempt: u64,
    /// Grant start (Unix seconds); the operator installs the grant after the
    /// run and attempt IDs are known.
    pub not_before_unix: u64,
    /// Grant expiry (Unix seconds), at most 15 minutes after the start.
    pub expires_at_unix: u64,
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
    /// Forgejo Actions OIDC (experimental tier).
    ForgejoActions,
}

impl ProviderKind {
    /// The configuration spelling of this provider kind.
    #[must_use]
    pub const fn config_name(self) -> &'static str {
        match self {
            Self::GithubActions => "githubActions",
            Self::ForgejoActions => "forgejoActions",
        }
    }

    /// Whether this provider sits in the experimental support tier.
    ///
    /// An experimental provider is outside the security guarantees and must
    /// be unreachable by accident: a catalog holding one loads only when the
    /// operator names it in the explicit experimental opt-in.
    #[must_use]
    pub const fn is_experimental(self) -> bool {
        match self {
            Self::GithubActions => false,
            Self::ForgejoActions => true,
        }
    }
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
    /// Per-run operation quota (SPEC: Per-run quota and kill switch): the
    /// number of typed operations this rule admits per
    /// `(rule, run_id, run_attempt)` before the broker denies with the
    /// retryable-never `PER_RUN_QUOTA_EXCEEDED` status.
    ///
    /// The value is required and must be at least 1; there is no unlimited
    /// default. It deserializes as optional only so catalog validation can
    /// reject an absent value with a diagnostic naming the rule: every rule
    /// inside a constructed [`ProviderCatalog`] carries a nonzero value, and
    /// quota enforcement fails closed (denies) if the value is somehow
    /// absent.
    #[serde(default)]
    pub max_operations_per_run: Option<u64>,
    /// Provider-specific configuration.
    pub provider: ProviderConfig,
}

/// Closed provider-specific configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ProviderConfig {
    /// GitHub Actions configuration.
    GithubActions(GithubActionsRule),
    /// Forgejo Actions configuration (experimental tier).
    ForgejoActions(ForgejoActionsRule),
}

impl ProviderConfig {
    /// Return the closed provider kind without consulting token claims.
    #[must_use]
    pub const fn kind(&self) -> ProviderKind {
        match self {
            Self::GithubActions(_) => ProviderKind::GithubActions,
            Self::ForgejoActions(_) => ProviderKind::ForgejoActions,
        }
    }

    /// Exact configured issuer URL.
    #[must_use]
    pub fn issuer(&self) -> &str {
        match self {
            Self::GithubActions(rule) => &rule.issuer,
            Self::ForgejoActions(rule) => &rule.issuer,
        }
    }

    /// Exact configured discovery URL.
    #[must_use]
    pub fn discovery_url(&self) -> &str {
        match self {
            Self::GithubActions(rule) => &rule.discovery_url,
            Self::ForgejoActions(rule) => &rule.discovery_url,
        }
    }

    /// Exact configured JWKS URL.
    #[must_use]
    pub fn jwks_url(&self) -> &str {
        match self {
            Self::GithubActions(rule) => &rule.jwks_url,
            Self::ForgejoActions(rule) => &rule.jwks_url,
        }
    }

    /// Validate the provider-specific rule and its endpoint URLs.
    pub fn validate(&self) -> Result<(), FederationError> {
        match self {
            Self::GithubActions(rule) => validate_github_rule(rule)?,
            Self::ForgejoActions(rule) => validate_forgejo_rule(rule)?,
        }
        validate_urls(self.issuer(), self.discovery_url(), self.jwks_url())
    }

    const fn rule_time_bounds(&self) -> (u64, u64) {
        match self {
            Self::GithubActions(rule) => (rule.max_token_age_secs, rule.clock_skew_secs),
            Self::ForgejoActions(rule) => (rule.max_token_age_secs, rule.clock_skew_secs),
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
    /// Protected deployment environment from the verified token.
    pub environment: Option<&'a str>,
}

/// Typed evidence used to select one Forgejo provider rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgejoSelection<'a> {
    /// Stable numeric repository ID from the verified token.
    pub repository_id: u64,
    /// Stable numeric owner ID from the verified token.
    pub repository_owner_id: u64,
    /// Exact same-repository workflow identity from the verified token.
    pub workflow_ref: &'a str,
    /// Exact triggering ref from the verified token.
    pub ref_name: &'a str,
    /// Exact ref type from the verified token.
    pub ref_type: &'a str,
    /// Exact triggering commit from the verified token.
    pub sha: &'a str,
    /// Exact run ID from the verified token.
    pub run_id: u64,
    /// Exact run attempt from the verified token.
    pub run_attempt: u64,
}

/// One unambiguous selected provider rule.
#[derive(Debug, Clone, Copy)]
pub struct SelectedProvider<'a> {
    /// The catalog rule selected by trusted typed evidence.
    pub rule: &'a ProviderRule,
}

impl ProviderCatalog {
    /// Validate and construct a catalog with no experimental tier opt-in.
    ///
    /// Any experimental-tier rule fails catalog construction with an error
    /// naming the tier; [`Self::with_experimental_providers`] is the only way
    /// to load one, so an operator cannot arrive at an experimental
    /// authorization anchor by copying an example.
    pub fn new(rules: Vec<ProviderRule>) -> Result<Self, FederationError> {
        Self::with_experimental_providers(rules, &[])
    }

    /// Validate and construct a catalog with an explicit experimental opt-in.
    ///
    /// `experimental` holds the provider kinds the operator explicitly named
    /// in the `experimentalProviders` configuration; a supported-tier kind in
    /// the list is ignored.
    pub fn with_experimental_providers(
        rules: Vec<ProviderRule>,
        experimental: &[ProviderKind],
    ) -> Result<Self, FederationError> {
        let mut ids = std::collections::BTreeSet::new();
        for rule in &rules {
            validate_common_rule(rule)?;
            if !ids.insert(rule.id.as_str()) {
                return Err(FederationError::DuplicateRuleId);
            }
            let kind = rule.provider.kind();
            if kind.is_experimental() && !experimental.contains(&kind) {
                return Err(FederationError::ExperimentalProviderDisabled(
                    kind.config_name(),
                ));
            }
            rule.provider.validate()?;
            let (max_token_age_secs, clock_skew_secs) = rule.provider.rule_time_bounds();
            if rule.max_token_age_secs != max_token_age_secs
                || rule.clock_skew_secs != clock_skew_secs
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
        let matches = self.rules.iter().filter(|rule| {
            let ProviderConfig::GithubActions(github) = &rule.provider else {
                return false;
            };
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
                && github.environment.as_deref() == selection.environment
        });
        exactly_one(matches)
    }

    /// Select exactly one Forgejo rule from already typed and verified evidence.
    pub fn select_forgejo(
        &self,
        selection: &ForgejoSelection<'_>,
    ) -> Result<SelectedProvider<'_>, FederationError> {
        let matches = self.rules.iter().filter(|rule| {
            let ProviderConfig::ForgejoActions(forgejo) = &rule.provider else {
                return false;
            };
            forgejo.repository_id == selection.repository_id
                && forgejo.repository_owner_id == selection.repository_owner_id
                && forgejo.workflow_ref == selection.workflow_ref
                && forgejo.ref_name == selection.ref_name
                && forgejo.ref_type == selection.ref_type
                && forgejo.sha == selection.sha
                && forgejo.run_id == selection.run_id
                && forgejo.run_attempt == selection.run_attempt
        });
        exactly_one(matches)
    }
}

fn exactly_one<'a>(
    mut matches: impl Iterator<Item = &'a ProviderRule>,
) -> Result<SelectedProvider<'a>, FederationError> {
    let Some(rule) = matches.next() else {
        return Err(FederationError::NoMatchingRule);
    };
    if matches.next().is_some() {
        return Err(FederationError::AmbiguousRule);
    }
    Ok(SelectedProvider { rule })
}

/// Broker-local secret keying the token and `jti` correlation digests.
///
/// The audit correlation identity of a verified token is a keyed digest so an
/// observer holding a raw token cannot confirm it against audit records. The
/// key never leaves broker memory and is zeroized on drop; a fresh random key
/// per broker process is sufficient, because correlation is only meaningful
/// within one audit stream.
#[derive(Clone)]
pub struct TokenCorrelationKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for TokenCorrelationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenCorrelationKey")
            .finish_non_exhaustive()
    }
}

impl TokenCorrelationKey {
    /// Wrap broker-local key bytes for correlation digests.
    ///
    /// Takes already-`Zeroizing` bytes so generating callers never hold an
    /// un-scrubbed copy of the key material.
    #[must_use]
    pub const fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self(key)
    }

    /// Domain-separated keyed digest: `HMAC-SHA256(key, len(domain) || domain || data)`.
    ///
    /// HMAC accepts any key length, so the error arm is unreachable for the
    /// fixed 32-byte key; it still fails closed instead of panicking.
    fn digest(&self, domain: &str, data: &[u8]) -> Result<[u8; 32], FederationError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_slice())
            .map_err(|_| FederationError::CorrelationUnavailable)?;
        let domain_length = u8::try_from(domain.len()).unwrap_or(u8::MAX);
        mac.update(&[domain_length]);
        mac.update(domain.as_bytes());
        mac.update(data);
        Ok(mac.finalize().into_bytes().into())
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
    /// Protected deployment environment, when configured.
    pub environment: Option<String>,
    /// Provider-attested run ID: half of the per-run quota partition.
    pub run_id: u64,
    /// Provider-attested run attempt; a rerun increments it and opens a
    /// fresh per-run quota bucket.
    pub run_attempt: u64,
    /// Keyed digest of the required non-empty GitHub token ID.
    pub jti_digest: [u8; 32],
    /// Keyed token correlation digest (never the raw token).
    pub token_digest: [u8; 32],
}

/// A validated, typed Forgejo Actions certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgejoEvidence {
    /// Stable numeric repository ID.
    pub repository_id: u64,
    /// Stable numeric owner ID.
    pub repository_owner_id: u64,
    /// Source repository name, for audit context only.
    pub repository: String,
    /// Actor ID, for audit correlation only.
    pub actor_id: Option<u64>,
    /// Exact same-repository workflow identity.
    pub workflow_ref: String,
    /// Exact triggering ref.
    pub ref_name: String,
    /// Exact ref type.
    pub ref_type: String,
    /// Exact triggering commit.
    pub sha: String,
    /// Exact run ID.
    pub run_id: u64,
    /// Exact run attempt.
    pub run_attempt: u64,
    /// The (closed) provider event, always `push`.
    pub event_name: String,
    /// Keyed digest of the required non-empty token ID.
    pub jti_digest: [u8; 32],
    /// Keyed token correlation digest (never the raw token).
    pub token_digest: [u8; 32],
}

/// Closed provider-specific verified claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderClaimEvidence {
    /// Verified GitHub Actions claims.
    GithubActions(GithubEvidence),
    /// Verified Forgejo Actions claims (experimental tier).
    ForgejoActions(ForgejoEvidence),
}

impl ProviderClaimEvidence {
    /// Keyed token correlation digest (never the raw token).
    #[must_use]
    pub const fn token_digest(&self) -> &[u8; 32] {
        match self {
            Self::GithubActions(evidence) => &evidence.token_digest,
            Self::ForgejoActions(evidence) => &evidence.token_digest,
        }
    }

    /// Keyed digest of the provider token ID.
    #[must_use]
    pub const fn jti_digest(&self) -> &[u8; 32] {
        match self {
            Self::GithubActions(evidence) => &evidence.jti_digest,
            Self::ForgejoActions(evidence) => &evidence.jti_digest,
        }
    }

    /// Provider-attested run ID: half of the per-run quota partition.
    #[must_use]
    pub const fn run_id(&self) -> u64 {
        match self {
            Self::GithubActions(evidence) => evidence.run_id,
            Self::ForgejoActions(evidence) => evidence.run_id,
        }
    }

    /// Provider-attested run attempt: the other half of the per-run quota
    /// partition; a rerun increments it and opens a fresh bucket.
    #[must_use]
    pub const fn run_attempt(&self) -> u64 {
        match self {
            Self::GithubActions(evidence) => evidence.run_attempt,
            Self::ForgejoActions(evidence) => evidence.run_attempt,
        }
    }
}

/// Verified provider evidence attached to one sealed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProviderEvidence {
    /// Provider family selected by trusted configuration.
    pub provider: ProviderKind,
    /// Stable configured rule identifier.
    pub rule_id: String,
    /// Policy subject granted by the rule.
    pub subject: String,
    /// The selected rule's per-run operation quota
    /// ([`ProviderRule::max_operations_per_run`]); catalog validation
    /// guarantees a loaded rule carries a nonzero value, and quota
    /// enforcement fails closed (denies) when it is absent.
    pub max_operations_per_run: Option<u64>,
    /// Retention window in seconds for this rule's per-run quota buckets:
    /// the rule's `max_token_age_secs + clock_skew_secs`. A bucket idle
    /// beyond this window holds no state a currently-valid token could
    /// still charge against under the same freshness bounds, so the table
    /// may reclaim it under pressure (see [`RunQuotaTable`]).
    pub run_bucket_retention_secs: u64,
    /// Provider-specific verified claims.
    pub claims: ProviderClaimEvidence,
}

/// Default per-rule bound on distinct tracked per-run quota buckets.
///
/// The bound is **per rule**, not global: one federated tenant opening many
/// run buckets can exhaust only its own rule's allowance and never denies
/// runs under other rules. When a rule's allowance is full, the table first
/// reclaims buckets whose retention window has lapsed; only if none can be
/// reclaimed is the new run denied (as the retryable
/// [`RunQuotaDenied::Untracked`]) rather than evicting live quota state,
/// because an evicted-then-recreated bucket would restart its counter and
/// re-admit past an exhausted quota. Operators can tune the bound with the
/// `invocation.run-quota-buckets-per-rule` configuration knob.
pub const DEFAULT_MAX_TRACKED_RUN_BUCKETS_PER_RULE: usize = 4096;

/// Identity of one per-run operation-quota bucket (SPEC: Per-run quota and
/// kill switch): one rule and one provider-attested workflow run attempt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RunQuotaKey {
    /// Stable catalog rule identifier.
    pub rule_id: String,
    /// Provider-attested run ID.
    pub run_id: u64,
    /// Provider-attested run attempt; a rerun increments it and opens a
    /// fresh bucket.
    pub run_attempt: u64,
}

/// Why a per-run quota charge was denied.
///
/// [`Exhausted`](Self::Exhausted) and
/// [`QuotaUnavailable`](Self::QuotaUnavailable) surface as the sealed
/// retryable-never `PER_RUN_QUOTA_EXCEEDED` status (genuine quota
/// exhaustion / fail-closed). [`Untracked`](Self::Untracked) is table
/// pressure, not exhaustion: it surfaces as a **retryable** sealed status
/// (reason `RUN_QUOTA_UNTRACKED`) so a legitimate run denied by unrelated
/// pressure retries after the pressure drains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RunQuotaDenied {
    /// The bucket reached the rule's per-run operation quota.
    #[error("per-run operation quota exhausted")]
    Exhausted,
    /// The selected rule carries no usable quota value; enforcement fails
    /// closed. Catalog validation makes this unreachable for a loaded rule.
    #[error("per-run operation quota unavailable for the selected rule")]
    QuotaUnavailable,
    /// The rule's bounded bucket allowance cannot track a new run without
    /// evicting live quota state, which would re-open exhausted buckets.
    /// Retryable: expired buckets are reclaimed on later charges.
    #[error("per-run quota bucket allowance for the rule is full")]
    Untracked,
}

/// One tracked per-run quota bucket: the admitted count and the unix time
/// past which the bucket may be reclaimed under table pressure.
#[derive(Debug, Clone, Copy)]
struct RunQuotaBucket {
    count: u64,
    expires_at_unix: i64,
}

/// Bounded in-memory per-run operation counters (SPEC: Per-run quota and
/// kill switch).
///
/// **Bound.** The table bounds distinct `(rule, run_id, run_attempt)`
/// buckets **per rule** (`max_tracked_buckets_per_rule`), so one federated
/// tenant opening many attested runs can exhaust only its own rule's
/// allowance and never denies runs under other rules.
///
/// **Retention.** Every bucket carries an expiry refreshed to `now +
/// retention` on each verified charge attempt for its key, where retention
/// is the rule's `max_token_age_secs + clock_skew_secs`. A bucket idle past
/// its expiry has seen no verified token activity for longer than any token
/// admitted under the rule's freshness bounds stays chargeable, so it is
/// reclaimed when its rule's allowance is under pressure. A run attempt
/// that idles past retention and later returns with a freshly minted token
/// opens a new bucket — the quota bounds each activity window of a run
/// attempt, the deliberate trade for bounded memory without permanent
/// denial (recorded on basil-jjgi.3.4).
///
/// **Generation scope.** Counters are cleared only when a charge arrives
/// under a **newer** serving generation than the one tracked (generation
/// ids are monotonic), so a reload resets the quota — stated behavior,
/// because the quota bounds a compromised job inside a normal window and
/// does not survive an agent restart either (the table is process memory).
/// A slow in-flight request still pinned to the previous generation charges
/// into the current counters instead of wiping them, so old/new generation
/// interleavings cannot alternate resets (fail-closed: at worst it
/// over-counts). Kill-switch semantics ride the existing generation
/// pinning: a generation installed without the rule stops new requests from
/// authenticating against it at verification, before any charge.
///
/// Every mutating operation takes `&mut self`; the caller serializes access
/// behind one mutex (no await points held), which is what makes concurrent
/// charges against one bucket admit at most the configured quota.
#[derive(Debug)]
pub struct RunQuotaTable {
    max_tracked_buckets_per_rule: usize,
    generation: Option<u64>,
    counters: HashMap<RunQuotaKey, RunQuotaBucket>,
    /// Distinct tracked buckets per rule id; kept in lockstep with
    /// `counters` so the per-rule bound check is O(1).
    rule_buckets: HashMap<String, usize>,
}

impl RunQuotaTable {
    /// Build an empty table bounded to `max_tracked_buckets_per_rule`
    /// distinct `(run_id, run_attempt)` buckets for each rule.
    #[must_use]
    pub fn new(max_tracked_buckets_per_rule: usize) -> Self {
        Self {
            max_tracked_buckets_per_rule,
            generation: None,
            counters: HashMap::new(),
            rule_buckets: HashMap::new(),
        }
    }

    /// Charge one typed operation against `key` under the pinned serving
    /// `generation`, admitting at most `limit` operations per bucket.
    ///
    /// `limit` is the selected rule's
    /// [`ProviderRule::max_operations_per_run`]; `None` (which catalog
    /// validation makes unreachable for a loaded rule) fails closed.
    /// `retention_secs` is the rule's `max_token_age_secs +
    /// clock_skew_secs` ([`VerifiedProviderEvidence::run_bucket_retention_secs`])
    /// and `now_unix` the broker's current time. A denied charge does not
    /// consume quota, but any charge attempt against an existing bucket
    /// refreshes its retention expiry: verified token activity proves the
    /// run attempt is still live, keeping an exhausted bucket exhausted.
    ///
    /// # Errors
    /// [`RunQuotaDenied::Exhausted`] / [`RunQuotaDenied::QuotaUnavailable`]
    /// surface as the sealed retryable-never `PER_RUN_QUOTA_EXCEEDED`
    /// status; [`RunQuotaDenied::Untracked`] (the rule's bucket allowance is
    /// full and nothing has expired) surfaces as a retryable sealed status.
    pub fn charge(
        &mut self,
        generation: u64,
        key: &RunQuotaKey,
        limit: Option<u64>,
        retention_secs: u64,
        now_unix: i64,
    ) -> Result<(), RunQuotaDenied> {
        let Some(limit) = limit else {
            return Err(RunQuotaDenied::QuotaUnavailable);
        };
        if limit == 0 {
            return Err(RunQuotaDenied::Exhausted);
        }
        match self.generation {
            Some(tracked) if generation > tracked => {
                // Generation scope: a charge under a newer serving
                // generation resets the counters (reload resets the quota,
                // stated behavior). Charges from an older pinned generation
                // fall through and count against the current counters
                // instead of wiping them.
                self.counters.clear();
                self.rule_buckets.clear();
                self.generation = Some(generation);
            }
            Some(_) => {}
            None => self.generation = Some(generation),
        }
        let expires_at_unix =
            now_unix.saturating_add(i64::try_from(retention_secs).unwrap_or(i64::MAX));
        if let Some(bucket) = self.counters.get_mut(key) {
            // Verified activity: the run attempt is provably still live, so
            // its bucket (exhausted or not) stays retained.
            bucket.expires_at_unix = bucket.expires_at_unix.max(expires_at_unix);
            if bucket.count >= limit {
                return Err(RunQuotaDenied::Exhausted);
            }
            bucket.count = bucket.count.saturating_add(1);
            return Ok(());
        }
        if self
            .rule_buckets
            .get(key.rule_id.as_str())
            .copied()
            .unwrap_or(0)
            >= self.max_tracked_buckets_per_rule
        {
            self.reclaim_expired(now_unix);
            if self
                .rule_buckets
                .get(key.rule_id.as_str())
                .copied()
                .unwrap_or(0)
                >= self.max_tracked_buckets_per_rule
            {
                return Err(RunQuotaDenied::Untracked);
            }
        }
        self.counters.insert(
            key.clone(),
            RunQuotaBucket {
                count: 1,
                expires_at_unix,
            },
        );
        *self.rule_buckets.entry(key.rule_id.clone()).or_insert(0) += 1;
        Ok(())
    }

    /// Drop every bucket whose retention expiry has lapsed. Called only
    /// under allowance pressure; the common charge path stays O(1).
    fn reclaim_expired(&mut self, now_unix: i64) {
        let expired: Vec<RunQuotaKey> = self
            .counters
            .iter()
            .filter(|(_, bucket)| bucket.expires_at_unix <= now_unix)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            self.counters.remove(&key);
            if let Some(count) = self.rule_buckets.get_mut(key.rule_id.as_str()) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.rule_buckets.remove(key.rule_id.as_str());
                }
            }
        }
    }
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
    environment: Option<String>,
    /// Required: the per-run quota (SPEC: Per-run quota and kill switch) is
    /// partitioned by `(rule, run_id, run_attempt)`, so a token that does
    /// not attest its run identity is rejected.
    run_id: String,
    run_attempt: String,
    jti: String,
    iat: u64,
    nbf: Option<u64>,
    exp: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct ForgejoClaims {
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
    ref_type: String,
    sha: String,
    workflow_ref: String,
    run_id: String,
    run_attempt: String,
    /// Forgejo publishes no environment identity; presence denies.
    environment: Option<Value>,
    /// Forgejo publishes no reusable-callee identity; presence denies.
    job_workflow_ref: Option<Value>,
    /// Forgejo publishes no reusable-callee identity; presence denies.
    job_workflow_sha: Option<Value>,
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
        if body.len() > MAX_JWKS_BODY_BYTES {
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
            // `x5c`, `x5t`, and `x5t#S256` appear in GitHub's production JWKS.
            // They are tolerated so the real document parses, and ignored:
            // verification uses only the checked RSA components below.
            let allowed = [
                "kty", "kid", "alg", "use", "key_ops", "n", "e", "x5c", "x5t", "x5t#S256",
            ];
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

/// Serving-path decision for one presented key ID against a generation cache.
#[derive(Debug)]
pub enum ServeDecision {
    /// The key ID is cached and the set is within its freshness window.
    Fresh(GenerationJwks),
    /// The key ID is cached but the set exceeded `max_age`: revalidate.
    Revalidate {
        /// Whether the cooldown admitted (and recorded) a refresh attempt.
        refresh_allowed: bool,
        /// The stale set, present only within the bounded stale window.
        stale: Option<GenerationJwks>,
    },
    /// The key ID is not in the cached set (or the cache is empty).
    UnknownKid {
        /// Whether the cooldown admitted (and recorded) a refresh attempt.
        refresh_allowed: bool,
    },
}

/// One immutable-generation discovery/JWKS cache.
///
/// The cache owns its key set and is intentionally not shared between
/// generations. A caller may retain the old cache while a reload is serving
/// it, but a new cache always starts empty.
#[derive(Debug)]
pub struct GenerationJwksCache {
    generation: u64,
    discovery_url: Url,
    jwks_url: Url,
    policy: JwksCachePolicy,
    keys: Option<GenerationJwks>,
    fetched_at: Option<SystemTime>,
    last_refresh_attempt: Option<SystemTime>,
}

impl GenerationJwksCache {
    /// Create an empty cache after validating the configured provider URLs.
    pub fn new(
        generation: u64,
        provider: &ProviderConfig,
        policy: JwksCachePolicy,
    ) -> Result<Self, FederationError> {
        provider.validate()?;
        if policy.max_body_bytes == 0 || policy.max_body_bytes > MAX_JWKS_BODY_BYTES {
            return Err(FederationError::InvalidCachePolicy);
        }
        Ok(Self {
            generation,
            discovery_url: Url::parse(provider.discovery_url())
                .map_err(|_| FederationError::InvalidUrl)?,
            jwks_url: Url::parse(provider.jwks_url()).map_err(|_| FederationError::InvalidUrl)?,
            policy,
            keys: None,
            fetched_at: None,
            last_refresh_attempt: None,
        })
    }

    /// Return the generation that owns this cache.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Decide whether an unknown key ID is allowed to trigger a fetch.
    #[must_use]
    pub fn should_refresh_on_unknown_kid(&self, now: SystemTime) -> bool {
        self.last_refresh_attempt.is_none_or(|attempt| {
            now.duration_since(attempt)
                .is_ok_and(|elapsed| elapsed >= self.policy.refresh_cooldown)
        })
    }

    /// Gate a refresh performed outside this cache (an async fetch): if the
    /// cooldown permits a refresh now, record the attempt and return `true`.
    ///
    /// Callers that fetch with their own client must call this before the
    /// fetch so an unknown key ID causes at most one bounded refresh per
    /// cooldown window, and a failed fetch still consumes the attempt.
    pub fn try_begin_refresh(&mut self, now: SystemTime) -> bool {
        if !self.should_refresh_on_unknown_kid(now) {
            return false;
        }
        self.last_refresh_attempt = Some(now);
        true
    }

    /// Refresh discovery and JWKS, retaining boundedly stale keys on outage.
    pub fn refresh<F: ProviderDocumentFetcher>(
        &mut self,
        fetcher: &mut F,
        now: SystemTime,
    ) -> Result<RefreshOutcome, FederationError> {
        self.last_refresh_attempt = Some(now);
        let result = self.fetch_and_parse(fetcher);
        match result {
            Ok(keys) => {
                self.keys = Some(keys);
                self.fetched_at = Some(now);
                Ok(RefreshOutcome::Fresh)
            }
            Err(_error) if self.keys_within_stale_window(now) => Ok(RefreshOutcome::Stale),
            Err(error) => Err(error),
        }
    }

    /// Resolve a key, making at most one refresh attempt for an unknown ID.
    pub fn key_or_refresh<F: ProviderDocumentFetcher>(
        &mut self,
        kid: &str,
        fetcher: &mut F,
        now: SystemTime,
    ) -> Result<Option<RsaJwk>, FederationError> {
        if let Some(key) = self.keys.as_ref().and_then(|keys| keys.key(kid)) {
            return Ok(Some(key.clone()));
        }
        if self.should_refresh_on_unknown_kid(now) {
            let _ = self.refresh(fetcher, now)?;
        }
        Ok(self.keys.as_ref().and_then(|keys| keys.key(kid)).cloned())
    }

    /// Return a cached key without changing refresh state.
    #[must_use]
    pub fn cached_key(&self, kid: &str) -> Option<RsaJwk> {
        self.keys.as_ref().and_then(|keys| keys.key(kid)).cloned()
    }

    /// Return the complete cached key set for verification, when present.
    #[must_use]
    pub fn cached_keys(&self) -> Option<GenerationJwks> {
        self.keys.clone()
    }

    /// Install a freshly fetched key set for this generation.
    pub fn install(&mut self, keys: GenerationJwks, now: SystemTime) {
        self.keys = Some(keys);
        self.fetched_at = Some(now);
    }

    /// Decide how the serving path may use this cache for one presented key ID.
    ///
    /// A cached key ID serves directly only while the set is within its
    /// positive freshness window (`max_age`). Past it, the caller must
    /// revalidate through the cooldown gate, and may serve the stale set only
    /// within `max_age + stale_if_error` of the last successful fetch — so a
    /// key the provider rotates out of its JWKS stops verifying within a
    /// bounded interval instead of persisting for the generation lifetime.
    /// Any admitted refresh attempt is recorded here, before the fetch, so a
    /// failed fetch still consumes the attempt.
    pub fn serve_or_revalidate(&mut self, kid: &str, now: SystemTime) -> ServeDecision {
        match self.cached_keys() {
            Some(keys) if keys.key(kid).is_some() => {
                if self.keys_are_fresh(now) {
                    return ServeDecision::Fresh(keys);
                }
                let refresh_allowed = self.try_begin_refresh(now);
                let stale = self.keys_within_stale_window(now).then_some(keys);
                ServeDecision::Revalidate {
                    refresh_allowed,
                    stale,
                }
            }
            _ => ServeDecision::UnknownKid {
                refresh_allowed: self.try_begin_refresh(now),
            },
        }
    }

    fn keys_are_fresh(&self, now: SystemTime) -> bool {
        self.keys.is_some()
            && self.fetched_at.is_some_and(|fetched| {
                now.duration_since(fetched)
                    .is_ok_and(|age| age <= self.policy.max_age)
            })
    }

    fn keys_within_stale_window(&self, now: SystemTime) -> bool {
        self.keys.is_some()
            && self.fetched_at.is_some_and(|fetched| {
                now.duration_since(fetched).is_ok_and(|age| {
                    age <= self
                        .policy
                        .max_age
                        .saturating_add(self.policy.stale_if_error)
                })
            })
    }

    fn fetch_and_parse<F: ProviderDocumentFetcher>(
        &self,
        fetcher: &mut F,
    ) -> Result<GenerationJwks, FederationError> {
        let discovery = self.fetch_document(fetcher, &self.discovery_url)?;
        let discovery_json: Value =
            serde_json::from_slice(&discovery.body).map_err(|_| FederationError::Malformed)?;
        let discovered_jwks = discovery_json
            .as_object()
            .and_then(|object| object.get("jwks_uri"))
            .and_then(Value::as_str)
            .ok_or(FederationError::Malformed)?;
        let discovered_jwks =
            Url::parse(discovered_jwks).map_err(|_| FederationError::InvalidUrl)?;
        if discovered_jwks != self.jwks_url {
            return Err(FederationError::InvalidUrl);
        }
        let jwks = self.fetch_document(fetcher, &self.jwks_url)?;
        GenerationJwks::parse(self.generation, &jwks.body)
    }

    fn fetch_document<F: ProviderDocumentFetcher>(
        &self,
        fetcher: &mut F,
        expected: &Url,
    ) -> Result<FetchedDocument, FederationError> {
        let response = fetcher.fetch(expected, self.policy.max_body_bytes)?;
        if response.url != *expected {
            return Err(FederationError::InvalidUrl);
        }
        if response.redirected && self.policy.redirect_policy == RedirectPolicy::Reject {
            return Err(FederationError::RedirectRejected);
        }
        if response.body.len() > self.policy.max_body_bytes {
            return Err(FederationError::Oversized("provider document"));
        }
        if !(200..300).contains(&response.status) {
            return Err(FederationError::FetchRejected);
        }
        Ok(response)
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
    /// A provider document exceeded the configured cache bounds.
    #[error("invalid JWKS cache policy")]
    InvalidCachePolicy,
    /// A provider fetch followed a forbidden redirect.
    #[error("provider redirect rejected")]
    RedirectRejected,
    /// A provider document returned a non-success status.
    #[error("provider fetch rejected")]
    FetchRejected,
    /// An experimental-tier provider rule was configured without the
    /// explicit tier opt-in.
    #[error(
        "provider {0} is in the experimental tier: outside the security guarantees, and loadable only when named in the `experimentalProviders` opt-in"
    )]
    ExperimentalProviderDisabled(&'static str),
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
    /// The broker-local correlation digest could not be computed.
    #[error("correlation digest unavailable")]
    CorrelationUnavailable,
    /// A provider rule was configured without its per-run operation quota.
    #[error(
        "provider rule `{0}` is missing `maxOperationsPerRun`: every rule must declare a per-run operation quota, and there is no unlimited default"
    )]
    MissingRunQuota(String),
    /// A provider rule declared a per-run operation quota of zero.
    #[error(
        "provider rule `{0}` declares `maxOperationsPerRun` 0: the per-run operation quota must be at least 1"
    )]
    InvalidRunQuota(String),
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
    // The per-run quota is validated after the identifier bounds above, so
    // this named diagnostic always carries a sane rule ID.
    match rule.max_operations_per_run {
        None => return Err(FederationError::MissingRunQuota(rule.id.clone())),
        Some(0) => return Err(FederationError::InvalidRunQuota(rule.id.clone())),
        Some(_) => {}
    }
    Ok(())
}

fn rules_overlap(left: &ProviderRule, right: &ProviderRule) -> bool {
    match (&left.provider, &right.provider) {
        (ProviderConfig::GithubActions(left), ProviderConfig::GithubActions(right)) => {
            github_rules_overlap(left, right)
        }
        (ProviderConfig::ForgejoActions(left), ProviderConfig::ForgejoActions(right)) => {
            forgejo_rules_overlap(left, right)
        }
        _ => false,
    }
}

/// Two Forgejo grants overlap when the same verified token could satisfy
/// both exact selector sets; differing grant windows do not disambiguate,
/// so identical selectors are rejected outright.
fn forgejo_rules_overlap(left: &ForgejoActionsRule, right: &ForgejoActionsRule) -> bool {
    left.repository_id == right.repository_id
        && left.repository_owner_id == right.repository_owner_id
        && left.workflow_ref == right.workflow_ref
        && left.ref_name == right.ref_name
        && left.ref_type == right.ref_type
        && left.sha == right.sha
        && left.run_id == right.run_id
        && left.run_attempt == right.run_attempt
}

fn github_rules_overlap(left: &GithubActionsRule, right: &GithubActionsRule) -> bool {
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

fn thumbprint(public_key: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(proof_key_thumbprint(public_key))
}

/// Return the raw RFC 7638 SHA-256 thumbprint (`jkt`) bytes for an Ed25519
/// proof key: the value bound by challenge issuance and consumption.
#[must_use]
pub fn proof_key_thumbprint(public_key: &[u8; 32]) -> [u8; 32] {
    let jwk = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(public_key)
    );
    Sha256::digest(jwk.as_bytes()).into()
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
    correlation: &TokenCorrelationKey,
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
    // The rule's `clock_skew_secs` is the single time-boundary authority: the
    // library's own leeway (default 60 s) and temporal checks are disabled and
    // the explicit `iat`/`nbf`/`exp` checks below apply exactly the rule skew.
    validation.leeway = 0;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
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
        || rule.environment.as_deref() != claims.environment.as_deref()
        || claims.job_workflow_ref != rule.job_workflow_ref
        || claims.job_workflow_sha != rule.job_workflow_sha
    {
        return Err(FederationError::ProviderRejected);
    }
    if claims.jti.is_empty() {
        return Err(FederationError::ProviderRejected);
    }
    let jti = correlation.digest("basil-ci-jti", claims.jti.as_bytes())?;
    let token_digest = correlation.digest("basil-ci-token", token.as_bytes())?;
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
        environment: claims.environment,
        run_id: decimal(&claims.run_id)?,
        run_attempt: decimal(&claims.run_attempt)?,
        jti_digest: jti,
        token_digest,
    })
}

/// Verify a Forgejo Actions token against one trusted run-specific grant and
/// one generation's isolated JWKS cache.
///
/// The supported event is closed to `push` and the workflow must belong to
/// the token's own repository. Tokens presenting environment or
/// reusable-callee authority are denied; `ref_protected` carries no
/// protection meaning on Forgejo and is ignored entirely. The rule's
/// `clock_skew_secs` bounds only the token's own temporal claims; the
/// operator-installed grant window is compared exactly against broker time.
pub fn verify_forgejo(
    rule: &ForgejoActionsRule,
    jwks: &GenerationJwks,
    token: &str,
    proof_public_key: &[u8; 32],
    correlation: &TokenCorrelationKey,
    now: SystemTime,
) -> Result<ForgejoEvidence, FederationError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(FederationError::Oversized("token"));
    }
    validate_forgejo_rule(rule)?;
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
    // The rule's `clock_skew_secs` is the single time-boundary authority: the
    // library's own leeway (default 60 s) and temporal checks are disabled and
    // the explicit `iat`/`nbf`/`exp` checks below apply exactly the rule skew.
    validation.leeway = 0;
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    let data = decode::<Value>(
        token,
        &DecodingKey::from_rsa_components(&key.n, &key.e)
            .map_err(|_| FederationError::TokenRejected)?,
        &validation,
    )
    .map_err(|_| FederationError::TokenRejected)?;
    let claims: ForgejoClaims =
        serde_json::from_value(data.claims).map_err(|_| FederationError::TokenRejected)?;
    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FederationError::TokenRejected)?
        .as_secs();
    check_forgejo_claims(rule, &claims, proof_public_key, now_secs)?;
    let jti = correlation.digest("basil-ci-jti", claims.jti.as_bytes())?;
    let token_digest = correlation.digest("basil-ci-token", token.as_bytes())?;
    Ok(ForgejoEvidence {
        repository_id: decimal(&claims.repository_id)?,
        repository_owner_id: decimal(&claims.repository_owner_id)?,
        repository: claims.repository,
        actor_id: claims.actor_id.as_deref().map(decimal).transpose()?,
        workflow_ref: claims.workflow_ref,
        ref_name: claims.ref_field,
        ref_type: claims.ref_type,
        sha: claims.sha,
        run_id: decimal(&claims.run_id)?,
        run_attempt: decimal(&claims.run_attempt)?,
        event_name: claims.event_name,
        jti_digest: jti,
        token_digest,
    })
}

/// Apply the exact Forgejo selector, denial, temporal, and grant-window rules.
fn check_forgejo_claims(
    rule: &ForgejoActionsRule,
    claims: &ForgejoClaims,
    proof_public_key: &[u8; 32],
    now_secs: u64,
) -> Result<(), FederationError> {
    if claims.iss != rule.issuer
        || claims.aud != proof_audience(proof_public_key)
        || claims.sub.is_empty()
        || claims.repository.is_empty()
        || decimal(&claims.repository_id)? != rule.repository_id
        || decimal(&claims.repository_owner_id)? != rule.repository_owner_id
        || claims.event_name != FORGEJO_EVENT
        || claims.ref_field != rule.ref_name
        || claims.ref_type != rule.ref_type
        || claims.sha != rule.sha
        || claims.workflow_ref != rule.workflow_ref
        // Same-repository workflow only: the workflow identity must belong to
        // the repository the token was issued for.
        || !claims
            .workflow_ref
            .strip_prefix(claims.repository.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
        || decimal(&claims.run_id)? != rule.run_id
        || decimal(&claims.run_attempt)? != rule.run_attempt
        // Forgejo publishes no environment or reusable-callee identity, so a
        // token presenting either is not a Forgejo Actions token this rule
        // can authorize.
        || claims.environment.is_some()
        || claims.job_workflow_ref.is_some()
        || claims.job_workflow_sha.is_some()
        || claims.exp < claims.iat
        || claims.iat > now_secs.saturating_add(rule.clock_skew_secs)
        || claims
            .nbf
            .is_some_and(|nbf| nbf > now_secs.saturating_add(rule.clock_skew_secs))
        || claims.exp.saturating_add(rule.clock_skew_secs) < now_secs
        || now_secs.saturating_sub(claims.iat) > rule.max_token_age_secs
        // The operator-installed grant window, compared exactly: authority
        // exists only between `not_before_unix` and `expires_at_unix`.
        || now_secs < rule.not_before_unix
        || now_secs > rule.expires_at_unix
        || claims.jti.is_empty()
    {
        return Err(FederationError::ProviderRejected);
    }
    Ok(())
}

/// Fetch and strictly parse one configured provider JWKS for a serving generation.
///
/// Redirects are disabled at the HTTP boundary and the response URL is checked
/// again here, so endpoint identity cannot change between configuration and use.
pub async fn fetch_generation_jwks(
    client: &reqwest::Client,
    generation: u64,
    provider: &ProviderConfig,
) -> Result<GenerationJwks, FederationError> {
    provider.validate()?;
    let discovery_url =
        Url::parse(provider.discovery_url()).map_err(|_| FederationError::InvalidUrl)?;
    let jwks_url = Url::parse(provider.jwks_url()).map_err(|_| FederationError::InvalidUrl)?;
    let discovery = client
        .get(discovery_url.clone())
        .send()
        .await
        .map_err(|_| FederationError::FetchRejected)?;
    if discovery.url() != &discovery_url || !discovery.status().is_success() {
        return Err(FederationError::FetchRejected);
    }
    let discovery_body = bounded_response_body(discovery).await?;
    let discovered: Value =
        serde_json::from_slice(&discovery_body).map_err(|_| FederationError::Malformed)?;
    if discovered
        .get("jwks_uri")
        .and_then(Value::as_str)
        .and_then(|url| Url::parse(url).ok())
        != Some(jwks_url.clone())
    {
        return Err(FederationError::InvalidUrl);
    }
    let jwks = client
        .get(jwks_url.clone())
        .send()
        .await
        .map_err(|_| FederationError::FetchRejected)?;
    if jwks.url() != &jwks_url || !jwks.status().is_success() {
        return Err(FederationError::FetchRejected);
    }
    let body = bounded_response_body(jwks).await?;
    GenerationJwks::parse(generation, &body)
}

async fn bounded_response_body(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, FederationError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JWKS_BODY_BYTES as u64)
    {
        return Err(FederationError::Oversized("provider document"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| FederationError::FetchRejected)?
    {
        if chunk.len() > MAX_JWKS_BODY_BYTES.saturating_sub(body.len()) {
            return Err(FederationError::Oversized("provider document"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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

fn validate_forgejo_rule(rule: &ForgejoActionsRule) -> Result<(), FederationError> {
    let issuer_path_ok =
        Url::parse(&rule.issuer).is_ok_and(|url| url.path().ends_with(FORGEJO_ISSUER_PATH));
    let ref_consistent = match rule.ref_type.as_str() {
        "branch" => rule.ref_name.starts_with("refs/heads/"),
        "tag" => rule.ref_name.starts_with("refs/tags/"),
        _ => false,
    };
    let sha_ok = matches!(rule.sha.len(), 40 | 64)
        && rule
            .sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !issuer_path_ok
        || rule.audience_prefix != "urn:basil:ci:jkt:"
        || rule.repository_id == 0
        || rule.repository_owner_id == 0
        || rule.workflow_ref.is_empty()
        || !ref_consistent
        || !sha_ok
        || rule.run_id == 0
        || rule.run_attempt == 0
        || rule.not_before_unix >= rule.expires_at_unix
        || rule.expires_at_unix - rule.not_before_unix > MAX_FORGEJO_GRANT_SECS
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
    use serde_json::json;
    use std::collections::VecDeque;

    fn github_rule(id: &str, refs: &[&str], events: &[&str]) -> ProviderRule {
        ProviderRule {
            id: id.to_string(),
            subject: "ci/release".to_string(),
            audience: "urn:basil:ci".to_string(),
            operation_profiles: vec!["artifact-sign".to_string()],
            max_token_age_secs: 900,
            clock_skew_secs: 30,
            max_operations_per_run: Some(64),
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
                environment: None,
                max_token_age_secs: 900,
                clock_skew_secs: 30,
            }),
        }
    }

    struct FakeFetcher {
        responses: VecDeque<FetchedDocument>,
        calls: usize,
    }

    impl ProviderDocumentFetcher for FakeFetcher {
        fn fetch(
            &mut self,
            _url: &Url,
            _max_body_bytes: usize,
        ) -> Result<FetchedDocument, FederationError> {
            self.calls += 1;
            self.responses
                .pop_front()
                .ok_or(FederationError::FetchRejected)
        }
    }

    fn cache_rule() -> ProviderConfig {
        github_rule("cache", &["main"], &["push"]).provider
    }

    fn discovery(provider: &ProviderConfig) -> FetchedDocument {
        FetchedDocument::new(
            provider.discovery_url(),
            200,
            false,
            format!(r#"{{"jwks_uri":"{}"}}"#, provider.jwks_url()).into_bytes(),
        )
        .expect("valid discovery response")
    }

    fn jwks(kid: &str) -> FetchedDocument {
        let modulus = URL_SAFE_NO_PAD.encode([0x80; 256]);
        FetchedDocument::new(
            &format!("{GITHUB_ISSUER}/.well-known/jwks"),
            200,
            false,
            format!(r#"{{"keys":[{{"kty":"RSA","kid":"{kid}","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB"}}]}}"#).into_bytes(),
        )
        .expect("valid JWKS response")
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
    fn jwks_tolerates_github_x5c_members_but_rejects_unknown_members() {
        let modulus = URL_SAFE_NO_PAD.encode([0x80; 256]);
        // GitHub's production JWKS carries x5c/x5t alongside the RSA components.
        let github_shaped = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB","x5c":["MIIB"],"x5t":"thumb","x5t#S256":"thumb256"}}]}}"#
        );
        let parsed = GenerationJwks::parse(1, github_shaped.as_bytes()).expect("real-shape JWKS");
        assert!(parsed.key("a").is_some());

        let unknown_member = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"{modulus}","e":"AQAB","jku":"https://evil.example"}}]}}"#
        );
        assert!(matches!(
            GenerationJwks::parse(1, unknown_member.as_bytes()),
            Err(FederationError::InvalidKey)
        ));
    }

    #[test]
    fn jwks_rejects_rsa_components_outside_bounds() {
        let case = |n: &[u8], e: &str| {
            let n = URL_SAFE_NO_PAD.encode(n);
            let body = format!(
                r#"{{"keys":[{{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"{n}","e":"{e}"}}]}}"#
            );
            GenerationJwks::parse(1, body.as_bytes())
        };
        // 1024-bit modulus is below the floor.
        assert!(matches!(
            case(&[0x80; 128], "AQAB"),
            Err(FederationError::InvalidKey)
        ));
        // Above the 4096-bit ceiling.
        assert!(matches!(
            case(&[0x80; 513], "AQAB"),
            Err(FederationError::InvalidKey)
        ));
        // High bit clear means the declared modulus width is padded.
        assert!(matches!(
            case(&[0x7F; 256], "AQAB"),
            Err(FederationError::InvalidKey)
        ));
        // Exponent must be exactly 65537.
        assert!(matches!(
            case(&[0x80; 256], "Aw"),
            Err(FederationError::InvalidKey)
        ));
        // 4096-bit modulus with e=65537 is accepted.
        assert!(case(&[0x80; 512], "AQAB").is_ok());
    }

    #[test]
    fn oversized_jwks_body_is_rejected() {
        let mut body = br#"{"keys":[]}"#.to_vec();
        body.resize(64 * 1024 + 1, b' ');
        assert!(matches!(
            GenerationJwks::parse(1, &body),
            Err(FederationError::Oversized("JWKS"))
        ));
    }

    #[test]
    fn correlation_digests_are_keyed_and_domain_separated() {
        let key = TokenCorrelationKey::new(Zeroizing::new([1; 32]));
        let other = TokenCorrelationKey::new(Zeroizing::new([2; 32]));
        let token = b"header.payload.signature";
        let first = key.digest("basil-ci-token", token).expect("digest");
        assert_eq!(key.digest("basil-ci-token", token).expect("digest"), first);
        assert_ne!(
            other.digest("basil-ci-token", token).expect("digest"),
            first
        );
        assert_ne!(key.digest("basil-ci-jti", token).expect("digest"), first);
        assert!(!format!("{key:?}").contains('1'));
    }

    #[test]
    fn try_begin_refresh_enforces_the_cooldown_window() {
        let rule = cache_rule();
        let policy = JwksCachePolicy {
            refresh_cooldown: Duration::from_secs(10),
            ..JwksCachePolicy::default()
        };
        let mut cache = GenerationJwksCache::new(1, &rule, policy).expect("cache");
        let start = UNIX_EPOCH + Duration::from_secs(100);
        assert!(cache.try_begin_refresh(start));
        // The attempt is consumed even though no fetch succeeded.
        assert!(!cache.try_begin_refresh(start));
        assert!(!cache.try_begin_refresh(start + Duration::from_secs(9)));
        assert!(cache.try_begin_refresh(start + Duration::from_secs(10)));
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
    fn cache_is_empty_and_isolated_per_generation() {
        let rule = cache_rule();
        let mut first = GenerationJwksCache::new(1, &rule, JwksCachePolicy::default()).unwrap();
        let second = GenerationJwksCache::new(2, &rule, JwksCachePolicy::default()).unwrap();
        let mut fetcher = FakeFetcher {
            responses: VecDeque::from([discovery(&rule), jwks("first")]),
            calls: 0,
        };
        assert_eq!(
            first.refresh(&mut fetcher, UNIX_EPOCH).unwrap(),
            RefreshOutcome::Fresh
        );
        assert!(first.keys.as_ref().unwrap().key("first").is_some());
        assert!(second.keys.is_none());
        assert_ne!(first.generation(), second.generation());
    }

    #[test]
    fn installed_keys_are_available_only_from_their_generation_cache() {
        let rule = cache_rule();
        let parsed = GenerationJwks::parse(7, &jwks("kid").body).expect("valid JWKS");
        let now = UNIX_EPOCH + Duration::from_secs(7);
        let mut first =
            GenerationJwksCache::new(7, &rule, JwksCachePolicy::default()).expect("cache");
        first.install(parsed, now);
        assert!(first.cached_key("kid").is_some());
        assert_eq!(first.cached_keys().expect("keys").generation(), 7);

        let second = GenerationJwksCache::new(8, &rule, JwksCachePolicy::default()).expect("cache");
        assert!(second.cached_key("kid").is_none());
    }

    #[test]
    fn unknown_kid_refreshes_once_and_cooldown_suppresses_retry() {
        let rule = cache_rule();
        let mut cache = GenerationJwksCache::new(1, &rule, JwksCachePolicy::default()).unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(10);
        let mut fetcher = FakeFetcher {
            responses: VecDeque::from([discovery(&rule), jwks("new")]),
            calls: 0,
        };
        assert_eq!(
            cache
                .key_or_refresh("new", &mut fetcher, now)
                .unwrap()
                .unwrap()
                .kid,
            "new"
        );
        assert_eq!(fetcher.calls, 2);
        assert!(!cache.should_refresh_on_unknown_kid(now));
        assert!(
            cache
                .key_or_refresh("missing", &mut fetcher, now)
                .unwrap()
                .is_none()
        );
        assert_eq!(fetcher.calls, 2);
    }

    #[test]
    fn stale_keys_survive_only_within_outage_grace() {
        let rule = cache_rule();
        let policy = JwksCachePolicy {
            // Zero freshness so the outage grace alone bounds staleness.
            max_age: Duration::ZERO,
            stale_if_error: Duration::from_secs(5),
            ..JwksCachePolicy::default()
        };
        let mut cache = GenerationJwksCache::new(1, &rule, policy).unwrap();
        let mut fetcher = FakeFetcher {
            responses: VecDeque::from([
                discovery(&rule),
                jwks("old"),
                FetchedDocument::new(rule.discovery_url(), 503, false, Vec::new()).unwrap(),
                FetchedDocument::new(rule.discovery_url(), 503, false, Vec::new()).unwrap(),
            ]),
            calls: 0,
        };
        let start = UNIX_EPOCH + Duration::from_secs(20);
        assert_eq!(
            cache.refresh(&mut fetcher, start).unwrap(),
            RefreshOutcome::Fresh
        );
        assert_eq!(
            cache
                .refresh(&mut fetcher, start + Duration::from_secs(5))
                .unwrap(),
            RefreshOutcome::Stale
        );
        assert!(
            cache
                .refresh(&mut fetcher, start + Duration::from_secs(6))
                .is_err()
        );
    }

    #[test]
    fn serving_decision_enforces_positive_ttl_and_bounded_staleness() {
        let rule = cache_rule();
        let policy = JwksCachePolicy {
            max_age: Duration::from_secs(100),
            stale_if_error: Duration::from_secs(20),
            refresh_cooldown: Duration::from_secs(10),
            ..JwksCachePolicy::default()
        };
        let mut cache = GenerationJwksCache::new(1, &rule, policy).expect("cache");
        let parsed = GenerationJwks::parse(1, &jwks("kid").body).expect("valid JWKS");
        let fetch_time = UNIX_EPOCH + Duration::from_secs(1000);
        cache.install(parsed, fetch_time);

        // Within max_age: a cached kid serves fresh, no refresh recorded.
        let fresh_now = fetch_time + Duration::from_secs(100);
        assert!(matches!(
            cache.serve_or_revalidate("kid", fresh_now),
            ServeDecision::Fresh(_)
        ));
        assert!(cache.should_refresh_on_unknown_kid(fresh_now));

        // Past max_age but within the stale window: revalidation admitted
        // once per cooldown; the stale set stays available meanwhile.
        let stale_now = fetch_time + Duration::from_secs(110);
        match cache.serve_or_revalidate("kid", stale_now) {
            ServeDecision::Revalidate {
                refresh_allowed,
                stale,
            } => {
                assert!(refresh_allowed);
                assert!(stale.is_some());
            }
            other => panic!("expected revalidate, got {other:?}"),
        }
        match cache.serve_or_revalidate("kid", stale_now) {
            ServeDecision::Revalidate {
                refresh_allowed,
                stale,
            } => {
                assert!(!refresh_allowed, "cooldown must gate the second attempt");
                assert!(stale.is_some());
            }
            other => panic!("expected revalidate, got {other:?}"),
        }

        // Past max_age + stale_if_error: no stale serving; only a successful
        // revalidation may serve, so a revoked key fails closed boundedly.
        let expired_now = fetch_time + Duration::from_secs(121);
        match cache.serve_or_revalidate("kid", expired_now) {
            ServeDecision::Revalidate {
                refresh_allowed,
                stale,
            } => {
                assert!(refresh_allowed);
                assert!(stale.is_none(), "stale set must not outlive the window");
            }
            other => panic!("expected revalidate, got {other:?}"),
        }

        // An unknown kid records the (cooldown-gated) refresh attempt.
        let unknown_now = expired_now + Duration::from_secs(10);
        assert!(matches!(
            cache.serve_or_revalidate("other", unknown_now),
            ServeDecision::UnknownKid {
                refresh_allowed: true
            }
        ));
        assert!(matches!(
            cache.serve_or_revalidate("other", unknown_now),
            ServeDecision::UnknownKid {
                refresh_allowed: false
            }
        ));
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
                environment: None,
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
            environment: None,
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
    fn catalog_requires_a_per_run_quota_and_names_the_rule() {
        // Absent value: load fails, no unlimited default, diagnostic names
        // the rule and the missing field.
        let mut missing = github_rule("release", &["main"], &["push"]);
        missing.max_operations_per_run = None;
        let error = ProviderCatalog::new(vec![missing]).expect_err("absent quota must not load");
        assert_eq!(
            error,
            FederationError::MissingRunQuota("release".to_string())
        );
        let message = error.to_string();
        assert!(message.contains("`release`"), "{message}");
        assert!(message.contains("maxOperationsPerRun"), "{message}");

        // Zero is not a quota either.
        let mut zero = github_rule("release", &["main"], &["push"]);
        zero.max_operations_per_run = Some(0);
        let error = ProviderCatalog::new(vec![zero]).expect_err("zero quota must not load");
        assert_eq!(
            error,
            FederationError::InvalidRunQuota("release".to_string())
        );
        assert!(error.to_string().contains("`release`"), "{error}");
    }

    #[test]
    fn catalog_json_without_the_quota_field_fails_load_naming_the_rule() {
        // The configuration load path: strip `maxOperationsPerRun` from an
        // otherwise valid serialized rule and deserialize the catalog.
        let valid = serde_json::to_value(vec![github_rule("release", &["main"], &["push"])])
            .expect("rule serializes");
        let mut stripped = valid.clone();
        stripped
            .as_array_mut()
            .and_then(|rules| rules.first_mut())
            .and_then(Value::as_object_mut)
            .expect("serialized rule object")
            .remove("maxOperationsPerRun")
            .expect("field present before stripping");
        let error = serde_json::from_value::<ProviderCatalog>(stripped)
            .expect_err("catalog without the quota field must not load");
        let message = error.to_string();
        assert!(message.contains("release"), "{message}");
        assert!(message.contains("maxOperationsPerRun"), "{message}");
        // The unmodified serialization still loads.
        serde_json::from_value::<ProviderCatalog>(valid).expect("valid catalog loads");
    }

    fn quota_key(rule_id: &str, run_id: u64, run_attempt: u64) -> RunQuotaKey {
        RunQuotaKey {
            rule_id: rule_id.to_string(),
            run_id,
            run_attempt,
        }
    }

    /// Retention window used by the quota tests.
    const RETENTION: u64 = 630;
    /// Fixed "now" used by the quota tests.
    const NOW: i64 = 1_700_000_000;

    #[test]
    fn run_quota_admits_the_limit_then_denies_without_consuming() {
        let mut table = RunQuotaTable::new(16);
        let key = quota_key("release", 900, 1);
        for _ in 0..3 {
            table
                .charge(1, &key, Some(3), RETENTION, NOW)
                .expect("within quota");
        }
        for _ in 0..4 {
            assert_eq!(
                table.charge(1, &key, Some(3), RETENTION, NOW),
                Err(RunQuotaDenied::Exhausted),
                "past the limit every charge is denied"
            );
        }
    }

    #[test]
    fn run_quota_fails_closed_without_a_usable_limit() {
        let mut table = RunQuotaTable::new(16);
        let key = quota_key("release", 900, 1);
        assert_eq!(
            table.charge(1, &key, None, RETENTION, NOW),
            Err(RunQuotaDenied::QuotaUnavailable)
        );
        assert_eq!(
            table.charge(1, &key, Some(0), RETENTION, NOW),
            Err(RunQuotaDenied::Exhausted)
        );
    }

    #[test]
    fn run_quota_resets_on_a_new_run_attempt_and_isolates_rules() {
        let mut table = RunQuotaTable::new(16);
        let first_attempt = quota_key("release", 900, 1);
        table
            .charge(1, &first_attempt, Some(1), RETENTION, NOW)
            .expect("admitted");
        assert_eq!(
            table.charge(1, &first_attempt, Some(1), RETENTION, NOW),
            Err(RunQuotaDenied::Exhausted)
        );

        // A rerun (new run_attempt) opens a fresh bucket.
        let second_attempt = quota_key("release", 900, 2);
        table
            .charge(1, &second_attempt, Some(1), RETENTION, NOW)
            .expect("fresh bucket");

        // Another rule's bucket is untouched by the exhausted one.
        let other_rule = quota_key("nightly", 900, 1);
        table
            .charge(1, &other_rule, Some(1), RETENTION, NOW)
            .expect("isolated rule");
        // And the exhausted bucket stays exhausted.
        assert_eq!(
            table.charge(1, &first_attempt, Some(1), RETENTION, NOW),
            Err(RunQuotaDenied::Exhausted)
        );
    }

    #[test]
    fn run_quota_resets_on_reload_and_on_restart() {
        // Reload: a charge under a newer serving generation clears the
        // counters (stated behavior; the quota bounds a compromised job
        // inside a normal window).
        let mut table = RunQuotaTable::new(16);
        let key = quota_key("release", 900, 1);
        table
            .charge(1, &key, Some(1), RETENTION, NOW)
            .expect("admitted");
        assert_eq!(
            table.charge(1, &key, Some(1), RETENTION, NOW),
            Err(RunQuotaDenied::Exhausted)
        );
        table
            .charge(2, &key, Some(1), RETENTION, NOW)
            .expect("a new generation starts a fresh counter");
        assert_eq!(
            table.charge(2, &key, Some(1), RETENTION, NOW),
            Err(RunQuotaDenied::Exhausted)
        );

        // Restart: the table is process memory; a new table is empty.
        let mut restarted = RunQuotaTable::new(16);
        restarted
            .charge(2, &key, Some(1), RETENTION, NOW)
            .expect("fresh after restart");
    }

    #[test]
    fn run_quota_old_generation_charge_does_not_wipe_counters() {
        // A slow in-flight request pinned to the previous generation whose
        // charge lands after a reload must not reset the new generation's
        // counters (and must not re-pin the table backwards): it charges
        // into the current counters instead.
        let mut table = RunQuotaTable::new(16);
        let key = quota_key("release", 900, 1);
        table
            .charge(2, &key, Some(2), RETENTION, NOW)
            .expect("new generation admitted");
        table
            .charge(1, &key, Some(2), RETENTION, NOW)
            .expect("old pinned generation counts against current counters");
        assert_eq!(
            table.charge(2, &key, Some(2), RETENTION, NOW),
            Err(RunQuotaDenied::Exhausted),
            "the old-generation charge consumed quota instead of wiping it"
        );
        assert_eq!(
            table.charge(1, &key, Some(2), RETENTION, NOW),
            Err(RunQuotaDenied::Exhausted),
            "no alternation ever resets the counters"
        );
    }

    #[test]
    fn run_quota_bucket_allowance_is_per_rule() {
        let mut table = RunQuotaTable::new(2);
        table
            .charge(1, &quota_key("release", 1, 1), Some(10), RETENTION, NOW)
            .expect("tracked");
        table
            .charge(1, &quota_key("release", 2, 1), Some(10), RETENTION, NOW)
            .expect("tracked");
        // A third distinct run under the SAME rule cannot be tracked: deny
        // instead of evicting (an evicted bucket would restart its counter
        // and over-admit).
        assert_eq!(
            table.charge(1, &quota_key("release", 3, 1), Some(10), RETENTION, NOW),
            Err(RunQuotaDenied::Untracked)
        );
        // A different rule is unaffected by the saturated one: the bound is
        // per rule, so one tenant cannot deny another tenant's runs.
        table
            .charge(1, &quota_key("nightly", 3, 1), Some(10), RETENTION, NOW)
            .expect("other rule tracks independently");
        // Already-tracked buckets keep serving inside their quota.
        table
            .charge(1, &quota_key("release", 1, 1), Some(10), RETENTION, NOW)
            .expect("tracked bucket unaffected");
    }

    #[test]
    fn run_quota_reclaims_expired_buckets_under_pressure() {
        let mut table = RunQuotaTable::new(2);
        table
            .charge(1, &quota_key("release", 1, 1), Some(10), RETENTION, NOW)
            .expect("tracked");
        table
            .charge(1, &quota_key("release", 2, 1), Some(10), RETENTION, NOW)
            .expect("tracked");
        let retention = i64::try_from(RETENTION).expect("fits");
        // Inside the retention window nothing is reclaimable: deny.
        assert_eq!(
            table.charge(
                1,
                &quota_key("release", 3, 1),
                Some(10),
                RETENTION,
                NOW + retention - 1,
            ),
            Err(RunQuotaDenied::Untracked)
        );
        // Past the retention window the idle buckets are reclaimed and the
        // new run is admitted: table pressure never becomes permanent
        // denial.
        table
            .charge(
                1,
                &quota_key("release", 3, 1),
                Some(10),
                RETENTION,
                NOW + retention,
            )
            .expect("expired buckets reclaimed under pressure");
    }

    #[test]
    fn run_quota_denied_charges_keep_an_exhausted_bucket_retained() {
        let mut table = RunQuotaTable::new(1);
        let exhausted = quota_key("release", 1, 1);
        table
            .charge(1, &exhausted, Some(1), RETENTION, NOW)
            .expect("admitted");
        let retention = i64::try_from(RETENTION).expect("fits");
        // A denied charge attempt is verified token activity: it refreshes
        // the bucket's expiry, so an actively retrying exhausted run stays
        // exhausted rather than being reclaimed into a fresh quota.
        let later = NOW + retention;
        assert_eq!(
            table.charge(1, &exhausted, Some(1), RETENTION, later),
            Err(RunQuotaDenied::Exhausted)
        );
        // Without the refresh the bucket would have lapsed at NOW +
        // retention and been reclaimed here; the denied attempt above
        // extended it to `later + retention`.
        let probe = later + retention - 1;
        assert_eq!(
            table.charge(1, &quota_key("release", 2, 1), Some(1), RETENTION, probe),
            Err(RunQuotaDenied::Untracked),
            "the refreshed exhausted bucket is not reclaimable yet"
        );
        assert_eq!(
            table.charge(1, &exhausted, Some(1), RETENTION, probe),
            Err(RunQuotaDenied::Exhausted),
            "and it stays exhausted"
        );
    }

    #[test]
    fn concurrent_run_quota_charges_never_over_admit() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        const LIMIT: u64 = 100;
        const THREADS: usize = 8;
        const CHARGES_PER_THREAD: usize = 50;

        let table = Arc::new(Mutex::new(RunQuotaTable::new(16)));
        let admitted = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let table = Arc::clone(&table);
                let admitted = Arc::clone(&admitted);
                std::thread::spawn(move || {
                    let key = quota_key("release", 900, 1);
                    for _ in 0..CHARGES_PER_THREAD {
                        let outcome = table.lock().expect("table lock").charge(
                            1,
                            &key,
                            Some(LIMIT),
                            RETENTION,
                            NOW,
                        );
                        if outcome.is_ok() {
                            admitted.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("charge thread joins");
        }
        // 400 attempted charges against a limit of 100: exactly the limit
        // is admitted, never more.
        assert_eq!(
            admitted.load(Ordering::SeqCst),
            usize::try_from(LIMIT).expect("fits")
        );
    }

    const FORGEJO_ISSUER: &str = "https://forge.example.com/api/actions";

    fn forgejo_rule(id: &str, run_attempt: u64) -> ProviderRule {
        ProviderRule {
            id: id.to_string(),
            subject: "ci/forgejo-release".to_string(),
            audience: "urn:basil:ci".to_string(),
            operation_profiles: vec!["artifact-sign".to_string()],
            max_token_age_secs: 300,
            clock_skew_secs: 30,
            max_operations_per_run: Some(64),
            provider: ProviderConfig::ForgejoActions(ForgejoActionsRule {
                issuer: FORGEJO_ISSUER.to_string(),
                discovery_url: format!("{FORGEJO_ISSUER}/.well-known/openid-configuration"),
                jwks_url: format!("{FORGEJO_ISSUER}/.well-known/jwks"),
                audience_prefix: "urn:basil:ci:jkt:".to_string(),
                repository_id: 11,
                repository_owner_id: 3,
                workflow_ref: "forge/basil/.forgejo/workflows/release.yml@refs/heads/main"
                    .to_string(),
                ref_name: "refs/heads/main".to_string(),
                ref_type: "branch".to_string(),
                sha: "b".repeat(40),
                run_id: 900,
                run_attempt,
                not_before_unix: 1_700_000_000,
                expires_at_unix: 1_700_000_000 + 900,
                max_token_age_secs: 300,
                clock_skew_secs: 30,
            }),
        }
    }

    #[test]
    fn forgejo_rules_require_the_explicit_experimental_opt_in() {
        // Without the opt-in, catalog load fails and the error names the tier.
        let denied = ProviderCatalog::new(vec![forgejo_rule("nightly", 1)]);
        let Err(error) = denied else {
            panic!("forgejo rule must not load without the opt-in");
        };
        assert_eq!(
            error,
            FederationError::ExperimentalProviderDisabled("forgejoActions")
        );
        let message = error.to_string();
        assert!(message.contains("experimental"), "{message}");
        assert!(message.contains("experimentalProviders"), "{message}");
        assert!(message.contains("forgejoActions"), "{message}");

        // With the opt-in the same rule loads; naming a supported kind in the
        // opt-in list changes nothing.
        let catalog = ProviderCatalog::with_experimental_providers(
            vec![forgejo_rule("nightly", 1)],
            &[ProviderKind::ForgejoActions],
        )
        .expect("opted-in forgejo rule loads");
        assert_eq!(catalog.rules().len(), 1);
        assert!(
            ProviderCatalog::with_experimental_providers(
                vec![forgejo_rule("nightly", 1)],
                &[ProviderKind::GithubActions],
            )
            .is_err(),
            "a supported-tier opt-in entry must not enable the experimental tier"
        );
    }

    #[test]
    fn deserialized_catalogs_never_enable_the_experimental_tier() {
        // The serde path routes through `new`, so configuration that has no
        // explicit opt-in wiring fails closed on an experimental rule.
        let serialized =
            serde_json::to_value(vec![forgejo_rule("nightly", 1)]).expect("rules serialize");
        let parsed: Result<ProviderCatalog, _> = serde_json::from_value(serialized);
        let message = parsed
            .expect_err("experimental rule fails closed")
            .to_string();
        assert!(message.contains("experimental"), "{message}");

        let github_only = serde_json::to_value(vec![github_rule("release", &["main"], &["push"])])
            .expect("rules serialize");
        assert!(serde_json::from_value::<ProviderCatalog>(github_only).is_ok());
    }

    #[test]
    fn forgejo_grants_overlap_only_on_identical_selectors() {
        let opt_in = [ProviderKind::ForgejoActions];
        // Identical selectors under two ids: rejected even though grant
        // windows could differ.
        let mut shifted = forgejo_rule("second", 1);
        if let ProviderConfig::ForgejoActions(rule) = &mut shifted.provider {
            rule.not_before_unix += 100;
            rule.expires_at_unix += 100;
        }
        assert!(matches!(
            ProviderCatalog::with_experimental_providers(
                vec![forgejo_rule("first", 1), shifted],
                &opt_in
            ),
            Err(FederationError::OverlappingRules)
        ));

        // A rerun grant (next attempt) is disjoint by construction.
        let catalog = ProviderCatalog::with_experimental_providers(
            vec![forgejo_rule("first", 1), forgejo_rule("rerun", 2)],
            &opt_in,
        )
        .expect("attempt-disjoint grants load");
        assert_eq!(catalog.rules().len(), 2);

        // Provider kinds never overlap with each other.
        let mixed = ProviderCatalog::with_experimental_providers(
            vec![
                github_rule("release", &["main"], &["push"]),
                forgejo_rule("nightly", 1),
            ],
            &opt_in,
        )
        .expect("mixed-kind catalog loads");
        assert_eq!(mixed.rules().len(), 2);
    }

    #[test]
    fn forgejo_selection_is_exact_and_kind_isolated() {
        let catalog = ProviderCatalog::with_experimental_providers(
            vec![
                github_rule("release", &["main"], &["push"]),
                forgejo_rule("nightly", 1),
            ],
            &[ProviderKind::ForgejoActions],
        )
        .expect("mixed catalog loads");
        let selection = ForgejoSelection {
            repository_id: 11,
            repository_owner_id: 3,
            workflow_ref: "forge/basil/.forgejo/workflows/release.yml@refs/heads/main",
            ref_name: "refs/heads/main",
            ref_type: "branch",
            sha: &"b".repeat(40),
            run_id: 900,
            run_attempt: 1,
        };
        let selected = catalog
            .select_forgejo(&selection)
            .expect("exact forgejo rule selected");
        assert_eq!(selected.rule.id, "nightly");

        // A near miss (wrong attempt) selects nothing, and GitHub rules are
        // invisible to Forgejo selection.
        let near_miss = ForgejoSelection {
            run_attempt: 2,
            ..selection
        };
        assert!(matches!(
            catalog.select_forgejo(&near_miss),
            Err(FederationError::NoMatchingRule)
        ));
    }

    #[test]
    fn forgejo_rule_configuration_is_validated_strictly() {
        let case = |mutate: fn(&mut ForgejoActionsRule)| {
            let mut rule = forgejo_rule("check", 1);
            if let ProviderConfig::ForgejoActions(forgejo) = &mut rule.provider {
                mutate(forgejo);
            }
            ProviderCatalog::with_experimental_providers(
                vec![rule],
                &[ProviderKind::ForgejoActions],
            )
        };
        assert!(case(|_| {}).is_ok());
        // The issuer must be the instance's Actions API root.
        assert!(case(|r| r.issuer = "https://forge.example.com".to_string()).is_err());
        // The grant window is bounded and ordered.
        assert!(case(|r| r.expires_at_unix = r.not_before_unix).is_err());
        assert!(case(|r| r.expires_at_unix = r.not_before_unix + 901).is_err());
        // Ref type and ref must be consistent.
        assert!(case(|r| r.ref_type = "tag".to_string()).is_err());
        assert!(
            case(|r| {
                r.ref_type = "tag".to_string();
                r.ref_name = "refs/tags/v1.0.0".to_string();
            })
            .is_ok()
        );
        // Numeric identities are nonzero.
        assert!(case(|r| r.repository_id = 0).is_err());
        assert!(case(|r| r.repository_owner_id = 0).is_err());
        assert!(case(|r| r.run_id = 0).is_err());
        assert!(case(|r| r.run_attempt = 0).is_err());
    }

    #[test]
    fn forgejo_config_rejects_unknown_and_selector_like_fields() {
        // `deny_unknown_fields` closes the schema: environment-like,
        // reusable-workflow, and `ref_protected` selectors do not exist.
        for field in ["environment", "jobWorkflowRef", "refProtected", "events"] {
            let mut value =
                serde_json::to_value(forgejo_rule("strict", 1)).expect("rule serializes");
            value
                .get_mut("provider")
                .and_then(Value::as_object_mut)
                .expect("provider object")
                .insert(field.to_string(), json!("x"));
            assert!(
                serde_json::from_value::<ProviderRule>(value).is_err(),
                "unknown field {field} must be rejected"
            );
        }
    }

    #[test]
    fn generation_caches_serve_forgejo_providers_identically() {
        let provider = forgejo_rule("cache", 1).provider;
        let cache = GenerationJwksCache::new(5, &provider, JwksCachePolicy::default())
            .expect("forgejo cache");
        assert_eq!(cache.generation(), 5);
        assert!(cache.cached_key("any").is_none());
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
            environment: None,
        };
        assert!(matches!(
            catalog.select_github(&unknown),
            Err(FederationError::NoMatchingRule)
        ));
    }
}
