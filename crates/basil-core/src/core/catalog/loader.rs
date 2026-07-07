// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Loader: parse + validate the exported catalog & policy JSON, and build the
//! ready-for-PDP [`ResolvedPolicy`] index (design §5, §6).
//!
//! [`load`] is the single entry point. It validates **all** of §5's hard errors
//! up front so a bad export fails fast at startup rather than at request time.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::glob::{GlobError, KeyGlob};
use super::policy::{
    ALL_OPS, ActionTerm, ActionTermError, Config, Grant, Op, PrincipalSpec, ResolvedPolicy,
    ResolvedRule, Rule, SignatureKeyAlgorithm, SubjectDefinition, SubjectMatch, SubjectName,
};
use super::schema::{Catalog, Class, Engine, GenerateSpec, KeyAlgorithm, KeyEntry, MissingPolicy};

/// A warning recorded during loading that is not fatal (§3.7). The broker should
/// log these; they do not abort the load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadWarning {
    /// An `ed25519-nkey` key without a `nats_type` label; mint will fail for it (§2.6).
    MissingNatsType {
        /// The offending key name.
        key: String,
    },
}

impl std::fmt::Display for LoadWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingNatsType { key } => write!(
                f,
                "ed25519-nkey key `{key}` has no nats_type label; mint will fail for it"
            ),
        }
    }
}

/// A fatal error encountered while loading the catalog or policy (§5).
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The catalog or policy JSON was not valid JSON / wrong shape.
    #[error("malformed {what} JSON: {source}")]
    Json {
        /// Which document failed (`"catalog"` or `"policy"`).
        what: &'static str,
        /// The underlying serde error.
        source: serde_json::Error,
    },

    /// A key entry references a backend not declared in `backends`.
    #[error("key `{key}` references unknown backend `{backend}`")]
    UnknownBackend {
        /// The offending key name.
        key: String,
        /// The unknown backend name.
        backend: String,
    },

    /// A rule action references a role not declared in `roles`.
    #[error("rule `{rule}` references unknown role `{role}`")]
    UnknownRole {
        /// The offending rule id.
        rule: String,
        /// The unknown role name.
        role: String,
    },

    /// The policy schema version is not supported by this loader.
    #[error("policy schemaVersion `{version}` is unsupported (expected 2)")]
    UnsupportedPolicySchema {
        /// The unsupported version.
        version: u32,
    },

    /// The catalog schema version is not supported by this loader.
    #[error("catalog schemaVersion `{version}` is unsupported (expected 1)")]
    UnsupportedCatalogSchema {
        /// The unsupported version.
        version: u32,
    },

    /// A subject name is empty after trimming.
    #[error("subject name must not be empty")]
    EmptySubjectName,

    /// A subject definition did not contain exactly one expression shape.
    #[error("subject `{subject}` must define exactly one of allOf or anyOf")]
    InvalidSubjectShape {
        /// The offending subject name.
        subject: String,
    },

    /// A subject expression list was empty.
    #[error("subject `{subject}` has an empty {field}")]
    EmptySubjectMatch {
        /// The offending subject name.
        subject: String,
        /// The empty field (`allOf` or `anyOf`).
        field: &'static str,
    },

    /// A Unix principal named neither uid nor gid.
    #[error("subject `{subject}` has a unix principal without uid or gid")]
    EmptyUnixPrincipal {
        /// The offending subject name.
        subject: String,
    },

    /// A signature principal has empty public key material.
    #[error("subject `{subject}` has a signature-key principal with empty public key material")]
    EmptySignaturePublic {
        /// The offending subject name.
        subject: String,
    },

    /// A signature principal has malformed public key material.
    #[error(
        "subject `{subject}` has malformed {algorithm} signature-key public material: {reason}"
    )]
    MalformedSignaturePublic {
        /// The offending subject name.
        subject: String,
        /// Signature-key algorithm token.
        algorithm: &'static str,
        /// Secret-free validation reason.
        reason: &'static str,
    },

    /// An unauthenticated principal appears outside the configured unauthenticated subject.
    #[error(
        "subject `{subject}` uses unauthenticated principal but `unauthenticatedSubject` does not name it"
    )]
    InvalidUnauthenticatedPrincipal {
        /// The offending subject name.
        subject: String,
    },

    /// `unauthenticatedSubject` names no configured subject.
    #[error("`unauthenticatedSubject` references undefined subject `{subject}`")]
    UnknownUnauthenticatedSubject {
        /// The unknown subject name.
        subject: String,
    },

    /// A rule did not name any subjects.
    #[error("rule `{rule}` must name at least one subject")]
    EmptyRuleSubjects {
        /// The offending rule id.
        rule: String,
    },

    /// A rule references a subject not declared in the subject registry.
    #[error("rule `{rule}` references undefined subject `{subject}`")]
    UnknownSubject {
        /// The offending rule id.
        rule: String,
        /// The unknown subject name.
        subject: String,
    },

    /// A key's `description` is blank or absent (§2.4).
    #[error("key `{key}` has a blank description")]
    BlankDescription {
        /// The offending key name.
        key: String,
    },

    /// `key_type` is required for an asymmetric/symmetric key but absent.
    #[error("key `{key}` ({class}) requires a keyType")]
    MissingKeyType {
        /// The offending key name.
        key: String,
        /// The class that requires a `key_type`.
        class: &'static str,
    },

    /// `key_type` is present on a `value` key, where it is forbidden (§2.4.1).
    #[error("key `{key}` (value) must not carry a keyType")]
    UnexpectedKeyType {
        /// The offending key name.
        key: String,
    },

    /// A `sealing` key has a `key_type` other than a supported KEM.
    #[error("key `{key}` (sealing) must have a supported KEM keyType, got `{key_type}`")]
    SealingKeyTypeNotX25519 {
        /// The offending key name.
        key: String,
        /// The (wrong) key type token supplied.
        key_type: &'static str,
    },

    /// A `value`/`public` key has `missing="generate"` but no `generate` recipe (§3.7).
    #[error("key `{key}` ({class}) has missing=generate but no generate recipe")]
    GenerateWithoutRecipe {
        /// The offending key name.
        key: String,
        /// The class (`value` or `public`).
        class: &'static str,
    },

    /// A `generate` recipe is present on a key where it is not allowed (§2.4 / §2.5):
    /// crypto keys generate from `key_type` and carry no recipe.
    #[error("key `{key}` ({class}) carries a generate recipe but only value/public may")]
    UnexpectedGenerate {
        /// The offending key name.
        key: String,
        /// The class.
        class: &'static str,
    },

    /// A PKI engine entry is not shaped like a Vault issue endpoint.
    #[error("key `{key}` uses engine=pki but path `{path}` is not a pki/issue endpoint")]
    InvalidPkiPath {
        /// The offending key name.
        key: String,
        /// The configured backend path.
        path: String,
    },

    /// An `engine=kv2` asymmetric (materialize-to-sign) key has a `key_type`
    /// other than `ed25519`. The value-store signing arm (`vault-iiz`) materializes
    /// a 32-byte Ed25519 seed only; RSA / nkey keys cannot route down it.
    #[error(
        "key `{key}` uses engine=kv2 (materialize-to-sign) but keyType `{key_type}` \
         is not ed25519"
    )]
    Kv2SigningKeyTypeNotEd25519 {
        /// The offending key name.
        key: String,
        /// The (wrong) key type token supplied.
        key_type: &'static str,
    },

    /// A `svid_kind=jwt` issuer is backed by a key algorithm outside the SPIFFE
    /// JWT-SVID profile (`RS256`/`ES256`/`PS*` → `rsa-*`/`ec-*`). `ed25519`/`EdDSA`
    /// mints a token every standard SPIFFE client rejects, so it is a fail-closed
    /// misconfiguration (caught at boot/check before any client fetch).
    #[error(
        "key `{key}` is a svid_kind=jwt issuer with keyType `{key_type}`, \
         which is not a SPIFFE JWT-SVID profile algorithm (need rsa-*/ec-*; \
         ed25519/EdDSA is rejected by standard SPIFFE clients)"
    )]
    NonSpiffeJwtSvidAlg {
        /// The offending key name.
        key: String,
        /// The configured (disallowed) key algorithm.
        key_type: &'static str,
    },

    /// A materialize-to-use key (`sealing` X25519 / `asymmetric`+`engine=kv2`
    /// Ed25519) has no `publicPath`. Its public half is provisioned out of band
    /// (basil-o86) so public ops resolve it without materializing the private; a
    /// missing `publicPath` would force the materialize footprint back, so it is
    /// rejected at load (boot reconcile **and** `check`).
    #[error(
        "key `{key}` ({class}) is a materialize-to-use key but has no publicPath; \
         provision its public half out of band and point publicPath at it"
    )]
    MissingPublicPath {
        /// The offending key name.
        key: String,
        /// The class (`sealing` or `asymmetric`).
        class: &'static str,
    },

    /// A `publicPath` appears on a key that is **not** materialize-to-use, where
    /// it is meaningless: an in-place crypto key (transit) needs no out-of-band
    /// public, a `value` key's bytes are its own material, and a `public` key
    /// already serves its public via `get` at `path`. Rejected to keep the
    /// catalog honest (fail closed on a misconfiguration).
    #[error(
        "key `{key}` ({class}) carries a publicPath but only a materialize-to-use \
         key (sealing / asymmetric+engine=kv2) may"
    )]
    UnexpectedPublicPath {
        /// The offending key name.
        key: String,
        /// The class.
        class: &'static str,
    },

    /// A `sealingPin` appears on a key that is not `class: sealing`, the only
    /// class routed through the `UnsealCose` decrypt oracle a pin narrows
    /// (`basil-2rqj`). Meaningless elsewhere; rejected to keep the catalog honest
    /// (fail closed).
    #[error("key `{key}` ({class}) carries a sealingPin but only a sealing key may")]
    UnexpectedSealingPin {
        /// The offending key name.
        key: String,
        /// The class.
        class: &'static str,
    },

    /// A `sealingPin` is present but pins neither KDF parties nor an `externalAad`
    /// set: a no-op that would read as configured intent. Rejected so a pin
    /// always constrains something (`basil-2rqj`).
    #[error("key `{key}` has an empty sealingPin; pin parties and/or externalAad, or omit it")]
    EmptySealingPin {
        /// The offending key name.
        key: String,
    },

    /// A pinned KDF party slot (`partyU`/`partyV`) is an empty string. The nil
    /// (anonymous) slot is expressed by omitting the field, never by an empty
    /// identity (`basil-2rqj`).
    #[error("key `{key}` sealingPin has an empty party identity; omit the slot for nil")]
    EmptyPinnedPartyIdentity {
        /// The offending key name.
        key: String,
    },

    /// A reserved label appears more than once on one key.
    #[error("key `{key}` has duplicate reserved label `{label}`")]
    DuplicateReservedLabel {
        /// The offending key name.
        key: String,
        /// The duplicated label key.
        label: String,
    },

    /// A reserved label is malformed or has an unsupported value.
    #[error("key `{key}` has invalid reserved label `{label}`: {reason}")]
    InvalidReservedLabel {
        /// The offending key name.
        key: String,
        /// The label key.
        label: String,
        /// Human-readable validation reason.
        reason: &'static str,
    },

    /// A target term failed glob parsing (intra-segment / non-last wildcard, §3.4).
    #[error("rule `{rule}`: {source}")]
    BadGlob {
        /// The offending rule id.
        rule: String,
        /// The glob parse error.
        source: GlobError,
    },

    /// A prefix-form action term failed parsing (§3.3).
    #[error("rule `{rule}`: {source}")]
    BadTerm {
        /// The offending rule id.
        rule: String,
        /// The action term parse error.
        source: ActionTermError,
    },

    /// A catalog key name is not dotted-lowercase (§2.4): `[a-z0-9][a-z0-9_]*`
    /// segments separated by single dots. Enforced at load so a key name can
    /// never carry control characters into the text tracing sinks (the audit
    /// record logs the key on every decision).
    #[error("key name `{key}` is not dotted-lowercase ([a-z0-9_] segments separated by `.`)")]
    BadKeyName {
        /// The offending key name, control characters escaped for display.
        key: String,
    },

    /// A subject name contains a control character. Subject names reach the
    /// text tracing sinks on every decision record, so they must be printable.
    #[error("subject name `{subject}` contains a control character")]
    BadSubjectName {
        /// The offending subject name, control characters escaped for display.
        subject: String,
    },

    /// A rule has a match-everything target (`*` or a bare `**`) but at least
    /// one referenced subject is not break-glass.
    #[error(
        "rule `{rule}`: a match-everything target (`*` or `**`) requires every referenced subject to set breakGlass=true"
    )]
    NonBreakGlassAnyTarget {
        /// The offending rule id.
        rule: String,
    },
}

// ---- Raw JSON wire shapes (pre-parse) ---------------------------------------

/// Raw policy document as exported. Rules carry subject names; `action`/`target`
/// are prefix-form strings parsed into typed forms by [`load`].
///
/// `Serialize` is derived too so the scaffolder (`basil-agent init`) emits a
/// policy document by serializing the **real** wire type: it cannot drift from
/// what [`load`] parses, and round-trips back through this same struct.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawPolicy {
    /// Policy schema version. The subject registry schema is version 2.
    #[serde(rename = "schemaVersion", default = "default_policy_schema_version")]
    pub schema_version: u32,
    /// Named subject registry.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub subjects: BTreeMap<SubjectName, RawSubjectDefinition>,
    /// Subject used for explicitly unauthenticated access, when configured.
    #[serde(
        rename = "unauthenticatedSubject",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub unauthenticated_subject: Option<SubjectName>,
    /// Named role → op-set table; an action `role:<name>` expands to its ops.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub roles: BTreeMap<String, BTreeSet<Op>>,
    /// The allow-rules (default-deny is the absence of a match).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RawRule>,
    /// Export-resolved name/membership tables (§4).
    #[serde(default)]
    pub config: Config,
}

const fn default_policy_schema_version() -> u32 {
    2
}

/// One raw subject definition. Exactly one of `allOf` or `anyOf` must be set.
///
/// Unknown fields fail closed: a typo'd `breakGlass` silently defaulting to
/// `false` would be caught by the any-target gate, but the same class of typo
/// on future fields must never load as a permissive default.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawSubjectDefinition {
    /// Whether this subject is eligible for rules targeting global `*`.
    #[serde(rename = "breakGlass", default, skip_serializing_if = "is_false")]
    pub break_glass: bool,
    /// All principal specs must match.
    #[serde(rename = "allOf", default, skip_serializing_if = "Option::is_none")]
    pub all_of: Option<Vec<PrincipalSpec>>,
    /// At least one principal spec must match.
    #[serde(rename = "anyOf", default, skip_serializing_if = "Option::is_none")]
    pub any_of: Option<Vec<PrincipalSpec>>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

/// One raw policy rule with `subjects` plus prefix-form `action`/`target` terms.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawRule {
    /// Stable rule id (for logging and audit).
    pub id: String,
    /// Subject names this rule grants to. The list is an OR.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<SubjectName>,
    /// Prefix-form action terms (`role:<name>`, `op:<op>`, `*`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action: Vec<String>,
    /// Target key globs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub target: Vec<String>,
    /// Optional free-text comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

// ---- Public entry point -----------------------------------------------------

/// Load + validate the exported catalog & policy JSON.
///
/// Returns the parsed [`Catalog`], the ready-for-PDP [`ResolvedPolicy`] index,
/// and the [`Config`] tables, plus any non-fatal [`LoadWarning`]s. Validates the
/// full §5 hard-error list; the first hard error aborts the load.
pub fn load(
    catalog_json: &str,
    policy_json: &str,
) -> Result<(Catalog, ResolvedPolicy, Config, Vec<LoadWarning>), LoadError> {
    let catalog: Catalog =
        serde_json::from_str(catalog_json).map_err(|source| LoadError::Json {
            what: "catalog",
            source,
        })?;
    let raw_policy: RawPolicy =
        serde_json::from_str(policy_json).map_err(|source| LoadError::Json {
            what: "policy",
            source,
        })?;

    validate_catalog_schema(catalog.schema_version)?;
    let warnings = validate_catalog(&catalog)?;
    validate_policy_schema(raw_policy.schema_version)?;
    let subjects = parse_subjects(
        raw_policy.subjects,
        raw_policy.unauthenticated_subject.as_ref(),
    )?;
    validate_unauthenticated_subject(raw_policy.unauthenticated_subject.as_ref(), &subjects)?;
    let rules = parse_rules(raw_policy.rules, &subjects)?;
    validate_rule_roles(&rules, &raw_policy.roles)?;
    let resolved = build_resolved(
        subjects,
        raw_policy.unauthenticated_subject,
        &rules,
        &raw_policy.roles,
    );

    Ok((catalog, resolved, raw_policy.config, warnings))
}

// ---- Catalog validation (§2, §5) --------------------------------------------

/// Hard-require the one catalog schema version this loader understands,
/// mirroring [`validate_policy_schema`]: a future incompatible catalog must
/// fail closed at load instead of parsing silently.
const fn validate_catalog_schema(version: u32) -> Result<(), LoadError> {
    if version == 1 {
        return Ok(());
    }
    Err(LoadError::UnsupportedCatalogSchema { version })
}

fn validate_catalog(catalog: &Catalog) -> Result<Vec<LoadWarning>, LoadError> {
    // Duplicate key names cannot occur (BTreeMap dedups on deserialize), so the
    // §5 "duplicate key" guard is structurally satisfied by the map type.
    let mut warnings = Vec::new();
    for (name, key) in &catalog.keys {
        validate_key(catalog, name, key, &mut warnings)?;
    }
    Ok(warnings)
}

fn validate_key(
    catalog: &Catalog,
    name: &str,
    key: &KeyEntry,
    warnings: &mut Vec<LoadWarning>,
) -> Result<(), LoadError> {
    validate_key_name(name)?;
    validate_backend_ref(catalog, name, key)?;
    validate_description(name, key)?;
    validate_key_type(name, key)?;
    validate_generate(name, key)?;
    validate_engine(name, key)?;
    validate_jwt_svid_issuer_alg(name, key)?;
    validate_public_path(name, key)?;
    validate_sealing_pin(name, key)?;
    validate_reserved_labels(name, key)?;
    warn_missing_nats_type(name, key, warnings);
    Ok(())
}

/// Enforce the documented dotted-lowercase key-name shape (§2.4): one or more
/// `[a-z0-9][a-z0-9_]*` segments separated by single dots. Key names are logged
/// on every decision record, so the charset is pinned here, at load,
/// fail-closed. (A *client-supplied* name on a denied request is separately
/// escaped when the `DecisionRecord` is built.)
fn validate_key_name(name: &str) -> Result<(), LoadError> {
    let seg_ok = |seg: &str| {
        let mut chars = seg.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };
    if !name.is_empty() && name.split('.').all(seg_ok) {
        return Ok(());
    }
    Err(LoadError::BadKeyName {
        key: name.chars().flat_map(char::escape_default).collect(),
    })
}

/// Fail-closed guardrail (basil-6o4): a `svid_kind=jwt` issuer must resolve to a
/// SPIFFE JWT-SVID profile algorithm (`rsa-*`/`ec-*` → `RS*`/`ES*`/`PS*`). An
/// `ed25519`/`EdDSA` issuer would boot fine yet mint tokens every conforming
/// SPIFFE client rejects with `UnsupportedAlgorithm`, so it is caught here, at
/// load (boot reconcile **and** `check`), before any client fetch.
///
/// The `svid_kind=jwt` selector mirrors the runtime `is_jwt_svid_issuer`
/// predicate in `service::spiffe`. A key without that label is not a JWT-SVID
/// issuer and is unaffected.
fn validate_jwt_svid_issuer_alg(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    if key.labels.get("svid_kind") != Some("jwt") {
        return Ok(());
    }
    // A JWT-SVID issuer is an asymmetric signing key; `validate_key_type` has
    // already required `key_type` for the asymmetric class. If it is somehow
    // absent (e.g. a `public` class mislabeled), there is no algorithm to vet.
    // Leave it to the other validators rather than guessing.
    let Some(alg) = key.key_type else {
        return Ok(());
    };
    if alg.is_spiffe_jwt_svid_profile() {
        return Ok(());
    }
    Err(LoadError::NonSpiffeJwtSvidAlg {
        key: name.to_string(),
        key_type: alg.token(),
    })
}

/// Fail-closed guardrail (basil-o86): a materialize-to-use key
/// (`sealing` / `asymmetric`+`engine=kv2`) **must** carry a non-blank
/// `publicPath`, and no other key may. The public half is provisioned out of
/// band so `wrap`/`get_public_key`/`verify` resolve it without materializing the
/// private; without a `publicPath` those ops would have to re-derive the public
/// from the private (the very footprint o86 removes), so it is required here:
/// at load (boot reconcile **and** `check`). On any other key a `publicPath` is
/// meaningless and rejected.
fn validate_public_path(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    let has_path = key
        .public_path
        .as_ref()
        .is_some_and(|p| !p.trim().is_empty());
    if key.is_materialize_to_use() {
        if has_path {
            return Ok(());
        }
        return Err(LoadError::MissingPublicPath {
            key: name.to_string(),
            class: class_str(key.class),
        });
    }
    // Not a materialize-to-use key: a publicPath (present or blank) is a config
    // error. `None` is the only valid state.
    if key.public_path.is_none() {
        return Ok(());
    }
    Err(LoadError::UnexpectedPublicPath {
        key: name.to_string(),
        class: class_str(key.class),
    })
}

/// Fail-closed guardrail (`basil-2rqj`): a COSE `sealingPin` is valid only on a
/// `class: sealing` key, must actually constrain something, and its party slots
/// (when present) must be non-empty identities. A pin narrows the `UnsealCose`
/// decrypt oracle; an incorrectly scoped or no-op pin is a config error caught at load
/// (boot reconcile **and** `check`) before any envelope reaches the key.
fn validate_sealing_pin(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    let Some(pin) = key.sealing_pin.as_ref() else {
        return Ok(());
    };
    if key.class != Class::Sealing {
        return Err(LoadError::UnexpectedSealingPin {
            key: name.to_string(),
            class: class_str(key.class),
        });
    }
    if !pin.is_configured() {
        return Err(LoadError::EmptySealingPin {
            key: name.to_string(),
        });
    }
    if let Some(parties) = pin.parties.as_ref() {
        let empty_slot = [parties.party_u.as_deref(), parties.party_v.as_deref()]
            .into_iter()
            .flatten()
            .any(str::is_empty);
        if empty_slot {
            return Err(LoadError::EmptyPinnedPartyIdentity {
                key: name.to_string(),
            });
        }
    }
    Ok(())
}

fn validate_backend_ref(catalog: &Catalog, name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    if catalog.backends.contains_key(&key.backend) {
        return Ok(());
    }
    Err(LoadError::UnknownBackend {
        key: name.to_string(),
        backend: key.backend.clone(),
    })
}

fn validate_description(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    if !key.description.trim().is_empty() {
        return Ok(());
    }
    Err(LoadError::BlankDescription {
        key: name.to_string(),
    })
}

fn validate_key_type(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    match key.class {
        Class::Asymmetric | Class::Symmetric => require_key_type(name, key),
        // A sealing key is always a supported KEM; require the type and pin it so
        // a misconfigured catalog can't route a non-KEM key down the unseal path.
        Class::Sealing => require_sealing_key_type(name, key),
        Class::Value => reject_key_type(name, key),
        Class::Public => Ok(()),
    }
}

fn require_sealing_key_type(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    require_key_type(name, key)?;
    // require_key_type already rejected `None`; only KEM recipient algorithms are
    // valid sealing types.
    match key.key_type {
        Some(
            KeyAlgorithm::X25519
            | KeyAlgorithm::MlKem512
            | KeyAlgorithm::MlKem768
            | KeyAlgorithm::MlKem1024,
        )
        | None => Ok(()),
        Some(other) => Err(LoadError::SealingKeyTypeNotX25519 {
            key: name.to_string(),
            key_type: other.token(),
        }),
    }
}

fn require_key_type(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    if key.key_type.is_some() {
        return Ok(());
    }
    Err(LoadError::MissingKeyType {
        key: name.to_string(),
        class: class_str(key.class),
    })
}

fn reject_key_type(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    if key.key_type.is_none() {
        return Ok(());
    }
    Err(LoadError::UnexpectedKeyType {
        key: name.to_string(),
    })
}

fn warn_missing_nats_type(name: &str, key: &KeyEntry, warnings: &mut Vec<LoadWarning>) {
    if key.key_type == Some(KeyAlgorithm::Ed25519Nkey) && !key.labels.has_nats_type() {
        warnings.push(LoadWarning::MissingNatsType {
            key: name.to_string(),
        });
    }
}

fn validate_reserved_labels(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    let mut seen = BTreeSet::new();
    for label in &key.labels.0 {
        validate_reserved_label(name, label, &mut seen)?;
    }
    Ok(())
}

fn validate_reserved_label(
    name: &str,
    label: &str,
    seen: &mut BTreeSet<String>,
) -> Result<(), LoadError> {
    let Some((label_key, value)) = label.split_once('=') else {
        return validate_bare_reserved_label(name, label);
    };
    if !is_reserved_label(label_key) {
        return Ok(());
    }
    record_reserved_label(name, label_key, seen)?;
    validate_reserved_label_value(name, label_key, value)
}

fn validate_bare_reserved_label(name: &str, label: &str) -> Result<(), LoadError> {
    if !is_reserved_label(label) {
        return Ok(());
    }
    Err(LoadError::InvalidReservedLabel {
        key: name.to_string(),
        label: label.to_string(),
        reason: "reserved labels must use name=value form",
    })
}

fn record_reserved_label(
    name: &str,
    label: &str,
    seen: &mut BTreeSet<String>,
) -> Result<(), LoadError> {
    if seen.insert(label.to_string()) {
        return Ok(());
    }
    Err(LoadError::DuplicateReservedLabel {
        key: name.to_string(),
        label: label.to_string(),
    })
}

fn validate_reserved_label_value(name: &str, label: &str, value: &str) -> Result<(), LoadError> {
    let valid = match label {
        "crypto_provider" => matches!(value, "vault-transit" | "local-software"),
        "pqc_algorithm" => matches!(
            value,
            "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" | "ml-kem-512" | "ml-kem-768" | "ml-kem-1024"
        ),
        "pqc_custody" => matches!(value, "backend-native" | "software-encrypted"),
        "crypto_provider_policy" => matches!(
            value,
            "backend-preferred" | "backend-required" | "local-software"
        ),
        "crypto_provider_version" | "migration_target" | "pqc_storage_key" => {
            !value.trim().is_empty()
        }
        "broker_key_use" => {
            matches!(
                value,
                "response-signing" | "request-encryption" | "response-encryption"
            )
        }
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(LoadError::InvalidReservedLabel {
            key: name.to_string(),
            label: label.to_string(),
            reason: "unsupported or empty value",
        })
    }
}

fn is_reserved_label(label: &str) -> bool {
    matches!(
        label,
        "crypto_provider"
            | "crypto_provider_version"
            | "pqc_algorithm"
            | "pqc_custody"
            | "pqc_storage_key"
            | "crypto_provider_policy"
            | "migration_target"
            | "broker_key_use"
    )
}

fn validate_engine(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    // An explicit `engine=kv2` on an asymmetric key is the materialize-to-sign arm
    // (`vault-iiz`): pin it to Ed25519 so a misconfigured catalog can't route an
    // RSA/nkey key down the 32-byte-seed sign path. `validate_key_type` already
    // rejected an absent key_type for the asymmetric class.
    if key.class == Class::Asymmetric && key.engine == Some(Engine::Kv2) {
        return match key.key_type {
            // None is unreachable (require_key_type rejects it for asymmetric
            // first); accepted here alongside ed25519 to keep the match total.
            Some(KeyAlgorithm::Ed25519) | None => Ok(()),
            Some(other) => Err(LoadError::Kv2SigningKeyTypeNotEd25519 {
                key: name.to_string(),
                key_type: other.token(),
            }),
        };
    }
    if key.engine != Some(Engine::Pki) {
        return Ok(());
    }
    if key.class == Class::Asymmetric && is_pki_issue_path(&key.path) {
        return Ok(());
    }
    Err(LoadError::InvalidPkiPath {
        key: name.to_string(),
        path: key.path.clone(),
    })
}

fn is_pki_issue_path(path: &str) -> bool {
    let mut segments = path.split('/');
    let Some(mount) = segments.next() else {
        return false;
    };
    mount.starts_with("pki") && segments.next() == Some("issue") && segments.next().is_some()
}

fn validate_generate(name: &str, key: &KeyEntry) -> Result<(), LoadError> {
    let is_recipe_class = matches!(key.class, Class::Value | Class::Public);

    match (is_recipe_class, key.missing, key.generate.as_ref()) {
        // value/public + missing=generate but no recipe -> error.
        (true, MissingPolicy::Generate, None) => Err(LoadError::GenerateWithoutRecipe {
            key: name.to_string(),
            class: class_str(key.class),
        }),
        // A recipe on a crypto class (asym/sym) is forbidden: they generate from
        // key_type (§2.4 generate row, §2.5).
        (false, _, Some(_)) => Err(LoadError::UnexpectedGenerate {
            key: name.to_string(),
            class: class_str(key.class),
        }),
        _ => {
            // Reference the recipe type so the import stays meaningful and to keep
            // the match exhaustive over the documented shapes.
            debug_assert!(matches!(
                key.generate,
                None | Some(
                    GenerateSpec::AsciiPrintable { .. }
                        | GenerateSpec::Base64 { .. }
                        | GenerateSpec::Hex { .. }
                        | GenerateSpec::AgeX25519
                        | GenerateSpec::SelfSignedTls { .. }
                        | GenerateSpec::SelfSignedTlsPairOf { .. }
                )
            ));
            Ok(())
        }
    }
}

const fn class_str(class: Class) -> &'static str {
    match class {
        Class::Asymmetric => "asymmetric",
        Class::Symmetric => "symmetric",
        Class::Value => "value",
        Class::Public => "public",
        Class::Sealing => "sealing",
    }
}

// ---- Policy parsing + validation (§3, §5) -----------------------------------

const fn validate_policy_schema(version: u32) -> Result<(), LoadError> {
    if version == 2 {
        return Ok(());
    }
    Err(LoadError::UnsupportedPolicySchema { version })
}

fn parse_subjects(
    raw: BTreeMap<SubjectName, RawSubjectDefinition>,
    unauthenticated_subject: Option<&SubjectName>,
) -> Result<BTreeMap<SubjectName, SubjectDefinition>, LoadError> {
    raw.into_iter()
        .map(|(name, subject)| parse_subject(&name, subject, unauthenticated_subject))
        .collect()
}

fn parse_subject(
    name: &str,
    raw: RawSubjectDefinition,
    unauthenticated_subject: Option<&SubjectName>,
) -> Result<(SubjectName, SubjectDefinition), LoadError> {
    let normalized = name.trim();
    if normalized.is_empty() {
        return Err(LoadError::EmptySubjectName);
    }
    // Subject names are logged on every decision record; a control character
    // (newline, ESC) could forge lines in the text tracing sinks.
    if normalized.chars().any(char::is_control) {
        return Err(LoadError::BadSubjectName {
            subject: normalized.chars().flat_map(char::escape_default).collect(),
        });
    }
    let match_ = match (raw.all_of, raw.any_of) {
        (Some(specs), None) => {
            validate_principal_specs(normalized, &specs, "allOf", unauthenticated_subject)?;
            SubjectMatch::AllOf(specs)
        }
        (None, Some(specs)) => {
            validate_principal_specs(normalized, &specs, "anyOf", unauthenticated_subject)?;
            SubjectMatch::AnyOf(specs)
        }
        (Some(_), Some(_)) | (None, None) => {
            return Err(LoadError::InvalidSubjectShape {
                subject: normalized.to_string(),
            });
        }
    };
    Ok((
        normalized.to_string(),
        SubjectDefinition {
            break_glass: raw.break_glass,
            match_,
        },
    ))
}

fn validate_unauthenticated_subject(
    unauthenticated_subject: Option<&SubjectName>,
    subjects: &BTreeMap<SubjectName, SubjectDefinition>,
) -> Result<(), LoadError> {
    let Some(subject) = unauthenticated_subject else {
        return Ok(());
    };
    if subjects.contains_key(subject) {
        Ok(())
    } else {
        Err(LoadError::UnknownUnauthenticatedSubject {
            subject: subject.clone(),
        })
    }
}

fn validate_principal_specs(
    subject: &str,
    specs: &[PrincipalSpec],
    field: &'static str,
    unauthenticated_subject: Option<&SubjectName>,
) -> Result<(), LoadError> {
    if specs.is_empty() {
        return Err(LoadError::EmptySubjectMatch {
            subject: subject.to_string(),
            field,
        });
    }
    for spec in specs {
        validate_principal_spec(subject, spec, unauthenticated_subject)?;
    }
    Ok(())
}

fn validate_principal_spec(
    subject: &str,
    spec: &PrincipalSpec,
    unauthenticated_subject: Option<&SubjectName>,
) -> Result<(), LoadError> {
    match spec {
        PrincipalSpec::Unix { uid, gid } => {
            if uid.is_some() || gid.is_some() {
                Ok(())
            } else {
                Err(LoadError::EmptyUnixPrincipal {
                    subject: subject.to_string(),
                })
            }
        }
        PrincipalSpec::Unauthenticated => {
            if unauthenticated_subject.is_some_and(|configured| configured == subject) {
                Ok(())
            } else {
                Err(LoadError::InvalidUnauthenticatedPrincipal {
                    subject: subject.to_string(),
                })
            }
        }
        PrincipalSpec::SignatureKey { algorithm, public } => {
            if public.trim().is_empty() {
                Err(LoadError::EmptySignaturePublic {
                    subject: subject.to_string(),
                })
            } else {
                validate_signature_public(subject, *algorithm, public)
            }
        }
    }
}

fn validate_signature_public(
    subject: &str,
    algorithm: SignatureKeyAlgorithm,
    public: &str,
) -> Result<(), LoadError> {
    let ok = match algorithm {
        SignatureKeyAlgorithm::Ed25519 => URL_SAFE_NO_PAD
            .decode(public.as_bytes())
            .is_ok_and(|bytes| bytes.len() == crate::ed25519_sign::PUBLIC_KEY_LEN),
        SignatureKeyAlgorithm::NatsNkey => basil_nats::decode_public(public).is_ok(),
    };
    if ok {
        return Ok(());
    }
    Err(LoadError::MalformedSignaturePublic {
        subject: subject.to_string(),
        algorithm: signature_key_algorithm_token(algorithm),
        reason: match algorithm {
            SignatureKeyAlgorithm::Ed25519 => {
                "expected base64url-no-pad 32-byte Ed25519 public key"
            }
            SignatureKeyAlgorithm::NatsNkey => "expected a valid public NATS NKey",
        },
    })
}

const fn signature_key_algorithm_token(algorithm: SignatureKeyAlgorithm) -> &'static str {
    match algorithm {
        SignatureKeyAlgorithm::Ed25519 => "ed25519",
        SignatureKeyAlgorithm::NatsNkey => "nats-nkey",
    }
}

fn parse_rules(
    raw: Vec<RawRule>,
    subjects: &BTreeMap<SubjectName, SubjectDefinition>,
) -> Result<Vec<Rule>, LoadError> {
    raw.into_iter()
        .map(|rule| parse_rule(rule, subjects))
        .collect()
}

fn parse_rule(
    raw: RawRule,
    subjects: &BTreeMap<SubjectName, SubjectDefinition>,
) -> Result<Rule, LoadError> {
    let id = raw.id;

    if raw.subjects.is_empty() {
        return Err(LoadError::EmptyRuleSubjects { rule: id });
    }
    for subject in &raw.subjects {
        if !subjects.contains_key(subject) {
            return Err(LoadError::UnknownSubject {
                rule: id,
                subject: subject.clone(),
            });
        }
    }

    let action = raw
        .action
        .iter()
        .map(|t| ActionTerm::parse(t))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| LoadError::BadTerm {
            rule: id.clone(),
            source,
        })?;

    let target = raw
        .target
        .iter()
        .map(|t| KeyGlob::parse(t))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| LoadError::BadGlob {
            rule: id.clone(),
            source,
        })?;

    if target.iter().any(KeyGlob::matches_all)
        && raw.subjects.iter().any(|name| {
            !subjects
                .get(name)
                .is_some_and(|subject| subject.break_glass)
        })
    {
        return Err(LoadError::NonBreakGlassAnyTarget { rule: id });
    }

    Ok(Rule {
        id,
        subjects: raw.subjects,
        action,
        target,
        comment: raw.comment,
    })
}

fn validate_rule_roles(
    rules: &[Rule],
    defined_roles: &BTreeMap<String, BTreeSet<Op>>,
) -> Result<(), LoadError> {
    for rule in rules {
        for action in &rule.action {
            if let ActionTerm::Role(name) = action
                && !defined_roles.contains_key(name)
            {
                return Err(LoadError::UnknownRole {
                    rule: rule.id.clone(),
                    role: name.clone(),
                });
            }
        }
    }
    Ok(())
}

// ---- ResolvedPolicy index building (§6) -------------------------------------

/// Expand a rule's action terms into the concrete `(op, action-term-spelling)`
/// set, via the roles map. `AnyOp` (`*`) expands to **every** op. The spelling is
/// the originating term (`role:<name>`, `op:<op>`, `*`) carried into each
/// [`Grant`] for `explain`/audit provenance.
///
/// When several action terms grant the same op, the FIRST term in declaration
/// order wins the spelling: `decide`/`explain` match by op, so a single
/// representative term is enough and stable.
fn expand_ops(
    action: &[ActionTerm],
    defined_roles: &BTreeMap<String, BTreeSet<Op>>,
) -> BTreeMap<Op, String> {
    let mut ops: BTreeMap<Op, String> = BTreeMap::new();
    let insert = |op: Op, spelling: &str, ops: &mut BTreeMap<Op, String>| {
        ops.entry(op).or_insert_with(|| spelling.to_string());
    };
    for term in action {
        match term {
            ActionTerm::Op(op) => insert(*op, &format!("op:{}", op.token()), &mut ops),
            ActionTerm::Role(name) => {
                // Unknown roles are rejected before this point.
                if let Some(role_ops) = defined_roles.get(name) {
                    let spelling = format!("role:{name}");
                    for op in role_ops {
                        insert(*op, &spelling, &mut ops);
                    }
                }
            }
            ActionTerm::AnyOp => {
                for op in ALL_OPS {
                    insert(op, "*", &mut ops);
                }
            }
        }
    }
    ops
}

fn build_resolved(
    subjects: BTreeMap<SubjectName, SubjectDefinition>,
    unauthenticated_subject: Option<SubjectName>,
    rules: &[Rule],
    defined_roles: &BTreeMap<String, BTreeSet<Op>>,
) -> ResolvedPolicy {
    let rules = rules
        .iter()
        .map(|rule| {
            let ops = expand_ops(&rule.action, defined_roles);
            // Cartesian product of (each op) × (each target glob), each grant
            // tagged with its originating rule id + action-term spelling.
            let grants = rule
                .target
                .iter()
                .flat_map(|target| {
                    ops.iter().map(move |(op, action)| Grant {
                        op: *op,
                        target: target.clone(),
                        rule_id: rule.id.clone(),
                        action: action.clone(),
                    })
                })
                .collect();
            ResolvedRule {
                subjects: rule.subjects.clone(),
                grants,
            }
        })
        .collect();
    ResolvedPolicy {
        subjects,
        unauthenticated_subject,
        rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::glob::KeyGlob;

    // A minimal valid catalog + policy, with knobs to mutate per-test.
    fn catalog_json(keys: &str) -> String {
        format!(
            r#"{{
              "schemaVersion": 1,
              "backends": {{ "bao": {{ "kind": "vault", "addr": "https://127.0.0.1:8200" }} }},
              "keys": {{ {keys} }}
            }}"#
        )
    }

    const ASYM_KEY: &str = r#"
      "nats.account": {
        "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
        "path": "nats", "writable": true, "missing": "error",
        "labels": ["nats_type=A"], "description": "account key"
      }"#;

    fn policy_json(roles_body: &str, rules_array: &str) -> String {
        format!(
            r#"{{
              "schemaVersion": 2,
              "subjects": {{
                "svc.nats": {{ "allOf": [ {{ "kind": "unix", "uid": 9002 }} ] }},
                "ops.wheel": {{ "allOf": [ {{ "kind": "unix", "gid": 10 }} ] }},
                "breakglass.root": {{ "breakGlass": true, "allOf": [ {{ "kind": "unix", "uid": 0 }} ] }},
                "root.group": {{ "allOf": [ {{ "kind": "unix", "gid": 0 }} ] }},
                "public.subject": {{ "allOf": [ {{ "kind": "unix", "uid": 42 }} ] }}
              }},
              "roles": {{ {roles_body} }},
              "rules": [ {rules_array} ],
              "config": {{ "names": {{ "users": {{}}, "groups": {{}} }}, "memberships": {{}} }}
            }}"#
        )
    }

    const READER_ROLE: &str = r#""reader": ["get", "list", "get_public_key"]"#;

    // ---- Happy path ---------------------------------------------------------

    #[test]
    fn loads_valid_catalog_and_policy() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["svc.nats"], "action": ["role:reader"], "target": ["nats.account"] }"#,
        );
        let (catalog, resolved, _cfg, warnings) = load(&cat, &pol).expect("loads");
        assert_eq!(catalog.schema_version, 1);
        assert!(warnings.is_empty());
        // reader = get/list/get_public_key over nats.account, rule for uid 9002.
        let rule = resolved
            .rules
            .iter()
            .find(|r| r.subjects == ["svc.nats"])
            .expect("uid rule present");
        assert_eq!(rule.grants.len(), 3); // 3 ops × 1 target
        assert!(rule.grants.iter().all(|g| g.target.matches("nats.account")));
    }

    // ---- Catalog hard errors ------------------------------------------------

    #[test]
    fn unsupported_catalog_schema_version_is_a_hard_error() {
        // Mirror of the strict policy schemaVersion check: a future incompatible
        // catalog must fail closed at load instead of parsing silently.
        let cat = catalog_json(ASYM_KEY).replacen("\"schemaVersion\": 1", "\"schemaVersion\": 7", 1);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["svc.nats"], "action": ["role:reader"], "target": ["nats.account"] }"#,
        );
        let err = load(&cat, &pol).expect_err("catalog schemaVersion 7 refused");
        assert!(matches!(
            err,
            LoadError::UnsupportedCatalogSchema { version: 7 }
        ));
    }

    #[test]
    fn key_name_charset_is_enforced_at_load() {
        // Key names land in the text log sinks on every decision record, so a
        // name outside the documented dotted-lowercase shape (control chars
        // especially) is a fatal load error.
        for bad in [
            "nats.\naccount", // newline: the log-injection vector
            "Nats.account",   // uppercase
            "nats.acc ount",  // space
            "nats.-account",  // segment must start [a-z0-9]
            ".nats",          // empty segment
        ] {
            let key = format!(
                r#""{}": {{
                  "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
                  "path": "nats", "writable": true, "description": "bad name"
                }}"#,
                bad.replace('\n', "\\n")
            );
            let cat = catalog_json(&key);
            let pol = policy_json(READER_ROLE, "");
            assert!(
                matches!(load(&cat, &pol), Err(LoadError::BadKeyName { .. })),
                "key name {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn subject_name_with_control_char_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = r#"{
          "schemaVersion": 2,
          "subjects": { "svc.\nnats": { "allOf": [ { "kind": "unix", "uid": 9002 } ] } },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(
            load(&cat, pol),
            Err(LoadError::BadSubjectName { .. })
        ));
    }

    #[test]
    fn unknown_catalog_key_field_is_fatal() {
        // A typo'd optional field (`sealingPim` for `sealingPin`) must be a hard
        // load error: silently dropping it would load the key in its most
        // permissive state (no pin = unrestricted unseal oracle).
        let typo_key = r#"
          "seal.recipient": {
            "class": "sealing", "keyType": "ml-kem-768", "backend": "bao",
            "path": "seal", "publicPath": "seal-pub", "writable": false,
            "sealingPim": { "externalAad": ["ctx"] },
            "description": "sealing key with a typo'd pin"
          }"#;
        let cat = catalog_json(typo_key);
        let pol = policy_json(READER_ROLE, "");
        let err = load(&cat, &pol).expect_err("unknown field rejected");
        assert!(matches!(
            err,
            LoadError::Json {
                what: "catalog",
                ..
            }
        ));
    }

    #[test]
    fn unknown_policy_rule_field_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["svc.nats"], "action": ["role:reader"], "target": ["nats.account"], "targe": ["*"] }"#,
        );
        let err = load(&cat, &pol).expect_err("unknown rule field rejected");
        assert!(matches!(err, LoadError::Json { what: "policy", .. }));
    }

    #[test]
    fn unknown_subject_field_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        // `breakGlas` (typo) silently defaulting breakGlass=false must not load.
        let pol = r#"{
          "schemaVersion": 2,
          "subjects": { "svc.nats": { "breakGlas": true, "allOf": [ { "kind": "unix", "uid": 9002 } ] } },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        let err = load(&cat, pol).expect_err("unknown subject field rejected");
        assert!(matches!(err, LoadError::Json { what: "policy", .. }));
    }

    #[test]
    fn unknown_backend_is_fatal() {
        let cat = catalog_json(
            r#""k": { "class": "value", "backend": "nope", "path": "p", "writable": true, "description": "d" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::UnknownBackend { .. })
        ));
    }

    #[test]
    fn blank_description_is_fatal() {
        let cat = catalog_json(
            r#""k": { "class": "value", "backend": "bao", "path": "p", "writable": true, "description": "   " }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::BlankDescription { .. })
        ));
    }

    #[test]
    fn missing_keytype_on_asymmetric_is_fatal() {
        let cat = catalog_json(
            r#""k": { "class": "asymmetric", "backend": "bao", "path": "p", "writable": true, "description": "d" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::MissingKeyType { .. })
        ));
    }

    #[test]
    fn keytype_on_value_is_fatal() {
        let cat = catalog_json(
            r#""k": { "class": "value", "keyType": "ed25519", "backend": "bao", "path": "p", "writable": true, "description": "d" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::UnexpectedKeyType { .. })
        ));
    }

    #[test]
    fn value_generate_without_recipe_is_fatal() {
        let cat = catalog_json(
            r#""k": { "class": "value", "backend": "bao", "path": "p", "writable": true, "missing": "generate", "description": "d" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::GenerateWithoutRecipe { .. })
        ));
    }

    #[test]
    fn value_generate_with_recipe_is_ok() {
        let cat = catalog_json(
            r#""k": { "class": "value", "backend": "bao", "path": "p", "writable": true, "missing": "generate", "generate": { "format": "ascii-printable", "bytes": 24 }, "description": "d" }"#,
        );
        let pol = policy_json("", "");
        assert!(load(&cat, &pol).is_ok());
    }

    #[test]
    fn recipe_on_crypto_key_is_fatal() {
        let cat = catalog_json(
            r#""k": { "class": "symmetric", "keyType": "aes-256-gcm", "backend": "bao", "path": "p", "writable": true, "generate": { "format": "hex", "bytes": 32 }, "description": "d" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::UnexpectedGenerate { .. })
        ));
    }

    #[test]
    fn pki_engine_issue_role_is_ok() {
        let cat = catalog_json(
            r#""svid.ca": { "class": "asymmetric", "keyType": "ed25519", "backend": "bao", "engine": "pki", "path": "pki/issue/svid", "writable": false, "description": "svid issuer" }"#,
        );
        let pol = policy_json("", "");
        assert!(load(&cat, &pol).is_ok());
    }

    #[test]
    fn pki_engine_requires_issue_role_path() {
        let cat = catalog_json(
            r#""svid.ca": { "class": "asymmetric", "keyType": "ed25519", "backend": "bao", "engine": "pki", "path": "pki/cert/ca", "writable": false, "description": "svid issuer" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::InvalidPkiPath { .. })
        ));
    }

    #[test]
    fn pki_engine_requires_asymmetric_class() {
        let cat = catalog_json(
            r#""svid.ca": { "class": "public", "backend": "bao", "engine": "pki", "path": "pki/issue/svid", "writable": false, "description": "svid issuer" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::InvalidPkiPath { .. })
        ));
    }

    // ---- Value-store materialize-to-sign engine guardrail (vault-iiz) -------

    #[test]
    fn kv2_asymmetric_ed25519_signing_key_is_ok() {
        let cat = catalog_json(
            r#""kv2.signer": { "class": "asymmetric", "keyType": "ed25519", "backend": "bao", "engine": "kv2", "path": "secret/data/kv2/signer", "publicPath": "secret/data/kv2/signer-public", "writable": true, "description": "materialize-to-sign" }"#,
        );
        let pol = policy_json("", "");
        assert!(load(&cat, &pol).is_ok(), "ed25519 engine=kv2 signer loads");
    }

    #[test]
    fn kv2_asymmetric_non_ed25519_signing_key_is_rejected() {
        // An RSA key cannot route down the 32-byte-seed Ed25519 materialize path.
        let cat = catalog_json(
            r#""kv2.signer": { "class": "asymmetric", "keyType": "rsa-2048", "backend": "bao", "engine": "kv2", "path": "secret/data/kv2/signer", "writable": true, "description": "materialize-to-sign" }"#,
        );
        let pol = policy_json("", "");
        match load(&cat, &pol) {
            Err(LoadError::Kv2SigningKeyTypeNotEd25519 { key, key_type }) => {
                assert_eq!(key, "kv2.signer");
                assert_eq!(key_type, "rsa-2048");
            }
            other => panic!("rsa-2048 engine=kv2 signer must fail closed, got {other:?}"),
        }
    }

    // ---- Materialize-to-use publicPath guardrail (basil-o86) ----------------

    #[test]
    fn sealing_key_requires_public_path() {
        // A sealing key with NO publicPath fails closed: without it, wrap/
        // get_public_key would have to re-derive the public from the private.
        let cat = catalog_json(
            r#""enroll.sealing": { "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2", "path": "secret/data/enroll/x25519", "writable": true, "description": "sealing" }"#,
        );
        let pol = policy_json("", "");
        match load(&cat, &pol) {
            Err(LoadError::MissingPublicPath { key, class }) => {
                assert_eq!(key, "enroll.sealing");
                assert_eq!(class, "sealing");
            }
            other => panic!("a sealing key without publicPath must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn kv2_signing_key_requires_public_path() {
        // The materialize-to-sign sibling: an engine=kv2 Ed25519 key likewise needs
        // a publicPath so verify/get_public_key never materialize the seed.
        let cat = catalog_json(
            r#""kv2.signer": { "class": "asymmetric", "keyType": "ed25519", "backend": "bao", "engine": "kv2", "path": "secret/data/kv2/signer", "writable": true, "description": "materialize-to-sign" }"#,
        );
        let pol = policy_json("", "");
        match load(&cat, &pol) {
            Err(LoadError::MissingPublicPath { key, class }) => {
                assert_eq!(key, "kv2.signer");
                assert_eq!(class, "asymmetric");
            }
            other => panic!("a kv2 signer without publicPath must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn blank_public_path_is_rejected_on_materialize_key() {
        // A present-but-blank publicPath is as bad as absent: it resolves to no
        // KV path.
        let cat = catalog_json(
            r#""enroll.sealing": { "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2", "path": "secret/data/enroll/x25519", "publicPath": "   ", "writable": true, "description": "sealing" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::MissingPublicPath { .. })
        ));
    }

    #[test]
    fn sealing_key_with_public_path_loads() {
        let cat = catalog_json(
            r#""enroll.sealing": { "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2", "path": "secret/data/enroll/x25519", "publicPath": "secret/data/enroll/x25519-public", "writable": true, "description": "sealing" }"#,
        );
        let pol = policy_json("", "");
        assert!(
            load(&cat, &pol).is_ok(),
            "a sealing key with publicPath loads"
        );
    }

    // ---- COSE unseal-context pin guardrail (basil-2rqj) ---------------------

    #[test]
    fn sealing_key_with_pin_loads() {
        let cat = catalog_json(
            r#""enroll.sealing": { "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2", "path": "secret/data/enroll/x25519", "publicPath": "secret/data/enroll/x25519-public", "writable": true, "sealingPin": { "parties": { "partyU": "alice" }, "externalAad": ["d2h", ""] }, "description": "pinned sealing" }"#,
        );
        let pol = policy_json("", "");
        assert!(load(&cat, &pol).is_ok(), "a sealing key with a pin loads");
    }

    #[test]
    fn sealing_pin_on_non_sealing_key_is_rejected() {
        let cat = catalog_json(
            r#""web.signer": { "class": "asymmetric", "keyType": "ed25519", "backend": "bao", "path": "signer", "writable": true, "sealingPin": { "externalAad": ["ctx"] }, "description": "signer" }"#,
        );
        let pol = policy_json("", "");
        match load(&cat, &pol) {
            Err(LoadError::UnexpectedSealingPin { key, class }) => {
                assert_eq!(key, "web.signer");
                assert_eq!(class, "asymmetric");
            }
            other => panic!("a sealingPin on a non-sealing key must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn empty_sealing_pin_is_rejected() {
        let cat = catalog_json(
            r#""enroll.sealing": { "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2", "path": "secret/data/enroll/x25519", "publicPath": "secret/data/enroll/x25519-public", "writable": true, "sealingPin": {}, "description": "sealing" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::EmptySealingPin { .. })
        ));
    }

    #[test]
    fn empty_pinned_party_identity_is_rejected() {
        let cat = catalog_json(
            r#""enroll.sealing": { "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2", "path": "secret/data/enroll/x25519", "publicPath": "secret/data/enroll/x25519-public", "writable": true, "sealingPin": { "parties": { "partyU": "" } }, "description": "sealing" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::EmptyPinnedPartyIdentity { .. })
        ));
    }

    #[test]
    fn public_path_on_non_materialize_key_is_rejected() {
        // A publicPath is meaningless on a transit signing key (it uses its key in
        // place) and is rejected to keep the catalog honest.
        let cat = catalog_json(
            r#""web.signer": { "class": "asymmetric", "keyType": "ed25519", "backend": "bao", "path": "signer", "publicPath": "secret/data/signer-public", "writable": true, "description": "transit signer" }"#,
        );
        let pol = policy_json("", "");
        match load(&cat, &pol) {
            Err(LoadError::UnexpectedPublicPath { key, class }) => {
                assert_eq!(key, "web.signer");
                assert_eq!(class, "asymmetric");
            }
            other => panic!("a transit key with publicPath must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn public_path_on_value_key_is_rejected() {
        let cat = catalog_json(
            r#""app.value": { "class": "value", "backend": "bao", "engine": "kv2", "path": "secret/data/app/value", "publicPath": "secret/data/app/value-public", "writable": true, "description": "a value" }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::UnexpectedPublicPath { class: "value", .. })
        ));
    }

    // ---- JWT-SVID issuer algorithm guardrail (basil-6o4) --------------------

    #[test]
    fn jwt_svid_issuer_rsa_is_accepted() {
        let cat = catalog_json(
            r#""spire.jwt": { "class": "asymmetric", "keyType": "rsa-2048", "backend": "bao", "path": "jwt-issuer", "writable": false, "labels": ["svid_kind=jwt", "trust_domain=example.org"], "description": "JWT-SVID issuer" }"#,
        );
        let pol = policy_json("", "");
        assert!(load(&cat, &pol).is_ok(), "rsa-2048 JWT-SVID issuer loads");
    }

    #[test]
    fn jwt_svid_issuer_ed25519_is_rejected_fail_closed() {
        let cat = catalog_json(
            r#""spire.jwt": { "class": "asymmetric", "keyType": "ed25519", "backend": "bao", "path": "jwt-issuer", "writable": false, "labels": ["svid_kind=jwt", "trust_domain=example.org"], "description": "JWT-SVID issuer" }"#,
        );
        let pol = policy_json("", "");
        match load(&cat, &pol) {
            Err(LoadError::NonSpiffeJwtSvidAlg { key, key_type }) => {
                assert_eq!(key, "spire.jwt");
                assert_eq!(key_type, "ed25519");
            }
            other => panic!("ed25519 JWT-SVID issuer must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn ed25519_non_jwt_issuer_is_unaffected() {
        // The guardrail keys off the `svid_kind=jwt` label; an ed25519 key used
        // for a NATS NKey (or an X.509-SVID issuer) is untouched.
        let cat = catalog_json(ASYM_KEY); // nats.account, ed25519-nkey, no svid_kind
        let pol = policy_json("", "");
        assert!(load(&cat, &pol).is_ok());

        let x509 = catalog_json(
            r#""spire.x509": { "class": "asymmetric", "keyType": "ed25519", "backend": "bao", "engine": "pki", "path": "pki/issue/svid", "writable": false, "labels": ["svid_kind=x509", "trust_domain=example.org"], "description": "X.509-SVID issuer" }"#,
        );
        assert!(
            load(&x509, &pol).is_ok(),
            "ed25519 X.509-SVID issuer is allowed (only JWT is constrained)"
        );
    }

    #[test]
    fn pqc_reserved_provider_labels_are_allowed() {
        let cat = catalog_json(
            r#""pqc.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
              "path": "pqc-signer", "writable": true, "missing": "error",
              "labels": [
                "crypto_provider=vault-transit",
                "crypto_provider_version=1.2.3",
                "pqc_algorithm=ml-dsa-65",
                "pqc_custody=backend-native",
                "crypto_provider_policy=backend-required",
                "migration_target=pqc.signer.next",
                "free_form"
              ],
              "description": "PQC signing key metadata"
            }"#,
        );
        let pol = policy_json("", "");
        assert!(load(&cat, &pol).is_ok());
    }

    #[test]
    fn broker_key_use_reserved_label_is_validated() {
        let cat = catalog_json(
            r#""broker.response": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
              "path": "broker-response", "writable": false, "missing": "error",
              "labels": ["broker_key_use=response-signing"],
              "description": "Broker response signing key"
            }"#,
        );
        let pol = policy_json("", "");
        assert!(load(&cat, &pol).is_ok());

        let cat = catalog_json(
            r#""broker.response": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
              "path": "broker-response", "writable": false, "missing": "error",
              "labels": ["broker_key_use=maybe"],
              "description": "Broker response signing key"
            }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::InvalidReservedLabel { label, .. }) if label == "broker_key_use"
        ));
    }

    #[test]
    fn duplicate_reserved_provider_label_is_fatal() {
        let cat = catalog_json(
            r#""pqc.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
              "path": "pqc-signer", "writable": true,
              "labels": ["pqc_algorithm=ml-dsa-65", "pqc_algorithm=ml-dsa-87"],
              "description": "PQC signing key metadata"
            }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::DuplicateReservedLabel { label, .. }) if label == "pqc_algorithm"
        ));
    }

    #[test]
    fn invalid_reserved_provider_label_value_is_fatal() {
        let cat = catalog_json(
            r#""pqc.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
              "path": "pqc-signer", "writable": true,
              "labels": ["crypto_provider_policy=maybe"],
              "description": "PQC signing key metadata"
            }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::InvalidReservedLabel { label, .. })
                if label == "crypto_provider_policy"
        ));
    }

    #[test]
    fn bare_reserved_provider_label_is_fatal() {
        let cat = catalog_json(
            r#""pqc.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
              "path": "pqc-signer", "writable": true,
              "labels": ["pqc_custody"],
              "description": "PQC signing key metadata"
            }"#,
        );
        let pol = policy_json("", "");
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::InvalidReservedLabel { label, .. }) if label == "pqc_custody"
        ));
    }

    #[test]
    fn duplicate_free_form_labels_remain_allowed() {
        let cat = catalog_json(
            r#""pqc.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
              "path": "pqc-signer", "writable": true,
              "labels": ["team=identity", "team=identity"],
              "description": "PQC signing key metadata"
            }"#,
        );
        let pol = policy_json("", "");
        assert!(load(&cat, &pol).is_ok());
    }

    #[test]
    fn nkey_without_nats_type_warns_not_fails() {
        let cat = catalog_json(
            r#""nats.account": { "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao", "path": "p", "writable": true, "description": "d" }"#,
        );
        let pol = policy_json("", "");
        let (_c, _r, _cfg, warnings) = load(&cat, &pol).expect("loads with a warning");
        assert_eq!(
            warnings,
            vec![LoadWarning::MissingNatsType {
                key: "nats.account".into()
            }]
        );
    }

    // ---- Policy hard errors -------------------------------------------------

    #[test]
    fn unknown_role_reference_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["svc.nats"], "action": ["role:ghost"], "target": ["nats.account"] }"#,
        );
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::UnknownRole { .. })
        ));
    }

    #[test]
    fn intra_segment_glob_in_target_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["svc.nats"], "action": ["role:reader"], "target": ["web*"] }"#,
        );
        assert!(matches!(load(&cat, &pol), Err(LoadError::BadGlob { .. })));
    }

    #[test]
    fn glob_not_last_in_target_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["svc.nats"], "action": ["role:reader"], "target": ["user.*.ssh.authorized_keys"] }"#,
        );
        assert!(matches!(load(&cat, &pol), Err(LoadError::BadGlob { .. })));
    }

    #[test]
    fn non_root_any_target_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        // Any-key target with a non-break-glass subject.
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["svc.nats"], "action": ["role:reader"], "target": ["*"] }"#,
        );
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::NonBreakGlassAnyTarget { .. })
        ));
    }

    #[test]
    fn non_root_bare_doublestar_target_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        // A bare `**` matches every catalog key, exactly like `*`; it must be
        // subject to the same break-glass gate (it previously slipped past).
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["svc.nats"], "action": ["role:reader"], "target": ["**"] }"#,
        );
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::NonBreakGlassAnyTarget { .. })
        ));
    }

    #[test]
    fn break_glass_bare_doublestar_target_is_allowed() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["breakglass.root"], "action": ["role:reader"], "target": ["**"] }"#,
        );
        load(&cat, &pol).expect("break-glass subject may hold a bare `**` target");
    }

    #[test]
    fn group_any_target_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["root.group"], "action": ["*"], "target": ["*"] }"#,
        );
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::NonBreakGlassAnyTarget { .. })
        ));
    }

    #[test]
    fn root_any_target_is_allowed() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            "",
            r#"{ "id": "root-all", "subjects": ["breakglass.root"], "action": ["*"], "target": ["*"] }"#,
        );
        let (_c, resolved, _cfg, _w) = load(&cat, &pol).expect("root any-target loads");
        // `*` action expands to every op, each paired with the AnyKey target.
        let rule = resolved
            .rules
            .iter()
            .find(|r| r.subjects == ["breakglass.root"])
            .expect("root rule present");
        assert_eq!(rule.grants.len(), 17);
        assert!(rule.grants.iter().all(|g| g.target == KeyGlob::AnyKey));
        assert!(
            rule.grants
                .iter()
                .all(|g| g.action == "*" && g.rule_id == "root-all")
        );
    }

    #[test]
    fn undefined_subject_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["missing.subject"], "action": ["role:reader"], "target": ["nats.account"] }"#,
        );
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::UnknownSubject { .. })
        ));
    }

    #[test]
    fn empty_rule_subjects_are_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": [], "action": ["role:reader"], "target": ["nats.account"] }"#,
        );
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::EmptyRuleSubjects { .. })
        ));
    }

    #[test]
    fn empty_subject_expressions_are_fatal() {
        let cat = catalog_json(ASYM_KEY);
        for field in ["allOf", "anyOf"] {
            let pol = format!(
                r#"{{
                  "schemaVersion": 2,
                  "subjects": {{ "svc.empty": {{ "{field}": [] }} }},
                  "roles": {{ }},
                  "rules": [],
                  "config": {{ }}
                }}"#
            );
            assert!(
                matches!(load(&cat, &pol), Err(LoadError::EmptySubjectMatch { .. })),
                "{field} must reject empty lists"
            );
        }
    }

    #[test]
    fn unix_principal_requires_uid_or_gid() {
        let cat = catalog_json(ASYM_KEY);
        let pol = r#"{
          "schemaVersion": 2,
          "subjects": { "svc.bad": { "allOf": [ { "kind": "unix" } ] } },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(
            load(&cat, pol),
            Err(LoadError::EmptyUnixPrincipal { .. })
        ));
    }

    #[test]
    fn unauthenticated_principal_must_match_configured_subject() {
        let cat = catalog_json(ASYM_KEY);
        let pol = r#"{
          "schemaVersion": 2,
          "unauthenticatedSubject": "guest",
          "subjects": { "other": { "allOf": [ { "kind": "unauthenticated" } ] } },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(
            load(&cat, pol),
            Err(LoadError::InvalidUnauthenticatedPrincipal { .. })
        ));
    }

    #[test]
    fn unauthenticated_subject_must_be_defined() {
        let cat = catalog_json(ASYM_KEY);
        let pol = r#"{
          "schemaVersion": 2,
          "unauthenticatedSubject": "guest",
          "subjects": {},
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(
            load(&cat, pol),
            Err(LoadError::UnknownUnauthenticatedSubject { .. })
        ));
    }

    #[test]
    fn unsupported_principal_kind_and_signature_algorithm_are_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let bad_kind = r#"{
          "schemaVersion": 2,
          "subjects": { "svc.bad": { "allOf": [ { "kind": "process", "sha256": "00" } ] } },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(load(&cat, bad_kind), Err(LoadError::Json { .. })));

        let bad_alg = r#"{
          "schemaVersion": 2,
          "subjects": {
            "svc.bad": {
              "allOf": [ { "kind": "signature-key", "algorithm": "ssh-ed25519", "public": "x" } ]
            }
          },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(load(&cat, bad_alg), Err(LoadError::Json { .. })));
    }

    #[test]
    fn malformed_signature_key_public_material_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let bad_ed25519 = r#"{
          "schemaVersion": 2,
          "subjects": {
            "svc.bad": {
              "allOf": [ { "kind": "signature-key", "algorithm": "ed25519", "public": "not-base64url" } ]
            }
          },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(
            load(&cat, bad_ed25519),
            Err(LoadError::MalformedSignaturePublic {
                algorithm: "ed25519",
                ..
            })
        ));

        let bad_nkey = r#"{
          "schemaVersion": 2,
          "subjects": {
            "svc.bad": {
              "allOf": [ { "kind": "signature-key", "algorithm": "nats-nkey", "public": "not-an-nkey" } ]
            }
          },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(
            load(&cat, bad_nkey),
            Err(LoadError::MalformedSignaturePublic {
                algorithm: "nats-nkey",
                ..
            })
        ));
    }

    // ---- ResolvedPolicy index building --------------------------------------

    #[test]
    fn resolved_index_buckets_by_principal_kind() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            r#""signer": ["sign", "verify", "get_public_key"]"#,
            r#"
            { "id": "u", "subjects": ["svc.nats"], "action": ["op:sign"], "target": ["nats.account"] },
            { "id": "g", "subjects": ["ops.wheel"], "action": ["op:verify"], "target": ["web.**"] },
            { "id": "a", "subjects": ["public.subject"], "action": ["op:get_public_key"], "target": ["web.tls.ca_cert"] }
            "#,
        );
        let (_c, resolved, _cfg, _w) = load(&cat, &pol).expect("loads");

        let user_rule = resolved
            .rules
            .iter()
            .find(|r| r.subjects == ["svc.nats"])
            .expect("user rule present");
        assert_eq!(user_rule.grants.len(), 1);
        assert_eq!(user_rule.grants[0].op, Op::Sign);
        assert_eq!(user_rule.grants[0].rule_id, "u");
        assert_eq!(user_rule.grants[0].action, "op:sign");

        let group_rule = resolved
            .rules
            .iter()
            .find(|r| r.subjects == ["ops.wheel"])
            .expect("group rule present");
        assert_eq!(group_rule.grants.len(), 1);
        assert_eq!(group_rule.grants[0].op, Op::Verify);
        assert!(group_rule.grants[0].target.matches("web.tls.signing_key"));
        assert_eq!(group_rule.grants[0].rule_id, "g");

        let any_rule = resolved
            .rules
            .iter()
            .find(|r| r.subjects == ["public.subject"])
            .expect("any rule present");
        assert_eq!(any_rule.grants.len(), 1);
        assert_eq!(any_rule.grants[0].op, Op::GetPublicKey);
        assert_eq!(any_rule.grants[0].rule_id, "a");
    }

    #[test]
    fn resolved_index_expands_role_and_inline_ops() {
        let cat = catalog_json(ASYM_KEY);
        // role:reader (3 ops) + op:sign (1) = 4 distinct ops, deduped, × 1 target.
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "u", "subjects": ["svc.nats"], "action": ["role:reader", "op:sign"], "target": ["nats.account"] }"#,
        );
        let (_c, resolved, _cfg, _w) = load(&cat, &pol).expect("loads");
        let rule = resolved
            .rules
            .iter()
            .find(|r| r.subjects == ["svc.nats"])
            .expect("user rule present");
        let ops: BTreeSet<Op> = rule.grants.iter().map(|g| g.op).collect();
        assert_eq!(
            ops,
            BTreeSet::from([Op::Get, Op::List, Op::GetPublicKey, Op::Sign])
        );
    }

    #[test]
    fn resolved_index_cartesian_over_multiple_targets() {
        let cat = catalog_json(ASYM_KEY);
        // 1 op × 2 targets = 2 grants.
        let pol = policy_json(
            "",
            r#"{ "id": "u", "subjects": ["svc.nats"], "action": ["op:get"], "target": ["a.b", "c.d"] }"#,
        );
        let (_c, resolved, _cfg, _w) = load(&cat, &pol).expect("loads");
        let rule = resolved
            .rules
            .iter()
            .find(|r| r.subjects == ["svc.nats"])
            .expect("user rule present");
        assert_eq!(rule.grants.len(), 2);
    }

    #[test]
    fn config_tables_round_trip() {
        let cat = catalog_json(ASYM_KEY);
        let pol = format!(
            r#"{{
              "roles": {{ {READER_ROLE} }},
              "rules": [],
              "config": {{
                "names": {{ "users": {{ "9002": "svc-nats" }}, "groups": {{ "10": "wheel" }} }},
                "memberships": {{ "9002": [9002, 10] }}
              }}
            }}"#
        );
        let (_c, _r, cfg, _w) = load(&cat, &pol).expect("loads");
        assert_eq!(cfg.user_name_num(9002), "svc-nats(9002)");
        assert_eq!(cfg.group_name_num(10), "wheel(10)");
        assert_eq!(cfg.groups_of(9002), Some(&BTreeSet::from([9002, 10])));
    }

    #[test]
    fn malformed_json_is_reported_per_document() {
        let bad = "{ not json";
        let good_pol = policy_json("", "");
        match load(bad, &good_pol) {
            Err(LoadError::Json { what, .. }) => assert_eq!(what, "catalog"),
            other => panic!("expected catalog JSON error, got {other:?}"),
        }
        let good_cat = catalog_json(ASYM_KEY);
        match load(&good_cat, bad) {
            Err(LoadError::Json { what, .. }) => assert_eq!(what, "policy"),
            other => panic!("expected policy JSON error, got {other:?}"),
        }
    }
}
