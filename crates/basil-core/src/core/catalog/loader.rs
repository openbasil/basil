// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Loader: parse + validate the exported catalog & policy JSON, and build the
//! ready-for-PDP [`ResolvedPolicy`] index (design §5, §6).
//!
//! [`load`] is the single entry point. It validates **all** of §5's hard errors
//! up front so a bad export fails fast at startup rather than at request time.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read as _;
use std::marker::PhantomData;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use super::evidence::{
    AuthorizationDomain, ComposeProjectSelector, ComposeServiceSelector, ContainerRuntimeKind,
    CredentialSlot, EvidenceExpression, EvidencePredicate, IdentitySelector, LocalAccountSource,
    MAX_EXPRESSION_DEPTH, MAX_EXPRESSION_LEAVES, SystemdSelector,
};
use super::glob::{GlobError, KeyGlob};
use super::policy::{
    ALL_OPS, ActionTerm, ActionTermError, Config, Grant, Op, ResolvedPolicy, ResolvedRule, Rule,
    SignatureKeyAlgorithm, SubjectDefinition, SubjectName,
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
    /// A valid subject expression exceeds the human-auditability warning threshold.
    ComplexSubjectExpression {
        /// Subject name.
        subject: SubjectName,
        /// Recursive group nesting depth.
        depth: usize,
        /// Leaf predicate count.
        leaves: usize,
    },
}

impl std::fmt::Display for LoadWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingNatsType { key } => write!(
                f,
                "ed25519-nkey key `{key}` has no nats_type label; mint will fail for it"
            ),
            Self::ComplexSubjectExpression {
                subject,
                depth,
                leaves,
            } => write!(
                f,
                "subject `{subject}` expression has depth {depth} and {leaves} leaves; review policies above depth 4 or 16 leaves"
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

    /// Strict schema-3 parsing rejected an unambiguous catalog-v1 document.
    #[error(
        "catalog-v1 input is not accepted by corpus schema 3; add `schema = catalog` and migrate the complete corpus"
    )]
    LegacyCatalogV1,

    /// Strict schema-3 parsing rejected an unambiguous policy-v2 document.
    #[error(
        "policy-v2 input is not accepted by corpus schema 3; add `schema = policy` and migrate the complete corpus"
    )]
    LegacyPolicyV2,

    /// A subject name is empty after trimming.
    #[error("subject name must not be empty")]
    EmptySubjectName,

    /// A subject name exceeds the audit-safe byte ceiling.
    #[error("subject name exceeds the 128-byte limit ({bytes} bytes)")]
    SubjectNameTooLong {
        /// Observed UTF-8 byte length.
        bytes: usize,
    },

    /// A subject definition did not contain a valid recursive expression.
    #[error("subject `{subject}` has invalid evidence expression: {reason}")]
    InvalidSubjectShape {
        /// The offending subject name.
        subject: String,
        /// Bounded, disclosure-safe structural reason.
        reason: String,
    },

    /// A recursive expression exceeded a hard complexity limit.
    #[error(
        "subject `{subject}` evidence expression exceeds limits: depth {depth}/{max_depth}, leaves {leaves}/{max_leaves}"
    )]
    SubjectExpressionTooComplex {
        /// Subject name.
        subject: String,
        /// Observed recursive group depth.
        depth: usize,
        /// Maximum permitted recursive group depth.
        max_depth: usize,
        /// Observed leaf count.
        leaves: usize,
        /// Maximum permitted leaf count.
        max_leaves: usize,
    },

    /// A predicate is invalid in the subject's declared domain.
    #[error("subject `{subject}` predicate `{predicate}` is not valid in domain `{domain}`")]
    PredicateDomainMismatch {
        /// Subject name.
        subject: String,
        /// Namespaced predicate token.
        predicate: &'static str,
        /// Domain token.
        domain: &'static str,
    },

    /// A symbolic process identity was used outside the host-process domain.
    #[error(
        "subject `{subject}` uses symbolic `{predicate}` in domain `{domain}`; use the observed numeric process credential"
    )]
    SymbolicProcessIdentity {
        /// Subject name.
        subject: String,
        /// Namespaced predicate token.
        predicate: &'static str,
        /// Declared authorization domain.
        domain: &'static str,
    },

    /// A symbolic local account could not be resolved strictly.
    #[error("subject `{subject}` cannot resolve local account `{account}`: {reason}")]
    LocalAccountResolution {
        /// Subject name.
        subject: String,
        /// Escaped symbolic account name.
        account: String,
        /// Bounded resolution failure.
        reason: &'static str,
    },

    /// A local account database could not be loaded atomically.
    #[error("cannot load local account database `{path}`: {reason}")]
    LocalAccountDatabase {
        /// Fixed local database path.
        path: &'static str,
        /// Bounded failure reason.
        reason: &'static str,
    },

    /// A signature predicate has empty public key material.
    #[error("subject `{subject}` has a signature-key predicate with empty public key material")]
    EmptySignaturePublic {
        /// The offending subject name.
        subject: String,
    },

    /// A signature predicate has malformed public key material.
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

    /// Two rules used the same stable audit id. Rule provenance must be
    /// unambiguous in `decide`/`explain` output and audit records.
    #[error("duplicate policy rule id `{rule}`")]
    DuplicateRuleId {
        /// The duplicated rule id.
        rule: String,
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
    /// Required corpus-slot discriminator.
    pub schema: PolicySchema,
    /// Named subject registry.
    #[serde(
        default,
        deserialize_with = "deserialize_unique_btree_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub subjects: BTreeMap<SubjectName, RawSubjectDefinition>,
    /// Named role → op-set table; an action `role:<name>` expands to its ops.
    #[serde(
        default,
        deserialize_with = "deserialize_unique_btree_map",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub roles: BTreeMap<String, BTreeSet<Op>>,
    /// The allow-rules (default-deny is the absence of a match).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<RawRule>,
    /// Export-resolved name/membership tables (§4).
    #[serde(default)]
    pub config: Config,
}

/// The only discriminator accepted in the policy slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum PolicySchema {
    /// A policy document governed by the bootstrap's corpus version.
    #[serde(rename = "policy")]
    Policy,
}

fn deserialize_unique_btree_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + Ord + std::fmt::Display,
    V: Deserialize<'de>,
{
    struct UniqueMapVisitor<K, V>(PhantomData<(K, V)>);

    impl<'de, K, V> Visitor<'de> for UniqueMapVisitor<K, V>
    where
        K: Deserialize<'de> + Ord + std::fmt::Display,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON object with unique keys")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut map = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<K, V>()? {
                match map.entry(key) {
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        slot.insert(value);
                    }
                    std::collections::btree_map::Entry::Occupied(slot) => {
                        return Err(de::Error::custom(format!(
                            "duplicate policy key `{}`",
                            slot.key()
                        )));
                    }
                }
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(UniqueMapVisitor(PhantomData))
}

/// One raw domain-scoped subject definition.
///
/// Unknown fields fail closed: a typo'd `breakGlass` silently defaulting to
/// `false` would be caught by the any-target gate, but the same class of typo
/// on future fields must never load as a permissive default.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawSubjectDefinition {
    /// Mandatory disjoint workload domain.
    pub domain: AuthorizationDomain,
    /// Whether this subject is eligible for rules targeting global `*`.
    #[serde(rename = "breakGlass", default, skip_serializing_if = "is_false")]
    pub break_glass: bool,
    /// Recursive monotonic evidence expression.
    #[serde(rename = "match")]
    pub match_: RawEvidenceExpression,
}

/// Raw recursive expression retained as JSON until strict semantic compilation.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct RawEvidenceExpression(pub serde_json::Value);

impl<'de> Deserialize<'de> for RawEvidenceExpression {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor).map(Self)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| de::Error::custom("non-finite evidence number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(value.into())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(serde_json::Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(Self)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element_seed(UniqueValueSeed)? {
            values.push(value);
        }
        Ok(serde_json::Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::with_capacity(object.size_hint().unwrap_or(0));
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate evidence key `{key}`")));
            }
            let value = object.next_value_seed(UniqueValueSeed)?;
            values.insert(key, value);
        }
        Ok(serde_json::Value::Object(values))
    }
}

struct UniqueValueSeed;

impl<'de> DeserializeSeed<'de> for UniqueValueSeed {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
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

/// Load and validate canonical JSON projections of corpus-schema-3 catalog and
/// policy documents.
///
/// Returns the parsed [`Catalog`], the ready-for-PDP [`ResolvedPolicy`] index,
/// and the [`Config`] tables, plus any non-fatal [`LoadWarning`]s. Validates the
/// full §5 hard-error list; the first hard error aborts the load.
pub fn load(
    catalog_json: &str,
    policy_json: &str,
) -> Result<(Catalog, ResolvedPolicy, Config, Vec<LoadWarning>), LoadError> {
    let catalog: Catalog = serde_json::from_str(catalog_json)
        .map_err(|source| classify_catalog_parse_error(catalog_json, source))?;
    let raw_policy: RawPolicy = serde_json::from_str(policy_json)
        .map_err(|source| classify_policy_parse_error(policy_json, source))?;

    let mut warnings = validate_catalog(&catalog)?;
    let (subjects, subject_warnings) = parse_subjects(raw_policy.subjects)?;
    warnings.extend(subject_warnings);
    let rules = parse_rules(raw_policy.rules, &subjects)?;
    validate_rule_roles(&rules, &raw_policy.roles)?;
    let resolved = build_resolved(subjects, &rules, &raw_policy.roles);

    Ok((catalog, resolved, raw_policy.config, warnings))
}

fn classify_catalog_parse_error(raw: &str, source: serde_json::Error) -> LoadError {
    let legacy = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .is_some_and(|object| {
            object.get("schema").is_none()
                && object
                    .get("schemaVersion")
                    .and_then(serde_json::Value::as_u64)
                    == Some(1)
                && object
                    .get("backends")
                    .is_some_and(serde_json::Value::is_object)
                && object.get("keys").is_some_and(serde_json::Value::is_object)
        });
    if legacy {
        LoadError::LegacyCatalogV1
    } else {
        LoadError::Json {
            what: "catalog",
            source,
        }
    }
}

fn classify_policy_parse_error(raw: &str, source: serde_json::Error) -> LoadError {
    let legacy = serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .is_some_and(|object| {
            object.get("schema").is_none()
                && object
                    .get("schemaVersion")
                    .and_then(serde_json::Value::as_u64)
                    == Some(2)
                && object
                    .get("subjects")
                    .is_some_and(serde_json::Value::is_object)
                && object.get("rules").is_some_and(serde_json::Value::is_array)
        });
    if legacy {
        LoadError::LegacyPolicyV2
    } else {
        LoadError::Json {
            what: "policy",
            source,
        }
    }
}

// ---- Catalog validation (§2, §5) --------------------------------------------

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

fn parse_subjects(
    raw: BTreeMap<SubjectName, RawSubjectDefinition>,
) -> Result<(BTreeMap<SubjectName, SubjectDefinition>, Vec<LoadWarning>), LoadError> {
    let mut accounts = None;
    let mut subjects = BTreeMap::new();
    let mut warnings = Vec::new();
    for (name, subject) in raw {
        let (name, subject) = parse_subject(&name, &subject, &mut accounts)?;
        let depth = subject.match_.depth();
        let leaves = subject.match_.leaf_count();
        if depth > 4 || leaves > 16 {
            warnings.push(LoadWarning::ComplexSubjectExpression {
                subject: name.clone(),
                depth,
                leaves,
            });
        }
        subjects.insert(name, subject);
    }
    Ok((subjects, warnings))
}

fn parse_subject(
    name: &str,
    raw: &RawSubjectDefinition,
    accounts: &mut Option<LocalAccounts>,
) -> Result<(SubjectName, SubjectDefinition), LoadError> {
    let normalized = name.trim();
    if normalized.is_empty() {
        return Err(LoadError::EmptySubjectName);
    }
    if normalized.len() > 128 {
        return Err(LoadError::SubjectNameTooLong {
            bytes: normalized.len(),
        });
    }
    // Subject names are logged on every decision record; a control character
    // (newline, ESC) could forge lines in the text tracing sinks.
    if normalized.chars().any(char::is_control) {
        return Err(LoadError::BadSubjectName {
            subject: normalized.chars().flat_map(char::escape_default).collect(),
        });
    }
    let match_ = compile_expression(normalized, raw.domain, &raw.match_.0, accounts)?;
    let depth = match_.depth();
    let leaves = match_.leaf_count();
    if depth > MAX_EXPRESSION_DEPTH || leaves > MAX_EXPRESSION_LEAVES {
        return Err(LoadError::SubjectExpressionTooComplex {
            subject: normalized.to_string(),
            depth,
            max_depth: MAX_EXPRESSION_DEPTH,
            leaves,
            max_leaves: MAX_EXPRESSION_LEAVES,
        });
    }
    Ok((
        normalized.to_string(),
        SubjectDefinition {
            domain: raw.domain,
            break_glass: raw.break_glass,
            match_,
        },
    ))
}

fn compile_expression(
    subject: &str,
    domain: AuthorizationDomain,
    value: &serde_json::Value,
    accounts: &mut Option<LocalAccounts>,
) -> Result<EvidenceExpression, LoadError> {
    let mut leaves = 0;
    compile_expression_node(subject, domain, value, accounts, 0, &mut leaves)
}

fn compile_expression_node(
    subject: &str,
    domain: AuthorizationDomain,
    value: &serde_json::Value,
    accounts: &mut Option<LocalAccounts>,
    group_depth: usize,
    leaves: &mut usize,
) -> Result<EvidenceExpression, LoadError> {
    let Some(object) = value.as_object() else {
        return invalid_expression(
            subject,
            "expected an object with exactly one operator or leaf",
        );
    };
    if object.len() != 1 {
        return invalid_expression(subject, "each expression node must contain exactly one key");
    }
    let Some((key, value)) = object.iter().next() else {
        return invalid_expression(subject, "expression node must not be empty");
    };
    match key.as_str() {
        "all" | "any" => {
            let next_depth = group_depth.saturating_add(1);
            if next_depth > MAX_EXPRESSION_DEPTH {
                return Err(LoadError::SubjectExpressionTooComplex {
                    subject: subject.to_string(),
                    depth: next_depth,
                    max_depth: MAX_EXPRESSION_DEPTH,
                    leaves: *leaves,
                    max_leaves: MAX_EXPRESSION_LEAVES,
                });
            }
            let Some(children) = value.as_array() else {
                return invalid_expression(subject, "`all` and `any` values must be arrays");
            };
            if children.is_empty() {
                return invalid_expression(subject, "`all` and `any` groups must not be empty");
            }
            let compiled = children
                .iter()
                .map(|child| {
                    compile_expression_node(subject, domain, child, accounts, next_depth, leaves)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if key == "all" {
                Ok(EvidenceExpression::All(compiled))
            } else {
                Ok(EvidenceExpression::Any(compiled))
            }
        }
        _ => {
            *leaves = leaves.saturating_add(1);
            if *leaves > MAX_EXPRESSION_LEAVES {
                return Err(LoadError::SubjectExpressionTooComplex {
                    subject: subject.to_string(),
                    depth: group_depth,
                    max_depth: MAX_EXPRESSION_DEPTH,
                    leaves: *leaves,
                    max_leaves: MAX_EXPRESSION_LEAVES,
                });
            }
            let predicate = compile_predicate(subject, domain, key, value, accounts)?;
            Ok(EvidenceExpression::Leaf(predicate))
        }
    }
}

fn invalid_expression<T>(subject: &str, reason: &str) -> Result<T, LoadError> {
    Err(LoadError::InvalidSubjectShape {
        subject: subject.to_string(),
        reason: reason.to_string(),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the strict one-key predicate decoder keeps the accepted namespace in one exhaustive match"
)]
fn compile_predicate(
    subject: &str,
    domain: AuthorizationDomain,
    key: &str,
    value: &serde_json::Value,
    accounts: &mut Option<LocalAccounts>,
) -> Result<EvidencePredicate, LoadError> {
    let predicate = match key {
        "process.uid" => EvidencePredicate::ProcessUid(compile_identity(
            subject,
            domain,
            "process.uid",
            value,
            LocalAccountSource::Passwd,
            accounts,
        )?),
        "process.uid.real" => process_uid_slot(
            subject,
            domain,
            "process.uid.real",
            value,
            CredentialSlot::Real,
            accounts,
        )?,
        "process.uid.effective" => process_uid_slot(
            subject,
            domain,
            "process.uid.effective",
            value,
            CredentialSlot::Effective,
            accounts,
        )?,
        "process.uid.saved" => process_uid_slot(
            subject,
            domain,
            "process.uid.saved",
            value,
            CredentialSlot::Saved,
            accounts,
        )?,
        "process.uid.filesystem" => process_uid_slot(
            subject,
            domain,
            "process.uid.filesystem",
            value,
            CredentialSlot::Filesystem,
            accounts,
        )?,
        "process.gid" => EvidencePredicate::ProcessGid(compile_identity(
            subject,
            domain,
            "process.gid",
            value,
            LocalAccountSource::Group,
            accounts,
        )?),
        "process.gid.real" => process_gid_slot(
            subject,
            domain,
            "process.gid.real",
            value,
            CredentialSlot::Real,
            accounts,
        )?,
        "process.gid.effective" => process_gid_slot(
            subject,
            domain,
            "process.gid.effective",
            value,
            CredentialSlot::Effective,
            accounts,
        )?,
        "process.gid.saved" => process_gid_slot(
            subject,
            domain,
            "process.gid.saved",
            value,
            CredentialSlot::Saved,
            accounts,
        )?,
        "process.gid.filesystem" => process_gid_slot(
            subject,
            domain,
            "process.gid.filesystem",
            value,
            CredentialSlot::Filesystem,
            accounts,
        )?,
        "process.gid.supplementary" => {
            EvidencePredicate::ProcessGidSupplementary(compile_identity(
                subject,
                domain,
                "process.gid.supplementary",
                value,
                LocalAccountSource::Group,
                accounts,
            )?)
        }
        "process.executable.digest" => {
            let digest = required_string(subject, value, "executable digest")?;
            if !valid_sha256_digest(&digest) {
                return invalid_expression(
                    subject,
                    "`process.executable.digest` must be `sha256:` plus 64 lowercase hex digits",
                );
            }
            EvidencePredicate::ProcessExecutableDigest(digest)
        }
        "systemd.unit" => EvidencePredicate::SystemdUnit(compile_systemd_selector(
            subject, value, false, accounts,
        )?),
        "systemd.template" => EvidencePredicate::SystemdTemplate(compile_systemd_selector(
            subject, value, true, accounts,
        )?),
        "compose.service" => {
            EvidencePredicate::ComposeService(compile_compose_service(subject, value)?)
        }
        "compose.project" => {
            EvidencePredicate::ComposeProject(compile_compose_project(subject, value)?)
        }
        "runtime.kind" => {
            let runtime = required_string(subject, value, "runtime kind")?;
            let runtime = match runtime.as_str() {
                "docker" => ContainerRuntimeKind::Docker,
                "podman" => ContainerRuntimeKind::Podman,
                _ => return invalid_expression(subject, "unknown `runtime.kind` value"),
            };
            EvidencePredicate::RuntimeKind(runtime)
        }
        "oci.signer" => EvidencePredicate::OciSigner(required_bounded_string(
            subject,
            value,
            "OCI signer policy",
        )?),
        "invocation.signature-key" => compile_signature_key(subject, value)?,
        _ => return invalid_expression(subject, "unknown evidence predicate"),
    };
    validate_predicate_domain(subject, domain, key, &predicate)?;
    Ok(predicate)
}

fn process_uid_slot(
    subject: &str,
    domain: AuthorizationDomain,
    key: &'static str,
    value: &serde_json::Value,
    slot: CredentialSlot,
    accounts: &mut Option<LocalAccounts>,
) -> Result<EvidencePredicate, LoadError> {
    Ok(EvidencePredicate::ProcessUidSlot(
        slot,
        compile_identity(
            subject,
            domain,
            key,
            value,
            LocalAccountSource::Passwd,
            accounts,
        )?,
    ))
}

fn process_gid_slot(
    subject: &str,
    domain: AuthorizationDomain,
    key: &'static str,
    value: &serde_json::Value,
    slot: CredentialSlot,
    accounts: &mut Option<LocalAccounts>,
) -> Result<EvidencePredicate, LoadError> {
    Ok(EvidencePredicate::ProcessGidSlot(
        slot,
        compile_identity(
            subject,
            domain,
            key,
            value,
            LocalAccountSource::Group,
            accounts,
        )?,
    ))
}

fn compile_identity(
    subject: &str,
    domain: AuthorizationDomain,
    predicate: &'static str,
    value: &serde_json::Value,
    source: LocalAccountSource,
    accounts: &mut Option<LocalAccounts>,
) -> Result<IdentitySelector, LoadError> {
    if let Some(id) = value.as_u64() {
        return u32::try_from(id)
            .map(IdentitySelector::Numeric)
            .map_err(|_| LoadError::LocalAccountResolution {
                subject: subject.to_string(),
                account: "numeric-id".to_string(),
                reason: "numeric identifier is out of range",
            });
    }
    let Some(name) = value.as_str() else {
        return invalid_expression(
            subject,
            "process identities must be integers or local names",
        );
    };
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return invalid_expression(subject, "local account name is empty, too long, or unsafe");
    }
    if name.parse::<i128>().is_ok() {
        return invalid_expression(subject, "numeric-looking identity strings are invalid");
    }
    if domain != AuthorizationDomain::HostProcess && predicate != "systemd.managerUser" {
        return Err(LoadError::SymbolicProcessIdentity {
            subject: subject.to_string(),
            predicate,
            domain: domain_token(domain),
        });
    }
    if accounts.is_none() {
        *accounts = Some(LocalAccounts::load()?);
    }
    let Some(local) = accounts.as_ref() else {
        return Err(LoadError::LocalAccountDatabase {
            path: "/etc/passwd",
            reason: "account database state unavailable",
        });
    };
    let id = match source {
        LocalAccountSource::Passwd => local.users.get(name),
        LocalAccountSource::Group => local.groups.get(name),
    }
    .copied()
    .ok_or_else(|| LoadError::LocalAccountResolution {
        subject: subject.to_string(),
        account: name.chars().flat_map(char::escape_default).collect(),
        reason: "name is missing from the local account database",
    })?;
    Ok(IdentitySelector::LocalName {
        name: name.to_string(),
        id,
        source,
    })
}

fn compile_systemd_selector(
    subject: &str,
    value: &serde_json::Value,
    template: bool,
    accounts: &mut Option<LocalAccounts>,
) -> Result<SystemdSelector, LoadError> {
    let Some(object) = value.as_object() else {
        return invalid_expression(subject, "systemd predicate must be an object");
    };
    if object
        .keys()
        .any(|key| key != "name" && key != "managerUser")
        || object.len() > 2
    {
        return invalid_expression(subject, "systemd predicate contains unknown fields");
    }
    let Some(name) = object.get("name").and_then(serde_json::Value::as_str) else {
        return invalid_expression(subject, "systemd predicate requires string `name`");
    };
    if !valid_systemd_service_name(name, template) {
        return invalid_expression(subject, "systemd name must be a canonical `.service` unit");
    }
    let manager_user = object
        .get("managerUser")
        .map(|value| {
            compile_identity(
                subject,
                AuthorizationDomain::SystemdUnit,
                "systemd.managerUser",
                value,
                LocalAccountSource::Passwd,
                accounts,
            )
        })
        .transpose()?;
    Ok(SystemdSelector {
        name: name.to_string(),
        manager_user,
    })
}

fn valid_systemd_service_name(name: &str, template: bool) -> bool {
    if name.is_empty() || name.len() > 255 || name.chars().any(char::is_control) {
        return false;
    }
    let Some(stem) = name.strip_suffix(".service") else {
        return false;
    };
    let mut parts = stem.split('@');
    let Some(base) = parts.next() else {
        return false;
    };
    let instance = parts.next();
    if parts.next().is_some() || !valid_systemd_name_component(base) {
        return false;
    }
    if template {
        instance == Some("")
    } else {
        instance.is_none_or(valid_systemd_name_component)
    }
}

fn valid_systemd_name_component(component: &str) -> bool {
    if component.is_empty() {
        return false;
    }
    let bytes = component.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let Some(byte) = bytes.get(offset).copied() else {
            break;
        };
        if byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'-') {
            offset += 1;
            continue;
        }
        if !matches!(
            bytes.get(offset..offset.saturating_add(4)),
            Some([b'\\', b'x', high, low]) if is_lower_hex(*high) && is_lower_hex(*low)
        ) {
            return false;
        }
        offset += 4;
    }
    true
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn compile_compose_service(
    subject: &str,
    value: &serde_json::Value,
) -> Result<ComposeServiceSelector, LoadError> {
    let object = exact_object(subject, value, &["realm", "project", "name"])?;
    Ok(ComposeServiceSelector {
        realm: required_object_string(subject, object, "realm")?,
        project: required_object_string(subject, object, "project")?,
        name: required_object_string(subject, object, "name")?,
    })
}

fn compile_compose_project(
    subject: &str,
    value: &serde_json::Value,
) -> Result<ComposeProjectSelector, LoadError> {
    let object = exact_object(subject, value, &["realm", "project"])?;
    Ok(ComposeProjectSelector {
        realm: required_object_string(subject, object, "realm")?,
        project: required_object_string(subject, object, "project")?,
    })
}

fn exact_object<'a>(
    subject: &str,
    value: &'a serde_json::Value,
    fields: &[&str],
) -> Result<&'a serde_json::Map<String, serde_json::Value>, LoadError> {
    let Some(object) = value.as_object() else {
        return invalid_expression(subject, "compound predicate must be an object");
    };
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return invalid_expression(
            subject,
            "compound predicate fields are incomplete or unknown",
        );
    }
    Ok(object)
}

fn required_object_string(
    subject: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<String, LoadError> {
    let Some(value) = object.get(field).and_then(serde_json::Value::as_str) else {
        return invalid_expression(subject, "compound predicate fields must be strings");
    };
    if !valid_bounded_text(value) {
        return invalid_expression(
            subject,
            "compound predicate string is empty, too long, or unsafe",
        );
    }
    Ok(value.to_string())
}

fn required_string(
    subject: &str,
    value: &serde_json::Value,
    _field: &str,
) -> Result<String, LoadError> {
    value
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| LoadError::InvalidSubjectShape {
            subject: subject.to_string(),
            reason: "predicate value must be a string".to_string(),
        })
}

fn required_bounded_string(
    subject: &str,
    value: &serde_json::Value,
    field: &str,
) -> Result<String, LoadError> {
    let value = required_string(subject, value, field)?;
    if !valid_bounded_text(&value) {
        return invalid_expression(subject, "predicate string is empty, too long, or unsafe");
    }
    Ok(value)
}

fn valid_bounded_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn compile_signature_key(
    subject: &str,
    value: &serde_json::Value,
) -> Result<EvidencePredicate, LoadError> {
    let object = exact_object(subject, value, &["algorithm", "public"])?;
    let algorithm = match object.get("algorithm").and_then(serde_json::Value::as_str) {
        Some("ed25519") => SignatureKeyAlgorithm::Ed25519,
        Some("nats-nkey") => SignatureKeyAlgorithm::NatsNkey,
        _ => return invalid_expression(subject, "unknown signature-key algorithm"),
    };
    let Some(public) = object.get("public").and_then(serde_json::Value::as_str) else {
        return invalid_expression(subject, "signature-key `public` must be a string");
    };
    if public.trim().is_empty() {
        return Err(LoadError::EmptySignaturePublic {
            subject: subject.to_string(),
        });
    }
    validate_signature_public(subject, algorithm, public)?;
    Ok(EvidencePredicate::InvocationSignatureKey {
        algorithm,
        public: public.to_string(),
    })
}

fn validate_predicate_domain(
    subject: &str,
    domain: AuthorizationDomain,
    key: &str,
    predicate: &EvidencePredicate,
) -> Result<(), LoadError> {
    let valid = match predicate {
        EvidencePredicate::ComposeService(_)
        | EvidencePredicate::ComposeProject(_)
        | EvidencePredicate::RuntimeKind(_)
        | EvidencePredicate::OciSigner(_) => domain == AuthorizationDomain::Container,
        EvidencePredicate::SystemdUnit(_) | EvidencePredicate::SystemdTemplate(_) => {
            domain != AuthorizationDomain::HostProcess
        }
        EvidencePredicate::ProcessUid(_)
        | EvidencePredicate::ProcessUidSlot(_, _)
        | EvidencePredicate::ProcessGid(_)
        | EvidencePredicate::ProcessGidSlot(_, _)
        | EvidencePredicate::ProcessGidSupplementary(_)
        | EvidencePredicate::ProcessExecutableDigest(_)
        | EvidencePredicate::InvocationSignatureKey { .. } => true,
    };
    if valid {
        Ok(())
    } else {
        Err(LoadError::PredicateDomainMismatch {
            subject: subject.to_string(),
            predicate: predicate_token(key),
            domain: domain_token(domain),
        })
    }
}

const fn domain_token(domain: AuthorizationDomain) -> &'static str {
    match domain {
        AuthorizationDomain::HostProcess => "host-process",
        AuthorizationDomain::SystemdUnit => "systemd-unit",
        AuthorizationDomain::Container => "container",
    }
}

fn predicate_token(key: &str) -> &'static str {
    match key {
        "compose.service" => "compose.service",
        "compose.project" => "compose.project",
        "runtime.kind" => "runtime.kind",
        "oci.signer" => "oci.signer",
        "systemd.unit" => "systemd.unit",
        "systemd.template" => "systemd.template",
        _ => "evidence",
    }
}

#[derive(Debug)]
struct LocalAccounts {
    users: BTreeMap<String, u32>,
    groups: BTreeMap<String, u32>,
}

impl LocalAccounts {
    fn load() -> Result<Self, LoadError> {
        let passwd = read_stable_account_file("/etc/passwd")?;
        let group = read_stable_account_file("/etc/group")?;
        Ok(Self {
            users: parse_account_file(&passwd, 7, 2, "/etc/passwd")?,
            groups: parse_account_file(&group, 4, 2, "/etc/group")?,
        })
    }
}

const MAX_ACCOUNT_FILE_BYTES: u64 = 1024 * 1024;

fn read_stable_account_file(path: &'static str) -> Result<String, LoadError> {
    let mut file = File::open(Path::new(path)).map_err(|_| LoadError::LocalAccountDatabase {
        path,
        reason: "file is unavailable",
    })?;
    let before = file
        .metadata()
        .map_err(|_| LoadError::LocalAccountDatabase {
            path,
            reason: "metadata is unavailable",
        })?;
    if before.len() > MAX_ACCOUNT_FILE_BYTES {
        return Err(LoadError::LocalAccountDatabase {
            path,
            reason: "file exceeds the 1 MiB limit",
        });
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_ACCOUNT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LoadError::LocalAccountDatabase {
            path,
            reason: "file read failed",
        })?;
    let after = file
        .metadata()
        .map_err(|_| LoadError::LocalAccountDatabase {
            path,
            reason: "post-read metadata is unavailable",
        })?;
    let path_after =
        std::fs::metadata(Path::new(path)).map_err(|_| LoadError::LocalAccountDatabase {
            path,
            reason: "post-read path metadata is unavailable",
        })?;
    let stable_time = before
        .modified()
        .ok()
        .zip(after.modified().ok())
        .zip(path_after.modified().ok())
        .is_some_and(|((before_time, after_time), path_time)| {
            before_time == after_time && after_time == path_time
        });
    let stable_identity = before.dev() == after.dev()
        && after.dev() == path_after.dev()
        && before.ino() == after.ino()
        && after.ino() == path_after.ino();
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || after.len() != path_after.len()
        || !stable_identity
        || !stable_time
    {
        return Err(LoadError::LocalAccountDatabase {
            path,
            reason: "file changed while it was read",
        });
    }
    String::from_utf8(bytes).map_err(|_| LoadError::LocalAccountDatabase {
        path,
        reason: "file is not valid UTF-8",
    })
}

fn parse_account_file(
    contents: &str,
    field_count: usize,
    id_index: usize,
    path: &'static str,
) -> Result<BTreeMap<String, u32>, LoadError> {
    let mut entries = BTreeMap::new();
    for line in contents.lines() {
        if line.is_empty() {
            continue;
        }
        let fields = line.split(':').collect::<Vec<_>>();
        let Some(name) = fields.first().copied() else {
            return Err(LoadError::LocalAccountDatabase {
                path,
                reason: "file contains a malformed entry",
            });
        };
        let Some(id) = fields
            .get(id_index)
            .and_then(|value| value.parse::<u32>().ok())
        else {
            return Err(LoadError::LocalAccountDatabase {
                path,
                reason: "file contains a malformed or out-of-range identifier",
            });
        };
        if fields.len() != field_count
            || name.is_empty()
            || name.len() > 128
            || name.chars().any(char::is_control)
            || entries.insert(name.to_string(), id).is_some()
        {
            return Err(LoadError::LocalAccountDatabase {
                path,
                reason: "file contains a malformed or duplicate account name",
            });
        }
    }
    Ok(entries)
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
    let mut seen = BTreeSet::new();
    raw.into_iter()
        .map(|rule| {
            if !seen.insert(rule.id.clone()) {
                return Err(LoadError::DuplicateRuleId { rule: rule.id });
            }
            parse_rule(rule, subjects)
        })
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
    ResolvedPolicy { subjects, rules }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::glob::KeyGlob;

    // A minimal valid catalog + policy, with knobs to mutate per-test.
    fn catalog_json(keys: &str) -> String {
        format!(
            r#"{{
              "schema": "catalog",
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
              "schema": "policy",
              "subjects": {{
                "svc.nats": {{ "domain": "host-process", "match": {{ "all": [ {{ "process.uid": 9002 }} ] }} }},
                "ops.wheel": {{ "domain": "host-process", "match": {{ "all": [ {{ "process.gid.supplementary": 10 }} ] }} }},
                "breakglass.root": {{ "domain": "host-process", "breakGlass": true, "match": {{ "all": [ {{ "process.uid": 0 }} ] }} }},
                "root.group": {{ "domain": "host-process", "match": {{ "all": [ {{ "process.gid.supplementary": 0 }} ] }} }},
                "public.subject": {{ "domain": "host-process", "match": {{ "all": [ {{ "process.uid": 42 }} ] }} }}
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
        assert_eq!(catalog.schema, crate::catalog::CatalogSchema::Catalog);
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
    fn wrong_catalog_discriminator_is_a_hard_error() {
        let cat =
            catalog_json(ASYM_KEY).replacen("\"schema\": \"catalog\"", "\"schema\": \"other\"", 1);
        let pol = policy_json(
            READER_ROLE,
            r#"{ "id": "r1", "subjects": ["svc.nats"], "action": ["role:reader"], "target": ["nats.account"] }"#,
        );
        let err = load(&cat, &pol).expect_err("wrong catalog discriminator refused");
        assert!(matches!(
            err,
            LoadError::Json {
                what: "catalog",
                ..
            }
        ));
    }

    #[test]
    fn legacy_catalog_v1_is_diagnostic_only() {
        let cat =
            catalog_json(ASYM_KEY).replacen("\"schema\": \"catalog\"", "\"schemaVersion\": 1", 1);
        let pol = policy_json(READER_ROLE, "");
        assert!(matches!(load(&cat, &pol), Err(LoadError::LegacyCatalogV1)));
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
          "schema": "policy",
          "subjects": { "svc.\nnats": { "domain": "host-process", "match": { "all": [ { "process.uid": 9002 } ] } } },
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
          "schema": "policy",
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
    fn duplicate_subject_key_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = r#"{
          "schema": "policy",
          "subjects": {
            "svc.nats": { "domain": "host-process", "match": { "all": [ { "process.uid": 9002 } ] } },
            "svc.nats": { "domain": "host-process", "match": { "all": [ { "process.uid": 9003 } ] } }
          },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        let err = load(&cat, pol).expect_err("duplicate subject key rejected");
        assert!(
            matches!(err, LoadError::Json { what: "policy", .. }),
            "duplicate subject keys fail during policy JSON decode: {err}"
        );
        assert!(
            err.to_string().contains("duplicate policy key `svc.nats`"),
            "error names the duplicate subject: {err}"
        );
    }

    #[test]
    fn duplicate_role_key_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = r#"{
          "schema": "policy",
          "subjects": {
            "svc.nats": { "domain": "host-process", "match": { "all": [ { "process.uid": 9002 } ] } }
          },
          "roles": {
            "reader": ["get"],
            "reader": ["sign"]
          },
          "rules": [],
          "config": {}
        }"#;
        let err = load(&cat, pol).expect_err("duplicate role key rejected");
        assert!(
            matches!(err, LoadError::Json { what: "policy", .. }),
            "duplicate role keys fail during policy JSON decode: {err}"
        );
        assert!(
            err.to_string().contains("duplicate policy key `reader`"),
            "error names the duplicate role: {err}"
        );
    }

    #[test]
    fn duplicate_evidence_key_is_fatal_at_decode() {
        let cat = catalog_json(ASYM_KEY);
        let pol = r#"{
          "schema": "policy",
          "subjects": {
            "svc.nats": {
              "domain": "host-process",
              "match": { "process.uid": 9002, "process.uid": 9003 }
            }
          },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        let err = load(&cat, pol).expect_err("duplicate evidence key rejected");
        assert!(
            matches!(err, LoadError::Json { what: "policy", .. }),
            "duplicate evidence keys fail during policy JSON decode: {err}"
        );
        assert!(
            err.to_string()
                .contains("duplicate evidence key `process.uid`"),
            "error names the duplicate predicate: {err}"
        );
    }

    #[test]
    fn duplicate_rule_id_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let pol = policy_json(
            READER_ROLE,
            r#"
            { "id": "r1", "subjects": ["svc.nats"], "action": ["role:reader"], "target": ["nats.account"] },
            { "id": "r1", "subjects": ["svc.nats"], "action": ["op:get"], "target": ["nats.account"] }
            "#,
        );
        assert!(matches!(
            load(&cat, &pol),
            Err(LoadError::DuplicateRuleId { rule }) if rule == "r1"
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
        for field in ["all", "any"] {
            let pol = format!(
                r#"{{
                  "schema": "policy",
                  "subjects": {{ "svc.empty": {{ "domain": "host-process", "match": {{ "{field}": [] }} }} }},
                  "roles": {{ }},
                  "rules": [],
                  "config": {{ }}
                }}"#
            );
            assert!(
                matches!(load(&cat, &pol), Err(LoadError::InvalidSubjectShape { .. })),
                "{field} must reject empty lists"
            );
        }
    }

    #[test]
    fn provisional_unix_principal_is_rejected() {
        let cat = catalog_json(ASYM_KEY);
        let pol = r#"{
          "schema": "policy",
          "subjects": { "svc.bad": { "allOf": [ { "kind": "unix" } ] } },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(load(&cat, pol), Err(LoadError::Json { .. })));
    }

    #[test]
    fn provisional_unauthenticated_principal_is_rejected() {
        let cat = catalog_json(ASYM_KEY);
        let pol = r#"{
          "schema": "policy",
          "unauthenticatedSubject": "guest",
          "subjects": { "other": { "allOf": [ { "kind": "unauthenticated" } ] } },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(load(&cat, pol), Err(LoadError::Json { .. })));
    }

    #[test]
    fn unauthenticated_subject_field_is_rejected() {
        let cat = catalog_json(ASYM_KEY);
        let pol = r#"{
          "schema": "policy",
          "unauthenticatedSubject": "guest",
          "subjects": {},
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(load(&cat, pol), Err(LoadError::Json { .. })));
    }

    #[test]
    fn unsupported_principal_kind_and_signature_algorithm_are_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let bad_kind = r#"{
          "schema": "policy",
          "subjects": { "svc.bad": { "domain": "host-process", "match": { "process.sha256": "00" } } },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(
            load(&cat, bad_kind),
            Err(LoadError::InvalidSubjectShape { .. })
        ));

        let bad_alg = r#"{
          "schema": "policy",
          "subjects": {
            "svc.bad": {
              "domain": "host-process",
              "match": { "invocation.signature-key": { "algorithm": "ssh-ed25519", "public": "x" } }
            }
          },
          "roles": {},
          "rules": [],
          "config": {}
        }"#;
        assert!(matches!(
            load(&cat, bad_alg),
            Err(LoadError::InvalidSubjectShape { .. })
        ));
    }

    #[test]
    fn malformed_signature_key_public_material_is_fatal() {
        let cat = catalog_json(ASYM_KEY);
        let bad_ed25519 = r#"{
          "schema": "policy",
          "subjects": {
            "svc.bad": {
              "domain": "host-process",
              "match": { "invocation.signature-key": { "algorithm": "ed25519", "public": "not-base64url" } }
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
          "schema": "policy",
          "subjects": {
            "svc.bad": {
              "domain": "host-process",
              "match": { "invocation.signature-key": { "algorithm": "nats-nkey", "public": "not-an-nkey" } }
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
    fn resolved_index_preserves_subject_rules() {
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
              "schema": "policy",
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

    fn raw_subject(domain: AuthorizationDomain, match_: serde_json::Value) -> RawSubjectDefinition {
        RawSubjectDefinition {
            domain,
            break_glass: false,
            match_: RawEvidenceExpression(match_),
        }
    }

    #[test]
    fn recursive_expression_depth_and_leaf_limits_are_hard() {
        let mut too_deep = serde_json::json!({ "process.uid": 7 });
        for _ in 0..=MAX_EXPRESSION_DEPTH {
            too_deep = serde_json::json!({ "all": [too_deep] });
        }
        let mut accounts = None;
        assert!(matches!(
            parse_subject(
                "too.deep",
                &raw_subject(AuthorizationDomain::HostProcess, too_deep),
                &mut accounts,
            ),
            Err(LoadError::SubjectExpressionTooComplex { .. })
        ));

        let too_many = serde_json::json!({
            "all": (0..=MAX_EXPRESSION_LEAVES)
                .map(|id| serde_json::json!({ "process.uid": id }))
                .collect::<Vec<_>>()
        });
        assert!(matches!(
            parse_subject(
                "too.many",
                &raw_subject(AuthorizationDomain::HostProcess, too_many),
                &mut accounts,
            ),
            Err(LoadError::SubjectExpressionTooComplex { .. })
        ));
    }

    #[test]
    fn complex_but_valid_expression_emits_review_warning() {
        let mut expression = serde_json::json!({ "process.uid": 7 });
        for _ in 0..5 {
            expression = serde_json::json!({ "all": [expression] });
        }
        let (_, warnings) = parse_subjects(BTreeMap::from([(
            "deep.valid".to_string(),
            raw_subject(AuthorizationDomain::HostProcess, expression),
        )]))
        .expect("expression within hard limits loads");
        assert_eq!(
            warnings,
            [LoadWarning::ComplexSubjectExpression {
                subject: "deep.valid".to_string(),
                depth: 5,
                leaves: 1,
            }]
        );
    }

    #[test]
    fn typed_compose_predicates_require_container_domain_and_exact_fields() {
        let expression = serde_json::json!({
            "all": [
                { "compose.service": { "realm": "ci", "project": "build", "name": "worker" } },
                { "compose.project": { "realm": "ci", "project": "build" } },
                { "runtime.kind": "podman" },
                { "oci.signer": "release" },
                { "process.uid": 7 },
                { "process.executable.digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
            ]
        });
        let mut accounts = None;
        let (_, subject) = parse_subject(
            "container.worker",
            &raw_subject(AuthorizationDomain::Container, expression.clone()),
            &mut accounts,
        )
        .expect("typed container expression loads");
        assert_eq!(subject.match_.leaf_count(), 6);

        assert!(matches!(
            parse_subject(
                "host.worker",
                &raw_subject(AuthorizationDomain::HostProcess, expression),
                &mut accounts,
            ),
            Err(LoadError::PredicateDomainMismatch { .. })
        ));
        assert!(matches!(
            parse_subject(
                "bad.compose",
                &raw_subject(
                    AuthorizationDomain::Container,
                    serde_json::json!({
                        "compose.service": { "project": "build", "name": "worker" }
                    }),
                ),
                &mut accounts,
            ),
            Err(LoadError::InvalidSubjectShape { .. })
        ));
    }

    #[test]
    fn symbolic_accounts_compile_only_for_host_processes_and_manager_owners() {
        let mut accounts = Some(LocalAccounts {
            users: BTreeMap::from([("svc-web".to_string(), 9001)]),
            groups: BTreeMap::from([("wheel".to_string(), 10)]),
        });
        let (_, subject) = parse_subject(
            "host.web",
            &raw_subject(
                AuthorizationDomain::HostProcess,
                serde_json::json!({
                    "all": [
                        { "process.uid": "svc-web" },
                        { "process.gid.supplementary": "wheel" }
                    ]
                }),
            ),
            &mut accounts,
        )
        .expect("strict local names compile");
        let mut symbolic = 0;
        subject
            .match_
            .visit_leaves(&mut |predicate| match predicate {
                EvidencePredicate::ProcessUid(selector)
                | EvidencePredicate::ProcessGidSupplementary(selector)
                    if selector.is_symbolic() =>
                {
                    symbolic += 1;
                }
                _ => {}
            });
        assert_eq!(symbolic, 2);

        assert!(matches!(
            parse_subject(
                "container.web",
                &raw_subject(
                    AuthorizationDomain::Container,
                    serde_json::json!({ "process.uid": "svc-web" }),
                ),
                &mut accounts,
            ),
            Err(LoadError::SymbolicProcessIdentity { .. })
        ));
        assert!(matches!(
            parse_subject(
                "systemd.web",
                &raw_subject(
                    AuthorizationDomain::SystemdUnit,
                    serde_json::json!({ "process.uid": "svc-web" }),
                ),
                &mut accounts,
            ),
            Err(LoadError::SymbolicProcessIdentity { .. })
        ));
        parse_subject(
            "systemd.manager",
            &raw_subject(
                AuthorizationDomain::SystemdUnit,
                serde_json::json!({
                    "systemd.unit": { "name": "web.service", "managerUser": "svc-web" }
                }),
            ),
            &mut accounts,
        )
        .expect("symbolic user-manager ownership compiles");
        assert!(matches!(
            parse_subject(
                "numeric.string",
                &raw_subject(
                    AuthorizationDomain::HostProcess,
                    serde_json::json!({ "process.uid": "001" }),
                ),
                &mut accounts,
            ),
            Err(LoadError::InvalidSubjectShape { .. })
        ));
    }

    #[test]
    fn systemd_names_require_exact_canonical_service_or_template_shape() {
        for (name, template) in [
            ("payments.service", false),
            ("worker@george.service", false),
            (r"worker@george\x20smith.service", false),
            ("worker@.service", true),
        ] {
            assert!(
                valid_systemd_service_name(name, template),
                "valid systemd name: {name}"
            );
        }
        for (name, template) in [
            ("payments.timer", false),
            ("bad name.service", false),
            ("worker@one@two.service", false),
            ("worker@.service", false),
            ("worker@george.service", true),
            (r"worker@bad\x2G.service", false),
        ] {
            assert!(
                !valid_systemd_service_name(name, template),
                "invalid systemd name: {name}"
            );
        }
    }

    #[test]
    fn local_account_files_reject_duplicate_and_malformed_entries() {
        assert_eq!(
            parse_account_file("svc:x:7:7::/:/bin/false\n", 7, 2, "/etc/passwd")
                .expect("valid entry")
                .get("svc"),
            Some(&7)
        );
        assert!(matches!(
            parse_account_file(
                "svc:x:7:7::/:/bin/false\nsvc:x:8:8::/:/bin/false\n",
                7,
                2,
                "/etc/passwd",
            ),
            Err(LoadError::LocalAccountDatabase { .. })
        ));
        assert!(matches!(
            parse_account_file("svc:x:not-a-number:7::/:/bin/false\n", 7, 2, "/etc/passwd"),
            Err(LoadError::LocalAccountDatabase { .. })
        ));
    }
}
