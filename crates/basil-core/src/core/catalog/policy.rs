// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Policy schema: the authorization allow-list and the export-resolved config
//! tables.
//!
//! Rules grant to named subjects. Subject definitions hold typed principal specs
//! such as numeric Unix uid/gid selectors, while rules carry only subject names,
//! action terms, and target globs. The export tool has already resolved symbolic
//! user/group names to numeric uid/gid values before this module sees them.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::glob::KeyGlob;

/// A stable subject name from the policy subject registry.
pub type SubjectName = String;

/// An authorization operation (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Read a stored value.
    Get,
    /// List key names.
    List,
    /// Read a public key.
    GetPublicKey,
    /// Verify a signature.
    Verify,
    /// Sign in place.
    Sign,
    /// Encrypt a payload.
    Encrypt,
    /// Decrypt a payload.
    Decrypt,
    /// Emit a credential (its own capability, §3.1.1).
    Mint,
    /// Validate and sign a caller-supplied NATS JWT claim document.
    SignNatsJwt,
    /// Validate a presented NATS JWT against an allowed signer set.
    ValidateNatsJwt,
    /// Encrypt with a custodied NATS curve xkey.
    EncryptNatsCurve,
    /// Decrypt with a custodied NATS curve xkey.
    DecryptNatsCurve,
    /// Validate a credential against a local trust bundle.
    Validate,
    /// Write a stored value (operator-only).
    Set,
    /// Rotate a key (operator-only).
    Rotate,
    /// Import key material (operator-only).
    Import,
    /// Create a new key (operator-only).
    NewKey,
    /// Hot-reload the catalog/policy generation from disk (broker-admin only).
    ///
    /// A privileged, **broker-wide** admin op: not key-scoped like the others.
    /// It is deliberately **absent from [`ALL_OPS`]**, so a `*` (any-op) action
    /// (including root's `* / *` rule) does **not** expand to it; the only way to
    /// grant it is an explicit `op:reload` action over the reserved admin target
    /// (see [`Pdp::decide_admin`](super::pdp::Pdp::decide_admin)). No data-plane
    /// grant implies it (least privilege, default-deny).
    Reload,
    /// Explain a policy decision against the serving broker generation.
    ///
    /// This is a broker-wide admin op because it can reveal policy reachability.
    /// It is deliberately absent from [`ALL_OPS`], so no data-plane grant or
    /// wildcard action implies it; grant it explicitly over `broker.explain`.
    Explain,
    /// Revoke a live JWT-SVID by adding its `jti` to the deny-list.
    ///
    /// This is a broker-wide admin op because it mutates serving revocation
    /// state. It is deliberately absent from [`ALL_OPS`], so no data-plane grant
    /// or wildcard action implies it; grant it explicitly over `broker.revoke`.
    Revoke,
    /// Permit a caller to use the **local-software** crypto provider for a key
    /// (the software-custodied PQC arm: ML-DSA signing, ML-KEM unwrap).
    ///
    /// This is a key-scoped op, but it is deliberately **absent from
    /// [`ALL_OPS`]** so a `*` (any-op) action (including root's `* / *`) never
    /// implies it: routing a private operation through Basil's in-process
    /// software custody (rather than a backend that holds the key in place) is a
    /// distinct trust decision and must be granted **explicitly** with an
    /// `op:use_software_custody` action over the key's target. It gates the
    /// `local_software_allowed` input to
    /// [`select_provider`](crate::core::crypto_provider::select_provider); the
    /// caller still needs the underlying op grant (`op:sign`, `op:new_key`, …).
    UseSoftwareCustody,
}

/// Every **key-scoped** broker policy op, in a fixed order. The expansion of an
/// action `*` (`AnyOp`) and the per-`(key, op)` sweep of the effective-permissions
/// preview both iterate this.
///
/// Broker-wide admin ops such as [`Op::Reload`] are deliberately **excluded**:
/// they are not key-scoped and must never be implied by a `*` action (not even
/// root's). They are granted only by explicit `op:<admin>` actions over reserved
/// admin targets: see [`Pdp::decide_admin`](super::pdp::Pdp::decide_admin).
pub(crate) const ALL_OPS: [Op; 17] = [
    Op::Get,
    Op::List,
    Op::GetPublicKey,
    Op::Verify,
    Op::Sign,
    Op::Encrypt,
    Op::Decrypt,
    Op::Mint,
    Op::SignNatsJwt,
    Op::ValidateNatsJwt,
    Op::EncryptNatsCurve,
    Op::DecryptNatsCurve,
    Op::Validate,
    Op::Set,
    Op::Rotate,
    Op::Import,
    Op::NewKey,
];

impl Op {
    /// Whether this is a write op (`set`/`rotate`/`import`/`new_key`, §3.1).
    /// Writes live in the `operator` role and are never implied (§2.4.2).
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(self, Self::Set | Self::Rotate | Self::Import | Self::NewKey)
    }

    /// The bare wire token for this op (the part after `op:`), e.g.
    /// `get_public_key`. Inverse of [`Op::parse`].
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::List => "list",
            Self::GetPublicKey => "get_public_key",
            Self::Verify => "verify",
            Self::Sign => "sign",
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::Mint => "mint",
            Self::SignNatsJwt => "sign_nats_jwt",
            Self::ValidateNatsJwt => "validate_nats_jwt",
            Self::EncryptNatsCurve => "encrypt_nats_curve",
            Self::DecryptNatsCurve => "decrypt_nats_curve",
            Self::Validate => "validate",
            Self::Set => "set",
            Self::Rotate => "rotate",
            Self::Import => "import",
            Self::NewKey => "new_key",
            Self::Reload => "reload",
            Self::Explain => "explain",
            Self::Revoke => "revoke",
            Self::UseSoftwareCustody => "use_software_custody",
        }
    }

    /// Parse the bare op token (the part after `op:`), e.g. `get_public_key`.
    pub fn parse(token: &str) -> Result<Self, ActionTermError> {
        let op = match token {
            "get" => Self::Get,
            "list" => Self::List,
            "get_public_key" => Self::GetPublicKey,
            "verify" => Self::Verify,
            "sign" => Self::Sign,
            "encrypt" => Self::Encrypt,
            "decrypt" => Self::Decrypt,
            "mint" => Self::Mint,
            "sign_nats_jwt" => Self::SignNatsJwt,
            "validate_nats_jwt" => Self::ValidateNatsJwt,
            "encrypt_nats_curve" => Self::EncryptNatsCurve,
            "decrypt_nats_curve" => Self::DecryptNatsCurve,
            "validate" => Self::Validate,
            "set" => Self::Set,
            "rotate" => Self::Rotate,
            "import" => Self::Import,
            "new_key" => Self::NewKey,
            "reload" => Self::Reload,
            "explain" => Self::Explain,
            "revoke" => Self::Revoke,
            "use_software_custody" => Self::UseSoftwareCustody,
            other => return Err(ActionTermError::UnknownOp(other.to_string())),
        };
        Ok(op)
    }
}

/// The supported public-key families for first-cut signature principals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureKeyAlgorithm {
    /// Ed25519 public key, encoded by the policy exporter.
    Ed25519,
    /// NATS public `NKey`.
    NatsNkey,
}

/// A typed principal selector inside a subject definition.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PrincipalSpec {
    /// Unix peer-credential selector. At least one of `uid` or `gid` must be set.
    Unix {
        /// Numeric uid to match.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uid: Option<u32>,
        /// Numeric gid to match against the full configured group set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gid: Option<u32>,
    },
    /// Explicit unauthenticated actor selector.
    Unauthenticated,
    /// Signed invocation key selector.
    SignatureKey {
        /// Signature algorithm family.
        algorithm: SignatureKeyAlgorithm,
        /// Public key material in the algorithm's canonical policy encoding.
        public: String,
    },
}

impl PrincipalSpec {
    /// Whether this principal matches an authenticated Unix actor.
    #[must_use]
    pub fn matches_unix(&self, uid: u32, gids: &[u32]) -> bool {
        match self {
            Self::Unix { uid: want_uid, gid } => {
                let uid_matches = want_uid.is_none_or(|want| want == uid);
                let gid_matches = gid.is_none_or(|want| gids.contains(&want));
                uid_matches && gid_matches
            }
            Self::Unauthenticated | Self::SignatureKey { .. } => false,
        }
    }

    /// Whether this principal matches the explicit unauthenticated actor.
    #[must_use]
    pub const fn matches_unauthenticated(&self) -> bool {
        matches!(self, Self::Unauthenticated)
    }
}

/// The boolean shape of a subject definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectMatch {
    /// Every listed principal spec must match.
    AllOf(Vec<PrincipalSpec>),
    /// At least one listed principal spec must match.
    AnyOf(Vec<PrincipalSpec>),
}

impl SubjectMatch {
    /// Whether this subject expression matches an authenticated Unix actor.
    #[must_use]
    pub fn matches_unix(&self, uid: u32, gids: &[u32]) -> bool {
        match self {
            Self::AllOf(specs) => specs.iter().all(|spec| spec.matches_unix(uid, gids)),
            Self::AnyOf(specs) => specs.iter().any(|spec| spec.matches_unix(uid, gids)),
        }
    }

    /// Whether this expression matches the explicit unauthenticated actor.
    #[must_use]
    pub fn matches_unauthenticated(&self) -> bool {
        match self {
            Self::AllOf(specs) => specs.iter().all(PrincipalSpec::matches_unauthenticated),
            Self::AnyOf(specs) => specs.iter().any(PrincipalSpec::matches_unauthenticated),
        }
    }

    /// Principal specs carried by this subject expression.
    #[must_use]
    pub fn specs(&self) -> &[PrincipalSpec] {
        match self {
            Self::AllOf(specs) | Self::AnyOf(specs) => specs,
        }
    }
}

/// A named subject definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectDefinition {
    /// Whether this subject may appear on a global `*` target rule.
    pub break_glass: bool,
    /// The typed principal selectors for this subject.
    pub match_: SubjectMatch,
}

/// A rule action term (§3.3): a role reference, an inline op, or `*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionTerm {
    /// `role:<name>`: expands to the role's op set.
    Role(String),
    /// `op:<op>`: a single op.
    Op(Op),
    /// `*`: any op (§3.6, pairs with the root rule).
    AnyOp,
}

/// Why a prefix-form action term failed to parse. All variants are fatal load
/// errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionTermError {
    /// An action term with an unknown/missing prefix.
    #[error("bad action term `{0}` (expected `role:<name>`, `op:<op>`, or `*`)")]
    BadAction(String),

    /// An `op:` term naming an unknown op.
    #[error("unknown op `{0}`")]
    UnknownOp(String),
}

impl ActionTerm {
    /// Parse a prefix-form action term (§3.3).
    pub fn parse(term: &str) -> Result<Self, ActionTermError> {
        if term == "*" {
            return Ok(Self::AnyOp);
        }
        if let Some(role) = term.strip_prefix("role:") {
            return Ok(Self::Role(role.to_string()));
        }
        if let Some(op) = term.strip_prefix("op:") {
            return Ok(Self::Op(Op::parse(op)?));
        }
        Err(ActionTermError::BadAction(term.to_string()))
    }
}

/// A policy rule with subject names, action terms, and target globs parsed into
/// typed forms.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Stable rule id (for logging and audit).
    pub id: String,
    /// Subject names this rule grants to. The list is an OR.
    pub subjects: Vec<SubjectName>,
    /// Action terms (roles + inline ops + `*`).
    pub action: Vec<ActionTerm>,
    /// Target key globs.
    pub target: Vec<KeyGlob>,
    /// Optional free-text comment.
    pub comment: Option<String>,
}

/// The export-resolved name table (§4): numeric id → symbolic name, for logging.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NameTable {
    /// uid → user name.
    #[serde(default)]
    pub users: BTreeMap<u32, String>,
    /// gid → group name.
    #[serde(default)]
    pub groups: BTreeMap<u32, String>,
}

/// Export-resolved config tables (§4).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    /// uid/gid → name, for `name(num)` logging.
    #[serde(default)]
    pub names: NameTable,
    /// uid → full declared group set (primary + supplementary, §4).
    #[serde(default)]
    pub memberships: BTreeMap<u32, BTreeSet<u32>>,
}

impl Config {
    /// Render a uid as `name(uid)` for logging, e.g. `svc-nats(9002)`; falls back
    /// to just the number when the name is unknown (§4).
    #[must_use]
    pub fn user_name_num(&self, uid: u32) -> String {
        Self::name_num(self.names.users.get(&uid), uid)
    }

    /// Render a gid as `name(gid)` for logging, e.g. `wheel(10)`; falls back to
    /// just the number when the name is unknown (§4).
    #[must_use]
    pub fn group_name_num(&self, gid: u32) -> String {
        Self::name_num(self.names.groups.get(&gid), gid)
    }

    /// The full declared group set for `uid` (empty if the uid is unknown, §4).
    #[must_use]
    pub fn groups_of(&self, uid: u32) -> Option<&BTreeSet<u32>> {
        self.memberships.get(&uid)
    }

    fn name_num(name: Option<&String>, num: u32) -> String {
        name.map_or_else(|| num.to_string(), |n| format!("{n}({num})"))
    }
}

/// One resolved allow-grant: an `(op, target)` pair plus the provenance of the
/// rule that produced it.
///
/// The loader's [`build_resolved`](super::loader) expansion flattens a rule's
/// action terms (roles + inline ops + `*`) into concrete `(op, target)` grants;
/// each carries the originating rule's stable `id` and the action **term** spelling
/// (e.g. `role:reader`, `op:sign`, `*`) that produced this op. This provenance is
/// what lets the PDP's `explain` report *which* rule matched without keeping a
/// second copy of the matching logic: `decide` and `explain` share one matcher
/// over these grants (the anti-divergence guard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The op this grant permits.
    pub op: Op,
    /// The target glob this grant permits `op` over.
    pub target: KeyGlob,
    /// The stable id of the rule that produced this grant (for `explain`/audit).
    pub rule_id: String,
    /// The action-term spelling that expanded into `op` (`role:<name>`,
    /// `op:<op>`, or `*`), for human-readable explanation.
    pub action: String,
}

/// One resolved rule: subject names plus the allow-grants it carries.
///
/// Built by the loader's [`build_resolved`](super::loader) from a [`Rule`] after
/// expanding action terms (roles + inline ops + `*`) into concrete `(op, target)`
/// grants. The PDP iterates these in declaration order and intersects the rule
/// subject set with the subjects resolved for the actor before checking grants.
#[derive(Debug, Clone)]
pub struct ResolvedRule {
    /// Subject names this rule grants to. The list is an OR.
    pub subjects: Vec<SubjectName>,
    /// The concrete `(op, target)` grants this rule produces.
    pub grants: Vec<Grant>,
}

/// The resolved, ready-for-PDP allow-list, built by the loader and consumed by the PDP.
///
/// A linear list of resolved rules in declaration order. The PDP iterates them,
/// matching the first rule whose subject and grant fit. Default-deny is the
/// **absence** of a match; this struct only carries the *allows*.
#[derive(Debug, Clone, Default)]
pub struct ResolvedPolicy {
    /// Validated subject registry.
    pub subjects: BTreeMap<SubjectName, SubjectDefinition>,
    /// Explicit subject used for unauthenticated requests, when configured.
    pub unauthenticated_subject: Option<SubjectName>,
    /// Resolved rules in declaration order.
    pub rules: Vec<ResolvedRule>,
}

impl ResolvedPolicy {
    /// Total number of resolved `(op, target)` allow-grants across all rules.
    ///
    /// A summary count for the reload audit trail (`basil-y3e`).
    #[must_use]
    pub fn grant_count(&self) -> usize {
        self.rules.iter().map(|r| r.grants.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_is_write_only_for_write_ops() {
        for op in [Op::Set, Op::Rotate, Op::Import, Op::NewKey] {
            assert!(op.is_write(), "{op:?} should be a write");
        }
        for op in [
            Op::Get,
            Op::List,
            Op::GetPublicKey,
            Op::Verify,
            Op::Sign,
            Op::Encrypt,
            Op::Decrypt,
            Op::Mint,
            Op::SignNatsJwt,
            Op::ValidateNatsJwt,
            Op::EncryptNatsCurve,
            Op::DecryptNatsCurve,
            Op::Validate,
        ] {
            assert!(!op.is_write(), "{op:?} should not be a write");
        }
    }

    #[test]
    fn op_parse_round_trips_tokens() {
        assert_eq!(Op::parse("get_public_key").unwrap(), Op::GetPublicKey);
        assert_eq!(Op::parse("new_key").unwrap(), Op::NewKey);
        assert_eq!(Op::parse("mint").unwrap(), Op::Mint);
        assert_eq!(Op::parse("sign_nats_jwt").unwrap(), Op::SignNatsJwt);
        assert_eq!(Op::parse("validate_nats_jwt").unwrap(), Op::ValidateNatsJwt);
        assert_eq!(
            Op::parse("encrypt_nats_curve").unwrap(),
            Op::EncryptNatsCurve
        );
        assert_eq!(
            Op::parse("decrypt_nats_curve").unwrap(),
            Op::DecryptNatsCurve
        );
        assert_eq!(Op::parse("validate").unwrap(), Op::Validate);
        assert_eq!(Op::parse("reload").unwrap(), Op::Reload);
        assert_eq!(Op::parse("explain").unwrap(), Op::Explain);
        assert_eq!(Op::parse("revoke").unwrap(), Op::Revoke);
        assert_eq!(Op::Reload.token(), "reload");
        assert_eq!(Op::Explain.token(), "explain");
        assert_eq!(Op::Revoke.token(), "revoke");
        assert!(matches!(
            Op::parse("nope"),
            Err(ActionTermError::UnknownOp(_))
        ));
    }

    #[test]
    fn admin_ops_are_not_write_and_excluded_from_any_op_expansion() {
        for op in [Op::Reload, Op::Explain, Op::Revoke] {
            assert!(!op.is_write());
            assert!(
                !ALL_OPS.contains(&op),
                "{op:?} must stay out of the `*`/effective-sweep op set"
            );
        }
    }

    #[test]
    fn action_parses_role_op_and_any() {
        assert_eq!(
            ActionTerm::parse("role:minter").unwrap(),
            ActionTerm::Role("minter".into())
        );
        assert_eq!(
            ActionTerm::parse("op:sign").unwrap(),
            ActionTerm::Op(Op::Sign)
        );
        assert_eq!(ActionTerm::parse("*").unwrap(), ActionTerm::AnyOp);
        assert!(matches!(
            ActionTerm::parse("get"),
            Err(ActionTermError::BadAction(_))
        ));
        assert!(matches!(
            ActionTerm::parse("op:bogus"),
            Err(ActionTermError::UnknownOp(_))
        ));
    }

    #[test]
    fn unauthenticated_principal_matches_only_unauthenticated_actor() {
        let subject = SubjectMatch::AnyOf(vec![PrincipalSpec::Unauthenticated]);
        assert!(subject.matches_unauthenticated());
        assert!(!subject.matches_unix(42, &[42]));
    }

    #[test]
    fn config_logging_helpers_fall_back_to_number() {
        let mut cfg = Config::default();
        cfg.names.users.insert(9002, "svc-nats".into());
        cfg.names.groups.insert(10, "wheel".into());
        assert_eq!(cfg.user_name_num(9002), "svc-nats(9002)");
        assert_eq!(cfg.group_name_num(10), "wheel(10)");
        assert_eq!(cfg.user_name_num(123), "123"); // unknown uid
        assert_eq!(cfg.group_name_num(456), "456"); // unknown gid
    }

    #[test]
    fn config_groups_of_reads_memberships() {
        let mut cfg = Config::default();
        cfg.memberships.insert(9002, BTreeSet::from([9002, 10]));
        assert_eq!(cfg.groups_of(9002), Some(&BTreeSet::from([9002, 10])));
        assert_eq!(cfg.groups_of(123), None);
    }
}
