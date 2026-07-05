//! Policy decision point (`PDP`) for per-request
//! `AuthenticatedActor` authorization. This is `vault-1l8`.
//!
//! The broker **is** the `PDP`. Local transports first resolve the connecting
//! peer's kernel-trustworthy `SO_PEERCRED` identity into an
//! [`AuthenticatedActor`]. The actor carries the configured subject that matched
//! the peer's `uid`, primary `gid`, or supplementary group set. Ambiguous or
//! missing subject resolution fails closed before operation-level policy is
//! evaluated.
//!
//! The decision is **default-deny**: a request is allowed only if the resolved
//! actor's subject has a matching grant, or a public-read rule applies to a
//! resolved actor. Truly unauthenticated access is represented by the configured
//! `unauthenticatedSubject`, not by falling through to all public reads. Denial is
//! the absence of an allow; there are no explicit deny rules.
//!
//! # Decision algorithm
//!
//! Given an [`AuthenticatedActor`], `op`, and `key`:
//!
//! 1. If `key` is not in the catalog → [`DenyReason::UnknownKey`] (don't leak
//!    which other check would have failed).
//! 2. **`writable` hard cap (§2.4.2):** if `op.is_write()` and the key's
//!    `writable == false` → [`DenyReason::NotWritable`], regardless of policy.
//! 3. Allow if a `(op, glob)` grant for the actor's [`SubjectName`] matches
//!    `key`.
//! 4. Allow if `op` is [`Op::Get`] or [`Op::GetPublicKey`], the key's
//!    `class == Public`, and the actor has a resolved subject. This preserves the
//!    public-read rule without making missing local identity authorization
//!    implicit.
//! 5. Else [`DenyReason::NotPermitted`].
//!
//! The decision carries enough for the audit log (`vault-vq5`): which subject
//! matched on allow, or which check failed on deny. This module does **not** write
//! the audit log; transport and services record actor-based decisions at the
//! request boundary.
//!
//! # Sealing-key op surface (basil-t9a)
//!
//! A `sealing` (X25519 sealed-box) key has exactly **three** permitted ops, all
//! gated by the manager's `require_class` and authorized here like any other op:
//!
//! - **`get_public_key`**: return the X25519 public half (derived from the
//!   materialized private, which is then zeroized). A public read.
//! - **`encrypt`** is a server-side **wrap** (`wrap_envelope`): seal a payload *to*
//!   the recipient public. This is a **PUBLIC** operation: sealing needs only the
//!   recipient's public key, so granting it discloses nothing secret.
//! - **`decrypt`** is an **unwrap** (`unwrap_envelope`): open a sealed box. This is the
//!   only op that *uses* the private (one `ECDH`, then zeroize).
//!
//! `get` / `set` / `sign` / `rotate` / `import` / `new_key` are **never** valid for
//! a sealing key (the private half is never released or overwritten through the
//! broker; it is operator-provisioned out-of-band).
//!
//! ## Shared-`Op` semantics (intentional, not accidental)
//!
//! [`Op::Encrypt`] is shared between symmetric-AEAD `encrypt` and sealing **wrap**;
//! [`Op::Decrypt`] between AEAD `decrypt` and sealing **unwrap**. The PDP does not
//! reason about key *class* when matching an `(op, glob)` grant, so a glob role
//! granting `encrypt`/`decrypt` over a target that resolves to a sealing key DOES
//! authorize wrap/unwrap on it. This is acceptable **by construction**: sealing
//! `encrypt` (wrap) is a public op (no secret disclosed), and sealing `decrypt`
//! (unwrap) is exactly the intended use of a sealing key. The narrowest grant is
//! still preferred (point a rule at the specific `enroll.sealing` target, not a
//! broad `**` glob), but the shared-`Op` mapping is a documented design choice, not
//! a privilege-escalation gap. (See the canonical `sealer` role below: it grants
//! `decrypt` + `encrypt` + `get_public_key`.)

use super::policy::{ALL_OPS, Config, Grant, Op, ResolvedPolicy, SubjectName};
use super::schema::{Catalog, Class};
use crate::actor::{
    AuthenticatedActor, PresenterInfo, SubjectResolutionError, TransportInfo, resolve_local_actor,
    resolve_unix_actor as resolve_unix_authenticated_actor,
};
use crate::peer::PeerInfo;

/// The policy decision point.
///
/// Borrows the loaded, immutable policy surface (the catalog, the resolved
/// allow-index, and the export-resolved config tables) and answers
/// `AuthenticatedActor`, [`Op`], and key decisions.
#[derive(Debug, Clone, Copy)]
pub struct Pdp<'a> {
    catalog: &'a Catalog,
    policy: &'a ResolvedPolicy,
    config: &'a Config,
}

/// The outcome of a [`Pdp::decide`] call.
///
/// Both variants carry enough context for the audit log (`vault-vq5`): an allow
/// records *which* principal matched (so a denied-then-allowed key can be
/// distinguished from a public read), and a deny records *which* check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The request is permitted; `via` records what granted it (for audit).
    Allow {
        /// Which kind of grant matched (for the audit trail).
        via: AllowVia,
    },
    /// The request is denied; `reason` records why (for audit).
    Deny {
        /// Which check failed (for the audit trail).
        reason: DenyReason,
    },
}

impl Decision {
    /// Whether this decision permits the request.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Whether this decision denies the request.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Which grant permitted an [`Decision::Allow`] (least-specific to broadest), for audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowVia {
    /// A named subject matched the authenticated actor.
    Subject(String),
    /// The §3.5 world-readable rule: a `class: public` key, read op.
    PublicClass,
}

/// Why a [`Decision::Deny`] was returned (which check failed), for audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The key is not in the catalog (step 1). Reported first so we don't leak
    /// which finer-grained check would otherwise have failed.
    UnknownKey,
    /// A write op against a key whose `writable == false` (the §2.4.2 hard cap),
    /// denied regardless of policy.
    NotWritable,
    /// No grant matched and the key is not a public read (default-deny, step 5).
    NotPermitted,
}

/// The full result of [`Pdp::explain`]: the [`Decision`] plus, on a rule-based
/// allow, the rule that produced it.
///
/// `decide` is exactly `explain(...).decision`; the two never carry different
/// decisions (a unit test pins this over a matrix). `matched` is `Some` only for
/// a rule-driven allow: a `PublicClass` (§3.5 world-readable) allow and every
/// deny carry `None`, since no policy *rule* produced them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// The authorization decision (identical to [`Pdp::decide`]).
    pub decision: Decision,
    /// The rule that produced a rule-based allow (`None` for public-class allows
    /// and for every deny).
    pub matched: Option<MatchedRule>,
}

impl Explanation {
    /// A deny with no matched rule.
    const fn deny(reason: DenyReason) -> Self {
        Self {
            decision: Decision::Deny { reason },
            matched: None,
        }
    }

    /// A rule-based allow, recording the subject that matched the caller and the
    /// matched grant's provenance.
    fn allow(subject: &str, grant: &Grant) -> Self {
        Self {
            decision: Decision::Allow {
                via: AllowVia::Subject(subject.to_string()),
            },
            matched: Some(MatchedRule {
                rule_id: grant.rule_id.clone(),
                via: AllowVia::Subject(subject.to_string()),
                subject: subject.to_string(),
                action: grant.action.clone(),
                target: grant.target.source(),
            }),
        }
    }

    /// Whether this explanation's decision permits the request.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        self.decision.is_allow()
    }
}

/// The rule provenance behind a rule-based [`Decision::Allow`] (for `explain`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    /// The stable id of the policy rule that granted the request.
    pub rule_id: String,
    /// The subject that matched the actor.
    pub via: AllowVia,
    /// The matched subject name.
    pub subject: String,
    /// The action-term spelling that granted the op (`role:<name>`, `op:<op>`, `*`).
    pub action: String,
    /// The canonical source spelling of the target glob that matched the key.
    pub target: String,
}

/// One `(key, op)` an identity is granted, from [`Pdp::effective`] (the
/// preview-effective-permissions view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveGrant {
    /// The catalog key.
    pub key: String,
    /// The op granted over `key`.
    pub op: Op,
    /// Which subject granted it.
    pub via: AllowVia,
    /// The originating rule id, or `None` for a §3.5 public-class read.
    pub rule_id: Option<String>,
}

impl<'a> Pdp<'a> {
    /// Build a PDP over the loaded policy surface (the `load()` 4-tuple's first
    /// three elements; the warnings are not a decision input).
    #[must_use]
    pub const fn new(catalog: &'a Catalog, policy: &'a ResolvedPolicy, config: &'a Config) -> Self {
        Self {
            catalog,
            policy,
            config,
        }
    }

    /// Resolve the local transport actor from captured peer information.
    pub fn resolve_local_actor(
        &self,
        peer: &PeerInfo,
    ) -> Result<AuthenticatedActor, SubjectResolutionError> {
        resolve_local_actor(self.policy, self.config, peer)
    }

    /// Resolve an offline Unix actor for policy inspection.
    pub fn resolve_unix_actor(
        &self,
        uid: u32,
    ) -> Result<AuthenticatedActor, SubjectResolutionError> {
        let peer = PeerInfo {
            uid: Some(uid),
            ..PeerInfo::default()
        };
        resolve_unix_authenticated_actor(self.policy, self.config, &peer, uid)
    }

    /// Resolve a named policy subject for offline/admin policy inspection.
    ///
    /// This does not authenticate a live presenter. It builds the same actor
    /// shape the matcher consumes, but only after the subject is present in the
    /// policy registry; unknown subjects fail closed.
    #[must_use]
    pub fn resolve_subject_actor(&self, subject: &str) -> Option<AuthenticatedActor> {
        self.policy
            .subjects
            .contains_key(subject)
            .then(|| AuthenticatedActor {
                subject: subject.to_string(),
                authenticated_by: Vec::new(),
                presenter: PresenterInfo {
                    pid: None,
                    uid: None,
                    gid: None,
                    executable_path: None,
                    display_label: Some("policy-inspection".to_string()),
                },
                transport: TransportInfo::default(),
            })
    }

    /// Decide whether `actor` may perform `op` on `key` (§3, §4.1).
    ///
    /// `uid` is the `SO_PEERCRED` uid (the kernel-trustworthy anchor); its group
    /// set is expanded from the declarative `memberships` table, never the
    /// kernel's primary gid alone. See the module docs for the full algorithm.
    ///
    /// This is a thin projection of [`Pdp::explain`]: both run the *same*
    /// [`evaluate`](Self::evaluate) matcher and this returns only its [`Decision`].
    /// There is intentionally no second copy of the matching logic: a divergent
    /// dry-run would be a fail-closed-bypass security bug (a unit test pins
    /// `explain(...).decision == decide(...)` over a matrix).
    #[must_use]
    pub fn decide(&self, actor: &AuthenticatedActor, op: Op, key: &str) -> Decision {
        self.evaluate(actor, op, key).decision
    }

    /// Decide whether `actor` may perform a **broker-wide admin** `op` (e.g.
    /// [`Op::Reload`]), an op that is *not* key-scoped (basil-atq).
    ///
    /// Where [`decide`](Self::decide) runs the §4.1 key algorithm (catalog
    /// membership, the `writable` hard cap, the §3.5 world-readable rule), an admin
    /// op has **no key**, so none of those apply. The decision is pure
    /// **default-deny grant matching**: allow iff some `(op, glob)` grant (under
    /// the caller's resolved principal scope) matches that op's reserved admin
    /// target, else deny [`DenyReason::NotPermitted`].
    ///
    /// Because [`Op::Reload`] is excluded from `ALL_OPS`, a `*` (any-op) action
    /// (**including root's `* / *`**) never produces a `Reload` grant, so it can
    /// only be granted by an explicit `op:reload` action. The reserved target is a
    /// normal dotted glob the operator names; an operator grant is therefore:
    /// `{ "action": ["op:reload"], "target": ["broker.reload"], ... }`.
    #[must_use]
    pub fn decide_admin(&self, actor: &AuthenticatedActor, op: Op) -> Decision {
        let Some(key) = admin_target(op) else {
            return Decision::Deny {
                reason: DenyReason::NotPermitted,
            };
        };
        for rule in &self.policy.rules {
            if let Some(subject) = matching_rule_subject(&rule.subjects, actor.subject.as_str())
                && rule
                    .grants
                    .iter()
                    .any(|g| g.op == op && g.target.matches(key))
            {
                return Decision::Allow {
                    via: AllowVia::Subject(subject.to_string()),
                };
            }
        }
        Decision::Deny {
            reason: DenyReason::NotPermitted,
        }
    }

    /// The full evaluation of `(actor, op, key)`: the [`Decision`] **plus**, on an
    /// allow, the rule that produced it, for the offline policy `explain` /
    /// dry-run tool (`basil-4vf`) and for a future gated live explain.
    ///
    /// This runs the IDENTICAL algorithm [`decide`](Self::decide) does (steps
    /// §4.1): they share this one method; `decide` discards the matched rule.
    /// Default-deny holds exactly as in enforcement: a tuple no grant matches
    /// returns `Deny`/[`DenyReason::NotPermitted`] with `matched == None`.
    #[must_use]
    pub fn explain(&self, actor: &AuthenticatedActor, op: Op, key: &str) -> Explanation {
        self.evaluate(actor, op, key)
    }

    /// Offline subject helper for explain/admin surfaces.
    #[must_use]
    pub fn explain_subject(&self, subject: &str, op: Op, key: &str) -> Explanation {
        self.resolve_subject_actor(subject).map_or_else(
            || self.evaluate_without_actor(op, key),
            |actor| self.evaluate(&actor, op, key),
        )
    }

    /// The one shared matcher behind both [`decide`](Self::decide) and
    /// [`explain`](Self::explain). Computes the §4.1 decision once, recording which
    /// rule/scope produced an allow.
    fn evaluate(&self, actor: &AuthenticatedActor, op: Op, key: &str) -> Explanation {
        // Step 1: unknown key -> deny without leaking finer detail.
        let Some(entry) = self.catalog.keys.get(key) else {
            return Explanation::deny(DenyReason::UnknownKey);
        };

        // Step 2: the `writable` hard cap (§2.4.2): a write to a non-writable key
        // is denied regardless of any policy grant.
        if op.is_write() && !entry.writable {
            return Explanation::deny(DenyReason::NotWritable);
        }

        // Step 4: iterate rules in declaration order; first matching predicate + grant wins.
        for rule in &self.policy.rules {
            if let Some(subject) = matching_rule_subject(&rule.subjects, actor.subject.as_str())
                && let Some(grant) = rule
                    .grants
                    .iter()
                    .find(|g| g.op == op && g.target.matches(key))
            {
                return Explanation::allow(subject, grant);
            }
        }

        // The §3.5 world-readable rule: a `class: public` key is readable by every
        // resolved subject, but only for `get` / `get_public_key`. No rule produces it.
        if entry.class == Class::Public && is_public_read(op) {
            return Explanation {
                decision: Decision::Allow {
                    via: AllowVia::PublicClass,
                },
                matched: None,
            };
        }

        // Step 5: default-deny.
        Explanation::deny(DenyReason::NotPermitted)
    }

    fn evaluate_without_actor(&self, op: Op, key: &str) -> Explanation {
        let Some(entry) = self.catalog.keys.get(key) else {
            return Explanation::deny(DenyReason::UnknownKey);
        };
        if op.is_write() && !entry.writable {
            return Explanation::deny(DenyReason::NotWritable);
        }
        Explanation::deny(DenyReason::NotPermitted)
    }

    /// Every `(key, op)` the named subject is granted across the whole
    /// catalog: the "preview effective permissions" view (`basil-4vf`). Pure and
    /// offline: it reuses [`explain`](Self::explain) per `(key, op)`, so it can
    /// never diverge from enforcement. The §3.5 world-readable public-class
    /// allows are included only for registered subjects.
    ///
    /// Returns the allowed entries sorted by `(key, op-token)` for stable output.
    #[must_use]
    pub fn effective(&self, subject: &str) -> Vec<EffectiveGrant> {
        let mut out = Vec::new();
        let Some(actor) = self.resolve_subject_actor(subject) else {
            return out;
        };
        for key in self.catalog.keys.keys() {
            for op in ALL_OPS {
                let ex = self.explain(&actor, op, key);
                if let Decision::Allow { via } = ex.decision {
                    out.push(EffectiveGrant {
                        key: key.clone(),
                        op,
                        via,
                        rule_id: ex.matched.map(|m| m.rule_id),
                    });
                }
            }
        }
        out.sort_by(|a, b| (a.key.as_str(), a.op.token()).cmp(&(b.key.as_str(), b.op.token())));
        out
    }

    /// Render `uid` as `name(uid)` for the audit log (§4), e.g. `svc-nats(9002)`.
    #[must_use]
    pub fn user_label(&self, uid: u32) -> String {
        self.config.user_name_num(uid)
    }

    /// Render `gid` as `name(gid)` for the audit log (§4), e.g. `wheel(10)`.
    #[must_use]
    pub fn group_label(&self, gid: u32) -> String {
        self.config.group_name_num(gid)
    }
}

/// The reserved policy target an operator grants a broker-wide admin op over (basil-atq).
///
/// It is **not** a catalog key. It is a sentinel glob the operator names in a
/// rule's `target` to scope an admin grant, e.g.
/// `{ "action": ["op:reload"], "target": ["broker.reload"] }`. It is matched only
/// by [`Pdp::decide_admin`], never by the key-scoped [`Pdp::decide`].
pub const ADMIN_RELOAD_TARGET: &str = "broker.reload";

/// The reserved policy target for the live policy explain admin op.
///
/// This is **not** a catalog key. Grant it explicitly with
/// `{ "action": ["op:explain"], "target": ["broker.explain"] }`.
pub const ADMIN_EXPLAIN_TARGET: &str = "broker.explain";

/// The reserved policy target for the live JWT-SVID revoke admin op.
///
/// This is **not** a catalog key. Grant it explicitly with
/// `{ "action": ["op:revoke"], "target": ["broker.revoke"] }`.
pub const ADMIN_REVOKE_TARGET: &str = "broker.revoke";

const fn admin_target(op: Op) -> Option<&'static str> {
    match op {
        Op::Reload => Some(ADMIN_RELOAD_TARGET),
        Op::Explain => Some(ADMIN_EXPLAIN_TARGET),
        Op::Revoke => Some(ADMIN_REVOKE_TARGET),
        Op::Get
        | Op::List
        | Op::GetPublicKey
        | Op::Verify
        | Op::Sign
        | Op::Encrypt
        | Op::Decrypt
        | Op::Mint
        | Op::SignNatsJwt
        | Op::ValidateNatsJwt
        | Op::EncryptNatsCurve
        | Op::DecryptNatsCurve
        | Op::Validate
        | Op::Set
        | Op::Rotate
        | Op::Import
        | Op::NewKey
        // A key-scoped op (decided via `decide`, not `decide_admin`); it has no
        // reserved admin target.
        | Op::UseSoftwareCustody => None,
    }
}

/// Whether `op` is one of the two world-readable ops for a `public`-class key (§3.5).
const fn is_public_read(op: Op) -> bool {
    matches!(op, Op::Get | Op::GetPublicKey)
}

fn matching_rule_subject<'a>(
    rule_subjects: &'a [SubjectName],
    actor_subject: &str,
) -> Option<&'a str> {
    rule_subjects
        .iter()
        .find(|subject| subject.as_str() == actor_subject)
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::load;

    // ---- Fixtures: build the real types via the loader from JSON literals ----

    // A catalog exercising every class the matrix needs:
    //  - nats.account     : asymmetric, writable      (sign/mint/operator target)
    //  - web.tls.ca_cert  : public, writable=false    (world-readable; hard-cap)
    //  - grafana.admin    : value, writable           (reader/operator target)
    //  - locked.value     : value, writable=false     (hard-cap on a value)
    const CATALOG: &str = r#"{
      "schemaVersion": 1,
      "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
      "keys": {
        "nats.account": {
          "class": "asymmetric", "keyType": "ed25519-nkey", "backend": "bao",
          "path": "nats", "writable": true, "missing": "error",
          "labels": ["nats_type=A"], "description": "account signing key"
        },
        "web.tls.ca_cert": {
          "class": "public", "backend": "bao", "engine": "kv2",
          "path": "secret/data/web/tls/ca-cert", "writable": false,
          "missing": "warn", "description": "public CA cert"
        },
        "grafana.admin_password": {
          "class": "value", "backend": "bao", "engine": "kv2",
          "path": "secret/data/grafana/admin", "writable": true,
          "missing": "error", "description": "grafana admin value"
        },
        "locked.value": {
          "class": "value", "backend": "bao", "engine": "kv2",
          "path": "secret/data/locked", "writable": false,
          "missing": "warn", "description": "externally managed value"
        },
        "enroll.sealing": {
          "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2",
          "path": "secret/data/enroll/x25519",
          "publicPath": "secret/data/enroll/x25519-public", "writable": true,
          "missing": "error", "description": "x25519 enrollment sealing key"
        }
      }
    }"#;

    // Roles mirror the §3.2 canonical set the matrix exercises.
    const ROLES: &str = r#"
      "reader":   ["get", "list", "get_public_key"],
      "signer":   ["sign", "verify", "get_public_key"],
      "minter":   ["mint", "get_public_key"],
      "sealer":   ["decrypt", "encrypt", "get_public_key"],
      "operator": ["set", "rotate", "import", "new_key"]
    "#;

    // The principal/op/target matrix.
    //
    //  uid 9002          : reader over grafana.admin_password (user: rule)
    //  uid 9003          : signer over nats.account           (user: rule; NO mint)
    //  uid 9004          : minter over nats.account           (user: rule; mint, no sign)
    //  gid 10 (wheel)    : operator over grafana.** and locked.value (group: rule)
    //  gid 10 (wheel)    : operator over web.tls.ca_cert      (hard-cap target)
    //  uid 5000          : member of gid 10 by supplementary membership only
    //  uid 9007          : revoke over broker.revoke          (admin op)
    //  uid 0 (root)      : * over * (root any-target)
    const SUBJECTS: &str = r#"
      "svc.grafana":     { "allOf": [ { "kind": "unix", "uid": 9002 } ] },
      "svc.nats":        { "allOf": [ { "kind": "unix", "uid": 9003 } ] },
      "svc.minter":      { "allOf": [ { "kind": "unix", "uid": 9004 } ] },
      "svc.enroll":      { "allOf": [ { "kind": "unix", "uid": 9005 } ] },
      "svc.reload":      { "allOf": [ { "kind": "unix", "uid": 9006 } ] },
      "svc.revoke":      { "allOf": [ { "kind": "unix", "uid": 9007 } ] },
      "ops.wheel":       { "allOf": [ { "kind": "unix", "gid": 10 } ] },
      "breakglass.root": { "breakGlass": true, "allOf": [ { "kind": "unix", "uid": 0 } ] }
    "#;

    const RULES: &str = r#"
      { "id": "grafana-reader",   "subjects": ["svc.grafana"],     "action": ["role:reader"],   "target": ["grafana.admin_password"] },
      { "id": "nats-signer",      "subjects": ["svc.nats"],        "action": ["role:signer"],   "target": ["nats.account"] },
      { "id": "nats-minter",      "subjects": ["svc.minter"],      "action": ["role:minter"],   "target": ["nats.account"] },
      { "id": "enroll-sealer",    "subjects": ["svc.enroll"],      "action": ["role:sealer"],   "target": ["enroll.sealing"] },
      { "id": "wheel-operator",   "subjects": ["ops.wheel"],       "action": ["role:operator"], "target": ["grafana.**", "locked.value", "web.tls.ca_cert"] },
      { "id": "reload-admin",     "subjects": ["svc.reload"],      "action": ["op:reload"],     "target": ["broker.reload"] },
      { "id": "reload-wheel",     "subjects": ["ops.wheel"],       "action": ["op:reload"],     "target": ["broker.reload"] },
      { "id": "revoke-admin",     "subjects": ["svc.revoke"],      "action": ["op:revoke"],     "target": ["broker.revoke"] },
      { "id": "root-all",         "subjects": ["breakglass.root"], "action": ["*"],             "target": ["*"] }
    "#;

    // uid 5000 is in gid 10 by SUPPLEMENTARY membership only (its "primary" gid
    // would be 5000); uid 9003/9004 are in no groups. This proves the PDP uses the
    // full declared group set, not the primary gid.
    const CONFIG: &str = r#"
      "names": {
        "users":  { "0": "root", "9002": "svc-grafana", "9003": "svc-nats", "9004": "svc-minter", "9005": "svc-enroll", "9006": "svc-admin", "9007": "svc-revoke", "5000": "alice" },
        "groups": { "10": "wheel" }
      },
      "memberships": { "5000": [5000, 10], "9002": [9002], "9003": [9003], "9004": [9004], "9005": [9005], "9006": [9006], "9007": [9007] }
    "#;

    fn policy_json() -> String {
        format!(
            r#"{{
              "schemaVersion": 2,
              "subjects": {{ {SUBJECTS} }},
              "roles": {{ {ROLES} }},
              "rules": [ {RULES} ],
              "config": {{ {CONFIG} }}
            }}"#
        )
    }

    fn via(subject: &str) -> AllowVia {
        AllowVia::Subject(subject.to_string())
    }

    /// Build the real `(Catalog, ResolvedPolicy, Config)` via the loader, then a PDP.
    /// Returns owned values so the PDP can borrow them in each test.
    fn fixture() -> (super::Catalog, super::ResolvedPolicy, Config) {
        let pol = policy_json();
        let (catalog, resolved, config, warnings) =
            load(CATALOG, &pol).expect("fixture loads cleanly");
        assert!(
            warnings.is_empty(),
            "fixture should have no warnings: {warnings:?}"
        );
        (catalog, resolved, config)
    }

    fn decide(pdp: &Pdp<'_>, uid: u32, op: Op, key: &str) -> Decision {
        pdp.resolve_unix_actor(uid).map_or_else(
            |_| Decision::Deny {
                reason: DenyReason::NotPermitted,
            },
            |actor| pdp.decide(&actor, op, key),
        )
    }

    fn explain(pdp: &Pdp<'_>, uid: u32, op: Op, key: &str) -> Explanation {
        pdp.resolve_unix_actor(uid).map_or_else(
            |_| Explanation::deny(DenyReason::NotPermitted),
            |actor| pdp.explain(&actor, op, key),
        )
    }

    fn decide_admin(pdp: &Pdp<'_>, uid: u32, op: Op) -> Decision {
        pdp.resolve_unix_actor(uid).map_or_else(
            |_| Decision::Deny {
                reason: DenyReason::NotPermitted,
            },
            |actor| pdp.decide_admin(&actor, op),
        )
    }

    // ---- Allow paths --------------------------------------------------------

    #[test]
    fn allow_via_user_rule() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // uid 9002 is a reader of grafana.admin_password.
        assert_eq!(
            decide(&pdp, 9002, Op::Get, "grafana.admin_password"),
            Decision::Allow {
                via: via("svc.grafana")
            }
        );
        assert_eq!(
            decide(&pdp, 9002, Op::List, "grafana.admin_password"),
            Decision::Allow {
                via: via("svc.grafana")
            }
        );
    }

    #[test]
    fn explain_all_of_subject_carries_subject_name() {
        const CAT: &str = r#"{
          "schemaVersion": 1,
          "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
          "keys": {
            "grafana.admin_password": {
              "class": "value", "backend": "bao", "engine": "kv2",
              "path": "secret/data/grafana/admin", "writable": true,
              "missing": "error", "description": "grafana admin value"
            }
          }
        }"#;
        const POL: &str = r#"{
          "schemaVersion": 2,
          "subjects": {
            "svc.compound": { "allOf": [
              { "kind": "unix", "uid": 333 },
              { "kind": "unix", "gid": 10 }
            ] }
          },
          "roles": { "reader": ["get"] },
          "rules": [
            { "id": "compound-reader", "subjects": ["svc.compound"],
              "action": ["role:reader"], "target": ["grafana.admin_password"] }
          ],
          "config": { "memberships": { "333": [333, 10] } }
        }"#;
        let (catalog, resolved, config, _warnings) =
            load(CAT, POL).expect("compound fixture loads");
        let pdp = Pdp::new(&catalog, &resolved, &config);

        // uid 333 is in gid 10, so the compound predicate matches.
        let ex = explain(&pdp, 333, Op::Get, "grafana.admin_password");
        assert!(ex.is_allow());
        let matched = ex
            .matched
            .expect("a rule-based allow carries its matched rule");
        assert_eq!(matched.via, via("svc.compound"));
        assert_eq!(matched.subject, "svc.compound");

        // The allOf subject denies a uid missing the group half.
        assert!(explain(&pdp, 333, Op::Get, "grafana.admin_password").is_allow());
        assert!(decide(&pdp, 334, Op::Get, "grafana.admin_password").is_deny());
    }

    #[test]
    fn allow_via_supplementary_group() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // uid 5000's PRIMARY gid is 5000 (which grants nothing); it reaches the
        // wheel(10) operator grant only via its SUPPLEMENTARY membership. This is
        // the full-declared-group-set rule (§4.1), not primary-gid-only.
        assert_eq!(
            decide(&pdp, 5000, Op::Set, "grafana.admin_password"),
            Decision::Allow {
                via: via("ops.wheel")
            }
        );
    }

    #[test]
    fn allow_public_class_read_for_resolved_subject() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // A resolved subject may read a public-class key (§3.5).
        assert_eq!(
            decide(&pdp, 9002, Op::Get, "web.tls.ca_cert"),
            Decision::Allow {
                via: AllowVia::PublicClass
            }
        );
        assert_eq!(
            decide(&pdp, 9002, Op::GetPublicKey, "web.tls.ca_cert"),
            Decision::Allow {
                via: AllowVia::PublicClass
            }
        );
    }

    #[test]
    fn operator_write_allowed() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // wheel(10) operator -> set/rotate/import/new_key on a writable value.
        // uid 5000 is in wheel via supplementary membership.
        for op in [Op::Set, Op::Rotate, Op::Import, Op::NewKey] {
            assert_eq!(
                decide(&pdp, 5000, op, "grafana.admin_password"),
                Decision::Allow {
                    via: via("ops.wheel")
                },
                "operator {op:?} should be allowed"
            );
        }
    }

    #[test]
    fn root_any_target_allowed() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // root (user:0) has `*` action over `*` target -> any op on any catalog key.
        assert_eq!(
            decide(&pdp, 0, Op::Sign, "nats.account"),
            Decision::Allow {
                via: via("breakglass.root")
            }
        );
        assert_eq!(
            decide(&pdp, 0, Op::Get, "grafana.admin_password"),
            Decision::Allow {
                via: via("breakglass.root")
            }
        );
        // Even a write to a writable key (the hard cap permits it: writable=true).
        assert_eq!(
            decide(&pdp, 0, Op::Set, "grafana.admin_password"),
            Decision::Allow {
                via: via("breakglass.root")
            }
        );
    }

    // ---- Deny paths ---------------------------------------------------------

    #[test]
    fn default_deny_for_unmatched_principal() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // uid 7777 has no rule and no group membership: default-deny.
        assert_eq!(
            decide(&pdp, 7777, Op::Get, "grafana.admin_password"),
            Decision::Deny {
                reason: DenyReason::NotPermitted
            }
        );
    }

    #[test]
    fn missing_actor_never_gets_public_or_rule_based_permissions() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);

        // A transport that cannot resolve a subject must fail closed before the
        // public-class convenience rule or any policy rule can apply.
        assert!(pdp.resolve_unix_actor(424_242).is_err());
        assert_eq!(
            pdp.explain_subject("missing.subject", Op::Get, "web.tls.ca_cert"),
            Explanation::deny(DenyReason::NotPermitted)
        );
        assert_eq!(
            pdp.explain_subject("missing.subject", Op::Get, "grafana.admin_password"),
            Explanation::deny(DenyReason::NotPermitted)
        );
        assert_eq!(
            pdp.explain_subject("missing.subject", Op::Get, "does.not.exist"),
            Explanation::deny(DenyReason::UnknownKey)
        );
    }

    #[test]
    fn non_public_key_read_denied_for_unauthorized_uid() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // The public-read rule applies ONLY to class:public keys. nats.account is
        // asymmetric, so an unauthorized uid cannot read it.
        assert_eq!(
            decide(&pdp, 424_242, Op::Get, "nats.account"),
            Decision::Deny {
                reason: DenyReason::NotPermitted
            }
        );
        assert_eq!(
            decide(&pdp, 424_242, Op::GetPublicKey, "nats.account"),
            Decision::Deny {
                reason: DenyReason::NotPermitted
            }
        );
    }

    #[test]
    fn write_denied_when_not_writable_even_with_operator_grant() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // wheel(10) operator grants set/rotate/... over locked.value AND
        // web.tls.ca_cert, but both have writable=false -> the §2.4.2 hard cap
        // denies regardless of the operator grant. uid 5000 is in wheel.
        for key in ["locked.value", "web.tls.ca_cert"] {
            for op in [Op::Set, Op::Rotate, Op::Import, Op::NewKey] {
                assert_eq!(
                    decide(&pdp, 5000, op, key),
                    Decision::Deny {
                        reason: DenyReason::NotWritable
                    },
                    "hard cap should deny {op:?} on non-writable {key}"
                );
            }
        }
        // Root is not exempt from the hard cap either: writable=false wins over `*`.
        assert_eq!(
            decide(&pdp, 0, Op::Set, "locked.value"),
            Decision::Deny {
                reason: DenyReason::NotWritable
            }
        );
    }

    #[test]
    fn mint_allowed_via_minter_but_denied_for_signer_only() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // uid 9004 has role:minter -> mint allowed; mint != sign so sign denied.
        assert_eq!(
            decide(&pdp, 9004, Op::Mint, "nats.account"),
            Decision::Allow {
                via: via("svc.minter")
            }
        );
        assert_eq!(
            decide(&pdp, 9004, Op::Sign, "nats.account"),
            Decision::Deny {
                reason: DenyReason::NotPermitted
            }
        );

        // uid 9003 has role:signer -> sign allowed; signer does NOT grant mint.
        assert_eq!(
            decide(&pdp, 9003, Op::Sign, "nats.account"),
            Decision::Allow {
                via: via("svc.nats")
            }
        );
        assert_eq!(
            decide(&pdp, 9003, Op::Mint, "nats.account"),
            Decision::Deny {
                reason: DenyReason::NotPermitted
            }
        );
    }

    #[test]
    fn unknown_key_denied() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // Even root gets UnknownKey for a key not in the catalog (step 1 first).
        assert_eq!(
            decide(&pdp, 0, Op::Get, "does.not.exist"),
            Decision::Deny {
                reason: DenyReason::UnknownKey
            }
        );
        assert_eq!(
            decide(&pdp, 9002, Op::Get, "does.not.exist"),
            Decision::Deny {
                reason: DenyReason::UnknownKey
            }
        );
    }

    // ---- Sealing class (X25519 sealed-box unseal, basil-t9a) ----------------

    #[test]
    fn sealing_key_allows_wrap_unwrap_and_get_public_key_when_granted() {
        // INVARIANT 2: a sealing key allows the full sealing surface, wrap
        // (encrypt), unwrap (decrypt), and get_public_key, when policy grants the
        // canonical `sealer` role. Encrypt (wrap) is a PUBLIC op (seal to the
        // recipient public), so a granted sealer must be able to wrap.
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        for op in [Op::Encrypt, Op::Decrypt, Op::GetPublicKey] {
            assert_eq!(
                decide(&pdp, 9005, op, "enroll.sealing"),
                Decision::Allow {
                    via: via("svc.enroll")
                },
                "granted sealer must be allowed to {op:?} a sealing key"
            );
        }
    }

    #[test]
    fn sealing_key_denies_get_and_set_even_for_the_sealer() {
        // INVARIANT 1: the private half is never released. The `sealer` role does
        // NOT include get/set; default-deny holds for both (the sealing class is
        // not world-readable like `public`, so an unauthorized read also fails).
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // enroll.sealing is writable=true, so the write ops are not stopped by the
        // §2.4.2 hard cap; they reach plain default-deny (NotPermitted) because the
        // `sealer` role grants neither read nor write of the private half.
        for op in [
            Op::Get,
            Op::Set,
            Op::Sign,
            Op::Rotate,
            Op::Import,
            Op::NewKey,
        ] {
            assert_eq!(
                decide(&pdp, 9005, op, "enroll.sealing"),
                Decision::Deny {
                    reason: DenyReason::NotPermitted
                },
                "sealer must not be able to {op:?} a sealing key"
            );
        }
    }

    #[test]
    fn sealing_key_default_denies_without_a_grant() {
        // INVARIANT 2 (default-deny): an arbitrary uid with no rule gets nothing on
        // a sealing key: not even get_public_key (it is NOT class:public).
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        for op in [Op::Decrypt, Op::GetPublicKey, Op::Get] {
            assert_eq!(
                decide(&pdp, 424_242, op, "enroll.sealing"),
                Decision::Deny {
                    reason: DenyReason::NotPermitted
                },
                "ungranted {op:?} on a sealing key must default-deny"
            );
        }
    }

    // ---- Broker-admin ops (basil-atq, basil-luw5, basil-3wnn) ---------------

    #[test]
    fn decide_admin_allows_explicit_reload_grant() {
        // uid 9006 has an explicit `op:reload` over the reserved admin target.
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        assert_eq!(
            decide_admin(&pdp, 9006, Op::Reload),
            Decision::Allow {
                via: via("svc.reload")
            }
        );
        // Also reachable via a group grant (gid 10 = wheel; uid 5000 is in it via
        // supplementary membership).
        assert_eq!(
            decide_admin(&pdp, 5000, Op::Reload),
            Decision::Allow {
                via: via("ops.wheel")
            }
        );
    }

    #[test]
    fn decide_admin_allows_explicit_revoke_grant() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        assert_eq!(
            decide_admin(&pdp, 9007, Op::Revoke),
            Decision::Allow {
                via: via("svc.revoke")
            }
        );
    }

    #[test]
    fn decide_admin_default_denies_without_an_explicit_reload_grant() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // A uid with no reload rule at all is denied.
        assert_eq!(
            decide_admin(&pdp, 7777, Op::Reload),
            Decision::Deny {
                reason: DenyReason::NotPermitted
            }
        );
    }

    #[test]
    fn no_data_plane_grant_implies_admin_ops() {
        // CRITICAL least-privilege guarantee: no data-plane grant (not even a
        // signer/minter/operator role, and NOT root's `* / *`) authorizes broker
        // admin ops. Admin ops are excluded from ALL_OPS, so `*` never expands to
        // them.
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        for uid in [
            9002, // grafana reader
            9003, // nats signer
            9004, // nats minter
            9005, // enroll sealer
            0,    // root: `*` action over `*` target
        ] {
            for op in [Op::Reload, Op::Explain, Op::Revoke] {
                assert_eq!(
                    decide_admin(&pdp, uid, op),
                    Decision::Deny {
                        reason: DenyReason::NotPermitted
                    },
                    "uid {uid} (a data-plane/root grant) must NOT be able to {op:?}"
                );
            }
        }
    }

    #[test]
    fn breakglass_data_plane_wildcard_still_excludes_admin_ops() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        let actor = pdp
            .resolve_unix_actor(0)
            .expect("root breakglass subject resolves");

        // The `*` action/target rule grants root every key-scoped data-plane op,
        // but admin ops use reserved broker targets and `decide_admin`.
        assert_eq!(
            pdp.decide(&actor, Op::Get, "grafana.admin_password"),
            Decision::Allow {
                via: via("breakglass.root")
            }
        );
        for op in [Op::Reload, Op::Explain, Op::Revoke] {
            assert_eq!(
                pdp.decide_admin(&actor, op),
                Decision::Deny {
                    reason: DenyReason::NotPermitted
                },
                "breakglass wildcard must not imply admin {op:?}"
            );
        }
    }

    #[test]
    fn presenter_identity_does_not_borrow_actor_authority() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        let mut actor = pdp
            .resolve_unix_actor(9002)
            .expect("grafana subject resolves");
        actor.presenter = PresenterInfo {
            pid: None,
            uid: Some(0),
            gid: Some(0),
            executable_path: None,
            display_label: Some("root-presenter".to_string()),
        };

        // Authorization is by resolved actor subject, not by a privileged
        // presenter uid carried for audit.
        assert_eq!(
            pdp.decide(&actor, Op::Get, "grafana.admin_password"),
            Decision::Allow {
                via: via("svc.grafana")
            }
        );
        assert_eq!(
            pdp.decide(&actor, Op::Sign, "nats.account"),
            Decision::Deny {
                reason: DenyReason::NotPermitted
            }
        );
        assert_eq!(
            pdp.decide_admin(&actor, Op::Reload),
            Decision::Deny {
                reason: DenyReason::NotPermitted
            }
        );
    }

    // ---- Decision helpers + audit labels ------------------------------------

    #[test]
    fn decision_predicates() {
        let allow = Decision::Allow {
            via: via("svc.grafana"),
        };
        let deny = Decision::Deny {
            reason: DenyReason::UnknownKey,
        };
        assert!(allow.is_allow() && !allow.is_deny());
        assert!(deny.is_deny() && !deny.is_allow());
    }

    #[test]
    fn audit_labels_render_name_num() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        assert_eq!(pdp.user_label(9002), "svc-grafana(9002)");
        assert_eq!(pdp.group_label(10), "wheel(10)");
        assert_eq!(pdp.user_label(123), "123"); // unknown uid -> bare number
    }

    // ---- explain / dry-run (basil-4vf) --------------------------------------

    #[test]
    fn explain_reports_matched_rule_on_user_allow() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        let ex = explain(&pdp, 9002, Op::Get, "grafana.admin_password");
        assert!(ex.is_allow());
        let m = ex.matched.expect("a rule-based allow carries provenance");
        assert_eq!(m.rule_id, "grafana-reader");
        assert_eq!(m.via, via("svc.grafana"));
        assert_eq!(m.subject, "svc.grafana");
        assert_eq!(m.action, "role:reader");
        assert_eq!(m.target, "grafana.admin_password");
    }

    #[test]
    fn explain_reports_specific_role_rule_not_a_sibling() {
        // uid 9003 (signer) and 9004 (minter) share the nats.account target but via
        // DIFFERENT rules; explain must name the rule that actually matched.
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);

        let signer = explain(&pdp, 9003, Op::Sign, "nats.account");
        assert_eq!(
            signer.matched.as_ref().map(|m| m.rule_id.as_str()),
            Some("nats-signer")
        );
        assert_eq!(
            signer.matched.as_ref().map(|m| m.action.as_str()),
            Some("role:signer")
        );

        let minter = explain(&pdp, 9004, Op::Mint, "nats.account");
        assert_eq!(
            minter.matched.as_ref().map(|m| m.rule_id.as_str()),
            Some("nats-minter")
        );
        assert_eq!(
            minter.matched.as_ref().map(|m| m.action.as_str()),
            Some("role:minter")
        );
    }

    #[test]
    fn explain_reports_group_rule_with_glob_target() {
        // uid 5000 reaches the wheel(10) operator rule only via supplementary
        // membership, over the `grafana.**` glob.
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        let ex = explain(&pdp, 5000, Op::Set, "grafana.admin_password");
        let m = ex.matched.expect("group allow carries provenance");
        assert_eq!(m.rule_id, "wheel-operator");
        assert_eq!(m.via, via("ops.wheel"));
        assert_eq!(m.subject, "ops.wheel");
        assert_eq!(m.action, "role:operator");
        assert_eq!(m.target, "grafana.**");
    }

    #[test]
    fn explain_public_class_allow_has_no_rule() {
        // The §3.5 world-readable allow is produced by NO policy rule.
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        let ex = explain(&pdp, 9002, Op::Get, "web.tls.ca_cert");
        assert_eq!(
            ex.decision,
            Decision::Allow {
                via: AllowVia::PublicClass
            }
        );
        assert!(
            ex.matched.is_none(),
            "public-class allow has no matched rule"
        );
    }

    #[test]
    fn explain_deny_is_default_deny_with_no_rule() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // unmatched principal -> default-deny.
        let ex = explain(&pdp, 7777, Op::Get, "grafana.admin_password");
        assert_eq!(
            ex.decision,
            Decision::Deny {
                reason: DenyReason::NotPermitted
            }
        );
        assert!(ex.matched.is_none());
        // unknown key and hard-cap denies also carry no rule.
        assert!(
            explain(&pdp, 0, Op::Get, "does.not.exist")
                .matched
                .is_none()
        );
        assert_eq!(
            explain(&pdp, 0, Op::Set, "locked.value").decision,
            Decision::Deny {
                reason: DenyReason::NotWritable
            }
        );
    }

    /// THE anti-divergence guard: `explain(...).decision` MUST equal `decide(...)`
    /// for every tuple: a dry-run that ever reports a different decision than
    /// enforcement is a fail-closed-bypass security bug. Sweep a broad matrix.
    #[test]
    fn explain_decision_always_equals_decide() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        let uids = [0, 9002, 9003, 9004, 9005, 5000, 7777, 424_242];
        let keys = [
            "nats.account",
            "web.tls.ca_cert",
            "grafana.admin_password",
            "locked.value",
            "enroll.sealing",
            "does.not.exist",
        ];
        let ops = [
            Op::Get,
            Op::List,
            Op::GetPublicKey,
            Op::Verify,
            Op::Sign,
            Op::Encrypt,
            Op::Decrypt,
            Op::Mint,
            Op::SignNatsJwt,
            Op::Validate,
            Op::Set,
            Op::Rotate,
            Op::Import,
            Op::NewKey,
        ];
        for uid in uids {
            for &key in &keys {
                for op in ops {
                    let decide = decide(&pdp, uid, op, key);
                    let explain = explain(&pdp, uid, op, key);
                    assert_eq!(
                        explain.decision, decide,
                        "explain/decide diverged at uid={uid} op={op:?} key={key}"
                    );
                    // An allow carries provenance unless it is the public-class rule.
                    if let Decision::Allow { via } = explain.decision {
                        let has_rule = explain.matched.is_some();
                        assert_eq!(
                            has_rule,
                            via != AllowVia::PublicClass,
                            "rule provenance presence wrong at uid={uid} op={op:?} key={key}"
                        );
                    } else {
                        assert!(explain.matched.is_none());
                    }
                }
            }
        }
    }

    #[test]
    fn effective_lists_only_granted_pairs_with_provenance() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        // uid 9002 = grafana reader: get/list/get_public_key over grafana.admin_password,
        // PLUS the public-class reads of web.tls.ca_cert that every uid gets.
        let grants = pdp.effective("svc.grafana");
        // Every returned pair is genuinely allowed (cross-check against decide).
        for g in &grants {
            assert!(
                decide(&pdp, 9002, g.op, &g.key).is_allow(),
                "effective listed a non-granted pair: {} {:?}",
                g.key,
                g.op
            );
        }
        // The reader's three ops over its own key are present, all via the rule.
        for op in [Op::Get, Op::List, Op::GetPublicKey] {
            let hit = grants
                .iter()
                .find(|g| g.key == "grafana.admin_password" && g.op == op)
                .expect("reader grant present");
            assert_eq!(hit.rule_id.as_deref(), Some("grafana-reader"));
            assert_eq!(hit.via, via("svc.grafana"));
        }
        // The world-readable reads appear with no rule id.
        let public = grants
            .iter()
            .find(|g| g.key == "web.tls.ca_cert" && g.op == Op::Get)
            .expect("public-class read present");
        assert!(public.rule_id.is_none());
        assert_eq!(public.via, AllowVia::PublicClass);
        // A non-granted op (sign on grafana) is absent.
        assert!(
            !grants
                .iter()
                .any(|g| g.key == "grafana.admin_password" && g.op == Op::Sign)
        );
    }

    #[test]
    fn effective_is_computed_for_subjects() {
        let (c, r, cfg) = fixture();
        let pdp = Pdp::new(&c, &r, &cfg);
        let grants = pdp.effective("ops.wheel");
        let op_set = grants
            .iter()
            .find(|g| g.key == "grafana.admin_password" && g.op == Op::Set)
            .expect("wheel subject yields the operator grant");
        assert_eq!(op_set.via, via("ops.wheel"));
        assert_eq!(op_set.rule_id.as_deref(), Some("wheel-operator"));

        let missing = pdp.effective("missing.subject");
        assert!(missing.is_empty());
    }
}
