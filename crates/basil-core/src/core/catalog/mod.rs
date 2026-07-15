// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Catalog + policy schema, loader, and resolution (design `catalog-policy-schema.html`).
//!
//! The broker loads two **exported JSON** documents at startup:
//!
//! - a **catalog** ([`schema`]): the key inventory + backend routing table (§2);
//! - a **policy** ([`policy`]): the authorization allow-list + the
//!   export-resolved name/membership tables (§3, §4).
//!
//! [`load`] parses and validates both (§5's full hard-error list), then builds a
//! [`ResolvedPolicy`] allow-index. Per-request `AuthenticatedActor`
//! authorization is handled by the [`pdp::Pdp`] engine, which consumes that
//! index plus the catalog and config. Default-deny is the **absence** of a
//! matching grant: this module only carries the allows.
//!
//! Glob matching ([`glob`]) is the load-bearing §3.4 semantics: wildcards are
//! last-position only, `*` matches exactly one segment, `**` matches one-or-more.

pub mod evidence;
pub mod glob;
pub mod loader;
pub mod pdp;
pub mod policy;
pub mod schema;

pub use evidence::{
    AuthorizationDomain, ComposeEvidence, ComposeProjectSelector, ComposeServiceSelector,
    ContainerRuntimeKind, CredentialSlot, CredentialSlots, EvidenceExpression, EvidencePredicate,
    EvidenceResolutionError, EvidenceSnapshot, EvidenceState, EvidenceValue, IdentitySelector,
    LocalAccountSource, MAX_EXPRESSION_DEPTH, MAX_EXPRESSION_LEAVES, MAX_REPORTED_SUBJECTS,
    ProcessEvidence, SignatureKeyEvidence, SubjectResolution, SystemdEvidence, SystemdSelector,
    resolve_subject,
};
pub use glob::{GlobError, GlobSeg, KeyGlob};
pub use loader::{
    LoadError, LoadWarning, PolicySchema, RawEvidenceExpression, RawPolicy, RawRule,
    RawSubjectDefinition, load,
};
pub use pdp::{
    ADMIN_EXPLAIN_TARGET, ADMIN_RELOAD_TARGET, ADMIN_REVOKE_TARGET, ADMIN_WATCH_TARGET, AllowVia,
    Decision, DenyReason, EffectiveGrant, Explanation, MatchedRule, Pdp,
};
pub use policy::{
    ActionTerm, ActionTermError, Config, Grant, NameTable, Op, ResolvedPolicy, ResolvedRule, Rule,
    SignatureKeyAlgorithm, SubjectDefinition, SubjectName,
};
pub use schema::{
    BackendKind, BackendRef, Capability, Catalog, CatalogSchema, Class, Engine, GenerateSpec,
    KeyAlgorithm, KeyEntry, Labels, MissingPolicy,
};
