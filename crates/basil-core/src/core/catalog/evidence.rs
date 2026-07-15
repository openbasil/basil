// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Provider-independent authorization evidence and recursive policy evaluation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::policy::{SignatureKeyAlgorithm, SubjectDefinition, SubjectName};

/// Maximum recursive `all`/`any` nesting accepted in one subject expression.
pub const MAX_EXPRESSION_DEPTH: usize = 8;
/// Maximum leaf predicates accepted in one subject expression.
pub const MAX_EXPRESSION_LEAVES: usize = 64;
/// Maximum matching subject names retained in a bounded resolution result.
pub const MAX_REPORTED_SUBJECTS: usize = 8;

/// The disjoint local workload domains supported by corpus schema 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorizationDomain {
    /// A local process not attributed to a more-specific supported manager.
    HostProcess,
    /// A workload established as a systemd service unit.
    SystemdUnit,
    /// A workload established by a supported container runtime.
    Container,
}

impl AuthorizationDomain {
    /// Stable schema token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::HostProcess => "host-process",
            Self::SystemdUnit => "systemd-unit",
            Self::Container => "container",
        }
    }
}

/// A numeric process identity compiled from a numeric or symbolic policy value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentitySelector {
    /// A numeric identifier supplied directly by policy.
    Numeric(u32),
    /// A local account name resolved atomically while loading policy.
    LocalName {
        /// The original local account name.
        name: String,
        /// The numeric identifier compiled into the serving policy.
        id: u32,
        /// The local account database used for resolution.
        source: LocalAccountSource,
    },
}

impl IdentitySelector {
    /// Numeric identifier used by the evaluator.
    #[must_use]
    pub const fn id(&self) -> u32 {
        match self {
            Self::Numeric(id) | Self::LocalName { id, .. } => *id,
        }
    }

    /// Whether this value originated as a symbolic local account name.
    #[must_use]
    pub const fn is_symbolic(&self) -> bool {
        matches!(self, Self::LocalName { .. })
    }
}

/// Local account database used to compile a symbolic identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAccountSource {
    /// `/etc/passwd` username entry.
    Passwd,
    /// `/etc/group` group-name entry.
    Group,
}

/// A systemd service-unit selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdSelector {
    /// Canonical unit or template name.
    pub name: String,
    /// Per-user manager owner. Absence means the system manager.
    pub manager_user: Option<IdentitySelector>,
}

/// Exact Compose service identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeServiceSelector {
    /// Configured attestor realm.
    pub realm: String,
    /// Effective Compose project name.
    pub project: String,
    /// Compose service name.
    pub name: String,
}

/// Exact Compose project identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeProjectSelector {
    /// Configured attestor realm.
    pub realm: String,
    /// Effective Compose project name.
    pub project: String,
}

/// Supported runtime kinds exposed to policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerRuntimeKind {
    /// Docker Engine.
    Docker,
    /// Podman.
    Podman,
}

/// One typed, namespaced evidence predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidencePredicate {
    /// All caller-visible user credential slots equal the selected ID.
    ProcessUid(IdentitySelector),
    /// One caller-visible user credential slot equals the selected ID.
    ProcessUidSlot(CredentialSlot, IdentitySelector),
    /// All caller-visible primary group credential slots equal the selected ID.
    ProcessGid(IdentitySelector),
    /// One caller-visible primary group credential slot equals the selected ID.
    ProcessGidSlot(CredentialSlot, IdentitySelector),
    /// Supplementary group membership contains the selected ID.
    ProcessGidSupplementary(IdentitySelector),
    /// Pinned executable content has this canonical digest.
    ProcessExecutableDigest(String),
    /// Exact canonical systemd service-unit identity.
    SystemdUnit(SystemdSelector),
    /// Exact canonical systemd template identity.
    SystemdTemplate(SystemdSelector),
    /// Exact Compose service identity.
    ComposeService(ComposeServiceSelector),
    /// Exact Compose project identity.
    ComposeProject(ComposeProjectSelector),
    /// Supported container runtime kind.
    RuntimeKind(ContainerRuntimeKind),
    /// Named OCI signer policy that verified the immutable image digest.
    OciSigner(String),
    /// Verified sealed-invocation signature key.
    InvocationSignatureKey {
        /// Signature algorithm family.
        algorithm: SignatureKeyAlgorithm,
        /// Canonical public key material.
        public: String,
    },
}

/// Independently usable real/effective/saved/filesystem credential slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSlot {
    /// Real process credential.
    Real,
    /// Effective process credential.
    Effective,
    /// Saved-set process credential.
    Saved,
    /// Filesystem process credential.
    Filesystem,
}

/// A monotonic recursive subject expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceExpression {
    /// Every child must match.
    All(Vec<Self>),
    /// At least one child must match.
    Any(Vec<Self>),
    /// One typed evidence predicate.
    Leaf(EvidencePredicate),
}

impl EvidenceExpression {
    /// Maximum group nesting depth, where a leaf has depth zero.
    #[must_use]
    pub fn depth(&self) -> usize {
        match self {
            Self::Leaf(_) => 0,
            Self::All(children) | Self::Any(children) => {
                1 + children.iter().map(Self::depth).max().unwrap_or(0)
            }
        }
    }

    /// Number of leaf predicates.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        match self {
            Self::Leaf(_) => 1,
            Self::All(children) | Self::Any(children) => {
                children.iter().map(Self::leaf_count).sum()
            }
        }
    }

    /// Visit every leaf predicate in declaration order.
    pub fn visit_leaves(&self, visitor: &mut impl FnMut(&EvidencePredicate)) {
        match self {
            Self::Leaf(predicate) => visitor(predicate),
            Self::All(children) | Self::Any(children) => {
                for child in children {
                    child.visit_leaves(visitor);
                }
            }
        }
    }

    /// Evaluate this expression over one immutable evidence snapshot.
    #[must_use]
    pub fn evaluate(&self, evidence: &EvidenceSnapshot) -> EvidenceState {
        match self {
            Self::Leaf(predicate) => evidence.evaluate(predicate),
            Self::All(children) => evaluate_all(children, evidence),
            Self::Any(children) => evaluate_any(children, evidence),
        }
    }

    /// Evaluate for subject resolution, requiring a verified signature leaf on
    /// a successful sealed-invocation path when signature evidence is present.
    #[must_use]
    pub fn evaluate_for_resolution(&self, evidence: &EvidenceSnapshot) -> EvidenceState {
        let require_signature = matches!(
            evidence.invocation_signature_key,
            EvidenceValue::Available(_)
        );
        let (state, signature_bound) = self.evaluate_with_signature_path(evidence);
        if require_signature && state == EvidenceState::Match && !signature_bound {
            EvidenceState::NoMatch
        } else {
            state
        }
    }

    fn evaluate_with_signature_path(&self, evidence: &EvidenceSnapshot) -> (EvidenceState, bool) {
        match self {
            Self::Leaf(predicate) => (
                evidence.evaluate(predicate),
                matches!(predicate, EvidencePredicate::InvocationSignatureKey { .. }),
            ),
            Self::All(children) => {
                let mut state = EvidenceState::Match;
                let mut signature_bound = false;
                for child in children {
                    let (child_state, child_bound) = child.evaluate_with_signature_path(evidence);
                    signature_bound |= child_state == EvidenceState::Match && child_bound;
                    if child_state == EvidenceState::NoMatch {
                        return (EvidenceState::NoMatch, false);
                    }
                    if child_state == EvidenceState::Unavailable {
                        state = EvidenceState::Unavailable;
                    }
                }
                (state, state == EvidenceState::Match && signature_bound)
            }
            Self::Any(children) => {
                let mut saw_match = false;
                let mut saw_unavailable = false;
                let mut signature_bound = false;
                for child in children {
                    let (child_state, child_bound) = child.evaluate_with_signature_path(evidence);
                    match child_state {
                        EvidenceState::Match => {
                            saw_match = true;
                            signature_bound |= child_bound;
                        }
                        EvidenceState::Unavailable => saw_unavailable = true,
                        EvidenceState::NoMatch => {}
                    }
                }
                if saw_match {
                    (EvidenceState::Match, signature_bound)
                } else if saw_unavailable {
                    (EvidenceState::Unavailable, false)
                } else {
                    (EvidenceState::NoMatch, false)
                }
            }
        }
    }
}

fn evaluate_all(children: &[EvidenceExpression], evidence: &EvidenceSnapshot) -> EvidenceState {
    let mut saw_unavailable = false;
    for child in children {
        match child.evaluate(evidence) {
            EvidenceState::NoMatch => return EvidenceState::NoMatch,
            EvidenceState::Unavailable => saw_unavailable = true,
            EvidenceState::Match => {}
        }
    }
    if saw_unavailable {
        EvidenceState::Unavailable
    } else {
        EvidenceState::Match
    }
}

fn evaluate_any(children: &[EvidenceExpression], evidence: &EvidenceSnapshot) -> EvidenceState {
    let mut saw_unavailable = false;
    for child in children {
        match child.evaluate(evidence) {
            EvidenceState::Match => return EvidenceState::Match,
            EvidenceState::Unavailable => saw_unavailable = true,
            EvidenceState::NoMatch => {}
        }
    }
    if saw_unavailable {
        EvidenceState::Unavailable
    } else {
        EvidenceState::NoMatch
    }
}

/// Three-state evidence result used by leaves, expressions, and subjects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceState {
    /// Trusted evidence equals the configured predicate.
    Match,
    /// Trusted evidence is available and differs from the predicate.
    NoMatch,
    /// Required evidence could not be established safely.
    Unavailable,
}

impl EvidenceState {
    /// Stable audit and diagnostics token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::NoMatch => "no-match",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Availability wrapper that never turns missing evidence into a match.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EvidenceValue<T> {
    /// Trusted evidence was captured successfully.
    Available(T),
    /// Evidence was absent, unstable, conflicting, or temporarily unavailable.
    #[default]
    Unavailable,
}

impl<T: PartialEq> EvidenceValue<T> {
    fn compare(&self, expected: &T) -> EvidenceState {
        match self {
            Self::Available(actual) if actual == expected => EvidenceState::Match,
            Self::Available(_) => EvidenceState::NoMatch,
            Self::Unavailable => EvidenceState::Unavailable,
        }
    }
}

/// Four independently observed process credential slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialSlots {
    /// Real credential.
    pub real: u32,
    /// Effective credential.
    pub effective: u32,
    /// Saved-set credential.
    pub saved: u32,
    /// Filesystem credential.
    pub filesystem: u32,
}

impl CredentialSlots {
    /// Construct uniform slots for an explicitly trusted aggregate observation.
    #[must_use]
    pub const fn uniform(id: u32) -> Self {
        Self {
            real: id,
            effective: id,
            saved: id,
            filesystem: id,
        }
    }

    const fn slot(self, slot: CredentialSlot) -> u32 {
        match slot {
            CredentialSlot::Real => self.real,
            CredentialSlot::Effective => self.effective,
            CredentialSlot::Saved => self.saved,
            CredentialSlot::Filesystem => self.filesystem,
        }
    }

    const fn all_equal(self, expected: u32) -> bool {
        self.real == expected
            && self.effective == expected
            && self.saved == expected
            && self.filesystem == expected
    }
}

/// Fresh process evidence used by credential predicates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessEvidence {
    /// Caller-visible user credential slots.
    pub uids: EvidenceValue<CredentialSlots>,
    /// Caller-visible primary group credential slots.
    pub gids: EvidenceValue<CredentialSlots>,
    /// Caller-visible supplementary groups.
    pub supplementary_gids: EvidenceValue<Vec<u32>>,
    /// Canonical executable-content digest.
    pub executable_digest: EvidenceValue<String>,
}

/// Trusted systemd identity correlated to the pinned presenter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdEvidence {
    /// Canonical concrete `.service` unit name.
    pub unit: String,
    /// Canonical template name for an instantiated unit.
    pub template: Option<String>,
    /// Per-user manager owner. Absence means the system manager.
    pub manager_user: Option<u32>,
}

/// Trusted Compose identity correlated to a runtime container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeEvidence {
    /// Configured attestor realm.
    pub realm: String,
    /// Effective Compose project name.
    pub project: String,
    /// Compose service name for a normal service container.
    pub service: Option<String>,
}

/// A verified invocation signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureKeyEvidence {
    /// Signature algorithm family.
    pub algorithm: SignatureKeyAlgorithm,
    /// Canonical public key material.
    pub public: String,
}

/// One immutable provider-independent snapshot used by subject resolution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceSnapshot {
    /// Independently resolved local workload domain.
    pub domain: EvidenceValue<AuthorizationDomain>,
    /// Fresh pinned process evidence.
    pub process: ProcessEvidence,
    /// Correlated systemd identity.
    pub systemd: EvidenceValue<SystemdEvidence>,
    /// Correlated Compose identity.
    pub compose: EvidenceValue<ComposeEvidence>,
    /// Correlated runtime kind.
    pub runtime: EvidenceValue<ContainerRuntimeKind>,
    /// OCI signer policies that verified the immutable image digest.
    pub oci_signers: EvidenceValue<Vec<String>>,
    /// Verified sealed-invocation signing key.
    pub invocation_signature_key: EvidenceValue<SignatureKeyEvidence>,
}

impl EvidenceSnapshot {
    /// Evaluate one predicate without exposing expected values to callers.
    #[must_use]
    pub fn evaluate(&self, predicate: &EvidencePredicate) -> EvidenceState {
        match predicate {
            EvidencePredicate::ProcessUid(selector) => {
                compare_slots(&self.process.uids, selector.id(), None)
            }
            EvidencePredicate::ProcessUidSlot(slot, selector) => {
                compare_slots(&self.process.uids, selector.id(), Some(*slot))
            }
            EvidencePredicate::ProcessGid(selector) => {
                compare_slots(&self.process.gids, selector.id(), None)
            }
            EvidencePredicate::ProcessGidSlot(slot, selector) => {
                compare_slots(&self.process.gids, selector.id(), Some(*slot))
            }
            EvidencePredicate::ProcessGidSupplementary(selector) => {
                compare_membership(&self.process.supplementary_gids, selector.id())
            }
            EvidencePredicate::ProcessExecutableDigest(expected) => {
                self.process.executable_digest.compare(expected)
            }
            EvidencePredicate::SystemdUnit(expected) => compare_systemd(
                &self.systemd,
                &expected.name,
                expected.manager_user.as_ref().map(IdentitySelector::id),
                false,
            ),
            EvidencePredicate::SystemdTemplate(expected) => compare_systemd(
                &self.systemd,
                &expected.name,
                expected.manager_user.as_ref().map(IdentitySelector::id),
                true,
            ),
            EvidencePredicate::ComposeService(expected) => {
                compare_compose_service(&self.compose, expected)
            }
            EvidencePredicate::ComposeProject(expected) => {
                compare_compose_project(&self.compose, expected)
            }
            EvidencePredicate::RuntimeKind(expected) => self.runtime.compare(expected),
            EvidencePredicate::OciSigner(expected) => {
                compare_membership_string(&self.oci_signers, expected)
            }
            EvidencePredicate::InvocationSignatureKey { algorithm, public } => self
                .invocation_signature_key
                .compare(&SignatureKeyEvidence {
                    algorithm: *algorithm,
                    public: public.clone(),
                }),
        }
    }
}

fn compare_slots(
    evidence: &EvidenceValue<CredentialSlots>,
    expected: u32,
    slot: Option<CredentialSlot>,
) -> EvidenceState {
    match evidence {
        EvidenceValue::Available(actual)
            if slot.map_or_else(
                || actual.all_equal(expected),
                |slot| actual.slot(slot) == expected,
            ) =>
        {
            EvidenceState::Match
        }
        EvidenceValue::Available(_) => EvidenceState::NoMatch,
        EvidenceValue::Unavailable => EvidenceState::Unavailable,
    }
}

fn compare_membership(evidence: &EvidenceValue<Vec<u32>>, expected: u32) -> EvidenceState {
    match evidence {
        EvidenceValue::Available(actual) if actual.contains(&expected) => EvidenceState::Match,
        EvidenceValue::Available(_) => EvidenceState::NoMatch,
        EvidenceValue::Unavailable => EvidenceState::Unavailable,
    }
}

fn compare_membership_string(
    evidence: &EvidenceValue<Vec<String>>,
    expected: &str,
) -> EvidenceState {
    match evidence {
        EvidenceValue::Available(actual) if actual.iter().any(|value| value == expected) => {
            EvidenceState::Match
        }
        EvidenceValue::Available(_) => EvidenceState::NoMatch,
        EvidenceValue::Unavailable => EvidenceState::Unavailable,
    }
}

fn compare_systemd(
    evidence: &EvidenceValue<SystemdEvidence>,
    name: &str,
    manager_user: Option<u32>,
    template: bool,
) -> EvidenceState {
    match evidence {
        EvidenceValue::Available(actual) => {
            let actual_name = if template {
                actual.template.as_deref()
            } else {
                Some(actual.unit.as_str())
            };
            if actual_name == Some(name) && actual.manager_user == manager_user {
                EvidenceState::Match
            } else {
                EvidenceState::NoMatch
            }
        }
        EvidenceValue::Unavailable => EvidenceState::Unavailable,
    }
}

fn compare_compose_service(
    evidence: &EvidenceValue<ComposeEvidence>,
    expected: &ComposeServiceSelector,
) -> EvidenceState {
    match evidence {
        EvidenceValue::Available(actual)
            if actual.realm == expected.realm
                && actual.project == expected.project
                && actual.service.as_deref() == Some(expected.name.as_str()) =>
        {
            EvidenceState::Match
        }
        EvidenceValue::Available(_) => EvidenceState::NoMatch,
        EvidenceValue::Unavailable => EvidenceState::Unavailable,
    }
}

fn compare_compose_project(
    evidence: &EvidenceValue<ComposeEvidence>,
    expected: &ComposeProjectSelector,
) -> EvidenceState {
    match evidence {
        EvidenceValue::Available(actual)
            if actual.realm == expected.realm && actual.project == expected.project =>
        {
            EvidenceState::Match
        }
        EvidenceValue::Available(_) => EvidenceState::NoMatch,
        EvidenceValue::Unavailable => EvidenceState::Unavailable,
    }
}

/// Bounded aggregate subject-resolution result for trusted audit/diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectResolution {
    /// Independently resolved domain.
    pub domain: AuthorizationDomain,
    /// Uniquely resolved subject, when resolution succeeded.
    pub subject: Option<SubjectName>,
    /// Bounded lexicographic prefix of matching subject names.
    pub matching_subjects: Vec<SubjectName>,
    /// Total matching subject count before bounding.
    pub matching_count: usize,
    /// Number of conclusively non-matching eligible subjects.
    pub no_match_count: usize,
    /// Number of eligible subjects whose expression was unavailable.
    pub unavailable_count: usize,
    /// Whether matching names were truncated.
    pub matching_subjects_truncated: bool,
}

/// Fail-closed subject resolution failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceResolutionError {
    /// The local workload domain could not be established safely.
    DomainUnavailable,
    /// Every eligible subject conclusively failed to match.
    NoSubject(SubjectResolution),
    /// More than one eligible subject matched.
    AmbiguousSubject(SubjectResolution),
    /// At least one otherwise eligible subject required unavailable evidence.
    EvidenceUnavailable(SubjectResolution),
}

/// Resolve exactly one domain-scoped subject from one immutable snapshot.
pub fn resolve_subject(
    subjects: &BTreeMap<SubjectName, SubjectDefinition>,
    evidence: &EvidenceSnapshot,
) -> Result<SubjectResolution, EvidenceResolutionError> {
    let EvidenceValue::Available(domain) = evidence.domain else {
        return Err(EvidenceResolutionError::DomainUnavailable);
    };
    let mut matching = Vec::new();
    let mut matching_count = 0;
    let mut no_match_count = 0;
    let mut unavailable_count = 0;
    for (name, definition) in subjects {
        if definition.domain != domain {
            continue;
        }
        match definition.match_.evaluate_for_resolution(evidence) {
            EvidenceState::Match => {
                matching_count += 1;
                if matching.len() < MAX_REPORTED_SUBJECTS {
                    matching.push(name.clone());
                }
            }
            EvidenceState::NoMatch => no_match_count += 1,
            EvidenceState::Unavailable => unavailable_count += 1,
        }
    }
    let matching_subjects_truncated = matching_count > MAX_REPORTED_SUBJECTS;
    let subject = (matching_count == 1 && unavailable_count == 0)
        .then(|| matching.first().cloned())
        .flatten();
    let resolution = SubjectResolution {
        domain,
        subject,
        matching_subjects: matching,
        matching_count,
        no_match_count,
        unavailable_count,
        matching_subjects_truncated,
    };
    if matching_count > 1 {
        Err(EvidenceResolutionError::AmbiguousSubject(resolution))
    } else if unavailable_count > 0 {
        Err(EvidenceResolutionError::EvidenceUnavailable(resolution))
    } else if matching_count == 0 {
        Err(EvidenceResolutionError::NoSubject(resolution))
    } else {
        Ok(resolution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(domain: AuthorizationDomain, match_: EvidenceExpression) -> SubjectDefinition {
        SubjectDefinition {
            domain,
            break_glass: false,
            match_,
        }
    }

    fn uid(expected: u32) -> EvidenceExpression {
        EvidenceExpression::Leaf(EvidencePredicate::ProcessUid(IdentitySelector::Numeric(
            expected,
        )))
    }

    fn evidence(available: bool) -> EvidenceSnapshot {
        EvidenceSnapshot {
            process: ProcessEvidence {
                uids: if available {
                    EvidenceValue::Available(CredentialSlots::uniform(7))
                } else {
                    EvidenceValue::Unavailable
                },
                ..ProcessEvidence::default()
            },
            ..EvidenceSnapshot::default()
        }
    }

    #[test]
    fn recursive_algebra_is_monotonic() {
        let mut unavailable = evidence(false);
        unavailable.runtime = EvidenceValue::Available(ContainerRuntimeKind::Podman);
        assert_eq!(
            EvidenceExpression::All(vec![
                uid(7),
                EvidenceExpression::Leaf(EvidencePredicate::RuntimeKind(
                    ContainerRuntimeKind::Docker,
                )),
            ])
            .evaluate(&unavailable),
            EvidenceState::NoMatch
        );
        assert_eq!(
            EvidenceExpression::Any(vec![
                uid(7),
                EvidenceExpression::Leaf(EvidencePredicate::RuntimeKind(
                    ContainerRuntimeKind::Podman,
                )),
            ])
            .evaluate(&unavailable),
            EvidenceState::Match
        );
        assert_eq!(
            EvidenceExpression::Any(vec![uid(7)]).evaluate(&unavailable),
            EvidenceState::Unavailable
        );
    }

    #[test]
    fn unavailable_candidate_prevents_unique_resolution() {
        let subjects = BTreeMap::from([
            (
                "matched".to_string(),
                subject(AuthorizationDomain::HostProcess, uid(7)),
            ),
            (
                "unknown".to_string(),
                subject(
                    AuthorizationDomain::HostProcess,
                    EvidenceExpression::Leaf(EvidencePredicate::ProcessExecutableDigest(
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    )),
                ),
            ),
        ]);
        let mut snapshot = evidence(true);
        snapshot.domain = EvidenceValue::Available(AuthorizationDomain::HostProcess);
        assert!(matches!(
            resolve_subject(&subjects, &snapshot),
            Err(EvidenceResolutionError::EvidenceUnavailable(
                SubjectResolution {
                    matching_count: 1,
                    unavailable_count: 1,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn conclusive_all_no_match_masks_unavailable_child() {
        let subjects = BTreeMap::from([(
            "stable-no-match".to_string(),
            subject(
                AuthorizationDomain::HostProcess,
                EvidenceExpression::All(vec![
                    uid(8),
                    EvidenceExpression::Leaf(EvidencePredicate::ProcessExecutableDigest(
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    )),
                ]),
            ),
        )]);
        let mut snapshot = evidence(true);
        snapshot.domain = EvidenceValue::Available(AuthorizationDomain::HostProcess);
        assert!(matches!(
            resolve_subject(&subjects, &snapshot),
            Err(EvidenceResolutionError::NoSubject(SubjectResolution {
                no_match_count: 1,
                unavailable_count: 0,
                ..
            }))
        ));
    }

    #[test]
    fn sealed_invocation_requires_signature_bound_success_path() {
        let public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let signature = EvidencePredicate::InvocationSignatureKey {
            algorithm: SignatureKeyAlgorithm::Ed25519,
            public: public.clone(),
        };
        let subjects = BTreeMap::from([
            (
                "local-only".to_string(),
                subject(AuthorizationDomain::HostProcess, uid(7)),
            ),
            (
                "remote".to_string(),
                subject(
                    AuthorizationDomain::HostProcess,
                    EvidenceExpression::All(vec![uid(7), EvidenceExpression::Leaf(signature)]),
                ),
            ),
        ]);
        let mut snapshot = evidence(true);
        snapshot.domain = EvidenceValue::Available(AuthorizationDomain::HostProcess);
        snapshot.invocation_signature_key = EvidenceValue::Available(SignatureKeyEvidence {
            algorithm: SignatureKeyAlgorithm::Ed25519,
            public,
        });
        let resolution = resolve_subject(&subjects, &snapshot).expect("remote subject resolves");
        assert_eq!(resolution.subject.as_deref(), Some("remote"));
        assert_eq!(resolution.no_match_count, 1);
    }

    #[test]
    fn compose_service_matches_all_three_identity_components_exactly() {
        let predicate = EvidencePredicate::ComposeService(ComposeServiceSelector {
            realm: "ci-podman".to_string(),
            project: "build".to_string(),
            name: "worker".to_string(),
        });
        let mut snapshot = EvidenceSnapshot {
            compose: EvidenceValue::Available(ComposeEvidence {
                realm: "ci-podman".to_string(),
                project: "build".to_string(),
                service: Some("worker".to_string()),
            }),
            ..EvidenceSnapshot::default()
        };
        assert_eq!(snapshot.evaluate(&predicate), EvidenceState::Match);
        snapshot.compose = EvidenceValue::Available(ComposeEvidence {
            realm: "other".to_string(),
            project: "build".to_string(),
            service: Some("worker".to_string()),
        });
        assert_eq!(snapshot.evaluate(&predicate), EvidenceState::NoMatch);
    }
}
