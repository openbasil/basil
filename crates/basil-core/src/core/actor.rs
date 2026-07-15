// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Authenticated authorization actor resolution.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};

use crate::catalog::evidence::{
    AuthorizationDomain, CredentialSlots, EvidenceResolutionError, EvidenceSnapshot, EvidenceState,
    EvidenceValue, ProcessEvidence, SignatureKeyEvidence, SubjectResolution, resolve_subject,
};
use crate::catalog::policy::{Config, ResolvedPolicy, SubjectName};
use crate::peer::PeerInfo;

/// A resolved actor that the `PDP` can authorize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedActor {
    /// Independently resolved local workload domain.
    pub domain: AuthorizationDomain,
    /// The uniquely selected policy subject.
    pub subject: SubjectName,
    /// Evidence summaries that established the subject.
    pub authenticated_by: Vec<ProofSummary>,
    /// The local presenter that brought the request to the broker.
    pub presenter: PresenterInfo,
    /// Transport facts for the request.
    pub transport: TransportInfo,
}

impl AuthenticatedActor {
    /// The presenter's `SO_PEERCRED` UID, when the actor came over a Unix socket.
    #[must_use]
    pub const fn unix_uid(&self) -> Option<u32> {
        self.presenter.uid
    }
}

/// Evidence that established an [`AuthenticatedActor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofSummary {
    /// The kind of proof.
    pub kind: ProofKind,
    /// The subject established by this proof.
    pub subject: SubjectName,
    /// Disclosure-safe fingerprint for key evidence, when applicable.
    pub fingerprint: Option<String>,
}

/// Bounded proof kinds suitable for trusted audit output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// Fresh process credentials correlated to the pinned presenter.
    ProcessCredentials,
    /// Trusted systemd unit evidence.
    SystemdUnit,
    /// Trusted container/runtime evidence.
    Container,
    /// Verified sealed-invocation signature key.
    SignatureKey,
}

/// Information about the process or bridge that presented the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenterInfo {
    /// `SO_PEERCRED` process ID.
    pub pid: Option<u32>,
    /// `SO_PEERCRED` UID.
    pub uid: Option<u32>,
    /// `SO_PEERCRED` primary GID.
    pub gid: Option<u32>,
    /// Best-effort executable path from `/proc`.
    pub executable_path: Option<String>,
    /// Human-readable presenter label.
    pub display_label: Option<String>,
}

impl From<&PeerInfo> for PresenterInfo {
    fn from(peer: &PeerInfo) -> Self {
        Self {
            pid: peer.pid,
            uid: peer.uid,
            gid: peer.gid,
            executable_path: peer.executable_path.clone(),
            display_label: peer.display_label.clone(),
        }
    }
}

/// Transport facts for the request carrying the actor proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportInfo {
    /// The transport class.
    pub kind: TransportKind,
}

/// Supported transport classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// Local Unix-domain socket.
    UnixSocket,
}

impl Default for TransportInfo {
    fn default() -> Self {
        Self {
            kind: TransportKind::UnixSocket,
        }
    }
}

/// Why fail-closed subject resolution stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectResolutionError {
    /// No kernel peer credentials were captured.
    MissingPeerCredentials,
    /// The local workload domain could not be established safely.
    DomainUnavailable,
    /// Every eligible subject conclusively failed to match.
    NoSubject {
        /// Independently resolved domain.
        domain: AuthorizationDomain,
        /// Number of conclusively non-matching eligible subjects.
        no_match_count: usize,
    },
    /// More than one eligible subject matched.
    AmbiguousSubject {
        /// Independently resolved domain.
        domain: AuthorizationDomain,
        /// Bounded matching-subject prefix for trusted diagnostics.
        subjects: Vec<SubjectName>,
        /// Total matching-subject count.
        total: usize,
        /// Whether `subjects` was truncated.
        truncated: bool,
        /// Number of conclusively non-matching eligible subjects.
        no_match_count: usize,
        /// Number of eligible subjects with unavailable evidence.
        unavailable_count: usize,
    },
    /// An eligible subject required evidence that was unavailable.
    EvidenceUnavailable {
        /// Independently resolved domain.
        domain: AuthorizationDomain,
        /// Bounded matching-subject prefix for trusted diagnostics.
        subjects: Vec<SubjectName>,
        /// Whether `subjects` was truncated.
        truncated: bool,
        /// Number of matching eligible subjects.
        matching_count: usize,
        /// Number of conclusively non-matching eligible subjects.
        no_match_count: usize,
        /// Number of eligible subjects with unavailable evidence.
        unavailable_count: usize,
    },
}

impl SubjectResolutionError {
    /// Independently resolved domain retained for trusted diagnostics.
    #[must_use]
    pub const fn domain(&self) -> Option<AuthorizationDomain> {
        match self {
            Self::MissingPeerCredentials | Self::DomainUnavailable => None,
            Self::NoSubject { domain, .. }
            | Self::AmbiguousSubject { domain, .. }
            | Self::EvidenceUnavailable { domain, .. } => Some(*domain),
        }
    }

    /// Three-state evidence outcome retained for audit and diagnostics.
    #[must_use]
    pub const fn evidence_state(&self) -> EvidenceState {
        match self {
            Self::NoSubject { .. } => EvidenceState::NoMatch,
            Self::AmbiguousSubject { .. } => EvidenceState::Match,
            Self::MissingPeerCredentials
            | Self::DomainUnavailable
            | Self::EvidenceUnavailable { .. } => EvidenceState::Unavailable,
        }
    }

    /// Bounded matching-subject names for trusted diagnostics.
    #[must_use]
    pub fn matching_subjects(&self) -> &[SubjectName] {
        match self {
            Self::AmbiguousSubject { subjects, .. }
            | Self::EvidenceUnavailable { subjects, .. } => subjects,
            Self::MissingPeerCredentials | Self::DomainUnavailable | Self::NoSubject { .. } => &[],
        }
    }

    /// Aggregate `(match, no-match, unavailable)` eligible-subject counts.
    #[must_use]
    pub const fn subject_counts(&self) -> (usize, usize, usize) {
        match self {
            Self::MissingPeerCredentials | Self::DomainUnavailable => (0, 0, 0),
            Self::NoSubject { no_match_count, .. } => (0, *no_match_count, 0),
            Self::AmbiguousSubject {
                total,
                no_match_count,
                unavailable_count,
                ..
            } => (*total, *no_match_count, *unavailable_count),
            Self::EvidenceUnavailable {
                matching_count,
                no_match_count,
                unavailable_count,
                ..
            } => (*matching_count, *no_match_count, *unavailable_count),
        }
    }

    /// Whether the matching-subject diagnostic prefix was truncated.
    #[must_use]
    pub const fn matching_subjects_truncated(&self) -> bool {
        matches!(
            self,
            Self::AmbiguousSubject {
                truncated: true,
                ..
            } | Self::EvidenceUnavailable {
                truncated: true,
                ..
            }
        )
    }
}

/// Resolve a local request actor from captured peer information.
///
/// This compatibility adapter treats its caller as an explicitly selected
/// `host-process` input. The pinned classifier introduced by `basil-9tj.10`
/// supplies a complete [`EvidenceSnapshot`] through [`resolve_evidence_actor`].
pub fn resolve_local_actor(
    policy: &ResolvedPolicy,
    config: &Config,
    peer: &PeerInfo,
) -> Result<AuthenticatedActor, SubjectResolutionError> {
    let Some(uid) = peer.uid else {
        return Err(SubjectResolutionError::MissingPeerCredentials);
    };
    resolve_unix_actor(policy, config, peer, uid)
}

/// Resolve an offline host-process actor from an explicitly supplied UID.
pub fn resolve_unix_actor(
    policy: &ResolvedPolicy,
    config: &Config,
    peer: &PeerInfo,
    uid: u32,
) -> Result<AuthenticatedActor, SubjectResolutionError> {
    let evidence = host_process_snapshot(config, peer, uid);
    let mut actor = resolve_evidence_actor(policy, &evidence, peer)?;
    actor.presenter.display_label = Some(config.user_name_num(uid));
    Ok(actor)
}

/// Build the compatibility host-process snapshot from current peer credentials.
#[must_use]
pub fn host_process_snapshot(config: &Config, peer: &PeerInfo, uid: u32) -> EvidenceSnapshot {
    let supplementary = config
        .groups_of(uid)
        .map(|groups| groups.iter().copied().collect())
        .unwrap_or_default();
    EvidenceSnapshot {
        domain: EvidenceValue::Available(AuthorizationDomain::HostProcess),
        process: ProcessEvidence {
            uids: EvidenceValue::Available(CredentialSlots::uniform(uid)),
            gids: peer.gid.map_or(EvidenceValue::Unavailable, |gid| {
                EvidenceValue::Available(CredentialSlots::uniform(gid))
            }),
            supplementary_gids: EvidenceValue::Available(supplementary),
            executable_digest: EvidenceValue::Unavailable,
        },
        ..EvidenceSnapshot::default()
    }
}

/// Resolve exactly one actor from a provider-independent immutable snapshot.
pub fn resolve_evidence_actor(
    policy: &ResolvedPolicy,
    evidence: &EvidenceSnapshot,
    peer: &PeerInfo,
) -> Result<AuthenticatedActor, SubjectResolutionError> {
    let resolution = resolve_subject(&policy.subjects, evidence).map_err(map_resolution_error)?;
    let Some(subject) = resolution.subject else {
        return Err(SubjectResolutionError::DomainUnavailable);
    };
    let mut authenticated_by = vec![ProofSummary {
        kind: domain_proof(resolution.domain),
        subject: subject.clone(),
        fingerprint: None,
    }];
    if let EvidenceValue::Available(signature_key) = &evidence.invocation_signature_key {
        authenticated_by.push(ProofSummary {
            kind: ProofKind::SignatureKey,
            subject: subject.clone(),
            fingerprint: Some(signature_key_fingerprint(signature_key)),
        });
    }
    Ok(AuthenticatedActor {
        domain: resolution.domain,
        subject,
        authenticated_by,
        presenter: PresenterInfo::from(peer),
        transport: TransportInfo::default(),
    })
}

fn signature_key_fingerprint(key: &SignatureKeyEvidence) -> String {
    let algorithm = match key.algorithm {
        crate::catalog::policy::SignatureKeyAlgorithm::Ed25519 => "ed25519",
        crate::catalog::policy::SignatureKeyAlgorithm::NatsNkey => "nats-nkey",
    };
    let mut hasher = Sha256::new();
    hasher.update(algorithm.as_bytes());
    hasher.update(b":");
    hasher.update(key.public.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

const fn domain_proof(domain: AuthorizationDomain) -> ProofKind {
    match domain {
        AuthorizationDomain::HostProcess => ProofKind::ProcessCredentials,
        AuthorizationDomain::SystemdUnit => ProofKind::SystemdUnit,
        AuthorizationDomain::Container => ProofKind::Container,
    }
}

fn map_resolution_error(error: EvidenceResolutionError) -> SubjectResolutionError {
    match error {
        EvidenceResolutionError::DomainUnavailable => SubjectResolutionError::DomainUnavailable,
        EvidenceResolutionError::NoSubject(SubjectResolution {
            domain,
            no_match_count,
            ..
        }) => SubjectResolutionError::NoSubject {
            domain,
            no_match_count,
        },
        EvidenceResolutionError::AmbiguousSubject(resolution) => {
            SubjectResolutionError::AmbiguousSubject {
                domain: resolution.domain,
                subjects: resolution.matching_subjects,
                total: resolution.matching_count,
                truncated: resolution.matching_subjects_truncated,
                no_match_count: resolution.no_match_count,
                unavailable_count: resolution.unavailable_count,
            }
        }
        EvidenceResolutionError::EvidenceUnavailable(SubjectResolution {
            domain,
            matching_count,
            matching_subjects,
            matching_subjects_truncated,
            no_match_count,
            unavailable_count,
            ..
        }) => SubjectResolutionError::EvidenceUnavailable {
            domain,
            subjects: matching_subjects,
            truncated: matching_subjects_truncated,
            matching_count,
            no_match_count,
            unavailable_count,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::catalog::evidence::{EvidenceExpression, EvidencePredicate, IdentitySelector};
    use crate::catalog::policy::SignatureKeyAlgorithm;
    use crate::catalog::policy::SubjectDefinition;

    fn host_subject(uid: u32) -> SubjectDefinition {
        SubjectDefinition {
            domain: AuthorizationDomain::HostProcess,
            break_glass: false,
            match_: EvidenceExpression::All(vec![EvidenceExpression::Leaf(
                EvidencePredicate::ProcessUid(IdentitySelector::Numeric(uid)),
            )]),
        }
    }

    fn peer(uid: Option<u32>) -> PeerInfo {
        PeerInfo {
            uid,
            gid: uid,
            ..PeerInfo::default()
        }
    }

    #[test]
    fn local_actor_resolves_exactly_one_subject() {
        let policy = ResolvedPolicy {
            subjects: BTreeMap::from([("svc.web".to_string(), host_subject(9001))]),
            rules: Vec::new(),
        };
        let actor = resolve_local_actor(&policy, &Config::default(), &peer(Some(9001)))
            .expect("one subject resolves");
        assert_eq!(actor.subject, "svc.web");
        assert_eq!(actor.domain, AuthorizationDomain::HostProcess);
        assert_eq!(actor.unix_uid(), Some(9001));
    }

    #[test]
    fn overlapping_subjects_are_bounded_and_rejected() {
        let subjects = (0..12)
            .map(|index| (format!("svc.{index:02}"), host_subject(42)))
            .collect();
        let policy = ResolvedPolicy {
            subjects,
            rules: Vec::new(),
        };
        let error = resolve_local_actor(&policy, &Config::default(), &peer(Some(42)))
            .expect_err("overlap must deny");
        let SubjectResolutionError::AmbiguousSubject {
            subjects,
            total,
            truncated,
            ..
        } = error
        else {
            panic!("expected ambiguity");
        };
        assert_eq!(subjects.len(), 8);
        assert_eq!(total, 12);
        assert!(truncated);
    }

    #[test]
    fn missing_peer_credentials_never_resolve() {
        let policy = ResolvedPolicy {
            subjects: BTreeMap::from([("svc.web".to_string(), host_subject(9001))]),
            rules: Vec::new(),
        };
        assert_eq!(
            resolve_local_actor(&policy, &Config::default(), &peer(None)),
            Err(SubjectResolutionError::MissingPeerCredentials)
        );
    }

    #[test]
    fn signature_fingerprint_is_stable_and_does_not_disclose_public_material() {
        let key = SignatureKeyEvidence {
            algorithm: SignatureKeyAlgorithm::Ed25519,
            public: "sensitive-public-material".to_string(),
        };
        let first = signature_key_fingerprint(&key);
        let second = signature_key_fingerprint(&key);
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
        assert!(!first.contains(&key.public));
    }
}
