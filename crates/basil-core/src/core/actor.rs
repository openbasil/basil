// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Authenticated authorization actor resolution.

use std::collections::BTreeSet;

use crate::catalog::policy::{Config, ResolvedPolicy, SubjectName};
use crate::peer::PeerInfo;

/// A resolved actor that the `PDP` can authorize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedActor {
    /// The subject selected for authorization.
    pub subject: SubjectName,
    /// Evidence summaries that established the subject.
    pub authenticated_by: Vec<ProofSummary>,
    /// The local presenter that brought the request to the broker.
    pub presenter: PresenterInfo,
    /// Transport facts for the request.
    pub transport: TransportInfo,
}

impl AuthenticatedActor {
    /// The presenter's `SO_PEERCRED` uid, when the actor came over a Unix socket.
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
}

/// Supported first-cut proof kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// Local Unix peer credentials from `SO_PEERCRED`.
    UnixPeerCredentials,
    /// Explicit configured anonymous subject.
    Unauthenticated,
    /// Signed sealed-invocation envelope with a configured public key.
    SignatureKey,
}

/// Information about the process or bridge that presented the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenterInfo {
    /// `SO_PEERCRED` process id.
    pub pid: Option<u32>,
    /// `SO_PEERCRED` uid.
    pub uid: Option<u32>,
    /// `SO_PEERCRED` primary gid.
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

/// Why actor resolution failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectResolutionError {
    /// No Unix credentials were present and no explicit unauthenticated subject applies.
    MissingPeerCredentials,
    /// Unix credentials were present but matched no subject.
    NoSubject {
        /// The presenter's uid.
        uid: u32,
    },
    /// Unix credentials matched more than one subject and no request-level subject disambiguated it.
    AmbiguousSubject {
        /// The presenter's uid.
        uid: u32,
        /// Matching subjects.
        subjects: Vec<SubjectName>,
    },
    /// The configured unauthenticated subject is absent or not an unauthenticated subject.
    InvalidUnauthenticatedSubject {
        /// The configured subject name.
        subject: SubjectName,
    },
}

/// Resolve a local request actor from captured peer information.
pub fn resolve_local_actor(
    policy: &ResolvedPolicy,
    config: &Config,
    peer: &PeerInfo,
) -> Result<AuthenticatedActor, SubjectResolutionError> {
    if let Some(uid) = peer.uid {
        return resolve_unix_actor(policy, config, peer, uid);
    }
    resolve_unauthenticated_actor(policy, peer)
}

/// Resolve a Unix actor by uid with optional presenter context.
pub fn resolve_unix_actor(
    policy: &ResolvedPolicy,
    config: &Config,
    peer: &PeerInfo,
    uid: u32,
) -> Result<AuthenticatedActor, SubjectResolutionError> {
    let gids: Vec<u32> = config
        .groups_of(uid)
        .map(|s| s.iter().copied().collect())
        .unwrap_or_default();
    let subjects: Vec<SubjectName> = matching_unix_subjects(policy, uid, &gids)
        .into_iter()
        .cloned()
        .collect();
    match subjects.as_slice() {
        [] => Err(SubjectResolutionError::NoSubject { uid }),
        [subject] => {
            let mut actor = actor(subject.clone(), ProofKind::UnixPeerCredentials, peer);
            actor.presenter.display_label = Some(config.user_name_num(uid));
            Ok(actor)
        }
        _ => Err(SubjectResolutionError::AmbiguousSubject { uid, subjects }),
    }
}

/// Resolve the configured unauthenticated actor, if enabled.
pub fn resolve_unauthenticated_actor(
    policy: &ResolvedPolicy,
    peer: &PeerInfo,
) -> Result<AuthenticatedActor, SubjectResolutionError> {
    let Some(subject) = policy.unauthenticated_subject.as_ref() else {
        return Err(SubjectResolutionError::MissingPeerCredentials);
    };
    if !policy
        .subjects
        .get(subject)
        .is_some_and(|definition| definition.match_.matches_unauthenticated())
    {
        return Err(SubjectResolutionError::InvalidUnauthenticatedSubject {
            subject: subject.clone(),
        });
    }
    Ok(actor(subject.clone(), ProofKind::Unauthenticated, peer))
}

fn matching_unix_subjects<'a>(
    policy: &'a ResolvedPolicy,
    uid: u32,
    gids: &[u32],
) -> BTreeSet<&'a SubjectName> {
    policy
        .subjects
        .iter()
        .filter_map(|(name, subject)| subject.match_.matches_unix(uid, gids).then_some(name))
        .collect()
}

fn actor(subject: SubjectName, kind: ProofKind, peer: &PeerInfo) -> AuthenticatedActor {
    AuthenticatedActor {
        authenticated_by: vec![ProofSummary {
            kind,
            subject: subject.clone(),
        }],
        subject,
        presenter: PresenterInfo::from(peer),
        transport: TransportInfo::default(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::catalog::policy::{PrincipalSpec, ResolvedPolicy, SubjectDefinition, SubjectMatch};

    fn unix_subject(uid: Option<u32>, gid: Option<u32>) -> SubjectDefinition {
        SubjectDefinition {
            break_glass: false,
            match_: SubjectMatch::AllOf(vec![PrincipalSpec::Unix { uid, gid }]),
        }
    }

    fn unauthenticated_subject() -> SubjectDefinition {
        SubjectDefinition {
            break_glass: false,
            match_: SubjectMatch::AnyOf(vec![PrincipalSpec::Unauthenticated]),
        }
    }

    fn peer(uid: Option<u32>, gid: Option<u32>) -> PeerInfo {
        PeerInfo {
            uid,
            gid,
            ..PeerInfo::default()
        }
    }

    #[test]
    fn local_unix_actor_resolves_exactly_one_subject() {
        let policy = ResolvedPolicy {
            subjects: BTreeMap::from([("svc.web".to_string(), unix_subject(Some(9001), None))]),
            unauthenticated_subject: None,
            rules: Vec::new(),
        };
        let actor =
            resolve_local_actor(&policy, &Config::default(), &peer(Some(9001), Some(1))).unwrap();
        assert_eq!(actor.subject, "svc.web");
        assert_eq!(actor.unix_uid(), Some(9001));
        assert_eq!(
            actor.authenticated_by[0].kind,
            ProofKind::UnixPeerCredentials
        );
    }

    #[test]
    fn group_subject_uses_configured_memberships_not_primary_gid() {
        let policy = ResolvedPolicy {
            subjects: BTreeMap::from([("ops.wheel".to_string(), unix_subject(None, Some(10)))]),
            unauthenticated_subject: None,
            rules: Vec::new(),
        };
        let mut config = Config::default();
        config.memberships.insert(5000, BTreeSet::from([5000, 10]));
        let actor = resolve_local_actor(&policy, &config, &peer(Some(5000), Some(5000))).unwrap();
        assert_eq!(actor.subject, "ops.wheel");

        let no_membership =
            resolve_local_actor(&policy, &Config::default(), &peer(Some(5000), Some(10)));
        assert!(matches!(
            no_membership,
            Err(SubjectResolutionError::NoSubject { uid: 5000 })
        ));
    }

    #[test]
    fn ambiguous_unix_actor_is_rejected() {
        let policy = ResolvedPolicy {
            subjects: BTreeMap::from([
                ("svc.one".to_string(), unix_subject(Some(42), None)),
                ("svc.two".to_string(), unix_subject(Some(42), None)),
            ]),
            unauthenticated_subject: None,
            rules: Vec::new(),
        };
        let err = resolve_local_actor(&policy, &Config::default(), &peer(Some(42), None))
            .expect_err("two subjects must be ambiguous");
        assert!(matches!(
            err,
            SubjectResolutionError::AmbiguousSubject { uid: 42, .. }
        ));
    }

    #[test]
    fn unauthenticated_subject_resolves_only_when_configured() {
        let policy = ResolvedPolicy {
            subjects: BTreeMap::from([("guest".to_string(), unauthenticated_subject())]),
            unauthenticated_subject: Some("guest".to_string()),
            rules: Vec::new(),
        };
        let actor = resolve_local_actor(&policy, &Config::default(), &PeerInfo::default()).unwrap();
        assert_eq!(actor.subject, "guest");
        assert_eq!(actor.authenticated_by[0].kind, ProofKind::Unauthenticated);

        let disabled = ResolvedPolicy {
            unauthenticated_subject: None,
            ..policy
        };
        assert!(matches!(
            resolve_local_actor(&disabled, &Config::default(), &PeerInfo::default()),
            Err(SubjectResolutionError::MissingPeerCredentials)
        ));
    }
}
