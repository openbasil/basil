// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Persistent listener **rewire diagnostics** (`basil-9tj.15`).
//!
//! A reload may change an existing listener's socket path under the same name
//! when that listener has zero accepted transports. The agent itself rewires
//! atomically, but externally *generated* wiring that recorded the old resolved
//! path (for example generated service wiring that records an exact socket path)
//! keeps failing closed until the operator regenerates it and restarts the
//! affected services. The [`RewireLedger`] records every
//! such applied path change so `reload`/readiness surfaces can enumerate the
//! listeners still awaiting a rewire.
//!
//! Invariants:
//!
//! - **Advisory only.** A diagnostic never affects authorization: a connected
//!   caller is decided from attested identity and policy, never from listener
//!   path metadata. Unrelated listeners keep serving.
//! - **Persistent until resolved.** An entry survives later reloads and is
//!   dropped only when its listener is removed or its path returns to the
//!   recorded previous path. Chained changes (`A → B → C`) keep the **oldest**
//!   unresolved previous path (`A`): wiring generated against `A` is still
//!   stale, and wiring regenerated in between cannot be observed from here.
//! - **Bounded.** At most [`MAX_REWIRE_DIAGNOSTICS`] entries (the listener-set
//!   ceiling). The set is keyed by listener name and removals resolve entries,
//!   so the bound cannot be exceeded through configuration churn; it is still
//!   enforced defensively by evicting the oldest entry.
//! - **No panic.** Lock poisoning is recovered (the ledger holds no invariant a
//!   panicked holder could have broken mid-update beyond a single map entry).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::grpc_server::MAX_LISTENERS;
use super::listener::ListenerConfigSet;

/// Hard ceiling on retained diagnostics: one per configurable listener.
pub const MAX_REWIRE_DIAGNOSTICS: usize = MAX_LISTENERS;

/// One persistent rewire diagnostic: a same-name listener socket-path change
/// applied by an earlier reload, awaiting external wiring regeneration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewireDiagnostic {
    listener: String,
    previous_path: PathBuf,
    new_path: PathBuf,
    applied_generation: u64,
    recorded_at_unix: u64,
}

impl RewireDiagnostic {
    /// Stable name of the listener whose path changed.
    #[must_use]
    pub fn listener(&self) -> &str {
        &self.listener
    }

    /// The oldest resolved path external wiring may still record.
    #[must_use]
    pub fn previous_path(&self) -> &Path {
        &self.previous_path
    }

    /// The path the listener now serves on.
    #[must_use]
    pub fn new_path(&self) -> &Path {
        &self.new_path
    }

    /// The generation whose reload applied the (latest) path change.
    #[must_use]
    pub const fn applied_generation(&self) -> u64 {
        self.applied_generation
    }

    /// Unix seconds when the (latest) path change was recorded.
    #[must_use]
    pub const fn recorded_at_unix(&self) -> u64 {
        self.recorded_at_unix
    }
}

/// One ledger mutation derived from a committed listener transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewireUpdate {
    /// A same-name path change was applied; record (or extend) a diagnostic.
    Record(RewireDiagnostic),
    /// The named listener no longer exists; drop any diagnostic for it.
    Resolve {
        /// Stable listener name.
        listener: String,
    },
}

/// Derive the ledger mutations a committed `current → candidate` listener
/// transition implies. Pure: no clock, no lock, no I/O.
///
/// - A removed listener resolves its diagnostic (no wiring can reach it and
///   final removal is the operator's explicit migration step).
/// - A same-name change whose path differs records a diagnostic stamped with
///   the generation that applied it.
/// - Additions and path-preserving reconfigurations (mode/group/type) change
///   nothing: generated wiring binds the *path*.
#[must_use]
pub fn rewire_updates(
    current: &ListenerConfigSet,
    candidate: &ListenerConfigSet,
    applied_generation: u64,
    recorded_at_unix: u64,
) -> Vec<RewireUpdate> {
    let mut updates = Vec::new();
    for listener in current.iter() {
        match candidate.get(listener.name()) {
            None => updates.push(RewireUpdate::Resolve {
                listener: listener.name().to_string(),
            }),
            Some(replacement) if replacement.path() != listener.path() => {
                updates.push(RewireUpdate::Record(RewireDiagnostic {
                    listener: listener.name().to_string(),
                    previous_path: listener.path().to_path_buf(),
                    new_path: replacement.path().to_path_buf(),
                    applied_generation,
                    recorded_at_unix,
                }));
            }
            Some(_) => {}
        }
    }
    updates
}

/// Process-lifetime, bounded, name-keyed rewire diagnostic store.
#[derive(Debug, Default)]
pub struct RewireLedger {
    entries: Mutex<BTreeMap<String, RewireDiagnostic>>,
}

impl RewireLedger {
    /// Apply the mutations of one committed listener transition.
    ///
    /// Recording keeps the **oldest** unresolved `previous_path` for a listener
    /// while adopting the newest `new_path`/generation/timestamp; a change back
    /// to the recorded previous path resolves the entry (the wiring generated
    /// against it is valid again). Resolution is idempotent.
    pub fn apply(&self, updates: impl IntoIterator<Item = RewireUpdate>) {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for update in updates {
            match update {
                RewireUpdate::Record(mut diagnostic) => {
                    if let Some(existing) = entries.get(diagnostic.listener()) {
                        diagnostic.previous_path.clone_from(&existing.previous_path);
                    }
                    if diagnostic.new_path == diagnostic.previous_path {
                        entries.remove(diagnostic.listener());
                        continue;
                    }
                    while entries.len() >= MAX_REWIRE_DIAGNOSTICS
                        && !entries.contains_key(diagnostic.listener())
                    {
                        let Some(oldest) = entries
                            .iter()
                            .min_by_key(|(_, entry)| entry.applied_generation)
                            .map(|(name, _)| name.clone())
                        else {
                            break;
                        };
                        entries.remove(&oldest);
                    }
                    entries.insert(diagnostic.listener.clone(), diagnostic);
                }
                RewireUpdate::Resolve { listener } => {
                    entries.remove(&listener);
                }
            }
        }
    }

    /// Snapshot every retained diagnostic in stable listener-name order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<RewireDiagnostic> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// Number of retained diagnostics (the readiness `rewire-required` count).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether no diagnostic is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;
    use crate::transport::grpc_server::ListenerType;
    use crate::transport::listener::{
        LegacyListenerConfig, ListenerConfigInput, ListenerConfigSet,
    };

    fn set(entries: &[(&str, ListenerType, &str)]) -> ListenerConfigSet {
        ListenerConfigSet::resolve(
            entries
                .iter()
                .map(|(name, listener_type, path)| {
                    (
                        (*name).to_string(),
                        ListenerConfigInput {
                            listener_type: *listener_type,
                            path: PathBuf::from(path),
                            mode: None,
                            group: None,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            LegacyListenerConfig::default(),
        )
        .expect("listener set resolves")
    }

    #[test]
    fn updates_classify_removal_path_change_and_ignore_additions() {
        let current = set(&[
            ("host", ListenerType::Host, "/run/basil/host.sock"),
            ("courier", ListenerType::Courier, "/run/basil/courier.sock"),
        ]);
        let candidate = set(&[
            ("host", ListenerType::Host, "/run/basil/host-v2.sock"),
            ("extra", ListenerType::Courier, "/run/basil/extra.sock"),
        ]);

        let updates = rewire_updates(&current, &candidate, 7, 1_000);
        assert_eq!(updates.len(), 2);
        assert!(updates.iter().any(|update| matches!(
            update,
            RewireUpdate::Resolve { listener } if listener == "courier"
        )));
        let recorded = updates
            .iter()
            .find_map(|update| match update {
                RewireUpdate::Record(diagnostic) => Some(diagnostic),
                RewireUpdate::Resolve { .. } => None,
            })
            .expect("host path change recorded");
        assert_eq!(recorded.listener(), "host");
        assert_eq!(
            recorded.previous_path(),
            std::path::Path::new("/run/basil/host.sock")
        );
        assert_eq!(
            recorded.new_path(),
            std::path::Path::new("/run/basil/host-v2.sock")
        );
        assert_eq!(recorded.applied_generation(), 7);
        assert_eq!(recorded.recorded_at_unix(), 1_000);
    }

    #[test]
    fn mode_only_reconfiguration_and_pure_addition_record_nothing() {
        let current = set(&[("host", ListenerType::Host, "/run/basil/host.sock")]);
        let candidate = set(&[
            ("host", ListenerType::Host, "/run/basil/host.sock"),
            ("aux", ListenerType::Courier, "/run/basil/aux.sock"),
        ]);
        assert!(rewire_updates(&current, &candidate, 2, 0).is_empty());
    }

    #[test]
    fn ledger_keeps_oldest_previous_path_and_resolves_on_return_or_removal() {
        let ledger = RewireLedger::default();
        let a = set(&[("host", ListenerType::Host, "/run/basil/a.sock")]);
        let b = set(&[("host", ListenerType::Host, "/run/basil/b.sock")]);
        let c = set(&[("host", ListenerType::Host, "/run/basil/c.sock")]);

        ledger.apply(rewire_updates(&a, &b, 2, 10));
        ledger.apply(rewire_updates(&b, &c, 3, 20));
        let snapshot = ledger.snapshot();
        assert_eq!(snapshot.len(), 1);
        let entry = snapshot.first().expect("one diagnostic");
        assert_eq!(
            entry.previous_path(),
            std::path::Path::new("/run/basil/a.sock")
        );
        assert_eq!(entry.new_path(), std::path::Path::new("/run/basil/c.sock"));
        assert_eq!(entry.applied_generation(), 3);
        assert_eq!(entry.recorded_at_unix(), 20);

        // Returning to the ORIGINAL path resolves the diagnostic.
        ledger.apply(rewire_updates(&c, &a, 4, 30));
        assert!(ledger.is_empty());

        // A fresh change then a removal also resolves it.
        ledger.apply(rewire_updates(&a, &b, 5, 40));
        assert_eq!(ledger.len(), 1);
        // Removal requires another host listener to remain; model it with a
        // candidate that renames the listener (remove `host`, add `host2`).
        let renamed = set(&[("host2", ListenerType::Host, "/run/basil/b.sock")]);
        ledger.apply(rewire_updates(&b, &renamed, 6, 50));
        assert!(ledger.is_empty());
    }

    #[test]
    fn ledger_is_bounded_and_evicts_the_oldest_generation() {
        let ledger = RewireLedger::default();
        for index in 0..=MAX_REWIRE_DIAGNOSTICS {
            let name = format!("l{index:02}");
            let current = ListenerConfigSet::resolve(
                BTreeMap::from([(
                    name.clone(),
                    ListenerConfigInput {
                        listener_type: ListenerType::Host,
                        path: PathBuf::from(format!("/run/basil/{name}-old.sock")),
                        mode: None,
                        group: None,
                    },
                )]),
                LegacyListenerConfig::default(),
            )
            .expect("current resolves");
            let candidate = ListenerConfigSet::resolve(
                BTreeMap::from([(
                    name.clone(),
                    ListenerConfigInput {
                        listener_type: ListenerType::Host,
                        path: PathBuf::from(format!("/run/basil/{name}-new.sock")),
                        mode: None,
                        group: None,
                    },
                )]),
                LegacyListenerConfig::default(),
            )
            .expect("candidate resolves");
            let generation = u64::try_from(index).expect("small index") + 2;
            ledger.apply(rewire_updates(&current, &candidate, generation, 0));
        }
        assert_eq!(ledger.len(), MAX_REWIRE_DIAGNOSTICS);
        let snapshot = ledger.snapshot();
        assert!(
            !snapshot.iter().any(|entry| entry.listener() == "l00"),
            "the oldest-generation entry is evicted at the bound"
        );
        assert!(
            snapshot
                .iter()
                .any(|entry| entry.listener() == format!("l{MAX_REWIRE_DIAGNOSTICS:02}"))
        );
    }
}
