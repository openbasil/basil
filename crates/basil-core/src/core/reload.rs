// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Signal-driven hot reload of the catalog/policy **generation** (`basil-y3e`).
//!
//! [`reload_generation`] is the single, fail-closed reload engine shared by the
//! SIGHUP handler and (later) the permission-scoped gRPC admin-reload follow-on
//! (`basil-atq`). It re-reads the catalog/policy from the **same on-disk paths**
//! the broker was started with (never from the wire), runs the **full**
//! startup/`check` validation on the candidate, enforces that only reloadable
//! dimensions changed, and (only on success) atomically swaps in a new
//! [`Generation`] with a bumped id. On any failure it does **not** swap: the
//! previous generation keeps serving and the rejection is returned to the caller
//! (the SIGHUP handler audits it). It never panics or exits.
//!
//! # Reloadable vs restart-only
//!
//! The reloadable surface is the **content** the [`Pdp`](crate::catalog::Pdp) and
//! the audit trail consume: the entire policy (rules / roles / name + membership
//! tables) and the per-key *authorization* attributes: `writable`, `labels`,
//! `description`, `missing`. A declared `nixCache` identity has one additional,
//! purpose-specific transition: `pending` may become `enrolled` exactly once.
//! Its name, route, version, and enrolled public key are process-lifetime
//! immutable, including through a monotonic enrolled-name tombstone. The
//! **routing shape** is otherwise restart-only:
//! the [`BackendManager`](crate::manager::BackendManager) and the live backend
//! instances were built from the sealed bundle at startup, so adding/removing a
//! backend, or changing any key's `class`/`backend`/`path`/`engine`/`key_type`/
//! `public_path`, needs a re-unlock and is rejected here (the Nix module routes
//! such edits to `ExecStart`, i.e. a restart). [`routing_shape`] captures exactly
//! the dimensions baked into the manager; a candidate whose shape differs from the
//! running generation is rejected with [`ReloadError::RoutingShapeChanged`].
//!
//! # Non-mutating
//!
//! Reload is **non-mutating**: it validates (and the loader's guardrails run) but
//! it performs **no** backend I/O and **no** CSPRNG side effects: it never
//! reconciles or generates missing material on the signal path. A candidate that
//! adds a `missing:error` key whose material is absent is *accepted* (its routing
//! shape is unchanged by construction, since a new key would change the shape and
//! be rejected anyway); a `missing:error` key that already exists in both
//! generations simply keeps failing closed at use if its material is absent. The
//! routing-shape guard means a reload can only ever change a *pre-existing* key's
//! authorization attributes, never introduce a new key/backend that would demand
//! fresh material, so there is no missing-material decision to make on the signal
//! path beyond what startup reconcile already settled.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::catalog::loader::LoadError;
use crate::catalog::schema::{BackendKind, Capability, Class, Engine, KeyAlgorithm};
use crate::catalog::{Catalog, Config, ResolvedPolicy};
use crate::configuration::{
    ConfigOverride, ConfigurationSourceTrace, ConfigurationTraceContext, CorpusDocuments,
    OverrideProvenance, emit_configuration_source_trace, load_bootstrap_with_trace_collector,
    load_documents_with_trace_collector,
};
use crate::state::{BrokerState, Generation};

/// The on-disk inputs a [`reload_generation`] re-reads.
///
/// Stored on [`BrokerState`] at construction so the reload engine reads from the
/// **same** paths startup used, never from anywhere else, never from the wire.
#[derive(Debug, Clone)]
pub struct ReloadInputs {
    /// Path to the selected schema-3 bootstrap.
    pub config_path: std::path::PathBuf,
    /// Immutable startup overrides reapplied to every candidate.
    pub overrides: Vec<ConfigOverride>,
}

/// The result of a **successful** [`reload_generation`].
///
/// Carries the old → new generation ids plus summary counts so the SIGHUP handler
/// (and the gRPC admin-reload, `basil-atq`) can log/return what changed, and the
/// candidate-aware listener impact so a dry-run reports exactly what a SIGHUP
/// would do to the listener surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadOutcome {
    /// The generation id that was serving before the swap.
    pub previous_generation: u64,
    /// The generation id now serving after the atomic swap.
    pub new_generation: u64,
    /// Number of catalog keys in the new generation.
    pub key_count: usize,
    /// Number of resolved policy allow-grants in the new generation.
    pub grant_count: usize,
    /// Every listener the candidate adds, removes, or reconfigures, with its
    /// exact active-transport count at assessment time. Empty when the
    /// candidate changes no listener.
    pub listener_impacts: Vec<crate::transport::listener_manager::ListenerImpact>,
}

/// Why a [`reload_generation`] was **rejected**. On any of these the previous
/// generation keeps serving (fail closed); none of them swap.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// A corpus input could not be fingerprinted during candidate assembly.
    #[error("reading configuration input metadata from {path}: {source}")]
    ReadInput {
        /// The input path that failed.
        path: String,
        /// The underlying IO error.
        source: std::io::Error,
    },

    /// The catalog or policy file changed while reload was reading the pair.
    /// The previous generation keeps serving so the broker never installs a
    /// catalog/policy pair assembled across an observed writer race.
    #[error("catalog/policy reload input changed while reading {path}; retry reload")]
    TornSnapshot {
        /// The path whose fingerprint changed during candidate assembly.
        path: String,
    },

    /// The candidate catalog/policy failed the full startup/`check` validation
    /// (`load`, including the JWT-SVID issuer-alg and `publicPath` guardrails).
    #[error("validating reloaded catalog/policy: {0}")]
    Validate(#[from] LoadError),

    /// The bootstrap or a non-catalog corpus document failed validation.
    #[error("validating reloaded configuration corpus: {0}")]
    Configuration(#[from] crate::configuration::ConfigurationError),

    /// Typed listener inputs failed closed validation.
    #[error("validating reloaded listener inputs: {0}")]
    ListenerConfiguration(String),

    /// CI federation trust or generation-owned clients failed validation.
    #[error("validating reloaded CI federation trust: {0}")]
    Federation(#[from] crate::core::ci_federation::FederationError),

    /// Listener transition could not be committed without disruption.
    #[error("validating listener transition: {0}")]
    ListenerTransition(String),

    /// A listener removal or reconfiguration still has accepted transports, so
    /// applying the candidate would disrupt them. The carried impact set names
    /// exactly the blocking listeners and their active-transport counts (the
    /// candidate-aware SIGHUP impact an operator drains before retrying).
    #[error("validating listener transition: {0}")]
    ListenerTransitionBlocked(#[from] crate::transport::listener_manager::ActiveListenerTransition),

    /// The candidate changed a **restart-only** routing dimension (a backend was
    /// added/removed/repathed, or a key's `backend`/`path`/`engine`/`key_type`/
    /// `public_path` changed). Such an edit needs a re-unlock and is rejected on
    /// the reload path; apply it via a restart instead.
    #[error("reload touches a restart-only routing dimension: {0}")]
    RoutingShapeChanged(String),

    /// A candidate violated the one-way, process-lifetime Nix cache identity
    /// enrollment contract.
    #[error("reload violates immutable nixCache identity: {0}")]
    NixCacheIdentityChanged(String),

    /// The broker was constructed without [`ReloadInputs`] (no configured
    /// catalog/policy paths), so it has nothing to re-read. A reload is a no-op
    /// fail-closed rather than reading from an unknown source.
    #[error("reload unavailable: broker has no configured catalog/policy paths")]
    NoInputs,

    /// A synchronous reload was attempted after live accept-loop management was
    /// installed; callers must use [`reload_generation_live`].
    #[error("reload requires the listener-aware asynchronous reload path")]
    LiveRuntimeRequired,
}

impl ReloadError {
    /// A short, stable, non-secret reason token for the audit trail.
    #[must_use]
    pub const fn audit_reason(&self) -> &'static str {
        match self {
            Self::ReadInput { .. } => "configuration_read_failed",
            Self::TornSnapshot { .. } => "inputs_changed_during_read",
            Self::Validate(_)
            | Self::Configuration(_)
            | Self::ListenerConfiguration(_)
            | Self::Federation(_)
            | Self::ListenerTransition(_) => "validation_failed",
            Self::ListenerTransitionBlocked(_) => "listener_transition_blocked",
            Self::RoutingShapeChanged(_) => "routing_shape_changed",
            Self::NixCacheIdentityChanged(_) => "nix_cache_identity_changed",
            Self::NoInputs => "no_reload_inputs",
            Self::LiveRuntimeRequired => "listener_runtime_required",
        }
    }
}

/// The restart-only **routing shape** of one backend: everything the
/// [`BackendManager`](crate::manager::BackendManager) and capability check bake in
/// at startup. Two generations may only differ in reloadable content if their
/// routing shapes are equal.
#[derive(Debug, PartialEq, Eq)]
struct BackendShape {
    kind: BackendKind,
    addr: String,
    engines: Vec<Engine>,
    capabilities: Vec<Capability>,
    requires: Vec<Capability>,
}

/// The restart-only routing shape of one key: the dimensions that select a
/// backend instance, a backend-native locator, and the materialize footprint.
/// `writable` is not here (it is reloadable), but `class` selects the op surface,
/// engine inference, and the materialize arm, so it is restart-only shape.
/// `nixCache` is validated separately because its sole pending-to-enrolled
/// transition is reloadable while all of its identity fields are immutable.
#[derive(Debug, PartialEq, Eq)]
struct KeyShape {
    class: Class,
    key_type: Option<KeyAlgorithm>,
    backend: String,
    engine: Option<Engine>,
    path: String,
    public_path: Option<String>,
}

/// Project a catalog onto its restart-only routing shape: the backend set and,
/// per key, the routing/materialize dimensions. Equal shapes ⇒ the live manager
/// and backends still route the new generation correctly; a differing shape needs
/// a restart.
fn routing_shape(
    catalog: &Catalog,
) -> (BTreeMap<String, BackendShape>, BTreeMap<String, KeyShape>) {
    let backends = catalog
        .backends
        .iter()
        .map(|(name, b)| {
            (
                name.clone(),
                BackendShape {
                    kind: b.kind,
                    addr: b.addr.clone(),
                    engines: b.engines.clone(),
                    capabilities: b.capabilities.clone(),
                    requires: b.requires.clone(),
                },
            )
        })
        .collect();
    let keys = catalog
        .keys
        .iter()
        .map(|(name, k)| {
            (
                name.clone(),
                KeyShape {
                    class: k.class,
                    key_type: k.key_type,
                    backend: k.backend.clone(),
                    engine: k.engine,
                    path: k.path.clone(),
                    public_path: k.public_path.clone(),
                },
            )
        })
        .collect();
    (backends, keys)
}

/// Reject the candidate if it touches any restart-only routing dimension.
///
/// Compares the candidate's routing shape against the **currently serving**
/// generation's catalog. A backend added/removed/repathed, or any key's
/// `class`/`backend`/`path`/`engine`/`key_type`/`public_path` changed (or a key
/// added/removed, which changes the key set, hence the shape), is restart-only.
fn ensure_reloadable(current: &Catalog, candidate: &Catalog) -> Result<(), ReloadError> {
    let (cur_backends, cur_keys) = routing_shape(current);
    let (new_backends, new_keys) = routing_shape(candidate);
    if cur_backends != new_backends {
        return Err(ReloadError::RoutingShapeChanged(
            "the backend set or a backend's kind/addr/engines/capabilities/requires changed"
                .to_string(),
        ));
    }
    if cur_keys != new_keys {
        return Err(ReloadError::RoutingShapeChanged(
            "a key was added/removed or a key's class/backend/path/engine/key_type/public_path changed"
                .to_string(),
        ));
    }
    Ok(())
}

fn ensure_nix_cache_reloadable(
    current: &Catalog,
    candidate: &Catalog,
    enrolled_tombstones: &BTreeSet<String>,
) -> Result<(), ReloadError> {
    for (key_id, current_key) in &current.keys {
        let candidate_key = candidate.keys.get(key_id).ok_or_else(|| {
            ReloadError::NixCacheIdentityChanged(format!("catalog key `{key_id}` was removed"))
        })?;
        match (
            current_key.nix_cache.as_ref(),
            candidate_key.nix_cache.as_ref(),
        ) {
            (None, None) => {}
            (None, Some(_)) => {
                return Err(ReloadError::NixCacheIdentityChanged(format!(
                    "catalog key `{key_id}` added nixCache metadata; declare the identity at startup"
                )));
            }
            (Some(_), None) => {
                return Err(ReloadError::NixCacheIdentityChanged(format!(
                    "catalog key `{key_id}` removed nixCache metadata"
                )));
            }
            (Some(previous), Some(next)) => {
                if previous.key_name != next.key_name {
                    return Err(ReloadError::NixCacheIdentityChanged(format!(
                        "catalog key `{key_id}` changed keyName"
                    )));
                }
                if previous.backend_version != next.backend_version {
                    return Err(ReloadError::NixCacheIdentityChanged(format!(
                        "catalog key `{key_id}` changed backendVersion"
                    )));
                }
                match (previous.state, next.state) {
                    (
                        crate::catalog::NixCacheState::Pending,
                        crate::catalog::NixCacheState::Pending
                        | crate::catalog::NixCacheState::Enrolled,
                    ) => {}
                    (
                        crate::catalog::NixCacheState::Enrolled,
                        crate::catalog::NixCacheState::Pending,
                    ) => {
                        return Err(ReloadError::NixCacheIdentityChanged(format!(
                            "catalog key `{key_id}` moved from enrolled back to pending"
                        )));
                    }
                    (
                        crate::catalog::NixCacheState::Enrolled,
                        crate::catalog::NixCacheState::Enrolled,
                    ) => {
                        if previous.public_key != next.public_key {
                            return Err(ReloadError::NixCacheIdentityChanged(format!(
                                "catalog key `{key_id}` replaced its enrolled publicKey"
                            )));
                        }
                    }
                }
            }
        }
    }

    for (key_id, candidate_key) in &candidate.keys {
        let Some(identity) = candidate_key.nix_cache.as_ref() else {
            continue;
        };
        if !enrolled_tombstones.contains(&identity.key_name) {
            continue;
        }
        let preserves_current_enrollment = current.keys.get(key_id).is_some_and(|current_key| {
            current_key.nix_cache.as_ref().is_some_and(|previous| {
                previous.state == crate::catalog::NixCacheState::Enrolled && previous == identity
            })
        });
        if !preserves_current_enrollment {
            return Err(ReloadError::NixCacheIdentityChanged(format!(
                "keyName `{}` was already enrolled during this process lifetime",
                identity.key_name
            )));
        }
    }
    Ok(())
}

fn spiffe_bundle_publishers(catalog: &Catalog) -> BTreeMap<String, (String, String)> {
    catalog
        .keys
        .iter()
        .filter_map(|(name, entry)| {
            let svid_kind = entry.labels.get("svid_kind")?;
            if !matches!(svid_kind, "jwt" | "x509") {
                return None;
            }
            let trust_domain = entry.labels.get("trust_domain")?;
            Some((
                name.clone(),
                (svid_kind.to_string(), trust_domain.to_string()),
            ))
        })
        .collect()
}

fn bundle_changed_trust_domains(current: &Catalog, candidate: &Catalog) -> Vec<String> {
    let current_publishers = spiffe_bundle_publishers(current);
    let candidate_publishers = spiffe_bundle_publishers(candidate);
    if current_publishers == candidate_publishers {
        return Vec::new();
    }

    current_publishers
        .values()
        .chain(candidate_publishers.values())
        .map(|(_, trust_domain)| trust_domain.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    dev: u64,
    ino: u64,
    len: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

const MAX_RELOAD_FINGERPRINT_PATHS: usize = 2048;

#[derive(Debug)]
struct ReloadFingerprintSnapshot {
    files: BTreeMap<PathBuf, FileFingerprint>,
}

impl ReloadFingerprintSnapshot {
    fn capture(paths: impl IntoIterator<Item = PathBuf>) -> Result<Self, ReloadError> {
        let mut snapshot = Self {
            files: BTreeMap::new(),
        };
        snapshot.extend(paths)?;
        Ok(snapshot)
    }

    fn extend(&mut self, paths: impl IntoIterator<Item = PathBuf>) -> Result<(), ReloadError> {
        for path in paths {
            if self.files.contains_key(&path) {
                continue;
            }
            if self.files.len() >= MAX_RELOAD_FINGERPRINT_PATHS {
                return Err(ReloadError::Configuration(
                    crate::configuration::ConfigurationError::InvalidCorpus(
                        "reload input fingerprint set exceeds safety bound".to_owned(),
                    ),
                ));
            }
            self.files.insert(path.clone(), fingerprint(&path)?);
        }
        Ok(())
    }

    fn verify_unchanged(&self) -> Result<(), ReloadError> {
        for (path, expected) in &self.files {
            if expected != &fingerprint(path)? {
                return Err(ReloadError::TornSnapshot {
                    path: path.display().to_string(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn file_fingerprint(path: &Path) -> std::io::Result<FileFingerprint> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path)?;
    Ok(FileFingerprint {
        dev: metadata.dev(),
        ino: metadata.ino(),
        len: metadata.len(),
        mtime_sec: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime_sec: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    })
}

#[cfg(not(unix))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified: Option<std::time::SystemTime>,
}

#[cfg(not(unix))]
fn file_fingerprint(path: &Path) -> std::io::Result<FileFingerprint> {
    let metadata = std::fs::metadata(path)?;
    Ok(FileFingerprint {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

#[cfg(test)]
fn read_reload_inputs_with_observer(
    inputs: &ReloadInputs,
    observer: impl FnOnce(),
) -> Result<CorpusDocuments, ReloadError> {
    read_reload_inputs_with_observer_and_context(
        inputs,
        observer,
        ConfigurationTraceContext::Offline,
    )
}

#[cfg(test)]
fn read_reload_inputs_with_observer_and_context(
    inputs: &ReloadInputs,
    observer: impl FnOnce(),
    trace_context: ConfigurationTraceContext,
) -> Result<CorpusDocuments, ReloadError> {
    let mut traces = Vec::new();
    let result = read_reload_inputs_with_observer_and_collector(inputs, observer, &mut traces)
        .map(|(documents, _, _, _)| documents);
    for trace in &traces {
        emit_configuration_source_trace(trace, trace_context, result.is_ok());
    }
    result
}

type ReloadInputsResult = (
    CorpusDocuments,
    crate::transport::listener::ListenerConfigSet,
    Option<Arc<crate::core::ci_federation::ProviderCatalog>>,
    ReloadFingerprintSnapshot,
);

#[cfg(test)]
fn read_reload_inputs_with_bootstrap_observer(
    inputs: &ReloadInputs,
    observer: impl FnOnce(),
) -> Result<CorpusDocuments, ReloadError> {
    let mut traces = Vec::new();
    read_reload_inputs_with_observers_and_collector(inputs, observer, || {}, &mut traces)
        .map(|(documents, _, _, _)| documents)
}

fn read_reload_inputs_with_observer_and_collector(
    inputs: &ReloadInputs,
    observer: impl FnOnce(),
    traces: &mut Vec<ConfigurationSourceTrace>,
) -> Result<ReloadInputsResult, ReloadError> {
    read_reload_inputs_with_observers_and_collector(inputs, || {}, observer, traces)
}

fn read_reload_inputs_with_observers_and_collector(
    inputs: &ReloadInputs,
    bootstrap_observer: impl FnOnce(),
    observer: impl FnOnce(),
    traces: &mut Vec<ConfigurationSourceTrace>,
) -> Result<ReloadInputsResult, ReloadError> {
    // Seed the snapshot before reading the bootstrap. Keeping this exact
    // fingerprint through the final verification closes the gap where an atomic
    // replacement after parsing could otherwise pair old listener values
    // with newly discovered corpus inputs.
    let mut snapshot = ReloadFingerprintSnapshot::capture([inputs.config_path.clone()])?;
    let bootstrap =
        load_bootstrap_with_trace_collector(Some(&inputs.config_path), &inputs.overrides, traces)?;
    let federation =
        crate::agent_cli::parse_reload_federation_config(&bootstrap.value).map_err(|error| {
            ReloadError::Configuration(crate::configuration::ConfigurationError::InvalidCorpus(
                error.to_string(),
            ))
        })?;
    let listeners = crate::agent_cli::parse_reload_listener_config(&bootstrap.value)
        .map_err(|error| ReloadError::ListenerConfiguration(error.to_string()))?;
    // Verify immediately after every source and bootstrap-owned serving value is
    // discovered. The final verification below protects the same fingerprint
    // through candidate installation.
    bootstrap_observer();
    snapshot.verify_unchanged()?;
    let paths = vec![
        bootstrap.sources.catalog.clone(),
        bootstrap.sources.policy.clone(),
    ];
    snapshot.extend(paths)?;
    let documents = load_documents_with_trace_collector(
        &bootstrap.sources,
        &bootstrap.document_overrides,
        bootstrap.overrides,
        traces,
    )
    .map_err(|error| match error {
        crate::configuration::ConfigurationError::Catalog(error) => ReloadError::Validate(error),
        other => ReloadError::Configuration(other),
    })?;
    // The observer models a writer racing after every input has been identified
    // and fingerprinted but before trust bytes are captured for the candidate.
    observer();
    snapshot.verify_unchanged()?;
    Ok((documents, listeners, federation, snapshot))
}

fn fingerprint(path: &Path) -> Result<FileFingerprint, ReloadError> {
    file_fingerprint(path).map_err(|source| ReloadError::ReadInput {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
fn read_reload_inputs(inputs: &ReloadInputs) -> Result<CorpusDocuments, ReloadError> {
    read_reload_inputs_with_observer(inputs, || {})
}

/// The fully-validated candidate generation produced by [`validate_candidate`]:
/// the loaded surface (ready to install) plus the [`ReloadOutcome`] the swap would
/// report. The dry-run path discards the surface and keeps only the outcome; the
/// real reload installs the surface.
struct ValidatedCandidate {
    catalog: Catalog,
    policy: ResolvedPolicy,
    config: Config,
    overrides: Vec<OverrideProvenance>,
    federation: Option<Arc<crate::core::ci_federation::ProviderCatalog>>,
    listeners: crate::transport::listener::ListenerConfigSet,
    outcome: ReloadOutcome,
    bundle_changed_trust_domains: Vec<String>,
}

/// Re-read the configured catalog/policy, run the **full** startup/`check`
/// validation, and enforce that only reloadable dimensions changed, all **without
/// swapping**. This is the single validation path shared by the real reload and
/// the `--check` dry-run, so a dry-run can never diverge from what a real reload
/// would accept (the same anti-divergence discipline the PDP's `decide`/`explain`
/// share).
///
/// It is non-mutating (no backend I/O, no CSPRNG, no generation swap) and never
/// panics. The returned [`ReloadOutcome`] reports the *would-be* generation ids
/// and counts; it is identical to what [`reload_generation`] reports after a
/// successful swap.
///
/// # Errors
///
/// Returns a [`ReloadError`] when the broker has no configured paths
/// ([`ReloadError::NoInputs`]), a file cannot be re-read, the candidate fails
/// validation ([`ReloadError::Validate`]), or it changes a restart-only routing
/// dimension ([`ReloadError::RoutingShapeChanged`]).
fn validate_candidate(state: &BrokerState) -> Result<ValidatedCandidate, ReloadError> {
    let active_generation = state.active_generation_id();
    let trace_context = ConfigurationTraceContext::Reload { active_generation };
    let mut traces = Vec::new();
    let result = validate_candidate_with_trace_collector(state, &mut traces);
    for trace in &traces {
        emit_configuration_source_trace(trace, trace_context, result.is_ok());
    }
    result
}

fn validate_candidate_with_trace_collector(
    state: &BrokerState,
    traces: &mut Vec<ConfigurationSourceTrace>,
) -> Result<ValidatedCandidate, ReloadError> {
    validate_candidate_with_trace_collector_and_observer(state, traces, || {})
}

fn validate_candidate_with_trace_collector_and_observer(
    state: &BrokerState,
    traces: &mut Vec<ConfigurationSourceTrace>,
    observer: impl FnOnce(),
) -> Result<ValidatedCandidate, ReloadError> {
    let inputs = state.reload_inputs().ok_or(ReloadError::NoInputs)?;
    let (
        CorpusDocuments {
            catalog,
            policy,
            policy_config: config,
            warnings,
            overrides,
            ..
        },
        listeners,
        federation,
        input_snapshot,
    ) = read_reload_inputs_with_observer_and_collector(inputs, || {}, traces)?;
    for w in &warnings {
        tracing::warn!(warning = %w, "reload: catalog/policy load warning");
    }

    // Pin the currently-serving generation to (a) compare routing shape against,
    // and (b) read the previous id to bump from: one coherent snapshot.
    let current = state.load_generation();
    ensure_reloadable(current.catalog(), &catalog)?;
    ensure_nix_cache_reloadable(
        current.catalog(),
        &catalog,
        &state.nix_cache_enrolled_tombstones(),
    )?;
    let listener_impacts = crate::transport::listener_manager::assess_transition(
        current.listeners(),
        &listeners,
        state.connections(),
    );
    crate::transport::listener_manager::require_zero_active(&listener_impacts)?;
    let previous_generation = current.id();
    let new_generation = previous_generation.saturating_add(1);
    let bundle_changed_trust_domains = bundle_changed_trust_domains(current.catalog(), &catalog);
    observer();
    input_snapshot.verify_unchanged()?;
    let outcome = ReloadOutcome {
        previous_generation,
        new_generation,
        key_count: catalog.keys.len(),
        grant_count: policy.grant_count(),
        listener_impacts,
    };

    Ok(ValidatedCandidate {
        catalog,
        policy,
        config,
        overrides,
        federation,
        listeners,
        outcome,
        bundle_changed_trust_domains,
    })
}

/// Validate the candidate catalog/policy **without** swapping (the `--check`
/// dry-run, basil-atq).
///
/// Runs the *identical* validation [`reload_generation`] runs (re-read from disk,
/// full `load()` validation, and the restart-only routing-shape guard) but
/// performs **no** generation swap: the currently-serving generation is untouched.
/// The returned [`ReloadOutcome`] reports what a real reload *would* apply (the
/// would-be new generation id + counts).
///
/// # Errors
///
/// The same [`ReloadError`] set as [`reload_generation`]; on any error the running
/// generation keeps serving (it was never going to change here regardless).
pub fn check_reload(state: &BrokerState) -> Result<ReloadOutcome, ReloadError> {
    validate_candidate(state).map(|c| c.outcome)
}

/// Re-read the configured catalog/policy, validate the candidate, enforce that
/// only reloadable dimensions changed, and on success atomically swap in a new
/// [`Generation`] with a bumped id.
///
/// This is the **one** fail-closed reload code path, shared by the SIGHUP handler
/// and the gRPC admin-reload follow-on (`basil-atq`). It is non-mutating up to the
/// final swap (no backend I/O, no CSPRNG) and never panics. The validation it runs
/// is exactly [`check_reload`]'s (they share [`validate_candidate`]), so a
/// dry-run that passes guarantees the real reload's validation passes too.
///
/// # Errors
///
/// Returns a [`ReloadError`] (without swapping, so the previous generation keeps
/// serving) when the broker has no configured paths ([`ReloadError::NoInputs`]),
/// a file cannot be re-read, the candidate fails validation
/// ([`ReloadError::Validate`]), or the candidate changes a restart-only routing
/// dimension ([`ReloadError::RoutingShapeChanged`]).
pub fn reload_generation(state: &BrokerState) -> Result<ReloadOutcome, ReloadError> {
    if state.listener_runtime().is_some() {
        return Err(ReloadError::LiveRuntimeRequired);
    }
    // Serialize the whole validate→swap sequence: SIGHUP and the admin RPC can
    // trigger concurrently, and without this two reloads could both pin
    // generation N, both stamp N+1, and let the staler candidate silently
    // overwrite the newer one. A poisoned lock is recovered: it holds no data,
    // it only orders the triggers.
    let _reload_guard = state
        .reload_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let candidate = validate_candidate(state)?;
    let ValidatedCandidate {
        catalog,
        policy,
        config,
        overrides,
        federation,
        listeners,
        outcome,
        bundle_changed_trust_domains,
    } = candidate;

    let current = state.load_generation();
    let (_, listener_guard) = crate::transport::listener_manager::begin_transition(
        current.listeners(),
        &listeners,
        state.connections(),
    )
    .map_err(|error| match error {
        crate::transport::listener_manager::ListenerTransitionError::Active(active) => {
            ReloadError::ListenerTransitionBlocked(active)
        }
        registry @ crate::transport::listener_manager::ListenerTransitionError::Registry(_) => {
            ReloadError::ListenerTransition(registry.to_string())
        }
    })?;
    let rewire_updates = crate::transport::rewire::rewire_updates(
        current.listeners(),
        &listeners,
        outcome.new_generation,
        unix_now(),
    );
    let catalog = Arc::new(catalog);
    let next = Generation::new_with_overrides_listeners_and_federation(
        outcome.new_generation,
        Arc::clone(&catalog),
        policy,
        config,
        overrides,
        Arc::new(listeners),
        federation,
    )?;
    drop(current);
    listener_guard.commit(|| {
        state.swap_generation(Arc::new(next));
        state.record_nix_cache_enrollments(&catalog);
        state.connections().rewire().apply(rewire_updates);
        for trust_domain in bundle_changed_trust_domains {
            state.events().bundle_changed(trust_domain);
        }
    });

    Ok(outcome)
}

/// Wall-clock Unix seconds for diagnostic stamps; `0` before the epoch (never
/// panics on a skewed clock).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Reload a running agent and apply listener accept-loop changes atomically with
/// the new generation.
///
/// When no live listener runtime is installed, this delegates to
/// [`reload_generation`]. A running agent serializes validation and transition,
/// gates affected listener admission, requires zero active transports for
/// removals and reconfiguration, and swaps the generation only after every new
/// socket has been published successfully.
///
/// # Errors
///
/// Returns the same validation errors as [`reload_generation`] plus a listener
/// transition error when an accept loop cannot be changed or restored safely.
pub async fn reload_generation_live(state: &BrokerState) -> Result<ReloadOutcome, ReloadError> {
    let Some(runtime) = state.listener_runtime() else {
        return reload_generation(state);
    };
    let _reload_guard = state.live_reload_lock().lock().await;
    let candidate = validate_candidate(state)?;
    let ValidatedCandidate {
        catalog,
        policy,
        config,
        overrides,
        federation,
        listeners,
        outcome,
        bundle_changed_trust_domains,
    } = candidate;
    let current = state.load_generation();
    if current.id() != outcome.previous_generation {
        return Err(ReloadError::ListenerTransition(
            "serving generation changed during listener-aware reload".to_string(),
        ));
    }
    let current_listeners = current.listeners().clone();
    drop(current);
    let rewire_updates = crate::transport::rewire::rewire_updates(
        &current_listeners,
        &listeners,
        outcome.new_generation,
        unix_now(),
    );
    let catalog = Arc::new(catalog);
    let next = Generation::new_with_overrides_listeners_and_federation(
        outcome.new_generation,
        Arc::clone(&catalog),
        policy,
        config,
        overrides,
        Arc::new(listeners.clone()),
        federation,
    )?;
    runtime
        .transition(&current_listeners, &listeners, || {
            state.swap_generation(Arc::new(next));
            state.record_nix_cache_enrollments(&catalog);
            state.connections().rewire().apply(rewire_updates);
            for trust_domain in bundle_changed_trust_domains {
                state.events().bundle_changed(trust_domain);
            }
        })
        .await
        .map_err(|error| ReloadError::ListenerTransition(error.to_string()))?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use base64::Engine as _;
    use basil_proto::KeyType;
    use tracing::field::{Field, Visit};
    use tracing::{Event, Level, Subscriber};
    use tracing_subscriber::layer::{Context, SubscriberExt as _};
    use tracing_subscriber::{Layer, Registry};

    use super::{
        ReloadError, ReloadInputs, check_reload, read_reload_inputs,
        read_reload_inputs_with_bootstrap_observer, read_reload_inputs_with_observer,
        reload_generation, reload_generation_live, validate_candidate_with_trace_collector,
    };
    use crate::backend::{Backend, BackendError, NewKey};
    use crate::catalog::load;
    use crate::configuration::ConfigOverride;
    use crate::manager::BackendManager;
    use crate::service::broker::InvocationRuntimeConfig;
    use crate::state::{BrokerState, INITIAL_GENERATION_ID};
    use crate::transport::grpc_server::{ListenerRuntime, ListenerType, ServerConfig};
    use crate::transport::listener::{
        LegacyListenerConfig, ListenerConfigInput, ListenerConfigSet,
    };

    #[derive(Clone, Default)]
    struct EventCapture {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    #[derive(Debug)]
    struct CapturedEvent {
        level: Level,
        fields: BTreeMap<String, CapturedValue>,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum CapturedValue {
        Bool(bool),
        I64(i64),
        U64(u64),
        String(String),
        Debug(String),
    }

    impl EventCapture {
        fn source_events(&self) -> Vec<CapturedEvent> {
            let mut guard = self.events.lock().expect("capture lock");
            let events = std::mem::take(&mut *guard);
            drop(guard);
            events
                .into_iter()
                .filter(|event| {
                    event.fields.get("event")
                        == Some(&CapturedValue::String(
                            "basil.configuration.source".to_string(),
                        ))
                })
                .collect()
        }
    }

    impl<S> Layer<S> for EventCapture
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            let mut visitor = FieldCapture::default();
            event.record(&mut visitor);
            self.events
                .lock()
                .expect("capture lock")
                .push(CapturedEvent {
                    level: *event.metadata().level(),
                    fields: visitor.fields,
                });
        }
    }

    #[derive(Default)]
    struct FieldCapture {
        fields: BTreeMap<String, CapturedValue>,
    }

    impl FieldCapture {
        fn insert(&mut self, field: &Field, value: CapturedValue) {
            self.fields.insert(field.name().to_string(), value);
        }
    }

    impl Visit for FieldCapture {
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.insert(field, CapturedValue::Bool(value));
        }

        fn record_i64(&mut self, field: &Field, value: i64) {
            self.insert(field, CapturedValue::I64(value));
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            self.insert(field, CapturedValue::U64(value));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.insert(field, CapturedValue::String(value.to_string()));
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.insert(field, CapturedValue::Debug(format!("{value:?}")));
        }
    }

    /// A no-op backend: reload is non-mutating and never calls the backend, so the
    /// required trait methods all fail closed (the manager only needs them present
    /// to satisfy `Backend`).
    struct NoopBackend;

    #[async_trait]
    impl Backend for NoopBackend {
        fn kind(&self) -> &'static str {
            "noop"
        }
        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }
        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("public_key"))
        }
        async fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("sign"))
        }
        async fn verify(
            &self,
            _key_id: &str,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, BackendError> {
            Err(BackendError::Unsupported("verify"))
        }
    }

    /// A one-key, one-backend catalog. `writable` is reloadable; the routing shape
    /// (`backend`/`path`/`engine`/`key_type`) is fixed across the variants below.
    fn catalog_json(writable: bool) -> String {
        format!(
            r#"{{
              "schema": "catalog",
              "backends": {{ "bao": {{ "kind": "vault", "addr": "http://127.0.0.1:8200" }} }},
              "keys": {{
                "web.signer": {{
                  "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
                  "path": "signer", "writable": {writable}, "description": "a signer"
                }}
              }}
            }}"#
        )
    }

    /// A catalog whose key routes to a DIFFERENT path: a restart-only change.
    fn catalog_json_repathed() -> String {
        r#"{
          "schema": "catalog",
          "backends": { "bao": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "web.signer": {
              "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
              "path": "signer-v2", "writable": true, "description": "a signer"
            }
          }
        }"#
        .to_string()
    }

    fn nix_catalog_json(state: &str, key_name: &str, public_key: Option<&str>) -> String {
        let public_key =
            public_key.map_or_else(String::new, |value| format!(r#", "publicKey": "{value}""#));
        format!(
            r#"{{
              "schema": "catalog",
              "backends": {{ "bao": {{ "kind": "vault", "addr": "http://127.0.0.1:8200" }} }},
              "keys": {{
                "cache.signer": {{
                  "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
                  "engine": "transit", "path": "cache-signer", "writable": false,
                  "nixCache": {{ "keyName": "{key_name}", "state": "{state}",
                    "backendVersion": 1{public_key} }},
                  "description": "Nix cache signer"
                }}
              }}
            }}"#
        )
    }

    fn policy_json(grant_sign: bool) -> String {
        let rules = if grant_sign {
            r#"[ { "id": "r1", "subjects": ["svc.web"], "action": ["op:sign"], "target": ["web.signer"] } ]"#
        } else {
            "[]"
        };
        format!(
            r#"{{
              "schema": "policy",
              "subjects": {{ "svc.web": {{ "domain": "host-process", "match": {{ "all": [ {{ "process.uid": 1000 }} ] }} }} }},
              "roles": {{}},
              "rules": {rules},
              "config": {{}}
            }}"#
        )
    }

    /// Build a [`BrokerState`] from catalog/policy JSON written to temp files, with
    /// the reload inputs pointed at those files so the engine re-reads them.
    fn state_with_files(catalog: &str, policy: &str) -> (Arc<BrokerState>, ReloadInputs) {
        let dir = std::env::temp_dir().join(format!(
            "basil-reload-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let catalog_path = dir.join("catalog.json");
        let policy_path = dir.join("policy.json");
        let config_path = dir.join("config.toml");
        std::fs::write(&catalog_path, catalog).expect("write catalog");
        std::fs::write(&policy_path, policy).expect("write policy");
        std::fs::write(
            &config_path,
            "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n",
        )
        .expect("write config");

        let (cat, pol, cfg, warnings) = load(catalog, policy).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".into(), Box::new(NoopBackend));
        let manager = BackendManager::new(cat.clone(), backends).expect("manager builds");
        let inputs = ReloadInputs {
            config_path,
            overrides: Vec::new(),
        };
        let state = Arc::new(
            BrokerState::new(cat, pol, cfg, manager, "noop").with_reload_inputs(inputs.clone()),
        );
        (state, inputs)
    }

    #[test]
    fn reload_reapplies_document_override_and_retains_provenance() {
        let (_state, mut inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        inputs.overrides = vec![
            ConfigOverride::parse("catalog.keys.web.signer.writable=true")
                .expect("override parses"),
        ];

        let first = read_reload_inputs(&inputs).expect("first candidate");
        assert!(first.catalog.keys.get("web.signer").expect("key").writable);
        assert_eq!(first.overrides[0].path, "catalog.keys.web.signer.writable");

        let bootstrap = crate::load_bootstrap(Some(&inputs.config_path), &[]).expect("bootstrap");
        std::fs::write(&bootstrap.sources.catalog, catalog_json(false)).expect("replace catalog");
        let second = read_reload_inputs(&inputs).expect("second candidate");
        assert!(second.catalog.keys.get("web.signer").expect("key").writable);
        assert_eq!(second.overrides[0].masked_source, bootstrap.sources.catalog);
    }

    fn write_files(inputs: &ReloadInputs, catalog: &str, policy: &str) {
        let dir = inputs.config_path.parent().expect("config parent");
        std::fs::write(dir.join("catalog.json"), catalog).expect("rewrite catalog");
        std::fs::write(dir.join("policy.json"), policy).expect("rewrite policy");
    }

    /// A valid reload (a reloadable-dimension edit) swaps to a new generation id,
    /// and a guard pinned BEFORE the swap still sees the old generation while a
    /// fresh load sees the new one: the reload-between-two-reads coherence the
    /// pinning plumbing (y3e.1) could not exercise without a trigger.
    #[test]
    fn valid_reload_swaps_generation_and_stays_coherent() {
        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);

        // An in-flight op pins the current generation BEFORE the reload.
        let pinned = state.load_generation();
        assert_eq!(pinned.id(), INITIAL_GENERATION_ID);

        // Edit a reloadable dimension (flip writable + add a sign grant).
        write_files(&inputs, &catalog_json(true), &policy_json(true));
        let outcome = reload_generation(&state).expect("valid reload applies");

        assert_eq!(outcome.previous_generation, INITIAL_GENERATION_ID);
        assert_eq!(outcome.new_generation, INITIAL_GENERATION_ID + 1);
        assert_eq!(outcome.key_count, 1);
        assert_eq!(outcome.grant_count, 1);

        // The pre-swap pin still sees the OLD generation (coherent in-flight read);
        // a fresh load sees the NEW one.
        assert_eq!(pinned.id(), INITIAL_GENERATION_ID);
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID + 1);
    }

    #[test]
    fn nix_cache_pending_enrolls_once_and_check_is_non_mutating() {
        let pending = nix_catalog_json("pending", "cache.example.org-1", None);
        let (state, inputs) = state_with_files(&pending, &policy_json(false));
        assert!(state.nix_cache_enrolled_tombstones().is_empty());

        let public_key = base64::engine::general_purpose::STANDARD.encode([0x42; 32]);
        let enrolled = nix_catalog_json("enrolled", "cache.example.org-1", Some(&public_key));
        write_files(&inputs, &enrolled, &policy_json(false));
        check_reload(&state).expect("pending to enrolled dry-run validates");
        assert!(
            state.nix_cache_enrolled_tombstones().is_empty(),
            "a dry-run must not mutate enrollment history"
        );

        reload_generation(&state).expect("pending to enrolled reload applies");
        let current = state.load_generation();
        assert_eq!(
            current.catalog().keys["cache.signer"]
                .nix_cache
                .as_ref()
                .expect("identity")
                .state,
            crate::catalog::NixCacheState::Enrolled
        );
        assert_eq!(
            state.nix_cache_enrolled_tombstones(),
            BTreeSet::from(["cache.example.org-1".to_string()])
        );
    }

    #[test]
    fn nix_cache_enrollment_reverse_replacement_and_removal_fail_closed() {
        let public_key = base64::engine::general_purpose::STANDARD.encode([0x42; 32]);
        let enrolled = nix_catalog_json("enrolled", "cache.example.org-1", Some(&public_key));
        let (state, inputs) = state_with_files(&enrolled, &policy_json(false));
        let initial_generation = state.active_generation_id();
        let replacement = base64::engine::general_purpose::STANDARD.encode([0x43; 32]);
        let mut without_identity: serde_json::Value =
            serde_json::from_str(&enrolled).expect("enrolled JSON parses");
        without_identity["keys"]["cache.signer"]
            .as_object_mut()
            .expect("key is an object")
            .remove("nixCache");
        let without_identity =
            serde_json::to_string(&without_identity).expect("candidate serializes");
        let candidates = [
            nix_catalog_json("pending", "cache.example.org-1", None),
            nix_catalog_json("enrolled", "cache.example.org-1", Some(&replacement)),
            nix_catalog_json("enrolled", "cache.example.org-2", Some(&public_key)),
            without_identity,
        ];
        for candidate in candidates {
            write_files(&inputs, &candidate, &policy_json(false));
            assert!(
                matches!(
                    reload_generation(&state),
                    Err(ReloadError::NixCacheIdentityChanged(_))
                ),
                "immutable identity edit must fail closed"
            );
            assert_eq!(state.active_generation_id(), initial_generation);
        }
    }

    #[test]
    fn nix_cache_metadata_cannot_be_added_by_reload() {
        let generic = catalog_json(false);
        let (state, inputs) = state_with_files(&generic, &policy_json(false));
        let pending = generic.replacen(
            r#", "writable": false, "description": "a signer""#,
            r#", "writable": false, "nixCache": { "keyName": "cache.example.org-1", "state": "pending", "backendVersion": 1 }, "description": "a signer""#,
            1,
        );
        write_files(&inputs, &pending, &policy_json(false));
        assert!(matches!(
            reload_generation(&state),
            Err(ReloadError::NixCacheIdentityChanged(_))
        ));
    }

    #[test]
    fn nix_cache_tombstone_rejects_redeclaration_after_absence() {
        let current_json = catalog_json(false);
        let candidate_json = current_json.replacen(
            r#", "writable": false, "description": "a signer""#,
            r#", "writable": false, "nixCache": { "keyName": "cache.example.org-1", "state": "pending", "backendVersion": 1 }, "description": "a signer""#,
            1,
        );
        let (current, _, _, _) = load(&current_json, &policy_json(false)).expect("current loads");
        let (candidate, _, _, _) =
            load(&candidate_json, &policy_json(false)).expect("candidate loads");
        assert!(matches!(
            super::ensure_nix_cache_reloadable(
                &current,
                &candidate,
                &BTreeSet::from(["cache.example.org-1".to_string()]),
            ),
            Err(ReloadError::NixCacheIdentityChanged(_))
        ));
    }

    #[test]
    fn failed_nix_cache_reload_does_not_add_tombstone() {
        let pending = nix_catalog_json("pending", "cache.example.org-1", None);
        let (state, inputs) = state_with_files(&pending, &policy_json(false));
        let public_key = base64::engine::general_purpose::STANDARD.encode([0x42; 32]);
        let enrolled = nix_catalog_json("enrolled", "cache.example.org-1", Some(&public_key));
        write_files(&inputs, &enrolled, "not-json");
        assert!(reload_generation(&state).is_err());
        assert!(state.nix_cache_enrolled_tombstones().is_empty());
    }

    #[test]
    fn listener_candidate_uses_bootstrap_snapshot_and_commits_with_generation() {
        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        let socket = format!("/tmp/basil-reload-listener-{}.sock", uuid::Uuid::new_v4());
        std::fs::write(
            &inputs.config_path,
            format!(
                "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n[listeners.control]\ntype = \"host\"\npath = {socket:?}\nmode = \"0600\"\n"
            ),
        )
        .expect("write named listener candidate");

        let dry = check_reload(&state).expect("listener dry-run validates");
        assert_eq!(dry.previous_generation, INITIAL_GENERATION_ID);
        let pinned = state.load_generation();
        assert_eq!(pinned.id(), INITIAL_GENERATION_ID);
        assert!(pinned.listeners().get("control").is_none());

        reload_generation(&state).expect("listener candidate commits");
        let current = state.load_generation();
        let control = current
            .listeners()
            .get("control")
            .expect("control listener installed");
        assert_eq!(control.path(), std::path::Path::new(&socket));
        assert_eq!(current.id(), INITIAL_GENERATION_ID + 1);
        assert_eq!(pinned.id(), INITIAL_GENERATION_ID);
        assert!(pinned.listeners().get("control").is_none());
    }

    #[test]
    fn reload_treats_courier_type_change_as_listener_routing_reconfiguration() {
        use crate::transport::listener_manager::ListenerChangeKind;

        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        let parent = inputs.config_path.parent().expect("config parent");
        let host_socket = parent.join("host.sock");
        let edge_socket = parent.join("edge.sock");
        let initial = ListenerConfigSet::resolve(
            BTreeMap::from([
                (
                    "host".to_string(),
                    ListenerConfigInput {
                        listener_type: ListenerType::Host,
                        path: host_socket.clone(),
                        mode: None,
                        group: None,
                    },
                ),
                (
                    "edge".to_string(),
                    ListenerConfigInput {
                        listener_type: ListenerType::Host,
                        path: edge_socket.clone(),
                        mode: None,
                        group: None,
                    },
                ),
            ]),
            LegacyListenerConfig::default(),
        )
        .expect("initial listeners validate");
        let state = Arc::new(
            Arc::try_unwrap(state)
                .unwrap_or_else(|_| panic!("fixture state has one owner"))
                .with_listener_configs(initial),
        );
        std::fs::write(
            &inputs.config_path,
            format!(
                "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n[listeners.host]\ntype = \"host\"\npath = {host_socket:?}\n[listeners.edge]\ntype = \"courier\"\npath = {edge_socket:?}\n"
            ),
        )
        .expect("write courier listener candidate");

        let dry = check_reload(&state).expect("courier type candidate validates");
        assert_eq!(dry.listener_impacts.len(), 1, "{:?}", dry.listener_impacts);
        let impact = dry
            .listener_impacts
            .first()
            .expect("one type reconfiguration");
        assert_eq!(impact.name(), "edge");
        assert_eq!(impact.kind(), ListenerChangeKind::Reconfigure);
        assert_eq!(impact.previous_path(), Some(edge_socket.as_path()));
        assert_eq!(impact.new_path(), Some(edge_socket.as_path()));

        reload_generation(&state).expect("courier type candidate applies");
        assert_eq!(
            state
                .load_generation()
                .listeners()
                .get("edge")
                .expect("edge listener retained")
                .listener_type(),
            ListenerType::Courier
        );
    }

    #[tokio::test]
    async fn live_reload_publishes_added_listener_with_generation() {
        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        let parent = inputs.config_path.parent().expect("config parent");
        let host_socket = parent.join("host.sock");
        let workload_socket = parent.join("workload.sock");
        let initial = ListenerConfigSet::resolve(
            BTreeMap::from([(
                "control".to_string(),
                ListenerConfigInput {
                    listener_type: ListenerType::Host,
                    path: host_socket.clone(),
                    mode: None,
                    group: None,
                },
            )]),
            LegacyListenerConfig::default(),
        )
        .expect("initial listener config");
        let state = Arc::new(
            Arc::try_unwrap(state)
                .unwrap_or_else(|_| panic!("fixture state has one owner"))
                .with_listener_configs(initial),
        );
        let runtime = Arc::new(
            ListenerRuntime::start(
                vec![ServerConfig {
                    listener_name: "control".to_string(),
                    listener_type: ListenerType::Host,
                    connections: state.connections().clone(),
                    socket_path: host_socket.to_string_lossy().into_owned(),
                    socket_mode: crate::DEFAULT_SOCKET_MODE,
                    socket_group: None,
                    invocation: InvocationRuntimeConfig::default(),
                }],
                Arc::clone(&state),
            )
            .await
            .expect("start listener runtime"),
        );
        state
            .install_listener_runtime(Arc::clone(&runtime))
            .expect("install listener runtime");
        std::fs::write(
            &inputs.config_path,
            format!(
                "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n[listeners.control]\ntype = \"host\"\npath = {host_socket:?}\n[listeners.workloads]\ntype = \"courier\"\npath = {workload_socket:?}\n"
            ),
        )
        .expect("write added-listener candidate");

        let outcome = reload_generation_live(&state)
            .await
            .expect("live reload succeeds");
        assert_eq!(outcome.new_generation, INITIAL_GENERATION_ID + 1);
        assert!(workload_socket.exists());
        let generation = state.load_generation();
        assert_eq!(generation.id(), outcome.new_generation);
        assert!(generation.listeners().get("workloads").is_some());
        drop(generation);
        runtime
            .run_until_shutdown(std::future::ready(()))
            .await
            .expect("listener runtime shuts down");
        assert!(!host_socket.exists());
        assert!(!workload_socket.exists());
    }

    /// An invalid candidate (malformed policy) is REJECTED, the previous
    /// generation keeps serving, and the engine never panics.
    #[test]
    fn invalid_policy_is_rejected_and_previous_generation_keeps_serving() {
        let (state, inputs) = state_with_files(&catalog_json(true), &policy_json(true));

        // Corrupt the policy: reference a role that is not declared (§5 hard error
        // UnknownRole), the catalog is unchanged, so this isolates a *validation*
        // rejection from the routing-shape guard.
        write_files(
            &inputs,
            &catalog_json(true),
            r#"{ "schema": "policy", "subjects": { "svc.web": { "domain": "host-process", "match": { "all": [ { "process.uid": 1000 } ] } } }, "roles": {}, "rules": [ { "id": "bad", "subjects": ["svc.web"], "action": ["role:nonexistent"], "target": ["web.signer"] } ], "config": {} }"#,
        );

        let err = reload_generation(&state).expect_err("malformed policy rejected");
        assert!(matches!(err, ReloadError::Validate(_)));
        assert_eq!(err.audit_reason(), "validation_failed");
        // Previous generation untouched.
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
    }

    fn assert_source_event_contract(
        event: &CapturedEvent,
        outcome: &str,
        active_generation: u64,
        prior_generation_active: bool,
    ) {
        assert_eq!(event.level, Level::INFO);
        assert_eq!(
            event.fields.get("operation"),
            Some(&CapturedValue::String("reload".to_string()))
        );
        assert_eq!(
            event.fields.get("outcome"),
            Some(&CapturedValue::String(outcome.to_string()))
        );
        assert_eq!(
            event.fields.get("active_generation"),
            Some(&CapturedValue::U64(active_generation))
        );
        assert_eq!(
            event.fields.get("active_generation_present"),
            Some(&CapturedValue::Bool(true))
        );
        assert_eq!(
            event.fields.get("prior_generation_active"),
            Some(&CapturedValue::Bool(prior_generation_active))
        );
        assert_eq!(
            event.fields.get("name"),
            Some(&CapturedValue::String(String::new()))
        );
        assert_eq!(
            event.fields.get("name_present"),
            Some(&CapturedValue::Bool(false))
        );
        assert!(
            matches!(
                event.fields.get("slot"),
                Some(CapturedValue::String(slot))
                    if matches!(slot.as_str(), "agent" | "catalog" | "policy")
            ),
            "source slot is stable"
        );
        assert!(
            matches!(
                event.fields.get("path"),
                Some(CapturedValue::String(path)) if !path.is_empty()
            ),
            "resolved path is present"
        );
        assert!(matches!(
            event.fields.get("byte_size"),
            Some(CapturedValue::U64(size)) if *size > 0
        ));
        assert!(matches!(
            event.fields.get("modified_unix_seconds"),
            Some(CapturedValue::I64(seconds)) if *seconds > 0
        ));
        assert!(matches!(
            event.fields.get("modified_nanoseconds"),
            Some(CapturedValue::U64(nanoseconds)) if *nanoseconds < 1_000_000_000
        ));
        assert_eq!(
            event.fields.get("hash_algorithm"),
            Some(&CapturedValue::String("sha256".to_string()))
        );
        assert!(matches!(
            event.fields.get("hash"),
            Some(CapturedValue::String(hash))
                if hash.len() == 64
                    && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        ));
        assert!(
            event
                .fields
                .values()
                .filter_map(|value| match value {
                    CapturedValue::String(value) | CapturedValue::Debug(value) => Some(value),
                    CapturedValue::Bool(_) | CapturedValue::I64(_) | CapturedValue::U64(_) => None,
                })
                .all(|value| !value.contains("source-secret-sentinel"))
        );
    }

    #[test]
    fn reload_source_events_are_typed_complete_and_attempt_scoped() {
        const CHILD_ENV: &str = "BASIL_RELOAD_TRACE_CAPTURE_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            let output = std::process::Command::new(
                std::env::current_exe().expect("current test executable"),
            )
            .args([
                "--exact",
                "core::reload::tests::reload_source_events_are_typed_complete_and_attempt_scoped",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .expect("run isolated trace-capture test");
            assert!(
                output.status.success(),
                "isolated trace capture failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        let capture = EventCapture::default();
        let subscriber = Registry::default().with(capture.clone());

        tracing::subscriber::with_default(subscriber, || {
            write_files(&inputs, &catalog_json(true), &policy_json(true));
            reload_generation(&state).expect("accepted reload");

            let rejected_policy = r#"{
              "schema": "policy",
              "subjects": { "svc.web": { "domain": "host-process", "match": { "all": [ { "process.uid": 1000 } ] } } },
              "roles": {},
              "rules": [ {
                "id": "bad", "subjects": ["svc.web"],
                "action": ["role:missing"], "target": ["web.signer"],
                "comment": "source-secret-sentinel"
              } ],
              "config": {}
            }"#;
            write_files(&inputs, &catalog_json(true), rejected_policy);
            reload_generation(&state).expect_err("semantic rejection");
        });

        let events = capture.source_events();
        assert_eq!(events.len(), 6, "three sources per reload attempt");
        for event in &events[..3] {
            assert_source_event_contract(event, "accepted", INITIAL_GENERATION_ID, false);
        }
        for event in &events[3..] {
            assert_source_event_contract(event, "rejected", INITIAL_GENERATION_ID + 1, true);
        }
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID + 1);
    }

    #[test]
    fn reload_input_change_during_read_is_rejected() {
        let (state, inputs) = state_with_files(&catalog_json(true), &policy_json(true));

        let err = read_reload_inputs_with_observer(&inputs, || {
            std::fs::write(
                inputs
                    .config_path
                    .parent()
                    .expect("config parent")
                    .join("policy.json"),
                policy_json(true).replace("\"rules\"", "\"rules_changed\""),
            )
            .expect("race policy rewrite");
        })
        .expect_err("changed policy fingerprint rejects torn read");

        assert!(matches!(err, ReloadError::TornSnapshot { .. }));
        assert_eq!(err.audit_reason(), "inputs_changed_during_read");
        assert_eq!(
            state.active_generation_id(),
            INITIAL_GENERATION_ID,
            "helper rejection leaves the serving generation untouched"
        );
    }

    #[test]
    fn atomic_bootstrap_replacement_after_listener_parse_is_rejected() {
        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        let parent = inputs.config_path.parent().expect("config parent");
        let replacement_policy = parent.join("policy.replacement.json");
        let replacement_bootstrap = parent.join("config.replacement.toml");
        std::fs::write(&replacement_policy, policy_json(true)).expect("stage replacement policy");
        std::fs::write(
            &replacement_bootstrap,
            "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n[listeners.replaced]\ntype = \"host\"\npath = \"/tmp/basil-replaced.sock\"\n",
        )
        .expect("stage replacement bootstrap");

        let error = read_reload_inputs_with_bootstrap_observer(&inputs, || {
            std::fs::rename(&replacement_policy, parent.join("policy.json"))
                .expect("atomically replace policy");
            std::fs::rename(&replacement_bootstrap, &inputs.config_path)
                .expect("atomically replace bootstrap after listener parse");
        })
        .expect_err("mixed bootstrap and corpus snapshot must be rejected");

        assert!(matches!(
            error,
            ReloadError::TornSnapshot { ref path }
                if path == &inputs.config_path.display().to_string()
        ));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
        let generation = state.load_generation();
        assert!(generation.listeners().get("replaced").is_none());
        assert_eq!(generation.policy().grant_count(), 0);
    }

    /// A non-profile JWT-SVID issuer candidate is rejected: the loader's fail-closed
    /// issuer-alg guardrail runs on the reload path (validation), so the broker
    /// never swaps in a generation that would mint SPIFFE-rejected tokens.
    #[test]
    fn non_profile_jwt_svid_issuer_is_rejected_on_reload() {
        // Base: an RSA JWT-SVID issuer (loads at startup).
        let base_catalog = r#"{
          "schema": "catalog",
          "backends": { "bao": { "kind": "vault", "addr": "http://127.0.0.1:8200" } },
          "keys": {
            "spiffe.jwt": {
              "class": "asymmetric", "keyType": "rsa-2048", "backend": "bao", "path": "jwt",
              "labels": ["svid_kind=jwt", "trust_domain=example.org"],
              "writable": false, "description": "jwt issuer"
            }
          }
        }"#;
        let (state, inputs) = state_with_files(base_catalog, &policy_json(false));

        // Candidate flips the issuer to ed25519 (EdDSA): a non-profile alg.
        let bad_catalog = base_catalog.replace("rsa-2048", "ed25519");
        write_files(&inputs, &bad_catalog, &policy_json(false));

        let err = reload_generation(&state).expect_err("non-profile jwt issuer rejected");
        // It is caught (either by the alg guardrail in validation, or, since the
        // key_type is part of the routing shape, by the restart-only guard);
        // either way the reload fails closed and the prior generation serves on.
        assert!(matches!(
            err,
            ReloadError::Validate(_) | ReloadError::RoutingShapeChanged(_)
        ));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
    }

    /// A restart-only edit (a key repathed to a different backend locator) is
    /// rejected: the live manager/backends cannot re-route without a restart.
    #[test]
    fn restart_only_routing_change_is_rejected() {
        let (state, inputs) = state_with_files(&catalog_json(true), &policy_json(true));
        write_files(&inputs, &catalog_json_repathed(), &policy_json(true));
        let mut traces = Vec::new();

        let err = validate_candidate_with_trace_collector(&state, &mut traces)
            .err()
            .expect("repath rejected");
        assert!(matches!(err, ReloadError::RoutingShapeChanged(_)));
        assert_eq!(err.audit_reason(), "routing_shape_changed");
        assert_eq!(traces.len(), 3, "all files read remain traceable");
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
    }

    /// `check_reload` (the `--check` dry-run) validates the candidate and reports
    /// the would-be outcome WITHOUT swapping: the serving generation id is
    /// unchanged, and a subsequent real reload applies the very same outcome.
    #[test]
    fn check_reload_validates_without_swapping() {
        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);

        write_files(&inputs, &catalog_json(true), &policy_json(true));
        let dry = check_reload(&state).expect("dry-run validates");
        assert_eq!(dry.previous_generation, INITIAL_GENERATION_ID);
        assert_eq!(dry.new_generation, INITIAL_GENERATION_ID + 1);
        assert_eq!(dry.key_count, 1);
        assert_eq!(dry.grant_count, 1);
        // The serving generation is UNCHANGED by the dry-run.
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);

        // A real reload now applies exactly what the dry-run previewed.
        let applied = reload_generation(&state).expect("real reload applies");
        assert_eq!(applied, dry);
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID + 1);
    }

    /// A rejected candidate is rejected identically by the dry-run and the real
    /// reload, and neither swaps: the dry-run never diverges from enforcement.
    #[test]
    fn check_reload_rejects_what_real_reload_rejects() {
        let (state, inputs) = state_with_files(&catalog_json(true), &policy_json(true));
        write_files(&inputs, &catalog_json_repathed(), &policy_json(true));

        let dry = check_reload(&state).expect_err("dry-run rejects repath");
        assert!(matches!(dry, ReloadError::RoutingShapeChanged(_)));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);

        let real = reload_generation(&state).expect_err("real reload rejects repath");
        assert!(matches!(real, ReloadError::RoutingShapeChanged(_)));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
    }

    /// Concurrent reload triggers (SIGHUP + admin RPC in production; two threads
    /// here) are serialized by the reload lock: both apply, generation ids stay
    /// monotonic with no duplicate stamp, and no candidate is lost.
    #[test]
    fn concurrent_reloads_are_serialized_with_monotonic_generations() {
        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        write_files(&inputs, &catalog_json(true), &policy_json(true));

        let outcomes = std::thread::scope(|scope| {
            // Spawn both BEFORE joining either, so the two reloads genuinely
            // overlap (a lazy spawn-then-join iterator would serialize them).
            let first = scope.spawn(|| reload_generation(&state));
            let second = scope.spawn(|| reload_generation(&state));
            [first, second].map(|h| h.join().expect("reload thread panicked"))
        });

        let mut transitions: Vec<(u64, u64)> = outcomes
            .into_iter()
            .map(|o| {
                let o = o.expect("both concurrent reloads apply");
                (o.previous_generation, o.new_generation)
            })
            .collect();
        transitions.sort_unstable();
        // Strictly ordered handoff: N→N+1 then N+1→N+2, never two identical
        // N→N+1 stamps (the lost-update signature).
        assert_eq!(
            transitions,
            vec![
                (INITIAL_GENERATION_ID, INITIAL_GENERATION_ID + 1),
                (INITIAL_GENERATION_ID + 1, INITIAL_GENERATION_ID + 2),
            ]
        );
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID + 2);
    }

    /// The dry-run outcome enumerates the candidate-aware listener impact: what
    /// a SIGHUP would do to the listener surface right now (adds/removals with
    /// exact active counts and paths), without swapping anything.
    #[test]
    fn check_reload_reports_candidate_listener_impacts() {
        use crate::transport::listener_manager::ListenerChangeKind;

        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        let socket = format!("/tmp/basil-reload-impact-{}.sock", uuid::Uuid::new_v4());
        std::fs::write(
            &inputs.config_path,
            format!(
                "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n[listeners.control]\ntype = \"host\"\npath = {socket:?}\n"
            ),
        )
        .expect("write named listener candidate");

        let dry = check_reload(&state).expect("candidate validates");
        assert_eq!(dry.listener_impacts.len(), 2, "{:?}", dry.listener_impacts);
        let add = dry
            .listener_impacts
            .iter()
            .find(|impact| impact.kind() == ListenerChangeKind::Add)
            .expect("an added listener impact");
        assert_eq!(add.name(), "control");
        assert_eq!(add.active_connections(), 0);
        assert_eq!(add.previous_path(), None);
        assert_eq!(add.new_path(), Some(std::path::Path::new(socket.as_str())));
        let remove = dry
            .listener_impacts
            .iter()
            .find(|impact| impact.kind() == ListenerChangeKind::Remove)
            .expect("the replaced default host listener impact");
        assert_eq!(remove.name(), "host");
        assert_eq!(
            remove.previous_path(),
            Some(std::path::Path::new(crate::DEFAULT_SOCKET_PATH))
        );
        assert_eq!(remove.new_path(), None);
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);

        // The applied reload reports the identical impacts.
        let applied = reload_generation(&state).expect("candidate applies");
        assert_eq!(applied, dry);
    }

    /// A removal/reconfiguration of a listener with accepted transports is
    /// rejected with the STRUCTURED blocking impact set (its own stable audit
    /// token), and both the dry-run and the real reload reject identically.
    #[tokio::test]
    async fn active_listener_transition_is_rejected_with_blocking_impacts() {
        use crate::transport::grpc_server::ListenerType;
        use crate::transport::listener_manager::ListenerChangeKind;

        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        let (stream, _peer) = tokio::net::UnixStream::pair().expect("stream pair");
        let tracked = state
            .connections()
            .register(stream, "host", ListenerType::Host)
            .expect("track a host connection");
        let socket = format!("/tmp/basil-reload-blocked-{}.sock", uuid::Uuid::new_v4());
        std::fs::write(
            &inputs.config_path,
            format!(
                "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n[listeners.control]\ntype = \"host\"\npath = {socket:?}\n"
            ),
        )
        .expect("write removing candidate");

        for result in [check_reload(&state), reload_generation(&state)] {
            let err = result.expect_err("active host connection blocks the transition");
            assert_eq!(err.audit_reason(), "listener_transition_blocked");
            let ReloadError::ListenerTransitionBlocked(active) = err else {
                panic!("expected the structured blocked variant");
            };
            let impacts = active.impacts();
            assert_eq!(impacts.len(), 1, "{impacts:?}");
            let blocking = impacts.first().expect("one blocking impact");
            assert_eq!(blocking.name(), "host");
            assert_eq!(blocking.kind(), ListenerChangeKind::Remove);
            assert_eq!(blocking.active_connections(), 1);
        }
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);

        // Draining the connection unblocks the same candidate.
        drop(tracked);
        reload_generation(&state).expect("drained transition applies");
    }

    /// An applied same-name path change records a persistent rewire diagnostic;
    /// returning the listener to the recorded previous path resolves it.
    #[test]
    fn applied_path_change_records_and_reverting_resolves_rewire_diagnostics() {
        let (state, inputs) = state_with_files(&catalog_json(false), &policy_json(false));
        assert!(state.connections().rewire().is_empty());
        let socket = format!("/tmp/basil-reload-rewire-{}.sock", uuid::Uuid::new_v4());
        std::fs::write(
            &inputs.config_path,
            format!(
                "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n[listeners.host]\ntype = \"host\"\npath = {socket:?}\n"
            ),
        )
        .expect("write repathed host candidate");

        // The dry-run reports the reconfiguration but records NOTHING.
        let dry = check_reload(&state).expect("repathed candidate validates");
        assert!(
            dry.listener_impacts
                .iter()
                .any(crate::transport::listener_manager::ListenerImpact::rewires_path),
            "{:?}",
            dry.listener_impacts
        );
        assert!(state.connections().rewire().is_empty());

        let outcome = reload_generation(&state).expect("repathed candidate applies");
        let diagnostics = state.connections().rewire().snapshot();
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = diagnostics.first().expect("one rewire diagnostic");
        assert_eq!(diagnostic.listener(), "host");
        assert_eq!(
            diagnostic.previous_path(),
            std::path::Path::new(crate::DEFAULT_SOCKET_PATH)
        );
        assert_eq!(diagnostic.new_path(), std::path::Path::new(socket.as_str()));
        assert_eq!(diagnostic.applied_generation(), outcome.new_generation);

        // Reverting to the original path resolves the diagnostic.
        std::fs::write(
            &inputs.config_path,
            "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n",
        )
        .expect("restore legacy default host listener");
        reload_generation(&state).expect("reverting candidate applies");
        assert!(state.connections().rewire().is_empty());
    }

    /// A broker with no configured paths fails the reload closed (no-op), never
    /// reading catalog/policy from an unconfigured source.
    #[test]
    fn reload_without_inputs_fails_closed() {
        let (cat, pol, cfg, _) =
            load(&catalog_json(true), &policy_json(true)).expect("fixture loads");
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".into(), Box::new(NoopBackend));
        let manager = BackendManager::new(cat.clone(), backends).expect("manager builds");
        let state = BrokerState::new(cat, pol, cfg, manager, "noop");

        let err = reload_generation(&state).expect_err("no inputs → fail closed");
        assert!(matches!(err, ReloadError::NoInputs));
        assert_eq!(state.active_generation_id(), INITIAL_GENERATION_ID);
    }
}
