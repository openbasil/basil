// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared broker state: a hot-swappable policy **generation** + the backend
//! manager, constructed once at startup and shared (`Arc`) across connections.
//!
//! [`BrokerState`] is the single object the gRPC service adapters share. It
//! bundles:
//!
//! - the active [`Generation`]: the loaded **catalog**, **resolved policy**
//!   index, and export-resolved **config** tables that are the inputs to the
//!   [`Pdp`] (`vault-1l8`), plus a monotonic generation **id**, held behind an
//!   [`arc_swap::ArcSwap`] so a future reload (`basil-y3e.2`) can atomically swap
//!   in a fresh generation without restarting the broker, and
//! - the [`BackendManager`] (`vault-jso`) that routes an allowed op to its backend.
//!
//! **Generation pinning.** The catalog/policy/config triple is no longer
//! immutable for the broker's lifetime: a SIGHUP reload may replace it atomically.
//! To keep each operation coherent (never deciding with an old catalog but a new
//! policy), every RPC snapshots the generation **once** at request entry via
//! [`BrokerState::load_generation`] and uses that one [`Generation`] (its
//! [`Generation::pdp`], [`Generation::config`], and [`Generation::id`]) for the
//! whole op. Holding a single snapshot makes cross-generation coherence true by
//! construction. The manager, limits, audit sink, and event source remain
//! lifetime-immutable and live directly on [`BrokerState`].
//!
//! Today there is exactly one generation (id `1`); this iteration lands only the
//! pinning plumbing: there is no reload trigger yet (`basil-y3e.2`).

use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, Guard};

use crate::audit::{AuditLog, ReloadActor};
use crate::catalog::policy::{Config, ResolvedPolicy};
use crate::catalog::{Catalog, Pdp};
use crate::configuration::OverrideProvenance;
use crate::core::crypto_provider::{ProviderAuditEvent, ProviderAuditOutcome};
use crate::decision::DecisionRecord;
use crate::event::EventSource;
use crate::manager::{BackendManager, ManagerError};
use crate::reload::ReloadInputs;
use crate::revocation::JwtRevocationStore;

/// The generation id assigned to the broker's first (startup) generation.
///
/// The id is a monotonic counter bumped on each successful reload; it starts at
/// `1` so `0` can never be mistaken for a live generation.
pub const INITIAL_GENERATION_ID: u64 = 1;

/// One coherent snapshot of the reloadable policy surface.
///
/// A `Generation` bundles the [`Catalog`], [`ResolvedPolicy`] index, and
/// export-resolved [`Config`] tables that together drive a [`Pdp`] decision, plus
/// a monotonic [`id`](Generation::id) that names this snapshot in the audit trail.
/// It is the unit that [`BrokerState`] swaps atomically on reload: an operation
/// that pins one `Generation` sees an internally consistent
/// `(catalog, policy, config)` triple for its entire lifetime, so a concurrent
/// reload can never mix an old catalog with a new policy.
#[derive(Debug)]
pub struct Generation {
    /// Monotonic generation id (starts at [`INITIAL_GENERATION_ID`], bumped on
    /// each successful reload). Carried into the audit record.
    id: u64,
    catalog: Arc<Catalog>,
    policy: ResolvedPolicy,
    config: Config,
    overrides: Vec<OverrideProvenance>,
}

impl Generation {
    /// Bundle a `(catalog, policy, config)` triple under a generation `id`.
    #[must_use]
    pub fn new(
        id: u64,
        catalog: impl Into<Arc<Catalog>>,
        policy: ResolvedPolicy,
        config: Config,
    ) -> Self {
        Self::new_with_overrides(id, catalog, policy, config, Vec::new())
    }

    /// Bundle a generation with its non-secret startup-override provenance.
    #[must_use]
    pub fn new_with_overrides(
        id: u64,
        catalog: impl Into<Arc<Catalog>>,
        policy: ResolvedPolicy,
        config: Config,
        overrides: Vec<OverrideProvenance>,
    ) -> Self {
        Self {
            id,
            catalog: catalog.into(),
            policy,
            config,
            overrides,
        }
    }

    /// This generation's monotonic id (for the audit record / status probe).
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// A [`Pdp`] borrowing this generation's catalog/policy/config for one
    /// decision.
    ///
    /// The PDP is `Copy` and holds only shared borrows into this generation, so
    /// this is a cheap view, not a clone. The borrow ties the PDP to the
    /// generation snapshot, keeping the whole decision coherent.
    #[must_use]
    pub fn pdp(&self) -> Pdp<'_> {
        Pdp::new(&self.catalog, &self.policy, &self.config)
    }

    /// The export-resolved config tables (for `name(num)` audit rendering).
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// This generation's resolved authorization policy.
    #[must_use]
    pub const fn policy(&self) -> &ResolvedPolicy {
        &self.policy
    }

    /// This generation's loaded [`Catalog`].
    ///
    /// Used by the reload engine (`basil-y3e.2`) to compare the candidate's
    /// restart-only routing shape against the currently-serving generation.
    #[must_use]
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Non-secret startup overrides applied to this coherent generation.
    #[must_use]
    pub fn override_provenance(&self) -> &[OverrideProvenance] {
        &self.overrides
    }
}

/// The default `max_encrypt_size`: 1 MiB (wire-protocol-v2 §2.1).
pub const DEFAULT_MAX_ENCRYPT_SIZE: usize = 1024 * 1024;

/// The default `max_payload_size`: 1 MiB.
///
/// Bounds the `set` value and the `import` key material broker-side
/// (wire-protocol-v2 §2.1, "same mechanism" as the AEAD cap), returning
/// `payload_too_large` instead of relying on the u32 frame ceiling (`vault-sao`).
pub const DEFAULT_MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// The default rotation grace window, in key versions (`vault-xhq`).
///
/// A ciphertext/signature made up to this many versions back still
/// decrypts/verifies. `1` honors the single previous version (plus the latest);
/// raise it for a longer window, or set `0` to honor *only* the newest version
/// (the compromise/panic setting).
pub const DEFAULT_ROTATION_GRACE_VERSIONS: u32 = 1;

/// Default SPIFFE SVID lifetime in seconds.
pub const DEFAULT_SVID_TTL_SECS: u64 = 300;

/// Broker-wide runtime limits + rotation policy, supplied by the binary at
/// startup and shared (immutable) across connections.
///
/// These are *broker* knobs (not catalog/policy data): payload caps, SVID
/// lifetime, and the rotation grace/retention windows the manager applies on
/// `rotate` + the retention sweep (`vault-xhq` / `vault-uo1`).
#[derive(Debug, Clone, Copy)]
pub struct BrokerLimits {
    /// Cap (bytes) on the `encrypt` plaintext **and** the `decrypt` ciphertext;
    /// over-limit → `payload_too_large` (wire §2.1). Default
    /// [`DEFAULT_MAX_ENCRYPT_SIZE`].
    pub max_encrypt_size: usize,
    /// Cap (bytes) on the `set` value and the `import` key material; over-limit →
    /// `payload_too_large` (wire §2.1, "same mechanism" as the AEAD cap). This is
    /// the broker-side max that replaces relying on the u32 frame ceiling
    /// (`vault-sao`). Default [`DEFAULT_MAX_PAYLOAD_SIZE`].
    pub max_payload_size: usize,
    /// Rotation grace window in **key versions**: on `rotate`, the manager raises
    /// the backend's `min_decryption_version` to `new_version - grace_versions`
    /// (clamped at 1), so versions older than the window stop decrypting/verifying
    /// while the in-window ones still do. Default
    /// [`DEFAULT_ROTATION_GRACE_VERSIONS`].
    pub grace_versions: u32,
    /// Lifetime, in seconds, for SPIFFE SVIDs minted by the Workload API. Default
    /// [`DEFAULT_SVID_TTL_SECS`].
    pub svid_ttl_secs: u64,
    /// Retention floor in **key versions**: [`BrokerLimits::retention_floor`]
    /// raises the backend's `min_available_version` to
    /// `latest - retain_versions` (clamped at 1), irreversibly pruning archived
    /// key material below it. `None` disables the sweep (retain everything).
    pub retain_versions: Option<u32>,
}

impl Default for BrokerLimits {
    fn default() -> Self {
        Self {
            max_encrypt_size: DEFAULT_MAX_ENCRYPT_SIZE,
            max_payload_size: DEFAULT_MAX_PAYLOAD_SIZE,
            grace_versions: DEFAULT_ROTATION_GRACE_VERSIONS,
            svid_ttl_secs: DEFAULT_SVID_TTL_SECS,
            retain_versions: None,
        }
    }
}

impl BrokerLimits {
    /// The grace floor (`min_decryption_version`) for a key now at `latest`:
    /// `latest - grace_versions`, clamped to at least `1`.
    #[must_use]
    pub const fn grace_floor(&self, latest: u32) -> u32 {
        let floor = latest.saturating_sub(self.grace_versions);
        if floor < 1 { 1 } else { floor }
    }

    /// The retention floor (`min_available_version`) for a key now at `latest`,
    /// or `None` when retention is disabled. `latest - retain_versions`, clamped
    /// to at least `1` (never prunes the only/last version).
    #[must_use]
    pub const fn retention_floor(&self, latest: u32) -> Option<u32> {
        match self.retain_versions {
            Some(retain) => {
                let floor = latest.saturating_sub(retain);
                Some(if floor < 1 { 1 } else { floor })
            }
            None => None,
        }
    }
}

/// How long a computed readiness probe is reused before re-fanning-out to the
/// backend (`basil-8nwy`).
///
/// The admin `Readiness` RPC runs one metadata/KV read **per catalog key** against
/// the backend. It is ungated (any socket peer may call it), so without a cache a
/// hostile local peer could hammer `basil ready` to amplify N backend reads. A
/// short TTL bounds that fan-out to at most one probe per window while staying well
/// under any sane liveness/readiness poll cadence, so a real readiness transition
/// is still surfaced within [`READINESS_CACHE_TTL`]. A generation change
/// (hot reload) invalidates the cache immediately regardless of the TTL.
pub const READINESS_CACHE_TTL: Duration = Duration::from_secs(2);

/// How long a computed JWKS document is reused before re-reading issuer public
/// keys from the backend. A generation change invalidates the cache immediately.
pub const JWKS_CACHE_TTL: Duration = Duration::from_secs(2);

/// The coarse readiness category a probe resolved to: the proto-free core of the
/// admin `Readiness` summary (the service layer maps it onto the wire enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessState {
    /// Every `missing=error` key is present and the backend was reachable.
    Ready,
    /// At least one `missing=error` key's material is absent: its ops would fail
    /// closed.
    RequiredKeyMissing,
    /// The backend was unreachable/rejecting during the probe (fail closed). The
    /// per-key counts are unknown in this arm and reported as zero.
    BackendUnreachable,
}

/// The non-secret outcome of one readiness probe.
///
/// Carries the coarse [`ReadinessState`] plus the key counts the admin summary
/// reports. Absent keys are classified against the serving generation's catalog
/// at probe time (`missing` is a reloadable dimension), so a cached outcome is
/// reused only while it still matches the generation that produced it (see
/// [`CachedReadiness`]); the serving generation id itself is stamped on the wire
/// response by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadinessOutcome {
    /// The coarse readiness category.
    pub state: ReadinessState,
    /// Total catalog keys probed (`0` when the backend was unreachable).
    pub keys_total: u32,
    /// Keys whose material is present.
    pub keys_present: u32,
    /// Absent `missing=error` keys (the ones that block readiness).
    pub keys_required_missing: u32,
    /// Absent `missing=warn`/`generate` keys (which do not block readiness).
    pub keys_optional_missing: u32,
}

impl ReadinessOutcome {
    /// Whether the broker is ready (no required key absent, backend reachable).
    #[must_use]
    pub const fn ready(&self) -> bool {
        matches!(self.state, ReadinessState::Ready)
    }
}

/// A cached readiness probe: the [`ReadinessOutcome`] plus the generation it was
/// computed for and the [`Instant`] after which it is stale (the TTL deadline).
#[derive(Debug, Clone, Copy)]
struct CachedReadiness {
    outcome: ReadinessOutcome,
    generation: u64,
    expires_at: Instant,
}

/// A cached JWKS document, keyed by the serving generation.
#[derive(Debug, Clone)]
pub struct CachedJwks {
    /// Serialized JWKS body.
    pub body: Vec<u8>,
    /// Strong `ETag` for `body`.
    pub etag: String,
    generation: u64,
    expires_at: Instant,
}

/// The shared broker state: the loaded policy surface plus the backend manager.
///
/// Construct once with [`BrokerState::new`] and wrap in an `Arc`; the accept loop
/// clones the `Arc` into every connection handler.
#[derive(Debug)]
pub struct BrokerState {
    /// The active policy generation, swapped atomically on reload (`basil-y3e`).
    /// Every RPC loads exactly one snapshot of this and pins the whole op to it.
    generation: ArcSwap<Generation>,
    manager: BackendManager,
    /// A stable backend label reported in a `status` response. The manager does
    /// not expose its backend kinds, so the binary supplies one at construction
    /// (e.g. `"vault"`); `vault-i9j`'s `list`/metadata work can refine this.
    backend_label: String,
    /// The broker software version reported by `status`/`health`. The binary
    /// (`basil-bin`) supplies its own `CARGO_PKG_VERSION` at construction via
    /// [`BrokerState::with_version`], so the served version tracks the shipped
    /// `basil` binary even if this library crate (`basil-core`) is versioned
    /// separately. Defaults to this crate's version (the workspace version, the
    /// two coincide today) when the binary does not set it.
    agent_version: String,
    /// Broker-wide payload caps + rotation grace/retention policy.
    limits: BrokerLimits,
    /// Optional JSONL audit sink (`vault-vq5`): when `Some`, every recorded
    /// decision is also appended as one JSON line to an append-only file. `None`
    /// disables file-audit (the `tracing` log is always emitted regardless). Held
    /// behind an `Arc` because the sink is shared, immutable, and internally
    /// synchronized; the field is cloneable into the per-op audit call.
    audit: Option<Arc<AuditLog>>,
    events: EventSource,
    jwt_revocations: JwtRevocationStore,
    /// The configured on-disk catalog/policy paths the SIGHUP reload engine
    /// (`basil-y3e.2`) re-reads from. `None` disables reload (the broker has no
    /// configured paths to re-read); a SIGHUP then only reopens the audit log.
    reload_inputs: Option<ReloadInputs>,
    /// A short TTL cache of the last admin readiness probe (`basil-8nwy`), so a
    /// burst of ungated `Readiness` RPCs re-fans-out to the backend at most once
    /// per [`READINESS_CACHE_TTL`] instead of per call. Guarded by a `Mutex`; the
    /// backend probe is never run while the lock is held, and the cache is bypassed
    /// when the serving generation has changed since the cached probe.
    readiness_cache: Mutex<Option<CachedReadiness>>,
    /// Short TTL cache for the unauthenticated network-facing JWKS endpoint.
    jwks_cache: Mutex<Option<CachedJwks>>,
    /// Serializes the reload engine's validate→swap sequence. SIGHUP and the
    /// admin-reload RPC can fire concurrently; without this lock both could pin
    /// generation N, both stamp N+1, and the staler candidate could overwrite
    /// the newer one (a silent lost update). Holds no data: it only orders the
    /// two triggers. Reloads are rare, so contention is irrelevant.
    reload_lock: Mutex<()>,
}

impl BrokerState {
    /// Bundle the loaded policy surface (the `load()` 4-tuple's first three
    /// elements) with an already-constructed [`BackendManager`].
    ///
    /// `backend_label` is the name a `status` response advertises (the backend
    /// `kind()`; with one backend today this is unambiguous). The manager is built
    /// separately because building backends from credentials is the binary's job
    /// (`vault-vh1`); this layer only routes + authorizes.
    #[must_use]
    pub fn new(
        catalog: Catalog,
        policy: ResolvedPolicy,
        config: Config,
        manager: BackendManager,
        backend_label: impl Into<String>,
    ) -> Self {
        Self::with_limits(
            Arc::new(catalog),
            policy,
            config,
            manager,
            backend_label,
            BrokerLimits::default(),
        )
    }

    /// Like [`BrokerState::new`] but with explicit broker [`BrokerLimits`] (the
    /// AEAD payload cap + rotation grace/retention policy the binary threads from
    /// its args). [`BrokerState::new`] uses [`BrokerLimits::default`].
    #[must_use]
    pub fn with_limits(
        catalog: impl Into<Arc<Catalog>>,
        policy: ResolvedPolicy,
        config: Config,
        manager: BackendManager,
        backend_label: impl Into<String>,
        limits: BrokerLimits,
    ) -> Self {
        let generation = Generation::new(INITIAL_GENERATION_ID, catalog, policy, config);
        Self {
            generation: ArcSwap::from_pointee(generation),
            manager,
            backend_label: backend_label.into(),
            // Default to this crate's version; the binary overrides with its own
            // via `with_version` so `status`/`health` report the `basil` binary's
            // version, not `basil-core`'s.
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            limits,
            audit: None,
            events: EventSource::new(),
            jwt_revocations: JwtRevocationStore::default(),
            reload_inputs: None,
            readiness_cache: Mutex::new(None),
            jwks_cache: Mutex::new(None),
            reload_lock: Mutex::new(()),
        }
    }

    /// Bind non-secret startup-override provenance to the initial generation.
    #[must_use]
    pub fn with_override_provenance(self, overrides: Vec<OverrideProvenance>) -> Self {
        let current = self.generation.load_full();
        let generation = Generation::new_with_overrides(
            current.id,
            Arc::clone(&current.catalog),
            current.policy.clone(),
            current.config.clone(),
            overrides,
        );
        self.generation.store(Arc::new(generation));
        self
    }

    /// Attach a JSONL audit sink (`vault-vq5`), consuming and returning `self`.
    ///
    /// When set, [`BrokerState::audit`] appends one JSONL line per recorded
    /// decision to the open append-only file; when this is never called, file
    /// audit is disabled (`tracing` still logs every decision). The binary opens
    /// the file once at startup and threads the [`AuditLog`] in here.
    #[must_use]
    pub fn with_audit_log(mut self, audit: Arc<AuditLog>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Attach the JWT-SVID revocation deny-list loaded at startup.
    #[must_use]
    pub fn with_jwt_revocations(mut self, jwt_revocations: JwtRevocationStore) -> Self {
        self.jwt_revocations = jwt_revocations;
        self
    }

    /// Set the broker software version reported by `status`/`health`.
    ///
    /// The binary (`basil-bin`) passes its own `env!("CARGO_PKG_VERSION")` so the
    /// served version follows the shipped `basil` binary rather than this
    /// library crate. Without this, the version defaults to `basil-core`'s.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.agent_version = version.into();
        self
    }

    /// Record the configured on-disk catalog/policy paths so the SIGHUP reload
    /// engine (`basil-y3e.2`) can re-read from the **same** paths startup used.
    ///
    /// Without this, [`BrokerState::reload_inputs`] is `None` and a reload fails
    /// closed with `ReloadError::NoInputs` (a SIGHUP then only reopens the audit
    /// log). The broker never reads catalog/policy from an unconfigured source.
    #[must_use]
    pub fn with_reload_inputs(mut self, inputs: ReloadInputs) -> Self {
        self.reload_inputs = Some(inputs);
        self
    }

    /// The configured catalog/policy paths the reload engine re-reads, if any.
    #[must_use]
    pub const fn reload_inputs(&self) -> Option<&ReloadInputs> {
        self.reload_inputs.as_ref()
    }

    /// The lock the reload engine holds across its whole validate→swap sequence,
    /// so concurrent triggers (SIGHUP + admin RPC) apply strictly one at a time
    /// and generation ids stay monotonic with no lost update.
    #[must_use]
    pub const fn reload_lock(&self) -> &Mutex<()> {
        &self.reload_lock
    }

    /// The id of the **currently serving** generation (observable for the status
    /// probe, `basil-s7h`, and the reload audit). A monotonic counter bumped on
    /// each successful reload.
    #[must_use]
    pub fn active_generation_id(&self) -> u64 {
        self.load_generation().id()
    }

    /// Return the cached readiness outcome if one was computed for the
    /// currently-serving generation within [`READINESS_CACHE_TTL`] (`basil-8nwy`).
    ///
    /// A cache hit lets the admin `Readiness` RPC answer **without** re-fanning-out
    /// one backend read per catalog key: the amplification a hostile, ungated
    /// socket peer could otherwise drive. The entry is bypassed (re-probe required)
    /// when it has expired **or** when the serving generation has changed since it
    /// was cached, so a hot reload that alters the key set can never be masked
    /// longer than it takes to recompute, and a stale generation's counts are never
    /// served. Returns `None` to mean "no usable cache; probe the backend".
    ///
    /// The returned outcome is generation-independent; the caller stamps the
    /// current generation id onto the wire response.
    #[must_use]
    pub fn cached_readiness(&self) -> Option<ReadinessOutcome> {
        let generation = self.active_generation_id();
        let now = Instant::now();
        // Copy the small entry out and release the lock immediately; the validity
        // check (and any caller work) never runs while the mutex is held.
        let cached = {
            let guard = self.readiness_cache.lock().ok()?;
            (*guard)?
        };
        (cached.generation == generation && now < cached.expires_at).then_some(cached.outcome)
    }

    /// Store a freshly-computed readiness `outcome` for `generation`, valid for
    /// [`READINESS_CACHE_TTL`] from now (`basil-8nwy`). A subsequent
    /// [`BrokerState::cached_readiness`] within that window (and on the same
    /// generation) reuses it instead of re-probing the backend.
    ///
    /// A poisoned lock is swallowed (the cache is a best-effort optimization, never
    /// a correctness or liveness dependency): the worst case is a missed cache and
    /// one extra probe, never a panic on the serving path.
    pub fn cache_readiness(&self, generation: u64, outcome: ReadinessOutcome) {
        if let Ok(mut guard) = self.readiness_cache.lock() {
            *guard = Some(CachedReadiness {
                outcome,
                generation,
                expires_at: Instant::now() + READINESS_CACHE_TTL,
            });
        }
    }

    /// Return the cached JWKS document for the currently-serving generation.
    #[must_use]
    pub fn cached_jwks(&self) -> Option<CachedJwks> {
        let generation = self.active_generation_id();
        let now = Instant::now();
        let cached = {
            let guard = self.jwks_cache.lock().ok()?;
            (*guard).clone()?
        };
        (cached.generation == generation && now < cached.expires_at).then_some(cached)
    }

    /// Store a freshly-built JWKS document for `generation`.
    pub fn cache_jwks(&self, generation: u64, body: Vec<u8>, etag: String) {
        if let Ok(mut guard) = self.jwks_cache.lock() {
            *guard = Some(CachedJwks {
                body,
                etag,
                generation,
                expires_at: Instant::now() + JWKS_CACHE_TTL,
            });
        }
    }

    /// Atomically swap in a new [`Generation`], replacing the currently serving
    /// one. The **only** mutation point of the reloadable policy surface.
    ///
    /// Callers (the reload engine, `basil-y3e.2`) must have already validated the
    /// new generation; this is the unconditional store. In-flight operations that
    /// pinned the previous generation via [`BrokerState::load_generation`] keep
    /// seeing it until they drop their guard. The swap never disturbs an op
    /// already in progress.
    pub fn swap_generation(&self, generation: Arc<Generation>) {
        self.generation.store(generation);
    }

    /// Snapshot the active [`Generation`] for the lifetime of one operation.
    ///
    /// This is the **one** point an RPC pins its generation: call it once at
    /// request entry, then drive the whole op off the returned guard
    /// ([`Generation::pdp`], [`Generation::config`], [`Generation::id`]) so the
    /// `(catalog, policy, config)` triple stays coherent even if a concurrent
    /// reload swaps in a newer generation mid-op. Hold the guard only as long as
    /// the op needs it (it pins the snapshot from being reclaimed); if the
    /// snapshot must survive an `.await`, clone the inner `Arc` out of the guard
    /// rather than holding the guard across the suspension point.
    #[must_use]
    pub fn load_generation(&self) -> Guard<Arc<Generation>> {
        self.generation.load()
    }

    /// Record one authorization decision (`vault-vq5`): emit it to `tracing`
    /// (allow=info, deny=warn) **and**, when a JSONL audit sink is configured,
    /// append it as one line to the append-only audit file.
    ///
    /// The file append is **best-effort**: an IO error is logged and swallowed by
    /// the sink so an audit-disk problem can never block, deny, or panic the data
    /// plane: the trustworthy decision already happened and is in `tracing`. This
    /// is the single hook the handler calls for every gated op, allow or deny.
    pub fn record_decision(&self, record: &DecisionRecord) {
        record.record();
        if let Some(audit) = &self.audit {
            audit.append(record);
        }
    }

    /// Record one software-custody provider operation (`wuj.7`): emit it to
    /// `tracing` (failure/deny at `warn`, allow/success at `info`) and, when a
    /// JSONL audit sink is configured, append the secret-free
    /// [`ProviderAuditEvent`] JSON as one line. The event carries the selected
    /// provider and algorithm and **never** any seed, signature, plaintext, or
    /// ciphertext bytes. Best-effort like [`Self::record_decision`]: it can never
    /// block, fail, or panic the data plane.
    pub fn record_provider_event(&self, event: &ProviderAuditEvent<'_>) {
        match event.outcome {
            ProviderAuditOutcome::Failure | ProviderAuditOutcome::Deny => tracing::warn!(
                event = "basil.audit.provider_operation",
                op = event.op,
                key = event.key_id,
                algorithm = event.algorithm,
                outcome = ?event.outcome,
                reason = event.reason,
                "software-custody provider operation",
            ),
            ProviderAuditOutcome::Allow | ProviderAuditOutcome::Success => tracing::info!(
                event = "basil.audit.provider_operation",
                op = event.op,
                key = event.key_id,
                algorithm = event.algorithm,
                outcome = ?event.outcome,
                reason = event.reason,
                "software-custody provider operation",
            ),
        }
        if let Some(audit) = &self.audit {
            audit.append_value(&event.to_json_value());
        }
    }

    /// Record a generation reload outcome (`basil-y3e.2`, `basil-atq`): emit it to
    /// `tracing` and, when a JSONL audit sink is configured, append one
    /// `basil.audit.reload` line.
    ///
    /// `outcome` is one of `"applied"` (a real swap happened, logged at `info`),
    /// `"checked"` (an admin `--check` dry-run validated, no swap, `info`), or
    /// `"rejected"` (the candidate failed; previous generation keeps serving,
    /// `warn`). `reason` is a short, stable, non-secret token (e.g. `signal`,
    /// `admin_rpc`, or a [`ReloadError`](crate::reload::ReloadError) audit token).
    /// `actor` attributes the trigger ([`ReloadActor::Sighup`] for the signal path
    /// or [`ReloadActor::Caller`] with the attested uid for the admin RPC), the
    /// only field that differs in the audit trail between an otherwise-identical
    /// SIGHUP and RPC reload (`basil-ftmc`). Like [`BrokerState::record_decision`],
    /// the file append is best-effort and can never block, fail, or panic the broker.
    pub fn record_reload(
        &self,
        previous_generation: u64,
        new_generation: u64,
        outcome: &str,
        reason: &str,
        actor: ReloadActor,
    ) {
        let generation = self.load_generation();
        let overrides = generation.override_provenance();
        match outcome {
            "applied" => tracing::info!(
                event = "basil.audit.reload",
                previous_generation,
                generation = new_generation,
                outcome,
                reason,
                override_count = overrides.len(),
                "catalog/policy reload applied",
            ),
            "checked" => tracing::info!(
                event = "basil.audit.reload",
                previous_generation,
                generation = new_generation,
                outcome,
                reason,
                override_count = overrides.len(),
                "catalog/policy reload dry-run validated; no swap",
            ),
            _ => tracing::warn!(
                event = "basil.audit.reload",
                previous_generation,
                generation = new_generation,
                outcome,
                reason,
                override_count = overrides.len(),
                "catalog/policy reload rejected; previous generation still serving",
            ),
        }
        if let Some(audit) = &self.audit {
            audit.append_reload_with_overrides(
                previous_generation,
                new_generation,
                outcome,
                reason,
                actor,
                overrides,
            );
        }
    }

    /// The backend manager that routes an allowed op to its backend instance.
    #[must_use]
    pub const fn manager(&self) -> &BackendManager {
        &self.manager
    }

    /// The backend label advertised in a `status` response.
    #[must_use]
    pub fn backend_label(&self) -> &str {
        &self.backend_label
    }

    /// The broker software version advertised in `status`/`health` responses.
    #[must_use]
    pub fn agent_version(&self) -> &str {
        &self.agent_version
    }

    /// The broker-wide payload caps + rotation grace/retention policy.
    #[must_use]
    pub const fn limits(&self) -> BrokerLimits {
        self.limits
    }

    /// Shared broker event source.
    #[must_use]
    pub const fn events(&self) -> &EventSource {
        &self.events
    }

    /// JWT-SVID revocation deny-list shared by Workload API validation.
    #[must_use]
    pub const fn jwt_revocations(&self) -> &JwtRevocationStore {
        &self.jwt_revocations
    }

    /// Re-read the catalog-backed JWT-SVID deny-list and merge it into memory.
    ///
    /// This stays outside the hot-swapped [`Generation`]: the deny-list is mutable
    /// serving state, and refresh uses union semantics so a live revocation cannot
    /// be clobbered by a concurrent reload.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] if the configured store is malformed, unreadable,
    /// or the live deny-list locks are poisoned. On error the previous in-memory
    /// set remains serving.
    pub async fn refresh_jwt_revocations(&self) -> Result<(), ManagerError> {
        self.jwt_revocations
            .refresh_from_manager(&self.manager)
            .await
    }

    /// Persist and publish a JWT-SVID revocation.
    ///
    /// # Errors
    ///
    /// Returns [`crate::manager::ManagerError`] if the optional catalog-backed
    /// deny-list write fails.
    pub async fn revoke_jwt_svid(
        &self,
        trust_domain: &str,
        jti: &str,
        expires_at_unix: u64,
    ) -> Result<(), crate::manager::ManagerError> {
        self.jwt_revocations
            .insert(trust_domain, jti, expires_at_unix)?;
        self.jwt_revocations.persist(&self.manager).await?;
        self.events.revoked(trust_domain, jti);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arc_swap::ArcSwap;

    use super::{Generation, INITIAL_GENERATION_ID};
    use crate::catalog::Catalog;
    use crate::catalog::policy::{Config, Op, ResolvedPolicy};

    /// A minimal, key-less catalog: enough to drive a `Pdp` decision (every key
    /// is unknown → default-deny), without standing up a backend manager.
    fn empty_catalog() -> Catalog {
        Catalog {
            schema: crate::catalog::CatalogSchema::Catalog,
            backends: BTreeMap::new(),
            keys: BTreeMap::new(),
        }
    }

    fn generation(id: u64) -> Generation {
        Generation::new(
            id,
            empty_catalog(),
            ResolvedPolicy::default(),
            Config::default(),
        )
    }

    #[test]
    fn initial_generation_id_is_one() {
        assert_eq!(INITIAL_GENERATION_ID, 1);
        assert_eq!(generation(INITIAL_GENERATION_ID).id(), 1);
    }

    /// A single `load()` guard yields ONE coherent generation: the id, the PDP
    /// it hands out, and its config all come from the same snapshot. This is the
    /// per-request pinning seam: an op drives every decision off one guard.
    #[test]
    fn one_snapshot_is_internally_coherent() {
        let swap = ArcSwap::from_pointee(generation(7));
        let pinned = swap.load();

        // The id, the PDP, and the config are all read from the SAME guard, so
        // they cannot disagree even if a concurrent swap lands mid-op.
        assert_eq!(pinned.id(), 7);
        // The pinned catalog is the empty one, so any key is unknown → deny.
        assert!(
            pinned
                .pdp()
                .explain_subject("svc.missing", Op::Get, "any.key")
                .decision
                .is_deny()
        );
        // The pinned config is the default (no user names), same snapshot.
        assert!(pinned.config().names.users.is_empty());
    }

    /// With no swap between two loads, both observe the same generation id: the
    /// property a future reload (`basil-y3e.2`) will deliberately break by
    /// bumping the id on swap. Today: byte-identical, monotonic, one generation.
    #[test]
    fn repeated_loads_without_swap_see_same_generation() {
        let swap = ArcSwap::from_pointee(generation(INITIAL_GENERATION_ID));
        let first = swap.load().id();
        let second = swap.load().id();
        assert_eq!(first, second);
        assert_eq!(first, INITIAL_GENERATION_ID);
    }

    /// Sanity check that an `ArcSwap` swap is observable by a *later* load while a
    /// guard taken *before* the swap still sees the old generation: the coherence
    /// guarantee the per-request pin relies on. (No production swap path exists
    /// yet; this exercises the primitive the reload engine will use.)
    #[test]
    fn pinned_guard_survives_a_later_swap() {
        let swap = ArcSwap::from_pointee(generation(1));
        let pinned = swap.load();
        assert_eq!(pinned.id(), 1);

        swap.store(std::sync::Arc::new(generation(2)));

        // The guard taken before the swap still names the old generation.
        assert_eq!(pinned.id(), 1);
        // A fresh load sees the new one.
        assert_eq!(swap.load().id(), 2);
    }
}
