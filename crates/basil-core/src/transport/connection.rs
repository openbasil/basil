// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Bounded accepted-transport registry and cancellable Unix-stream wrapper.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future as _;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tonic::transport::server::Connected;

use super::grpc_server::ListenerType;
use crate::actor::{AuthenticatedActor, WorkloadIdentity};
use crate::catalog::AuthorizationDomain;
use crate::peer::PeerInfo;

/// Default broker-wide accepted-transport safety ceiling.
pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;

/// Default accepted-transport ceiling for one listener.
pub const DEFAULT_MAX_CONNECTIONS_PER_LISTENER: usize = 1024;

/// Stable, process-lifetime connection identifier.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(u64);

impl ConnectionId {
    /// Construct a nonzero wire identifier.
    #[must_use]
    pub const fn from_u64(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Numeric identifier for protocol and diagnostic serialization.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Immutable context inserted into every tonic request from one connection.
#[derive(Clone, Debug)]
pub struct ListenerConnectInfo {
    connection_id: ConnectionId,
    listener_name: Arc<str>,
    listener_type: ListenerType,
    peer: PeerInfo,
}

impl ListenerConnectInfo {
    #[cfg(test)]
    pub(crate) fn for_test(
        listener_name: impl Into<Arc<str>>,
        listener_type: ListenerType,
        peer: PeerInfo,
    ) -> Self {
        Self {
            connection_id: ConnectionId(1),
            listener_name: listener_name.into(),
            listener_type,
            peer,
        }
    }

    /// Stable connection identifier.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Stable listener name captured at accept time.
    #[must_use]
    pub fn listener_name(&self) -> &str {
        &self.listener_name
    }

    /// Closed listener type captured at accept time.
    #[must_use]
    pub const fn listener_type(&self) -> ListenerType {
        self.listener_type
    }

    /// Kernel-derived peer facts captured once at accept time.
    #[must_use]
    pub const fn peer(&self) -> &PeerInfo {
        &self.peer
    }
}

/// Bounded diagnostic record for one accepted transport.
#[derive(Clone, Debug)]
pub struct ConnectionRecord {
    context: ListenerConnectInfo,
    identity: Option<ConnectionIdentity>,
    cancellation_requested: bool,
}

impl ConnectionRecord {
    /// Immutable connection context.
    #[must_use]
    pub const fn context(&self) -> &ListenerConnectInfo {
        &self.context
    }

    /// Most recently resolved workload identity for this transport.
    #[must_use]
    pub const fn identity(&self) -> Option<&ConnectionIdentity> {
        self.identity.as_ref()
    }

    /// Whether transport cancellation has been requested.
    #[must_use]
    pub const fn cancellation_requested(&self) -> bool {
        self.cancellation_requested
    }
}

/// Disclosure-safe, typed workload identity retained for connection operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionIdentity {
    domain: AuthorizationDomain,
    subject: String,
    workload: Option<WorkloadIdentity>,
}

impl ConnectionIdentity {
    /// Independently resolved authorization domain.
    #[must_use]
    pub const fn domain(&self) -> AuthorizationDomain {
        self.domain
    }

    /// Uniquely selected policy subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Typed systemd or Compose identity, when the domain supplies one.
    #[must_use]
    pub const fn workload(&self) -> Option<&WorkloadIdentity> {
        self.workload.as_ref()
    }
}

/// Exact typed selector for deliberate connection cancellation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionSelector {
    /// One process-lifetime connection identifier.
    Id(ConnectionId),
    /// Every connection presented by one Unix UID. This is intentionally broad.
    Uid(u32),
    /// A concrete systemd unit in one manager scope.
    Systemd {
        /// Canonical concrete `.service` unit name.
        unit: String,
        /// Per-user manager owner. Absence identifies the system manager.
        manager_user: Option<u32>,
    },
    /// An attested Compose workload identity.
    Compose {
        /// Configured attestor realm.
        realm: String,
        /// Effective Compose project name.
        project: String,
        /// Compose service name, when the workload is a normal service.
        service: Option<String>,
    },
}

/// Aggregate result of one bounded selector cancellation operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectionCancellation {
    /// Active entries matched by at least one selector.
    pub matched: usize,
    /// Cancellation signals delivered during this operation.
    pub cancelled: usize,
    /// Matching entries whose cancellation had already been requested.
    pub already_requested: usize,
    /// Matching caller entry deliberately excluded so the RPC can reply.
    pub caller_excluded: usize,
}

/// Registry construction or registration failure.
#[derive(Debug, Error)]
pub enum ConnectionRegistryError {
    /// One of the configured limits is zero.
    #[error("connection registry limits must be nonzero")]
    InvalidLimit,
    /// The broker-wide accepted-transport ceiling has been reached.
    #[error("broker connection limit reached")]
    GlobalLimit,
    /// One listener's accepted-transport ceiling has been reached.
    #[error("listener `{0}` connection limit reached")]
    ListenerLimit(String),
    /// The process-lifetime monotonic identifier space is exhausted.
    #[error("connection identifier space exhausted")]
    IdExhausted,
    /// Required kernel peer credentials could not be captured.
    #[error("required Unix peer credentials unavailable")]
    PeerCredentials(#[source] io::Error),
    /// The listener is gated for an atomic configuration transition.
    #[error("listener `{0}` is not accepting during configuration transition")]
    ListenerGated(String),
}

/// Synchronous bounded inventory shared by all listener accept loops.
#[derive(Clone)]
pub struct ConnectionRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    maximum: usize,
    maximum_per_listener: usize,
    state: Mutex<RegistryState>,
}

struct RegistryState {
    next_id: Option<u64>,
    entries: BTreeMap<ConnectionId, RegistryEntry>,
    listener_counts: BTreeMap<Arc<str>, usize>,
    gated_listeners: BTreeSet<Arc<str>>,
}

struct RegistryEntry {
    context: ListenerConnectInfo,
    identity: Option<ConnectionIdentity>,
    cancel: Option<oneshot::Sender<()>>,
}

impl ConnectionRegistry {
    /// Construct a registry with the compiled safety ceilings.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                maximum: DEFAULT_MAX_CONNECTIONS,
                maximum_per_listener: DEFAULT_MAX_CONNECTIONS_PER_LISTENER,
                state: Mutex::new(RegistryState {
                    next_id: Some(1),
                    entries: BTreeMap::new(),
                    listener_counts: BTreeMap::new(),
                    gated_listeners: BTreeSet::new(),
                }),
            }),
        }
    }

    /// Construct a registry with hard global and per-listener limits.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRegistryError::InvalidLimit`] when either limit is
    /// zero or when the per-listener limit exceeds the global limit.
    pub fn new(
        maximum: usize,
        maximum_per_listener: usize,
    ) -> Result<Self, ConnectionRegistryError> {
        if maximum == 0 || maximum_per_listener == 0 || maximum_per_listener > maximum {
            return Err(ConnectionRegistryError::InvalidLimit);
        }
        Ok(Self {
            inner: Arc::new(RegistryInner {
                maximum,
                maximum_per_listener,
                state: Mutex::new(RegistryState {
                    next_id: Some(1),
                    entries: BTreeMap::new(),
                    listener_counts: BTreeMap::new(),
                    gated_listeners: BTreeSet::new(),
                }),
            }),
        })
    }

    /// Register an accepted stream before it is yielded to tonic.
    ///
    /// Peer credentials and listener context are captured exactly once. A
    /// rejected stream is returned to the caller and never enters tonic.
    ///
    /// # Errors
    ///
    /// Returns a bounded capacity or identifier-space error.
    pub fn register(
        &self,
        stream: UnixStream,
        listener_name: impl Into<Arc<str>>,
        listener_type: ListenerType,
    ) -> Result<TrackedUnixStream, ConnectionRegistryError> {
        let listener_name = listener_name.into();
        let peer =
            PeerInfo::try_from_stream(&stream).map_err(ConnectionRegistryError::PeerCredentials)?;
        let mut state = lock_state(&self.inner);
        if state.gated_listeners.contains(&listener_name) {
            return Err(ConnectionRegistryError::ListenerGated(
                listener_name.to_string(),
            ));
        }
        if state.entries.len() >= self.inner.maximum {
            return Err(ConnectionRegistryError::GlobalLimit);
        }
        if state
            .listener_counts
            .get(&listener_name)
            .is_some_and(|count| *count >= self.inner.maximum_per_listener)
        {
            return Err(ConnectionRegistryError::ListenerLimit(
                listener_name.to_string(),
            ));
        }
        let Some(raw_id) = state.next_id else {
            return Err(ConnectionRegistryError::IdExhausted);
        };
        let id = ConnectionId(raw_id);
        if state.entries.contains_key(&id) {
            state.next_id = None;
            return Err(ConnectionRegistryError::IdExhausted);
        }
        state.next_id = raw_id.checked_add(1);
        let context = ListenerConnectInfo {
            connection_id: id,
            listener_name: Arc::clone(&listener_name),
            listener_type,
            peer,
        };
        let (cancel, cancellation) = oneshot::channel();
        state.entries.insert(
            id,
            RegistryEntry {
                context: context.clone(),
                identity: None,
                cancel: Some(cancel),
            },
        );
        state
            .listener_counts
            .entry(listener_name)
            .and_modify(|count| *count += 1)
            .or_insert(1);
        drop(state);

        Ok(TrackedUnixStream {
            stream,
            context,
            cancellation,
            lease: ConnectionLease {
                id,
                registry: Arc::downgrade(&self.inner),
            },
        })
    }

    /// Request cancellation of one exact connection.
    ///
    /// The inventory entry remains active until the stream actually drops, so
    /// zero-connection reload checks cannot race ahead of transport teardown.
    #[must_use]
    pub fn cancel(&self, id: ConnectionId) -> bool {
        let sender = {
            let mut state = lock_state(&self.inner);
            state
                .entries
                .get_mut(&id)
                .and_then(|entry| entry.cancel.take())
        };
        sender.is_some_and(|sender| sender.send(()).is_ok())
    }

    /// Retain the latest successfully resolved actor for one active transport.
    pub fn record_actor(&self, id: ConnectionId, actor: &AuthenticatedActor) {
        let mut state = lock_state(&self.inner);
        if let Some(entry) = state.entries.get_mut(&id) {
            entry.identity = Some(ConnectionIdentity {
                domain: actor.domain,
                subject: actor.subject.clone(),
                workload: actor.workload_identity.clone(),
            });
        }
    }

    /// Cancel every active entry matching any selector, except the caller.
    ///
    /// Matching and sender extraction are atomic with registration and release.
    /// Signals are delivered after releasing the registry lock.
    #[must_use]
    pub fn cancel_matching(
        &self,
        selectors: &[ConnectionSelector],
        caller: Option<ConnectionId>,
    ) -> ConnectionCancellation {
        let (senders, mut result) = {
            let mut state = lock_state(&self.inner);
            let mut senders = Vec::new();
            let mut result = ConnectionCancellation::default();
            for (id, entry) in &mut state.entries {
                if !selectors
                    .iter()
                    .any(|selector| selector_matches(selector, *id, entry))
                {
                    continue;
                }
                result.matched += 1;
                if caller == Some(*id) {
                    result.caller_excluded += 1;
                } else if let Some(sender) = entry.cancel.take() {
                    senders.push(sender);
                } else {
                    result.already_requested += 1;
                }
            }
            drop(state);
            (senders, result)
        };
        result.cancelled = senders
            .into_iter()
            .map(|sender| sender.send(()).is_ok())
            .filter(|delivered| *delivered)
            .count();
        result
    }

    /// Return a stable-ID ordered, globally bounded inventory snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Vec<ConnectionRecord> {
        let state = lock_state(&self.inner);
        state
            .entries
            .values()
            .map(|entry| ConnectionRecord {
                context: entry.context.clone(),
                identity: entry.identity.clone(),
                cancellation_requested: entry.cancel.is_none(),
            })
            .collect()
    }

    /// Active connection count for one exact listener name.
    #[must_use]
    pub fn active_for_listener(&self, listener_name: &str) -> usize {
        let state = lock_state(&self.inner);
        state
            .listener_counts
            .get(listener_name)
            .copied()
            .unwrap_or(0)
    }

    /// Gate registration for listener names and atomically snapshot their active
    /// counts under the same lock registration uses.
    ///
    /// The returned guard keeps registration closed until it is dropped. This is
    /// the transition primitive used before zero-active validation, so a new
    /// accepted transport cannot appear between the count and listener commit.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionRegistryError::ListenerGated`] if another transition
    /// already owns one of the requested listener gates.
    pub fn begin_listener_transition(
        &self,
        listener_names: impl IntoIterator<Item = String>,
    ) -> Result<ListenerTransitionGuard, ConnectionRegistryError> {
        let names = listener_names
            .into_iter()
            .map(Arc::<str>::from)
            .collect::<BTreeSet<_>>();
        let mut state = lock_state(&self.inner);
        if let Some(name) = names
            .iter()
            .find(|name| state.gated_listeners.contains(*name))
        {
            return Err(ConnectionRegistryError::ListenerGated(name.to_string()));
        }
        state.gated_listeners.extend(names.iter().cloned());
        let active = names
            .iter()
            .map(|name| {
                (
                    Arc::clone(name),
                    state.listener_counts.get(name).copied().unwrap_or(0),
                )
            })
            .collect();
        drop(state);
        Ok(ListenerTransitionGuard {
            registry: Arc::clone(&self.inner),
            names,
            active,
        })
    }
}

fn selector_matches(
    selector: &ConnectionSelector,
    id: ConnectionId,
    entry: &RegistryEntry,
) -> bool {
    match selector {
        ConnectionSelector::Id(expected) => id == *expected,
        ConnectionSelector::Uid(expected) => entry.context.peer.uid == Some(*expected),
        ConnectionSelector::Systemd { unit, manager_user } => entry
            .identity
            .as_ref()
            .and_then(ConnectionIdentity::workload)
            .is_some_and(|identity| {
                matches!(
                    identity,
                    WorkloadIdentity::Systemd {
                        unit: actual_unit,
                        manager_user: actual_manager,
                    } if actual_unit == unit && actual_manager == manager_user
                )
            }),
        ConnectionSelector::Compose { realm, project, service } => entry
            .identity
            .as_ref()
            .and_then(ConnectionIdentity::workload)
            .is_some_and(|identity| {
                matches!(
                    identity,
                    WorkloadIdentity::Compose {
                        realm: actual_realm,
                        project: actual_project,
                        service: actual_service,
                    } if actual_realm == realm && actual_project == project && actual_service == service
                )
            }),
    }
}

/// Exclusive admission gate for an atomic listener transition.
pub struct ListenerTransitionGuard {
    registry: Arc<RegistryInner>,
    names: BTreeSet<Arc<str>>,
    active: BTreeMap<Arc<str>, usize>,
}

impl ListenerTransitionGuard {
    /// Active count captured atomically when the listener gate closed.
    #[must_use]
    pub fn active_for_listener(&self, listener_name: &str) -> usize {
        self.active.get(listener_name).copied().unwrap_or(0)
    }

    /// Apply the complete listener-set commit while admission remains gated.
    ///
    /// The guard remains held after the closure returns and releases admission
    /// only when the caller drops it. This lets listener runtimes start and retire
    /// accept loops after an irrevocable configuration commit while admission is
    /// still closed.
    pub fn commit<R>(&self, apply: impl FnOnce() -> R) -> R {
        apply()
    }
}

impl Drop for ListenerTransitionGuard {
    fn drop(&mut self) {
        let mut state = lock_state(&self.registry);
        for name in &self.names {
            state.gated_listeners.remove(name);
        }
    }
}

impl fmt::Debug for ConnectionRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionRegistry")
            .field("maximum", &self.inner.maximum)
            .field("maximum_per_listener", &self.inner.maximum_per_listener)
            .finish_non_exhaustive()
    }
}

fn lock_state(inner: &RegistryInner) -> MutexGuard<'_, RegistryState> {
    match inner.state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn release(inner: &RegistryInner, id: ConnectionId) {
    let mut state = lock_state(inner);
    let Some(entry) = state.entries.remove(&id) else {
        return;
    };
    let listener_name = entry.context.listener_name;
    let remove_count = match state.listener_counts.get_mut(&listener_name) {
        Some(count) if *count > 1 => {
            *count -= 1;
            false
        }
        Some(_) => true,
        None => false,
    };
    if remove_count {
        state.listener_counts.remove(&listener_name);
    }
}

struct ConnectionLease {
    id: ConnectionId,
    registry: Weak<RegistryInner>,
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            release(&registry, self.id);
        }
    }
}

/// Accepted Unix stream whose lifetime and cancellation are registry tracked.
pub struct TrackedUnixStream {
    stream: UnixStream,
    context: ListenerConnectInfo,
    cancellation: oneshot::Receiver<()>,
    lease: ConnectionLease,
}

impl TrackedUnixStream {
    fn poll_cancelled(&mut self, cx: &mut Context<'_>) -> bool {
        Pin::new(&mut self.cancellation).poll(cx).is_ready()
    }

    fn cancelled_error() -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionAborted, "connection cancelled")
    }
}

impl Connected for TrackedUnixStream {
    type ConnectInfo = ListenerConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.context.clone()
    }
}

impl AsyncRead for TrackedUnixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.poll_cancelled(cx) {
            return Poll::Ready(Err(Self::cancelled_error()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for TrackedUnixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if self.poll_cancelled(cx) {
            return Poll::Ready(Err(Self::cancelled_error()));
        }
        Pin::new(&mut self.stream).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        if self.poll_cancelled(cx) {
            return Poll::Ready(Err(Self::cancelled_error()));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if self.poll_cancelled(cx) {
            return Poll::Ready(Err(Self::cancelled_error()));
        }
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl fmt::Debug for TrackedUnixStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrackedUnixStream")
            .field("context", &self.context)
            .field("lease_id", &self.lease.id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    fn pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().expect("Unix stream pair")
    }

    #[test]
    fn limits_must_be_nonzero_and_coherent() {
        assert!(matches!(
            ConnectionRegistry::new(0, 0),
            Err(ConnectionRegistryError::InvalidLimit)
        ));
        assert!(matches!(
            ConnectionRegistry::new(1, 2),
            Err(ConnectionRegistryError::InvalidLimit)
        ));
    }

    #[tokio::test]
    async fn capacity_is_enforced_before_tracking_and_ids_never_reuse() {
        let registry = ConnectionRegistry::new(2, 1).expect("registry");
        let (stream, _peer) = pair();
        let first = registry
            .register(stream, "host", ListenerType::Host)
            .expect("first connection");
        assert_eq!(first.context.connection_id().get(), 1);

        let (stream, _peer) = pair();
        assert!(matches!(
            registry.register(stream, "host", ListenerType::Host),
            Err(ConnectionRegistryError::ListenerLimit(name)) if name == "host"
        ));

        let (stream, _peer) = pair();
        let container = registry
            .register(stream, "container", ListenerType::Container)
            .expect("second listener fits global capacity");
        let (stream, _peer) = pair();
        assert!(matches!(
            registry.register(stream, "other", ListenerType::Container),
            Err(ConnectionRegistryError::GlobalLimit)
        ));

        drop(first);
        let (stream, _peer) = pair();
        let replacement = registry
            .register(stream, "host", ListenerType::Host)
            .expect("released capacity is reusable");
        assert_eq!(replacement.context.connection_id().get(), 3);
        assert_eq!(registry.snapshot().len(), 2);
        drop(container);
        drop(replacement);
        assert!(registry.snapshot().is_empty());
    }

    #[tokio::test]
    async fn cancellation_interrupts_io_but_inventory_waits_for_drop() {
        let registry = ConnectionRegistry::new(2, 2).expect("registry");
        let (stream, mut peer) = pair();
        let mut tracked = registry
            .register(stream, "host", ListenerType::Host)
            .expect("tracked stream");
        let context = tracked.connect_info();
        assert_eq!(context.listener_name(), "host");
        assert_eq!(context.listener_type(), ListenerType::Host);
        assert!(context.peer().uid.is_some());

        peer.write_all(b"a").await.expect("peer write");
        let mut byte = [0_u8; 1];
        tracked
            .read_exact(&mut byte)
            .await
            .expect("read before drop");
        assert_eq!(byte, [b'a']);

        assert!(registry.cancel(context.connection_id()));
        assert_eq!(registry.active_for_listener("host"), 1);
        assert!(
            registry
                .snapshot()
                .first()
                .is_some_and(ConnectionRecord::cancellation_requested)
        );
        let error = tracked
            .write_all(b"b")
            .await
            .expect_err("cancel interrupts writes");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);

        drop(tracked);
        assert_eq!(registry.active_for_listener("host"), 0);
        assert!(registry.snapshot().is_empty());
    }

    #[tokio::test]
    async fn typed_cancellation_is_atomic_deduplicated_and_excludes_caller() {
        let registry = ConnectionRegistry::new(4, 4).expect("registry");
        let mut tracked = Vec::new();
        for _ in 0..3 {
            let (stream, _peer) = pair();
            tracked.push(
                registry
                    .register(stream, "workloads", ListenerType::Container)
                    .expect("tracked connection"),
            );
        }
        let first = tracked[0].context.connection_id();
        let second = tracked[1].context.connection_id();
        let actor = AuthenticatedActor {
            domain: AuthorizationDomain::Container,
            subject: "svc.api".to_string(),
            workload_identity: Some(WorkloadIdentity::Compose {
                realm: "podman-alice".to_string(),
                project: "shop".to_string(),
                service: Some("api".to_string()),
            }),
            authenticated_by: Vec::new(),
            presenter: crate::actor::PresenterInfo::from(tracked[0].context.peer()),
            transport: crate::actor::TransportInfo::default(),
        };
        registry.record_actor(first, &actor);
        registry.record_actor(second, &actor);

        let selector = ConnectionSelector::Compose {
            realm: "podman-alice".to_string(),
            project: "shop".to_string(),
            service: Some("api".to_string()),
        };
        let outcome = registry.cancel_matching(&[selector.clone(), selector], Some(first));
        assert_eq!(
            outcome,
            ConnectionCancellation {
                matched: 2,
                cancelled: 1,
                already_requested: 0,
                caller_excluded: 1,
            }
        );
        let snapshot = registry.snapshot();
        assert!(
            snapshot
                .iter()
                .find(|record| record.context.connection_id() == second)
                .is_some_and(ConnectionRecord::cancellation_requested)
        );

        let uid = tracked[0].context.peer().uid.expect("peer uid");
        let broad = registry.cancel_matching(&[ConnectionSelector::Uid(uid)], Some(first));
        assert_eq!(broad.matched, 3);
        assert_eq!(broad.cancelled, 1);
        assert_eq!(broad.already_requested, 1);
        assert_eq!(broad.caller_excluded, 1);
    }

    #[tokio::test]
    async fn transition_gate_makes_zero_active_check_atomic_with_registration() {
        let registry = ConnectionRegistry::new(2, 2).expect("registry");
        let transition = registry
            .begin_listener_transition(["host".to_string()])
            .expect("transition gate");
        assert_eq!(transition.active_for_listener("host"), 0);

        let (stream, _peer) = pair();
        assert!(matches!(
            registry.register(stream, "host", ListenerType::Host),
            Err(ConnectionRegistryError::ListenerGated(name)) if name == "host"
        ));
        assert_eq!(transition.active_for_listener("host"), 0);
        assert_eq!(registry.active_for_listener("host"), 0);

        let committed = transition.commit(|| {
            let (stream, _peer) = pair();
            assert!(matches!(
                registry.register(stream, "host", ListenerType::Host),
                Err(ConnectionRegistryError::ListenerGated(name)) if name == "host"
            ));
            "committed"
        });
        assert_eq!(committed, "committed");
        drop(transition);
        let (stream, _peer) = pair();
        let tracked = registry
            .register(stream, "host", ListenerType::Host)
            .expect("registration resumes after transition");
        assert_eq!(registry.active_for_listener("host"), 1);
        drop(tracked);
    }
}
