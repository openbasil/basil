// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! tonic server wiring for the broker gRPC API.

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use basil_proto::broker::v1::admin_service_server::AdminServiceServer;
use basil_proto::broker::v1::aead_service_server::AeadServiceServer;
use basil_proto::broker::v1::invocation_service_server::InvocationServiceServer;
use basil_proto::broker::v1::minting_service_server::MintingServiceServer;
use basil_proto::broker::v1::nats_service_server::NatsServiceServer;
use basil_proto::broker::v1::secret_service_server::SecretServiceServer;
use basil_proto::broker::v1::signing_service_server::SigningServiceServer;
use basil_proto::envoy::service::secret::v3::secret_discovery_service_server::SecretDiscoveryServiceServer;
use basil_proto::spiffe::spiffe_workload_api_server::SpiffeWorkloadApiServer;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_stream::{StreamExt as _, wrappers::UnixListenerStream};
use tonic::transport::Server;
use tracing::{info, warn};

use crate::grpc::BrokerGrpc;
use crate::sds::EnvoySdsGrpc;
use crate::service::broker::InvocationRuntimeConfig;
use crate::spiffe::SpiffeWorkloadGrpc;
use crate::state::BrokerState;
use crate::transport::connection::ConnectionRegistry;
use crate::transport::listener::{ListenerConfig, ListenerConfigSet};
use crate::transport::listener_manager::{
    ExchangedListener, PreparedExchangedListener, PreparedListener, PreparedListenerBatch,
    PublishedListener, PublishedSocketLease, QualifiedListener,
};

/// Default Unix socket mode: owner read/write only.
pub const DEFAULT_SOCKET_MODE: u32 = 0o600;

/// Maximum number of named Unix listeners accepted from one agent config.
pub const MAX_LISTENERS: usize = 32;

/// Closed listener types compiled into the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListenerType {
    /// Host and operator surface, including the Admin service.
    Host,
    /// Container workload surface, excluding the Admin service.
    Container,
}

impl FromStr for ListenerType {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "host" => Ok(Self::Host),
            "container" => Ok(Self::Container),
            _ => Err("listener type must be `host` or `container`"),
        }
    }
}

impl std::fmt::Display for ListenerType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Host => "host",
            Self::Container => "container",
        })
    }
}

/// Every gRPC service compiled into a Basil Unix listener.
///
/// Keep this enum exhaustive and update [`ListenerType::exposes`] whenever a
/// service is added. The registry test prevents an existing service from being
/// exposed accidentally while listener builders are assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcService {
    /// Sealed invocation.
    Invocation,
    /// Signing and verification.
    Signing,
    /// Authenticated encryption.
    Aead,
    /// Secret storage and retrieval.
    Secret,
    /// Short-lived credential minting.
    Minting,
    /// NATS identity operations.
    Nats,
    /// Operator and control-plane operations.
    Admin,
    /// SPIFFE Workload API.
    SpiffeWorkload,
    /// Envoy Secret Discovery Service.
    Sds,
}

/// Exhaustive list used by service-surface validation and diagnostics.
pub const ALL_GRPC_SERVICES: [GrpcService; 9] = [
    GrpcService::Invocation,
    GrpcService::Signing,
    GrpcService::Aead,
    GrpcService::Secret,
    GrpcService::Minting,
    GrpcService::Nats,
    GrpcService::Admin,
    GrpcService::SpiffeWorkload,
    GrpcService::Sds,
];

impl ListenerType {
    /// Return whether this listener type exposes a compiled service.
    #[must_use]
    #[allow(clippy::match_same_arms)] // Repeated arms keep new services fail-closed at compile time.
    pub const fn exposes(self, service: GrpcService) -> bool {
        match (self, service) {
            (Self::Host, _) => true,
            (Self::Container, GrpcService::Admin) => false,
            (
                Self::Container,
                GrpcService::Invocation
                | GrpcService::Signing
                | GrpcService::Aead
                | GrpcService::Secret
                | GrpcService::Minting
                | GrpcService::Nats
                | GrpcService::SpiffeWorkload
                | GrpcService::Sds,
            ) => true,
        }
    }
}

/// Runtime configuration for the gRPC listener.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Stable name used for connection inventory and trusted diagnostics.
    pub listener_name: String,
    /// Closed compiled service surface exposed by this listener.
    pub listener_type: ListenerType,
    /// Broker-wide accepted-transport registry shared by every listener.
    pub connections: ConnectionRegistry,
    /// Path to bind the listening Unix socket at.
    pub socket_path: String,
    /// File mode to apply to the listening Unix socket after bind.
    pub socket_mode: u32,
    /// Group name or numeric gid to apply to the listening Unix socket.
    pub socket_group: Option<String>,
    /// Runtime settings for the sealed invocation service.
    pub invocation: InvocationRuntimeConfig,
}

/// Bind a Unix socket and serve the broker gRPC services until shutdown.
///
/// Registers all broker services, the SPIFFE Workload API, and Envoy SDS on one
/// tonic server.
pub async fn run(config: ServerConfig, state: Arc<BrokerState>) -> std::io::Result<()> {
    serve_with_shutdown(config, state, shutdown_signal()).await
}

/// Publish and serve every configured listener as one startup transaction.
///
/// Every socket is qualified, bound privately, and published before any accept
/// loop starts. If one preparation or publication fails, all sockets owned by
/// the transaction are rolled back and no listener serves traffic.
///
/// # Errors
///
/// Returns a listener preparation, publication, serving, or task failure.
pub async fn run_many(configs: Vec<ServerConfig>, state: Arc<BrokerState>) -> io::Result<()> {
    run_many_with_ready(configs, state, || {}).await
}

/// Start every listener under reload serialization, then enable reload triggers.
pub(crate) async fn run_many_with_ready(
    configs: Vec<ServerConfig>,
    state: Arc<BrokerState>,
    ready: impl FnOnce(),
) -> io::Result<()> {
    let runtime = initialize_many(configs, state, ready).await?;
    runtime.run_until_shutdown(shutdown_signal()).await
}

async fn initialize_many(
    configs: Vec<ServerConfig>,
    state: Arc<BrokerState>,
    ready: impl FnOnce(),
) -> io::Result<Arc<ListenerRuntime>> {
    let runtime = Arc::new(ListenerRuntime::prepare(configs, Arc::clone(&state))?);
    let startup_guard = state.live_reload_lock().lock().await;
    state
        .install_listener_runtime(Arc::clone(&runtime))
        .map_err(io::Error::other)?;
    runtime.activate().await?;
    ready();
    drop(startup_guard);
    Ok(runtime)
}

fn listener_config(config: &ServerConfig) -> io::Result<ListenerConfig> {
    ListenerConfig::validated(
        config.listener_name.clone(),
        config.listener_type,
        PathBuf::from(&config.socket_path),
        config.socket_mode,
        config.socket_group.clone(),
    )
    .map_err(io::Error::other)
}

async fn serve_with_shutdown(
    config: ServerConfig,
    state: Arc<BrokerState>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let listener_config = listener_config(&config)?;
    QualifiedListener::validate(&listener_config).map_err(io::Error::other)?;
    let published = PreparedListenerBatch::prepare([&listener_config])
        .and_then(PreparedListenerBatch::publish)
        .map_err(io::Error::other)?;
    let Some(published) = published.into_listeners().pop() else {
        return Err(io::Error::other("listener publication returned no socket"));
    };
    serve_published(config, state, published, shutdown).await
}

#[cfg(test)]
async fn serve_many_with_shutdown(
    configs: Vec<ServerConfig>,
    state: Arc<BrokerState>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let runtime = ListenerRuntime::start(configs, state).await?;
    runtime.run_until_shutdown(shutdown).await
}

struct RunningListener {
    config: ServerConfig,
    lease: PublishedSocketLease,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

impl RunningListener {
    fn preflight(&self) -> io::Result<()> {
        if self.task.is_finished() {
            return Err(io::Error::other(format!(
                "listener `{}` accept task is not active",
                self.config.listener_name
            )));
        }
        Ok(())
    }

    async fn stop(mut self) -> io::Result<ServerConfig> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task
            .await
            .map_err(|error| io::Error::other(format!("listener task failed: {error}")))??;
        Ok(self.config)
    }
}

struct PreparedRunningListener {
    config: ServerConfig,
    listener: tokio::net::UnixListener,
    lease: PublishedSocketLease,
}

impl PreparedRunningListener {
    fn from_published(config: ServerConfig, published: PublishedListener) -> io::Result<Self> {
        let (listener, lease) = published.into_listener().map_err(io::Error::other)?;
        Ok(Self {
            config,
            listener,
            lease,
        })
    }

    fn from_exchange(config: ServerConfig, exchange: PreparedExchangedListener) -> Self {
        let (listener, lease) = exchange.commit();
        Self {
            config,
            listener,
            lease,
        }
    }

    fn spawn(
        self,
        state: Arc<BrokerState>,
        failures: mpsc::UnboundedSender<(String, String)>,
    ) -> RunningListener {
        let Self {
            config,
            listener,
            lease,
        } = self;
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task_config = config.clone();
        let name = config.listener_name.clone();
        let task = tokio::spawn(async move {
            let result = serve_bound(task_config, state, listener, async {
                let _ = shutdown_rx.await;
            })
            .await;
            if let Err(error) = &result {
                let _ = failures.send((name, error.to_string()));
            }
            result
        });
        RunningListener {
            config,
            lease,
            shutdown: Some(shutdown),
            task,
        }
    }
}

struct ListenerRuntimeState {
    running: BTreeMap<String, RunningListener>,
    pending: Vec<(ServerConfig, PublishedListener)>,
    initialized: bool,
}

struct PreparedRuntimeTransition {
    changed: Vec<String>,
    ordinary: Vec<PreparedRunningListener>,
    exchanged: Vec<(ServerConfig, PreparedExchangedListener)>,
}

fn rollback_exchanges(exchanges: Vec<(ServerConfig, ExchangedListener)>) -> io::Result<()> {
    for (_, exchange) in exchanges.into_iter().rev() {
        exchange.rollback().map_err(io::Error::other)?;
    }
    Ok(())
}

/// Live listener accept-loop owner used by reload transitions.
pub struct ListenerRuntime {
    state: Arc<BrokerState>,
    connections: ConnectionRegistry,
    invocation: InvocationRuntimeConfig,
    inner: Mutex<ListenerRuntimeState>,
    failures: Mutex<mpsc::UnboundedReceiver<(String, String)>>,
    failure_tx: mpsc::UnboundedSender<(String, String)>,
}

impl std::fmt::Debug for ListenerRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ListenerRuntime")
            .finish_non_exhaustive()
    }
}

impl ListenerRuntime {
    fn prepare(configs: Vec<ServerConfig>, state: Arc<BrokerState>) -> io::Result<Self> {
        let Some(first) = configs.first() else {
            return Err(io::Error::other("no listeners configured"));
        };
        let connections = first.connections.clone();
        let invocation = first.invocation.clone();
        let listener_configs = configs
            .iter()
            .map(listener_config)
            .collect::<io::Result<Vec<_>>>()?;
        let published = PreparedListenerBatch::prepare(listener_configs.iter())
            .and_then(PreparedListenerBatch::publish)
            .map_err(io::Error::other)?
            .into_listeners();
        if published.len() != configs.len() {
            return Err(io::Error::other(
                "listener publication returned an incomplete batch",
            ));
        }
        let (failure_tx, failures) = mpsc::unbounded_channel();
        let mut names = std::collections::BTreeSet::new();
        let pending = configs
            .into_iter()
            .zip(published)
            .map(|(config, published)| {
                if !names.insert(config.listener_name.clone()) {
                    return Err(io::Error::other(format!(
                        "duplicate runtime listener name `{}`",
                        config.listener_name
                    )));
                }
                Ok((config, published))
            })
            .collect::<io::Result<Vec<_>>>()?;
        if pending.is_empty() {
            return Err(io::Error::other("listener publication returned no sockets"));
        }
        Ok(Self {
            state,
            connections,
            invocation,
            inner: Mutex::new(ListenerRuntimeState {
                running: BTreeMap::new(),
                pending,
                initialized: false,
            }),
            failures: Mutex::new(failures),
            failure_tx,
        })
    }

    #[cfg(test)]
    pub(crate) async fn start(
        configs: Vec<ServerConfig>,
        state: Arc<BrokerState>,
    ) -> io::Result<Self> {
        let runtime = Self::prepare(configs, state)?;
        runtime.activate().await?;
        Ok(runtime)
    }

    async fn activate(&self) -> io::Result<()> {
        let mut runtime = self.inner.lock().await;
        let pending = std::mem::take(&mut runtime.pending);
        let prepared = pending
            .into_iter()
            .map(|(config, published)| PreparedRunningListener::from_published(config, published))
            .collect::<io::Result<Vec<_>>>()?;
        for prepared in prepared {
            let name = prepared.config.listener_name.clone();
            let listener = prepared.spawn(Arc::clone(&self.state), self.failure_tx.clone());
            runtime.running.insert(name, listener);
        }
        runtime.initialized = true;
        drop(runtime);
        Ok(())
    }

    fn config_for(&self, listener: &ListenerConfig) -> ServerConfig {
        ServerConfig {
            listener_name: listener.name().to_string(),
            listener_type: listener.listener_type(),
            connections: self.connections.clone(),
            socket_path: listener.path().to_string_lossy().into_owned(),
            socket_mode: listener.mode(),
            socket_group: listener.group().map(str::to_string),
            invocation: self.invocation.clone(),
        }
    }

    /// Apply one validated listener-set transition while affected accepts are
    /// gated and disruptive listeners have zero active transports.
    pub async fn transition(
        &self,
        current: &ListenerConfigSet,
        candidate: &ListenerConfigSet,
        commit: impl FnOnce(),
    ) -> io::Result<()> {
        self.transition_with_precommit(current, candidate, || Ok(()), commit)
            .await
    }

    async fn transition_with_precommit(
        &self,
        current: &ListenerConfigSet,
        candidate: &ListenerConfigSet,
        precommit: impl FnOnce() -> io::Result<()>,
        commit: impl FnOnce(),
    ) -> io::Result<()> {
        self.transition_with_hooks(current, candidate, precommit, |_| {}, commit)
            .await
    }

    async fn transition_with_hooks(
        &self,
        current: &ListenerConfigSet,
        candidate: &ListenerConfigSet,
        precommit: impl FnOnce() -> io::Result<()>,
        postcommit: impl FnOnce(&mut ListenerRuntimeState),
        commit: impl FnOnce(),
    ) -> io::Result<()> {
        let (impacts, guard) = crate::transport::listener_manager::begin_transition(
            current,
            candidate,
            &self.connections,
        )
        .map_err(io::Error::other)?;
        let changed = impacts
            .iter()
            .map(|impact| impact.name().to_string())
            .collect::<Vec<_>>();
        let mut runtime = self.inner.lock().await;
        if !runtime.initialized {
            return Err(io::Error::other("listener runtime is not active"));
        }
        for name in &changed {
            if let Some(running) = runtime.running.get(name) {
                running.preflight()?;
            }
        }
        let mut ordinary_configs = Vec::new();
        let mut same_path = Vec::<(ServerConfig, PreparedListener)>::new();
        for listener in candidate
            .iter()
            .filter(|listener| changed.iter().any(|name| name == listener.name()))
        {
            let config = self.config_for(listener);
            match runtime.running.get(listener.name()) {
                Some(running) if running.config.socket_path == config.socket_path => {
                    let prepared =
                        QualifiedListener::validate_replacement(listener, &running.lease)
                            .and_then(QualifiedListener::prepare)
                            .map_err(io::Error::other)?;
                    same_path.push((config, prepared));
                }
                _ => ordinary_configs.push(config),
            }
        }
        let ordinary_listener_configs = ordinary_configs
            .iter()
            .map(listener_config)
            .collect::<io::Result<Vec<_>>>()?;
        let ordinary_published = PreparedListenerBatch::prepare(ordinary_listener_configs.iter())
            .and_then(PreparedListenerBatch::publish)
            .map_err(io::Error::other)?
            .into_listeners();
        let ordinary = ordinary_configs
            .into_iter()
            .zip(ordinary_published)
            .map(|(config, published)| PreparedRunningListener::from_published(config, published))
            .collect::<io::Result<Vec<_>>>()?;

        let mut exchanged = Vec::<(ServerConfig, ExchangedListener)>::new();
        for (config, prepared) in same_path {
            let Some(current) = runtime.running.get(&config.listener_name) else {
                rollback_exchanges(exchanged)?;
                return Err(io::Error::other(
                    "runtime listener disappeared during exchange",
                ));
            };
            match prepared.exchange(&current.lease) {
                Ok(exchange) => exchanged.push((config, exchange)),
                Err(error) => {
                    rollback_exchanges(exchanged)?;
                    return Err(io::Error::other(error));
                }
            }
        }
        if let Err(error) = precommit() {
            rollback_exchanges(exchanged)?;
            return Err(error);
        }
        let exchanged = exchanged
            .into_iter()
            .map(|(config, exchange)| exchange.prepare().map(|exchange| (config, exchange)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(io::Error::other)?;

        let prepared = PreparedRuntimeTransition {
            changed,
            ordinary,
            exchanged,
        };
        self.install_transition(
            &mut runtime,
            candidate,
            &guard,
            prepared,
            postcommit,
            commit,
        )
        .await;
        drop(runtime);
        drop(guard);
        Ok(())
    }

    async fn install_transition(
        &self,
        runtime: &mut ListenerRuntimeState,
        candidate: &ListenerConfigSet,
        guard: &crate::transport::connection::ListenerTransitionGuard,
        prepared: PreparedRuntimeTransition,
        postcommit: impl FnOnce(&mut ListenerRuntimeState),
        commit: impl FnOnce(),
    ) {
        guard.commit(commit);
        postcommit(runtime);
        let mut retired = Vec::new();
        for prepared in prepared.ordinary {
            let name = prepared.config.listener_name.clone();
            let replacement = prepared.spawn(Arc::clone(&self.state), self.failure_tx.clone());
            if let Some(old) = runtime.running.insert(name, replacement) {
                retired.push(old);
            }
        }
        for (config, exchange) in prepared.exchanged {
            let prepared = PreparedRunningListener::from_exchange(config.clone(), exchange);
            let replacement = prepared.spawn(Arc::clone(&self.state), self.failure_tx.clone());
            if let Some(old) = runtime
                .running
                .insert(config.listener_name.clone(), replacement)
            {
                retired.push(old);
            }
        }
        for name in prepared
            .changed
            .iter()
            .filter(|name| candidate.get(name).is_none())
        {
            if let Some(old) = runtime.running.remove(name) {
                retired.push(old);
            }
        }
        for listener in retired {
            let name = listener.config.listener_name.clone();
            if listener.stop().await.is_err() {
                warn!(
                    listener = %name,
                    "retired listener cleanup failed after applied reload"
                );
            }
        }
    }

    #[cfg(test)]
    async fn transition_with_injected_precommit_failure(
        &self,
        current: &ListenerConfigSet,
        candidate: &ListenerConfigSet,
        commit: impl FnOnce(),
    ) -> io::Result<()> {
        self.transition_with_precommit(
            current,
            candidate,
            || Err(io::Error::other("injected pre-commit failure")),
            commit,
        )
        .await
    }

    #[cfg(test)]
    async fn transition_with_injected_postcommit_task_abort(
        &self,
        current: &ListenerConfigSet,
        candidate: &ListenerConfigSet,
        listener_name: &str,
        commit: impl FnOnce(),
    ) -> io::Result<()> {
        self.transition_with_hooks(
            current,
            candidate,
            || Ok(()),
            |runtime| {
                if let Some(listener) = runtime.running.get(listener_name) {
                    listener.task.abort();
                }
            },
            commit,
        )
        .await
    }

    pub(crate) async fn run_until_shutdown(
        &self,
        shutdown: impl Future<Output = ()>,
    ) -> io::Result<()> {
        tokio::pin!(shutdown);
        let mut failures = self.failures.lock().await;
        let failure = tokio::select! {
            () = &mut shutdown => None,
            failure = failures.recv() => failure,
        };
        drop(failures);
        let mut runtime = self.inner.lock().await;
        let running = std::mem::take(&mut runtime.running);
        drop(runtime);
        let mut stop_error = None;
        for (_, listener) in running {
            if let Err(error) = listener.stop().await {
                stop_error.get_or_insert(error);
            }
        }
        match (failure, stop_error) {
            (Some((name, error)), _) => Err(io::Error::other(format!(
                "listener `{name}` terminated: {error}"
            ))),
            (None, Some(error)) => Err(error),
            (None, None) => Ok(()),
        }
    }
}

async fn serve_published(
    config: ServerConfig,
    state: Arc<BrokerState>,
    published: PublishedListener,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let (listener, _socket_lease) = published.into_listener().map_err(io::Error::other)?;
    serve_bound(config, state, listener, shutdown).await
}

async fn serve_bound(
    config: ServerConfig,
    state: Arc<BrokerState>,
    listener: tokio::net::UnixListener,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let path = config.socket_path.clone();

    info!(
        %path,
        listener_type = ?config.listener_type,
        mode = %format_socket_mode(config.socket_mode),
        group = ?config.socket_group,
        backend = state.backend_label(),
        "basil gRPC agent listening"
    );
    let listener_name: Arc<str> = Arc::from(config.listener_name);
    let listener_type = config.listener_type;
    let connections = config.connections;
    let incoming = UnixListenerStream::new(listener).filter_map(move |accepted| {
        let listener_name = Arc::clone(&listener_name);
        let connections = connections.clone();
        match accepted {
            Ok(stream) => match connections.register(stream, listener_name, listener_type) {
                Ok(stream) => Some(Ok(stream)),
                Err(error) => {
                    warn!(%error, ?listener_type, "rejected accepted connection");
                    None
                }
            },
            Err(error) => Some(Err(error)),
        }
    });
    let broker = BrokerGrpc::new_with_invocation_config(state.clone(), config.invocation);

    let server = Server::builder()
        .add_optional_service(
            listener_type
                .exposes(GrpcService::Invocation)
                .then(|| InvocationServiceServer::new(broker.clone())),
        )
        .add_optional_service(
            listener_type
                .exposes(GrpcService::Signing)
                .then(|| SigningServiceServer::new(broker.clone())),
        )
        .add_optional_service(
            listener_type
                .exposes(GrpcService::Aead)
                .then(|| AeadServiceServer::new(broker.clone())),
        )
        .add_optional_service(
            listener_type
                .exposes(GrpcService::Secret)
                .then(|| SecretServiceServer::new(broker.clone())),
        )
        .add_optional_service(
            listener_type
                .exposes(GrpcService::Minting)
                .then(|| MintingServiceServer::new(broker.clone())),
        )
        .add_optional_service(
            listener_type
                .exposes(GrpcService::Nats)
                .then(|| NatsServiceServer::new(broker.clone())),
        )
        .add_optional_service(
            listener_type
                .exposes(GrpcService::Admin)
                .then(|| AdminServiceServer::new(broker)),
        );
    let server = server
        .add_optional_service(
            listener_type
                .exposes(GrpcService::SpiffeWorkload)
                .then(|| SpiffeWorkloadApiServer::new(SpiffeWorkloadGrpc::new(state.clone()))),
        )
        .add_optional_service(
            listener_type
                .exposes(GrpcService::Sds)
                .then(|| SecretDiscoveryServiceServer::new(EnvoySdsGrpc::new(state))),
        );
    let result = server
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await;

    result.map_err(std::io::Error::other)
}

pub(crate) fn resolve_group(group: &str) -> io::Result<u32> {
    if let Ok(gid) = group.parse::<u32>() {
        return Ok(gid);
    }
    resolve_group_from(group, "/etc/group")
}

fn resolve_group_from(group: &str, group_file: impl AsRef<Path>) -> io::Result<u32> {
    let body = std::fs::read_to_string(group_file)?;
    for line in body.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next() else {
            continue;
        };
        if name != group {
            continue;
        }
        let _passwd = fields.next();
        let Some(gid) = fields.next() else {
            break;
        };
        return gid.parse::<u32>().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("group `{group}` has invalid gid `{gid}`: {err}"),
            )
        });
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("group `{group}` not found"),
    ))
}

fn format_socket_mode(mode: u32) -> String {
    format!("{mode:04o}")
}

async fn shutdown_signal() {
    let mut int = signal(SignalKind::interrupt()).ok();
    let mut quit = signal(SignalKind::quit()).ok();
    let mut term = signal(SignalKind::terminate()).ok();

    tokio::select! {
        () = async {
            if let Some(sig) = int.as_mut() {
                sig.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
        () = async {
            if let Some(sig) = quit.as_mut() {
                sig.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
        () = async {
            if let Some(sig) = term.as_mut() {
                sig.recv().await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
    }
}

#[cfg(test)]
#[allow(clippy::significant_drop_tightening)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use basil::Client;
    use basil_proto::KeyType;
    use basil_proto::broker::v1::SealedRequest;
    use basil_proto::broker::v1::StatusRequest;
    use basil_proto::broker::v1::admin_service_client::AdminServiceClient;
    use basil_proto::broker::v1::invocation_service_client::InvocationServiceClient;
    use basil_proto::envoy::service::discovery::v3::DiscoveryRequest;
    use basil_proto::envoy::service::secret::v3::secret_discovery_service_client::SecretDiscoveryServiceClient;
    use basil_proto::spiffe::X509BundlesRequest;
    use basil_proto::spiffe::spiffe_workload_api_client::SpiffeWorkloadApiClient;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;
    use tokio::sync::oneshot;
    use tonic::Code;
    use tonic::Request;
    use tonic::metadata::MetadataValue;
    use tonic::transport::{Channel, Endpoint, Uri};
    use tower::service_fn;

    use super::*;
    use crate::backend::{Backend, BackendError, NewKey};
    use crate::catalog::load;
    use crate::manager::BackendManager;
    use crate::transport::listener::{LegacyListenerConfig, ListenerConfigInput};

    #[test]
    fn listener_service_registry_is_closed_and_admin_is_host_only() {
        for service in ALL_GRPC_SERVICES {
            assert!(ListenerType::Host.exposes(service));
            assert_eq!(
                ListenerType::Container.exposes(service),
                service != GrpcService::Admin
            );
        }
    }

    #[test]
    fn listener_type_parser_rejects_unknown_and_ambiguous_values() {
        assert_eq!("host".parse(), Ok(ListenerType::Host));
        assert_eq!("container".parse(), Ok(ListenerType::Container));
        assert!("Host".parse::<ListenerType>().is_err());
        assert!("workload".parse::<ListenerType>().is_err());
        assert!("".parse::<ListenerType>().is_err());
    }

    struct DummyBackend;

    #[async_trait]
    impl Backend for DummyBackend {
        fn kind(&self) -> &'static str {
            "dummy"
        }

        async fn new_key(&self, key_type: KeyType) -> Result<NewKey, BackendError> {
            let _ = key_type;
            Err(BackendError::Unsupported("new_key"))
        }

        async fn public_key(&self, key_id: &str) -> Result<Vec<u8>, BackendError> {
            let _ = key_id;
            Err(BackendError::Unsupported("public_key"))
        }

        async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
            let _ = (key_id, message);
            Err(BackendError::Unsupported("sign"))
        }

        async fn verify(
            &self,
            key_id: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, BackendError> {
            let _ = (key_id, message, signature);
            Err(BackendError::Unsupported("verify"))
        }
    }

    fn state() -> Arc<BrokerState> {
        let catalog = r#"{
          "schema": "catalog",
          "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
          "keys": {}
        }"#;
        // These tests exercise transport wiring over a real UDS, so the peer uid
        // the kernel reports is this test process's own; register it as a policy
        // subject so the `status` canary RPC (which requires a resolved subject)
        // answers.
        let uid = rustix::process::getuid().as_raw();
        let policy = format!(
            r#"{{
              "schema": "policy",
              "subjects": {{ "test.peer": {{ "domain": "host-process", "match": {{ "all": [ {{ "process.uid": {uid} }} ] }} }} }},
              "roles": {{}},
              "rules": [],
              "config": {{
                "names": {{ "users": {{ "{uid}": "test-peer" }}, "groups": {{}} }},
                "memberships": {{ "{uid}": [{uid}] }}
              }}
            }}"#
        );
        let (catalog, policy, config, warnings) = load(catalog, &policy).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".to_string(), Box::new(DummyBackend));
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        Arc::new(BrokerState::new(catalog, policy, config, manager, "dummy"))
    }

    async fn spawn_server(socket: PathBuf) -> oneshot::Sender<()> {
        spawn_server_with_type(socket, ListenerType::Host).await
    }

    async fn spawn_server_with_type(
        socket: PathBuf,
        listener_type: ListenerType,
    ) -> oneshot::Sender<()> {
        let (tx, rx) = oneshot::channel();
        let config = test_server_config(
            "test",
            &socket,
            listener_type,
            ConnectionRegistry::with_defaults(),
        );
        tokio::spawn(async move {
            serve_with_shutdown(config, state(), async {
                let _ = rx.await;
            })
            .await
            .expect("server exits cleanly");
        });
        wait_for_socket(&socket).await;
        tx
    }

    fn test_server_config(
        name: &str,
        socket: &Path,
        listener_type: ListenerType,
        connections: ConnectionRegistry,
    ) -> ServerConfig {
        ServerConfig {
            listener_name: name.to_string(),
            listener_type,
            connections,
            socket_path: socket.to_string_lossy().into_owned(),
            socket_mode: DEFAULT_SOCKET_MODE,
            socket_group: None,
            invocation: InvocationRuntimeConfig::default(),
        }
    }

    fn listener_set(
        listeners: impl IntoIterator<Item = (&'static str, ListenerType, PathBuf)>,
    ) -> ListenerConfigSet {
        let named = listeners
            .into_iter()
            .map(|(name, listener_type, path)| {
                (
                    name.to_string(),
                    ListenerConfigInput {
                        listener_type,
                        path,
                        mode: None,
                        group: None,
                    },
                )
            })
            .collect();
        ListenerConfigSet::resolve(named, LegacyListenerConfig::default())
            .expect("listener set validates")
    }

    fn single_host_listener_set(name: &str, path: PathBuf, mode: u32) -> ListenerConfigSet {
        ListenerConfigSet::resolve(
            BTreeMap::from([(
                name.to_string(),
                ListenerConfigInput {
                    listener_type: ListenerType::Host,
                    path,
                    mode: Some(mode),
                    group: None,
                },
            )]),
            LegacyListenerConfig::default(),
        )
        .expect("single host listener validates")
    }

    async fn wait_for_socket(socket: &Path) {
        for _ in 0..100 {
            if socket.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("server socket did not appear: {}", socket.display());
    }

    fn socket_path(name: &str) -> PathBuf {
        // Unix-domain socket paths must fit in sun_path: 104 bytes on macOS, 108
        // on Linux. macOS's std::env::temp_dir() (/var/folders/...) is long enough
        // that "basil-{name}-{uuid}.sock" overflowed the macOS limit; anchor at the
        // short, always-writable /tmp so the full path stays well under it.
        let directory = PathBuf::from("/tmp").join(format!("b-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).expect("trusted socket parent");
        directory.join(format!("{name}.sock"))
    }

    #[test]
    fn concurrent_socket_binds_publish_privately_without_clobbering() {
        const BIND_COUNT: usize = 16;

        let barrier = Arc::new(std::sync::Barrier::new(BIND_COUNT));
        let results = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..BIND_COUNT {
                let barrier = Arc::clone(&barrier);
                handles.push(scope.spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .build()
                        .expect("test runtime");
                    let _runtime_guard = runtime.enter();
                    let socket = socket_path("umask-race");
                    barrier.wait();
                    let config = ListenerConfig::validated(
                        "host".to_string(),
                        ListenerType::Host,
                        socket.clone(),
                        DEFAULT_SOCKET_MODE,
                        None,
                    )
                    .map_err(io::Error::other)?;
                    let published = PreparedListenerBatch::prepare([&config])
                        .and_then(PreparedListenerBatch::publish)
                        .map_err(io::Error::other)?;
                    let published = published.into_listeners().pop().ok_or_else(|| {
                        io::Error::other("listener publication returned no socket")
                    })?;
                    let (listener, lease) = published.into_listener().map_err(io::Error::other)?;
                    Ok::<_, io::Error>((socket, listener, lease))
                }));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().expect("bind thread does not panic"))
                .collect::<Vec<_>>()
        });
        for result in results {
            let (socket, listener, lease) = result.expect("concurrent bind succeeds");
            let mode = std::fs::metadata(&socket)
                .expect("socket metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "socket must be owner-only at publication");
            drop(listener);
            drop(lease);
            assert!(!socket.exists());
            std::fs::remove_dir(socket.parent().expect("socket parent"))
                .expect("remove socket parent");
        }
    }

    #[test]
    fn group_resolution_accepts_numeric_gid_and_group_file_name() {
        assert_eq!(resolve_group("4242").expect("numeric gid"), 4242);
        let path = std::env::temp_dir().join(format!(
            "basil-group-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, "root:x:0:\nbasil-edge:x:9876:edge\n").expect("write group fixture");
        assert_eq!(
            resolve_group_from("basil-edge", &path).expect("named group"),
            9876
        );
        let err = resolve_group_from("missing", &path).expect_err("missing group");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        std::fs::remove_file(path).expect("remove group fixture");
    }

    #[tokio::test]
    async fn configured_socket_mode_is_applied_before_serving() {
        let socket = socket_path("mode");
        let (tx, rx) = oneshot::channel();
        let config = ServerConfig {
            listener_name: "test".to_string(),
            listener_type: ListenerType::Host,
            connections: ConnectionRegistry::with_defaults(),
            socket_path: socket.to_string_lossy().into_owned(),
            socket_mode: 0o660,
            socket_group: None,
            invocation: InvocationRuntimeConfig::default(),
        };
        tokio::spawn(async move {
            serve_with_shutdown(config, state(), async {
                let _ = rx.await;
            })
            .await
            .expect("server exits cleanly");
        });
        wait_for_socket(&socket).await;
        let mode = std::fs::metadata(&socket)
            .expect("stat socket")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o660);
        let _ = tx.send(());
    }

    #[test]
    fn active_runtime_sources_have_no_legacy_json_wire_symbols() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let banned = [
            ["json", "_codec"].concat(),
            ["Client", "Request"].concat(),
            ["Client", "Response"].concat(),
            ["core", "::", "handler"].concat(),
            ["core", "::", "server"].concat(),
        ];
        let mut stack = vec![src];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path).expect("source directory readable") {
                let entry = entry.expect("source entry readable");
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("source file readable");
                for needle in &banned {
                    assert!(
                        !source.contains(needle),
                        "legacy JSON wire symbol `{needle}` remains in {}",
                        path.display()
                    );
                }
            }
        }
    }

    async fn uds_channel(path: &Path) -> Channel {
        let path = path.to_path_buf();
        Endpoint::try_from("http://[::]:50051")
            .expect("endpoint")
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = path.clone();
                async move { UnixStream::connect(path).await.map(TokioIo::new) }
            }))
            .await
            .expect("connect")
    }

    #[tokio::test]
    async fn broker_grpc_serves_status_on_unix_socket() {
        let socket = socket_path("broker-only");
        let shutdown = spawn_server(socket.clone()).await;
        {
            let mut client = Client::connect(socket.to_str().expect("utf8 path"))
                .await
                .expect("broker client connects");
            let status = client.status().await.expect("status");
            assert_eq!(status.backend, "dummy");
            assert_eq!(status.protocol, 1);
        }
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn invocation_service_is_registered_but_disabled_by_default() {
        let socket = socket_path("invocation-disabled");
        let shutdown = spawn_server(socket.clone()).await;

        let channel = uds_channel(&socket).await;
        let mut invocation = InvocationServiceClient::new(channel);
        let status = invocation
            .invoke(SealedRequest::default())
            .await
            .expect_err("invocation is disabled by default");
        assert_eq!(status.code(), Code::FailedPrecondition);

        let mut broker = Client::connect(socket.to_str().expect("utf8 path"))
            .await
            .expect("broker client still connects");
        let status = broker
            .status()
            .await
            .expect("typed status remains available");
        assert_eq!(status.protocol, 1);

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn container_listener_omits_admin_but_retains_workload_services() {
        let socket = socket_path("container-surface");
        let shutdown = spawn_server_with_type(socket.clone(), ListenerType::Container).await;
        let channel = uds_channel(&socket).await;

        let mut admin = AdminServiceClient::new(channel.clone());
        let status = admin
            .status(StatusRequest {
                include_realms: false,
            })
            .await
            .expect_err("Admin must be absent from a container listener");
        assert_eq!(status.code(), Code::Unimplemented);

        let mut invocation = InvocationServiceClient::new(channel.clone());
        let status = invocation
            .invoke(SealedRequest::default())
            .await
            .expect_err("invocation remains present but disabled by default");
        assert_eq!(status.code(), Code::FailedPrecondition);

        let mut spiffe = SpiffeWorkloadApiClient::new(channel);
        let status = spiffe
            .fetch_x509_bundles(X509BundlesRequest {})
            .await
            .expect_err("SPIFFE remains present and validates its header");
        assert_eq!(status.code(), Code::InvalidArgument);

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn configured_host_and_container_listeners_serve_together() {
        let host_socket = socket_path("multi-host");
        let container_socket = socket_path("multi-container");
        let connections = ConnectionRegistry::with_defaults();
        let configs = vec![
            test_server_config(
                "control",
                &host_socket,
                ListenerType::Host,
                connections.clone(),
            ),
            test_server_config(
                "workloads",
                &container_socket,
                ListenerType::Container,
                connections,
            ),
        ];
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            serve_many_with_shutdown(configs, state(), async {
                let _ = shutdown_rx.await;
            })
            .await
        });
        wait_for_socket(&host_socket).await;
        wait_for_socket(&container_socket).await;

        let mut host_admin = AdminServiceClient::new(uds_channel(&host_socket).await);
        let status = host_admin
            .status(StatusRequest {
                include_realms: false,
            })
            .await
            .expect("host listener exposes Admin")
            .into_inner();
        assert_eq!(status.backend, "dummy");

        let mut container_admin = AdminServiceClient::new(uds_channel(&container_socket).await);
        let status = container_admin
            .status(StatusRequest {
                include_realms: false,
            })
            .await
            .expect_err("container listener omits Admin");
        assert_eq!(status.code(), Code::Unimplemented);

        let _ = shutdown_tx.send(());
        server
            .await
            .expect("multi-listener task does not panic")
            .expect("multi-listener server exits cleanly");
        assert!(!host_socket.exists());
        assert!(!container_socket.exists());
    }

    #[tokio::test]
    async fn multi_listener_publication_rolls_back_the_complete_batch() {
        let first_socket = socket_path("rollback-first");
        let occupied_socket = socket_path("rollback-occupied");
        std::fs::write(&occupied_socket, "occupied").expect("occupy second listener path");
        let connections = ConnectionRegistry::with_defaults();
        let configs = vec![
            test_server_config(
                "first",
                &first_socket,
                ListenerType::Host,
                connections.clone(),
            ),
            test_server_config(
                "occupied",
                &occupied_socket,
                ListenerType::Container,
                connections,
            ),
        ];

        let error = serve_many_with_shutdown(configs, state(), std::future::pending())
            .await
            .expect_err("occupied path rejects the startup transaction");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(!first_socket.exists());
        assert_eq!(
            std::fs::read_to_string(&occupied_socket).expect("foreign path remains"),
            "occupied"
        );
        std::fs::remove_file(occupied_socket).expect("remove occupied fixture");
    }

    #[tokio::test]
    async fn startup_enables_reload_only_after_runtime_activation_under_lock() {
        let socket = socket_path("startup-reload-order");
        let state = state();
        let hook_state = Arc::clone(&state);
        let hook_socket = socket.clone();
        let observed = Arc::new(AtomicBool::new(false));
        let hook_observed = Arc::clone(&observed);
        let runtime = initialize_many(
            vec![test_server_config(
                "control",
                &socket,
                ListenerType::Host,
                ConnectionRegistry::with_defaults(),
            )],
            state,
            move || {
                let runtime = hook_state
                    .listener_runtime()
                    .expect("runtime installed before reload hook");
                let inner = runtime
                    .inner
                    .try_lock()
                    .expect("activation released the runtime lock");
                assert!(inner.initialized);
                assert_eq!(inner.running.len(), 1);
                assert!(hook_state.live_reload_lock().try_lock().is_err());
                assert!(hook_socket.exists());
                hook_observed.store(true, Ordering::SeqCst);
            },
        )
        .await
        .expect("startup transaction succeeds");
        assert!(observed.load(Ordering::SeqCst));
        let mut admin = AdminServiceClient::new(uds_channel(&socket).await);
        admin
            .status(StatusRequest {
                include_realms: false,
            })
            .await
            .expect("activated listener serves before reload hook returns");
        drop(admin);
        runtime
            .run_until_shutdown(std::future::ready(()))
            .await
            .expect("runtime shuts down");
    }

    #[tokio::test]
    async fn live_runtime_adds_reconfigures_and_removes_accept_loops() {
        let host_socket = socket_path("runtime-host");
        let first_container = socket_path("runtime-container-a");
        let second_container = socket_path("runtime-container-b");
        let connections = ConnectionRegistry::with_defaults();
        let runtime = ListenerRuntime::start(
            vec![test_server_config(
                "control",
                &host_socket,
                ListenerType::Host,
                connections.clone(),
            )],
            state(),
        )
        .await
        .expect("runtime starts");
        wait_for_socket(&host_socket).await;
        let initial = listener_set([("control", ListenerType::Host, host_socket.clone())]);
        let added = listener_set([
            ("control", ListenerType::Host, host_socket.clone()),
            (
                "workloads",
                ListenerType::Container,
                first_container.clone(),
            ),
        ]);
        let committed = Arc::new(AtomicBool::new(false));
        let commit_flag = Arc::clone(&committed);
        runtime
            .transition(&initial, &added, move || {
                commit_flag.store(true, Ordering::SeqCst);
            })
            .await
            .expect("hot add succeeds");
        assert!(committed.load(Ordering::SeqCst));
        wait_for_socket(&first_container).await;
        let mut container_admin = AdminServiceClient::new(uds_channel(&first_container).await);
        assert_eq!(
            container_admin
                .status(StatusRequest {
                    include_realms: false,
                })
                .await
                .expect_err("container Admin remains absent")
                .code(),
            Code::Unimplemented
        );
        drop(container_admin);
        for _ in 0..100 {
            if connections.active_for_listener("workloads") == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(connections.active_for_listener("workloads"), 0);

        let reconfigured = listener_set([
            ("control", ListenerType::Host, host_socket.clone()),
            (
                "workloads",
                ListenerType::Container,
                second_container.clone(),
            ),
        ]);
        runtime
            .transition(&added, &reconfigured, || {})
            .await
            .expect("zero-active reconfigure succeeds");
        assert!(!first_container.exists());
        wait_for_socket(&second_container).await;

        runtime
            .transition(&reconfigured, &initial, || {})
            .await
            .expect("zero-active removal succeeds");
        assert!(!second_container.exists());
        let mut host_admin = AdminServiceClient::new(uds_channel(&host_socket).await);
        host_admin
            .status(StatusRequest {
                include_realms: false,
            })
            .await
            .expect("unchanged host listener keeps serving");
        runtime
            .run_until_shutdown(std::future::ready(()))
            .await
            .expect("runtime shuts down");
    }

    #[tokio::test]
    async fn live_runtime_rejects_occupied_new_path_without_disturbing_old_listener() {
        let original_socket = socket_path("runtime-rollback-original");
        let occupied_socket = socket_path("runtime-rollback-occupied");
        std::fs::write(&occupied_socket, "foreign").expect("occupy candidate path");
        let connections = ConnectionRegistry::with_defaults();
        let runtime = ListenerRuntime::start(
            vec![test_server_config(
                "control",
                &original_socket,
                ListenerType::Host,
                connections,
            )],
            state(),
        )
        .await
        .expect("runtime starts");
        wait_for_socket(&original_socket).await;
        let initial = listener_set([("control", ListenerType::Host, original_socket.clone())]);
        let rejected = listener_set([("control", ListenerType::Host, occupied_socket.clone())]);
        let committed = AtomicBool::new(false);

        runtime
            .transition(&initial, &rejected, || {
                committed.store(true, Ordering::SeqCst);
            })
            .await
            .expect_err("occupied replacement fails");
        assert!(!committed.load(Ordering::SeqCst));
        wait_for_socket(&original_socket).await;
        let mut host_admin = AdminServiceClient::new(uds_channel(&original_socket).await);
        host_admin
            .status(StatusRequest {
                include_realms: false,
            })
            .await
            .expect("rolled-back listener serves again");
        assert_eq!(
            std::fs::read_to_string(&occupied_socket).expect("foreign path remains"),
            "foreign"
        );
        runtime
            .run_until_shutdown(std::future::ready(()))
            .await
            .expect("runtime shuts down");
        std::fs::remove_file(occupied_socket).expect("remove occupied fixture");
    }

    #[tokio::test]
    async fn live_runtime_exchanges_back_after_post_exchange_precommit_failure() {
        let socket = socket_path("runtime-exchange-rollback");
        let connections = ConnectionRegistry::with_defaults();
        let runtime = ListenerRuntime::start(
            vec![test_server_config(
                "control",
                &socket,
                ListenerType::Host,
                connections,
            )],
            state(),
        )
        .await
        .expect("runtime starts");
        wait_for_socket(&socket).await;
        let old_inode = std::fs::metadata(&socket)
            .expect("old socket metadata")
            .ino();
        let initial = single_host_listener_set("control", socket.clone(), 0o600);
        let replacement = single_host_listener_set("control", socket.clone(), 0o660);
        let committed = AtomicBool::new(false);

        runtime
            .transition_with_injected_precommit_failure(&initial, &replacement, || {
                committed.store(true, Ordering::SeqCst);
            })
            .await
            .expect_err("injected pre-commit failure rolls exchange back");

        assert!(!committed.load(Ordering::SeqCst));
        let metadata = std::fs::metadata(&socket).expect("old path restored");
        assert_eq!(metadata.ino(), old_inode);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let mut host_admin = AdminServiceClient::new(uds_channel(&socket).await);
        host_admin
            .status(StatusRequest {
                include_realms: false,
            })
            .await
            .expect("old listener keeps serving after exchange-back");
        drop(host_admin);
        runtime
            .run_until_shutdown(std::future::ready(()))
            .await
            .expect("runtime shuts down");
    }

    #[tokio::test]
    async fn live_runtime_reports_applied_after_postcommit_old_task_failure() {
        let socket = socket_path("runtime-postcommit-task-failure");
        let runtime = ListenerRuntime::start(
            vec![test_server_config(
                "control",
                &socket,
                ListenerType::Host,
                ConnectionRegistry::with_defaults(),
            )],
            state(),
        )
        .await
        .expect("runtime starts");
        wait_for_socket(&socket).await;
        let initial = single_host_listener_set("control", socket.clone(), 0o600);
        let replacement = single_host_listener_set("control", socket.clone(), 0o660);
        let committed = AtomicBool::new(false);

        runtime
            .transition_with_injected_postcommit_task_abort(
                &initial,
                &replacement,
                "control",
                || committed.store(true, Ordering::SeqCst),
            )
            .await
            .expect("postcommit retire failure cannot reject an applied generation");
        assert!(committed.load(Ordering::SeqCst));
        assert_eq!(
            std::fs::metadata(&socket)
                .expect("replacement metadata")
                .permissions()
                .mode()
                & 0o777,
            0o660
        );
        let mut admin = AdminServiceClient::new(uds_channel(&socket).await);
        admin
            .status(StatusRequest {
                include_realms: false,
            })
            .await
            .expect("replacement listener serves after applied outcome");
        drop(admin);
        runtime
            .run_until_shutdown(std::future::ready(()))
            .await
            .expect("runtime shuts down");
    }

    #[tokio::test]
    async fn live_runtime_preserves_foreign_inode_during_exchange_rollback() {
        let socket = socket_path("runtime-foreign-rollback");
        let runtime = ListenerRuntime::start(
            vec![test_server_config(
                "control",
                &socket,
                ListenerType::Host,
                ConnectionRegistry::with_defaults(),
            )],
            state(),
        )
        .await
        .expect("runtime starts");
        wait_for_socket(&socket).await;
        let initial = single_host_listener_set("control", socket.clone(), 0o600);
        let replacement = single_host_listener_set("control", socket.clone(), 0o660);
        let hook_socket = socket.clone();
        let committed = AtomicBool::new(false);

        runtime
            .transition_with_precommit(
                &initial,
                &replacement,
                move || {
                    std::fs::remove_file(&hook_socket).expect("remove exchanged candidate");
                    std::fs::write(&hook_socket, "foreign").expect("install foreign inode");
                    Err(io::Error::other("injected precommit failure"))
                },
                || committed.store(true, Ordering::SeqCst),
            )
            .await
            .expect_err("foreign substitution rejects the transition");
        assert!(!committed.load(Ordering::SeqCst));
        assert_eq!(
            std::fs::read_to_string(&socket).expect("foreign final inode remains"),
            "foreign"
        );
        runtime
            .run_until_shutdown(std::future::ready(()))
            .await
            .expect("runtime shuts down");
        assert_eq!(
            std::fs::read_to_string(&socket).expect("shutdown preserves foreign inode"),
            "foreign"
        );
        std::fs::remove_file(socket).expect("remove foreign fixture");
    }

    #[tokio::test]
    async fn live_runtime_preserves_foreign_inode_replacing_expected_socket() {
        let socket = socket_path("runtime-foreign-replacement");
        let connections = ConnectionRegistry::with_defaults();
        let runtime = ListenerRuntime::start(
            vec![test_server_config(
                "control",
                &socket,
                ListenerType::Host,
                connections,
            )],
            state(),
        )
        .await
        .expect("runtime starts");
        wait_for_socket(&socket).await;
        let initial = single_host_listener_set("control", socket.clone(), 0o600);
        let replacement = single_host_listener_set("control", socket.clone(), 0o660);
        std::fs::remove_file(&socket).expect("unlink expected socket inode");
        std::fs::write(&socket, "foreign").expect("install foreign inode");
        let foreign_inode = std::fs::metadata(&socket).expect("foreign metadata").ino();
        let committed = AtomicBool::new(false);

        runtime
            .transition(&initial, &replacement, || {
                committed.store(true, Ordering::SeqCst);
            })
            .await
            .expect_err("foreign replacement rejects exchange");
        assert!(!committed.load(Ordering::SeqCst));
        assert_eq!(
            std::fs::metadata(&socket)
                .expect("foreign inode remains")
                .ino(),
            foreign_inode
        );
        assert_eq!(
            std::fs::read_to_string(&socket).expect("foreign contents remain"),
            "foreign"
        );
        runtime
            .run_until_shutdown(std::future::ready(()))
            .await
            .expect("runtime shuts down");
        assert_eq!(
            std::fs::read_to_string(&socket).expect("shutdown preserves foreign inode"),
            "foreign"
        );
        std::fs::remove_file(socket).expect("remove foreign fixture");
    }

    #[tokio::test]
    async fn broker_and_spiffe_services_share_one_unix_socket() {
        let socket = socket_path("broker-spiffe");
        let shutdown = spawn_server(socket.clone()).await;

        {
            let mut broker = Client::connect(socket.to_str().expect("utf8 path"))
                .await
                .expect("broker client connects");
            let status = broker.status().await.expect("status");
            assert_eq!(status.backend, "dummy");
            assert_eq!(status.protocol, 1);
        }

        {
            let channel = uds_channel(&socket).await;
            let mut broker = AdminServiceClient::new(channel.clone());
            let mut request = Request::new(StatusRequest {
                include_realms: false,
            });
            request
                .metadata_mut()
                .insert("workload.spiffe.io", "true".parse().expect("metadata"));
            let status = broker
                .status(request)
                .await
                .expect("broker RPC ignores Workload API metadata")
                .into_inner();
            assert_eq!(status.backend, "dummy");
            assert_eq!(status.protocol, 1);
        }

        {
            let channel = uds_channel(&socket).await;
            let mut spiffe = SpiffeWorkloadApiClient::new(channel);
            let status = spiffe
                .fetch_x509_bundles(X509BundlesRequest {})
                .await
                .expect_err("registered SPIFFE service rejects missing workload header");
            assert_eq!(status.code(), Code::InvalidArgument);
            assert_eq!(
                status.message(),
                "SPIFFE Workload API requests require workload.spiffe.io=true"
            );
        }

        {
            let channel = uds_channel(&socket).await;
            let mut spiffe = SpiffeWorkloadApiClient::new(channel);
            let mut request = Request::new(X509BundlesRequest {});
            request
                .metadata_mut()
                .append("workload.spiffe.io", "true".parse().expect("metadata"));
            request
                .metadata_mut()
                .append("workload.spiffe.io", "false".parse().expect("metadata"));
            let status = spiffe
                .fetch_x509_bundles(request)
                .await
                .expect_err("duplicate Workload API metadata is fail-closed");
            assert_eq!(status.code(), Code::InvalidArgument);
        }

        {
            let channel = uds_channel(&socket).await;
            let mut spiffe = SpiffeWorkloadApiClient::new(channel);
            let mut request = Request::new(X509BundlesRequest {});
            request
                .metadata_mut()
                .insert_bin("workload.spiffe.io-bin", MetadataValue::from_bytes(b"true"));
            let status = spiffe
                .fetch_x509_bundles(request)
                .await
                .expect_err("binary Workload API metadata is fail-closed");
            assert_eq!(status.code(), Code::InvalidArgument);
        }

        {
            let channel = uds_channel(&socket).await;
            let mut sds = SecretDiscoveryServiceClient::new(channel);
            let status = sds
                .fetch_secrets(DiscoveryRequest {
                    version_info: String::new(),
                    node: None,
                    resource_names: vec!["default".to_string()],
                    type_url: crate::sds::SECRET_TYPE_URL.to_string(),
                    response_nonce: String::new(),
                    error_detail: None,
                })
                .await
                .expect_err("registered SDS service has no configured resources");
            assert_eq!(status.code(), Code::NotFound);
        }
        let _ = shutdown.send(());
    }
}
