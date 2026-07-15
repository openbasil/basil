// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! tonic server wiring for the broker gRPC API.

use std::future::Future;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
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
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::{info, warn};

use crate::grpc::BrokerGrpc;
use crate::sds::EnvoySdsGrpc;
use crate::service::broker::InvocationRuntimeConfig;
use crate::spiffe::SpiffeWorkloadGrpc;
use crate::state::BrokerState;

/// Default Unix socket mode: owner read/write only.
pub const DEFAULT_SOCKET_MODE: u32 = 0o600;

/// Runtime configuration for the gRPC listener.
#[derive(Debug, Clone)]
pub struct ServerConfig {
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

async fn serve_with_shutdown(
    config: ServerConfig,
    state: Arc<BrokerState>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let path = config.socket_path;
    if Path::new(&path).exists() {
        std::fs::remove_file(&path)?;
        warn!(%path, "removed stale socket");
    }

    let listener = bind_restricted(&path)?;
    apply_socket_permissions(&path, config.socket_mode, config.socket_group.as_deref())?;

    info!(
        %path,
        mode = %format_socket_mode(config.socket_mode),
        group = ?config.socket_group,
        backend = state.backend_label(),
        "basil gRPC agent listening"
    );
    let incoming = UnixListenerStream::new(listener);
    let broker = BrokerGrpc::new_with_invocation_config(state.clone(), config.invocation);

    let server = Server::builder()
        .add_service(InvocationServiceServer::new(broker.clone()))
        .add_service(SigningServiceServer::new(broker.clone()))
        .add_service(AeadServiceServer::new(broker.clone()))
        .add_service(SecretServiceServer::new(broker.clone()))
        .add_service(MintingServiceServer::new(broker.clone()))
        .add_service(NatsServiceServer::new(broker.clone()))
        .add_service(AdminServiceServer::new(broker));
    let server = server
        .add_service(SpiffeWorkloadApiServer::new(SpiffeWorkloadGrpc::new(
            state.clone(),
        )))
        .add_service(SecretDiscoveryServiceServer::new(EnvoySdsGrpc::new(state)));
    let result = server
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await;

    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(?e, %path, "could not remove socket on shutdown");
    }

    result.map_err(std::io::Error::other)
}

/// Bind the listening Unix socket with the process umask tightened to `0o177`,
/// so the socket node is created owner-only no matter how loose the inherited
/// umask is. The listen backlog is live from `bind`, so the mode must be
/// restrictive *at creation*; the later [`apply_socket_permissions`] can only
/// widen it to the configured mode/group (never leaves a permissive window).
fn bind_restricted(path: &str) -> io::Result<UnixListener> {
    let inherited = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o177));
    let listener = UnixListener::bind(path);
    rustix::process::umask(inherited);
    listener
}

fn apply_socket_permissions(path: &str, mode: u32, group: Option<&str>) -> io::Result<()> {
    if let Some(group) = group {
        let gid = resolve_group(group)?;
        std::os::unix::fs::chown(path, None, Some(gid))?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

fn resolve_group(group: &str) -> io::Result<u32> {
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
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
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
              "subjects": {{ "test.peer": {{ "allOf": [ {{ "kind": "unix", "uid": {uid} }} ] }} }},
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
        let (tx, rx) = oneshot::channel();
        let config = ServerConfig {
            socket_path: socket.to_string_lossy().into_owned(),
            socket_mode: DEFAULT_SOCKET_MODE,
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
        tx
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
        PathBuf::from("/tmp").join(format!("basil-{name}-{}.sock", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn socket_is_owner_only_at_bind_even_under_a_loose_umask() {
        // Loosen the process umask: without the tightened bind the socket node
        // would be group/world-accessible for the instant before the explicit
        // chmod, with the listen backlog already live.
        let inherited = rustix::process::umask(rustix::fs::Mode::empty());
        let socket = socket_path("umask");
        let listener = bind_restricted(&socket.to_string_lossy()).expect("binds");
        rustix::process::umask(inherited);

        let mode = std::fs::metadata(&socket)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "socket must be owner-only at bind");
        drop(listener);
        let _ = std::fs::remove_file(&socket);
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
            let mut request = Request::new(StatusRequest {});
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
