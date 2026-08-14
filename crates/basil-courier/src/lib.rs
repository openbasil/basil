// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Hardened local transport shared by Basil invocation couriers.
//!
//! This leaf crate deliberately exposes only the invocation courier surface.
//! It validates a Unix socket from trusted directory descriptors on every
//! connection and verifies the broker's closed courier capability profile
//! before every forwarded call.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use basil_proto::broker::v1::invocation_service_client::InvocationServiceClient;
use basil_proto::broker::v1::{
    GetInvocationCapabilitiesRequest, GetInvocationChallengeRequest,
    GetInvocationChallengeResponse, ListenerProfile, SealedRequest, SealedResponse,
};
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Status};
use tower::service_fn;

/// Frozen local courier protocol version.
pub const COURIER_PROTOCOL_VERSION: u32 = 1;
/// Maximum trusted-courier source partition length.
pub const MAX_COURIER_SOURCE_BYTES: usize = 128;
/// Maximum raw sealed invocation bytes accepted by a public courier.
pub const MAX_RAW_INVOCATION_BYTES: usize = 4 * 1024 * 1024;
/// Tonic message ceiling for a maximum raw invocation plus field tag and length.
pub const MAX_COURIER_GRPC_MESSAGE_BYTES: usize = MAX_RAW_INVOCATION_BYTES + 5;

/// Required ownership and permission policy for one Basil Unix socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedUdsPolicy {
    /// Absolute normalized path of the Basil Unix socket.
    pub socket_path: PathBuf,
    /// Non-root UID allowed to own ancestor directories.
    pub service_owner_uid: u32,
    /// Required owner UID of the socket's final directory.
    pub directory_owner_uid: u32,
    /// Required final-directory permission bits, including special bits.
    pub directory_mode: u32,
    /// Required owner UID of the socket filesystem object.
    pub socket_owner_uid: u32,
    /// Required socket permission bits, including special bits.
    pub socket_mode: u32,
    /// Required server UID reported by Linux `SO_PEERCRED`.
    pub expected_peer_uid: u32,
}

impl TrustedUdsPolicy {
    /// Validate the policy's closed path and permission grammar.
    ///
    /// # Errors
    ///
    /// Returns [`TrustedUdsError::InvalidPolicy`] for a relative, non-normal,
    /// root-only, or out-of-range configuration.
    pub fn validate(&self) -> Result<(), TrustedUdsError> {
        validate_path(&self.socket_path)?;
        if self.directory_mode > 0o7777 || self.socket_mode > 0o7777 {
            return Err(TrustedUdsError::InvalidPolicy);
        }
        if (self.directory_owner_uid != 0 && self.directory_owner_uid != self.service_owner_uid)
            || self.socket_owner_uid != self.expected_peer_uid
        {
            return Err(TrustedUdsError::InvalidPolicy);
        }
        if self.directory_mode & 0o022 != 0 {
            return Err(TrustedUdsError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Unix socket trust or connection failure.
#[derive(Debug, Error)]
pub enum TrustedUdsError {
    /// The configured path or mode is outside the closed policy grammar.
    #[error("invalid trusted Unix socket policy")]
    InvalidPolicy,
    /// The platform lacks the qualified Linux `/proc/self/fd` connector.
    #[error("trusted Unix socket transport is unsupported on this platform")]
    UnsupportedPlatform,
    /// A path component, socket object, or peer failed a trust check.
    #[error("Unix socket trust verification failed")]
    TrustViolation,
    /// The verified socket could not be connected.
    #[error("verified Unix socket connection failed")]
    Connect,
}

/// Stable failure returned by the typed invocation courier client.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CourierCallError {
    /// The request violates the public courier contract.
    #[error("courier request is invalid")]
    InvalidRequest,
    /// The local listener is not the required courier-only profile.
    #[error("local invocation listener capability mismatch")]
    CapabilityMismatch,
    /// The local broker was unavailable before forwarding the operation.
    #[error("local broker unavailable before forwarding")]
    UnavailableBeforeForward,
    /// The local broker became unavailable after forwarding the invocation.
    #[error("local broker unavailable after forwarding")]
    UnavailableAfterForward,
    /// The call deadline elapsed before forwarding the operation.
    #[error("local broker deadline elapsed before forwarding")]
    DeadlineBeforeForward,
    /// The invocation deadline elapsed after forwarding.
    #[error("local broker deadline elapsed after forwarding")]
    DeadlineAfterForward,
    /// Challenge issuance was declined under bounded broker pressure.
    #[error("challenge issuance declined")]
    ChallengeDeclined,
    /// The local broker rejected a request without a sealed response.
    #[error("local broker rejected the courier request")]
    BrokerRejected,
}

impl CourierCallError {
    /// Return a stable transport token suitable for an untrusted reply.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "MALFORMED_REQUEST",
            Self::CapabilityMismatch => "CAPABILITY_MISMATCH",
            Self::UnavailableBeforeForward | Self::UnavailableAfterForward => "BASIL_UNAVAILABLE",
            Self::DeadlineBeforeForward | Self::DeadlineAfterForward => "TIMEOUT",
            Self::ChallengeDeclined => "CHALLENGE_ISSUANCE_DECLINED",
            Self::BrokerRejected => "BASIL_REJECTED",
        }
    }

    /// Return whether the identical public request is safe to retry.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::UnavailableBeforeForward | Self::DeadlineBeforeForward | Self::ChallengeDeclined
        )
    }
}

/// Failure while establishing the trusted local channel.
#[derive(Debug, Error)]
pub enum CourierConnectError {
    /// Unix socket policy or trust validation failed.
    #[error(transparent)]
    TrustedUds(#[from] TrustedUdsError),
    /// Tonic could not construct or establish the endpoint.
    #[error("local invocation endpoint failed")]
    Endpoint,
    /// The endpoint does not report the frozen courier capability profile.
    #[error("local invocation listener capability mismatch")]
    CapabilityMismatch,
}

/// Typed, capability-checking client for a Basil courier listener.
#[derive(Clone, Debug)]
pub struct InvocationCourierClient {
    policy: TrustedUdsPolicy,
    connect_timeout: Duration,
    call_timeout: Duration,
    #[cfg(test)]
    forward_barrier: Option<Arc<TestForwardBarrier>>,
}

#[cfg(test)]
#[derive(Debug)]
struct TestForwardBarrier {
    capability_complete: tokio::sync::Notify,
    operation_release: tokio::sync::Notify,
    reconnect_attempts: Arc<std::sync::atomic::AtomicUsize>,
}

/// Typed invocation-only client for a local Host listener.
///
/// This compatibility surface uses the same hardened Unix connector as a
/// courier, but rejects courier listeners and mandatory-freshness profiles. It
/// exposes no challenge issuance method.
#[derive(Clone, Debug)]
pub struct InvocationOnlyClient {
    policy: TrustedUdsPolicy,
    connect_timeout: Duration,
    call_timeout: Duration,
}

impl InvocationCourierClient {
    /// Connect through a trusted Unix socket and verify the listener profile.
    ///
    /// Each forwarded operation opens and verifies a fresh channel. Its
    /// capability check and operation share that channel, which refuses
    /// automatic reconnection if the transport is replaced between RPCs.
    ///
    /// # Errors
    ///
    /// Returns an error when trust validation, connection, or the startup
    /// capability check fails.
    pub async fn connect(
        policy: TrustedUdsPolicy,
        connect_timeout: Duration,
        call_timeout: Duration,
    ) -> Result<Self, CourierConnectError> {
        policy.validate()?;
        if connect_timeout.is_zero() || call_timeout.is_zero() {
            return Err(TrustedUdsError::InvalidPolicy.into());
        }
        let this = Self {
            policy,
            connect_timeout,
            call_timeout,
            #[cfg(test)]
            forward_barrier: None,
        };
        let deadline = tokio::time::Instant::now() + call_timeout;
        this.fresh_verified_client(deadline)
            .await
            .map_err(|_| CourierConnectError::CapabilityMismatch)?;
        Ok(this)
    }

    /// Request a freshness challenge after injecting the trusted source.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the caller supplied a source, the trusted
    /// source is invalid, capabilities changed, or Basil rejected the call.
    pub async fn get_challenge(
        &self,
        mut request: GetInvocationChallengeRequest,
        courier_observed_source: &str,
    ) -> Result<GetInvocationChallengeResponse, CourierCallError> {
        if request.courier_observed_source.is_some()
            || courier_observed_source.is_empty()
            || courier_observed_source.len() > MAX_COURIER_SOURCE_BYTES
        {
            return Err(CourierCallError::InvalidRequest);
        }
        request.courier_observed_source = Some(courier_observed_source.to_owned());
        let deadline = tokio::time::Instant::now() + self.call_timeout;
        let mut client = self.fresh_verified_client(deadline).await?;
        let call = client.get_invocation_challenge(request);
        let response = tokio::time::timeout_at(deadline, call)
            .await
            .map_err(|_| CourierCallError::DeadlineBeforeForward)?
            .map_err(|status| classify_challenge_status(&status))?;
        Ok(response.into_inner())
    }

    /// Forward one opaque sealed invocation after rechecking capabilities.
    ///
    /// # Errors
    ///
    /// Returns a stable error when capabilities changed or Basil did not
    /// return a sealed response. Failures after forwarding are never marked
    /// retryable for the identical invocation.
    pub async fn invoke(&self, request: SealedRequest) -> Result<SealedResponse, CourierCallError> {
        let deadline = tokio::time::Instant::now() + self.call_timeout;
        let mut client = self.fresh_verified_client(deadline).await?;
        #[cfg(test)]
        if let Some(barrier) = &self.forward_barrier {
            barrier.capability_complete.notify_one();
            tokio::time::timeout_at(deadline, barrier.operation_release.notified())
                .await
                .map_err(|_| CourierCallError::DeadlineAfterForward)?;
        }
        let call = client.invoke(request);
        let response = tokio::time::timeout_at(deadline, call)
            .await
            .map_err(|_| CourierCallError::DeadlineAfterForward)?
            .map_err(|status| classify_invoke_status(&status))?;
        Ok(response.into_inner())
    }

    async fn fresh_verified_client(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<InvocationServiceClient<Channel>, CourierCallError> {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or(CourierCallError::DeadlineBeforeForward)?;
        let connect_timeout = self.connect_timeout.min(remaining);
        let channel = tokio::time::timeout_at(
            deadline,
            trusted_channel(
                self.policy.clone(),
                connect_timeout,
                #[cfg(test)]
                self.forward_barrier
                    .as_ref()
                    .map(|barrier| Arc::clone(&barrier.reconnect_attempts)),
            ),
        )
        .await
        .map_err(|_| CourierCallError::DeadlineBeforeForward)?
        .map_err(|_| CourierCallError::UnavailableBeforeForward)?;
        let mut client = bounded_client(channel);
        let call = client.get_invocation_capabilities(GetInvocationCapabilitiesRequest {});
        let response = tokio::time::timeout_at(deadline, call)
            .await
            .map_err(|_| CourierCallError::DeadlineBeforeForward)?
            .map_err(|status| classify_pre_forward_status(&status))?
            .into_inner();
        if response.listener_profile != ListenerProfile::Courier as i32
            || !response.require_challenge
            || response.courier_protocol_version != COURIER_PROTOCOL_VERSION
        {
            return Err(CourierCallError::CapabilityMismatch);
        }
        Ok(client)
    }
}

impl InvocationOnlyClient {
    /// Connect to a hardened local Host invocation listener.
    ///
    /// # Errors
    ///
    /// Returns an error when socket trust, connection, or the startup local
    /// invocation-only capability check fails.
    pub async fn connect(
        policy: TrustedUdsPolicy,
        connect_timeout: Duration,
        call_timeout: Duration,
    ) -> Result<Self, CourierConnectError> {
        policy.validate()?;
        if connect_timeout.is_zero() || call_timeout.is_zero() {
            return Err(TrustedUdsError::InvalidPolicy.into());
        }
        let this = Self {
            policy,
            connect_timeout,
            call_timeout,
        };
        let deadline = tokio::time::Instant::now() + call_timeout;
        this.fresh_verified_client(deadline)
            .await
            .map_err(|_| CourierConnectError::CapabilityMismatch)?;
        Ok(this)
    }

    /// Forward one opaque sealed invocation after rechecking the local profile.
    ///
    /// # Errors
    ///
    /// Returns a stable error when the listener profile changed or Basil did
    /// not return a sealed response. Post-forward failures are not retryable.
    pub async fn invoke(&self, request: SealedRequest) -> Result<SealedResponse, CourierCallError> {
        let deadline = tokio::time::Instant::now() + self.call_timeout;
        let mut client = self.fresh_verified_client(deadline).await?;
        let call = client.invoke(request);
        let response = tokio::time::timeout_at(deadline, call)
            .await
            .map_err(|_| CourierCallError::DeadlineAfterForward)?
            .map_err(|status| classify_invoke_status(&status))?;
        Ok(response.into_inner())
    }

    async fn fresh_verified_client(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<InvocationServiceClient<Channel>, CourierCallError> {
        let remaining = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or(CourierCallError::DeadlineBeforeForward)?;
        let connect_timeout = self.connect_timeout.min(remaining);
        let channel = tokio::time::timeout_at(
            deadline,
            trusted_channel(
                self.policy.clone(),
                connect_timeout,
                #[cfg(test)]
                None,
            ),
        )
        .await
        .map_err(|_| CourierCallError::DeadlineBeforeForward)?
        .map_err(|_| CourierCallError::UnavailableBeforeForward)?;
        let mut client = bounded_client(channel);
        let call = client.get_invocation_capabilities(GetInvocationCapabilitiesRequest {});
        let response = tokio::time::timeout_at(deadline, call)
            .await
            .map_err(|_| CourierCallError::DeadlineBeforeForward)?
            .map_err(|status| classify_pre_forward_status(&status))?
            .into_inner();
        if response.listener_profile != ListenerProfile::Host as i32 || response.require_challenge {
            return Err(CourierCallError::CapabilityMismatch);
        }
        Ok(client)
    }
}

fn bounded_client(channel: Channel) -> InvocationServiceClient<Channel> {
    InvocationServiceClient::new(channel)
        .max_encoding_message_size(MAX_COURIER_GRPC_MESSAGE_BYTES)
        .max_decoding_message_size(MAX_COURIER_GRPC_MESSAGE_BYTES)
}

fn classify_pre_forward_status(status: &Status) -> CourierCallError {
    if status.code() == Code::DeadlineExceeded {
        CourierCallError::DeadlineBeforeForward
    } else if status.code() == Code::Unavailable {
        CourierCallError::UnavailableBeforeForward
    } else {
        CourierCallError::CapabilityMismatch
    }
}

fn classify_challenge_status(status: &Status) -> CourierCallError {
    match status.code() {
        Code::ResourceExhausted if status.message() == "CHALLENGE_ISSUANCE_DECLINED" => {
            CourierCallError::ChallengeDeclined
        }
        Code::DeadlineExceeded => CourierCallError::DeadlineBeforeForward,
        Code::Unavailable => CourierCallError::UnavailableBeforeForward,
        Code::InvalidArgument => CourierCallError::InvalidRequest,
        _ => CourierCallError::BrokerRejected,
    }
}

fn classify_invoke_status(status: &Status) -> CourierCallError {
    match status.code() {
        Code::DeadlineExceeded => CourierCallError::DeadlineAfterForward,
        Code::Unavailable => CourierCallError::UnavailableAfterForward,
        _ => CourierCallError::BrokerRejected,
    }
}

async fn trusted_channel(
    policy: TrustedUdsPolicy,
    connect_timeout: Duration,
    #[cfg(test)] reconnect_attempts: Option<Arc<std::sync::atomic::AtomicUsize>>,
) -> Result<Channel, CourierConnectError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (policy, connect_timeout);
        #[cfg(test)]
        let _ = reconnect_attempts;
        Err(TrustedUdsError::UnsupportedPlatform.into())
    }

    #[cfg(target_os = "linux")]
    {
        let endpoint = Endpoint::try_from("http://[::]:50051")
            .map_err(|_| CourierConnectError::Endpoint)?
            .connect_timeout(connect_timeout);
        let connector_used = Arc::new(AtomicBool::new(false));
        let channel = endpoint
            .connect_with_connector(service_fn(move |_: Uri| {
                let policy = policy.clone();
                let connector_used = Arc::clone(&connector_used);
                #[cfg(test)]
                let reconnect_attempts = reconnect_attempts.clone();
                async move {
                    if connector_used.swap(true, Ordering::AcqRel) {
                        #[cfg(test)]
                        if let Some(reconnect_attempts) = reconnect_attempts {
                            reconnect_attempts.fetch_add(1, Ordering::SeqCst);
                        }
                        return Err(std::io::Error::other(
                            "courier channel reconnect requires a fresh capability check",
                        ));
                    }
                    connect_verified(&policy)
                        .await
                        .map(TokioIo::new)
                        .map_err(std::io::Error::other)
                }
            }))
            .await
            .map_err(|_| CourierConnectError::Endpoint)?;
        Ok(channel)
    }
}

fn validate_path(path: &Path) -> Result<(), TrustedUdsError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let bytes = path.as_os_str().as_bytes();
        if bytes.len() < 2
            || bytes.first() != Some(&b'/')
            || bytes.last() == Some(&b'/')
            || bytes.contains(&0)
            || bytes.windows(2).any(|pair| pair == b"//")
            || bytes.windows(3).any(|part| part == b"/./")
            || bytes.windows(4).any(|part| part == b"/../")
            || bytes.ends_with(b"/.")
            || bytes.ends_with(b"/..")
        {
            return Err(TrustedUdsError::InvalidPolicy);
        }
    }
    #[cfg(not(unix))]
    if !path.is_absolute() {
        return Err(TrustedUdsError::InvalidPolicy);
    }

    let mut normals = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(_) => normals += 1,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(TrustedUdsError::InvalidPolicy);
            }
        }
    }
    if normals == 0 {
        return Err(TrustedUdsError::InvalidPolicy);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn connect_verified(
    policy: &TrustedUdsPolicy,
) -> Result<tokio::net::UnixStream, TrustedUdsError> {
    connect_verified_with_hook(policy, || {}).await
}

#[cfg(target_os = "linux")]
async fn connect_verified_with_hook(
    policy: &TrustedUdsPolicy,
    before_connect: impl FnOnce(),
) -> Result<tokio::net::UnixStream, TrustedUdsError> {
    use std::os::fd::AsRawFd;

    let before = open_verified_path(policy)?;
    before_connect();
    let pinned_path = PathBuf::from("/proc/self/fd")
        .join(before.directory.as_raw_fd().to_string())
        .join(&before.leaf);
    let stream = tokio::net::UnixStream::connect(&pinned_path)
        .await
        .map_err(|_| TrustedUdsError::Connect)?;

    verify_after_connect(policy, &before, &stream)?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn verify_after_connect(
    policy: &TrustedUdsPolicy,
    before: &VerifiedPath,
    stream: &tokio::net::UnixStream,
) -> Result<(), TrustedUdsError> {
    use rustix::fs::{AtFlags, statat};

    let pinned_after = statat(&before.directory, &before.leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| TrustedUdsError::TrustViolation)?;
    if NodeIdentity::from_stat(&pinned_after) != before.socket_identity {
        return Err(TrustedUdsError::TrustViolation);
    }

    let after = open_verified_path(policy)?;
    if after.directories != before.directories || after.socket_identity != before.socket_identity {
        return Err(TrustedUdsError::TrustViolation);
    }
    let peer = stream
        .peer_cred()
        .map_err(|_| TrustedUdsError::TrustViolation)?;
    if peer.uid() != policy.expected_peer_uid {
        return Err(TrustedUdsError::TrustViolation);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_verified_path(policy: &TrustedUdsPolicy) -> Result<VerifiedPath, TrustedUdsError> {
    use std::ffi::OsString;

    use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, open, openat, statat};

    let components: Vec<OsString> = policy
        .socket_path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect();
    let (leaf, directory_components) = components
        .split_last()
        .ok_or(TrustedUdsError::InvalidPolicy)?;
    let directory_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        open("/", directory_flags, Mode::empty()).map_err(|_| TrustedUdsError::TrustViolation)?;
    let mut directories = Vec::with_capacity(directory_components.len() + 1);
    directories.push(validate_ancestor(&directory, policy)?);
    for component in directory_components {
        directory = openat(&directory, component, directory_flags, Mode::empty())
            .map_err(|_| TrustedUdsError::TrustViolation)?;
        directories.push(validate_ancestor(&directory, policy)?);
    }

    let final_directory = directories.last().ok_or(TrustedUdsError::TrustViolation)?;
    if final_directory.uid != policy.directory_owner_uid
        || final_directory.mode & 0o7777 != policy.directory_mode
    {
        return Err(TrustedUdsError::TrustViolation);
    }

    let socket = openat(
        &directory,
        leaf,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| TrustedUdsError::TrustViolation)?;
    let socket_stat = fstat(&socket).map_err(|_| TrustedUdsError::TrustViolation)?;
    let socket_identity = NodeIdentity::from_stat(&socket_stat);
    if FileType::from_raw_mode(socket_stat.st_mode) != FileType::Socket
        || socket_stat.st_uid != policy.socket_owner_uid
        || socket_stat.st_mode & 0o7777 != policy.socket_mode
    {
        return Err(TrustedUdsError::TrustViolation);
    }
    let named_socket = statat(&directory, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| TrustedUdsError::TrustViolation)?;
    if NodeIdentity::from_stat(&named_socket) != socket_identity {
        return Err(TrustedUdsError::TrustViolation);
    }

    Ok(VerifiedPath {
        directories,
        directory,
        _socket: socket,
        leaf: leaf.clone(),
        socket_identity,
    })
}

#[cfg(target_os = "linux")]
fn validate_ancestor(
    directory: &impl std::os::fd::AsFd,
    policy: &TrustedUdsPolicy,
) -> Result<NodeIdentity, TrustedUdsError> {
    let stat = rustix::fs::fstat(directory).map_err(|_| TrustedUdsError::TrustViolation)?;
    if (stat.st_uid != 0 && stat.st_uid != policy.service_owner_uid) || stat.st_mode & 0o022 != 0 {
        return Err(TrustedUdsError::TrustViolation);
    }
    Ok(NodeIdentity::from_stat(&stat))
}

#[cfg(target_os = "linux")]
struct VerifiedPath {
    directories: Vec<NodeIdentity>,
    directory: std::os::fd::OwnedFd,
    _socket: std::os::fd::OwnedFd,
    leaf: std::ffi::OsString,
    socket_identity: NodeIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NodeIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(target_os = "linux")]
impl NodeIdentity {
    const fn from_stat(stat: &rustix::fs::Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;

    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[cfg(target_os = "linux")]
    use std::sync::Arc;
    #[cfg(target_os = "linux")]
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    #[cfg(target_os = "linux")]
    use basil_proto::broker::v1::GetInvocationCapabilitiesResponse;
    #[cfg(target_os = "linux")]
    use basil_proto::broker::v1::invocation_service_server::{
        InvocationService, InvocationServiceServer,
    };
    #[cfg(target_os = "linux")]
    use tokio::net::UnixListener;
    #[cfg(target_os = "linux")]
    use tokio_stream::StreamExt as _;
    #[cfg(target_os = "linux")]
    use tokio_stream::wrappers::UnixListenerStream;
    #[cfg(target_os = "linux")]
    use tonic::{Request, Response};

    const TEST_WAIT: Duration = Duration::from_secs(2);

    struct TestTask<T> {
        handle: Option<tokio::task::JoinHandle<T>>,
    }

    impl<T> TestTask<T> {
        fn new(handle: tokio::task::JoinHandle<T>) -> Self {
            Self {
                handle: Some(handle),
            }
        }

        #[allow(clippy::panic)]
        async fn join(mut self) -> T {
            let result = tokio::time::timeout(TEST_WAIT, self.handle.as_mut().unwrap()).await;
            if let Ok(result) = result {
                self.handle.take();
                return result.expect("test task panicked");
            }

            let _aborted = self.abort_and_reap().await;
            panic!("test task join timed out");
        }

        async fn abort_and_join(mut self) {
            let result = self.abort_and_reap().await;
            if let Err(error) = result {
                assert!(error.is_cancelled(), "test task panicked: {error}");
            }
        }

        async fn abort_and_reap(&mut self) -> Result<T, tokio::task::JoinError> {
            let handle = self.handle.as_mut().unwrap();
            handle.abort();
            let result = tokio::time::timeout(TEST_WAIT, &mut *handle).await;
            if let Ok(result) = result {
                self.handle.take();
                return result;
            }

            // All guarded tasks are cooperative async futures. If an aborted
            // task cannot be reaped, terminating the test process is the only
            // way to guarantee it is not detached.
            std::process::abort();
        }
    }

    impl<T> Drop for TestTask<T> {
        fn drop(&mut self) {
            if let Some(handle) = &self.handle {
                handle.abort();
            }
        }
    }

    #[test]
    fn rejects_non_normal_socket_paths() {
        for path in [
            "relative.sock",
            "/",
            "/run/../basil.sock",
            "/run/./basil.sock",
            "/run//basil.sock",
            "/run/basil.sock/",
        ] {
            let policy = policy(path);
            assert!(matches!(
                policy.validate(),
                Err(TrustedUdsError::InvalidPolicy)
            ));
        }
    }

    #[test]
    fn accepts_closed_policy_grammar() {
        policy("/run/basil/basil.sock").validate().unwrap();
    }

    #[test]
    fn rejects_writable_final_directory_policy() {
        let mut value = policy("/run/basil/basil.sock");
        value.directory_mode = 0o770;
        assert!(matches!(
            value.validate(),
            Err(TrustedUdsError::InvalidPolicy)
        ));
    }

    #[test]
    fn stable_errors_never_expose_status_text() {
        assert_eq!(CourierCallError::BrokerRejected.code(), "BASIL_REJECTED");
        assert!(!CourierCallError::UnavailableAfterForward.retryable());
        assert!(CourierCallError::UnavailableBeforeForward.retryable());
        assert!(!CourierCallError::CapabilityMismatch.retryable());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn trusted_connector_checks_socket_metadata_and_peer_uid() {
        let fixture = SocketFixture::bind();
        let accept = fixture.accept_one();
        let policy = fixture.policy();
        let connect = connect_verified(&policy);
        let (accepted, connected) = tokio::join!(accept, connect);
        accepted.unwrap();
        connected.unwrap();

        let mut wrong_mode = fixture.policy();
        wrong_mode.socket_mode = 0o600;
        assert!(matches!(
            connect_verified(&wrong_mode).await,
            Err(TrustedUdsError::TrustViolation)
        ));

        let mut wrong_peer = fixture.policy();
        wrong_peer.expected_peer_uid += 1;
        assert!(matches!(
            connect_verified(&wrong_peer).await,
            Err(TrustedUdsError::TrustViolation)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn trusted_connector_rejects_wrong_owners_and_writable_directory() {
        let fixture = SocketFixture::bind();

        let mut wrong_directory_owner = fixture.policy();
        wrong_directory_owner.service_owner_uid += 1;
        wrong_directory_owner.directory_owner_uid += 1;
        assert!(matches!(
            connect_verified(&wrong_directory_owner).await,
            Err(TrustedUdsError::TrustViolation)
        ));

        let mut wrong_socket_owner = fixture.policy();
        wrong_socket_owner.socket_owner_uid += 1;
        wrong_socket_owner.expected_peer_uid += 1;
        assert!(matches!(
            connect_verified(&wrong_socket_owner).await,
            Err(TrustedUdsError::TrustViolation)
        ));

        fs::set_permissions(fixture.root.join("d"), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(matches!(
            connect_verified(&fixture.policy()).await,
            Err(TrustedUdsError::TrustViolation)
        ));
        fs::set_permissions(fixture.root.join("d"), fs::Permissions::from_mode(0o750)).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn trusted_connector_rejects_non_socket_leaf() {
        let mut fixture = SocketFixture::bind();
        drop(fixture.listener.take());
        let socket = fixture.root.join("d/broker.sock");
        fs::remove_file(&socket).unwrap();
        fs::write(&socket, b"not a socket").unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();

        assert!(matches!(
            connect_verified(&fixture.policy()).await,
            Err(TrustedUdsError::TrustViolation)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn trusted_connector_rejects_symlink_socket_leaf() {
        let fixture = SocketFixture::bind();
        let socket = fixture.root.join("d/broker.sock");
        let target = fixture.root.join("d/target.sock");
        fs::rename(&socket, &target).unwrap();
        symlink(&target, &socket).unwrap();

        assert!(matches!(
            connect_verified(&fixture.policy()).await,
            Err(TrustedUdsError::TrustViolation)
        ));

        fs::remove_file(&socket).unwrap();
        fs::rename(target, socket).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn trusted_connector_rejects_ancestor_symlink() {
        let fixture = SocketFixture::bind();
        let link = fixture.root.with_extension("link");
        symlink(&fixture.root, &link).unwrap();
        let mut policy = fixture.policy();
        policy.socket_path = link.join("d/broker.sock");
        assert!(matches!(
            connect_verified(&policy).await,
            Err(TrustedUdsError::TrustViolation)
        ));
        fs::remove_file(link).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn trusted_connector_rejects_ancestor_rename_after_initial_walk() {
        let fixture = SocketFixture::bind();
        let policy = fixture.policy();
        let moved = fixture.root.with_extension("moved");
        let accept = fixture.accept_one();
        let connect = connect_verified_with_hook(&policy, || {
            fs::rename(&fixture.root, &moved).unwrap();
            fs::create_dir(&fixture.root).unwrap();
            fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o750)).unwrap();
            let replacement_final = fixture.root.join("d");
            fs::create_dir(&replacement_final).unwrap();
            fs::set_permissions(&replacement_final, fs::Permissions::from_mode(0o750)).unwrap();
        });
        let (accepted, connected) = tokio::join!(accept, connect);
        accepted.unwrap();
        assert!(matches!(connected, Err(TrustedUdsError::TrustViolation)));

        fs::remove_dir(fixture.root.join("d")).unwrap();
        fs::remove_dir(&fixture.root).unwrap();
        fs::remove_file(moved.join("d/broker.sock")).unwrap();
        fs::remove_dir(moved.join("d")).unwrap();
        fs::remove_dir(moved).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn trusted_connector_rejects_socket_replacement_after_leaf_open() {
        use std::cell::RefCell;
        use std::os::unix::net::UnixListener as StdUnixListener;

        let fixture = SocketFixture::bind();
        let policy = fixture.policy();
        let socket = policy.socket_path.clone();
        let old_socket = fixture.root.join("d/original.sock");
        let replacement = RefCell::new(None);
        let connected = connect_verified_with_hook(&policy, || {
            fs::rename(&socket, &old_socket).unwrap();
            let listener = StdUnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
            replacement.replace(Some(listener));
        })
        .await;
        assert!(matches!(connected, Err(TrustedUdsError::TrustViolation)));
        drop(replacement);
        fs::remove_file(socket).unwrap();
        fs::rename(old_socket, fixture.root.join("d/broker.sock")).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn typed_client_rejects_every_capability_mismatch() {
        for (profile, require_challenge, version) in [
            (ListenerProfile::Host as i32, true, 1),
            (ListenerProfile::Unspecified as i32, true, 1),
            (99, true, 1),
            (ListenerProfile::Courier as i32, false, 1),
            (ListenerProfile::Courier as i32, true, 2),
        ] {
            let service = TestInvocation::new(profile, require_challenge, version);
            let mut fixture = SocketFixture::bind();
            let policy = fixture.policy();
            let server = fixture.serve(service);
            let result = InvocationCourierClient::connect(
                policy,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await;
            assert!(matches!(
                result,
                Err(CourierConnectError::CapabilityMismatch)
            ));
            server.abort();
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn typed_client_rechecks_capability_before_each_forward() {
        let service = TestInvocation::new(ListenerProfile::Courier as i32, true, 1);
        let profile = Arc::clone(&service.profile);
        let challenges = Arc::clone(&service.challenge_calls);
        let mut fixture = SocketFixture::bind();
        let policy = fixture.policy();
        let server = fixture.serve(service);
        let client = InvocationCourierClient::connect(
            policy,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        profile.store(ListenerProfile::Host as i32, Ordering::SeqCst);
        let error = client
            .get_challenge(
                GetInvocationChallengeRequest {
                    jkt: vec![1; 32],
                    courier_observed_source: None,
                },
                "agent-a",
            )
            .await
            .unwrap_err();
        assert_eq!(error, CourierCallError::CapabilityMismatch);
        assert_eq!(challenges.load(Ordering::SeqCst), 0);
        server.abort();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn replacement_after_capability_cannot_receive_operation_on_reconnect() {
        let service = TestInvocation::new(ListenerProfile::Courier as i32, true, 1);
        let capability_calls = Arc::clone(&service.capability_calls);
        let mut fixture = SocketFixture::bind();
        let policy = fixture.policy();
        let (server, mut connections) = fixture.serve_with_connection_controls(service);
        let server = TestTask::new(server);
        let mut client = InvocationCourierClient::connect(
            policy,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        drop(
            tokio::time::timeout(TEST_WAIT, connections.recv())
                .await
                .expect("startup connection observation timed out")
                .expect("startup connection observation channel closed"),
        );

        let barrier = Arc::new(TestForwardBarrier {
            capability_complete: tokio::sync::Notify::new(),
            operation_release: tokio::sync::Notify::new(),
            reconnect_attempts: Arc::new(AtomicUsize::new(0)),
        });
        client.forward_barrier = Some(Arc::clone(&barrier));
        let operation = TestTask::new(tokio::spawn(async move {
            client
                .invoke(SealedRequest {
                    message: b"opaque".to_vec(),
                })
                .await
        }));

        tokio::time::timeout(TEST_WAIT, barrier.capability_complete.notified())
            .await
            .expect("capability barrier timed out");
        assert_eq!(capability_calls.load(Ordering::SeqCst), 2);
        let operation_connection = tokio::time::timeout(TEST_WAIT, connections.recv())
            .await
            .expect("operation connection observation timed out")
            .expect("operation connection observation channel closed");
        operation_connection
            .shutdown(std::net::Shutdown::Both)
            .unwrap();
        server.abort_and_join().await;

        let replacement = TestInvocation::new(ListenerProfile::Host as i32, false, 0);
        let replacement_invokes = Arc::clone(&replacement.invoke_calls);
        let replacement_server = TestTask::new(fixture.replace_and_serve(replacement));
        barrier.operation_release.notify_one();
        let error = operation.join().await.unwrap_err();
        assert_eq!(error, CourierCallError::UnavailableAfterForward);
        assert_eq!(barrier.reconnect_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(replacement_invokes.load(Ordering::SeqCst), 0);
        replacement_server.abort_and_join().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn capability_and_operation_share_one_end_to_end_budget() {
        let service = TestInvocation::new(ListenerProfile::Courier as i32, true, 1);
        let capability_delay_ms = Arc::clone(&service.capability_delay_ms);
        let invoke_delay_ms = Arc::clone(&service.invoke_delay_ms);
        let mut fixture = SocketFixture::bind();
        let policy = fixture.policy();
        let server = fixture.serve(service);
        let client = InvocationCourierClient::connect(
            policy,
            Duration::from_secs(2),
            Duration::from_millis(100),
        )
        .await
        .unwrap();

        capability_delay_ms.store(60, Ordering::SeqCst);
        invoke_delay_ms.store(60, Ordering::SeqCst);
        let started = tokio::time::Instant::now();
        let error = client
            .invoke(SealedRequest {
                message: b"opaque".to_vec(),
            })
            .await
            .unwrap_err();
        assert_eq!(error, CourierCallError::DeadlineAfterForward);
        assert!(started.elapsed() < Duration::from_millis(140));
        server.abort();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn exact_raw_message_limit_succeeds_and_next_byte_is_not_forwarded() {
        let service = TestInvocation::new(ListenerProfile::Courier as i32, true, 1);
        let invokes = Arc::clone(&service.invoke_calls);
        let mut fixture = SocketFixture::bind();
        let policy = fixture.policy();
        let server = fixture.serve(service);
        let client = InvocationCourierClient::connect(
            policy,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        let exact = vec![9; MAX_RAW_INVOCATION_BYTES];
        let response = client
            .invoke(SealedRequest {
                message: exact.clone(),
            })
            .await
            .unwrap();
        assert_eq!(response.message, exact);
        let error = client
            .invoke(SealedRequest {
                message: vec![9; MAX_RAW_INVOCATION_BYTES + 1],
            })
            .await
            .unwrap_err();
        assert_eq!(error, CourierCallError::BrokerRejected);
        assert_eq!(invokes.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn invocation_only_client_accepts_host_profile() {
        let service = TestInvocation::new(ListenerProfile::Host as i32, false, 0);
        let mut fixture = SocketFixture::bind();
        let policy = fixture.policy();
        let server = fixture.serve(service);
        let client =
            InvocationOnlyClient::connect(policy, Duration::from_secs(2), Duration::from_secs(2))
                .await
                .unwrap();
        let response = client
            .invoke(SealedRequest {
                message: b"opaque".to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(response.message, b"opaque");
        server.abort();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn invocation_only_client_rejects_courier_unknown_and_freshness_profiles() {
        for (profile, require_challenge) in [
            (ListenerProfile::Courier as i32, false),
            (ListenerProfile::Unspecified as i32, false),
            (99, false),
            (ListenerProfile::Host as i32, true),
        ] {
            let service = TestInvocation::new(profile, require_challenge, 1);
            let mut fixture = SocketFixture::bind();
            let policy = fixture.policy();
            let server = fixture.serve(service);
            let result = InvocationOnlyClient::connect(
                policy,
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await;
            assert!(matches!(
                result,
                Err(CourierConnectError::CapabilityMismatch)
            ));
            server.abort();
        }
    }

    #[cfg(target_os = "linux")]
    struct SocketFixture {
        root: PathBuf,
        listener: Option<UnixListener>,
        uid: u32,
    }

    #[cfg(target_os = "linux")]
    impl SocketFixture {
        fn bind() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);

            let uid = rustix::process::geteuid().as_raw();
            let root = std::env::current_dir().unwrap().join(format!(
                ".bc-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
            let final_directory = root.join("d");
            fs::create_dir(&final_directory).unwrap();
            fs::set_permissions(&final_directory, fs::Permissions::from_mode(0o750)).unwrap();
            let socket = final_directory.join("broker.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
            Self {
                root,
                listener: Some(listener),
                uid,
            }
        }

        fn policy(&self) -> TrustedUdsPolicy {
            TrustedUdsPolicy {
                socket_path: self.root.join("d/broker.sock"),
                service_owner_uid: self.uid,
                directory_owner_uid: self.uid,
                directory_mode: 0o750,
                socket_owner_uid: self.uid,
                socket_mode: 0o660,
                expected_peer_uid: self.uid,
            }
        }

        async fn accept_one(&self) -> std::io::Result<()> {
            self.listener.as_ref().unwrap().accept().await.map(|_| ())
        }

        fn serve(&mut self, service: TestInvocation) -> tokio::task::JoinHandle<()> {
            let listener = self.listener.take().unwrap();
            tokio::spawn(async move {
                let _ = tonic::transport::Server::builder()
                    .add_service(
                        InvocationServiceServer::new(service)
                            .max_decoding_message_size(MAX_COURIER_GRPC_MESSAGE_BYTES)
                            .max_encoding_message_size(MAX_COURIER_GRPC_MESSAGE_BYTES),
                    )
                    .serve_with_incoming(UnixListenerStream::new(listener))
                    .await;
            })
        }

        fn serve_with_connection_controls(
            &mut self,
            service: TestInvocation,
        ) -> (
            tokio::task::JoinHandle<()>,
            tokio::sync::mpsc::UnboundedReceiver<std::os::unix::net::UnixStream>,
        ) {
            let listener = self.listener.take().unwrap();
            let (controls_tx, controls_rx) = tokio::sync::mpsc::unbounded_channel();
            let incoming = UnixListenerStream::new(listener).map(move |accepted| {
                let stream = accepted?;
                let control = rustix::io::dup(&stream).map_err(std::io::Error::other)?;
                let control = std::os::unix::net::UnixStream::from(control);
                controls_tx
                    .send(control)
                    .map_err(|_| std::io::Error::other("connection control receiver closed"))?;
                Ok::<_, std::io::Error>(stream)
            });
            let server = tokio::spawn(async move {
                let _ = tonic::transport::Server::builder()
                    .add_service(
                        InvocationServiceServer::new(service)
                            .max_decoding_message_size(MAX_COURIER_GRPC_MESSAGE_BYTES)
                            .max_encoding_message_size(MAX_COURIER_GRPC_MESSAGE_BYTES),
                    )
                    .serve_with_incoming(incoming)
                    .await;
            });
            (server, controls_rx)
        }

        fn replace_and_serve(&mut self, service: TestInvocation) -> tokio::task::JoinHandle<()> {
            let socket = self.root.join("d/broker.sock");
            fs::remove_file(&socket).unwrap();
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
            self.listener = Some(listener);
            self.serve(service)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for SocketFixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.root.join("d/broker.sock"));
            let _ = fs::remove_dir(self.root.join("d"));
            let _ = fs::remove_dir(&self.root);
        }
    }

    #[cfg(target_os = "linux")]
    #[derive(Clone, Debug)]
    struct TestInvocation {
        profile: Arc<AtomicI32>,
        require_challenge: bool,
        version: u32,
        challenge_calls: Arc<AtomicUsize>,
        invoke_calls: Arc<AtomicUsize>,
        capability_calls: Arc<AtomicUsize>,
        capability_delay_ms: Arc<AtomicUsize>,
        invoke_delay_ms: Arc<AtomicUsize>,
    }

    #[cfg(target_os = "linux")]
    impl TestInvocation {
        fn new(profile: i32, require_challenge: bool, version: u32) -> Self {
            Self {
                profile: Arc::new(AtomicI32::new(profile)),
                require_challenge,
                version,
                challenge_calls: Arc::new(AtomicUsize::new(0)),
                invoke_calls: Arc::new(AtomicUsize::new(0)),
                capability_calls: Arc::new(AtomicUsize::new(0)),
                capability_delay_ms: Arc::new(AtomicUsize::new(0)),
                invoke_delay_ms: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[tonic::async_trait]
    impl InvocationService for TestInvocation {
        async fn invoke(
            &self,
            request: Request<SealedRequest>,
        ) -> Result<Response<SealedResponse>, Status> {
            self.invoke_calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(
                u64::try_from(self.invoke_delay_ms.load(Ordering::SeqCst)).unwrap(),
            ))
            .await;
            Ok(Response::new(SealedResponse {
                message: request.into_inner().message,
                response_subject: None,
            }))
        }

        async fn get_invocation_challenge(
            &self,
            request: Request<GetInvocationChallengeRequest>,
        ) -> Result<Response<GetInvocationChallengeResponse>, Status> {
            self.challenge_calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                request.into_inner().courier_observed_source.as_deref(),
                Some("agent-a")
            );
            Ok(Response::new(GetInvocationChallengeResponse {
                challenge: vec![2; 32],
                generation: 1,
                expires_at_unix: 10,
            }))
        }

        async fn get_invocation_capabilities(
            &self,
            _request: Request<GetInvocationCapabilitiesRequest>,
        ) -> Result<Response<GetInvocationCapabilitiesResponse>, Status> {
            self.capability_calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(
                u64::try_from(self.capability_delay_ms.load(Ordering::SeqCst)).unwrap(),
            ))
            .await;
            Ok(Response::new(GetInvocationCapabilitiesResponse {
                listener_profile: self.profile.load(Ordering::SeqCst),
                require_challenge: self.require_challenge,
                courier_protocol_version: self.version,
            }))
        }
    }

    fn policy(path: &str) -> TrustedUdsPolicy {
        TrustedUdsPolicy {
            socket_path: PathBuf::from(path),
            service_owner_uid: 1000,
            directory_owner_uid: 1000,
            directory_mode: 0o750,
            socket_owner_uid: 1001,
            socket_mode: 0o660,
            expected_peer_uid: 1001,
        }
    }
}
