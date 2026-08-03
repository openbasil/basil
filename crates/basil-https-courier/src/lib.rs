// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Bounded HTTPS transport for opaque Basil sealed invocations.
//!
//! The courier terminates one HTTP/1.1 request per connection and forwards only
//! freshness challenges and sealed invocations through [`basil_courier`]. It
//! never exposes a broker or administration service on its TCP listener.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use basil_courier::{CourierCallError, InvocationCourierClient, TrustedUdsPolicy};
use basil_proto::broker::v1::{GetInvocationChallengeRequest, SealedRequest};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::header::{
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
    HeaderName, HeaderValue, TRANSFER_ENCODING, UPGRADE,
};
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri, Version};
use prost::Message;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_BEARER_BYTES: usize = 256;
const MAX_CERTIFICATE_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;
const MAX_REQUEST_LINE_BYTES: usize = 64;
const PROBLEM_BODY_LIMIT: usize = 128;
const SOURCE_HEADER: HeaderName = HeaderName::from_static("x-forwarded-for");
const FORWARDED_HEADER: HeaderName = HeaderName::from_static("forwarded");
const REAL_IP_HEADER: HeaderName = HeaderName::from_static("x-real-ip");

/// Frozen default challenge-body limit.
pub const DEFAULT_CHALLENGE_BODY_BYTES: usize = 256;
/// Frozen maximum challenge-body limit.
pub const MAX_CHALLENGE_BODY_BYTES: usize = 4 * 1024;
/// Frozen default invocation request and response limit.
pub const DEFAULT_INVOCATION_BYTES: usize = 1024 * 1024;
/// Frozen maximum invocation request and response limit.
pub const MAX_INVOCATION_BYTES: usize = 4 * 1024 * 1024;
/// Frozen maximum number of accepted HTTP headers.
pub const MAX_HEADER_COUNT: usize = 64;
/// Frozen maximum decoded HTTP header bytes.
pub const MAX_HEADER_BYTES: usize = 32 * 1024;
/// Frozen maximum simultaneous TCP connections.
pub const MAX_CONNECTIONS: usize = 1024;
/// Frozen maximum forwarded calls in flight.
pub const MAX_IN_FLIGHT: usize = 256;
/// Frozen maximum retained source partitions.
pub const MAX_SOURCE_BUCKETS: usize = 65_536;

/// Command-line arguments for the HTTPS courier.
#[derive(Clone, Debug, Parser)]
#[command(name = "basil-https-courier")]
pub struct Args {
    /// Courier configuration file.
    #[arg(long)]
    pub config: PathBuf,
}

/// Complete HTTPS courier configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    /// TCP address used only by this courier process.
    pub bind: SocketAddr,
    /// Mutually exclusive TLS or trusted-loopback-proxy listener.
    pub listener: ListenerConfig,
    /// Trusted local Basil courier socket.
    pub basil: BasilSocketConfig,
    /// Optional owner-only bearer file. Mandatory in proxy mode.
    pub bearer_file: Option<PathBuf>,
    /// Resource and deadline limits.
    #[serde(default)]
    pub limits: Limits,
}

/// Exclusive public listener mode.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "mode", deny_unknown_fields, rename_all = "kebab-case")]
pub enum ListenerConfig {
    /// Direct `rustls` TLS termination.
    DirectTls {
        /// PEM certificate chain.
        certificate_file: PathBuf,
        /// PEM private key.
        private_key_file: PathBuf,
    },
    /// Plain HTTP from one explicitly trusted loopback proxy address.
    TrustedProxy {
        /// Required immediate TCP peer address.
        proxy_address: IpAddr,
    },
}

/// Hardened Basil Unix-socket policy in configuration form.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct BasilSocketConfig {
    /// Absolute normalized courier-listener socket path.
    pub socket_path: PathBuf,
    /// UID allowed to own non-root trusted ancestors.
    pub service_owner_uid: u32,
    /// Required final-directory owner UID.
    pub directory_owner_uid: u32,
    /// Required final-directory mode.
    pub directory_mode: u32,
    /// Required socket owner UID.
    pub socket_owner_uid: u32,
    /// Required socket mode.
    pub socket_mode: u32,
    /// Required Basil peer UID from `SO_PEERCRED`.
    pub expected_peer_uid: u32,
}

impl From<&BasilSocketConfig> for TrustedUdsPolicy {
    fn from(value: &BasilSocketConfig) -> Self {
        Self {
            socket_path: value.socket_path.clone(),
            service_owner_uid: value.service_owner_uid,
            directory_owner_uid: value.directory_owner_uid,
            directory_mode: value.directory_mode,
            socket_owner_uid: value.socket_owner_uid,
            socket_mode: value.socket_mode,
            expected_peer_uid: value.expected_peer_uid,
        }
    }
}

/// Validated resource limits for the public listener.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Limits {
    /// Maximum serialized challenge request or response bytes.
    pub challenge_body_bytes: usize,
    /// Maximum sealed invocation request bytes.
    pub invocation_request_bytes: usize,
    /// Maximum sealed invocation response bytes.
    pub invocation_response_bytes: usize,
    /// Maximum number of decoded headers.
    pub header_count: usize,
    /// Maximum decoded header-name and value bytes.
    pub header_bytes: usize,
    /// Maximum simultaneous accepted connections.
    pub connections: usize,
    /// Maximum forwarded calls, with no admission queue.
    pub in_flight: usize,
    /// Per-source requests admitted per second.
    pub per_source_rate: u32,
    /// Per-source token burst.
    pub per_source_burst: u32,
    /// Global requests admitted per second.
    pub global_rate: u32,
    /// Global token burst.
    pub global_burst: u32,
    /// Maximum retained source buckets.
    pub source_buckets: usize,
    /// TLS handshake, request I/O, and response write deadline in seconds.
    pub io_deadline_seconds: u64,
    /// Challenge forwarding deadline in seconds.
    pub challenge_deadline_seconds: u64,
    /// Invocation forwarding deadline in seconds.
    pub invocation_deadline_seconds: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            challenge_body_bytes: DEFAULT_CHALLENGE_BODY_BYTES,
            invocation_request_bytes: DEFAULT_INVOCATION_BYTES,
            invocation_response_bytes: DEFAULT_INVOCATION_BYTES,
            header_count: 32,
            header_bytes: 16 * 1024,
            connections: 128,
            in_flight: 32,
            per_source_rate: 16,
            per_source_burst: 64,
            global_rate: 128,
            global_burst: 256,
            source_buckets: 4096,
            io_deadline_seconds: 5,
            challenge_deadline_seconds: 3,
            invocation_deadline_seconds: 30,
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<(), ConfigError> {
        validate_limit(self.challenge_body_bytes, MAX_CHALLENGE_BODY_BYTES)?;
        validate_limit(self.invocation_request_bytes, MAX_INVOCATION_BYTES)?;
        validate_limit(self.invocation_response_bytes, MAX_INVOCATION_BYTES)?;
        validate_limit(self.header_count, MAX_HEADER_COUNT)?;
        validate_limit(self.header_bytes, MAX_HEADER_BYTES)?;
        validate_limit(self.connections, MAX_CONNECTIONS)?;
        validate_limit(self.in_flight, MAX_IN_FLIGHT)?;
        validate_limit(self.source_buckets, MAX_SOURCE_BUCKETS)?;
        validate_limit(self.per_source_rate, 1024)?;
        validate_limit(self.per_source_burst, 2048)?;
        validate_limit(self.global_rate, 4096)?;
        validate_limit(self.global_burst, 8192)?;
        validate_limit(self.io_deadline_seconds, 30)?;
        validate_limit(self.challenge_deadline_seconds, 30)?;
        validate_limit(self.invocation_deadline_seconds, 120)?;
        Ok(())
    }
}

fn validate_limit<T>(value: T, maximum: T) -> Result<(), ConfigError>
where
    T: Copy + Ord + Default,
{
    if value == T::default() || value > maximum {
        Err(ConfigError::InvalidLimit)
    } else {
        Ok(())
    }
}

/// Configuration or trusted-secret loading failure.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be opened or read within its bound.
    #[error("courier configuration could not be read")]
    Read,
    /// TOML did not match the closed configuration schema.
    #[error("courier configuration is invalid")]
    Parse,
    /// A configured limit is zero or exceeds its frozen maximum.
    #[error("courier limit is outside the supported range")]
    InvalidLimit,
    /// Listener-mode invariants are not satisfied.
    #[error("courier listener mode is invalid")]
    InvalidListener,
    /// Bearer material is missing, malformed, or not owner-only.
    #[error("courier bearer file is invalid")]
    InvalidBearer,
    /// TLS identity material is malformed or exceeds its bound.
    #[error("courier TLS identity is invalid")]
    InvalidTls,
    /// The local socket policy is invalid.
    #[error("courier Basil socket policy is invalid")]
    InvalidSocket,
}

impl Config {
    /// Read and validate a bounded TOML configuration file.
    ///
    /// # Errors
    ///
    /// Returns a typed error for unreadable, oversized, malformed, or unsafe
    /// configuration.
    pub async fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let bytes = read_bounded(path, MAX_CONFIG_BYTES).await?;
        let text = std::str::from_utf8(&bytes).map_err(|_| ConfigError::Parse)?;
        let config: Self = toml::from_str(text).map_err(|_| ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        self.limits.validate()?;
        TrustedUdsPolicy::from(&self.basil)
            .validate()
            .map_err(|_| ConfigError::InvalidSocket)?;
        match &self.listener {
            ListenerConfig::DirectTls { .. } => {}
            ListenerConfig::TrustedProxy { proxy_address } => {
                if !self.bind.ip().is_loopback()
                    || !proxy_address.is_loopback()
                    || self.bearer_file.is_none()
                {
                    return Err(ConfigError::InvalidListener);
                }
            }
        }
        Ok(())
    }
}

/// Fatal courier startup or listener failure.
#[derive(Debug, Error)]
pub enum RunError {
    /// The configuration became invalid before startup.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The closed local courier listener could not be verified.
    #[error("Basil courier listener verification failed")]
    Basil,
    /// The public TCP listener could not be bound or accepted.
    #[error("HTTPS courier TCP listener failed")]
    Listener,
}

/// Validate all trust anchors and serve until process shutdown.
///
/// # Errors
///
/// Returns an error before serving if the bearer, TLS identity, Unix socket,
/// or frozen courier capability profile cannot be verified.
pub async fn run(config: Config) -> Result<(), RunError> {
    config.validate()?;
    let bearer = match &config.bearer_file {
        Some(path) => Some(Bearer::from_path(path).await?),
        None => None,
    };
    let tls = load_tls(&config.listener).await?;
    let policy = TrustedUdsPolicy::from(&config.basil);
    let io_timeout = Duration::from_secs(config.limits.io_deadline_seconds);
    let challenge_client = InvocationCourierClient::connect(
        policy.clone(),
        io_timeout,
        Duration::from_secs(config.limits.challenge_deadline_seconds),
    )
    .await
    .map_err(|_| RunError::Basil)?;
    let invoke_client = InvocationCourierClient::connect(
        policy,
        io_timeout,
        Duration::from_secs(config.limits.invocation_deadline_seconds),
    )
    .await
    .map_err(|_| RunError::Basil)?;

    let state = Arc::new(AppState::new(
        &config.limits,
        bearer,
        challenge_client,
        invoke_client,
    ));
    let listener = TcpListener::bind(config.bind)
        .await
        .map_err(|_| RunError::Listener)?;
    let connections = Arc::new(ConnectionAdmission::new(
        config.limits.connections,
        &config.listener,
    ));

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(|_| RunError::Listener)?;
                let Ok(permit) = connections.try_request() else {
                    state.log_rejection(Problem::overloaded());
                    reject_excess_connection(
                        stream,
                        peer,
                        &config.listener,
                        Arc::clone(&state),
                        &connections,
                    );
                    continue;
                };
                serve_accepted(stream, peer, &config.listener, tls.clone(), Arc::clone(&state), permit);
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    return Err(RunError::Listener);
                }
                return Ok(());
            }
        }
    }
}

struct ConnectionAdmission {
    requests: Arc<Semaphore>,
    overloads: Arc<Semaphore>,
    #[cfg(test)]
    retained: Arc<std::sync::atomic::AtomicUsize>,
}

impl ConnectionAdmission {
    fn new(total: usize, listener: &ListenerConfig) -> Self {
        let overload =
            usize::from(total > 1 && matches!(listener, ListenerConfig::TrustedProxy { .. }));
        Self {
            requests: Arc::new(Semaphore::new(total.saturating_sub(overload))),
            overloads: Arc::new(Semaphore::new(overload)),
            #[cfg(test)]
            retained: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn try_request(&self) -> Result<RetainedConnectionPermit, ()> {
        let permit = Arc::clone(&self.requests)
            .try_acquire_owned()
            .map_err(|_| ())?;
        #[cfg(test)]
        self.retained
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(RetainedConnectionPermit {
            _permit: permit,
            #[cfg(test)]
            retained: Arc::clone(&self.retained),
        })
    }

    fn try_overload(&self) -> Result<RetainedConnectionPermit, ()> {
        let permit = Arc::clone(&self.overloads)
            .try_acquire_owned()
            .map_err(|_| ())?;
        #[cfg(test)]
        self.retained
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(RetainedConnectionPermit {
            _permit: permit,
            #[cfg(test)]
            retained: Arc::clone(&self.retained),
        })
    }

    #[cfg(test)]
    fn retained(&self) -> usize {
        self.retained.load(std::sync::atomic::Ordering::SeqCst)
    }
}

struct RetainedConnectionPermit {
    _permit: OwnedSemaphorePermit,
    #[cfg(test)]
    retained: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for RetainedConnectionPermit {
    fn drop(&mut self) {
        #[cfg(test)]
        self.retained
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn reject_excess_connection(
    stream: TcpStream,
    peer: SocketAddr,
    listener: &ListenerConfig,
    state: Arc<AppState>,
    connections: &ConnectionAdmission,
) {
    // A direct listener cannot emit HTTP until the TLS handshake completes.
    // One reserved responder lets an authenticated proxy receive a stable 429
    // while preserving a hard bound under a connection flood.
    let trusted_proxy = matches!(
        listener,
        ListenerConfig::TrustedProxy { proxy_address } if peer.ip() == *proxy_address
    );
    if !trusted_proxy {
        return;
    }
    let Ok(permit) = connections.try_overload() else {
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        let mut stream = stream;
        let drained = tokio::time::timeout(
            state.limits.io_deadline,
            drain_request_for_rejection(&mut stream, &state.limits),
        )
        .await;
        if matches!(drained, Ok(Ok(()))) {
            let response = problem_response(Problem::overloaded());
            let _ = tokio::time::timeout(
                state.limits.io_deadline,
                write_response(&mut stream, response),
            )
            .await;
        }
    });
}

async fn drain_request_for_rejection(
    stream: &mut TcpStream,
    limits: &RuntimeLimits,
) -> Result<(), Problem> {
    let (parts, initial) = read_request_head(stream, limits).await?;
    let mut lengths = parts.headers.get_all(CONTENT_LENGTH).iter();
    let length = lengths
        .next()
        .and_then(parse_content_length)
        .ok_or_else(Problem::malformed)?;
    if lengths.next().is_some() || length > limits.invocation_request_bytes {
        return Err(Problem::malformed());
    }
    if initial.len() > length {
        return Err(Problem::malformed());
    }
    let mut remaining = length.saturating_sub(initial.len());
    let mut buffer = [0_u8; 8192];
    while remaining != 0 {
        let chunk_length = remaining.min(buffer.len());
        let target = buffer
            .get_mut(..chunk_length)
            .ok_or_else(Problem::internal)?;
        let read = stream
            .read(target)
            .await
            .map_err(|_| Problem::malformed())?;
        if read == 0 {
            return Err(Problem::malformed());
        }
        remaining = remaining.saturating_sub(read);
    }
    Ok(())
}

fn serve_accepted(
    stream: TcpStream,
    peer: SocketAddr,
    listener: &ListenerConfig,
    tls: Option<TlsAcceptor>,
    state: Arc<AppState>,
    permit: RetainedConnectionPermit,
) {
    match listener {
        ListenerConfig::DirectTls { .. } => {
            let Some(acceptor) = tls else {
                state.log_rejection(Problem::internal());
                return;
            };
            tokio::spawn(async move {
                let _permit = permit;
                let accepted =
                    tokio::time::timeout(state.limits.io_deadline, acceptor.accept(stream)).await;
                if let Ok(Ok(stream)) = accepted {
                    serve_http(stream, peer, SourceMode::Direct, state).await;
                }
            });
        }
        ListenerConfig::TrustedProxy { proxy_address } => {
            if peer.ip() != *proxy_address {
                state.log_rejection(Problem::malformed());
                return;
            }
            tokio::spawn(async move {
                let _permit = permit;
                serve_http(stream, peer, SourceMode::Proxy, state).await;
            });
        }
    }
}

async fn serve_http<I>(io: I, peer: SocketAddr, mode: SourceMode, state: Arc<AppState>)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut io = io;
    let response = match tokio::time::timeout(
        state.limits.io_deadline,
        read_request_head(&mut io, &state.limits),
    )
    .await
    {
        Ok(Ok((parts, initial_body))) => match prepare_request(&parts, peer, mode, &state) {
            Ok(prepared) => {
                let length = prepared.content_length;
                match tokio::time::timeout(
                    state.limits.io_deadline,
                    read_request_body(&mut io, initial_body, length),
                )
                .await
                {
                    Ok(Ok(body)) => dispatch(prepared, body, &state).await,
                    Ok(Err(problem)) => problem_response(problem),
                    Err(_) => problem_response(Problem::timeout_before()),
                }
            }
            Err(problem) => problem_response(problem),
        },
        Ok(Err(problem)) => problem_response(problem),
        Err(_) => problem_response(Problem::timeout_before()),
    };
    if !response.status().is_success() {
        let problem = problem_from_response(&response);
        state.log_rejection(problem);
    }
    let _ = tokio::time::timeout(state.limits.io_deadline, write_response(&mut io, response)).await;
}

async fn read_request_head<I>(
    io: &mut I,
    limits: &RuntimeLimits,
) -> Result<(hyper::http::request::Parts, Bytes), Problem>
where
    I: AsyncRead + Unpin,
{
    let maximum = limits
        .header_bytes
        .checked_add(MAX_REQUEST_LINE_BYTES + 4)
        .ok_or_else(Problem::too_large)?;
    let mut bytes = Vec::with_capacity(maximum);
    let header_end = loop {
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        let remaining = maximum.saturating_sub(bytes.len());
        if remaining == 0 {
            return Err(Problem::too_large());
        }
        let mut buffer = [0_u8; 1024];
        let chunk_length = remaining.min(buffer.len());
        let target = buffer
            .get_mut(..chunk_length)
            .ok_or_else(Problem::internal)?;
        let read = io.read(target).await.map_err(|_| Problem::malformed())?;
        if read == 0 {
            return Err(Problem::malformed());
        }
        let source = target.get(..read).ok_or_else(Problem::internal)?;
        bytes.extend_from_slice(source);
    };

    let head = bytes.get(..header_end).ok_or_else(Problem::internal)?;
    let mut parsed_headers = [httparse::EMPTY_HEADER; MAX_HEADER_COUNT + 1];
    let mut parsed = httparse::Request::new(&mut parsed_headers);
    match parsed.parse(head) {
        Ok(httparse::Status::Complete(consumed)) if consumed == header_end => {}
        Err(httparse::Error::TooManyHeaders) => return Err(Problem::too_large()),
        _ => return Err(Problem::malformed()),
    }
    if parsed.version != Some(1) {
        return Err(Problem::malformed());
    }
    let method = parsed
        .method
        .and_then(|value| Method::from_bytes(value.as_bytes()).ok())
        .ok_or_else(Problem::malformed)?;
    let target = parsed.path.ok_or_else(Problem::malformed)?;
    let uri = parse_origin_target(target)?;
    let mut headers = HeaderMap::with_capacity(parsed.headers.len());
    for header in parsed.headers {
        let name =
            HeaderName::from_bytes(header.name.as_bytes()).map_err(|_| Problem::malformed())?;
        let value = HeaderValue::from_bytes(header.value).map_err(|_| Problem::malformed())?;
        headers.append(name, value);
    }
    let mut request = Request::new(());
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_11;
    *request.headers_mut() = headers;
    let (parts, ()) = request.into_parts();
    let initial = bytes
        .get(header_end..)
        .map_or_else(Bytes::new, Bytes::copy_from_slice);
    Ok((parts, initial))
}

fn parse_origin_target(target: &str) -> Result<Uri, Problem> {
    if !target.starts_with('/')
        || target.starts_with("//")
        || target.as_bytes().contains(&b'?')
        || target.as_bytes().contains(&b'#')
    {
        return Err(Problem::malformed());
    }
    let uri = Uri::try_from(target).map_err(|_| Problem::malformed())?;
    if uri.scheme().is_some() || uri.authority().is_some() || uri.query().is_some() {
        return Err(Problem::malformed());
    }
    Ok(uri)
}

async fn read_request_body<I>(io: &mut I, initial: Bytes, length: usize) -> Result<Bytes, Problem>
where
    I: AsyncRead + Unpin,
{
    if initial.len() > length {
        return Err(Problem::malformed());
    }
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|_| Problem::internal())?;
    body.extend_from_slice(&initial);
    while body.len() < length {
        let remaining = length.saturating_sub(body.len());
        let mut buffer = [0_u8; 8192];
        let chunk_length = remaining.min(buffer.len());
        let target = buffer
            .get_mut(..chunk_length)
            .ok_or_else(Problem::internal)?;
        let read = io.read(target).await.map_err(|_| Problem::malformed())?;
        if read == 0 {
            return Err(Problem::malformed());
        }
        let source = target.get(..read).ok_or_else(Problem::internal)?;
        body.extend_from_slice(source);
    }
    Ok(Bytes::from(body))
}

async fn write_response<I>(io: &mut I, response: Response<Full<Bytes>>) -> std::io::Result<()>
where
    I: AsyncWrite + Unpin,
{
    let (parts, body) = response.into_parts();
    let body = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(never) => match never {},
    };
    let reason = parts
        .status
        .canonical_reason()
        .map_or("Error", |value| value);
    let mut head = String::new();
    write!(&mut head, "HTTP/1.1 {} {reason}\r\n", parts.status.as_u16())
        .map_err(|_| std::io::Error::other("response rendering failed"))?;
    for (name, value) in &parts.headers {
        let value = value
            .to_str()
            .map_err(|_| std::io::Error::other("response rendering failed"))?;
        head.push_str(name.as_str());
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    write!(&mut head, "content-length: {}\r\n\r\n", body.len())
        .map_err(|_| std::io::Error::other("response rendering failed"))?;
    io.write_all(head.as_bytes()).await?;
    io.write_all(&body).await?;
    io.shutdown().await
}

#[derive(Clone, Copy)]
enum SourceMode {
    Direct,
    Proxy,
}

#[derive(Clone, Copy, Debug)]
enum Route {
    Challenge,
    Invoke,
}

struct PreparedRequest {
    route: Route,
    source: IpAddr,
    content_length: usize,
    _permit: OwnedSemaphorePermit,
}

fn prepare_request(
    parts: &hyper::http::request::Parts,
    peer: SocketAddr,
    mode: SourceMode,
    state: &Arc<AppState>,
) -> Result<PreparedRequest, Problem> {
    validate_headers(parts, &state.limits)?;
    let source = derive_source(&parts.headers, peer, mode)?;
    if let Some(bearer) = &state.bearer {
        let mut authorization = parts.headers.get_all(AUTHORIZATION).iter();
        let value = authorization.next();
        if authorization.next().is_some() {
            return Err(Problem::unauthenticated());
        }
        bearer.verify(value)?;
    }
    let route = classify_route(&parts.method, parts.uri.path())?;
    let content_length = validate_media_and_length(&parts.headers, route, &state.limits)?;
    state.admit_source(source)?;
    let permit = Arc::clone(&state.in_flight)
        .try_acquire_owned()
        .map_err(|_| Problem::overloaded())?;
    Ok(PreparedRequest {
        route,
        source,
        content_length,
        _permit: permit,
    })
}

fn validate_headers(
    parts: &hyper::http::request::Parts,
    limits: &RuntimeLimits,
) -> Result<(), Problem> {
    if parts.headers.len() > limits.header_count {
        return Err(Problem::too_large());
    }
    let mut bytes = 0_usize;
    for (name, value) in &parts.headers {
        bytes = bytes
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
            .and_then(|total| total.checked_add(4))
            .ok_or_else(Problem::too_large)?;
    }
    // The per-instance configured byte limit is checked by Hyper's buffer and
    // again in prepare_request, where the exact configured value is available.
    if bytes > limits.header_bytes {
        return Err(Problem::too_large());
    }
    if parts.headers.contains_key(TRANSFER_ENCODING) {
        return Err(Problem::malformed());
    }
    if parts.headers.contains_key(UPGRADE) {
        return Err(Problem::malformed());
    }
    Ok(())
}

fn configured_header_bytes(headers: &hyper::HeaderMap, maximum: usize) -> Result<(), Problem> {
    let mut bytes = 0_usize;
    for (name, value) in headers {
        bytes = bytes
            .checked_add(name.as_str().len() + value.as_bytes().len() + 4)
            .ok_or_else(Problem::too_large)?;
        if bytes > maximum {
            return Err(Problem::too_large());
        }
    }
    Ok(())
}

fn derive_source(
    headers: &hyper::HeaderMap,
    peer: SocketAddr,
    mode: SourceMode,
) -> Result<IpAddr, Problem> {
    match mode {
        SourceMode::Direct => {
            if headers.contains_key(&SOURCE_HEADER)
                || headers.contains_key(&FORWARDED_HEADER)
                || headers.contains_key(&REAL_IP_HEADER)
            {
                Err(Problem::malformed())
            } else {
                Ok(peer.ip())
            }
        }
        SourceMode::Proxy => {
            if headers.contains_key(&FORWARDED_HEADER) || headers.contains_key(&REAL_IP_HEADER) {
                return Err(Problem::malformed());
            }
            let mut values = headers.get_all(&SOURCE_HEADER).iter();
            let value = values.next().ok_or_else(Problem::malformed)?;
            if values.next().is_some() {
                return Err(Problem::malformed());
            }
            let text = value.to_str().map_err(|_| Problem::malformed())?;
            let source: IpAddr = text.parse().map_err(|_| Problem::malformed())?;
            if source.to_string() != text {
                return Err(Problem::malformed());
            }
            Ok(source)
        }
    }
}

fn classify_route(method: &Method, path: &str) -> Result<Route, Problem> {
    match path {
        "/v1/challenge" if method == Method::POST => Ok(Route::Challenge),
        "/v1/invoke" if method == Method::POST => Ok(Route::Invoke),
        "/v1/challenge" | "/v1/invoke" => Err(Problem::method_not_allowed()),
        _ => Err(Problem::not_found()),
    }
}

fn validate_media_and_length(
    headers: &hyper::HeaderMap,
    route: Route,
    limits: &RuntimeLimits,
) -> Result<usize, Problem> {
    configured_header_bytes(headers, limits.header_bytes)?;
    for encoding in headers.get_all(CONTENT_ENCODING) {
        if encoding.as_bytes() != b"identity" {
            return Err(Problem::unsupported_media());
        }
    }
    let expected_type = match route {
        Route::Challenge => b"application/protobuf".as_slice(),
        Route::Invoke => b"application/cose".as_slice(),
    };
    let mut content_types = headers.get_all(CONTENT_TYPE).iter();
    if content_types.next().map(HeaderValue::as_bytes) != Some(expected_type)
        || content_types.next().is_some()
    {
        return Err(Problem::unsupported_media());
    }
    let mut lengths = headers.get_all(CONTENT_LENGTH).iter();
    let length = lengths
        .next()
        .and_then(parse_content_length)
        .ok_or_else(Problem::malformed)?;
    if lengths.next().is_some() {
        return Err(Problem::malformed());
    }
    let maximum = match route {
        Route::Challenge => limits.challenge_body_bytes,
        Route::Invoke => limits.invocation_request_bytes,
    };
    if length > maximum {
        return Err(Problem::too_large());
    }
    Ok(length)
}

fn parse_content_length(value: &HeaderValue) -> Option<usize> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

async fn dispatch(
    prepared: PreparedRequest,
    body: Bytes,
    state: &Arc<AppState>,
) -> Response<Full<Bytes>> {
    match prepared.route {
        Route::Challenge => dispatch_challenge(body, prepared.source, state).await,
        Route::Invoke => dispatch_invoke(body, state).await,
    }
}

async fn dispatch_challenge(
    body: Bytes,
    source: IpAddr,
    state: &Arc<AppState>,
) -> Response<Full<Bytes>> {
    let Ok(request) = GetInvocationChallengeRequest::decode(body) else {
        return problem_response(Problem::malformed());
    };
    if request.courier_observed_source.is_some() {
        return problem_response(Problem::malformed());
    }
    let client = state.challenge_client.clone();
    match client.get_challenge(request, &source.to_string()).await {
        Ok(response) => {
            let encoded = response.encode_to_vec();
            if encoded.len() > state.limits.challenge_body_bytes {
                problem_response(Problem::internal())
            } else {
                success_response("application/protobuf", Bytes::from(encoded))
            }
        }
        Err(error) => problem_response(Problem::from_courier(error)),
    }
}

async fn dispatch_invoke(body: Bytes, state: &Arc<AppState>) -> Response<Full<Bytes>> {
    let client = state.invoke_client.clone();
    match client
        .invoke(SealedRequest {
            message: body.to_vec(),
        })
        .await
    {
        Ok(response) => {
            if response.response_subject.is_some() {
                return problem_response(Problem::internal());
            }
            if response.message.len() > state.limits.invocation_response_bytes {
                problem_response(Problem::too_large())
            } else {
                success_response("application/cose", Bytes::from(response.message))
            }
        }
        Err(error) => problem_response(Problem::from_courier(error)),
    }
}

fn success_response(content_type: &'static str, body: Bytes) -> Response<Full<Bytes>> {
    response(StatusCode::OK, content_type, body)
}

fn problem_response(problem: Problem) -> Response<Full<Bytes>> {
    let retryable = if problem.retryable { "true" } else { "false" };
    let rendered = format!(
        "{{\"code\":\"{}\",\"retryable\":{retryable}}}",
        problem.code
    );
    let body = if rendered.len() <= PROBLEM_BODY_LIMIT {
        Bytes::from(rendered)
    } else {
        Bytes::from_static(b"{\"code\":\"INTERNAL\",\"retryable\":false}")
    };
    response(problem.status, "application/problem+json", body)
}

fn response(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("close"));
    response
}

fn problem_from_response(response: &Response<Full<Bytes>>) -> Problem {
    match response.status() {
        StatusCode::BAD_REQUEST => Problem::malformed(),
        StatusCode::UNAUTHORIZED => Problem::unauthenticated(),
        StatusCode::NOT_FOUND => Problem::not_found(),
        StatusCode::METHOD_NOT_ALLOWED => Problem::method_not_allowed(),
        StatusCode::PAYLOAD_TOO_LARGE => Problem::too_large(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => Problem::unsupported_media(),
        StatusCode::TOO_MANY_REQUESTS => Problem::overloaded(),
        StatusCode::BAD_GATEWAY => Problem::new(StatusCode::BAD_GATEWAY, "BASIL_REJECTED", false),
        StatusCode::SERVICE_UNAVAILABLE => {
            Problem::new(StatusCode::SERVICE_UNAVAILABLE, "BASIL_UNAVAILABLE", false)
        }
        StatusCode::GATEWAY_TIMEOUT => Problem::new(StatusCode::GATEWAY_TIMEOUT, "TIMEOUT", false),
        _ => Problem::internal(),
    }
}

#[derive(Clone, Copy, Debug)]
struct Problem {
    status: StatusCode,
    code: &'static str,
    retryable: bool,
}

impl Problem {
    const fn new(status: StatusCode, code: &'static str, retryable: bool) -> Self {
        Self {
            status,
            code,
            retryable,
        }
    }

    const fn malformed() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "MALFORMED_REQUEST", false)
    }

    const fn unauthenticated() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "UNAUTHENTICATED", false)
    }

    const fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", false)
    }

    const fn method_not_allowed() -> Self {
        Self::new(StatusCode::METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED", false)
    }

    const fn too_large() -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "MESSAGE_TOO_LARGE", false)
    }

    const fn unsupported_media() -> Self {
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            false,
        )
    }

    const fn overloaded() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "OVERLOADED", true)
    }

    const fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", false)
    }

    const fn timeout_before() -> Self {
        Self::new(StatusCode::GATEWAY_TIMEOUT, "TIMEOUT", true)
    }

    const fn from_courier(error: CourierCallError) -> Self {
        let status = match error {
            CourierCallError::InvalidRequest => StatusCode::BAD_REQUEST,
            CourierCallError::CapabilityMismatch
            | CourierCallError::UnavailableBeforeForward
            | CourierCallError::UnavailableAfterForward => StatusCode::SERVICE_UNAVAILABLE,
            CourierCallError::ChallengeDeclined => StatusCode::TOO_MANY_REQUESTS,
            CourierCallError::BrokerRejected => StatusCode::BAD_GATEWAY,
            CourierCallError::DeadlineBeforeForward | CourierCallError::DeadlineAfterForward => {
                StatusCode::GATEWAY_TIMEOUT
            }
        };
        Self::new(status, error.code(), error.retryable())
    }
}

struct AppState {
    limits: RuntimeLimits,
    bearer: Option<Bearer>,
    challenge_client: InvocationCourierClient,
    invoke_client: InvocationCourierClient,
    in_flight: Arc<Semaphore>,
    admission: Mutex<Admission>,
    rejection_log: Mutex<TokenBucket>,
}

impl AppState {
    fn new(
        limits: &Limits,
        bearer: Option<Bearer>,
        challenge_client: InvocationCourierClient,
        invoke_client: InvocationCourierClient,
    ) -> Self {
        let runtime = RuntimeLimits::from(limits);
        Self {
            limits: runtime,
            bearer,
            challenge_client,
            invoke_client,
            in_flight: Arc::new(Semaphore::new(limits.in_flight)),
            admission: Mutex::new(Admission::new(limits)),
            rejection_log: Mutex::new(TokenBucket::new(10, 20)),
        }
    }

    fn admit_source(&self, source: IpAddr) -> Result<(), Problem> {
        self.admission
            .lock()
            .map_err(|_| Problem::internal())?
            .admit(source)
    }

    fn log_rejection(&self, problem: Problem) {
        let should_log = self
            .rejection_log
            .lock()
            .is_ok_and(|mut bucket| bucket.take());
        if should_log {
            tracing::warn!(
                code = problem.code,
                retryable = problem.retryable,
                "courier request rejected"
            );
        }
    }
}

#[derive(Clone)]
struct RuntimeLimits {
    challenge_body_bytes: usize,
    invocation_request_bytes: usize,
    invocation_response_bytes: usize,
    header_count: usize,
    header_bytes: usize,
    io_deadline: Duration,
}

impl From<&Limits> for RuntimeLimits {
    fn from(value: &Limits) -> Self {
        Self {
            challenge_body_bytes: value.challenge_body_bytes,
            invocation_request_bytes: value.invocation_request_bytes,
            invocation_response_bytes: value.invocation_response_bytes,
            header_count: value.header_count,
            header_bytes: value.header_bytes,
            io_deadline: Duration::from_secs(value.io_deadline_seconds),
        }
    }
}

struct Admission {
    global: TokenBucket,
    per_source_rate: u32,
    per_source_burst: u32,
    maximum_sources: usize,
    sources: HashMap<IpAddr, TokenBucket>,
}

impl Admission {
    fn new(limits: &Limits) -> Self {
        Self {
            global: TokenBucket::new(limits.global_rate, limits.global_burst),
            per_source_rate: limits.per_source_rate,
            per_source_burst: limits.per_source_burst,
            maximum_sources: limits.source_buckets,
            sources: HashMap::with_capacity(limits.source_buckets.min(4096)),
        }
    }

    fn admit(&mut self, source: IpAddr) -> Result<(), Problem> {
        if !self.global.take() {
            return Err(Problem::overloaded());
        }
        if !self.sources.contains_key(&source) {
            if self.sources.len() >= self.maximum_sources {
                return Err(Problem::overloaded());
            }
            self.sources.insert(
                source,
                TokenBucket::new(self.per_source_rate, self.per_source_burst),
            );
        }
        if self
            .sources
            .get_mut(&source)
            .is_none_or(|bucket| !bucket.take())
        {
            return Err(Problem::overloaded());
        }
        Ok(())
    }
}

struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate: f64::from(rate),
            capacity: f64::from(burst),
            tokens: f64::from(burst),
            last: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = now
            .duration_since(self.last)
            .as_secs_f64()
            .mul_add(self.rate, self.tokens)
            .min(self.capacity);
        self.last = now;
        if self.tokens < 1.0 {
            false
        } else {
            self.tokens -= 1.0;
            true
        }
    }
}

struct Bearer {
    bytes: Zeroizing<[u8; MAX_BEARER_BYTES]>,
    length: usize,
}

impl Bearer {
    async fn from_path(path: &Path) -> Result<Self, ConfigError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            Err(ConfigError::InvalidBearer)
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{Mode, OFlags, fstat, open};

            let fd = open(
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| ConfigError::InvalidBearer)?;
            let stat = fstat(&fd).map_err(|_| ConfigError::InvalidBearer)?;
            if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file()
                || stat.st_uid != rustix::process::geteuid().as_raw()
                || stat.st_nlink != 1
                || stat.st_mode & 0o077 != 0
                || stat.st_mode & 0o400 == 0
            {
                return Err(ConfigError::InvalidBearer);
            }
            let std_file = std::fs::File::from(fd);
            let file = tokio::fs::File::from_std(std_file);
            let mut value = Zeroizing::new(Vec::with_capacity(MAX_BEARER_BYTES + 1));
            file.take(u64::try_from(MAX_BEARER_BYTES + 1).map_err(|_| ConfigError::InvalidBearer)?)
                .read_to_end(&mut value)
                .await
                .map_err(|_| ConfigError::InvalidBearer)?;
            if value.last() == Some(&b'\n') {
                value.pop();
            }
            if value.is_empty()
                || value.len() > MAX_BEARER_BYTES
                || value
                    .iter()
                    .any(|byte| byte.is_ascii_whitespace() || *byte == 0)
            {
                return Err(ConfigError::InvalidBearer);
            }
            let mut bytes = Zeroizing::new([0_u8; MAX_BEARER_BYTES]);
            bytes
                .get_mut(..value.len())
                .ok_or(ConfigError::InvalidBearer)?
                .copy_from_slice(&value);
            Ok(Self {
                bytes,
                length: value.len(),
            })
        }
    }

    fn verify(&self, authorization: Option<&HeaderValue>) -> Result<(), Problem> {
        let value = authorization
            .map(HeaderValue::as_bytes)
            .and_then(|value| value.strip_prefix(b"Bearer "))
            .ok_or_else(Problem::unauthenticated)?;
        let mut candidate = Zeroizing::new([0_u8; MAX_BEARER_BYTES]);
        let copy_length = value.len().min(MAX_BEARER_BYTES);
        if let (Some(target), Some(source)) =
            (candidate.get_mut(..copy_length), value.get(..copy_length))
        {
            target.copy_from_slice(source);
        }
        let bytes_match = self.bytes.ct_eq(&*candidate);
        let lengths_match = self.length.ct_eq(&value.len());
        if bool::from(bytes_match & lengths_match) {
            Ok(())
        } else {
            Err(Problem::unauthenticated())
        }
    }
}

async fn load_tls(listener: &ListenerConfig) -> Result<Option<TlsAcceptor>, ConfigError> {
    let ListenerConfig::DirectTls {
        certificate_file,
        private_key_file,
    } = listener
    else {
        return Ok(None);
    };
    let certificates = read_bounded(certificate_file, MAX_CERTIFICATE_BYTES).await?;
    let private_key = read_private_key(private_key_file).await?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(certificates))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ConfigError::InvalidTls)?;
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(&*private_key))
        .map_err(|_| ConfigError::InvalidTls)?
        .ok_or(ConfigError::InvalidTls)?;
    if certificates.is_empty() {
        return Err(ConfigError::InvalidTls);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| ConfigError::InvalidTls)?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|_| ConfigError::InvalidTls)?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Some(TlsAcceptor::from(Arc::new(server))))
}

async fn read_private_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    read_private_key_with_hook(path, || {}).await
}

#[cfg(target_os = "linux")]
fn validate_private_key_path(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::ffi::OsStrExt as _;

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
        return Err(ConfigError::InvalidTls);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn read_private_key_with_hook(
    path: &Path,
    after_open: impl FnOnce(),
) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    use rustix::fs::{AtFlags, FileType, fstat, statat};

    validate_private_key_path(path)?;
    let (fd, directory, leaf) = open_private_key_descriptor(path)?;
    let before = fstat(&fd).map_err(|_| ConfigError::InvalidTls)?;
    let expected_uid = rustix::process::geteuid().as_raw();
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != expected_uid
        || before.st_nlink != 1
        || before.st_mode & 0o077 != 0
        || before.st_mode & 0o400 == 0
        || before.st_size < 0
        || u64::try_from(before.st_size).map_err(|_| ConfigError::InvalidTls)?
            > MAX_PRIVATE_KEY_BYTES
    {
        return Err(ConfigError::InvalidTls);
    }
    after_open();
    let std_file = std::fs::File::from(fd);
    let file = tokio::fs::File::from_std(std_file);
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(before.st_size).map_err(|_| ConfigError::InvalidTls)?,
    ));
    let mut limited = file.take(MAX_PRIVATE_KEY_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ConfigError::InvalidTls)?;
    let file = limited.into_inner().into_std().await;
    let descriptor_after = fstat(&file).map_err(|_| ConfigError::InvalidTls)?;
    if u64::try_from(bytes.len()).map_err(|_| ConfigError::InvalidTls)? > MAX_PRIVATE_KEY_BYTES {
        return Err(ConfigError::InvalidTls);
    }
    let named_after = statat(&directory, &leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| ConfigError::InvalidTls)?;
    if private_key_identity(&before) != private_key_identity(&descriptor_after)
        || private_key_identity(&before) != private_key_identity(&named_after)
    {
        return Err(ConfigError::InvalidTls);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn open_private_key_descriptor(
    path: &Path,
) -> Result<
    (
        std::os::fd::OwnedFd,
        std::os::fd::OwnedFd,
        std::ffi::OsString,
    ),
    ConfigError,
> {
    use std::path::Component;

    use rustix::fs::{Mode, OFlags, open, openat};

    let components: Vec<_> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect();
    let (leaf, ancestors) = components.split_last().ok_or(ConfigError::InvalidTls)?;
    let directory_flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        open("/", directory_flags, Mode::empty()).map_err(|_| ConfigError::InvalidTls)?;
    for ancestor in ancestors {
        directory = openat(&directory, ancestor, directory_flags, Mode::empty())
            .map_err(|_| ConfigError::InvalidTls)?;
    }
    let file = openat(
        &directory,
        leaf,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ConfigError::InvalidTls)?;
    Ok((file, directory, leaf.clone()))
}

#[cfg(not(target_os = "linux"))]
async fn read_private_key_with_hook(
    path: &Path,
    after_open: impl FnOnce(),
) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    let _ = (path, after_open);
    Err(ConfigError::InvalidTls)
}

#[cfg(target_os = "linux")]
const fn private_key_identity(stat: &rustix::fs::Stat) -> (u64, u64, u32, u32, u32, u64, i64) {
    (
        stat.st_dev,
        stat.st_ino,
        stat.st_uid,
        stat.st_gid,
        stat.st_mode,
        stat.st_nlink,
        stat.st_size,
    )
}

async fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, ConfigError> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|_| ConfigError::Read)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(ConfigError::Read);
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| ConfigError::Read)?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| ConfigError::Read)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| ConfigError::Read)?;
    if u64::try_from(bytes.len()).map_err(|_| ConfigError::Read)? > limit {
        return Err(ConfigError::Read);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;
    use hyper::body::Body;

    use hyper::http::request::Parts;
    #[cfg(target_os = "linux")]
    use std::fs;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[cfg(target_os = "linux")]
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn limits() -> Limits {
        Limits::default()
    }

    fn request_parts(
        method: Method,
        path: &str,
        content_type: &'static str,
        length: usize,
    ) -> Parts {
        let (request, ()) = Request::builder()
            .method(method)
            .uri(path)
            .header(CONTENT_TYPE, content_type)
            .header(CONTENT_LENGTH, length)
            .body(())
            .unwrap()
            .into_parts();
        request
    }

    #[test]
    fn default_and_maximum_limits_are_frozen() {
        let value = limits();
        value.validate().unwrap();
        assert_eq!(value.challenge_body_bytes, 256);
        assert_eq!(value.invocation_request_bytes, 1024 * 1024);
        assert_eq!(value.connections, 128);
        assert_eq!(value.in_flight, 32);
        assert_eq!(value.source_buckets, 4096);

        let mut invalid = value;
        invalid.global_burst = 8193;
        assert!(matches!(invalid.validate(), Err(ConfigError::InvalidLimit)));
        invalid.global_burst = 0;
        assert!(matches!(invalid.validate(), Err(ConfigError::InvalidLimit)));
    }

    #[test]
    fn overload_responder_is_inside_the_exact_connection_ceiling() {
        let proxy = ListenerConfig::TrustedProxy {
            proxy_address: "127.0.0.1".parse().unwrap(),
        };
        let proxy_one = ConnectionAdmission::new(1, &proxy);
        let only_request = proxy_one.try_request().unwrap();
        assert_eq!(proxy_one.retained(), 1);
        assert!(proxy_one.try_request().is_err());
        assert!(proxy_one.try_overload().is_err());
        assert_eq!(proxy_one.retained(), 1);
        drop(only_request);
        assert_eq!(proxy_one.retained(), 0);

        let proxy_many = ConnectionAdmission::new(3, &proxy);
        let first_request = proxy_many.try_request().unwrap();
        let second_request = proxy_many.try_request().unwrap();
        let overload_response = proxy_many.try_overload().unwrap();
        assert_eq!(proxy_many.retained(), 3);
        assert!(proxy_many.try_request().is_err());
        assert!(proxy_many.try_overload().is_err());
        assert_eq!(proxy_many.retained(), 3);
        drop((first_request, second_request, overload_response));
        assert_eq!(proxy_many.retained(), 0);

        let direct = ListenerConfig::DirectTls {
            certificate_file: PathBuf::from("/certificate.pem"),
            private_key_file: PathBuf::from("/private-key.pem"),
        };
        let direct_two = ConnectionAdmission::new(2, &direct);
        let first_request = direct_two.try_request().unwrap();
        let second_request = direct_two.try_request().unwrap();
        assert_eq!(direct_two.retained(), 2);
        assert!(direct_two.try_request().is_err());
        assert!(direct_two.try_overload().is_err());
        assert_eq!(direct_two.retained(), 2);
        drop((first_request, second_request));
        assert_eq!(direct_two.retained(), 0);
    }

    #[test]
    fn only_two_post_routes_exist() {
        assert!(matches!(
            classify_route(&Method::POST, "/v1/challenge"),
            Ok(Route::Challenge)
        ));
        assert!(matches!(
            classify_route(&Method::POST, "/v1/invoke"),
            Ok(Route::Invoke)
        ));
        assert_eq!(
            classify_route(&Method::GET, "/v1/invoke")
                .unwrap_err()
                .status,
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            classify_route(&Method::POST, "/health").unwrap_err().status,
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn request_target_is_exact_origin_form_without_query_or_authority() {
        assert_eq!(
            parse_origin_target("/v1/invoke").unwrap().path(),
            "/v1/invoke"
        );
        for invalid in [
            "/v1/invoke?debug=true",
            "//courier.test/v1/invoke",
            "https://courier.test/v1/invoke",
            "*",
        ] {
            assert_eq!(
                parse_origin_target(invalid).unwrap_err().code,
                "MALFORMED_REQUEST"
            );
        }
    }

    #[test]
    fn framing_media_and_compression_are_closed() {
        let runtime = RuntimeLimits::from(&limits());
        let mut parts = request_parts(Method::POST, "/v1/invoke", "application/cose", 12);
        assert!(validate_headers(&parts, &runtime).is_ok());
        assert!(validate_media_and_length(&parts.headers, Route::Invoke, &runtime).is_ok());

        parts
            .headers
            .insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert_eq!(
            validate_headers(&parts, &runtime).unwrap_err().code,
            "MALFORMED_REQUEST"
        );
        parts.headers.remove(TRANSFER_ENCODING);
        parts
            .headers
            .insert(UPGRADE, HeaderValue::from_static("websocket"));
        assert_eq!(
            validate_headers(&parts, &runtime).unwrap_err().code,
            "MALFORMED_REQUEST"
        );
        parts.headers.remove(UPGRADE);
        parts
            .headers
            .insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert_eq!(
            validate_media_and_length(&parts.headers, Route::Invoke, &runtime)
                .unwrap_err()
                .code,
            "UNSUPPORTED_MEDIA_TYPE"
        );
        parts.headers.remove(CONTENT_ENCODING);
        parts
            .headers
            .insert(CONTENT_LENGTH, HeaderValue::from_static("1048577"));
        assert_eq!(
            validate_media_and_length(&parts.headers, Route::Invoke, &runtime)
                .unwrap_err()
                .code,
            "MESSAGE_TOO_LARGE"
        );
    }

    #[test]
    fn configured_header_bounds_reject_before_body_dispatch() {
        let mut configured = limits();
        configured.header_count = 2;
        configured.header_bytes = 24;
        let runtime = RuntimeLimits::from(&configured);
        let mut parts = request_parts(Method::POST, "/v1/invoke", "application/cose", 1);
        parts
            .headers
            .insert("x-padding", HeaderValue::from_static("padding"));
        let error = validate_headers(&parts, &runtime).unwrap_err();
        assert_eq!(error.code, "MESSAGE_TOO_LARGE");
    }

    #[test]
    fn repeated_content_length_and_content_type_fail_closed() {
        let runtime = RuntimeLimits::from(&limits());
        let mut parts = request_parts(Method::POST, "/v1/invoke", "application/cose", 1);
        parts
            .headers
            .append(CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert_eq!(
            validate_media_and_length(&parts.headers, Route::Invoke, &runtime)
                .unwrap_err()
                .code,
            "MALFORMED_REQUEST"
        );

        let mut parts = request_parts(Method::POST, "/v1/invoke", "application/cose", 1);
        parts
            .headers
            .append(CONTENT_TYPE, HeaderValue::from_static("application/cose"));
        assert_eq!(
            validate_media_and_length(&parts.headers, Route::Invoke, &runtime)
                .unwrap_err()
                .code,
            "UNSUPPORTED_MEDIA_TYPE"
        );
    }

    #[test]
    fn proxy_source_is_single_and_canonical() {
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        assert!(derive_source(&headers, peer, SourceMode::Proxy).is_err());
        headers.insert(&SOURCE_HEADER, HeaderValue::from_static("2001:db8::1"));
        assert_eq!(
            derive_source(&headers, peer, SourceMode::Proxy).unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        headers.insert(&SOURCE_HEADER, HeaderValue::from_static("2001:0db8::1"));
        assert!(derive_source(&headers, peer, SourceMode::Proxy).is_err());
        headers.insert(
            &SOURCE_HEADER,
            HeaderValue::from_static("192.0.2.1, 192.0.2.2"),
        );
        assert!(derive_source(&headers, peer, SourceMode::Proxy).is_err());
        headers.insert(&SOURCE_HEADER, HeaderValue::from_static("192.0.2.1"));
        headers.append(&SOURCE_HEADER, HeaderValue::from_static("192.0.2.2"));
        assert!(derive_source(&headers, peer, SourceMode::Proxy).is_err());
        assert!(derive_source(&headers, peer, SourceMode::Direct).is_err());
    }

    #[tokio::test]
    async fn response_write_and_shutdown_obey_io_deadline_for_slow_reader() {
        let (mut writer, _reader) = tokio::io::duplex(64);
        let response = success_response("application/cose", Bytes::from(vec![7; 1024 * 1024]));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                write_response(&mut writer, response)
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn problem_responses_are_bounded_sanitized_and_no_store() {
        for problem in [
            Problem::malformed(),
            Problem::unauthenticated(),
            Problem::not_found(),
            Problem::method_not_allowed(),
            Problem::too_large(),
            Problem::unsupported_media(),
            Problem::overloaded(),
            Problem::from_courier(CourierCallError::ChallengeDeclined),
            Problem::from_courier(CourierCallError::UnavailableAfterForward),
            Problem::from_courier(CourierCallError::DeadlineBeforeForward),
        ] {
            let response = problem_response(problem);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[CONTENT_TYPE], "application/problem+json");
            assert!(response.body().size_hint().exact().unwrap() <= PROBLEM_BODY_LIMIT as u64);
        }

        let sealed = Bytes::from_static(b"\xd2\x84opaque-sealed-response");
        let success = success_response("application/cose", sealed.clone());
        assert_eq!(success.headers()[CACHE_CONTROL], "no-store");
        assert_eq!(
            success.body().size_hint().exact(),
            Some(sealed.len() as u64)
        );
    }

    #[test]
    fn rate_and_source_table_pressure_fail_without_queueing() {
        let first: IpAddr = "192.0.2.1".parse().unwrap();
        let second: IpAddr = "192.0.2.2".parse().unwrap();

        let mut per_source = limits();
        per_source.global_burst = 10;
        per_source.per_source_burst = 1;
        let mut admission = Admission::new(&per_source);
        assert!(admission.admit(first).is_ok());
        assert_eq!(admission.admit(first).unwrap_err().code, "OVERLOADED");

        let mut global = limits();
        global.global_burst = 1;
        global.per_source_burst = 10;
        let mut admission = Admission::new(&global);
        assert!(admission.admit(first).is_ok());
        assert_eq!(admission.admit(second).unwrap_err().code, "OVERLOADED");

        let mut table = limits();
        table.global_burst = 10;
        table.per_source_burst = 10;
        table.source_buckets = 1;
        let mut admission = Admission::new(&table);
        assert!(admission.admit(first).is_ok());
        assert_eq!(admission.admit(second).unwrap_err().code, "OVERLOADED");

        let semaphore = Arc::new(Semaphore::new(1));
        let _held = Arc::clone(&semaphore).try_acquire_owned().unwrap();
        assert!(Arc::clone(&semaphore).try_acquire_owned().is_err());
    }

    #[test]
    fn rejection_logging_has_the_documented_burst_bound() {
        let mut bucket = TokenBucket::new(10, 20);
        for _ in 0..20 {
            assert!(bucket.take());
        }
        assert!(!bucket.take());
    }

    #[test]
    fn bearer_comparison_checks_exact_scheme_length_and_bytes() {
        let mut bytes = Zeroizing::new([0_u8; MAX_BEARER_BYTES]);
        bytes[..6].copy_from_slice(b"secret");
        let bearer = Bearer { bytes, length: 6 };
        assert!(
            bearer
                .verify(Some(&HeaderValue::from_static("Bearer secret")))
                .is_ok()
        );
        for invalid in ["Bearer secreu", "Bearer secretx", "Basic secret", "Bearer"] {
            assert_eq!(
                bearer
                    .verify(Some(&HeaderValue::from_str(invalid).unwrap()))
                    .unwrap_err()
                    .code,
                "UNAUTHENTICATED"
            );
        }
        assert!(bearer.verify(None).is_err());
    }

    #[test]
    fn retry_classification_is_phase_aware() {
        let before = Problem::from_courier(CourierCallError::UnavailableBeforeForward);
        let after = Problem::from_courier(CourierCallError::UnavailableAfterForward);
        assert!(before.retryable);
        assert!(!after.retryable);
        assert_eq!(before.code, after.code);
        assert!(Problem::from_courier(CourierCallError::ChallengeDeclined).retryable);
    }

    #[test]
    fn trusted_proxy_requires_loopback_and_bearer() {
        let basil = BasilSocketConfig {
            socket_path: PathBuf::from("/run/basil/courier.sock"),
            service_owner_uid: 991,
            directory_owner_uid: 991,
            directory_mode: 0o750,
            socket_owner_uid: 990,
            socket_mode: 0o660,
            expected_peer_uid: 990,
        };
        let mut config = Config {
            bind: "127.0.0.1:8443".parse().unwrap(),
            listener: ListenerConfig::TrustedProxy {
                proxy_address: "127.0.0.1".parse().unwrap(),
            },
            basil,
            bearer_file: None,
            limits: limits(),
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidListener)
        ));
        config.bearer_file = Some(PathBuf::from("/run/credentials/bearer"));
        assert!(config.validate().is_ok());
        config.bind = "0.0.0.0:8443".parse().unwrap();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidListener)
        ));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn direct_tls_loads_a_rustls_http1_identity() {
        let (root, certificate_file, private_key_file) = tls_key_fixture();
        let listener = ListenerConfig::DirectTls {
            certificate_file,
            private_key_file,
        };
        assert!(load_tls(&listener).await.unwrap().is_some());
        let proxy = ListenerConfig::TrustedProxy {
            proxy_address: "127.0.0.1".parse().unwrap(),
        };
        assert!(load_tls(&proxy).await.unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn private_key_loader_rejects_path_near_misses_and_replacement() {
        assert!(matches!(
            read_private_key(Path::new("relative-key.pem")).await,
            Err(ConfigError::InvalidTls)
        ));

        let (root, _certificate, key) = tls_key_fixture();
        for path in [
            PathBuf::from(format!("{}//key.pem", root.display())),
            PathBuf::from(format!("{}/./key.pem", root.display())),
            PathBuf::from(format!("{}/real/../key.pem", root.display())),
            PathBuf::from(format!("{}/key.pem/", root.display())),
        ] {
            assert!(matches!(
                read_private_key(&path).await,
                Err(ConfigError::InvalidTls)
            ));
        }
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_private_key(&key).await,
            Err(ConfigError::InvalidTls)
        ));
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join("key-link.pem");
        symlink(&key, &link).unwrap();
        assert!(matches!(
            read_private_key(&link).await,
            Err(ConfigError::InvalidTls)
        ));

        let hard_link = root.join("hard-link.pem");
        fs::hard_link(&key, &hard_link).unwrap();
        assert!(matches!(
            read_private_key(&key).await,
            Err(ConfigError::InvalidTls)
        ));
        fs::remove_file(&hard_link).unwrap();

        let real_directory = root.join("real");
        fs::create_dir(&real_directory).unwrap();
        let nested_key = real_directory.join("key.pem");
        fs::copy(&key, &nested_key).unwrap();
        fs::set_permissions(&nested_key, fs::Permissions::from_mode(0o600)).unwrap();
        let directory_link = root.join("directory-link");
        symlink(&real_directory, &directory_link).unwrap();
        assert!(matches!(
            read_private_key(&directory_link.join("key.pem")).await,
            Err(ConfigError::InvalidTls)
        ));

        let moved = root.join("original-key.pem");
        let replacement_bytes = fs::read(&key).unwrap();
        let result = read_private_key_with_hook(&key, || {
            fs::rename(&key, &moved).unwrap();
            fs::write(&key, replacement_bytes).unwrap();
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        })
        .await;
        assert!(matches!(result, Err(ConfigError::InvalidTls)));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn tls_key_fixture() -> (PathBuf, PathBuf, PathBuf) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        let uid = rustix::process::geteuid().as_raw();
        let root = PathBuf::from(format!("/run/user/{uid}")).join(format!(
            ".https-key-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let testdata = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../basil-core/testdata");
        let certificate = testdata.join("registry_tls_cert.pem");
        let key = root.join("key.pem");
        fs::copy(testdata.join("registry_tls_key.pem"), &key).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        (root, certificate, key)
    }
}
