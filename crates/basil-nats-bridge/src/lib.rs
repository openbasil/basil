// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! NATS request/reply courier for Basil sealed invocation messages.
//!
//! The bridge treats invocation messages as opaque tagged `COSE` bytes. It
//! validates only transport shape, wraps bytes in [`SealedRequest`] for Basil's
//! invocation service, and never parses, decrypts, or authorizes actor payloads
//! locally.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use basil_proto::broker::v1::invocation_service_client::InvocationServiceClient;
use basil_proto::broker::v1::{SealedRequest, SealedResponse};
use bytes::Bytes;
use futures::StreamExt;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::time::timeout;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Status};
use tower::service_fn;
use tracing::{debug, info, warn};

/// NATS header carrying the stable bridge error token.
pub const ERROR_HEADER: &str = "Basil-Bridge-Error";
/// NATS header carrying bridge error detail intended for logs/operators.
pub const MESSAGE_HEADER: &str = "Basil-Bridge-Message";
/// NATS header carrying `true` when the caller may retry unchanged.
pub const RETRYABLE_HEADER: &str = "Basil-Bridge-Retryable";

const DEFAULT_BASIL_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_ALLOWED_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

/// Command-line arguments for the `basil-nats-bridge` binary.
#[derive(Debug, clap::Parser)]
#[command(version, about = "NATS courier for Basil sealed invocation envelopes")]
pub struct Args {
    /// Path to bridge TOML config.
    #[arg(short, long, env = "BASIL_NATS_BRIDGE_CONFIG")]
    pub config: PathBuf,
}

/// Returns the fully assembled top-level clap [`Command`](clap::Command) for the
/// `basil-nats-bridge` binary, for tooling such as man-page generation.
#[must_use]
pub fn cli() -> clap::Command {
    <Args as clap::CommandFactory>::command()
}

/// Bridge configuration loaded from TOML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// NATS connection settings.
    pub nats: NatsConfig,
    /// Basil socket settings.
    pub basil: BasilConfig,
    /// Bridge routing and bounds settings.
    pub bridge: BridgeConfig,
}

/// NATS connection settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatsConfig {
    /// NATS server URL.
    pub url: String,
    /// Optional NATS credentials file.
    pub creds: Option<PathBuf>,
}

/// Basil broker socket settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasilConfig {
    /// Unix-domain socket path for the Basil broker.
    pub socket: PathBuf,
}

/// Bridge routing and request size settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeConfig {
    /// NATS subject accepting sealed invocation request bytes.
    pub request_subject: String,
    /// Optional NATS queue group for shared bridge workers.
    pub queue_group: Option<String>,
    /// Maximum accepted NATS payload size in bytes.
    pub max_message_bytes: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawConfig {
    nats: RawNatsConfig,
    basil: RawBasilConfig,
    bridge: RawBridgeConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawNatsConfig {
    url: String,
    creds: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawBasilConfig {
    socket: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RawBridgeConfig {
    request_subject: String,
    queue_group: Option<String>,
    max_message_bytes: usize,
}

impl Config {
    /// Parse and validate bridge configuration from TOML bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when TOML is malformed, a required field is empty, or
    /// `max-message-bytes` is outside the supported bounds.
    pub fn from_toml_str(input: &str) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(input)?;
        Self::try_from(raw)
    }

    /// Read, parse, and validate bridge configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or validation fails.
    pub async fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let bytes = tokio::fs::read_to_string(path).await?;
        Self::from_toml_str(&bytes)
    }
}

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        let nats_url = non_empty(&raw.nats.url, "nats.url")?;
        let creds = raw
            .nats
            .creds
            .map(|path| non_empty_path(path, "nats.creds"))
            .transpose()?;
        let socket = non_empty_path(raw.basil.socket, "basil.socket")?;
        let request_subject = non_empty(&raw.bridge.request_subject, "bridge.request-subject")?;
        let queue_group = raw
            .bridge
            .queue_group
            .map(|value| non_empty(&value, "bridge.queue-group"))
            .transpose()?;
        validate_max_message_bytes(raw.bridge.max_message_bytes)?;

        Ok(Self {
            nats: NatsConfig {
                url: nats_url,
                creds,
            },
            basil: BasilConfig { socket },
            bridge: BridgeConfig {
                request_subject,
                queue_group,
                max_message_bytes: raw.bridge.max_message_bytes,
            },
        })
    }
}

fn non_empty(value: &str, field: &'static str) -> Result<String, ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::EmptyField(field));
    }
    Ok(trimmed.to_owned())
}

fn non_empty_path(path: PathBuf, field: &'static str) -> Result<PathBuf, ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::EmptyField(field));
    }
    Ok(path)
}

const fn validate_max_message_bytes(value: usize) -> Result<(), ConfigError> {
    if value == 0 {
        return Err(ConfigError::InvalidMaxMessageBytes {
            value,
            max: MAX_ALLOWED_MESSAGE_BYTES,
        });
    }
    if value > MAX_ALLOWED_MESSAGE_BYTES {
        return Err(ConfigError::InvalidMaxMessageBytes {
            value,
            max: MAX_ALLOWED_MESSAGE_BYTES,
        });
    }
    Ok(())
}

/// Configuration parse and validation error.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// TOML syntax or schema error.
    #[error("config TOML is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    /// Config file read error.
    #[error("config file cannot be read: {0}")]
    Io(#[from] std::io::Error),
    /// Required field is empty.
    #[error("config field `{0}` must not be empty")]
    EmptyField(&'static str),
    /// Message size bound is unsupported.
    #[error("`bridge.max-message-bytes` must be in 1..={max}, got {value}")]
    InvalidMaxMessageBytes {
        /// Configured value.
        value: usize,
        /// Maximum supported value.
        max: usize,
    },
}

/// Inbound NATS request metadata and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeRequest {
    /// Request subject the bridge received.
    pub subject: String,
    /// Optional reply subject. Requests without this cannot receive an error.
    pub reply: Option<String>,
    /// Raw tagged `COSE` bytes.
    pub payload: Vec<u8>,
}

/// Outbound bridge action after handling a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeAction {
    /// Publish the reply payload and headers to the subject.
    Reply(BridgeReply),
    /// No reply subject was present; the runtime must not publish.
    NoReply(BridgeErrorReply),
}

/// A NATS reply emitted by the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeReply {
    /// Reply subject supplied by the requester.
    pub subject: String,
    /// Reply payload. Empty for bridge-level errors.
    pub payload: Vec<u8>,
    /// Reply headers. Empty for sealed Basil responses.
    pub headers: BridgeHeaders,
}

/// Small testable header map used before conversion to NATS headers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BridgeHeaders {
    inner: BTreeMap<&'static str, String>,
}

impl BridgeHeaders {
    /// Return an empty header map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return true when no headers are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get a header value by name.
    #[must_use]
    pub fn get(&self, name: &'static str) -> Option<&str> {
        self.inner.get(name).map(String::as_str)
    }

    fn insert(&mut self, name: &'static str, value: impl Into<String>) {
        self.inner.insert(name, value.into());
    }

    fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.inner
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
    }
}

/// Stable bridge-level error token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeErrorCode {
    /// The request is not a valid bridge request.
    MalformedRequest,
    /// The request payload exceeds `max-message-bytes`.
    MessageTooLarge,
    /// Basil cannot be reached.
    BasilUnavailable,
    /// Basil rejected the invocation at gRPC/status level.
    BasilRejected,
    /// Basil did not respond before the bridge timeout.
    Timeout,
    /// Unexpected bridge failure.
    Internal,
}

impl BridgeErrorCode {
    /// Return the stable wire token.
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::MalformedRequest => "MALFORMED_REQUEST",
            Self::MessageTooLarge => "MESSAGE_TOO_LARGE",
            Self::BasilUnavailable => "BASIL_UNAVAILABLE",
            Self::BasilRejected => "BASIL_REJECTED",
            Self::Timeout => "TIMEOUT",
            Self::Internal => "INTERNAL",
        }
    }
}

/// Bridge-level error metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeErrorReply {
    /// Stable error token.
    pub code: BridgeErrorCode,
    /// Operator-facing detail.
    pub message: String,
    /// True when retrying the same request may succeed.
    pub retryable: bool,
}

impl BridgeErrorReply {
    /// Convert bridge error metadata to the required NATS headers.
    #[must_use]
    pub fn headers(&self) -> BridgeHeaders {
        let mut headers = BridgeHeaders::new();
        headers.insert(ERROR_HEADER, self.code.as_token());
        headers.insert(MESSAGE_HEADER, self.message.clone());
        headers.insert(
            RETRYABLE_HEADER,
            if self.retryable { "true" } else { "false" },
        );
        headers
    }
}

/// Basil invocation client abstraction.
#[async_trait]
pub trait BasilInvoker {
    /// Submit one sealed invocation message.
    ///
    /// # Errors
    ///
    /// Returns a transport/status error when Basil does not produce a sealed
    /// response.
    async fn invoke(&mut self, request: SealedRequest) -> Result<SealedResponse, BasilInvokeError>;
}

/// Basil invocation failure as seen by the bridge.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BasilInvokeError {
    /// Basil could not be reached.
    #[error("Basil unavailable: {0}")]
    Unavailable(String),
    /// Basil rejected the request without a sealed response.
    #[error("Basil rejected invocation: {0}")]
    Rejected(String),
    /// Basil did not respond before the timeout.
    #[error("Basil invocation timed out")]
    Timeout,
    /// Unexpected bridge-side failure.
    #[error("internal bridge error: {0}")]
    Internal(String),
}

/// Handle one NATS request according to the sealed-message bridge contract.
///
/// # Errors
///
/// This function returns no process-level errors. All request and Basil failures
/// are represented as [`BridgeAction`] values so the runtime can respond over
/// NATS when a reply subject exists.
pub async fn handle_request(
    request: BridgeRequest,
    max_message_bytes: usize,
    basil: &mut impl BasilInvoker,
) -> BridgeAction {
    let Some(reply_subject) = request.reply.clone() else {
        return BridgeAction::NoReply(error_reply(
            BridgeErrorCode::MalformedRequest,
            "NATS request is missing a reply subject",
            false,
        ));
    };

    if request.payload.len() > max_message_bytes {
        return error_action(
            reply_subject,
            BridgeErrorCode::MessageTooLarge,
            format!(
                "request payload is {} bytes, exceeding the configured {} byte limit",
                request.payload.len(),
                max_message_bytes
            ),
            false,
        );
    }

    let sealed_request = SealedRequest {
        message: request.payload,
    };

    match basil.invoke(sealed_request).await {
        Ok(response) => match response_subject(&response, &reply_subject) {
            Ok(subject) => BridgeAction::Reply(BridgeReply {
                subject,
                payload: response.message,
                headers: BridgeHeaders::new(),
            }),
            Err(error) => error_action(
                reply_subject,
                BridgeErrorCode::MalformedRequest,
                error,
                false,
            ),
        },
        Err(error) => basil_error_action(reply_subject, error),
    }
}

fn response_subject(response: &SealedResponse, fallback_subject: &str) -> Result<String, String> {
    let Some(response_subject) = response.response_subject.as_deref() else {
        return Ok(fallback_subject.to_owned());
    };

    if response_subject.chars().any(|c| matches!(c, '*' | '>')) {
        return Err(format!(
            "Basil returned invalid `response_subject` `{response_subject}`: wildcard tokens are not publish subjects"
        ));
    }

    match async_nats::Subject::validated(response_subject) {
        Ok(subject) => Ok(subject.into_string()),
        Err(error) => Err(format!(
            "Basil returned invalid `response_subject` `{response_subject}`: {error}"
        )),
    }
}

fn basil_error_action(reply_subject: String, error: BasilInvokeError) -> BridgeAction {
    match error {
        BasilInvokeError::Unavailable(message) => error_action(
            reply_subject,
            BridgeErrorCode::BasilUnavailable,
            message,
            true,
        ),
        BasilInvokeError::Rejected(message) => error_action(
            reply_subject,
            BridgeErrorCode::BasilRejected,
            message,
            false,
        ),
        BasilInvokeError::Timeout => error_action(
            reply_subject,
            BridgeErrorCode::Timeout,
            "Basil invocation timed out",
            true,
        ),
        BasilInvokeError::Internal(message) => {
            error_action(reply_subject, BridgeErrorCode::Internal, message, true)
        }
    }
}

fn error_action(
    reply_subject: String,
    code: BridgeErrorCode,
    message: impl Into<String>,
    retryable: bool,
) -> BridgeAction {
    let error = error_reply(code, message, retryable);
    BridgeAction::Reply(BridgeReply {
        subject: reply_subject,
        payload: Vec::new(),
        headers: error.headers(),
    })
}

fn error_reply(
    code: BridgeErrorCode,
    message: impl Into<String>,
    retryable: bool,
) -> BridgeErrorReply {
    BridgeErrorReply {
        code,
        message: message.into(),
        retryable,
    }
}

/// gRPC client for Basil's invocation service over a Unix-domain socket.
#[derive(Debug, Clone)]
pub struct BasilGrpcInvoker {
    client: InvocationServiceClient<Channel>,
    timeout: Duration,
}

impl BasilGrpcInvoker {
    /// Connect to Basil over its Unix-domain socket.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the socket cannot be reached.
    pub async fn connect(socket: &Path) -> Result<Self, RuntimeError> {
        let channel = uds_channel(socket, DEFAULT_CONNECT_TIMEOUT).await?;
        Ok(Self {
            client: InvocationServiceClient::new(channel),
            timeout: DEFAULT_BASIL_TIMEOUT,
        })
    }
}

#[async_trait]
impl BasilInvoker for BasilGrpcInvoker {
    async fn invoke(&mut self, request: SealedRequest) -> Result<SealedResponse, BasilInvokeError> {
        let response = timeout(self.timeout, self.client.invoke(request))
            .await
            .map_err(|_| BasilInvokeError::Timeout)?;

        response
            .map(tonic::Response::into_inner)
            .map_err(|status| classify_status(&status))
    }
}

fn classify_status(status: &Status) -> BasilInvokeError {
    match status.code() {
        Code::Unavailable => BasilInvokeError::Unavailable(status.message().to_owned()),
        Code::DeadlineExceeded => BasilInvokeError::Timeout,
        Code::Internal | Code::Unknown => BasilInvokeError::Internal(status.message().to_owned()),
        _ => BasilInvokeError::Rejected(status.message().to_owned()),
    }
}

async fn uds_channel(path: &Path, connect_timeout: Duration) -> Result<Channel, RuntimeError> {
    let path = path.to_path_buf();
    let endpoint = Endpoint::try_from("http://[::]:50051")?.connect_timeout(connect_timeout);
    endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .map_err(RuntimeError::Endpoint)
}

/// Run the bridge until the NATS subscription ends or a runtime error occurs.
///
/// # Errors
///
/// Returns an error when NATS/Basil setup fails or a reply publish fails.
#[allow(clippy::significant_drop_tightening)]
pub async fn run(config: Config) -> Result<(), RuntimeError> {
    let nats = connect_nats(&config).await?;
    let mut basil = BasilGrpcInvoker::connect(&config.basil.socket).await?;
    let mut subscriber = subscribe(&nats, &config).await?;

    info!(
        request_subject = %config.bridge.request_subject,
        queue_group = ?config.bridge.queue_group,
        "Basil NATS bridge listening",
    );

    while let Some(message) = subscriber.next().await {
        let request = BridgeRequest {
            subject: message.subject.to_string(),
            reply: message.reply.map(|subject| subject.to_string()),
            payload: message.payload.to_vec(),
        };
        let action = handle_request(request, config.bridge.max_message_bytes, &mut basil).await;
        publish_action(&nats, action).await?;
    }
    Ok(())
}

async fn connect_nats(config: &Config) -> Result<async_nats::Client, RuntimeError> {
    let options = match &config.nats.creds {
        Some(creds) => {
            async_nats::ConnectOptions::new()
                .credentials_file(creds)
                .await?
        }
        None => async_nats::ConnectOptions::new(),
    };
    options
        .connect(config.nats.url.clone())
        .await
        .map_err(RuntimeError::NatsConnect)
}

async fn subscribe(
    nats: &async_nats::Client,
    config: &Config,
) -> Result<async_nats::Subscriber, RuntimeError> {
    match &config.bridge.queue_group {
        Some(queue_group) => nats
            .queue_subscribe(config.bridge.request_subject.clone(), queue_group.clone())
            .await
            .map_err(RuntimeError::NatsSubscribe),
        None => nats
            .subscribe(config.bridge.request_subject.clone())
            .await
            .map_err(RuntimeError::NatsSubscribe),
    }
}

async fn publish_action(
    nats: &async_nats::Client,
    action: BridgeAction,
) -> Result<(), RuntimeError> {
    match action {
        BridgeAction::Reply(reply) if reply.headers.is_empty() => {
            debug!(reply_subject = %reply.subject, "forwarding sealed Basil response");
            nats.publish(reply.subject, Bytes::from(reply.payload))
                .await
                .map_err(RuntimeError::NatsPublish)
        }
        BridgeAction::Reply(reply) => {
            warn!(
                reply_subject = %reply.subject,
                error = reply.headers.get(ERROR_HEADER).unwrap_or("UNKNOWN"),
                "replying with bridge-level error",
            );
            nats.publish_with_headers(reply.subject, to_nats_headers(&reply.headers), Bytes::new())
                .await
                .map_err(RuntimeError::NatsPublish)
        }
        BridgeAction::NoReply(error) => {
            warn!(
                error = error.code.as_token(),
                message = %error.message,
                "dropping request because no NATS reply subject was present",
            );
            Ok(())
        }
    }
}

fn to_nats_headers(headers: &BridgeHeaders) -> async_nats::HeaderMap {
    let mut nats_headers = async_nats::HeaderMap::new();
    for (name, value) in headers.iter() {
        nats_headers.insert(name, value);
    }
    nats_headers
}

/// Runtime setup and transport error.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Basil gRPC endpoint construction failed.
    #[error("Basil endpoint configuration failed: {0}")]
    EndpointConfig(#[from] tonic::transport::Error),
    /// Basil gRPC Unix socket connection failed.
    #[error("Basil socket connection failed: {0}")]
    Endpoint(tonic::transport::Error),
    /// NATS credentials file could not be loaded.
    #[error("NATS credentials file could not be loaded: {0}")]
    NatsCredentials(#[from] std::io::Error),
    /// NATS connection failed.
    #[error("NATS connection failed: {0}")]
    NatsConnect(async_nats::ConnectError),
    /// NATS subscription failed.
    #[error("NATS subscription failed: {0}")]
    NatsSubscribe(async_nats::SubscribeError),
    /// NATS reply publish failed.
    #[error("NATS publish failed: {0}")]
    NatsPublish(async_nats::PublishError),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_panics_doc, clippy::unwrap_used)]

    use super::*;
    use basil_proto::KeyType;
    use basil_proto::broker::v1::{GetSecretResponse, ImportRequest, KeyMaterial, key_material};

    const VALID_CONFIG: &str = r#"
[nats]
url = "nats://127.0.0.1:4222"
creds = "/run/basil/bridge.creds"

[basil]
socket = "/run/basil/basil.sock"

[bridge]
request-subject = "basil.invocation"
queue-group = "basil-bridge"
max-message-bytes = 1048576
"#;

    #[derive(Debug)]
    struct FakeBasil {
        result: Result<SealedResponse, BasilInvokeError>,
        received: Vec<SealedRequest>,
    }

    impl FakeBasil {
        fn ok(response: SealedResponse) -> Self {
            Self {
                result: Ok(response),
                received: Vec::new(),
            }
        }

        fn err(error: BasilInvokeError) -> Self {
            Self {
                result: Err(error),
                received: Vec::new(),
            }
        }
    }

    #[async_trait]
    impl BasilInvoker for FakeBasil {
        async fn invoke(
            &mut self,
            request: SealedRequest,
        ) -> Result<SealedResponse, BasilInvokeError> {
            self.received.push(request);
            self.result.clone()
        }
    }

    #[test]
    fn parses_valid_config() {
        let config = Config::from_toml_str(VALID_CONFIG).unwrap();

        assert_eq!(config.nats.url, "nats://127.0.0.1:4222");
        assert_eq!(
            config.nats.creds.as_deref(),
            Some(Path::new("/run/basil/bridge.creds"))
        );
        assert_eq!(config.basil.socket, PathBuf::from("/run/basil/basil.sock"));
        assert_eq!(config.bridge.request_subject, "basil.invocation");
        assert_eq!(config.bridge.queue_group.as_deref(), Some("basil-bridge"));
        assert_eq!(config.bridge.max_message_bytes, 1_048_576);
    }

    #[test]
    fn parses_config_without_optional_creds_or_queue_group() {
        let config = Config::from_toml_str(
            r#"
[nats]
url = "nats://127.0.0.1:4222"

[basil]
socket = "/run/basil/basil.sock"

[bridge]
request-subject = "basil.invocation"
max-message-bytes = 4096
"#,
        )
        .unwrap();

        assert_eq!(config.nats.creds, None);
        assert_eq!(config.bridge.queue_group, None);
    }

    #[test]
    fn rejects_empty_config_fields() {
        let error = Config::from_toml_str(
            r#"
[nats]
url = " "

[basil]
socket = "/run/basil/basil.sock"

[bridge]
request-subject = "basil.invocation"
max-message-bytes = 1024
"#,
        )
        .unwrap_err();

        assert!(matches!(error, ConfigError::EmptyField("nats.url")));
    }

    #[test]
    fn rejects_invalid_message_size_bounds() {
        let error = Config::from_toml_str(
            r#"
[nats]
url = "nats://127.0.0.1:4222"

[basil]
socket = "/run/basil/basil.sock"

[bridge]
request-subject = "basil.invocation"
max-message-bytes = 0
"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigError::InvalidMaxMessageBytes { value: 0, .. }
        ));
    }

    #[tokio::test]
    async fn forwards_raw_bytes_and_returns_raw_response_without_error_headers() {
        let request_payload = b"\xd2\x84raw tagged cose request".to_vec();
        let response_payload = b"\xd2\x84raw tagged cose response".to_vec();
        let mut basil = FakeBasil::ok(sealed_response(&response_payload));

        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.1".to_owned()),
                payload: request_payload.clone(),
            },
            1024,
            &mut basil,
        )
        .await;

        assert_eq!(basil.received, vec![sealed_request(&request_payload)]);
        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_eq!(reply.subject, "_INBOX.1");
        assert_eq!(reply.payload, response_payload);
        assert!(reply.headers.is_empty());
    }

    #[tokio::test]
    async fn response_subject_overrides_nats_reply_subject() {
        let mut basil = FakeBasil::ok(sealed_response_to(
            b"sealed response",
            Some("tenant.reply.inbox"),
        ));

        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.original".to_owned()),
                payload: b"sealed request".to_vec(),
            },
            1024,
            &mut basil,
        )
        .await;

        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_eq!(reply.subject, "tenant.reply.inbox");
        assert_eq!(reply.payload.as_slice(), b"sealed response");
        assert!(reply.headers.is_empty());
    }

    #[tokio::test]
    async fn import_key_request_body_is_forwarded_as_opaque_cose_payload() {
        let import_body = import_key_request_body();
        assert!(bytes_contain(
            &import_body,
            b"import-seed-material-remains-secret"
        ));
        let response = sealed_response(b"sealed response");
        let mut basil = FakeBasil::ok(response);

        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.import".to_owned()),
                payload: import_body.clone(),
            },
            4096,
            &mut basil,
        )
        .await;

        assert_eq!(basil.received, vec![sealed_request(&import_body)]);
        let received = basil
            .received
            .first()
            .expect("bridge forwarded one request");
        assert_eq!(received.message, import_body);
        assert!(bytes_contain(
            &received.message,
            b"import-seed-material-remains-secret"
        ));
        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert!(reply.headers.is_empty());
        assert_eq!(reply.payload.as_slice(), b"sealed response");
    }

    #[tokio::test]
    async fn get_secret_response_body_is_returned_as_opaque_cose_payload() {
        let secret_body = get_secret_response_body();
        assert!(bytes_contain(&secret_body, b"secret-response-value"));
        let mut basil = FakeBasil::ok(sealed_response(&secret_body));

        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.secret".to_owned()),
                payload: b"sealed request".to_vec(),
            },
            4096,
            &mut basil,
        )
        .await;

        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert!(reply.headers.is_empty());
        assert_eq!(reply.payload, secret_body);
        assert!(bytes_contain(&reply.payload, b"secret-response-value"));
    }

    #[tokio::test]
    async fn preserves_routing_metadata_in_error_reply_subject() {
        let mut basil = FakeBasil::err(BasilInvokeError::Unavailable("down".to_owned()));
        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.route".to_owned()),
                payload: b"sealed request".to_vec(),
            },
            1024,
            &mut basil,
        )
        .await;

        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_eq!(reply.subject, "_INBOX.route");
        assert_error(&reply, BridgeErrorCode::BasilUnavailable, true);
    }

    #[tokio::test]
    async fn non_protobuf_payload_is_forwarded_without_cose_parsing() {
        let payload = b"not protobuf and not cose".to_vec();
        let mut basil = FakeBasil::ok(sealed_response(b"body"));
        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.1".to_owned()),
                payload: payload.clone(),
            },
            1024,
            &mut basil,
        )
        .await;

        assert_eq!(basil.received, vec![sealed_request(&payload)]);
        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_eq!(reply.payload.as_slice(), b"body");
        assert!(reply.headers.is_empty());
    }

    #[tokio::test]
    async fn adversarial_cose_payload_is_forwarded_byte_exact_without_local_claims_parsing() {
        let payload = adversarial_cose_like_payload();
        let mut basil = FakeBasil::ok(sealed_response(b"sealed response"));

        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.original".to_owned()),
                payload: payload.clone(),
            },
            4096,
            &mut basil,
        )
        .await;

        assert_eq!(basil.received, vec![sealed_request(&payload)]);
        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_eq!(reply.subject, "_INBOX.original");
        assert_eq!(reply.payload.as_slice(), b"sealed response");
        assert!(reply.headers.is_empty());
    }

    #[tokio::test]
    async fn embedded_reply_and_grant_hints_cannot_override_signed_response_subject() {
        let payload = adversarial_cose_like_payload();
        let response_payload = b"payload response_subject=attacker.payload.reply".to_vec();
        let mut basil = FakeBasil::ok(sealed_response_to(
            &response_payload,
            Some("tenant.signed.reply"),
        ));

        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.attacker".to_owned()),
                payload: payload.clone(),
            },
            4096,
            &mut basil,
        )
        .await;

        assert_eq!(basil.received, vec![sealed_request(&payload)]);
        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_eq!(reply.subject, "tenant.signed.reply");
        assert_eq!(reply.payload, response_payload);
        assert!(reply.headers.is_empty());
    }

    #[tokio::test]
    async fn basil_authorization_rejection_is_not_masked_by_bridge_grants() {
        let payload = adversarial_cose_like_payload();
        let mut basil = FakeBasil::err(BasilInvokeError::Rejected(
            "permission denied for actor".to_owned(),
        ));

        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.original".to_owned()),
                payload: payload.clone(),
            },
            4096,
            &mut basil,
        )
        .await;

        assert_eq!(basil.received, vec![sealed_request(&payload)]);
        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_eq!(reply.subject, "_INBOX.original");
        assert_error(&reply, BridgeErrorCode::BasilRejected, false);
        assert_eq!(
            reply.headers.get(MESSAGE_HEADER),
            Some("permission denied for actor")
        );
    }

    #[tokio::test]
    async fn invalid_response_subject_returns_error_on_original_reply_subject() {
        for response_subject in ["", "not a subject", "tenant.*"] {
            let mut basil = FakeBasil::ok(sealed_response_to(
                b"sealed response",
                Some(response_subject),
            ));
            let action = handle_request(
                BridgeRequest {
                    subject: "basil.invocation".to_owned(),
                    reply: Some("_INBOX.original".to_owned()),
                    payload: b"sealed request".to_vec(),
                },
                1024,
                &mut basil,
            )
            .await;

            let BridgeAction::Reply(reply) = action else {
                panic!("expected reply");
            };
            assert_eq!(reply.subject, "_INBOX.original");
            assert_error(&reply, BridgeErrorCode::MalformedRequest, false);
        }
    }

    #[tokio::test]
    async fn invalid_basil_response_subject_error_ignores_payload_routing_hint() {
        let payload = adversarial_cose_like_payload();
        let mut basil = FakeBasil::ok(sealed_response_to(
            b"response_subject=attacker.payload.reply",
            Some("tenant.>"),
        ));

        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.original".to_owned()),
                payload: payload.clone(),
            },
            4096,
            &mut basil,
        )
        .await;

        assert_eq!(basil.received, vec![sealed_request(&payload)]);
        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_eq!(reply.subject, "_INBOX.original");
        assert_error(&reply, BridgeErrorCode::MalformedRequest, false);
    }

    #[tokio::test]
    async fn too_large_message_returns_error_headers_without_basil_call() {
        let mut basil = FakeBasil::ok(sealed_response(b"body"));
        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.1".to_owned()),
                payload: vec![7; 9],
            },
            8,
            &mut basil,
        )
        .await;

        assert!(basil.received.is_empty());
        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_error(&reply, BridgeErrorCode::MessageTooLarge, false);
    }

    #[tokio::test]
    async fn missing_reply_subject_is_reported_as_no_reply_action() {
        let mut basil = FakeBasil::ok(sealed_response(b"body"));
        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: None,
                payload: b"body".to_vec(),
            },
            1024,
            &mut basil,
        )
        .await;

        assert!(basil.received.is_empty());
        let BridgeAction::NoReply(error) = action else {
            panic!("expected no-reply action");
        };
        assert_eq!(error.code, BridgeErrorCode::MalformedRequest);
        assert!(!error.retryable);
    }

    #[tokio::test]
    async fn basil_rejection_maps_to_stable_error_headers() {
        let mut basil = FakeBasil::err(BasilInvokeError::Rejected("denied".to_owned()));
        let reply = invoke_error_reply(&mut basil).await;

        assert_error(&reply, BridgeErrorCode::BasilRejected, false);
    }

    #[tokio::test]
    async fn basil_timeout_maps_to_retryable_error_headers() {
        let mut basil = FakeBasil::err(BasilInvokeError::Timeout);
        let reply = invoke_error_reply(&mut basil).await;

        assert_error(&reply, BridgeErrorCode::Timeout, true);
    }

    #[tokio::test]
    async fn basil_unavailable_maps_to_retryable_error_headers() {
        let mut basil = FakeBasil::err(BasilInvokeError::Unavailable("socket closed".to_owned()));
        let reply = invoke_error_reply(&mut basil).await;

        assert_error(&reply, BridgeErrorCode::BasilUnavailable, true);
    }

    async fn invoke_error_reply(basil: &mut FakeBasil) -> BridgeReply {
        let action = handle_request(
            BridgeRequest {
                subject: "basil.invocation".to_owned(),
                reply: Some("_INBOX.1".to_owned()),
                payload: b"body".to_vec(),
            },
            1024,
            basil,
        )
        .await;

        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        reply
    }

    fn assert_error(reply: &BridgeReply, code: BridgeErrorCode, retryable: bool) {
        assert_eq!(reply.payload, Vec::<u8>::new());
        assert_eq!(reply.headers.get(ERROR_HEADER), Some(code.as_token()));
        assert_eq!(
            reply.headers.get(RETRYABLE_HEADER),
            Some(if retryable { "true" } else { "false" })
        );
        assert!(reply.headers.get(MESSAGE_HEADER).is_some());
    }

    fn sealed_request(body: &[u8]) -> SealedRequest {
        SealedRequest {
            message: body.to_vec(),
        }
    }

    fn sealed_response(body: &[u8]) -> SealedResponse {
        sealed_response_to(body, None)
    }

    fn sealed_response_to(body: &[u8], subject: Option<&str>) -> SealedResponse {
        SealedResponse {
            message: body.to_vec(),
            response_subject: subject.map(str::to_owned),
        }
    }

    fn import_key_request_body() -> Vec<u8> {
        encode_proto(&ImportRequest {
            key_id: "tenant.imported.signing".to_owned(),
            key_type: KeyType::Ed25519 as i32,
            material: Some(KeyMaterial {
                material: Some(key_material::Material::Ed25519Seed(
                    b"import-seed-material-remains-secret".to_vec(),
                )),
            }),
        })
    }

    fn get_secret_response_body() -> Vec<u8> {
        encode_proto(&GetSecretResponse {
            value: b"secret-response-value".to_vec(),
            version: 7,
        })
    }

    fn adversarial_cose_like_payload() -> Vec<u8> {
        [
            &[
                0xD2, 0x84, 0xA5, 0x01, 0x27, 0x04, 0x58, 0x20, 0xA5, 0x5A, 0xC3, 0x0E,
            ][..],
            b"issuer=spiffe://tenant/service-a;",
            b"content-type=application/x-basil.sign-request+cbor;",
            b"kid=tenant.signing-key;",
            b"ciphertext=must-remain-opaque;",
            b"response-key=tenant.response-key;",
            b"response_subject=attacker.reply;",
            b"bridge-grant=sign:tenant/*",
        ]
        .concat()
    }

    fn encode_proto(message: &impl prost::Message) -> Vec<u8> {
        let mut bytes = Vec::new();
        message.encode(&mut bytes).unwrap();
        bytes
    }

    fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
