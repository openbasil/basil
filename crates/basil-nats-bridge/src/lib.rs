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
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil_courier::{
    CourierCallError, InvocationCourierClient, InvocationOnlyClient, MAX_COURIER_SOURCE_BYTES,
    TrustedUdsPolicy,
};
use basil_proto::broker::v1::{
    GetInvocationChallengeRequest, GetInvocationChallengeResponse, SealedRequest, SealedResponse,
};
use bytes::Bytes;
use futures::{StreamExt, stream};
use prost::Message;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, info, warn};

/// NATS header carrying the stable bridge error token.
pub const ERROR_HEADER: &str = "Basil-Bridge-Error";
/// NATS header carrying bridge error detail intended for logs/operators.
pub const RETRYABLE_HEADER: &str = "Basil-Bridge-Retryable";

const DEFAULT_BASIL_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CONCURRENCY_LIMIT: usize = 32;
const DEFAULT_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_ALLOWED_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CHALLENGE_MESSAGE_BYTES: usize = 4 * 1024;
const MAX_CONCURRENCY_LIMIT: usize = 256;
const LEASE_MAX_AGE: Duration = Duration::from_secs(15);
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(5);

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
    /// Non-root UID allowed to own socket-path ancestors.
    pub service_owner_uid: u32,
    /// Required owner UID of the final socket directory.
    pub directory_owner_uid: u32,
    /// Required final-directory mode.
    pub directory_mode: u32,
    /// Required socket owner and kernel peer UID.
    pub server_uid: u32,
    /// Required socket mode.
    pub socket_mode: u32,
}

/// Bridge routing and request size settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeConfig {
    /// NATS subject accepting sealed invocation request bytes.
    pub request_subject: String,
    /// Federation challenge subject; absent selects local legacy mode.
    pub challenge_subject: Option<String>,
    /// Trusted rate-limit partition inserted into challenge requests.
    pub source_partition: Option<String>,
    /// Pre-created `JetStream` Key/Value bucket for the federation lease.
    pub lease_bucket: Option<String>,
    /// Optional NATS queue group for shared bridge workers.
    pub queue_group: Option<String>,
    /// Maximum accepted NATS payload size in bytes.
    pub max_message_bytes: usize,
    /// Maximum broker calls in flight at once.
    pub concurrency_limit: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawConfig {
    nats: RawNatsConfig,
    basil: RawBasilConfig,
    bridge: RawBridgeConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawNatsConfig {
    url: String,
    creds: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawBasilConfig {
    socket: PathBuf,
    service_owner_uid: u32,
    directory_owner_uid: u32,
    directory_mode: u32,
    server_uid: u32,
    socket_mode: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawBridgeConfig {
    request_subject: String,
    challenge_subject: Option<String>,
    source_partition: Option<String>,
    lease_bucket: Option<String>,
    queue_group: Option<String>,
    max_message_bytes: Option<usize>,
    concurrency_limit: Option<usize>,
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
        validate_subject(&request_subject, "bridge.request-subject")?;
        let challenge_subject = raw
            .bridge
            .challenge_subject
            .map(|value| non_empty(&value, "bridge.challenge-subject"))
            .transpose()?;
        if let Some(subject) = challenge_subject.as_deref() {
            validate_subject(subject, "bridge.challenge-subject")?;
            if subject == request_subject {
                return Err(ConfigError::SubjectsMustDiffer);
            }
        }
        let source_partition = raw
            .bridge
            .source_partition
            .map(|value| non_empty(&value, "bridge.source-partition"))
            .transpose()?;
        let lease_bucket = raw
            .bridge
            .lease_bucket
            .map(|value| non_empty(&value, "bridge.lease-bucket"))
            .transpose()?;
        let queue_group = raw
            .bridge
            .queue_group
            .map(|value| non_empty(&value, "bridge.queue-group"))
            .transpose()?;
        let max_message_bytes = raw
            .bridge
            .max_message_bytes
            .unwrap_or(DEFAULT_MAX_MESSAGE_BYTES);
        validate_max_message_bytes(max_message_bytes)?;
        let concurrency_limit = raw
            .bridge
            .concurrency_limit
            .unwrap_or(DEFAULT_CONCURRENCY_LIMIT);
        validate_concurrency_limit(concurrency_limit)?;
        let federation = challenge_subject.is_some();
        if federation != source_partition.is_some() || federation != lease_bucket.is_some() {
            return Err(ConfigError::IncompleteFederation);
        }
        if federation && queue_group.is_some() {
            return Err(ConfigError::FederationQueueGroup);
        }
        if source_partition
            .as_ref()
            .is_some_and(|value| value.len() > MAX_COURIER_SOURCE_BYTES)
        {
            return Err(ConfigError::SourcePartitionTooLong);
        }

        let policy = TrustedUdsPolicy {
            socket_path: socket.clone(),
            service_owner_uid: raw.basil.service_owner_uid,
            directory_owner_uid: raw.basil.directory_owner_uid,
            directory_mode: raw.basil.directory_mode,
            socket_owner_uid: raw.basil.server_uid,
            socket_mode: raw.basil.socket_mode,
            expected_peer_uid: raw.basil.server_uid,
        };
        policy
            .validate()
            .map_err(|_| ConfigError::InvalidTrustedSocketPolicy)?;

        Ok(Self {
            nats: NatsConfig {
                url: nats_url,
                creds,
            },
            basil: BasilConfig {
                socket,
                service_owner_uid: raw.basil.service_owner_uid,
                directory_owner_uid: raw.basil.directory_owner_uid,
                directory_mode: raw.basil.directory_mode,
                server_uid: raw.basil.server_uid,
                socket_mode: raw.basil.socket_mode,
            },
            bridge: BridgeConfig {
                request_subject,
                challenge_subject,
                source_partition,
                lease_bucket,
                queue_group,
                max_message_bytes,
                concurrency_limit,
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

const fn validate_concurrency_limit(value: usize) -> Result<(), ConfigError> {
    if value == 0 || value > MAX_CONCURRENCY_LIMIT {
        return Err(ConfigError::InvalidConcurrencyLimit { value });
    }
    Ok(())
}

fn validate_subject(value: &str, field: &'static str) -> Result<(), ConfigError> {
    if value.contains('*') || value.contains('>') || async_nats::Subject::validated(value).is_err()
    {
        return Err(ConfigError::InvalidSubject(field));
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
    /// Concurrency bound is unsupported.
    #[error("`bridge.concurrency-limit` must be >= 1, got {value}")]
    InvalidConcurrencyLimit {
        /// Configured value.
        value: usize,
    },
    /// A configured subject is invalid or contains wildcards.
    #[error("config field `{0}` must be one concrete NATS subject")]
    InvalidSubject(&'static str),
    /// Federation requires both a challenge subject and source partition.
    #[error(
        "federation requires `challenge-subject`, `source-partition`, and `lease-bucket` together"
    )]
    IncompleteFederation,
    /// Federation subject pairs must be distinct.
    #[error("federation challenge and invocation subjects must differ")]
    SubjectsMustDiffer,
    /// Queue groups violate single-agent federation routing.
    #[error("federation mode forbids `queue-group`")]
    FederationQueueGroup,
    /// The trusted source partition is larger than the wire maximum.
    #[error("`bridge.source-partition` exceeds 128 bytes")]
    SourcePartitionTooLong,
    /// The Basil socket trust policy is not closed and valid.
    #[error("Basil trusted Unix socket policy is invalid")]
    InvalidTrustedSocketPolicy,
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
    /// The broker declined freshness issuance under bounded pressure.
    ChallengeIssuanceDeclined,
    /// The local listener is not the frozen courier profile.
    CapabilityMismatch,
    /// The bridge's no-queue in-flight bound is full.
    Overloaded,
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
            Self::ChallengeIssuanceDeclined => "CHALLENGE_ISSUANCE_DECLINED",
            Self::CapabilityMismatch => "CAPABILITY_MISMATCH",
            Self::Overloaded => "OVERLOADED",
        }
    }
}

/// Bridge-level error metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeErrorReply {
    /// Stable error token.
    pub code: BridgeErrorCode,
    /// True when retrying the same request may succeed.
    pub retryable: bool,
}

impl BridgeErrorReply {
    /// Convert bridge error metadata to the required NATS headers.
    #[must_use]
    pub fn headers(&self) -> BridgeHeaders {
        let mut headers = BridgeHeaders::new();
        headers.insert(ERROR_HEADER, self.code.as_token());
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
    async fn invoke(&mut self, request: SealedRequest) -> Result<SealedResponse, CourierCallError>;

    /// Request one freshness challenge through the trusted courier client.
    async fn get_challenge(
        &mut self,
        request: GetInvocationChallengeRequest,
        source: &str,
    ) -> Result<GetInvocationChallengeResponse, CourierCallError>;
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
        return BridgeAction::NoReply(error_reply(BridgeErrorCode::MalformedRequest, false));
    };

    if request.payload.len() > max_message_bytes {
        return error_action(reply_subject, BridgeErrorCode::MessageTooLarge, false);
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
            Err(_) => error_action(reply_subject, BridgeErrorCode::MalformedRequest, false),
        },
        Err(error) => courier_error_action(reply_subject, error),
    }
}

/// Handle one protobuf freshness-challenge request in federation mode.
pub async fn handle_challenge_request(
    request: BridgeRequest,
    source_partition: &str,
    basil: &mut impl BasilInvoker,
) -> BridgeAction {
    let Some(reply_subject) = request.reply else {
        return BridgeAction::NoReply(error_reply(BridgeErrorCode::MalformedRequest, false));
    };
    if request.payload.len() > MAX_CHALLENGE_MESSAGE_BYTES {
        return error_action(reply_subject, BridgeErrorCode::MessageTooLarge, false);
    }
    let Ok(challenge) = GetInvocationChallengeRequest::decode(request.payload.as_slice()) else {
        return error_action(reply_subject, BridgeErrorCode::MalformedRequest, false);
    };
    if challenge.courier_observed_source.is_some() {
        return error_action(reply_subject, BridgeErrorCode::MalformedRequest, false);
    }
    match basil.get_challenge(challenge, source_partition).await {
        Ok(response) => BridgeAction::Reply(BridgeReply {
            subject: reply_subject,
            payload: response.encode_to_vec(),
            headers: BridgeHeaders::new(),
        }),
        Err(error) => courier_error_action(reply_subject, error),
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

fn courier_error_action(reply_subject: String, error: CourierCallError) -> BridgeAction {
    let code = match error {
        CourierCallError::InvalidRequest => BridgeErrorCode::MalformedRequest,
        CourierCallError::UnavailableBeforeForward | CourierCallError::UnavailableAfterForward => {
            BridgeErrorCode::BasilUnavailable
        }
        CourierCallError::DeadlineBeforeForward | CourierCallError::DeadlineAfterForward => {
            BridgeErrorCode::Timeout
        }
        CourierCallError::CapabilityMismatch => BridgeErrorCode::CapabilityMismatch,
        CourierCallError::ChallengeDeclined => BridgeErrorCode::ChallengeIssuanceDeclined,
        CourierCallError::BrokerRejected => BridgeErrorCode::BasilRejected,
    };
    error_action(reply_subject, code, error.retryable())
}

fn error_action(reply_subject: String, code: BridgeErrorCode, retryable: bool) -> BridgeAction {
    let error = error_reply(code, retryable);
    BridgeAction::Reply(BridgeReply {
        subject: reply_subject,
        payload: Vec::new(),
        headers: error.headers(),
    })
}

fn overloaded_action(reply_subject: Option<String>) -> BridgeAction {
    reply_subject.map_or_else(
        || BridgeAction::NoReply(error_reply(BridgeErrorCode::Overloaded, true)),
        |reply| error_action(reply, BridgeErrorCode::Overloaded, true),
    )
}

const fn error_reply(code: BridgeErrorCode, retryable: bool) -> BridgeErrorReply {
    BridgeErrorReply { code, retryable }
}

/// gRPC client for Basil's invocation service over a Unix-domain socket.
#[derive(Debug, Clone)]
pub struct BasilGrpcInvoker {
    client: BasilInvocationClient,
}

#[derive(Debug, Clone)]
enum BasilInvocationClient {
    Federation(InvocationCourierClient),
    Legacy(InvocationOnlyClient),
}

impl BasilGrpcInvoker {
    /// Connect to Basil over its Unix-domain socket.
    ///
    /// # Errors
    ///
    /// Returns a transport error when the socket cannot be reached.
    pub async fn connect(config: &BasilConfig, federation: bool) -> Result<Self, RuntimeError> {
        let policy = TrustedUdsPolicy {
            socket_path: config.socket.clone(),
            service_owner_uid: config.service_owner_uid,
            directory_owner_uid: config.directory_owner_uid,
            directory_mode: config.directory_mode,
            socket_owner_uid: config.server_uid,
            socket_mode: config.socket_mode,
            expected_peer_uid: config.server_uid,
        };
        let client = if federation {
            BasilInvocationClient::Federation(
                InvocationCourierClient::connect(
                    policy,
                    DEFAULT_CONNECT_TIMEOUT,
                    DEFAULT_BASIL_TIMEOUT,
                )
                .await
                .map_err(|_| RuntimeError::BasilConnect)?,
            )
        } else {
            BasilInvocationClient::Legacy(
                InvocationOnlyClient::connect(
                    policy,
                    DEFAULT_CONNECT_TIMEOUT,
                    DEFAULT_BASIL_TIMEOUT,
                )
                .await
                .map_err(|_| RuntimeError::BasilConnect)?,
            )
        };
        Ok(Self { client })
    }
}

#[async_trait]
impl BasilInvoker for BasilGrpcInvoker {
    async fn invoke(&mut self, request: SealedRequest) -> Result<SealedResponse, CourierCallError> {
        match &mut self.client {
            BasilInvocationClient::Federation(client) => client.invoke(request).await,
            BasilInvocationClient::Legacy(client) => client.invoke(request).await,
        }
    }

    async fn get_challenge(
        &mut self,
        request: GetInvocationChallengeRequest,
        source: &str,
    ) -> Result<GetInvocationChallengeResponse, CourierCallError> {
        match &mut self.client {
            BasilInvocationClient::Federation(client) => {
                client.get_challenge(request, source).await
            }
            BasilInvocationClient::Legacy(_) => Err(CourierCallError::InvalidRequest),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("federation lease operation failed")]
struct LeaseError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeaseBucketStatus {
    history: i64,
    max_age: Duration,
}

#[async_trait]
trait LeaseBackend: Clone + Send + Sync + 'static {
    async fn status(&self) -> Result<LeaseBucketStatus, LeaseError>;
    async fn create(&self, key: &str, value: Bytes) -> Result<u64, LeaseError>;
    async fn update(&self, key: &str, value: Bytes, revision: u64) -> Result<u64, LeaseError>;
    async fn delete(&self, key: &str, revision: u64) -> Result<(), LeaseError>;
}

#[derive(Clone, Debug)]
struct JetStreamLeaseBackend {
    store: async_nats::jetstream::kv::Store,
}

#[async_trait]
impl LeaseBackend for JetStreamLeaseBackend {
    async fn status(&self) -> Result<LeaseBucketStatus, LeaseError> {
        let status = self.store.status().await.map_err(|_| LeaseError)?;
        Ok(LeaseBucketStatus {
            history: status.history(),
            max_age: status.max_age(),
        })
    }

    async fn create(&self, key: &str, value: Bytes) -> Result<u64, LeaseError> {
        self.store.create(key, value).await.map_err(|_| LeaseError)
    }

    async fn update(&self, key: &str, value: Bytes, revision: u64) -> Result<u64, LeaseError> {
        self.store
            .update(key, value, revision)
            .await
            .map_err(|_| LeaseError)
    }

    async fn delete(&self, key: &str, revision: u64) -> Result<(), LeaseError> {
        self.store
            .delete_expect_revision(key, Some(revision))
            .await
            .map_err(|_| LeaseError)
    }
}

#[derive(Debug)]
struct LeaseState<B> {
    backend: B,
    key: String,
    value: Bytes,
    revision: u64,
}

#[derive(Clone, Debug)]
struct FederationLease<B> {
    state: Arc<Mutex<LeaseState<B>>>,
}

impl<B: LeaseBackend> FederationLease<B> {
    async fn acquire(
        backend: B,
        challenge_subject: &str,
        request_subject: &str,
    ) -> Result<Self, LeaseError> {
        let status = backend.status().await?;
        if status.history != 1 || status.max_age != LEASE_MAX_AGE {
            return Err(LeaseError);
        }
        let key = lease_key(challenge_subject, request_subject);
        let mut instance_id = [0_u8; 32];
        getrandom::fill(&mut instance_id).map_err(|_| LeaseError)?;
        let value = Bytes::copy_from_slice(&instance_id);
        let revision = backend.create(&key, value.clone()).await?;
        Ok(Self {
            state: Arc::new(Mutex::new(LeaseState {
                backend,
                key,
                value,
                revision,
            })),
        })
    }

    async fn renew(&self) -> Result<(), LeaseError> {
        let mut state = self.state.lock().await;
        let revision = state
            .backend
            .update(&state.key, state.value.clone(), state.revision)
            .await?;
        state.revision = revision;
        drop(state);
        Ok(())
    }

    async fn release(&self) -> Result<(), LeaseError> {
        let state = self.state.lock().await;
        state.backend.delete(&state.key, state.revision).await
    }
}

fn lease_key(challenge_subject: &str, request_subject: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"basil-courier-nats-v1\0");
    digest.update(challenge_subject.as_bytes());
    digest.update(b"\0");
    digest.update(request_subject.as_bytes());
    format!("lease.{}", URL_SAFE_NO_PAD.encode(digest.finalize()))
}

async fn acquire_federation_lease(
    nats: &async_nats::Client,
    config: &Config,
) -> Result<Option<FederationLease<JetStreamLeaseBackend>>, RuntimeError> {
    let (Some(challenge_subject), Some(bucket)) = (
        config.bridge.challenge_subject.as_deref(),
        config.bridge.lease_bucket.as_deref(),
    ) else {
        return Ok(None);
    };
    let context = async_nats::jetstream::new(nats.clone());
    let store = context
        .get_key_value(bucket)
        .await
        .map_err(|_| RuntimeError::LeaseSetup)?;
    FederationLease::acquire(
        JetStreamLeaseBackend { store },
        challenge_subject,
        &config.bridge.request_subject,
    )
    .await
    .map(Some)
    .map_err(|_| RuntimeError::LeaseSetup)
}

async fn abort_workers(tasks: &mut JoinSet<()>) {
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

/// Run the bridge until the NATS subscription ends or a runtime error occurs.
///
/// Reply-publish failures are logged and do not stop the bridge.
///
/// # Errors
///
/// Returns an error when NATS/Basil setup fails, a request worker panics, or
/// the subscription stream ends ([`RuntimeError::SubscriptionEnded`]), so an
/// on-failure supervisor restarts the bridge instead of seeing a clean exit.
#[allow(clippy::significant_drop_tightening)]
pub async fn run(config: Config) -> Result<(), RuntimeError> {
    let nats = connect_nats(&config).await?;
    let basil =
        BasilGrpcInvoker::connect(&config.basil, config.bridge.challenge_subject.is_some()).await?;
    let lease = acquire_federation_lease(&nats, &config).await?;
    let invocation = subscribe_invocations(&nats, &config)
        .await?
        .map(|message| (RequestKind::Invocation, message))
        .boxed();
    let challenges = if let Some(subject) = config.bridge.challenge_subject.as_ref() {
        nats.subscribe(subject.clone())
            .await
            .map_err(RuntimeError::NatsSubscribe)?
            .map(|message| (RequestKind::Challenge, message))
            .boxed()
    } else {
        stream::empty().boxed()
    };
    let mut subscribers = stream::select(invocation, challenges);
    let concurrency_limit = config.bridge.concurrency_limit;

    info!(
        request_subject = %config.bridge.request_subject,
        challenge_subject = ?config.bridge.challenge_subject,
        queue_group = ?config.bridge.queue_group,
        concurrency_limit,
        "Basil NATS bridge listening",
    );

    let mut tasks = JoinSet::new();
    let first_renewal = tokio::time::Instant::now() + LEASE_RENEW_INTERVAL;
    let mut heartbeat = tokio::time::interval_at(first_renewal, LEASE_RENEW_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            shutdown_result = &mut shutdown => {
                abort_workers(&mut tasks).await;
                shutdown_result.map_err(RuntimeError::ShutdownSignal)?;
                if let Some(lease) = lease.as_ref() {
                    lease.release().await.map_err(|_| RuntimeError::LeaseLost)?;
                }
                return Ok(());
            }
            _ = heartbeat.tick(), if lease.is_some() => {
                let Some(active_lease) = lease.as_ref() else {
                    continue;
                };
                if active_lease.renew().await.is_err() {
                    abort_workers(&mut tasks).await;
                    return Err(RuntimeError::LeaseLost);
                }
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = joined {
                    result.map_err(RuntimeError::WorkerJoin)?;
                }
            }
            message = subscribers.next() => {
                let Some((kind, message)) = message else {
                    tasks.abort_all();
                    return Err(RuntimeError::SubscriptionEnded);
                };
                let request = BridgeRequest {
                    subject: message.subject.to_string(),
                    reply: message.reply.map(|subject| subject.to_string()),
                    payload: message.payload.to_vec(),
                };
                if tasks.len() >= concurrency_limit {
                    let action = overloaded_action(request.reply.clone());
                    publish_action(&nats, action).await;
                    continue;
                }
                if let Some(active_lease) = lease.as_ref()
                    && active_lease.renew().await.is_err()
                {
                    abort_workers(&mut tasks).await;
                    return Err(RuntimeError::LeaseLost);
                }
                let nats = nats.clone();
                let mut basil = basil.clone();
                let max_message_bytes = config.bridge.max_message_bytes;
                let source_partition = config.bridge.source_partition.clone();
                tasks.spawn(async move {
                    let action = match kind {
                        RequestKind::Invocation => {
                            handle_request(request, max_message_bytes, &mut basil).await
                        }
                        RequestKind::Challenge => {
                            let Some(source) = source_partition.as_deref() else {
                                return;
                            };
                            handle_challenge_request(request, source, &mut basil).await
                        }
                    };
                    publish_action(&nats, action).await;
                });
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum RequestKind {
    Invocation,
    Challenge,
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

async fn subscribe_invocations(
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

/// Publish a bridge action, logging (not propagating) publish failures so one
/// failed reply cannot take down the whole bridge.
async fn publish_action(nats: &async_nats::Client, action: BridgeAction) {
    let (subject, result) = match action {
        BridgeAction::Reply(reply) if reply.headers.is_empty() => {
            debug!(reply_subject = %reply.subject, "forwarding sealed Basil response");
            let subject = reply.subject.clone();
            let result = nats
                .publish(reply.subject, Bytes::from(reply.payload))
                .await;
            (subject, result)
        }
        BridgeAction::Reply(reply) => {
            warn!(
                reply_subject = %reply.subject,
                error = reply.headers.get(ERROR_HEADER).unwrap_or("UNKNOWN"),
                "replying with bridge-level error",
            );
            let subject = reply.subject.clone();
            let result = nats
                .publish_with_headers(reply.subject, to_nats_headers(&reply.headers), Bytes::new())
                .await;
            (subject, result)
        }
        BridgeAction::NoReply(error) => {
            warn!(
                error = error.code.as_token(),
                "dropping request because no NATS reply subject was present",
            );
            return;
        }
    };
    if let Err(publish_error) = result {
        error!(
            reply_subject = %subject,
            error = %publish_error,
            "reply publish failed; dropping the reply and keeping the bridge alive",
        );
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
    /// Basil trusted courier channel could not be established.
    #[error("Basil trusted courier connection failed")]
    BasilConnect,
    /// NATS credentials file could not be loaded.
    #[error("NATS credentials file could not be loaded: {0}")]
    NatsCredentials(#[from] std::io::Error),
    /// NATS connection failed.
    #[error("NATS connection failed: {0}")]
    NatsConnect(async_nats::ConnectError),
    /// NATS subscription failed.
    #[error("NATS subscription failed: {0}")]
    NatsSubscribe(async_nats::SubscribeError),
    /// Federation lease setup failed before subscriptions opened.
    #[error("federation lease setup failed")]
    LeaseSetup,
    /// Federation lease ownership was lost or could not be renewed.
    #[error("federation lease ownership lost")]
    LeaseLost,
    /// Clean-shutdown signal registration failed.
    #[error("shutdown signal registration failed: {0}")]
    ShutdownSignal(std::io::Error),
    /// The NATS subscription stream ended; the bridge can no longer serve
    /// requests and a supervisor should restart it.
    #[error("NATS subscription stream ended")]
    SubscriptionEnded,
    /// Request worker failed.
    #[error("bridge request worker failed: {0}")]
    WorkerJoin(tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::missing_panics_doc, clippy::unwrap_used)]

    use std::collections::BTreeMap;
    use std::sync::Mutex as StdMutex;

    use super::*;
    use basil_proto::KeyType;
    use basil_proto::broker::v1::{GetSecretResponse, ImportRequest, KeyMaterial, key_material};

    const VALID_CONFIG: &str = r#"
[nats]
url = "nats://127.0.0.1:4222"
creds = "/run/basil/bridge.creds"

[basil]
socket = "/run/basil/basil.sock"
service-owner-uid = 991
directory-owner-uid = 0
directory-mode = 493
server-uid = 991
socket-mode = 432

[bridge]
request-subject = "basil.invocation"
queue-group = "basil-bridge"
max-message-bytes = 1048576
concurrency-limit = 8
"#;

    #[derive(Debug)]
    struct FakeBasil {
        result: Result<SealedResponse, CourierCallError>,
        challenge_result: Result<GetInvocationChallengeResponse, CourierCallError>,
        received: Vec<SealedRequest>,
        challenges: Vec<(GetInvocationChallengeRequest, String)>,
    }

    impl FakeBasil {
        fn ok(response: SealedResponse) -> Self {
            Self {
                result: Ok(response),
                challenge_result: Ok(GetInvocationChallengeResponse {
                    challenge: vec![7; 32],
                    generation: 9,
                    expires_at_unix: 100,
                }),
                received: Vec::new(),
                challenges: Vec::new(),
            }
        }

        fn err(error: CourierCallError) -> Self {
            Self {
                result: Err(error),
                challenge_result: Ok(GetInvocationChallengeResponse {
                    challenge: vec![7; 32],
                    generation: 9,
                    expires_at_unix: 100,
                }),
                received: Vec::new(),
                challenges: Vec::new(),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct FakeLeaseBackend {
        state: Arc<StdMutex<FakeLeaseBackendState>>,
    }

    #[derive(Debug)]
    struct FakeLeaseBackendState {
        status: LeaseBucketStatus,
        entries: BTreeMap<String, (Bytes, u64)>,
        next_revision: u64,
    }

    impl FakeLeaseBackend {
        fn qualified() -> Self {
            Self::with_status(1, LEASE_MAX_AGE)
        }

        fn with_status(history: i64, max_age: Duration) -> Self {
            Self {
                state: Arc::new(StdMutex::new(FakeLeaseBackendState {
                    status: LeaseBucketStatus { history, max_age },
                    entries: BTreeMap::new(),
                    next_revision: 1,
                })),
            }
        }

        fn expire(&self, key: &str) {
            self.state.lock().unwrap().entries.remove(key);
        }

        fn replace(&self, key: &str, value: Bytes) -> u64 {
            let mut state = self.state.lock().unwrap();
            let revision = state.next_revision;
            state.next_revision += 1;
            state.entries.insert(key.to_owned(), (value, revision));
            revision
        }

        fn entry(&self, key: &str) -> Option<(Bytes, u64)> {
            self.state.lock().unwrap().entries.get(key).cloned()
        }
    }

    #[async_trait]
    impl LeaseBackend for FakeLeaseBackend {
        async fn status(&self) -> Result<LeaseBucketStatus, LeaseError> {
            Ok(self.state.lock().unwrap().status)
        }

        async fn create(&self, key: &str, value: Bytes) -> Result<u64, LeaseError> {
            let mut state = self.state.lock().unwrap();
            if state.entries.contains_key(key) {
                drop(state);
                return Err(LeaseError);
            }
            let revision = state.next_revision;
            state.next_revision += 1;
            state.entries.insert(key.to_owned(), (value, revision));
            drop(state);
            Ok(revision)
        }

        async fn update(&self, key: &str, value: Bytes, revision: u64) -> Result<u64, LeaseError> {
            let mut state = self.state.lock().unwrap();
            if state.entries.get(key).map(|entry| entry.1) != Some(revision) {
                drop(state);
                return Err(LeaseError);
            }
            let next_revision = state.next_revision;
            state.next_revision += 1;
            state.entries.insert(key.to_owned(), (value, next_revision));
            drop(state);
            Ok(next_revision)
        }

        async fn delete(&self, key: &str, revision: u64) -> Result<(), LeaseError> {
            let mut state = self.state.lock().unwrap();
            if state.entries.get(key).map(|entry| entry.1) != Some(revision) {
                drop(state);
                return Err(LeaseError);
            }
            state.entries.remove(key);
            drop(state);
            Ok(())
        }
    }

    #[async_trait]
    impl BasilInvoker for FakeBasil {
        async fn invoke(
            &mut self,
            request: SealedRequest,
        ) -> Result<SealedResponse, CourierCallError> {
            self.received.push(request);
            self.result.clone()
        }

        async fn get_challenge(
            &mut self,
            request: GetInvocationChallengeRequest,
            source: &str,
        ) -> Result<GetInvocationChallengeResponse, CourierCallError> {
            self.challenges.push((request, source.to_owned()));
            self.challenge_result.clone()
        }
    }

    #[test]
    fn overload_before_forward_is_retryable() {
        let BridgeAction::Reply(reply) = overloaded_action(Some("_INBOX.full".to_owned())) else {
            panic!("expected reply");
        };
        assert_error(&reply, BridgeErrorCode::Overloaded, true);

        let BridgeAction::NoReply(error) = overloaded_action(None) else {
            panic!("expected no-reply action");
        };
        assert_eq!(error.code, BridgeErrorCode::Overloaded);
        assert!(error.retryable);
    }

    #[tokio::test]
    async fn lease_acquire_is_atomic_and_expired_entry_can_be_reacquired() {
        let backend = FakeLeaseBackend::qualified();
        let first = FederationLease::acquire(backend.clone(), "basil.challenge", "basil.invoke");
        let second = FederationLease::acquire(backend.clone(), "basil.challenge", "basil.invoke");
        let (first, second) = tokio::join!(first, second);
        assert_ne!(first.is_ok(), second.is_ok());

        let key = lease_key("basil.challenge", "basil.invoke");
        let (value, _) = backend.entry(&key).unwrap();
        assert_eq!(value.len(), 32);
        backend.expire(&key);
        FederationLease::acquire(backend, "basil.challenge", "basil.invoke")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn lease_rejects_wrong_bucket_history_or_max_age() {
        for backend in [
            FakeLeaseBackend::with_status(2, LEASE_MAX_AGE),
            FakeLeaseBackend::with_status(1, Duration::from_secs(14)),
        ] {
            assert!(
                FederationLease::acquire(backend, "basil.challenge", "basil.invoke")
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn lease_cas_loss_fails_renewal_and_preserves_new_owner() {
        let backend = FakeLeaseBackend::qualified();
        let lease = FederationLease::acquire(backend.clone(), "basil.challenge", "basil.invoke")
            .await
            .unwrap();
        let key = lease_key("basil.challenge", "basil.invoke");
        let replacement = Bytes::from_static(b"replacement-owner");
        let replacement_revision = backend.replace(&key, replacement.clone());

        assert!(lease.renew().await.is_err());
        assert_eq!(
            backend.entry(&key),
            Some((replacement, replacement_revision))
        );
    }

    #[tokio::test]
    async fn lease_release_uses_expected_revision() {
        let backend = FakeLeaseBackend::qualified();
        let lease = FederationLease::acquire(backend.clone(), "basil.challenge", "basil.invoke")
            .await
            .unwrap();
        let key = lease_key("basil.challenge", "basil.invoke");
        let replacement = Bytes::from_static(b"replacement-owner");
        let replacement_revision = backend.replace(&key, replacement.clone());

        assert!(lease.release().await.is_err());
        assert_eq!(
            backend.entry(&key),
            Some((replacement, replacement_revision))
        );
    }

    #[tokio::test]
    async fn distinct_subject_pairs_have_independent_leases() {
        let backend = FakeLeaseBackend::qualified();
        FederationLease::acquire(backend.clone(), "basil.a", "basil.bc")
            .await
            .unwrap();
        FederationLease::acquire(backend.clone(), "basil.ab", "basil.c")
            .await
            .unwrap();

        let first_key = lease_key("basil.a", "basil.bc");
        let second_key = lease_key("basil.ab", "basil.c");
        assert_ne!(first_key, second_key);
        assert!(backend.entry(&first_key).is_some());
        assert!(backend.entry(&second_key).is_some());
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
        assert_eq!(config.bridge.concurrency_limit, 8);
    }

    #[test]
    fn parses_config_without_optional_creds_or_queue_group() {
        let config = Config::from_toml_str(
            r#"
[nats]
url = "nats://127.0.0.1:4222"

[basil]
socket = "/run/basil/basil.sock"
service-owner-uid = 991
directory-owner-uid = 0
directory-mode = 493
server-uid = 991
socket-mode = 432

[bridge]
request-subject = "basil.invocation"
max-message-bytes = 4096
"#,
        )
        .unwrap();

        assert_eq!(config.nats.creds, None);
        assert_eq!(config.bridge.queue_group, None);
        assert_eq!(config.bridge.concurrency_limit, DEFAULT_CONCURRENCY_LIMIT);
    }

    #[test]
    fn rejects_zero_concurrency_limit() {
        let error = Config::from_toml_str(
            r#"
[nats]
url = "nats://127.0.0.1:4222"

[basil]
socket = "/run/basil/basil.sock"
service-owner-uid = 991
directory-owner-uid = 0
directory-mode = 493
server-uid = 991
socket-mode = 432

[bridge]
request-subject = "basil.invocation"
max-message-bytes = 1024
concurrency-limit = 0
"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigError::InvalidConcurrencyLimit { value: 0 }
        ));
    }

    #[test]
    fn rejects_empty_config_fields() {
        let error = Config::from_toml_str(
            r#"
[nats]
url = " "

[basil]
socket = "/run/basil/basil.sock"
service-owner-uid = 991
directory-owner-uid = 0
directory-mode = 493
server-uid = 991
socket-mode = 432

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
service-owner-uid = 991
directory-owner-uid = 0
directory-mode = 493
server-uid = 991
socket-mode = 432

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

    #[test]
    fn federation_requires_distinct_subject_pair_without_queue_group() {
        let same = VALID_CONFIG
            .replace("queue-group = \"basil-bridge\"\n", "")
            .replace(
                "max-message-bytes = 1048576",
                "challenge-subject = \"basil.invocation\"\nsource-partition = \"agent-a\"\nlease-bucket = \"BASIL_COURIER_LEASES\"\nmax-message-bytes = 1048576",
            );
        assert!(matches!(
            Config::from_toml_str(&same),
            Err(ConfigError::SubjectsMustDiffer)
        ));

        let queued = VALID_CONFIG.replace(
            "max-message-bytes = 1048576",
            "challenge-subject = \"basil.challenge\"\nsource-partition = \"agent-a\"\nlease-bucket = \"BASIL_COURIER_LEASES\"\nmax-message-bytes = 1048576",
        );
        assert!(matches!(
            Config::from_toml_str(&queued),
            Err(ConfigError::FederationQueueGroup)
        ));
    }

    #[test]
    fn federation_requires_both_challenge_subject_and_partition() {
        let incomplete = VALID_CONFIG.replace(
            "max-message-bytes = 1048576",
            "challenge-subject = \"basil.challenge\"\nmax-message-bytes = 1048576",
        );
        assert!(matches!(
            Config::from_toml_str(&incomplete),
            Err(ConfigError::IncompleteFederation)
        ));
    }

    #[tokio::test]
    async fn challenge_contract_injects_partition_and_returns_protobuf() {
        let request = GetInvocationChallengeRequest {
            jkt: vec![3; 32],
            courier_observed_source: None,
        };
        let mut basil = FakeBasil::ok(sealed_response(b"unused"));
        let action = handle_challenge_request(
            BridgeRequest {
                subject: "basil.challenge".to_owned(),
                reply: Some("_INBOX.challenge".to_owned()),
                payload: request.encode_to_vec(),
            },
            "agent-a",
            &mut basil,
        )
        .await;

        assert_eq!(basil.challenges, vec![(request, "agent-a".to_owned())]);
        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert!(reply.headers.is_empty());
        let response = GetInvocationChallengeResponse::decode(reply.payload.as_slice()).unwrap();
        assert_eq!(response.challenge, vec![7; 32]);
        assert_eq!(response.generation, 9);
    }

    #[tokio::test]
    async fn challenge_rejects_caller_supplied_source_without_forwarding() {
        let request = GetInvocationChallengeRequest {
            jkt: vec![3; 32],
            courier_observed_source: Some("attacker".to_owned()),
        };
        let mut basil = FakeBasil::ok(sealed_response(b"unused"));
        let action = handle_challenge_request(
            BridgeRequest {
                subject: "basil.challenge".to_owned(),
                reply: Some("_INBOX.challenge".to_owned()),
                payload: request.encode_to_vec(),
            },
            "agent-a",
            &mut basil,
        )
        .await;

        assert!(basil.challenges.is_empty());
        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_error(&reply, BridgeErrorCode::MalformedRequest, false);
    }

    #[tokio::test]
    async fn challenge_pressure_uses_sanitized_retryable_token() {
        let mut basil = FakeBasil::ok(sealed_response(b"unused"));
        basil.challenge_result = Err(CourierCallError::ChallengeDeclined);
        let action = handle_challenge_request(
            BridgeRequest {
                subject: "basil.challenge".to_owned(),
                reply: Some("_INBOX.challenge".to_owned()),
                payload: GetInvocationChallengeRequest {
                    jkt: vec![3; 32],
                    courier_observed_source: None,
                }
                .encode_to_vec(),
            },
            "agent-a",
            &mut basil,
        )
        .await;

        let BridgeAction::Reply(reply) = action else {
            panic!("expected reply");
        };
        assert_error(&reply, BridgeErrorCode::ChallengeIssuanceDeclined, true);
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
        let mut basil = FakeBasil::err(CourierCallError::UnavailableAfterForward);
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
        assert_error(&reply, BridgeErrorCode::BasilUnavailable, false);
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
        let mut basil = FakeBasil::err(CourierCallError::BrokerRejected);

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
        assert_eq!(reply.headers.inner.len(), 2);
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
        let mut basil = FakeBasil::err(CourierCallError::BrokerRejected);
        let reply = invoke_error_reply(&mut basil).await;

        assert_error(&reply, BridgeErrorCode::BasilRejected, false);
    }

    #[tokio::test]
    async fn post_forward_timeout_is_not_retryable() {
        let mut basil = FakeBasil::err(CourierCallError::DeadlineAfterForward);
        let reply = invoke_error_reply(&mut basil).await;

        assert_error(&reply, BridgeErrorCode::Timeout, false);
    }

    #[tokio::test]
    async fn post_forward_unavailable_is_not_retryable() {
        let mut basil = FakeBasil::err(CourierCallError::UnavailableAfterForward);
        let reply = invoke_error_reply(&mut basil).await;

        assert_error(&reply, BridgeErrorCode::BasilUnavailable, false);
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
        assert_eq!(reply.headers.inner.len(), 2);
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
