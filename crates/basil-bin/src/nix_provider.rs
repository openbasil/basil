// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Reference provider for the purpose-specific Nix external-signer protocol.

use std::ffi::OsString;
use std::future::Future;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use basil::{Client, NixCacheKey, NixCacheSignature};
use basil_core::nix_cache_fingerprint::PathInfoV1;
use clap::Args;
use ed25519_dalek::{Signature, VerifyingKey};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};

const HEADER_LEN: usize = 48;
const CORRELATION_ID_LEN: usize = 16;
const ENDPOINT_ID_LEN: usize = 16;
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const MAX_KEY_NAME_LEN: usize = 128;
const MAX_SIGN_REQUEST_BODY: usize = 524_808;
const MAX_DIAGNOSTIC_LEN: usize = 1_024;
const OPERATION_DEADLINE: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 32;
const MAX_SIGNS: usize = 8;
const RANDOM_ID_ATTEMPTS: usize = 8;

const MAGIC: &[u8; 4] = b"NXSG";
const MAJOR: u8 = 1;
const MINOR: u8 = 0;

/// Arguments for `basil nix provider serve`.
#[derive(Clone, Debug, Args)]
pub struct ProviderServeArgs {
    /// Enrolled catalog key ID served by this listener.
    #[arg(long)]
    pub key_id: String,
    /// Absolute path of the owner-only Nix external-signer socket.
    #[arg(long)]
    pub listen: PathBuf,
}

/// Run one Nix external-signer listener until `SIGINT` or `SIGTERM`.
///
/// # Errors
///
/// Returns an error when the Basil connection, random endpoint generation,
/// secure socket publication, accept loop, or shutdown signal fails.
pub async fn serve(basil_socket: &str, args: ProviderServeArgs) -> Result<()> {
    let client = Client::connect_with_timeout(basil_socket, OPERATION_DEADLINE.as_secs())
        .await
        .with_context(|| format!("connecting to agent at {basil_socket}"))?;
    let provider = NixProvider::new(args.key_id, client)?;
    let listener = SecureListener::bind(&args.listen)?;
    let shutdown = async {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("waiting for SIGINT"),
            result = terminate_signal() => result,
        }
    };
    provider.serve_until(listener, shutdown).await
}

#[cfg(unix)]
async fn terminate_signal() -> Result<()> {
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("registering SIGTERM handler")?;
    let _ = signal.recv().await;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum MessageType {
    DescribeRequest = 0x01,
    SignRequest = 0x02,
    DescribeResponse = 0x81,
    SignResponse = 0x82,
}

impl MessageType {
    const fn response(self) -> Option<Self> {
        match self {
            Self::DescribeRequest => Some(Self::DescribeResponse),
            Self::SignRequest => Some(Self::SignResponse),
            Self::DescribeResponse | Self::SignResponse => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Status {
    Ok = 0,
    Malformed = 1,
    UnsupportedVersion = 2,
    Unauthorized = 3,
    KeyMismatch = 4,
    InvalidFingerprint = 5,
    Unavailable = 6,
    DeadlineExceeded = 7,
    Internal = 8,
    Overloaded = 9,
}

#[derive(Clone, Copy, Debug)]
struct RequestHeader {
    request_type: MessageType,
    body_len: usize,
    batch_id: [u8; CORRELATION_ID_LEN],
    request_id: [u8; CORRELATION_ID_LEN],
}

impl RequestHeader {
    const fn response_type(self) -> MessageType {
        match self.request_type {
            MessageType::DescribeRequest => MessageType::DescribeResponse,
            MessageType::SignRequest => MessageType::SignResponse,
            MessageType::DescribeResponse | MessageType::SignResponse => {
                // Request parsing never constructs a response message type.
                MessageType::DescribeResponse
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ResponseContext {
    response_type: MessageType,
    batch_id: [u8; CORRELATION_ID_LEN],
    request_id: [u8; CORRELATION_ID_LEN],
}

impl From<RequestHeader> for ResponseContext {
    fn from(header: RequestHeader) -> Self {
        Self {
            response_type: header.response_type(),
            batch_id: header.batch_id,
            request_id: header.request_id,
        }
    }
}

#[derive(Debug)]
struct ProtocolFailure {
    status: Status,
    diagnostic: &'static str,
    response: Option<ResponseContext>,
}

impl ProtocolFailure {
    const fn close(diagnostic: &'static str) -> Self {
        Self {
            status: Status::Malformed,
            diagnostic,
            response: None,
        }
    }

    const fn respond(status: Status, diagnostic: &'static str, response: ResponseContext) -> Self {
        Self {
            status,
            diagnostic,
            response: Some(response),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SignRequest {
    key_name: String,
    public_key: [u8; PUBLIC_KEY_LEN],
    endpoint_id: [u8; ENDPOINT_ID_LEN],
    fingerprint: Vec<u8>,
}

trait NixCacheRpc: Clone + Send + Sync + 'static {
    fn describe_nix_cache_key(
        &mut self,
        key_id: &str,
        batch_id: [u8; CORRELATION_ID_LEN],
        request_id: [u8; CORRELATION_ID_LEN],
    ) -> impl Future<Output = basil::Result<NixCacheKey>> + Send;

    fn sign_nix_cache_fingerprint(
        &mut self,
        key_id: &str,
        fingerprint: &[u8],
        batch_id: [u8; CORRELATION_ID_LEN],
        request_id: [u8; CORRELATION_ID_LEN],
    ) -> impl Future<Output = basil::Result<NixCacheSignature>> + Send;
}

impl NixCacheRpc for Client {
    async fn describe_nix_cache_key(
        &mut self,
        key_id: &str,
        batch_id: [u8; CORRELATION_ID_LEN],
        request_id: [u8; CORRELATION_ID_LEN],
    ) -> basil::Result<NixCacheKey> {
        Self::describe_nix_cache_key(self, key_id, batch_id, request_id).await
    }

    async fn sign_nix_cache_fingerprint(
        &mut self,
        key_id: &str,
        fingerprint: &[u8],
        batch_id: [u8; CORRELATION_ID_LEN],
        request_id: [u8; CORRELATION_ID_LEN],
    ) -> basil::Result<NixCacheSignature> {
        Self::sign_nix_cache_fingerprint(self, key_id, fingerprint, batch_id, request_id).await
    }
}

#[derive(Clone)]
struct NixProvider<C> {
    key_id: Arc<str>,
    endpoint_id: [u8; ENDPOINT_ID_LEN],
    client: C,
    identity: Arc<RwLock<Option<NixCacheKey>>>,
    connection_slots: Arc<Semaphore>,
    sign_slots: Arc<Semaphore>,
    overload_slot: Arc<Semaphore>,
}

impl<C: NixCacheRpc> NixProvider<C> {
    fn new(key_id: String, client: C) -> Result<Self> {
        if key_id.is_empty()
            || key_id.len() > 256
            || key_id.as_bytes().contains(&0)
            || key_id.chars().any(char::is_control)
        {
            bail!("Nix provider key ID is outside the broker contract");
        }
        Ok(Self {
            key_id: Arc::from(key_id),
            endpoint_id: random_nonzero_id()?,
            client,
            identity: Arc::new(RwLock::new(None)),
            connection_slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            sign_slots: Arc::new(Semaphore::new(MAX_SIGNS)),
            overload_slot: Arc::new(Semaphore::new(1)),
        })
    }

    async fn serve_until<F>(self, listener: SecureListener, shutdown: F) -> Result<()>
    where
        F: Future<Output = Result<()>>,
    {
        self.serve_until_with_deadline(listener, shutdown, OPERATION_DEADLINE)
            .await
    }

    async fn serve_until_with_deadline<F>(
        self,
        listener: SecureListener,
        shutdown: F,
        operation_deadline: Duration,
    ) -> Result<()>
    where
        F: Future<Output = Result<()>>,
    {
        tokio::pin!(shutdown);
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                result = &mut shutdown => {
                    result?;
                    break;
                }
                accepted = listener.accept() => {
                    let stream = match accepted {
                        Ok(stream) => stream,
                        Err(error) => {
                            tracing::warn!(%error, "Nix provider accept failed; retrying");
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                    };
                    let deadline = Instant::now() + operation_deadline;
                    match Arc::clone(&self.connection_slots).try_acquire_owned() {
                        Ok(permit) => {
                            let provider = self.clone();
                            tasks.spawn(async move {
                                let _permit = permit;
                                provider.handle_bounded(stream, deadline).await;
                            });
                        }
                        Err(_) => {
                            if let Ok(permit) = Arc::clone(&self.overload_slot).try_acquire_owned() {
                                tasks.spawn(async move {
                                    let _permit = permit;
                                    reject_overloaded(stream, deadline).await;
                                });
                            }
                        }
                    }
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = completed {
                        tracing::warn!(%error, "Nix provider connection task failed");
                    }
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        drop(listener);
        Ok(())
    }

    async fn handle_bounded(&self, stream: UnixStream, deadline: Instant) {
        let mut stream = stream;
        if timeout_at(deadline, self.handle(&mut stream))
            .await
            .is_err()
        {
            let _ = stream.shutdown().await;
        }
    }

    async fn handle(&self, stream: &mut UnixStream) {
        if !same_uid(stream) {
            return;
        }
        let request = match read_request(stream).await {
            Ok(request) => request,
            Err(failure) => {
                write_failure(stream, failure).await;
                return;
            }
        };
        let response = match request.0.request_type {
            MessageType::DescribeRequest => self.describe(request.0).await,
            MessageType::SignRequest => self.sign(request.0, &request.1).await,
            MessageType::DescribeResponse | MessageType::SignResponse => {
                Err(ProtocolFailure::close("invalid request type"))
            }
        };
        match response {
            Ok(body) => {
                let bytes = encode_response(request.0.into(), Status::Ok, &body);
                let _ = stream.write_all(&bytes).await;
            }
            Err(failure) => write_failure(stream, failure).await,
        }
        let _ = stream.shutdown().await;
    }

    async fn describe(&self, header: RequestHeader) -> Result<Vec<u8>, ProtocolFailure> {
        let context = header.into();
        let mut client = self.client.clone();
        let described = client
            .describe_nix_cache_key(&self.key_id, header.batch_id, header.request_id)
            .await
            .map_err(|error| rpc_failure(&error, context))?;
        validate_key_identity(&described).map_err(|()| {
            ProtocolFailure::respond(Status::Internal, "invalid Basil key identity", context)
        })?;

        let mut pin = self.identity.write().await;
        if let Some(expected) = pin.as_ref() {
            if expected != &described {
                return Err(ProtocolFailure::respond(
                    Status::Unavailable,
                    "configured key identity changed",
                    context,
                ));
            }
        } else {
            *pin = Some(described.clone());
        }
        drop(pin);
        Ok(encode_describe_body(&described, &self.endpoint_id))
    }

    async fn sign(&self, header: RequestHeader, body: &[u8]) -> Result<Vec<u8>, ProtocolFailure> {
        let context = header.into();
        let request = parse_sign_body(body).map_err(|status| {
            ProtocolFailure::respond(status, status_diagnostic(status), context)
        })?;
        let identity = self.identity.read().await.clone().ok_or_else(|| {
            ProtocolFailure::respond(
                Status::KeyMismatch,
                "key identity has not been described",
                context,
            )
        })?;
        if request.key_name != identity.key_name
            || request.public_key != identity.public_key
            || request.endpoint_id != self.endpoint_id
        {
            return Err(ProtocolFailure::respond(
                Status::KeyMismatch,
                "pinned key identity does not match",
                context,
            ));
        }
        let fingerprint = PathInfoV1::parse(&request.fingerprint).map_err(|_| {
            ProtocolFailure::respond(
                Status::InvalidFingerprint,
                "fingerprint is not canonical PATH_INFO_V1",
                context,
            )
        })?;
        let _sign_permit = Arc::clone(&self.sign_slots)
            .try_acquire_owned()
            .map_err(|_| {
                ProtocolFailure::respond(Status::Overloaded, "signer is overloaded", context)
            })?;
        let mut client = self.client.clone();
        let signed = client
            .sign_nix_cache_fingerprint(
                &self.key_id,
                fingerprint.as_bytes(),
                header.batch_id,
                header.request_id,
            )
            .await
            .map_err(|error| rpc_failure(&error, context))?;
        if signed.key != identity {
            return Err(ProtocolFailure::respond(
                Status::Internal,
                "Basil signing identity changed",
                context,
            ));
        }
        verify_signature(&identity, fingerprint.as_bytes(), &signed.signature).map_err(|()| {
            ProtocolFailure::respond(
                Status::Internal,
                "Basil returned an invalid signature",
                context,
            )
        })?;
        Ok(encode_sign_body(
            &identity,
            &self.endpoint_id,
            &signed.signature,
        ))
    }
}

const fn rpc_failure(error: &basil::Error, context: ResponseContext) -> ProtocolFailure {
    let status = match error {
        basil::Error::Timeout => Status::DeadlineExceeded,
        basil::Error::Status {
            code: tonic::Code::PermissionDenied | tonic::Code::Unauthenticated,
            ..
        } => Status::Unauthorized,
        basil::Error::Protocol(_) => Status::Internal,
        basil::Error::Io(_)
        | basil::Error::Endpoint(_)
        | basil::Error::Json(_)
        | basil::Error::Status { .. } => Status::Unavailable,
    };
    ProtocolFailure::respond(status, status_diagnostic(status), context)
}

fn verify_signature(
    identity: &NixCacheKey,
    fingerprint: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> std::result::Result<(), ()> {
    let key = VerifyingKey::from_bytes(&identity.public_key).map_err(|_| ())?;
    key.verify_strict(fingerprint, &Signature::from_bytes(signature))
        .map_err(|_| ())
}

async fn reject_overloaded(mut stream: UnixStream, deadline: Instant) {
    if !same_uid(&stream) {
        return;
    }
    let operation = async {
        match read_request(&mut stream).await {
            Ok((header, _)) => {
                write_failure(
                    &mut stream,
                    ProtocolFailure::respond(
                        Status::Overloaded,
                        "connection limit is full",
                        header.into(),
                    ),
                )
                .await;
            }
            Err(failure) => write_failure(&mut stream, failure).await,
        }
        let _ = stream.shutdown().await;
    };
    let _ = timeout_at(deadline, operation).await;
}

fn same_uid(stream: &UnixStream) -> bool {
    peer_uid_result_is_authorized(
        stream.peer_cred().map(|credentials| credentials.uid()),
        rustix::process::geteuid().as_raw(),
    )
}

const fn peer_uid_is_authorized(peer_uid: u32, provider_uid: u32) -> bool {
    peer_uid == provider_uid
}

fn peer_uid_result_is_authorized<E>(peer_uid: Result<u32, E>, provider_uid: u32) -> bool {
    peer_uid.is_ok_and(|uid| peer_uid_is_authorized(uid, provider_uid))
}

async fn read_request(
    stream: &mut UnixStream,
) -> std::result::Result<(RequestHeader, Vec<u8>), ProtocolFailure> {
    let mut encoded = [0_u8; HEADER_LEN];
    stream
        .read_exact(&mut encoded)
        .await
        .map_err(|_| ProtocolFailure::close("truncated header"))?;
    let header = parse_request_header(&encoded)?;
    let mut body = vec![0_u8; header.body_len];
    stream.read_exact(&mut body).await.map_err(|_| {
        ProtocolFailure::respond(Status::Malformed, "truncated body", header.into())
    })?;
    let mut trailing = [0_u8; 1];
    let count = stream.read(&mut trailing).await.map_err(|_| {
        ProtocolFailure::respond(Status::Malformed, "request read failed", header.into())
    })?;
    if count != 0 {
        return Err(ProtocolFailure::respond(
            Status::Malformed,
            "trailing request bytes",
            header.into(),
        ));
    }
    Ok((header, body))
}

fn parse_request_header(
    encoded: &[u8; HEADER_LEN],
) -> std::result::Result<RequestHeader, ProtocolFailure> {
    if encoded.get(0..4) != Some(MAGIC.as_slice()) {
        return Err(ProtocolFailure::close("bad magic"));
    }
    let request_type = match encoded.get(6).copied() {
        Some(0x01) => MessageType::DescribeRequest,
        Some(0x02) => MessageType::SignRequest,
        _ => return Err(ProtocolFailure::close("unknown request type")),
    };
    let mut batch_id = [0_u8; CORRELATION_ID_LEN];
    let mut request_id = [0_u8; CORRELATION_ID_LEN];
    let Some(batch) = encoded.get(16..32) else {
        return Err(ProtocolFailure::close("truncated batch ID"));
    };
    let Some(request) = encoded.get(32..48) else {
        return Err(ProtocolFailure::close("truncated request ID"));
    };
    batch_id.copy_from_slice(batch);
    request_id.copy_from_slice(request);
    if batch_id == [0; CORRELATION_ID_LEN] || request_id == [0; CORRELATION_ID_LEN] {
        return Err(ProtocolFailure::close("zero correlation ID"));
    }
    let response = ResponseContext {
        response_type: request_type
            .response()
            .unwrap_or(MessageType::DescribeResponse),
        batch_id,
        request_id,
    };
    if encoded.get(4) != Some(&MAJOR) || encoded.get(5) != Some(&MINOR) {
        return Err(ProtocolFailure::respond(
            Status::UnsupportedVersion,
            "unsupported NXSG version",
            response,
        ));
    }
    if encoded.get(7) != Some(&0) {
        return Err(ProtocolFailure::respond(
            Status::Malformed,
            "request status must be zero",
            response,
        ));
    }
    if encoded.get(8..12) != Some([0_u8; 4].as_slice()) {
        return Err(ProtocolFailure::respond(
            Status::Malformed,
            "request flags must be zero",
            response,
        ));
    }
    let length_bytes: [u8; 4] = encoded
        .get(12..16)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| ProtocolFailure::close("truncated length"))?;
    let body_len = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| ProtocolFailure::respond(Status::Malformed, "body too large", response))?;
    let valid_length = match request_type {
        MessageType::DescribeRequest => body_len == 0,
        MessageType::SignRequest => body_len <= MAX_SIGN_REQUEST_BODY,
        MessageType::DescribeResponse | MessageType::SignResponse => false,
    };
    if !valid_length {
        return Err(ProtocolFailure::respond(
            Status::Malformed,
            "body length exceeds message bound",
            response,
        ));
    }
    Ok(RequestHeader {
        request_type,
        body_len,
        batch_id,
        request_id,
    })
}

fn parse_sign_body(body: &[u8]) -> std::result::Result<SignRequest, Status> {
    let key_length = body
        .get(0..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map(u16::from_be_bytes)
        .map(usize::from)
        .ok_or(Status::Malformed)?;
    if !(1..=MAX_KEY_NAME_LEN).contains(&key_length) {
        return Err(Status::Malformed);
    }
    let key_end = 2usize.checked_add(key_length).ok_or(Status::Malformed)?;
    let public_end = key_end
        .checked_add(PUBLIC_KEY_LEN)
        .ok_or(Status::Malformed)?;
    let endpoint_end = public_end
        .checked_add(ENDPOINT_ID_LEN)
        .ok_or(Status::Malformed)?;
    let length_end = endpoint_end.checked_add(4).ok_or(Status::Malformed)?;
    let key_bytes = body.get(2..key_end).ok_or(Status::Malformed)?;
    let key_name = validate_key_name(key_bytes).ok_or(Status::Malformed)?;
    let public_key = body
        .get(key_end..public_end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Status::Malformed)?;
    let endpoint_id = body
        .get(public_end..endpoint_end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Status::Malformed)?;
    if endpoint_id == [0; ENDPOINT_ID_LEN] {
        return Err(Status::KeyMismatch);
    }
    let fingerprint_length = body
        .get(endpoint_end..length_end)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(Status::Malformed)?;
    let fingerprint_end = length_end
        .checked_add(fingerprint_length)
        .ok_or(Status::Malformed)?;
    if fingerprint_end != body.len() {
        return Err(Status::Malformed);
    }
    let fingerprint = body
        .get(length_end..fingerprint_end)
        .ok_or(Status::Malformed)?
        .to_vec();
    Ok(SignRequest {
        key_name,
        public_key,
        endpoint_id,
        fingerprint,
    })
}

fn validate_key_name(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut chars = text.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphanumeric()
        || !chars.all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return None;
    }
    Some(text.to_string())
}

fn validate_key_identity(key: &NixCacheKey) -> std::result::Result<(), ()> {
    if key.backend_version != 1
        || key.key_name.len() > MAX_KEY_NAME_LEN
        || validate_key_name(key.key_name.as_bytes()).is_none()
        || VerifyingKey::from_bytes(&key.public_key).is_err()
    {
        return Err(());
    }
    Ok(())
}

fn encode_describe_body(key: &NixCacheKey, endpoint_id: &[u8; ENDPOINT_ID_LEN]) -> Vec<u8> {
    let mut body =
        Vec::with_capacity(2 + key.key_name.len() + 1 + PUBLIC_KEY_LEN + ENDPOINT_ID_LEN);
    push_key_name(&mut body, &key.key_name);
    body.push(1);
    body.extend_from_slice(&key.public_key);
    body.extend_from_slice(endpoint_id);
    body
}

fn encode_sign_body(
    key: &NixCacheKey,
    endpoint_id: &[u8; ENDPOINT_ID_LEN],
    signature: &[u8; SIGNATURE_LEN],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(
        2 + key.key_name.len() + PUBLIC_KEY_LEN + ENDPOINT_ID_LEN + SIGNATURE_LEN,
    );
    push_key_name(&mut body, &key.key_name);
    body.extend_from_slice(&key.public_key);
    body.extend_from_slice(endpoint_id);
    body.extend_from_slice(signature);
    body
}

fn push_key_name(output: &mut Vec<u8>, key_name: &str) {
    let length = u16::try_from(key_name.len()).unwrap_or(0);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(key_name.as_bytes());
}

fn encode_response(context: ResponseContext, status: Status, body: &[u8]) -> Vec<u8> {
    let body_len = u32::try_from(body.len()).unwrap_or(0);
    let mut encoded = Vec::with_capacity(HEADER_LEN.saturating_add(body.len()));
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&[MAJOR, MINOR, context.response_type as u8, status as u8]);
    encoded.extend_from_slice(&[0; 4]);
    encoded.extend_from_slice(&body_len.to_be_bytes());
    encoded.extend_from_slice(&context.batch_id);
    encoded.extend_from_slice(&context.request_id);
    encoded.extend_from_slice(body);
    encoded
}

fn encode_diagnostic(diagnostic: &str) -> Vec<u8> {
    let mut text = String::new();
    for character in diagnostic
        .chars()
        .filter(|character| !character.is_control())
    {
        let next = text.len().saturating_add(character.len_utf8());
        if next > MAX_DIAGNOSTIC_LEN {
            break;
        }
        text.push(character);
    }
    let length = u16::try_from(text.len()).unwrap_or(0);
    let mut body = Vec::with_capacity(2 + text.len());
    body.extend_from_slice(&length.to_be_bytes());
    body.extend_from_slice(text.as_bytes());
    body
}

async fn write_failure(stream: &mut UnixStream, failure: ProtocolFailure) {
    let Some(context) = failure.response else {
        return;
    };
    let body = encode_diagnostic(failure.diagnostic);
    let response = encode_response(context, failure.status, &body);
    let _ = stream.write_all(&response).await;
}

const fn status_diagnostic(status: Status) -> &'static str {
    match status {
        Status::Ok => "request succeeded",
        Status::Malformed => "malformed request",
        Status::UnsupportedVersion => "unsupported NXSG version",
        Status::Unauthorized => "request is not authorized",
        Status::KeyMismatch => "pinned key identity does not match",
        Status::InvalidFingerprint => "fingerprint is not canonical PATH_INFO_V1",
        Status::Unavailable => "signing key is unavailable",
        Status::DeadlineExceeded => "operation deadline exceeded",
        Status::Internal => "provider operation failed",
        Status::Overloaded => "provider is overloaded",
    }
}

fn random_nonzero_id() -> Result<[u8; ENDPOINT_ID_LEN]> {
    for _ in 0..RANDOM_ID_ATTEMPTS {
        let mut id = [0_u8; ENDPOINT_ID_LEN];
        getrandom::fill(&mut id)
            .map_err(|error| anyhow!("generating Nix provider endpoint ID: {error}"))?;
        if id != [0; ENDPOINT_ID_LEN] {
            return Ok(id);
        }
    }
    bail!("operating-system randomness did not produce a nonzero endpoint ID")
}

#[derive(Debug, Error)]
enum ListenerError {
    #[error("Nix provider socket path must be an absolute directory-and-leaf path")]
    InvalidPath,
    #[error("Nix provider socket parent must be a real owner-only directory")]
    UntrustedDirectory,
    #[error("Nix provider socket path already exists")]
    PathOccupied,
    #[error("Nix provider socket operation failed: {0}")]
    Io(#[from] rustix::io::Errno),
    #[error("Nix provider runtime registration failed: {0}")]
    Runtime(#[from] std::io::Error),
}

#[derive(Debug)]
struct SecureListener {
    inner: UnixListener,
    parent: OwnedFd,
    name: OsString,
    binding: OwnedFd,
}

impl SecureListener {
    fn bind(path: &Path) -> std::result::Result<Self, ListenerError> {
        if !path.is_absolute() {
            return Err(ListenerError::InvalidPath);
        }
        let name = path.file_name().ok_or(ListenerError::InvalidPath)?;
        let parent_fd = open_parent_without_symlinks(path)?;
        let parent_stat = rustix::fs::fstat(&parent_fd)?;
        if FileType::from_raw_mode(parent_stat.st_mode) != FileType::Directory
            || parent_stat.st_uid != rustix::process::geteuid().as_raw()
            || parent_stat.st_mode & 0o7777 != 0o700
        {
            return Err(ListenerError::UntrustedDirectory);
        }
        match rustix::fs::statat(&parent_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Ok(_) => return Err(ListenerError::PathOccupied),
            Err(error) => return Err(error.into()),
        }
        let fd = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        let address = SocketAddrUnix::new(path)?;
        rustix::net::bind(&fd, &address)?;
        // Linux reports a sockfs inode for the AF_UNIX descriptor and a
        // filesystem inode for the pathname, so those two `fstat` results are
        // not comparable. Retain an `O_PATH` descriptor for the final
        // direntry instead. The owner-only parent makes the narrow bind-to-open
        // interval part of the documented same-UID trust domain.
        let binding = rustix::fs::openat(
            &parent_fd,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ListenerError::PathOccupied)?;
        if let Err(error) = rustix::fs::chmodat(
            &parent_fd,
            name,
            Mode::from_bits_truncate(0o600),
            AtFlags::empty(),
        ) {
            remove_if_binding_current(&parent_fd, name, &binding, false);
            return Err(error.into());
        }
        let socket_stat = match rustix::fs::statat(&parent_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(error) => {
                remove_if_binding_current(&parent_fd, name, &binding, false);
                return Err(error.into());
            }
        };
        let binding_stat = rustix::fs::fstat(&binding)?;
        if FileType::from_raw_mode(socket_stat.st_mode) != FileType::Socket
            || FileType::from_raw_mode(binding_stat.st_mode) != FileType::Socket
            || socket_stat.st_uid != rustix::process::geteuid().as_raw()
            || socket_stat.st_mode & 0o7777 != 0o600
            || socket_stat.st_dev != binding_stat.st_dev
            || socket_stat.st_ino != binding_stat.st_ino
        {
            return Err(ListenerError::PathOccupied);
        }
        if let Err(error) = rustix::net::listen(&fd, i32::try_from(MAX_CONNECTIONS).unwrap_or(32)) {
            remove_if_binding_current(&parent_fd, name, &binding, true);
            return Err(error.into());
        }
        let std_listener = StdUnixListener::from(fd);
        let exact_address = std_listener
            .local_addr()
            .ok()
            .and_then(|address| address.as_pathname().map(Path::to_path_buf))
            .is_some_and(|bound| bound == path);
        if !exact_address {
            remove_if_binding_current(&parent_fd, name, &binding, true);
            return Err(ListenerError::PathOccupied);
        }
        let inner = match UnixListener::from_std(std_listener) {
            Ok(listener) => listener,
            Err(error) => {
                remove_if_binding_current(&parent_fd, name, &binding, true);
                return Err(error.into());
            }
        };
        Ok(Self {
            inner,
            parent: parent_fd,
            name: name.to_os_string(),
            binding,
        })
    }

    async fn accept(&self) -> std::io::Result<UnixStream> {
        self.inner.accept().await.map(|(stream, _)| stream)
    }
}

impl Drop for SecureListener {
    fn drop(&mut self) {
        remove_if_binding_current(&self.parent, &self.name, &self.binding, true);
    }
}

fn remove_if_binding_current(
    parent: &OwnedFd,
    name: &std::ffi::OsStr,
    binding: &OwnedFd,
    require_published_mode: bool,
) {
    let Ok(bound) = rustix::fs::fstat(binding) else {
        return;
    };
    let Ok(current) = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return;
    };
    if FileType::from_raw_mode(bound.st_mode) == FileType::Socket
        && FileType::from_raw_mode(current.st_mode) == FileType::Socket
        && current.st_dev == bound.st_dev
        && current.st_ino == bound.st_ino
        && current.st_uid == rustix::process::geteuid().as_raw()
        && (!require_published_mode || current.st_mode & 0o7777 == 0o600)
    {
        let _ = rustix::fs::unlinkat(parent, name, AtFlags::empty());
    }
}

fn open_parent_without_symlinks(path: &Path) -> std::result::Result<OwnedFd, ListenerError> {
    use std::path::Component;

    let parent = path.parent().ok_or(ListenerError::InvalidPath)?;
    let mut components = parent.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(ListenerError::InvalidPath);
    }
    let mut directory = rustix::fs::open(
        "/",
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
        Mode::empty(),
    )
    .map_err(|_| ListenerError::UntrustedDirectory)?;
    for component in components {
        let Component::Normal(name) = component else {
            return Err(ListenerError::UntrustedDirectory);
        };
        directory = rustix::fs::openat(
            &directory,
            name,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
            Mode::empty(),
        )
        .map_err(|_| ListenerError::UntrustedDirectory)?;
    }
    Ok(directory)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use std::collections::VecDeque;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::sync::Mutex;

    use base64::Engine as _;
    use basil_core::core::nix_cache_file::{NarinfoEdit, NarinfoMutation, edit_narinfo};
    use ed25519_dalek::{Signer as _, SigningKey};
    use serde::Deserialize;

    use super::*;

    const BATCH_ID: [u8; CORRELATION_ID_LEN] = [0x41; CORRELATION_ID_LEN];
    const REQUEST_ID: [u8; CORRELATION_ID_LEN] = [0x52; CORRELATION_ID_LEN];
    const KEY_NAME: &str = "cache.example-1";
    const FINGERPRINT: &str = concat!(
        "1;/nix/store/00000000000000000000000000000000-package;sha256:",
        "0000000000000000000000000000000000000000000000000000;1;"
    );

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        Describe {
            batch_id: [u8; 16],
            request_id: [u8; 16],
        },
        Sign {
            fingerprint: Vec<u8>,
            batch_id: [u8; 16],
            request_id: [u8; 16],
        },
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SignBehavior {
        Valid,
        WrongIdentity,
        InvalidSignature,
        ProtocolFailure,
    }

    struct FakeState {
        key: NixCacheKey,
        describe_results: VecDeque<NixCacheKey>,
        signing_key: SigningKey,
        calls: Vec<Call>,
        sign_behavior: SignBehavior,
        describe_delay: Duration,
        sign_delay: Duration,
    }

    #[derive(Clone)]
    struct FakeRpc(Arc<Mutex<FakeState>>);

    #[derive(Debug, Deserialize)]
    struct Corpus {
        vectors: Vec<CorpusVector>,
    }

    #[derive(Debug, Deserialize)]
    struct CorpusVector {
        name: String,
        result: String,
        input: Option<String>,
        construction: Option<Construction>,
    }

    #[derive(Debug, Deserialize)]
    struct Construction {
        rule: String,
        parameters: ConstructionParameters,
    }

    #[derive(Debug, Deserialize)]
    struct ConstructionParameters {
        version: String,
        store_hash: String,
        store_name_byte: String,
        store_name_length: usize,
        nar_hash: String,
        nar_size: String,
        reference_hash_alphabet: String,
        reference_hash_prefix: String,
        reference_hash_counter_width: usize,
        reference_hash_counter_start: usize,
        reference_name_byte: String,
        reference_name_length: usize,
        last_reference_name_length: usize,
        reference_count: usize,
    }

    impl FakeRpc {
        fn new() -> Self {
            let signing_key = SigningKey::from_bytes(&[7; 32]);
            let key = NixCacheKey {
                key_name: KEY_NAME.to_string(),
                public_key: signing_key.verifying_key().to_bytes(),
                backend_version: 1,
            };
            Self(Arc::new(Mutex::new(FakeState {
                key,
                describe_results: VecDeque::new(),
                signing_key,
                calls: Vec::new(),
                sign_behavior: SignBehavior::Valid,
                describe_delay: Duration::ZERO,
                sign_delay: Duration::ZERO,
            })))
        }

        fn key(&self) -> NixCacheKey {
            self.0.lock().unwrap().key.clone()
        }

        fn calls(&self) -> Vec<Call> {
            self.0.lock().unwrap().calls.clone()
        }

        fn set_sign_behavior(&self, behavior: SignBehavior) {
            self.0.lock().unwrap().sign_behavior = behavior;
        }

        fn set_delays(&self, describe: Duration, sign: Duration) {
            let mut state = self.0.lock().unwrap();
            state.describe_delay = describe;
            state.sign_delay = sign;
        }

        fn push_describe(&self, key: NixCacheKey) {
            self.0.lock().unwrap().describe_results.push_back(key);
        }
    }

    impl NixCacheRpc for FakeRpc {
        async fn describe_nix_cache_key(
            &mut self,
            _key_id: &str,
            batch_id: [u8; 16],
            request_id: [u8; 16],
        ) -> basil::Result<NixCacheKey> {
            let (delay, key) = {
                let mut state = self.0.lock().unwrap();
                state.calls.push(Call::Describe {
                    batch_id,
                    request_id,
                });
                let key = state
                    .describe_results
                    .pop_front()
                    .unwrap_or_else(|| state.key.clone());
                (state.describe_delay, key)
            };
            tokio::time::sleep(delay).await;
            Ok(key)
        }

        async fn sign_nix_cache_fingerprint(
            &mut self,
            _key_id: &str,
            fingerprint: &[u8],
            batch_id: [u8; 16],
            request_id: [u8; 16],
        ) -> basil::Result<NixCacheSignature> {
            let (delay, behavior, key, signing_key) = {
                let mut state = self.0.lock().unwrap();
                state.calls.push(Call::Sign {
                    fingerprint: fingerprint.to_vec(),
                    batch_id,
                    request_id,
                });
                (
                    state.sign_delay,
                    state.sign_behavior,
                    state.key.clone(),
                    state.signing_key.clone(),
                )
            };
            tokio::time::sleep(delay).await;
            if behavior == SignBehavior::ProtocolFailure {
                return Err(basil::Error::Protocol(
                    "Nix cache response changed the request ID".to_string(),
                ));
            }
            let mut result_key = key;
            if behavior == SignBehavior::WrongIdentity {
                result_key.key_name = "other.example-1".to_string();
            }
            let mut signature = signing_key.sign(fingerprint).to_bytes();
            if behavior == SignBehavior::InvalidSignature {
                signature[0] ^= 0x80;
            }
            Ok(NixCacheSignature {
                key: result_key,
                signature,
            })
        }
    }

    fn header(request_type: MessageType) -> RequestHeader {
        RequestHeader {
            request_type,
            body_len: 0,
            batch_id: BATCH_ID,
            request_id: REQUEST_ID,
        }
    }

    fn encoded_header(
        request_type: u8,
        status: u8,
        flags: u32,
        body_len: u32,
        batch_id: [u8; 16],
        request_id: [u8; 16],
    ) -> [u8; HEADER_LEN] {
        let mut encoded = [0_u8; HEADER_LEN];
        encoded[0..4].copy_from_slice(MAGIC);
        encoded[4] = MAJOR;
        encoded[5] = MINOR;
        encoded[6] = request_type;
        encoded[7] = status;
        encoded[8..12].copy_from_slice(&flags.to_be_bytes());
        encoded[12..16].copy_from_slice(&body_len.to_be_bytes());
        encoded[16..32].copy_from_slice(&batch_id);
        encoded[32..48].copy_from_slice(&request_id);
        encoded
    }

    fn sign_body(key: &NixCacheKey, endpoint_id: [u8; 16], fingerprint: &[u8]) -> Vec<u8> {
        sign_body_with_key_bytes(
            key.key_name.as_bytes(),
            key.public_key,
            endpoint_id,
            fingerprint,
        )
    }

    fn sign_body_with_key_bytes(
        key_name: &[u8],
        public_key: [u8; 32],
        endpoint_id: [u8; 16],
        fingerprint: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&u16::try_from(key_name.len()).unwrap().to_be_bytes());
        body.extend_from_slice(key_name);
        body.extend_from_slice(&public_key);
        body.extend_from_slice(&endpoint_id);
        body.extend_from_slice(&u32::try_from(fingerprint.len()).unwrap().to_be_bytes());
        body.extend_from_slice(fingerprint);
        body
    }

    fn request_bytes(request_type: MessageType, body: &[u8]) -> Vec<u8> {
        let mut encoded = encoded_header(
            request_type as u8,
            0,
            0,
            u32::try_from(body.len()).unwrap(),
            BATCH_ID,
            REQUEST_ID,
        )
        .to_vec();
        encoded.extend_from_slice(body);
        encoded
    }

    fn response_status(response: &[u8]) -> u8 {
        response[7]
    }

    fn construct(construction: &Construction) -> Vec<u8> {
        assert_eq!(construction.rule, "sequential-max-store-path-references-v1");
        let parameters = &construction.parameters;
        let store_name = parameters
            .store_name_byte
            .repeat(parameters.store_name_length);
        let store_path = format!("/nix/store/{}-{store_name}", parameters.store_hash);
        let mut references = Vec::with_capacity(parameters.reference_count);
        for offset in 0..parameters.reference_count {
            let counter = fixed_nix32(
                parameters.reference_hash_counter_start + offset,
                parameters.reference_hash_counter_width,
                parameters.reference_hash_alphabet.as_bytes(),
            );
            let hash = format!("{}{counter}", parameters.reference_hash_prefix);
            let name_length = if offset + 1 == parameters.reference_count {
                parameters.last_reference_name_length
            } else {
                parameters.reference_name_length
            };
            references.push(format!(
                "/nix/store/{hash}-{}",
                parameters.reference_name_byte.repeat(name_length)
            ));
        }
        format!(
            "{};{store_path};sha256:{};{};{}",
            parameters.version,
            parameters.nar_hash,
            parameters.nar_size,
            references.join(",")
        )
        .into_bytes()
    }

    fn fixed_nix32(mut value: usize, width: usize, alphabet: &[u8]) -> String {
        let mut encoded = vec![b'0'; width];
        for slot in encoded.iter_mut().rev() {
            let index = value % alphabet.len();
            *slot = alphabet[index];
            value /= alphabet.len();
        }
        assert_eq!(value, 0);
        String::from_utf8(encoded).unwrap()
    }

    async fn exchange<C: NixCacheRpc>(
        provider: NixProvider<C>,
        request: &[u8],
        deadline: Duration,
    ) -> Vec<u8> {
        let (mut client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(async move {
            provider
                .handle_bounded(server, Instant::now() + deadline)
                .await;
        });
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        task.await.unwrap();
        response
    }

    async fn wait_for_permits(semaphore: &Semaphore, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while semaphore.available_permits() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn strict_header_accepts_only_exact_request_contract() {
        let valid = encoded_header(0x01, 0, 0, 0, BATCH_ID, REQUEST_ID);
        let parsed = parse_request_header(&valid).unwrap();
        assert_eq!(parsed.request_type, MessageType::DescribeRequest);
        assert_eq!(parsed.batch_id, BATCH_ID);
        assert_eq!(parsed.request_id, REQUEST_ID);

        for (name, encoded, response) in [
            (
                "unknown-type",
                encoded_header(0x03, 0, 0, 0, BATCH_ID, REQUEST_ID),
                false,
            ),
            (
                "nonzero-status",
                encoded_header(0x01, 1, 0, 0, BATCH_ID, REQUEST_ID),
                true,
            ),
            (
                "reserved-flags",
                encoded_header(0x01, 0, 1, 0, BATCH_ID, REQUEST_ID),
                true,
            ),
            (
                "describe-body",
                encoded_header(0x01, 0, 0, 1, BATCH_ID, REQUEST_ID),
                true,
            ),
            (
                "oversize-sign",
                encoded_header(
                    0x02,
                    0,
                    0,
                    u32::try_from(MAX_SIGN_REQUEST_BODY + 1).unwrap(),
                    BATCH_ID,
                    REQUEST_ID,
                ),
                true,
            ),
            (
                "zero-batch",
                encoded_header(0x01, 0, 0, 0, [0; 16], REQUEST_ID),
                false,
            ),
            (
                "zero-request",
                encoded_header(0x01, 0, 0, 0, BATCH_ID, [0; 16]),
                false,
            ),
        ] {
            let error = parse_request_header(&encoded).unwrap_err();
            assert_eq!(error.response.is_some(), response, "{name}");
        }
    }

    #[test]
    fn exact_version_mismatch_is_typed_and_not_negotiated() {
        for (major, minor) in [(0, 0), (1, 1), (2, 0)] {
            let mut encoded = encoded_header(0x01, 0, 0, 0, BATCH_ID, REQUEST_ID);
            encoded[4] = major;
            encoded[5] = minor;
            let failure = parse_request_header(&encoded).unwrap_err();
            assert_eq!(failure.status, Status::UnsupportedVersion);
            assert!(failure.response.is_some());
        }
    }

    #[test]
    fn sign_body_rejects_truncation_length_mismatch_and_zero_endpoint() {
        let rpc = FakeRpc::new();
        let key = rpc.key();
        let endpoint = [0x33; 16];
        let valid = sign_body(&key, endpoint, FINGERPRINT.as_bytes());
        assert_eq!(
            parse_sign_body(&valid).unwrap().fingerprint,
            FINGERPRINT.as_bytes()
        );
        for length in 0..valid.len() {
            assert!(
                parse_sign_body(&valid[..length]).is_err(),
                "length {length}"
            );
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(parse_sign_body(&trailing), Err(Status::Malformed));
        let mut zero_endpoint = valid;
        let start = 2 + key.key_name.len() + PUBLIC_KEY_LEN;
        zero_endpoint[start..start + ENDPOINT_ID_LEN].fill(0);
        assert_eq!(parse_sign_body(&zero_endpoint), Err(Status::KeyMismatch));
    }

    #[test]
    fn diagnostics_remove_c0_and_c1_controls_and_stay_bounded() {
        let input = format!("safe\u{0000}\u{0085}text{}", "x".repeat(2_000));
        let body = encode_diagnostic(&input);
        let length = usize::from(u16::from_be_bytes([body[0], body[1]]));
        assert!(length <= MAX_DIAGNOSTIC_LEN);
        let text = std::str::from_utf8(&body[2..]).unwrap();
        assert!(!text.chars().any(char::is_control));
        assert_eq!(length, text.len());
        assert_eq!(body.len(), 1_026);
    }

    #[tokio::test]
    async fn describe_pins_once_and_preserves_exact_ids_on_every_call() {
        let rpc = FakeRpc::new();
        let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        let first = provider
            .describe(header(MessageType::DescribeRequest))
            .await
            .unwrap();
        let second = provider
            .describe(header(MessageType::DescribeRequest))
            .await
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            rpc.calls(),
            [
                Call::Describe {
                    batch_id: BATCH_ID,
                    request_id: REQUEST_ID,
                },
                Call::Describe {
                    batch_id: BATCH_ID,
                    request_id: REQUEST_ID,
                },
            ]
        );
    }

    #[tokio::test]
    async fn later_describe_cannot_repin_listener_identity() {
        let rpc = FakeRpc::new();
        let original = rpc.key();
        let mut changed = original.clone();
        changed.key_name = "changed.example-1".to_string();
        rpc.push_describe(original.clone());
        rpc.push_describe(changed);
        let provider = NixProvider::new("catalog.key".to_string(), rpc).unwrap();
        provider
            .describe(header(MessageType::DescribeRequest))
            .await
            .unwrap();
        let failure = provider
            .describe(header(MessageType::DescribeRequest))
            .await
            .unwrap_err();
        assert_eq!(failure.status, Status::Unavailable);
        assert_eq!(*provider.identity.read().await, Some(original));
    }

    #[tokio::test]
    async fn concurrent_first_describes_establish_exactly_one_immutable_pin() {
        let rpc = FakeRpc::new();
        let original = rpc.key();
        let mut changed = original.clone();
        changed.key_name = "changed.example-1".to_string();
        rpc.push_describe(original.clone());
        rpc.push_describe(changed.clone());
        let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        let first = {
            let provider = provider.clone();
            tokio::spawn(async move {
                provider
                    .describe(header(MessageType::DescribeRequest))
                    .await
            })
        };
        let second = {
            let provider = provider.clone();
            tokio::spawn(async move {
                provider
                    .describe(header(MessageType::DescribeRequest))
                    .await
            })
        };
        let first = first.await.unwrap();
        let second = second.await.unwrap();
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        let pinned = provider.identity.read().await.clone().unwrap();
        assert!(pinned == original || pinned == changed);
        assert_eq!(
            rpc.calls()
                .iter()
                .filter(|call| matches!(call, Call::Describe { .. }))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn sign_checks_pin_before_only_purpose_specific_sign_call() {
        let rpc = FakeRpc::new();
        let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        provider
            .describe(header(MessageType::DescribeRequest))
            .await
            .unwrap();
        let body = sign_body(&rpc.key(), provider.endpoint_id, FINGERPRINT.as_bytes());
        let response = provider
            .sign(header(MessageType::SignRequest), &body)
            .await
            .unwrap();
        assert_eq!(response.len(), 2 + KEY_NAME.len() + 32 + 16 + 64);
        assert_eq!(
            rpc.calls().last(),
            Some(&Call::Sign {
                fingerprint: FINGERPRINT.as_bytes().to_vec(),
                batch_id: BATCH_ID,
                request_id: REQUEST_ID,
            })
        );
    }

    #[tokio::test]
    async fn identity_endpoint_and_fingerprint_fail_before_backend_sign() {
        let rpc = FakeRpc::new();
        let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        let no_pin = sign_body(&rpc.key(), provider.endpoint_id, FINGERPRINT.as_bytes());
        assert_eq!(
            provider
                .sign(header(MessageType::SignRequest), &no_pin)
                .await
                .unwrap_err()
                .status,
            Status::KeyMismatch
        );
        provider
            .describe(header(MessageType::DescribeRequest))
            .await
            .unwrap();
        let mut wrong_name_key = rpc.key();
        wrong_name_key.key_name = "wrong.example-1".to_string();
        let wrong_name = sign_body(
            &wrong_name_key,
            provider.endpoint_id,
            FINGERPRINT.as_bytes(),
        );
        assert_eq!(
            provider
                .sign(header(MessageType::SignRequest), &wrong_name)
                .await
                .unwrap_err()
                .status,
            Status::KeyMismatch
        );
        let mut wrong_public_key = rpc.key();
        wrong_public_key.public_key[0] ^= 0x80;
        let wrong_public = sign_body(
            &wrong_public_key,
            provider.endpoint_id,
            FINGERPRINT.as_bytes(),
        );
        assert_eq!(
            provider
                .sign(header(MessageType::SignRequest), &wrong_public)
                .await
                .unwrap_err()
                .status,
            Status::KeyMismatch
        );
        let wrong_endpoint = sign_body(&rpc.key(), [0x99; 16], FINGERPRINT.as_bytes());
        assert_eq!(
            provider
                .sign(header(MessageType::SignRequest), &wrong_endpoint)
                .await
                .unwrap_err()
                .status,
            Status::KeyMismatch
        );
        let invalid = sign_body(&rpc.key(), provider.endpoint_id, b"arbitrary bytes");
        assert_eq!(
            provider
                .sign(header(MessageType::SignRequest), &invalid)
                .await
                .unwrap_err()
                .status,
            Status::InvalidFingerprint
        );
        assert_eq!(
            rpc.calls()
                .iter()
                .filter(|call| matches!(call, Call::Sign { .. }))
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn normative_path_info_corpus_runs_through_adapter_sign_boundary() {
        let corpus: Corpus = serde_json::from_str(include_str!(
            "../../basil-tests/fixtures/nix-cache-signing/path-info-v1.json"
        ))
        .unwrap();
        for vector in corpus.vectors {
            let input = match (&vector.input, &vector.construction) {
                (Some(encoded), None) => hex::decode(encoded).unwrap(),
                (None, Some(construction)) => construct(construction),
                _ => panic!("{} has ambiguous corpus input", vector.name),
            };
            let rpc = FakeRpc::new();
            let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
            provider
                .describe(header(MessageType::DescribeRequest))
                .await
                .unwrap();
            let body = sign_body(&rpc.key(), provider.endpoint_id, &input);
            let result = provider.sign(header(MessageType::SignRequest), &body).await;
            let sign_calls = rpc
                .calls()
                .iter()
                .filter(|call| matches!(call, Call::Sign { .. }))
                .count();
            match vector.result.as_str() {
                "accept" => {
                    result.unwrap_or_else(|failure| {
                        panic!("{} rejected as {:?}", vector.name, failure.status)
                    });
                    assert_eq!(sign_calls, 1, "{} sign count", vector.name);
                }
                "reject" => {
                    assert_eq!(
                        result.unwrap_err().status,
                        Status::InvalidFingerprint,
                        "{} status",
                        vector.name
                    );
                    assert_eq!(sign_calls, 0, "{} must not reach Sign RPC", vector.name);
                }
                other => panic!("unknown corpus result {other}"),
            }
        }
    }

    #[tokio::test]
    async fn sign_response_identity_signature_and_echo_fail_without_fallback() {
        for behavior in [
            SignBehavior::WrongIdentity,
            SignBehavior::InvalidSignature,
            SignBehavior::ProtocolFailure,
        ] {
            let rpc = FakeRpc::new();
            rpc.set_sign_behavior(behavior);
            let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
            provider
                .describe(header(MessageType::DescribeRequest))
                .await
                .unwrap();
            let body = sign_body(&rpc.key(), provider.endpoint_id, FINGERPRINT.as_bytes());
            assert_eq!(
                provider
                    .sign(header(MessageType::SignRequest), &body)
                    .await
                    .unwrap_err()
                    .status,
                Status::Internal
            );
            assert_eq!(
                rpc.calls()
                    .iter()
                    .filter(|call| matches!(call, Call::Sign { .. }))
                    .count(),
                1
            );
        }
    }

    #[tokio::test]
    async fn ninth_concurrent_sign_fails_fast_without_queueing() {
        let rpc = FakeRpc::new();
        rpc.set_delays(Duration::ZERO, Duration::from_millis(100));
        let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        provider
            .describe(header(MessageType::DescribeRequest))
            .await
            .unwrap();
        let body = Arc::new(sign_body(
            &rpc.key(),
            provider.endpoint_id,
            FINGERPRINT.as_bytes(),
        ));
        let mut tasks = JoinSet::new();
        for _ in 0..9 {
            let provider = provider.clone();
            let body = Arc::clone(&body);
            tasks
                .spawn(async move { provider.sign(header(MessageType::SignRequest), &body).await });
        }
        let mut ok = 0;
        let mut overloaded = 0;
        while let Some(result) = tasks.join_next().await {
            match result.unwrap() {
                Ok(_) => ok += 1,
                Err(failure) if failure.status == Status::Overloaded => overloaded += 1,
                Err(failure) => panic!("unexpected status: {:?}", failure.status),
            }
        }
        assert_eq!((ok, overloaded), (8, 1));
    }

    #[tokio::test]
    async fn transport_requires_half_close_rejects_trailing_and_echoes_ids() {
        let rpc = FakeRpc::new();
        let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        let request = request_bytes(MessageType::DescribeRequest, &[]);
        let response = exchange(provider.clone(), &request, Duration::from_secs(1)).await;
        assert_eq!(response_status(&response), Status::Ok as u8);
        assert_eq!(&response[16..32], BATCH_ID);
        assert_eq!(&response[32..48], REQUEST_ID);

        let mut trailing = request;
        trailing.push(0xff);
        let response = exchange(provider, &trailing, Duration::from_secs(1)).await;
        assert_eq!(response_status(&response), Status::Malformed as u8);
        assert_eq!(
            rpc.calls()
                .iter()
                .filter(|call| matches!(call, Call::Describe { .. }))
                .count(),
            1,
            "trailing bytes must fail before any RPC"
        );
    }

    #[tokio::test]
    async fn transport_rejects_truncated_and_oversized_frames_before_rpc() {
        let rpc = FakeRpc::new();
        let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        let header = encoded_header(0x01, 0, 0, 0, BATCH_ID, REQUEST_ID);
        let response = exchange(
            provider.clone(),
            &header[..HEADER_LEN - 1],
            Duration::from_secs(1),
        )
        .await;
        assert!(response.is_empty(), "truncated header cannot be correlated");

        let truncated_body = encoded_header(0x02, 0, 0, 8, BATCH_ID, REQUEST_ID);
        let response = exchange(provider.clone(), &truncated_body, Duration::from_secs(1)).await;
        assert_eq!(response_status(&response), Status::Malformed as u8);

        let oversized = encoded_header(
            0x02,
            0,
            0,
            u32::try_from(MAX_SIGN_REQUEST_BODY + 1).unwrap(),
            BATCH_ID,
            REQUEST_ID,
        );
        let response = exchange(provider, &oversized, Duration::from_secs(1)).await;
        assert_eq!(response_status(&response), Status::Malformed as u8);
        assert!(
            rpc.calls().is_empty(),
            "framing failures must not reach Basil"
        );
    }

    #[tokio::test]
    async fn bad_magic_and_invalid_sign_key_names_fail_before_any_rpc() {
        let rpc = FakeRpc::new();
        let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();

        let mut bad_magic = request_bytes(MessageType::DescribeRequest, &[]);
        bad_magic[0..4].copy_from_slice(b"NOPE");
        let response = exchange(provider.clone(), &bad_magic, Duration::from_secs(1)).await;
        assert!(response.is_empty(), "bad magic has no recoverable response");

        for (name, key_name) in [
            ("invalid-utf8", vec![0xff]),
            ("control", vec![b'a', 0x1f]),
            ("overlong", vec![b'a'; MAX_KEY_NAME_LEN + 1]),
        ] {
            let body = sign_body_with_key_bytes(
                &key_name,
                rpc.key().public_key,
                provider.endpoint_id,
                FINGERPRINT.as_bytes(),
            );
            let response = exchange(
                provider.clone(),
                &request_bytes(MessageType::SignRequest, &body),
                Duration::from_secs(1),
            )
            .await;
            assert_eq!(
                response_status(&response),
                Status::Malformed as u8,
                "{name}"
            );
        }
        assert!(
            rpc.calls().is_empty(),
            "invalid frames must not reach Basil"
        );
    }

    #[tokio::test]
    async fn idle_connection_consumes_one_absolute_deadline_then_closes() {
        let rpc = FakeRpc::new();
        let provider = NixProvider::new("catalog.key".to_string(), rpc).unwrap();
        let (mut client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(async move {
            provider
                .handle_bounded(server, Instant::now() + Duration::from_millis(10))
                .await;
        });
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        task.await.unwrap();
        assert!(response.is_empty());
    }

    #[tokio::test]
    async fn one_absolute_deadline_cancels_delayed_basil_operation() {
        let rpc = FakeRpc::new();
        rpc.set_delays(Duration::from_millis(100), Duration::ZERO);
        let provider = NixProvider::new("catalog.key".to_string(), rpc).unwrap();
        let response = exchange(
            provider,
            &request_bytes(MessageType::DescribeRequest, &[]),
            Duration::from_millis(10),
        )
        .await;
        assert!(response.is_empty());
    }

    #[tokio::test]
    async fn restart_endpoint_mismatch_fails_before_signing() {
        let rpc = FakeRpc::new();
        let first = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        let second = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        assert_ne!(first.endpoint_id, second.endpoint_id);
        second
            .describe(header(MessageType::DescribeRequest))
            .await
            .unwrap();
        let stale = sign_body(&rpc.key(), first.endpoint_id, FINGERPRINT.as_bytes());
        assert_eq!(
            second
                .sign(header(MessageType::SignRequest), &stale)
                .await
                .unwrap_err()
                .status,
            Status::KeyMismatch
        );
        assert!(
            !rpc.calls()
                .iter()
                .any(|call| matches!(call, Call::Sign { .. }))
        );
    }

    fn unique_directory(mode: u32) -> PathBuf {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "basil-nxsg-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[tokio::test]
    async fn secure_listener_refuses_existing_objects_and_publishes_0600() {
        let directory = unique_directory(0o700);
        let socket = directory.join("signer.sock");
        let listener = SecureListener::bind(&socket).unwrap();
        let metadata = std::fs::symlink_metadata(&socket).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        let binding = rustix::fs::fstat(&listener.binding).unwrap();
        assert_eq!(
            (binding.st_dev, binding.st_ino),
            (metadata.dev(), metadata.ino())
        );
        assert!(matches!(
            SecureListener::bind(&socket),
            Err(ListenerError::PathOccupied)
        ));
        drop(listener);
        assert!(!socket.exists());

        std::fs::write(&socket, b"occupied").unwrap();
        assert!(matches!(
            SecureListener::bind(&socket),
            Err(ListenerError::PathOccupied)
        ));
        std::fs::remove_file(&socket).unwrap();
        std::os::unix::fs::symlink("target", &socket).unwrap();
        assert!(matches!(
            SecureListener::bind(&socket),
            Err(ListenerError::PathOccupied)
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn listener_cleanup_preserves_substituted_path() {
        let directory = unique_directory(0o700);
        let socket = directory.join("signer.sock");
        let listener = SecureListener::bind(&socket).unwrap();
        std::fs::remove_file(&socket).unwrap();
        std::fs::write(&socket, b"replacement").unwrap();
        drop(listener);
        assert_eq!(std::fs::read(&socket).unwrap(), b"replacement");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn listener_rejects_relative_symlinked_and_non_owner_only_parents() {
        assert!(matches!(
            SecureListener::bind(Path::new("relative.sock")),
            Err(ListenerError::InvalidPath)
        ));
        let loose = unique_directory(0o750);
        assert!(matches!(
            SecureListener::bind(&loose.join("signer.sock")),
            Err(ListenerError::UntrustedDirectory)
        ));
        std::fs::remove_dir_all(&loose).unwrap();

        let directory = unique_directory(0o700);
        let real = directory.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = directory.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            SecureListener::bind(&link.join("signer.sock")),
            Err(ListenerError::UntrustedDirectory)
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn connection_limit_overloads_once_closes_next_and_releases_on_deadline() {
        let directory = unique_directory(0o700);
        let socket = directory.join("signer.sock");
        let listener = SecureListener::bind(&socket).unwrap();
        let rpc = FakeRpc::new();
        let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        let observed = provider.clone();
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            provider
                .serve_until_with_deadline(
                    listener,
                    async move {
                        receiver
                            .await
                            .map_err(|_| anyhow!("test shutdown sender dropped"))
                    },
                    Duration::from_millis(500),
                )
                .await
        });

        let mut idle = Vec::with_capacity(MAX_CONNECTIONS);
        for _ in 0..MAX_CONNECTIONS {
            idle.push(UnixStream::connect(&socket).await.unwrap());
        }
        wait_for_permits(&observed.connection_slots, 0).await;

        let mut overloaded = UnixStream::connect(&socket).await.unwrap();
        overloaded.write_all(&[MAGIC[0]]).await.unwrap();
        wait_for_permits(&observed.overload_slot, 0).await;

        let mut closed = UnixStream::connect(&socket).await.unwrap();
        let mut closed_response = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            closed.read_to_end(&mut closed_response),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(closed_response.is_empty());

        let request = request_bytes(MessageType::DescribeRequest, &[]);
        overloaded.write_all(&request[1..]).await.unwrap();
        overloaded.shutdown().await.unwrap();
        let mut overload_response = Vec::new();
        overloaded
            .read_to_end(&mut overload_response)
            .await
            .unwrap();
        assert_eq!(
            response_status(&overload_response),
            Status::Overloaded as u8
        );
        assert!(rpc.calls().is_empty(), "overload paths must not call Basil");

        wait_for_permits(&observed.connection_slots, MAX_CONNECTIONS).await;
        assert!(
            rpc.calls().is_empty(),
            "idle slots must time out without RPC"
        );
        drop(idle);
        shutdown.send(()).unwrap();
        server.await.unwrap().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn peer_uid_comparison_is_exact() {
        let effective = rustix::process::geteuid().as_raw();
        assert!(peer_uid_is_authorized(effective, effective));
        assert!(!peer_uid_is_authorized(
            effective.wrapping_add(1),
            effective
        ));
        assert!(peer_uid_result_is_authorized::<()>(
            Ok(effective),
            effective
        ));
        assert!(!peer_uid_result_is_authorized::<()>(Err(()), effective));
    }

    #[tokio::test]
    async fn verified_adapter_signature_edits_narinfo_without_byte_loss() {
        let rpc = FakeRpc::new();
        let provider = NixProvider::new("catalog.key".to_string(), rpc.clone()).unwrap();
        provider
            .describe(header(MessageType::DescribeRequest))
            .await
            .unwrap();
        let body = sign_body(&rpc.key(), provider.endpoint_id, FINGERPRINT.as_bytes());
        let response = provider
            .sign(header(MessageType::SignRequest), &body)
            .await
            .unwrap();
        let signature_start = response.len() - SIGNATURE_LEN;
        let signature =
            base64::engine::general_purpose::STANDARD.encode(&response[signature_start..]);
        let signature_value = format!("{KEY_NAME}:{signature}");
        let input = concat!(
            "StorePath: /nix/store/00000000000000000000000000000000-package\n",
            "URL: nar/example.nar.zst\n",
            "NarHash: sha256:0000000000000000000000000000000000000000000000000000\n",
            "NarSize: 1\n",
            "X-Future-Field: exact bytes"
        )
        .as_bytes();
        let edited = edit_narinfo(
            input,
            NarinfoMutation::Add {
                signature: &signature_value,
            },
        )
        .unwrap();
        let NarinfoEdit::Changed(output) = edited else {
            panic!("signature must be inserted");
        };
        assert!(output.starts_with(input));
        assert!(
            output
                .windows(b"X-Future-Field: exact bytes".len())
                .any(|window| { window == b"X-Future-Field: exact bytes" })
        );
        assert!(output.ends_with(format!("\nSig: {signature_value}").as_bytes()));
    }
}
