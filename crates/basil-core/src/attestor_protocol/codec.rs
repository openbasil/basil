// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::io;

use prost::Message;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

use super::limits::ProtocolLimits;
use super::wire::Envelope;

/// Kernel credentials captured from a connected Unix stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    /// Kernel process ID, when supplied by the platform.
    pub pid: Option<u32>,
    /// Kernel user ID.
    pub uid: u32,
    /// Kernel group ID.
    pub gid: u32,
}

/// Opaque digest of peer, unit, and admitted release-artifact authentication.
///
/// The digest is not an identity claim from the wire peer. The socket admission
/// layer constructs it only after independently authenticating the peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedPeerBinding([u8; 32]);

impl VerifiedPeerBinding {
    /// Wrap a digest produced by the independent peer authentication layer.
    #[must_use]
    // Socket/unit/release admission is intentionally a later module; keep the
    // constructor crate-private until that verifier calls it.
    #[allow(dead_code)]
    pub(crate) const fn from_authenticator(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Return the binding digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Connected Unix stream whose credentials were captured before byte decoding.
pub struct CapturedUnixStream {
    stream: UnixStream,
    credentials: PeerCredentials,
}

impl CapturedUnixStream {
    /// Capture kernel credentials without reading protocol bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::PeerCredentials`] if the kernel cannot supply the
    /// connected peer credentials.
    pub fn capture(stream: UnixStream) -> Result<Self, CodecError> {
        let credentials = stream
            .peer_cred()
            .map_err(CodecError::PeerCredentials)
            .map(|credential| PeerCredentials {
                pid: credential.pid().and_then(|pid| u32::try_from(pid).ok()),
                uid: credential.uid(),
                gid: credential.gid(),
            })?;
        Ok(Self {
            stream,
            credentials,
        })
    }

    /// Return the credentials captured before any protocol byte is read.
    #[must_use]
    pub const fn credentials(&self) -> PeerCredentials {
        self.credentials
    }

    /// Consume the captured stream after authentication and enable framing.
    #[must_use]
    pub fn into_framed(
        self,
        binding: VerifiedPeerBinding,
        limits: ProtocolLimits,
    ) -> FrameCodec<UnixStream> {
        FrameCodec {
            io: self.stream,
            credentials: Some(self.credentials),
            binding,
            max_frame_bytes: limits.max_frame_bytes,
        }
    }
}

/// Strict length-prefixed protobuf codec for an authenticated stream.
pub struct FrameCodec<S> {
    io: S,
    credentials: Option<PeerCredentials>,
    binding: VerifiedPeerBinding,
    max_frame_bytes: usize,
}

impl<S> FrameCodec<S> {
    /// Return captured Unix peer credentials, if this codec wraps a Unix stream.
    #[must_use]
    pub const fn peer_credentials(&self) -> Option<PeerCredentials> {
        self.credentials
    }

    /// Return the independently verified peer-binding digest.
    #[must_use]
    pub const fn peer_binding(&self) -> VerifiedPeerBinding {
        self.binding
    }

    #[cfg(test)]
    pub(super) const fn for_test(
        io: S,
        binding: VerifiedPeerBinding,
        limits: ProtocolLimits,
    ) -> Self {
        Self {
            io,
            credentials: None,
            binding,
            max_frame_bytes: limits.max_frame_bytes,
        }
    }
}

impl<S> FrameCodec<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Read and strictly decode one complete envelope.
    ///
    /// The four-byte size is checked before allocation. The accepted wire form
    /// is canonical: unknown fields, duplicate singular fields, and appended
    /// protobuf material are rejected because decoding and re-encoding must
    /// reproduce the payload byte-for-byte.
    pub async fn read_envelope(&mut self) -> Result<Envelope, CodecError> {
        let mut prefix = [0_u8; 4];
        self.io
            .read_exact(&mut prefix)
            .await
            .map_err(|error| map_read_error(error, ReadStage::Prefix))?;
        let payload_len = u32::from_be_bytes(prefix) as usize;
        if payload_len == 0 {
            return Err(CodecError::ZeroLength);
        }
        if payload_len > self.max_frame_bytes {
            return Err(CodecError::FrameTooLarge {
                length: payload_len,
                maximum: self.max_frame_bytes,
            });
        }

        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_len)
            .map_err(|_| CodecError::Allocation {
                length: payload_len,
            })?;
        payload.resize(payload_len, 0);
        self.io
            .read_exact(&mut payload)
            .await
            .map_err(|error| map_read_error(error, ReadStage::Payload))?;

        let envelope = Envelope::decode(payload.as_slice()).map_err(CodecError::Malformed)?;
        let canonical = encode_canonical(&envelope, self.max_frame_bytes)?;
        if canonical != payload {
            return Err(CodecError::NonCanonical);
        }
        Ok(envelope)
    }

    /// Encode and write one complete envelope.
    pub async fn write_envelope(&mut self, envelope: &Envelope) -> Result<(), CodecError> {
        let payload = encode_canonical(envelope, self.max_frame_bytes)?;
        let payload_len = u32::try_from(payload.len()).map_err(|_| CodecError::FrameTooLarge {
            length: payload.len(),
            maximum: self.max_frame_bytes,
        })?;
        self.io
            .write_all(&payload_len.to_be_bytes())
            .await
            .map_err(CodecError::Write)?;
        self.io
            .write_all(&payload)
            .await
            .map_err(CodecError::Write)?;
        self.io.flush().await.map_err(CodecError::Write)
    }

    /// Close the write half after a timeout or protocol violation.
    pub async fn terminate(&mut self) {
        let _ = self.io.shutdown().await;
    }
}

fn encode_canonical(envelope: &Envelope, max_frame_bytes: usize) -> Result<Vec<u8>, CodecError> {
    let length = envelope.encoded_len();
    if length == 0 {
        return Err(CodecError::ZeroLength);
    }
    if length > max_frame_bytes {
        return Err(CodecError::FrameTooLarge {
            length,
            maximum: max_frame_bytes,
        });
    }
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .map_err(|_| CodecError::Allocation { length })?;
    envelope.encode(&mut payload).map_err(CodecError::Encode)?;
    Ok(payload)
}

#[derive(Clone, Copy)]
enum ReadStage {
    Prefix,
    Payload,
}

fn map_read_error(error: io::Error, stage: ReadStage) -> CodecError {
    if error.kind() == io::ErrorKind::UnexpectedEof {
        return match stage {
            ReadStage::Prefix => CodecError::TruncatedPrefix,
            ReadStage::Payload => CodecError::TruncatedPayload,
        };
    }
    CodecError::Read(error)
}

/// Deterministic framing or protobuf failure.
#[derive(Debug, Error)]
pub enum CodecError {
    /// Kernel peer credentials could not be captured.
    #[error("could not capture Unix peer credentials: {0}")]
    PeerCredentials(io::Error),
    /// The stream ended within the four-byte length prefix.
    #[error("truncated attestor frame length")]
    TruncatedPrefix,
    /// A zero payload length was supplied.
    #[error("zero-length attestor frame")]
    ZeroLength,
    /// The claimed or encoded frame exceeds the active lower-only ceiling.
    #[error("attestor frame length {length} exceeds maximum {maximum}")]
    FrameTooLarge {
        /// Claimed or encoded payload bytes.
        length: usize,
        /// Active payload ceiling.
        maximum: usize,
    },
    /// A bounded payload allocation could not be reserved.
    #[error("could not reserve {length} bytes for attestor frame")]
    Allocation {
        /// Requested bounded allocation.
        length: usize,
    },
    /// The stream ended inside a bounded payload.
    #[error("truncated attestor frame payload")]
    TruncatedPayload,
    /// The payload is not a protobuf envelope.
    #[error("malformed attestor protobuf: {0}")]
    Malformed(prost::DecodeError),
    /// The payload contains unknown, duplicated, reordered, or trailing wire data.
    #[error("non-canonical attestor protobuf envelope")]
    NonCanonical,
    /// Encoding a bounded envelope failed.
    #[error("could not encode attestor protobuf: {0}")]
    Encode(prost::EncodeError),
    /// An ordinary stream read failed.
    #[error("attestor stream read failed: {0}")]
    Read(io::Error),
    /// An ordinary stream write failed.
    #[error("attestor stream write failed: {0}")]
    Write(io::Error),
}
