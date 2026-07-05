// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! On-the-wire container format and AEAD primitives for streaming encryption.
//!
//! This module owns the byte layout of the Basil streaming container (magic,
//! header, per-chunk AEAD records), the per-stream key derivation, and the
//! per-chunk nonce derivation. The exact format is specified in
//! `docs/specs/streaming-encryption-format.md`; the Go client re-implements the
//! same bytes for cross-language interop, so every constant and byte ordering
//! here is load-bearing.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Container magic: ASCII `"BSLSTR"` (Basil stream).
pub const MAGIC: [u8; 6] = *b"BSLSTR";
/// Container format version. Bump on any breaking byte-layout change.
pub const FORMAT_VERSION: u8 = 1;
/// Length of the fixed (suite-independent) header prefix in bytes.
pub const FIXED_HEADER_LEN: usize = 61;

/// Domain-separation tag prefixed to every per-chunk AEAD AAD.
const CHUNK_AAD_MAGIC: [u8; 4] = *b"BSLA";
/// Domain-separation tag prefixed to the KEM-wrapped-CEK AAD.
const CEKWRAP_AAD_MAGIC: [u8; 4] = *b"BSLK";

/// HKDF info label binding the per-stream message key derivation.
const STREAM_CEK_LABEL: &[u8] = b"basil-stream-cek-v1";

/// AEAD authentication-tag length (AES-256-GCM and ChaCha20-Poly1305 both 16).
pub const TAG_LEN: usize = 16;
/// AEAD nonce length (both suites use a 96-bit nonce).
pub const NONCE_LEN: usize = 12;
/// Content-encryption-key length (256-bit).
pub const CEK_LEN: usize = 32;
/// Per-stream random stream identifier length.
pub const STREAM_ID_LEN: usize = 16;
/// Per-stream random HKDF salt length.
pub const STREAM_SALT_LEN: usize = 32;

/// Default plaintext chunk size: 64 KiB.
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
/// Maximum permitted plaintext chunk size: 1 MiB. Bounds per-record buffering on
/// decrypt so a malicious length prefix cannot trigger unbounded allocation.
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// Suite id for the symmetric AES-256-GCM stream.
pub const SUITE_AES256GCM: u8 = 1;
/// Suite id for the symmetric ChaCha20-Poly1305 stream.
pub const SUITE_CHACHA20POLY1305: u8 = 2;
/// Suite id for the ML-KEM-512 + AES-256-GCM stream.
pub const SUITE_MLKEM512: u8 = 3;
/// Suite id for the ML-KEM-768 + AES-256-GCM stream.
pub const SUITE_MLKEM768: u8 = 4;
/// Suite id for the ML-KEM-1024 + AES-256-GCM stream.
pub const SUITE_MLKEM1024: u8 = 5;

/// Errors produced by the streaming encrypt/decrypt API.
///
/// All authentication failures collapse to [`StreamError::AuthFailed`] so the
/// caller learns nothing beyond "this stream did not verify".
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StreamError {
    /// Underlying reader or writer I/O failed.
    #[error("stream io error: {0}")]
    Io(#[from] std::io::Error),

    /// The container magic bytes did not match.
    #[error("bad stream magic")]
    BadMagic,

    /// The container declared an unsupported format version.
    #[error("unsupported stream format version: {0}")]
    UnsupportedVersion(u8),

    /// The container declared an unknown algorithm suite.
    #[error("unsupported stream suite id: {0}")]
    UnsupportedSuite(u8),

    /// The reserved header flags byte was non-zero.
    #[error("reserved header flags must be zero")]
    ReservedFlags,

    /// The header was shorter than the format requires.
    #[error("truncated or malformed stream header")]
    ShortHeader,

    /// The requested or declared chunk size was zero or above [`MAX_CHUNK_SIZE`].
    #[error("invalid chunk size: {0} (must be 1..={max})", max = MAX_CHUNK_SIZE)]
    BadChunkSize(usize),

    /// A record's length prefix implied a plaintext chunk above the limit.
    #[error("chunk record too large")]
    ChunkTooLarge,

    /// The decrypt entry point was called for a different suite family than the
    /// container actually uses (e.g. AEAD decrypt on an ML-KEM stream).
    #[error("stream suite mismatch: container suite id {actual} not valid for this operation")]
    SuiteMismatch {
        /// The suite id found in the container header.
        actual: u8,
    },

    /// A supplied ML-KEM public encapsulation key was malformed.
    #[error("invalid ML-KEM public key")]
    BadPublicKey,

    /// A supplied content-encryption key was not [`CEK_LEN`] bytes.
    #[error("invalid content-encryption key length")]
    BadCekLength,

    /// The ML-KEM ciphertext / encapsulated key was malformed.
    #[error("invalid ML-KEM ciphertext")]
    BadKemCiphertext,

    /// The stream ended before a final-marked chunk was authenticated.
    #[error("stream truncated: missing final chunk")]
    Truncated,

    /// AEAD authentication failed: wrong key, tampered data/AAD, reordered or
    /// truncated chunk, or a downgraded header.
    #[error("stream authentication failed")]
    AuthFailed,

    /// HKDF key derivation failed.
    #[error("key derivation failed")]
    KdfFailed,

    /// AEAD sealing failed.
    #[error("seal failed")]
    SealFailed,

    /// Recovering the content-encryption key from the broker failed.
    #[error("kem cek recovery failed: {0}")]
    CekRecovery(#[from] crate::error::Error),
}

/// Result alias for streaming operations.
pub type StreamResult<T> = std::result::Result<T, StreamError>;

/// The two AEAD suites used to seal individual chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkAead {
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

/// Parsed fixed header fields shared by every suite.
#[derive(Debug, Clone)]
pub struct StreamHeader {
    /// Algorithm suite id.
    pub suite_id: u8,
    /// Declared plaintext chunk size.
    pub chunk_size: u32,
    /// Per-stream random identifier.
    pub stream_id: [u8; STREAM_ID_LEN],
    /// Per-stream HKDF salt.
    pub stream_salt: [u8; STREAM_SALT_LEN],
}

/// Resolve the chunk AEAD used by a suite id, if the suite is known.
pub const fn chunk_aead_for_suite(suite_id: u8) -> Option<ChunkAead> {
    match suite_id {
        SUITE_AES256GCM | SUITE_MLKEM512 | SUITE_MLKEM768 | SUITE_MLKEM1024 => {
            Some(ChunkAead::Aes256Gcm)
        }
        SUITE_CHACHA20POLY1305 => Some(ChunkAead::ChaCha20Poly1305),
        _ => None,
    }
}

/// Serialize the fixed header prefix into `out`.
pub fn write_fixed_header(
    out: &mut Vec<u8>,
    suite_id: u8,
    chunk_size: u32,
    stream_id: &[u8; STREAM_ID_LEN],
    stream_salt: &[u8; STREAM_SALT_LEN],
) {
    out.extend_from_slice(&MAGIC);
    out.push(FORMAT_VERSION);
    out.push(suite_id);
    out.push(0); // reserved flags
    out.extend_from_slice(&chunk_size.to_be_bytes());
    out.extend_from_slice(stream_id);
    out.extend_from_slice(stream_salt);
}

/// Parse and validate the fixed header prefix from a [`FIXED_HEADER_LEN`] buffer.
///
/// # Errors
///
/// Returns [`StreamError::ShortHeader`] for a short buffer,
/// [`StreamError::BadMagic`]/[`StreamError::UnsupportedVersion`]/
/// [`StreamError::ReservedFlags`]/[`StreamError::UnsupportedSuite`] for a
/// malformed or downgraded header, and [`StreamError::BadChunkSize`] for an
/// out-of-range chunk size.
pub fn parse_fixed_header(buf: &[u8]) -> StreamResult<StreamHeader> {
    if buf.get(0..6).ok_or(StreamError::ShortHeader)? != MAGIC {
        return Err(StreamError::BadMagic);
    }
    let version = *buf.get(6).ok_or(StreamError::ShortHeader)?;
    if version != FORMAT_VERSION {
        return Err(StreamError::UnsupportedVersion(version));
    }
    let suite_id = *buf.get(7).ok_or(StreamError::ShortHeader)?;
    if *buf.get(8).ok_or(StreamError::ShortHeader)? != 0 {
        return Err(StreamError::ReservedFlags);
    }
    if chunk_aead_for_suite(suite_id).is_none() {
        return Err(StreamError::UnsupportedSuite(suite_id));
    }
    let chunk_size_bytes: [u8; 4] = buf
        .get(9..13)
        .ok_or(StreamError::ShortHeader)?
        .try_into()
        .map_err(|_| StreamError::ShortHeader)?;
    let chunk_size = u32::from_be_bytes(chunk_size_bytes);
    let in_range = chunk_size >= 1 && (chunk_size as usize) <= MAX_CHUNK_SIZE;
    if !in_range {
        return Err(StreamError::BadChunkSize(chunk_size as usize));
    }
    let stream_id: [u8; STREAM_ID_LEN] = buf
        .get(13..29)
        .ok_or(StreamError::ShortHeader)?
        .try_into()
        .map_err(|_| StreamError::ShortHeader)?;
    let stream_salt: [u8; STREAM_SALT_LEN] = buf
        .get(29..61)
        .ok_or(StreamError::ShortHeader)?
        .try_into()
        .map_err(|_| StreamError::ShortHeader)?;
    Ok(StreamHeader {
        suite_id,
        chunk_size,
        stream_id,
        stream_salt,
    })
}

/// Build the per-chunk AEAD additional-authenticated-data.
///
/// Layout (39 bytes, big-endian integers):
/// `"BSLA" | version | suite_id | stream_id[16] | chunk_index[8] | final_flag |
/// chunk_plaintext_len[4] | chunk_size[4]`.
pub fn build_chunk_aad(
    suite_id: u8,
    stream_id: &[u8; STREAM_ID_LEN],
    chunk_index: u64,
    is_final: bool,
    chunk_plaintext_len: u32,
    chunk_size: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(39);
    aad.extend_from_slice(&CHUNK_AAD_MAGIC);
    aad.push(FORMAT_VERSION);
    aad.push(suite_id);
    aad.extend_from_slice(stream_id);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.push(u8::from(is_final));
    aad.extend_from_slice(&chunk_plaintext_len.to_be_bytes());
    aad.extend_from_slice(&chunk_size.to_be_bytes());
    aad
}

/// Build the AAD that binds a KEM-wrapped CEK to its stream.
///
/// Layout (22 bytes): `"BSLK" | version | suite_id | stream_id[16]`.
pub fn build_cekwrap_aad(suite_id: u8, stream_id: &[u8; STREAM_ID_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(22);
    aad.extend_from_slice(&CEKWRAP_AAD_MAGIC);
    aad.push(FORMAT_VERSION);
    aad.push(suite_id);
    aad.extend_from_slice(stream_id);
    aad
}

/// Per-chunk nonce: 4 zero bytes followed by the 64-bit big-endian chunk index.
///
/// The per-stream message key is unique per stream (derived from a fresh random
/// salt), so a counter nonce is sufficient for `(key, nonce)` uniqueness.
pub fn chunk_nonce(chunk_index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    let index_bytes = chunk_index.to_be_bytes();
    // nonce[4..12] = index_bytes; written without indexing for the no-panic gate.
    let (_zero_prefix, counter) = nonce.split_at_mut(4);
    counter.copy_from_slice(&index_bytes);
    nonce
}

/// Derive the per-stream message key `K_msg = HKDF-SHA256(salt=stream_salt,
/// ikm=cek, info="basil-stream-cek-v1" | suite_id | stream_id)`.
///
/// # Errors
///
/// Returns [`StreamError::KdfFailed`] if HKDF expansion fails.
pub fn derive_message_key(
    stream_salt: &[u8; STREAM_SALT_LEN],
    cek: &[u8],
    suite_id: u8,
    stream_id: &[u8; STREAM_ID_LEN],
) -> StreamResult<Zeroizing<[u8; CEK_LEN]>> {
    let mut info = Vec::with_capacity(STREAM_CEK_LABEL.len() + 1 + STREAM_ID_LEN);
    info.extend_from_slice(STREAM_CEK_LABEL);
    info.push(suite_id);
    info.extend_from_slice(stream_id);

    let hk = Hkdf::<Sha256>::new(Some(stream_salt.as_slice()), cek);
    let mut okm = Zeroizing::new([0u8; CEK_LEN]);
    hk.expand(&info, okm.as_mut_slice())
        .map_err(|_| StreamError::KdfFailed)?;
    Ok(okm)
}

/// Seal one chunk under the per-stream message key.
///
/// # Errors
///
/// Returns [`StreamError::SealFailed`] if AEAD sealing fails.
pub fn aead_seal(
    alg: ChunkAead,
    key: &[u8; CEK_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> StreamResult<Vec<u8>> {
    match alg {
        ChunkAead::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| StreamError::SealFailed)?;
            cipher
                .encrypt(
                    &aes_gcm::Nonce::from(*nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| StreamError::SealFailed)
        }
        ChunkAead::ChaCha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| StreamError::SealFailed)?;
            cipher
                .encrypt(
                    &chacha20poly1305::Nonce::from(*nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| StreamError::SealFailed)
        }
    }
}

/// Open one chunk under the per-stream message key.
///
/// # Errors
///
/// Returns [`StreamError::AuthFailed`] for any authentication failure (wrong
/// key, tampered ciphertext/AAD, reorder, truncation, or downgrade).
pub fn aead_open(
    alg: ChunkAead,
    key: &[u8; CEK_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> StreamResult<Zeroizing<Vec<u8>>> {
    let plaintext = match alg {
        ChunkAead::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| StreamError::AuthFailed)?;
            cipher.decrypt(
                &aes_gcm::Nonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
        }
        ChunkAead::ChaCha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| StreamError::AuthFailed)?;
            cipher.decrypt(
                &chacha20poly1305::Nonce::from(*nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
        }
    }
    .map_err(|_| StreamError::AuthFailed)?;
    Ok(Zeroizing::new(plaintext))
}
