// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Streaming, chunked authenticated encryption for large payloads and files.
//!
//! These APIs encrypt and decrypt a [`tokio::io::AsyncRead`] into a
//! [`tokio::io::AsyncWrite`] without buffering the whole payload in memory. The
//! caller picks one suite ([`AeadSuite::Aes256Gcm`], [`AeadSuite::ChaCha20Poly1305`],
//! or one of the [`MlKemSuite`] post-quantum parameter sets) and Basil owns the
//! container format and every nonce. The exact byte layout is specified in
//! `docs/specs/streaming-encryption-format.md` for cross-language interop.
//!
//! # Security properties
//!
//! Every chunk is sealed under a per-stream message key with a counter nonce, and
//! its additional-authenticated-data binds the format version, suite, a random
//! per-stream id, the chunk index, a final-chunk marker, the chunk length, and
//! the declared chunk size. Records are therefore non-reorderable,
//! non-truncatable (the stream fails closed if it ends before a final-marked
//! chunk), non-replayable into another stream, and non-downgradable. All
//! authentication failures fail closed.
//!
//! # Suites and the content-encryption key (CEK)
//!
//! * The AEAD suites seal chunks directly under a 256-bit CEK established
//!   symmetrically. Secure by default, [`CekSource::Generate`] mints a fresh
//!   random CEK per stream and [`encrypt_aead`] returns it for the caller to
//!   store or transmit; [`CekSource::Provided`] accepts a caller-held key.
//! * The ML-KEM suites generate a fresh CEK, wrap it once against the recipient's
//!   public encapsulation key, and write that envelope into the header. Chunks are
//!   then sealed with AES-256-GCM under the CEK. Encryption needs only the public
//!   key; decryption recovers the CEK through a [`CekRecovery`] seam (see
//!   [`BrokerCekRecovery`]).

mod format;
mod kem;

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

use basil_proto::broker::v1 as pb;

pub use format::{DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, StreamError, StreamResult};
pub use kem::{BrokerCekRecovery, CekRecovery, LocalSeedCekRecovery, StreamKemEnvelope};

use format::{
    CEK_LEN, ChunkAead, FIXED_HEADER_LEN, NONCE_LEN, STREAM_ID_LEN, STREAM_SALT_LEN,
    SUITE_AES256GCM, SUITE_CHACHA20POLY1305, SUITE_MLKEM512, SUITE_MLKEM768, SUITE_MLKEM1024,
    StreamHeader, TAG_LEN, aead_open, aead_seal, build_cekwrap_aad, build_chunk_aad, chunk_nonce,
    derive_message_key, parse_fixed_header, write_fixed_header,
};

/// A symmetric AEAD suite for streaming encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadSuite {
    /// AES-256-GCM with a 96-bit nonce and 128-bit tag.
    Aes256Gcm,
    /// ChaCha20-Poly1305 with a 96-bit nonce and 128-bit tag.
    ChaCha20Poly1305,
}

impl AeadSuite {
    pub(crate) const fn suite_id(self) -> u8 {
        match self {
            Self::Aes256Gcm => SUITE_AES256GCM,
            Self::ChaCha20Poly1305 => SUITE_CHACHA20POLY1305,
        }
    }

    pub(crate) const fn chunk_aead(self) -> ChunkAead {
        match self {
            Self::Aes256Gcm => ChunkAead::Aes256Gcm,
            Self::ChaCha20Poly1305 => ChunkAead::ChaCha20Poly1305,
        }
    }

    pub(crate) const fn from_suite_id(suite_id: u8) -> Option<Self> {
        match suite_id {
            SUITE_AES256GCM => Some(Self::Aes256Gcm),
            SUITE_CHACHA20POLY1305 => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }
}

/// An ML-KEM (FIPS 203) parameter set for post-quantum streaming encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemSuite {
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
}

impl MlKemSuite {
    pub(crate) const fn suite_id(self) -> u8 {
        match self {
            Self::MlKem512 => SUITE_MLKEM512,
            Self::MlKem768 => SUITE_MLKEM768,
            Self::MlKem1024 => SUITE_MLKEM1024,
        }
    }

    pub(crate) const fn kem_token(self) -> &'static str {
        match self {
            Self::MlKem512 => "ml-kem-512",
            Self::MlKem768 => "ml-kem-768",
            Self::MlKem1024 => "ml-kem-1024",
        }
    }

    /// FIPS 203 ML-KEM ciphertext (encapsulated-key) length in bytes.
    pub(crate) const fn ciphertext_len(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    pub(crate) const fn proto_kem_algorithm(self) -> pb::KemAlgorithm {
        match self {
            Self::MlKem512 => pb::KemAlgorithm::MlKem512,
            Self::MlKem768 => pb::KemAlgorithm::MlKem768,
            Self::MlKem1024 => pb::KemAlgorithm::MlKem1024,
        }
    }

    pub(crate) const fn from_suite_id(suite_id: u8) -> Option<Self> {
        match suite_id {
            SUITE_MLKEM512 => Some(Self::MlKem512),
            SUITE_MLKEM768 => Some(Self::MlKem768),
            SUITE_MLKEM1024 => Some(Self::MlKem1024),
            _ => None,
        }
    }
}

/// How the content-encryption key for an AEAD stream is established.
pub enum CekSource {
    /// Generate a fresh random 256-bit CEK (secure default). [`encrypt_aead`]
    /// returns the generated key so the caller can persist or transmit it.
    Generate,
    /// Use a caller-supplied 32-byte content-encryption key.
    Provided(Zeroizing<[u8; CEK_LEN]>),
}

/// Fill `buf` with cryptographically secure random bytes from the OS RNG.
pub(crate) fn fill_random(buf: &mut [u8]) {
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(buf);
}

/// Per-chunk crypto context shared by the encrypt and decrypt loops.
struct ChunkCrypto<'a> {
    suite_id: u8,
    chunk_aead: ChunkAead,
    chunk_size: usize,
    stream_id: &'a [u8; STREAM_ID_LEN],
    message_key: &'a [u8; CEK_LEN],
}

/// Encrypt `reader` into `writer` under a symmetric AEAD suite.
///
/// Returns the content-encryption key that was used (freshly generated for
/// [`CekSource::Generate`], or a copy of the supplied key). The returned key is
/// what [`decrypt_aead`] needs.
///
/// # Errors
///
/// Returns [`StreamError::BadChunkSize`] for an out-of-range `chunk_size`,
/// [`StreamError::Io`] for reader/writer failures, and a crypto error if sealing
/// fails.
pub async fn encrypt_aead<R, W>(
    mut reader: R,
    mut writer: W,
    suite: AeadSuite,
    cek: CekSource,
    chunk_size: usize,
) -> StreamResult<Zeroizing<[u8; CEK_LEN]>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let chunk_size = validate_chunk_size(chunk_size)?;
    let cek = match cek {
        CekSource::Generate => {
            let mut key = Zeroizing::new([0u8; CEK_LEN]);
            fill_random(key.as_mut_slice());
            key
        }
        CekSource::Provided(key) => key,
    };
    let mut stream_id = [0u8; STREAM_ID_LEN];
    let mut stream_salt = [0u8; STREAM_SALT_LEN];
    fill_random(&mut stream_id);
    fill_random(&mut stream_salt);

    let suite_id = suite.suite_id();
    let chunk_size_u32 =
        u32::try_from(chunk_size).map_err(|_| StreamError::BadChunkSize(chunk_size))?;
    let mut header = Vec::with_capacity(FIXED_HEADER_LEN);
    write_fixed_header(
        &mut header,
        suite_id,
        chunk_size_u32,
        &stream_id,
        &stream_salt,
    );

    let message_key = derive_message_key(&stream_salt, cek.as_slice(), suite_id, &stream_id)?;
    let crypto = ChunkCrypto {
        suite_id,
        chunk_aead: suite.chunk_aead(),
        chunk_size,
        stream_id: &stream_id,
        message_key: &message_key,
    };
    write_chunks(&mut reader, &mut writer, header, &crypto).await?;
    Ok(cek)
}

/// Decrypt a symmetric-AEAD stream produced by [`encrypt_aead`] into `writer`.
///
/// # Errors
///
/// Returns [`StreamError::SuiteMismatch`] if the container is an ML-KEM stream,
/// [`StreamError::Truncated`] / [`StreamError::AuthFailed`] on a truncated,
/// reordered, or tampered stream, and [`StreamError::BadMagic`] /
/// [`StreamError::ShortHeader`] for a malformed header.
pub async fn decrypt_aead<R, W>(
    mut reader: R,
    mut writer: W,
    cek: &[u8; CEK_LEN],
) -> StreamResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let header = read_fixed_header(&mut reader).await?;
    let suite = AeadSuite::from_suite_id(header.suite_id).ok_or(StreamError::SuiteMismatch {
        actual: header.suite_id,
    })?;
    let message_key =
        derive_message_key(&header.stream_salt, cek, header.suite_id, &header.stream_id)?;
    let crypto = ChunkCrypto {
        suite_id: header.suite_id,
        chunk_aead: suite.chunk_aead(),
        chunk_size: header.chunk_size as usize,
        stream_id: &header.stream_id,
        message_key: &message_key,
    };
    read_chunks(&mut reader, &mut writer, &crypto).await
}

/// Encrypt `reader` into `writer` under an ML-KEM suite, wrapping a fresh CEK to
/// `public_key` (the recipient's ML-KEM public encapsulation key). No broker is
/// contacted.
///
/// # Errors
///
/// Returns [`StreamError::BadChunkSize`] for an out-of-range `chunk_size`,
/// [`StreamError::BadPublicKey`] for a malformed encapsulation key, and a crypto
/// or I/O error on failure.
pub async fn encrypt_ml_kem<R, W>(
    mut reader: R,
    mut writer: W,
    suite: MlKemSuite,
    public_key: &[u8],
    chunk_size: usize,
) -> StreamResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let chunk_size = validate_chunk_size(chunk_size)?;
    let mut cek = Zeroizing::new([0u8; CEK_LEN]);
    fill_random(cek.as_mut_slice());
    let mut stream_id = [0u8; STREAM_ID_LEN];
    let mut stream_salt = [0u8; STREAM_SALT_LEN];
    fill_random(&mut stream_id);
    fill_random(&mut stream_salt);

    let suite_id = suite.suite_id();
    let cekwrap_aad = build_cekwrap_aad(suite_id, &stream_id);
    let envelope = kem::wrap_cek(public_key, suite, cek.as_slice(), &cekwrap_aad)?;

    let chunk_size_u32 =
        u32::try_from(chunk_size).map_err(|_| StreamError::BadChunkSize(chunk_size))?;
    let mut header = Vec::new();
    write_fixed_header(
        &mut header,
        suite_id,
        chunk_size_u32,
        &stream_id,
        &stream_salt,
    );
    header.extend_from_slice(&kem::serialize_kem_header(&envelope)?);

    let message_key = derive_message_key(&stream_salt, cek.as_slice(), suite_id, &stream_id)?;
    let crypto = ChunkCrypto {
        suite_id,
        chunk_aead: ChunkAead::Aes256Gcm,
        chunk_size,
        stream_id: &stream_id,
        message_key: &message_key,
    };
    write_chunks(&mut reader, &mut writer, header, &crypto).await
}

/// Decrypt an ML-KEM stream produced by [`encrypt_ml_kem`] into `writer`,
/// recovering the CEK through `recovery` (exactly once).
///
/// # Errors
///
/// Returns [`StreamError::SuiteMismatch`] if the container is not an ML-KEM
/// stream, [`StreamError::ShortHeader`] / [`StreamError::BadKemCiphertext`] for a
/// malformed KEM header, a recovery error if the CEK cannot be unwrapped, and
/// [`StreamError::Truncated`] / [`StreamError::AuthFailed`] on a truncated,
/// reordered, or tampered stream.
// The future borrows the generic reader/writer/recovery across awaits; whether it
// is `Send` is the caller's to decide via the concrete types, so do not force it.
#[allow(clippy::future_not_send)]
pub async fn decrypt_ml_kem<R, W, C>(mut reader: R, mut writer: W, recovery: &C) -> StreamResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    C: CekRecovery,
{
    let header = read_fixed_header(&mut reader).await?;
    let suite = MlKemSuite::from_suite_id(header.suite_id).ok_or(StreamError::SuiteMismatch {
        actual: header.suite_id,
    })?;
    let envelope = read_kem_envelope(&mut reader, suite).await?;
    let cekwrap_aad = build_cekwrap_aad(header.suite_id, &header.stream_id);
    let cek = recovery.recover_cek(&envelope, &cekwrap_aad).await?;
    if cek.len() != CEK_LEN {
        return Err(StreamError::BadCekLength);
    }
    let message_key = derive_message_key(
        &header.stream_salt,
        &cek,
        header.suite_id,
        &header.stream_id,
    )?;
    let crypto = ChunkCrypto {
        suite_id: header.suite_id,
        chunk_aead: ChunkAead::Aes256Gcm,
        chunk_size: header.chunk_size as usize,
        stream_id: &header.stream_id,
        message_key: &message_key,
    };
    read_chunks(&mut reader, &mut writer, &crypto).await
}

const fn validate_chunk_size(chunk_size: usize) -> StreamResult<usize> {
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(StreamError::BadChunkSize(chunk_size));
    }
    Ok(chunk_size)
}

/// Write the header then the length-prefixed per-chunk AEAD records.
async fn write_chunks<R, W>(
    reader: &mut R,
    writer: &mut W,
    header: Vec<u8>,
    crypto: &ChunkCrypto<'_>,
) -> StreamResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    writer.write_all(&header).await?;

    let chunk_size_u32 = u32::try_from(crypto.chunk_size)
        .map_err(|_| StreamError::BadChunkSize(crypto.chunk_size))?;
    let mut current = vec![0u8; crypto.chunk_size];
    let mut have = read_full(reader, &mut current).await?;
    let mut index: u64 = 0;
    loop {
        let mut next = vec![0u8; crypto.chunk_size];
        let next_have = read_full(reader, &mut next).await?;
        let is_final = next_have == 0;

        let plaintext_len = u32::try_from(have).map_err(|_| StreamError::SealFailed)?;
        let aad = build_chunk_aad(
            crypto.suite_id,
            crypto.stream_id,
            index,
            is_final,
            plaintext_len,
            chunk_size_u32,
        );
        let nonce = chunk_nonce(index);
        let plaintext = current.get(..have).ok_or(StreamError::SealFailed)?;
        let record = aead_seal(
            crypto.chunk_aead,
            crypto.message_key,
            &nonce,
            plaintext,
            &aad,
        )?;
        let record_len = u32::try_from(record.len()).map_err(|_| StreamError::SealFailed)?;
        writer.write_all(&record_len.to_be_bytes()).await?;
        writer.write_all(&record).await?;

        index = index.checked_add(1).ok_or(StreamError::SealFailed)?;
        if is_final {
            break;
        }
        current = next;
        have = next_have;
    }
    writer.flush().await?;
    Ok(())
}

/// Read and authenticate the length-prefixed per-chunk records into `writer`.
async fn read_chunks<R, W>(
    reader: &mut R,
    writer: &mut W,
    crypto: &ChunkCrypto<'_>,
) -> StreamResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let max_record = crypto
        .chunk_size
        .checked_add(TAG_LEN)
        .ok_or(StreamError::ChunkTooLarge)?;
    let chunk_size_u32 = u32::try_from(crypto.chunk_size)
        .map_err(|_| StreamError::BadChunkSize(crypto.chunk_size))?;

    let Some(first_len) = read_len_prefix(reader).await? else {
        // An empty stream still carries one final-marked chunk; no records at all
        // means truncation.
        return Err(StreamError::Truncated);
    };
    let mut current = read_record(reader, first_len, max_record).await?;
    let mut index: u64 = 0;
    loop {
        let next_len = read_len_prefix(reader).await?;
        let is_final = next_len.is_none();

        let plaintext_len = current
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(StreamError::AuthFailed)?;
        let plaintext_len_u32 =
            u32::try_from(plaintext_len).map_err(|_| StreamError::ChunkTooLarge)?;
        let aad = build_chunk_aad(
            crypto.suite_id,
            crypto.stream_id,
            index,
            is_final,
            plaintext_len_u32,
            chunk_size_u32,
        );
        let nonce = chunk_nonce(index);
        let plaintext = aead_open(
            crypto.chunk_aead,
            crypto.message_key,
            &nonce,
            &current,
            &aad,
        )?;

        // A non-final chunk must carry exactly chunk_size plaintext; this is also
        // bound in the AAD above, so a tampered framing already failed to open.
        if !is_final && plaintext_len != crypto.chunk_size {
            return Err(StreamError::AuthFailed);
        }
        writer.write_all(plaintext.as_slice()).await?;
        if is_final {
            break;
        }
        index = index.checked_add(1).ok_or(StreamError::Truncated)?;
        let next_len = next_len.ok_or(StreamError::Truncated)?;
        current = read_record(reader, next_len, max_record).await?;
    }
    writer.flush().await?;
    Ok(())
}

async fn read_fixed_header<R>(reader: &mut R) -> StreamResult<StreamHeader>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; FIXED_HEADER_LEN];
    let got = read_full(reader, &mut buf).await?;
    if got != FIXED_HEADER_LEN {
        return Err(StreamError::ShortHeader);
    }
    parse_fixed_header(&buf)
}

async fn read_kem_envelope<R>(reader: &mut R, suite: MlKemSuite) -> StreamResult<StreamKemEnvelope>
where
    R: AsyncRead + Unpin,
{
    let kem_ct_len = read_len_prefix(reader)
        .await?
        .ok_or(StreamError::ShortHeader)?;
    let expected = suite.ciphertext_len();
    if kem_ct_len as usize != expected {
        return Err(StreamError::BadKemCiphertext);
    }
    let encapsulated_key = read_record_exact(reader, expected).await?;
    let nonce_bytes = read_record_exact(reader, NONCE_LEN).await?;
    let nonce: [u8; NONCE_LEN] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| StreamError::ShortHeader)?;
    let wrapped_len = read_len_prefix(reader)
        .await?
        .ok_or(StreamError::ShortHeader)?;
    let wrapped = CEK_LEN
        .checked_add(TAG_LEN)
        .ok_or(StreamError::BadKemCiphertext)?;
    if wrapped_len as usize != wrapped {
        return Err(StreamError::BadKemCiphertext);
    }
    let ciphertext = read_record_exact(reader, wrapped).await?;
    Ok(StreamKemEnvelope {
        encapsulated_key,
        nonce,
        ciphertext,
    })
}

/// Read a length-prefixed record body, bounding its size against `max_record`.
async fn read_record<R>(reader: &mut R, len: u32, max_record: usize) -> StreamResult<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let len = len as usize;
    if len > max_record {
        return Err(StreamError::ChunkTooLarge);
    }
    read_record_exact(reader, len).await
}

/// Read exactly `n` bytes or fail closed with [`StreamError::Truncated`].
async fn read_record_exact<R>(reader: &mut R, n: usize) -> StreamResult<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; n];
    let got = read_full(reader, &mut buf).await?;
    if got != n {
        return Err(StreamError::Truncated);
    }
    Ok(buf)
}

/// Read a 4-byte big-endian length prefix. `None` signals a clean end of stream
/// at a record boundary; a partial prefix is [`StreamError::Truncated`].
async fn read_len_prefix<R>(reader: &mut R) -> StreamResult<Option<u32>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 4];
    let got = read_full(reader, &mut buf).await?;
    match got {
        0 => Ok(None),
        4 => Ok(Some(u32::from_be_bytes(buf))),
        _ => Err(StreamError::Truncated),
    }
}

/// Read until `buf` is full or the reader reaches EOF; return the bytes filled.
async fn read_full<R>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize>
where
    R: AsyncRead + Unpin,
{
    let mut filled = 0;
    while filled < buf.len() {
        let Some(dst) = buf.get_mut(filled..) else {
            break;
        };
        let n = reader.read(dst).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

#[cfg(test)]
mod tests;
