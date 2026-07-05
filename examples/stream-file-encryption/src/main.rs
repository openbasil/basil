// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Encrypt a large file with `basil::stream`, where **Basil owns every nonce**
//! and the container format is fixed by the library.
//!
//! Two passes over a multi-mebibyte file:
//!
//! 1. **Symmetric AEAD** (AES-256-GCM) with a freshly generated
//!    content-encryption key (CEK). Encrypt → decrypt → assert byte-for-byte
//!    equality. No broker is involved: the CEK is established locally and Basil
//!    still owns the chunk nonces and the container framing.
//! 2. **Post-quantum ML-KEM-768**, where the CEK is wrapped once against a
//!    **broker-custodied** encapsulation key. Encryption needs only the public
//!    key; decryption recovers the CEK through the broker's `UnwrapEnvelope` RPC
//!    (`BrokerCekRecovery`): the ML-KEM decapsulation seed never leaves the
//!    vault. This mirrors the Go `stream` subpackage byte-for-byte.
//!
//! Finally a **tamper** pass flips one ciphertext byte and asserts decryption
//! fails closed.
//!
//! Arguments: `<agent-socket-path> <scratch-dir>`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use basil::{
    AeadSuite, BrokerCekRecovery, CekSource, Client, DEFAULT_CHUNK_SIZE, KeyType, MlKemSuite,
    decrypt_aead, decrypt_ml_kem, encrypt_aead, encrypt_ml_kem,
};
use tokio::fs::File;

/// A "few MiB" input so the stream spans many chunks (~64 chunks at the default
/// 64 KiB chunk size).
const INPUT_LEN: usize = 4 * 1024 * 1024;
/// The catalog key that custodies the ML-KEM decapsulation seed.
const KEM_KEY: &str = "stream.kem";

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let socket = args
        .next()
        .context("usage: stream-file-encryption <agent-socket-path> <scratch-dir>")?;
    let dir = PathBuf::from(
        args.next()
            .context("usage: stream-file-encryption <agent-socket-path> <scratch-dir>")?,
    );
    tokio::fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create scratch dir {}", dir.display()))?;

    let client = Client::connect(&socket)
        .await
        .with_context(|| format!("connect basil agent at {socket}"))?;

    // One shared plaintext for both passes.
    let plaintext = dir.join("plain.bin");
    write_pseudorandom(&plaintext, INPUT_LEN).await?;
    println!("generated {INPUT_LEN} byte input across many chunks");

    aead_pass(&dir, &plaintext).await?;
    ml_kem_pass(&client, &dir, &plaintext).await?;
    tamper_pass(&dir, &plaintext).await?;

    println!("stream-file-encryption: all assertions passed");
    Ok(())
}

/// AES-256-GCM with a generated CEK: encrypt, decrypt, assert byte-identical.
async fn aead_pass(dir: &Path, plaintext: &Path) -> Result<()> {
    let cipher = dir.join("aead.cipher");
    let cek = {
        let reader = File::open(plaintext).await.context("open plaintext")?;
        let writer = File::create(&cipher)
            .await
            .context("create aead ciphertext")?;
        encrypt_aead(
            reader,
            writer,
            AeadSuite::Aes256Gcm,
            CekSource::Generate,
            DEFAULT_CHUNK_SIZE,
        )
        .await
        .context("encrypt_aead")?
    };

    let roundtrip = dir.join("aead.round");
    {
        let reader = File::open(&cipher).await.context("open aead ciphertext")?;
        let writer = File::create(&roundtrip)
            .await
            .context("create aead roundtrip")?;
        decrypt_aead(reader, writer, &cek)
            .await
            .context("decrypt_aead")?;
    }

    ensure!(
        files_equal(plaintext, &roundtrip).await?,
        "AES-256-GCM round-trip did not match byte-for-byte"
    );
    println!("aead (aes-256-gcm): round-trip byte-identical");
    Ok(())
}

/// ML-KEM-768 with a broker-custodied key: encrypt with the public encapsulation
/// key, recover the CEK through the broker, assert byte-identical.
async fn ml_kem_pass(client: &Client, dir: &Path, plaintext: &Path) -> Result<()> {
    // Provision the custodied KEM key. The broker generates and seals the seed
    // and returns only the public encapsulation key.
    let public_key = {
        let mut client = client.clone();
        client
            .new_key(KEM_KEY, KeyType::MlKem768)
            .await
            .context("provision custodied ML-KEM-768 key")?
            .public_key
    };
    println!(
        "provisioned custodied {KEM_KEY} ({} byte ML-KEM-768 encapsulation key)",
        public_key.len()
    );

    let cipher = dir.join("kem.cipher");
    {
        // Encryption is broker-free: it only needs the public key.
        let reader = File::open(plaintext).await.context("open plaintext")?;
        let writer = File::create(&cipher)
            .await
            .context("create kem ciphertext")?;
        encrypt_ml_kem(
            reader,
            writer,
            MlKemSuite::MlKem768,
            &public_key,
            DEFAULT_CHUNK_SIZE,
        )
        .await
        .context("encrypt_ml_kem")?;
    }

    let roundtrip = dir.join("kem.round");
    {
        // Decryption recovers the CEK through the broker; the seed stays custodied.
        let recovery = BrokerCekRecovery::new(client.clone(), KEM_KEY, MlKemSuite::MlKem768);
        let reader = File::open(&cipher).await.context("open kem ciphertext")?;
        let writer = File::create(&roundtrip)
            .await
            .context("create kem roundtrip")?;
        decrypt_ml_kem(reader, writer, &recovery)
            .await
            .context("decrypt_ml_kem via broker CEK recovery")?;
    }

    ensure!(
        files_equal(plaintext, &roundtrip).await?,
        "ML-KEM-768 round-trip did not match byte-for-byte"
    );
    println!("ml-kem-768 (broker CEK recovery): round-trip byte-identical");
    Ok(())
}

/// Flip one ciphertext byte and assert decryption fails closed.
async fn tamper_pass(dir: &Path, plaintext: &Path) -> Result<()> {
    let cipher = dir.join("aead.cipher");
    let cek = {
        let reader = File::open(plaintext).await.context("open plaintext")?;
        let writer = File::create(&cipher)
            .await
            .context("create tamper-source ciphertext")?;
        encrypt_aead(
            reader,
            writer,
            AeadSuite::Aes256Gcm,
            CekSource::Generate,
            DEFAULT_CHUNK_SIZE,
        )
        .await
        .context("encrypt_aead for tamper")?
    };

    let mut bytes = tokio::fs::read(&cipher).await.context("read ciphertext")?;
    ensure!(bytes.len() > 64, "ciphertext unexpectedly short");
    // Flip a bit well past the fixed header, inside the authenticated body.
    let victim = bytes.len() / 2;
    bytes[victim] ^= 0x01;

    let result = decrypt_aead(bytes.as_slice(), Vec::new(), &cek).await;
    match result {
        Ok(()) => bail!("decryption of a tampered stream unexpectedly SUCCEEDED"),
        Err(err) => println!("tamper: decryption failed closed ({err})"),
    }
    Ok(())
}

/// Write `len` bytes of deterministic pseudo-random data (xorshift; no extra
/// dependency) to `path`.
async fn write_pseudorandom(path: &Path, len: usize) -> Result<()> {
    let mut buf = vec![0u8; len];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for byte in &mut buf {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xff) as u8;
    }
    tokio::fs::write(path, &buf)
        .await
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Compare two files byte-for-byte.
async fn files_equal(a: &Path, b: &Path) -> Result<bool> {
    let a = tokio::fs::read(a).await.context("read left file")?;
    let b = tokio::fs::read(b).await.context("read right file")?;
    Ok(a == b)
}
