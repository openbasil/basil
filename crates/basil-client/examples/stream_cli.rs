// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-language interop CLI for the Basil streaming container format.
//!
//! It reads plaintext (or a container) on stdin and writes the result to stdout,
//! so the Go client's `stream` package can prove byte-for-byte interop against
//! this Rust reference implementation. The format is specified in
//! `docs/specs/streaming-encryption-format.md`.
//!
//! Usage:
//!
//! ```text
//! stream_cli encrypt       --suite <aes256gcm|chacha20poly1305> --key <hex32> [--chunk-size N]
//! stream_cli decrypt       --key <hex32>
//! stream_cli mlkem-encrypt --suite <mlkem512|mlkem768|mlkem1024> --pubkey <hex> [--chunk-size N]
//! stream_cli mlkem-decrypt --suite <mlkem512|mlkem768|mlkem1024> --seed <hex64>
//! ```
//!
//! For the AEAD suites the key is the raw 32-byte content-encryption key as hex,
//! which is trivially shared with the Go side. For the ML-KEM suites the public
//! encapsulation key (encrypt) and the raw 64-byte decapsulation seed (decrypt)
//! are hex; the seed path uses the local recovery seam, so no broker is needed.

use std::collections::HashMap;
use std::io::{Read, Write};

use basil_client::stream::{
    AeadSuite, CekSource, LocalSeedCekRecovery, MlKemSuite, decrypt_aead, decrypt_ml_kem,
    encrypt_aead, encrypt_ml_kem,
};
use zeroize::Zeroizing;

type CliError = Box<dyn std::error::Error>;

const DEFAULT_CLI_CHUNK_SIZE: usize = 64;

fn main() {
    if let Err(err) = run() {
        eprintln!("stream_cli: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    let mut args = std::env::args();
    let _bin = args.next();
    let command = args.next().ok_or("missing subcommand")?;
    let flags = parse_flags(args)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input)?;
    let mut output = Vec::new();

    match command.as_str() {
        "encrypt" => {
            let suite = parse_aead_suite(flag(&flags, "suite")?)?;
            let key = parse_cek(flag(&flags, "key")?)?;
            let chunk = chunk_size(&flags)?;
            rt.block_on(async {
                encrypt_aead(
                    input.as_slice(),
                    &mut output,
                    suite,
                    CekSource::Provided(key),
                    chunk,
                )
                .await
                .map(|_| ())
            })?;
        }
        "decrypt" => {
            let key = parse_cek(flag(&flags, "key")?)?;
            rt.block_on(decrypt_aead(input.as_slice(), &mut output, &key))?;
        }
        "mlkem-encrypt" => {
            let suite = parse_ml_kem_suite(flag(&flags, "suite")?)?;
            let public = hex::decode(flag(&flags, "pubkey")?)?;
            let chunk = chunk_size(&flags)?;
            rt.block_on(encrypt_ml_kem(
                input.as_slice(),
                &mut output,
                suite,
                &public,
                chunk,
            ))?;
        }
        "mlkem-decrypt" => {
            let suite = parse_ml_kem_suite(flag(&flags, "suite")?)?;
            let seed = hex::decode(flag(&flags, "seed")?)?;
            let recovery = LocalSeedCekRecovery::new(seed, suite);
            rt.block_on(decrypt_ml_kem(input.as_slice(), &mut output, &recovery))?;
        }
        other => return Err(format!("unknown subcommand: {other}").into()),
    }

    std::io::stdout().write_all(&output)?;
    std::io::stdout().flush()?;
    Ok(())
}

fn parse_flags(mut args: std::env::Args) -> Result<HashMap<String, String>, CliError> {
    let mut flags = HashMap::new();
    while let Some(key) = args.next() {
        let name = key
            .strip_prefix("--")
            .ok_or_else(|| format!("expected --flag, got {key}"))?;
        let value = args
            .next()
            .ok_or_else(|| format!("flag --{name} needs a value"))?;
        flags.insert(name.to_owned(), value);
    }
    Ok(flags)
}

fn flag<'a>(flags: &'a HashMap<String, String>, name: &str) -> Result<&'a str, CliError> {
    flags
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required flag --{name}").into())
}

fn chunk_size(flags: &HashMap<String, String>) -> Result<usize, CliError> {
    match flags.get("chunk-size") {
        Some(value) => Ok(value.parse()?),
        None => Ok(DEFAULT_CLI_CHUNK_SIZE),
    }
}

fn parse_cek(value: &str) -> Result<Zeroizing<[u8; 32]>, CliError> {
    let bytes = hex::decode(value)?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "key must be 32 bytes (64 hex chars)")?;
    Ok(Zeroizing::new(array))
}

fn parse_aead_suite(name: &str) -> Result<AeadSuite, CliError> {
    match name {
        "aes256gcm" | "aes-256-gcm" => Ok(AeadSuite::Aes256Gcm),
        "chacha20poly1305" | "chacha20-poly1305" => Ok(AeadSuite::ChaCha20Poly1305),
        other => Err(format!("unknown AEAD suite: {other}").into()),
    }
}

fn parse_ml_kem_suite(name: &str) -> Result<MlKemSuite, CliError> {
    match name {
        "mlkem512" | "ml-kem-512" => Ok(MlKemSuite::MlKem512),
        "mlkem768" | "ml-kem-768" => Ok(MlKemSuite::MlKem768),
        "mlkem1024" | "ml-kem-1024" => Ok(MlKemSuite::MlKem1024),
        other => Err(format!("unknown ML-KEM suite: {other}").into()),
    }
}
