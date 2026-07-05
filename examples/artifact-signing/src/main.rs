//! Sign and verify a release artifact through the Basil broker without the
//! signing key ever leaving the vault.
//!
//! The flow, in order:
//!
//! 1. Sign a small release manifest with a transit-backed Ed25519 catalog key
//!    (`release.signing`). The key material stays in the backend; the broker
//!    returns only the detached signature.
//! 2. Verify the signature through the broker (`verify`).
//! 3. Fetch the public half (`get_public_key`) and verify the SAME signature
//!    locally with `ed25519-dalek`, proving the broker produced a standard,
//!    interoperable Ed25519 signature: no Basil-specific verifier required.
//! 4. Attempt to sign with a key the policy does not grant this process
//!    (`forbidden.key`) and assert the broker denies it with a typed
//!    `PermissionDenied`. Reading a key never implies the right to sign with
//!    another one.
//!
//! The socket path is the single positional argument.

use anyhow::{Context, Result, bail, ensure};
use basil::{Client, Error};
use ed25519_dalek::{Signature, VerifyingKey};

/// Catalog key the policy grants this process `sign`/`verify`/`get_public_key`.
const SIGNING_KEY: &str = "release.signing";
/// Catalog key that exists but is NOT granted to this process: the deny case.
const FORBIDDEN_KEY: &str = "forbidden.key";

/// A tiny, deterministic release manifest. In a real pipeline these bytes would
/// be a checksum manifest, an SBOM, or the artifact digest itself.
const MANIFEST: &[u8] = br#"{
  "artifact": "basil-agent",
  "version": "1.4.2",
  "sha256": "9f2c1e4a7b0d5e8f3a6c9b2d1e4f7a0c3b6d9e2f5a8c1b4d7e0f3a6c9b2d1e4f"
}"#;

#[tokio::main]
async fn main() -> Result<()> {
    let socket = std::env::args()
        .nth(1)
        .context("usage: artifact-signing <agent-socket-path>")?;
    let mut client = Client::connect(&socket)
        .await
        .with_context(|| format!("connect basil agent at {socket}"))?;

    // 1. Sign the manifest bytes in place. `sign` takes the raw bytes; the
    //    broker does no client-directed prehashing.
    let signature = client
        .sign(SIGNING_KEY, MANIFEST)
        .await
        .context("broker sign")?;
    println!(
        "signed {} manifest bytes with {SIGNING_KEY}",
        MANIFEST.len()
    );

    // 2. Verify through the broker.
    let broker_ok = client
        .verify(SIGNING_KEY, MANIFEST, &signature)
        .await
        .context("broker verify")?;
    ensure!(broker_ok, "broker reported the signature as INVALID");
    println!("broker verify: true");

    // 3. Fetch the public half and verify locally with a stock Ed25519 library.
    let public_key = client
        .get_public_key(SIGNING_KEY, None)
        .await
        .context("fetch public key")?
        .public_key;
    let public_key: [u8; 32] = public_key
        .as_slice()
        .try_into()
        .with_context(|| format!("expected 32 public-key bytes, got {}", public_key.len()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).context("public key is not a valid Ed25519 point")?;
    let dalek_sig =
        Signature::from_slice(&signature).context("broker signature is not 64 bytes")?;
    verifying_key
        .verify_strict(MANIFEST, &dalek_sig)
        .context("independent ed25519-dalek verification failed")?;
    println!("dalek verify: true");

    // A control check: a one-bit tamper must fail the same local verifier.
    let mut tampered = MANIFEST.to_vec();
    tampered[0] ^= 0x01;
    ensure!(
        verifying_key.verify_strict(&tampered, &dalek_sig).is_err(),
        "tampered manifest unexpectedly verified"
    );
    println!("dalek verify (tampered): rejected");

    // 4. Least privilege: signing with an ungranted key must be denied.
    match client.sign(FORBIDDEN_KEY, MANIFEST).await {
        Ok(_) => bail!("signing {FORBIDDEN_KEY} succeeded but policy grants no such right"),
        Err(Error::Status { code, reason, .. }) if code == tonic::Code::PermissionDenied => {
            println!("deny observed: {code:?}/{reason}");
        }
        Err(other) => bail!("expected PermissionDenied for {FORBIDDEN_KEY}, got: {other}"),
    }

    println!("artifact-signing: all assertions passed");
    Ok(())
}
