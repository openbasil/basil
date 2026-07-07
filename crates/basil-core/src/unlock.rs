// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Startup unlock: build the method registry from flags, check bundle perms,
//! open the sealed bundle, and exchange `AppRole` creds for a short-lived token.
//!
//! Every step is fallible-by-`Result` and **fails closed** (clean non-zero exit,
//! no panic, §1.3 / §5 of `designs/unlock-and-bundle.html`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::seal::{CredBundle, MethodRegistry, format};
use anyhow::{Context, Result, bail};
use tracing::{info, warn};
use zeroize::Zeroizing;

#[cfg(feature = "unlock-age-yubikey")]
use crate::seal::AgeYubikeyMethod;
#[cfg(feature = "unlock-bip39")]
use crate::seal::Bip39Method;
use crate::seal::PassphraseMethod;
#[cfg(feature = "unlock-tpm")]
use crate::seal::TpmMethod;

/// Default `age-plugin-yubikey` plugin name.
#[cfg(feature = "unlock-age-yubikey")]
const DEFAULT_YUBIKEY_PLUGIN: &str = "yubikey";

/// Unlock-method selection flags.
///
/// These are independent operator toggles (one per unlock surface), not a state
/// machine, so the several-bools shape is intentional.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct UnlockArgs {
    /// Enable the age-yubikey slot via `age-plugin-yubikey` (drives PIN/touch).
    pub age_yubikey: bool,

    /// Read the 24-word BIP39 recovery phrase from this `0600` file (break-glass).
    /// The phrase is never taken from argv/env.
    pub bip39_phrase_file: Option<std::path::PathBuf>,

    /// Enable the TPM2 sealed slot. Availability is the runtime `/dev/tpmrm0`
    /// probe (no operator secret); requires the `unlock-tpm` feature.
    pub tpm: bool,

    /// Read the production passphrase from this file.
    pub passphrase_file: Option<std::path::PathBuf>,

    /// Do not wipe the passphrase file after reading it.
    pub passphrase_no_wipe: bool,

    /// Refuse to start if the bundle file is not `0600` (default: warn only).
    pub strict_bundle_perms: bool,
}

/// Read + check perms of the bundle file, then unlock it into a [`CredBundle`].
///
/// The master KEK is recovered and zeroized inside `seal::open_bundle`; only the
/// decrypted [`CredBundle`] is returned. Fails closed if no slot opens.
pub fn open_bundle_at_startup(bundle_path: &Path, args: &UnlockArgs) -> Result<CredBundle> {
    check_bundle_perms(bundle_path, args.strict_bundle_perms)?;

    let bytes = std::fs::read(bundle_path)
        .with_context(|| format!("reading sealed bundle from {}", bundle_path.display()))?;
    let parsed = format::decode(&bytes).context("parsing sealed bundle")?;

    // Build the registry from the enabled+configured methods. We keep the
    // method values alive for the duration of the open call.
    #[cfg(feature = "unlock-age-yubikey")]
    let age_method = build_age_method(args)?;
    #[cfg(feature = "unlock-bip39")]
    let bip39_method = build_bip39_method(args)?;
    #[cfg(feature = "unlock-tpm")]
    let tpm_method = build_tpm_method(args);
    let passphrase_method = build_passphrase_method(args)?;

    // `mut` is only exercised when at least one unlock-* feature is enabled; the
    // default + all-features builds always do. Allow the unused-mut in the
    // degenerate no-method build rather than scatter cfgs.
    #[allow(unused_mut)]
    let mut registry = MethodRegistry::new();
    #[cfg(feature = "unlock-age-yubikey")]
    if let Some(m) = &age_method {
        registry = registry.with(m);
    }
    #[cfg(feature = "unlock-bip39")]
    if let Some(m) = &bip39_method {
        registry = registry.with(m);
    }
    #[cfg(feature = "unlock-tpm")]
    if let Some(m) = &tpm_method {
        registry = registry.with(m);
    }
    if let Some(m) = &passphrase_method {
        registry = registry.with(m);
    }

    let mut creds = crate::seal::open_bundle(&parsed, &registry)
        .context("no unlock slot opened the bundle (fail closed)")?;
    let reviews = crate::seal::apply_authorized_deposits(&parsed, &mut creds);
    for review in reviews {
        if review.status == crate::seal::DepositStatus::Effective {
            info!(
                backend_id = %review.backend_id,
                contributor = %review.contributor_key_id,
                seq = review.seq,
                "sealed-bundle credential deposit applied"
            );
        } else {
            warn!(
                backend_id = %review.backend_id,
                contributor = %review.contributor_key_id,
                seq = review.seq,
                status = review.status.as_str(),
                "sealed-bundle credential deposit ignored"
            );
        }
    }
    crate::seal::verify_epoch_sidecar(&parsed, &epoch_sidecar_path(bundle_path))
        .context("checking sealed-bundle epoch sidecar")?;
    Ok(creds)
}

fn epoch_sidecar_path(bundle_path: &Path) -> PathBuf {
    let mut path = OsString::from(bundle_path.as_os_str());
    path.push(".epoch");
    PathBuf::from(path)
}

#[cfg(feature = "unlock-age-yubikey")]
fn build_age_method(args: &UnlockArgs) -> Result<Option<AgeYubikeyMethod>> {
    if !args.age_yubikey {
        return Ok(None);
    }
    // The recipient is read from the slot params at recover time; here we only
    // need a plugin identity that can decrypt. The recipient string is supplied
    // by the slot, so we pass an empty placeholder and rely on the plugin.
    let method = AgeYubikeyMethod::with_plugin("", DEFAULT_YUBIKEY_PLUGIN)
        .context("initializing age-plugin-yubikey identity")?;
    info!(
        plugin = DEFAULT_YUBIKEY_PLUGIN,
        "age-yubikey unlock enabled"
    );
    Ok(Some(method))
}

#[cfg(feature = "unlock-bip39")]
fn build_bip39_method(args: &UnlockArgs) -> Result<Option<Bip39Method>> {
    let Some(path) = &args.bip39_phrase_file else {
        return Ok(None);
    };
    let phrase = read_secret_file(path)
        .with_context(|| format!("reading bip39 phrase from {}", path.display()))?;
    let phrase = Zeroizing::new(
        String::from_utf8(phrase.to_vec())
            .map_err(|_| anyhow::anyhow!("bip39 phrase file is not valid UTF-8"))?,
    );
    let phrase = Zeroizing::new(phrase.trim().to_string());
    info!("bip39 break-glass unlock enabled");
    Ok(Some(Bip39Method::new(phrase)))
}

/// Build a recover-capable TPM method when `--tpm` is set. The PCR selection a
/// new slot would bind is irrelevant for recovery: it reads the selection
/// recorded in the slot, so a default instance opens any TPM slot. Availability
/// is the runtime `/dev/tpmrm0` probe; there is no operator-supplied secret.
#[cfg(feature = "unlock-tpm")]
fn build_tpm_method(args: &UnlockArgs) -> Option<TpmMethod> {
    if !args.tpm {
        return None;
    }
    info!("tpm sealed-slot unlock enabled");
    Some(TpmMethod::new_default())
}

fn build_passphrase_method(args: &UnlockArgs) -> Result<Option<PassphraseMethod>> {
    let Some(path) = &args.passphrase_file else {
        return Ok(None);
    };
    let passphrase = read_secret_file(path)
        .with_context(|| format!("reading passphrase from {}", path.display()))?;
    if !args.passphrase_no_wipe {
        wipe_secret_file(path).unwrap_or_else(|err| {
            warn!(
                path = %path.display(),
                error = %err,
                "passphrase file wipe failed; continuing after successful read"
            );
        });
    }
    info!("passphrase unlock enabled");
    Ok(Some(PassphraseMethod::new(Zeroizing::new(
        passphrase.to_vec(),
    ))))
}

/// Read a secret file into a zeroizing buffer, trimming a trailing newline.
fn read_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(std::fs::read(path)?);
    // Trim a single trailing newline (common in editor-written files).
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Ok(bytes)
}

fn wipe_secret_file(path: &Path) -> Result<()> {
    use std::io::Write as _;

    let len = std::fs::metadata(path)
        .with_context(|| format!("stat passphrase file {}", path.display()))?
        .len();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("opening passphrase file for wipe {}", path.display()))?;
    let zeros = vec![0u8; 4096];
    let mut remaining = len;
    while remaining > 0 {
        let n = usize::try_from(remaining.min(zeros.len() as u64))
            .context("passphrase file length does not fit usize")?;
        let chunk = zeros
            .get(..n)
            .context("passphrase wipe chunk length out of range")?;
        file.write_all(chunk)
            .with_context(|| format!("overwriting passphrase file {}", path.display()))?;
        remaining -= u64::try_from(n).unwrap_or(0);
    }
    file.sync_all()
        .with_context(|| format!("syncing passphrase file wipe {}", path.display()))?;
    drop(file);
    std::fs::remove_file(path)
        .with_context(|| format!("removing wiped passphrase file {}", path.display()))?;
    Ok(())
}

/// Warn (or, with `strict-bundle-perms`, refuse) if the bundle is not `0600`.
fn check_bundle_perms(path: &Path, strict: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .with_context(|| format!("stat sealed bundle {}", path.display()))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            if strict {
                bail!(
                    "sealed bundle {} has mode {:o}, expected 0600 (strict-bundle-perms)",
                    path.display(),
                    mode
                );
            }
            warn!(
                path = %path.display(),
                mode = format!("{mode:o}"),
                "sealed bundle is not 0600 (continuing; set strict-bundle-perms to refuse)"
            );
        }
    }
    Ok(())
}

/// Exchange an `AppRole` `role_id` + `secret_id` for a short-lived token at the
/// bao `AppRole` login endpoint (§5 step 6). Returns the client token.
///
/// Live verification is covered by `scripts/test-prefill-e2e.sh` when `bao` is
/// available on `PATH`. The request shape matches Vault's
/// `auth/approle/login`.
pub async fn approle_login(
    addr: &str,
    role_id: &str,
    secret_id: &str,
) -> Result<Zeroizing<String>> {
    /// Typed view of the login response body: only the two fields the caller
    /// needs are parsed; everything else is skipped as transient parser state
    /// instead of landing in a `serde_json::Value` copy of the token.
    #[derive(serde::Deserialize)]
    struct LoginResponse {
        auth: Option<LoginAuth>,
    }
    #[derive(serde::Deserialize)]
    struct LoginAuth {
        client_token: Option<String>,
        #[serde(default)]
        lease_duration: u64,
    }

    let addr = addr.trim_end_matches('/');
    let url = format!("{addr}/v1/auth/approle/login");
    crate::ensure_crypto_provider();
    let client = reqwest::Client::builder()
        .build()
        .context("building http client for AppRole login")?;
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id,
        }))
        .send()
        .await
        .context("sending AppRole login request")?;
    let status = resp.status();
    if !status.is_success() {
        // Fail before reading the body; it is never echoed into the error.
        bail!("AppRole login failed (HTTP {status})");
    }
    // The raw body text carries the token: hold it in `Zeroizing` (wiped on
    // drop) and deserialize the typed view above, moving — never copying — the
    // token `String` into the returned `Zeroizing` handle.
    let body = Zeroizing::new(
        resp.text()
            .await
            .context("reading AppRole login response")?,
    );
    let parsed: LoginResponse =
        serde_json::from_str(&body).context("decoding AppRole login response")?;
    let auth = parsed
        .auth
        .context("AppRole login response has no auth.client_token")?;
    let token = auth
        .client_token
        .map(Zeroizing::new)
        .context("AppRole login response has no auth.client_token")?;
    info!(
        lease_seconds = auth.lease_duration,
        "exchanged AppRole secret_id for vault token"
    );
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::UnlockMethod as _;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "basil-unlock-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        ))
    }

    fn write_secret(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("write secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod secret");
        }
    }

    fn args(path: PathBuf, no_wipe: bool) -> UnlockArgs {
        UnlockArgs {
            age_yubikey: false,
            bip39_phrase_file: None,
            tpm: false,
            passphrase_file: Some(path),
            passphrase_no_wipe: no_wipe,
            strict_bundle_perms: false,
        }
    }

    #[test]
    fn passphrase_read_wipes_file_by_default() {
        let path = temp_path("wipe");
        write_secret(&path, b"secret\n");

        let method = build_passphrase_method(&args(path.clone(), false))
            .expect("build passphrase method")
            .expect("method present");

        assert!(method.available());
        assert!(!path.exists());
    }

    #[test]
    fn passphrase_no_wipe_leaves_file() {
        let path = temp_path("no-wipe");
        write_secret(&path, b"secret\n");

        let method = build_passphrase_method(&args(path.clone(), true))
            .expect("build passphrase method")
            .expect("method present");

        assert!(method.available());
        assert!(path.exists());
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn passphrase_wipe_failure_does_not_fail_unlock_method() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("wipe-fails");
        write_secret(&path, b"secret\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
            .expect("make secret read-only");

        let method = build_passphrase_method(&args(path.clone(), false))
            .expect("wipe failure is warning-only")
            .expect("method present");

        assert!(method.available());
        assert!(path.exists());
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        let _ = std::fs::remove_file(path);
    }
}
