// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Offline `basil keystore` maintenance commands.

use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use basil_keystore_backend::rekey::{
    BundleTransitionBinding, EpochPair, KeystoreRekeyError, RecoveryOutcome, RecoveryPhase,
    RekeyLock, RekeyPlan, SensitiveDek, finish_rekey, marker_present, read_intent_marker,
    read_new_dek_file, rekey_to_staging, roll_back, roll_forward, swap_candidate,
    write_intent_marker,
};
use clap::Subcommand;

use crate::bundle_cli::{OpenArg, prepare_db_keystore_rekey, resume_db_keystore_rekey};
use crate::{AuditLog, BackendKind};

/// `keystore` subcommands.
#[derive(Debug, Subcommand)]
pub enum KeystoreCommand {
    /// Rotate one `db-keystore` data-encryption key while the agent is stopped.
    Rekey(RekeyArgs),
}

/// Arguments for coupled database and sealed-bundle DEK rotation.
#[derive(Debug, clap::Args)]
pub struct RekeyArgs {
    /// Agent configuration that selects the database and sealed bundle.
    #[arg(short = 'c', long = "config", env = "BASIL_CONFIG")]
    config: Option<PathBuf>,

    /// Catalog backend ID to rotate or recover.
    #[arg(long)]
    backend: String,

    /// Owner-only file containing the replacement raw 32-byte DEK.
    ///
    /// Required for a fresh rotation and forbidden with `--resume`. Basil does
    /// not delete operator-owned key files.
    #[arg(
        long,
        value_name = "FILE",
        required_unless_present = "resume",
        conflicts_with = "resume"
    )]
    new_dek_file: Option<PathBuf>,

    /// Recover the transaction described by the on-disk intent marker.
    ///
    /// Recovery authenticates the exact pre- or post-rotation bundle and never
    /// reads or accepts a replacement DEK file.
    #[arg(long, conflicts_with = "new_dek_file")]
    resume: bool,

    /// Existing bundle unlock method. Repeat for independent slots.
    #[arg(long = "open", value_name = "METHOD", required = true)]
    open: Vec<OpenArg>,
}

struct DatabaseTarget {
    directory: OwnedFd,
    name: String,
}

impl DatabaseTarget {
    fn open(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .context("db-keystore path must end in a UTF-8 database file name")?
            .to_owned();
        let parent = path
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let directory = rustix::fs::open(
            parent,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| format!("opening db-keystore directory {}", parent.display()))?;
        Ok(Self { directory, name })
    }
}

#[derive(Clone, Copy)]
enum RekeyMode {
    Fresh,
    Resume,
}

impl RekeyMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Resume => "resume",
        }
    }
}

struct RekeyAudit<'a> {
    log: Option<AuditLog>,
    backend_id: &'a str,
    mode: RekeyMode,
}

#[cfg(debug_assertions)]
fn stop_at_test_checkpoint(checkpoint: &str) -> Result<()> {
    const VARIABLE: &str = "BASIL_TEST_KEYSTORE_REKEY_STOP_AFTER";
    if std::env::var(VARIABLE).as_deref() == Ok(checkpoint) {
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::STOP)
            .context("stopping at the requested keystore rekey test checkpoint")?;
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
const fn stop_at_test_checkpoint(_checkpoint: &str) -> Result<()> {
    Ok(())
}

#[cfg(debug_assertions)]
fn inject_enospc_at_test_boundary(variable: &str, boundary: &'static str) -> Result<()> {
    if std::env::var_os(variable).is_some() {
        return Err(std::io::Error::from_raw_os_error(
            rustix::io::Errno::NOSPC.raw_os_error(),
        ))
        .context(boundary);
    }
    Ok(())
}

#[cfg(debug_assertions)]
struct OldDekOwners {
    bundle_owner_live: bool,
    sensitive_owner_live: bool,
}

#[cfg(debug_assertions)]
impl OldDekOwners {
    const fn returned_bundle_owner() -> Self {
        Self {
            bundle_owner_live: true,
            sensitive_owner_live: false,
        }
    }

    fn copied_into_sensitive_owner(&mut self) -> Result<()> {
        ensure!(
            self.bundle_owner_live && !self.sensitive_owner_live,
            "old-DEK ownership instrumentation observed an invalid copy boundary"
        );
        self.sensitive_owner_live = true;
        Ok(())
    }

    fn sensitive_owner_consumed(&mut self) -> Result<()> {
        ensure!(
            self.sensitive_owner_live,
            "old-DEK ownership instrumentation missed the consumed sensitive owner"
        );
        self.sensitive_owner_live = false;
        Ok(())
    }

    fn bundle_owner_dropped(&mut self) -> Result<()> {
        ensure!(
            self.bundle_owner_live,
            "old-DEK ownership instrumentation missed the bundle owner"
        );
        self.bundle_owner_live = false;
        Ok(())
    }

    fn assert_cleared(&self) -> Result<()> {
        ensure!(
            !self.bundle_owner_live && !self.sensitive_owner_live,
            "old-DEK owner survived to the durable bundle commit boundary"
        );
        Ok(())
    }
}

impl RekeyAudit<'_> {
    fn append(
        &self,
        outcome: &str,
        pre_epoch: Option<u64>,
        post_epoch: Option<u64>,
        copied: Option<u64>,
        recovery: Option<&str>,
    ) {
        let Some(log) = &self.log else {
            return;
        };
        let occurred_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        log.append_value(&serde_json::json!({
            "event_kind": "basil.audit.keystore_rekey",
            "event_version": 1,
            "occurred_at_unix": occurred_at_unix,
            "backend_id": self.backend_id,
            "mode": self.mode.as_str(),
            "outcome": outcome,
            "pre_epoch": pre_epoch,
            "post_epoch": post_epoch,
            "copied": copied,
            "recovery": recovery,
        }));
    }
}

fn print_rekey_completion(backend_id: &str, copied: u64, epochs: EpochPair) {
    println!(
        "rekeyed backend `{backend_id}`: verified and copied {copied} records; bundle epoch {} -> {}",
        epochs.pre, epochs.post
    );
    println!(
        "destroy any pre-rekey sealed-bundle backups and operator-held old DEK copies; \
         Basil does not delete the replacement DEK file"
    );
}

/// Run one offline keystore maintenance command.
///
/// # Errors
///
/// Returns a typed, fail-closed error when configuration, bundle
/// authentication, quiescence, staging, commit, or recovery fails. A failed
/// transaction keeps its intent marker whenever explicit recovery is needed.
pub fn run(command: KeystoreCommand) -> Result<()> {
    let KeystoreCommand::Rekey(args) = command;
    run_rekey(&args)
}

fn run_rekey(args: &RekeyArgs) -> Result<()> {
    let config = crate::agent_cli::load_rekey_maintenance_config(args.config.clone())?;
    let backend = config
        .catalog
        .backends
        .get(&args.backend)
        .with_context(|| format!("catalog backend `{}` does not exist", args.backend))?;
    ensure!(
        backend.kind == BackendKind::Keystore,
        "catalog backend `{}` is not a keystore backend",
        args.backend
    );
    let target = DatabaseTarget::open(Path::new(&backend.addr))?;
    let lock = RekeyLock::acquire_exclusive(target.directory.as_fd(), &target.name)?;

    // The database lock is authoritative quiescence and must precede the
    // bundle-writer lock acquired inside the bundle helpers.
    let mode = if args.resume {
        RekeyMode::Resume
    } else {
        RekeyMode::Fresh
    };
    let audit = RekeyAudit {
        log: config
            .audit_path
            .as_deref()
            .map(AuditLog::open)
            .transpose()
            .context("opening configured audit log for keystore rekey")?,
        backend_id: &args.backend,
        mode,
    };
    audit.append("started", None, None, None, None);
    let result = if args.resume {
        resume_rekey(args, &config.bundle_path, &target, &lock, &audit)
    } else {
        fresh_rekey(
            args,
            &config.bundle_path,
            &config.cipher,
            &target,
            &lock,
            &audit,
        )
    };
    if result.is_err() {
        audit.append("failed", None, None, None, None);
    }
    result
}

fn fresh_rekey(
    args: &RekeyArgs,
    bundle_path: &Path,
    cipher: &str,
    target: &DatabaseTarget,
    lock: &RekeyLock,
    audit: &RekeyAudit<'_>,
) -> Result<()> {
    if marker_present(target.directory.as_fd(), &target.name)? {
        return Err(KeystoreRekeyError::RekeyInProgress {
            marker: format!("{}.rekey-intent", target.name),
        }
        .into());
    }
    let new_dek_path = args
        .new_dek_file
        .as_deref()
        .context("a fresh rekey requires --new-dek-file")?;
    let new_dek = read_new_dek_file(new_dek_path)?;
    let (old_bundle_dek, mut bundle) = prepare_db_keystore_rekey(
        bundle_path,
        &args.backend,
        &args.open,
        new_dek.to_secret_array(),
    )?;
    #[cfg(debug_assertions)]
    let mut old_dek_owners = OldDekOwners::returned_bundle_owner();
    let old_dek = SensitiveDek::from_secret(&old_bundle_dek);
    #[cfg(debug_assertions)]
    old_dek_owners.copied_into_sensitive_owner()?;
    let plan = RekeyPlan {
        db_dir: target.directory.as_fd(),
        db_name: &target.name,
        cipher,
    };
    let staged = rekey_to_staging(&plan, old_dek, &new_dek, lock)?;
    #[cfg(debug_assertions)]
    old_dek_owners.sensitive_owner_consumed()?;
    drop(old_bundle_dek);
    #[cfg(debug_assertions)]
    old_dek_owners.bundle_owner_dropped()?;

    let prepared = bundle.binding();
    let epochs = EpochPair {
        pre: prepared.pre_epoch,
        post: prepared.post_epoch,
    };
    let binding = BundleTransitionBinding::new(
        prepared.bundle_id,
        prepared.backend_id.clone(),
        prepared.pre_bundle_b3,
        prepared.post_bundle_b3,
        epochs,
        staged.report().copied,
    )?;
    let marker = staged.intent_marker(binding)?;
    write_intent_marker(target.directory.as_fd(), &target.name, &marker, lock)?;
    audit.append(
        "prepared",
        Some(epochs.pre),
        Some(epochs.post),
        Some(staged.report().copied),
        None,
    );

    // The bundle replacement is the sole commit authority. From this point a
    // surviving marker authorizes only exact post-bundle roll-forward.
    #[cfg(debug_assertions)]
    old_dek_owners.assert_cleared()?;
    stop_at_test_checkpoint("old-dek-owners-cleared")?;
    #[cfg(debug_assertions)]
    inject_enospc_at_test_boundary(
        "BASIL_TEST_KEYSTORE_REKEY_BUNDLE_REPLACE_ENOSPC",
        "writing the replacement sealed bundle",
    )?;
    bundle.commit_bundle()?;
    stop_at_test_checkpoint("bundle-committed")?;
    audit.append(
        "bundle_committed",
        Some(epochs.pre),
        Some(epochs.post),
        Some(staged.report().copied),
        None,
    );
    #[cfg(debug_assertions)]
    inject_enospc_at_test_boundary(
        "BASIL_TEST_KEYSTORE_REKEY_EPOCH_SIDECAR_ENOSPC",
        "writing the sealed-bundle epoch sidecar",
    )?;
    bundle.write_epoch_sidecar()?;
    stop_at_test_checkpoint("epoch-sidecar-durable")?;
    swap_candidate(target.directory.as_fd(), &target.name, &staged, lock)?;
    stop_at_test_checkpoint("db-swap-durable")?;
    finish_rekey(target.directory.as_fd(), &target.name, lock)?;
    audit.append(
        "completed",
        Some(epochs.pre),
        Some(epochs.post),
        Some(staged.report().copied),
        None,
    );
    print_rekey_completion(&args.backend, staged.report().copied, epochs);
    Ok(())
}

fn resume_rekey(
    args: &RekeyArgs,
    bundle_path: &Path,
    target: &DatabaseTarget,
    lock: &RekeyLock,
    audit: &RekeyAudit<'_>,
) -> Result<()> {
    ensure!(
        args.new_dek_file.is_none(),
        "--resume never accepts or reads --new-dek-file"
    );
    let marker = read_intent_marker(target.directory.as_fd(), &target.name)?;
    let bundle = resume_db_keystore_rekey(bundle_path, &args.backend, &args.open)?;
    let identity = bundle.identity();
    let bundle_id = identity.bundle_id;
    let backend_id = identity.backend_id.clone();
    let bundle_b3 = identity.bundle_b3;
    let bundle_epoch = identity.epoch;
    let phase =
        marker.phase_for_authenticated_bundle(bundle_id, &backend_id, bundle_b3, bundle_epoch)?;
    if let Some(seen) = bundle.observed_epoch_sidecar() {
        ensure!(
            seen <= bundle_epoch,
            "sealed-bundle epoch sidecar is ahead of the authenticated bundle"
        );
    }
    #[cfg(debug_assertions)]
    inject_enospc_at_test_boundary(
        "BASIL_TEST_KEYSTORE_REKEY_EPOCH_SIDECAR_ENOSPC",
        "writing the sealed-bundle epoch sidecar",
    )?;
    bundle.write_epoch_sidecar(bundle_epoch)?;

    let recovery = match phase {
        RecoveryPhase::RollBack => {
            roll_back(target.directory.as_fd(), &target.name, &marker, lock)?;
            "rolled_back"
        }
        RecoveryPhase::RollForward => {
            match roll_forward(target.directory.as_fd(), &target.name, &marker, lock)? {
                RecoveryOutcome::ResumedSwap => "resumed_swap",
                RecoveryOutcome::SwapAlreadyComplete => "swap_already_complete",
            }
        }
    };
    let epochs = marker.epochs();
    audit.append(
        "completed",
        Some(epochs.pre),
        Some(epochs.post),
        Some(marker.copied()),
        Some(recovery),
    );
    println!(
        "recovered backend `{}` at authenticated bundle epoch {}: {}",
        args.backend, bundle_epoch, recovery
    );
    Ok(())
}
