// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Local, byte-preserving Nix binary-cache signature maintenance.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use basil::{Client, NixCacheKey, NixCacheSignature};
use basil_core::core::nix_cache_file::{
    LockedCacheRoot, NarinfoCommit, NarinfoEdit, NarinfoMutation, NixCacheFileError,
    ReadOnlyCacheRoot, edit_narinfo,
};
use basil_core::nix_cache_fingerprint::{MAX_PATH_INFO_V1_LEN, MAX_REFERENCES, PathInfoV1};
use clap::{Args, Subcommand};
use ed25519_dalek::{Signature, VerifyingKey};

#[cfg(test)]
use crate::nix_cache_mutation_audit::NoopAudit;
use crate::nix_cache_mutation_audit::{
    AuditSink, BatchAudit, MutationOp, SignatureSource, StderrAudit,
};

const CORRELATION_ID_LEN: usize = 16;
const RANDOM_ID_ATTEMPTS: usize = 8;
const DEFAULT_LOCK_TIMEOUT_SECONDS: u64 = 30;
const MAX_SELECTED_NARINFOS: usize = 65_536;
const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
const STORE_PREFIX: &str = "/nix/store/";

/// Local Nix binary-cache signature maintenance commands.
#[derive(Debug, Subcommand)]
pub enum NixCacheCommand {
    /// Add a verified signature when the selected paths are not already signed.
    Sign(SignArgs),
    /// Remove named old signatures and add the selected verified signature.
    Replace(ReplaceArgs),
    /// Remove signatures with exactly matching key names.
    Remove(RemoveArgs),
}

/// Arguments shared by local cache mutation commands.
#[derive(Clone, Debug, Args)]
pub struct SelectionArgs {
    /// Local Nix binary-cache directory.
    #[arg(long)]
    pub cache: PathBuf,
    /// Canonical `/nix/store` path to select; repeat for multiple paths.
    #[arg(
        long = "path",
        value_name = "STORE_PATH",
        conflicts_with = "all",
        required_unless_present = "all"
    )]
    pub paths: Vec<PathBuf>,
    /// Select every root `.narinfo` record in the cache.
    #[arg(long, conflicts_with = "paths", required_unless_present = "paths")]
    pub all: bool,
    /// Preview planned changes without acquiring or creating the mutation lock.
    #[arg(long)]
    pub dry_run: bool,
    /// Seconds to wait for the cooperative cache-root mutation lock.
    #[arg(long, default_value_t = DEFAULT_LOCK_TIMEOUT_SECONDS)]
    pub lock_timeout: u64,
    /// Confirm a destructive operation over every cache record.
    #[arg(long)]
    pub yes: bool,
}

/// Arguments for additive cache signing.
#[derive(Debug, Args)]
pub struct SignArgs {
    /// Catalog ID of the enrolled backend-custodied Nix cache key.
    #[arg(long = "key")]
    pub key_id: String,
    /// Cache and selection options.
    #[command(flatten)]
    pub selection: SelectionArgs,
}

/// Arguments for cache signature replacement.
#[derive(Debug, Args)]
pub struct ReplaceArgs {
    /// Catalog ID of the enrolled backend-custodied Nix cache key.
    #[arg(long = "key")]
    pub key_id: String,
    /// Exact old Nix verifier key name to remove; repeat for multiple names.
    #[arg(long, required = true)]
    pub old_key_name: Vec<String>,
    /// Cache and selection options.
    #[command(flatten)]
    pub selection: SelectionArgs,
}

/// Arguments for cache signature removal.
#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Exact Nix verifier key name to remove; repeat for multiple names.
    #[arg(long, required = true)]
    pub key_name: Vec<String>,
    /// Cache and selection options.
    #[command(flatten)]
    pub selection: SelectionArgs,
}

trait CacheRpc {
    fn describe_nix_cache_key(
        &mut self,
        key_id: &str,
        batch_id: [u8; CORRELATION_ID_LEN],
        request_id: [u8; CORRELATION_ID_LEN],
    ) -> impl Future<Output = basil::Result<NixCacheKey>>;

    fn sign_nix_cache_fingerprint(
        &mut self,
        key_id: &str,
        fingerprint: &[u8],
        batch_id: [u8; CORRELATION_ID_LEN],
        request_id: [u8; CORRELATION_ID_LEN],
    ) -> impl Future<Output = basil::Result<NixCacheSignature>>;
}

impl CacheRpc for Client {
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

trait IdSource {
    fn fresh(
        &mut self,
        excluded: &BTreeSet<[u8; CORRELATION_ID_LEN]>,
    ) -> Result<[u8; CORRELATION_ID_LEN]>;
}

struct SystemIds;

impl IdSource for SystemIds {
    fn fresh(&mut self, excluded: &BTreeSet<[u8; CORRELATION_ID_LEN]>) -> Result<[u8; 16]> {
        for _ in 0..RANDOM_ID_ATTEMPTS {
            let mut id = [0_u8; CORRELATION_ID_LEN];
            getrandom::fill(&mut id)
                .map_err(|error| anyhow!("generating Nix RPC correlation ID: {error}"))?;
            if id != [0; CORRELATION_ID_LEN] && !excluded.contains(&id) {
                return Ok(id);
            }
        }
        bail!("operating-system randomness did not produce a fresh nonzero Nix RPC correlation ID")
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SelectedNarinfo {
    relative: PathBuf,
    expected_store_path: Option<String>,
    expected_hash: String,
}

#[derive(Clone, Copy)]
enum Operation<'a> {
    Sign,
    Replace { old_key_names: &'a [&'a str] },
    Remove { key_names: &'a [&'a str] },
}

enum ExistingSignature {
    Absent,
    Verified(String),
    Conflict,
}

/// Run one local Nix cache maintenance command.
///
/// # Errors
///
/// Returns an error for invalid selection, unsafe cache files, lock failure,
/// broker rejection, unverified signatures, or filesystem mutation failure.
pub async fn run(socket: &str, command: NixCacheCommand) -> Result<()> {
    validate_local_command(&command)?;
    let mut output = std::io::stdout();
    let mut audit = StderrAudit;
    match command {
        NixCacheCommand::Remove(args) => {
            run_remove_audited(&args, &mut SystemIds, &mut output, &mut audit).await
        }
        NixCacheCommand::Sign(args) => {
            run_connected(socket, SigningCommand::Sign(args), &mut output, &mut audit).await
        }
        NixCacheCommand::Replace(args) => {
            run_connected(
                socket,
                SigningCommand::Replace(args),
                &mut output,
                &mut audit,
            )
            .await
        }
    }
}

fn validate_local_command(command: &NixCacheCommand) -> Result<()> {
    match command {
        NixCacheCommand::Sign(args) => {
            validate_catalog_key_id(&args.key_id)?;
            let _ = select_explicit(&args.selection)?;
        }
        NixCacheCommand::Replace(args) => {
            validate_catalog_key_id(&args.key_id)?;
            let _ = validate_key_names(&args.old_key_name)?;
            require_destructive_confirmation(&args.selection, true)?;
            let _ = select_explicit(&args.selection)?;
        }
        NixCacheCommand::Remove(args) => {
            let _ = validate_key_names(&args.key_name)?;
            require_destructive_confirmation(&args.selection, true)?;
            let _ = select_explicit(&args.selection)?;
        }
    }
    Ok(())
}

fn validate_catalog_key_id(key_id: &str) -> Result<()> {
    let valid_segment = |segment: &str| {
        let mut bytes = segment.bytes();
        bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    };
    if key_id.is_empty() || !key_id.split('.').all(valid_segment) {
        bail!("Nix cache key ID must use dotted-lowercase catalog syntax");
    }
    Ok(())
}

enum SigningCommand {
    Sign(SignArgs),
    Replace(ReplaceArgs),
}

async fn run_connected<W: Write>(
    socket: &str,
    command: SigningCommand,
    output: &mut W,
    audit_sink: &mut impl AuditSink,
) -> Result<()> {
    let mut signals = MutationSignals::register()?;
    let mut ids = SystemIds;
    run_connected_with(
        command,
        &mut ids,
        output,
        audit_sink,
        &mut signals,
        || async { Client::connect(socket).await.map_err(anyhow::Error::from) },
    )
    .await
}

async fn run_connected_with<C, I, W, S, X, F, K>(
    command: SigningCommand,
    ids: &mut I,
    output: &mut W,
    audit_sink: &mut S,
    cancellation: &mut K,
    mut connect: X,
) -> Result<()>
where
    C: CacheRpc,
    I: IdSource,
    W: Write,
    S: AuditSink,
    X: FnMut() -> F,
    F: Future<Output = Result<C>>,
    K: CancellationSource,
{
    let (op, key_id, selection) = signing_metadata(&command);
    let mut used_ids = BTreeSet::new();
    let batch_id = ids.fresh(&used_ids)?;
    used_ids.insert(batch_id);
    let mut audit = BatchAudit::new(
        audit_sink,
        op,
        batch_id,
        selection.dry_run,
        selection.all,
        Some(key_id),
    );
    let connection = tokio::select! {
        biased;
        cancellation = cancellation.wait() => BatchRun::Cancelled(cancellation),
        result = connect() => BatchRun::Finished(result),
    };
    let mut client = match connection {
        BatchRun::Cancelled(cancellation) => {
            record_cancellation(&mut audit, cancellation);
            return cancellation_error(cancellation);
        }
        BatchRun::Finished(Ok(client)) => client,
        BatchRun::Finished(Err(error)) => {
            audit.fail("connect_failed");
            return Err(error).context("connecting to Basil agent");
        }
    };
    let mut correlations = CorrelationBatch {
        ids,
        used_ids: &mut used_ids,
        batch_id,
    };
    match run_signing_batch_cancelable(
        &mut client,
        command,
        &mut correlations,
        output,
        &mut audit,
        cancellation,
    )
    .await
    {
        Ok(()) => {
            audit.complete();
            Ok(())
        }
        Err(error) => {
            if let Some(cancellation) = cancellation_reason(&error) {
                record_cancellation(&mut audit, cancellation);
                return cancellation_error(cancellation);
            }
            audit.fail(failure_reason(&error));
            Err(error)
        }
    }
}

enum BatchRun<T> {
    Cancelled(CancellationReason),
    Finished(T),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CancellationReason {
    Signal(&'static str),
    Task,
}

#[derive(Debug, thiserror::Error)]
#[error("Nix cache mutation cancelled")]
struct BatchCancelled(CancellationReason);

trait CancellationSource {
    fn wait(&mut self) -> impl Future<Output = CancellationReason>;
}

struct MutationSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl MutationSignals {
    fn register() -> Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .context("registering SIGINT handler")?,
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("registering SIGTERM handler")?,
        })
    }
}

impl CancellationSource for MutationSignals {
    async fn wait(&mut self) -> CancellationReason {
        tokio::select! {
            received = self.interrupt.recv() => received.map_or(
                CancellationReason::Task,
                |()| CancellationReason::Signal("SIGINT"),
            ),
            received = self.terminate.recv() => received.map_or(
                CancellationReason::Task,
                |()| CancellationReason::Signal("SIGTERM"),
            ),
        }
    }
}

fn record_cancellation<S: AuditSink>(
    audit: &mut BatchAudit<'_, S>,
    cancellation: CancellationReason,
) {
    match cancellation {
        CancellationReason::Signal(signal) => audit.cancel(signal),
        CancellationReason::Task => audit.cancel_task(),
    }
}

fn cancellation_error<T>(cancellation: CancellationReason) -> Result<T> {
    match cancellation {
        CancellationReason::Signal(signal) => {
            bail!("Nix cache mutation cancelled by {signal}")
        }
        CancellationReason::Task => bail!("Nix cache mutation task cancelled"),
    }
}

fn cancelled_error(cancellation: CancellationReason) -> anyhow::Error {
    anyhow::Error::new(BatchCancelled(cancellation))
}

fn cancellation_reason(error: &anyhow::Error) -> Option<CancellationReason> {
    error
        .downcast_ref::<BatchCancelled>()
        .map(|cancelled| cancelled.0)
}

async fn cancellation_checkpoint<K: CancellationSource>(cancellation: &mut K) -> Result<()> {
    tokio::select! {
        biased;
        reason = cancellation.wait() => Err(cancelled_error(reason)),
        () = tokio::task::yield_now() => Ok(()),
    }
}

#[cfg(test)]
struct NeverCancellation;

#[cfg(test)]
impl CancellationSource for NeverCancellation {
    async fn wait(&mut self) -> CancellationReason {
        std::future::pending().await
    }
}

fn signing_metadata(command: &SigningCommand) -> (MutationOp, &str, &SelectionArgs) {
    match command {
        SigningCommand::Sign(args) => (MutationOp::Sign, &args.key_id, &args.selection),
        SigningCommand::Replace(args) => (MutationOp::Replace, &args.key_id, &args.selection),
    }
}

#[cfg(test)]
async fn run_signing<C: CacheRpc, I: IdSource, W: Write>(
    client: &mut C,
    command: SigningCommand,
    ids: &mut I,
    output: &mut W,
) -> Result<()> {
    let mut audit_sink = NoopAudit;
    let (op, key_id, selection) = signing_metadata(&command);
    let mut used_ids = BTreeSet::new();
    let batch_id = ids.fresh(&used_ids)?;
    used_ids.insert(batch_id);
    let mut audit = BatchAudit::new(
        &mut audit_sink,
        op,
        batch_id,
        selection.dry_run,
        selection.all,
        Some(key_id),
    );
    run_signing_batch(
        client,
        command,
        ids,
        &mut used_ids,
        batch_id,
        output,
        &mut audit,
    )
    .await
}

#[cfg(test)]
async fn run_signing_batch<C: CacheRpc, I: IdSource, W: Write, S: AuditSink>(
    client: &mut C,
    command: SigningCommand,
    ids: &mut I,
    used_ids: &mut BTreeSet<[u8; CORRELATION_ID_LEN]>,
    batch_id: [u8; CORRELATION_ID_LEN],
    output: &mut W,
    audit: &mut BatchAudit<'_, S>,
) -> Result<()> {
    let mut correlations = CorrelationBatch {
        ids,
        used_ids,
        batch_id,
    };
    run_signing_batch_cancelable(
        client,
        command,
        &mut correlations,
        output,
        audit,
        &mut NeverCancellation,
    )
    .await
}

struct CorrelationBatch<'a, I> {
    ids: &'a mut I,
    used_ids: &'a mut BTreeSet<[u8; CORRELATION_ID_LEN]>,
    batch_id: [u8; CORRELATION_ID_LEN],
}

async fn run_signing_batch_cancelable<
    C: CacheRpc,
    I: IdSource,
    W: Write,
    S: AuditSink,
    K: CancellationSource,
>(
    client: &mut C,
    command: SigningCommand,
    correlations: &mut CorrelationBatch<'_, I>,
    output: &mut W,
    audit: &mut BatchAudit<'_, S>,
    cancellation: &mut K,
) -> Result<()> {
    let (key_id, selection, old_names) = match &command {
        SigningCommand::Sign(args) => (args.key_id.as_str(), &args.selection, None),
        SigningCommand::Replace(args) => (
            args.key_id.as_str(),
            &args.selection,
            Some(validate_key_names(&args.old_key_name)?),
        ),
    };
    require_destructive_confirmation(selection, old_names.is_some())?;
    let explicit = select_explicit(selection)?;
    let describe_request_id = correlations.ids.fresh(correlations.used_ids)?;
    correlations.used_ids.insert(describe_request_id);
    let identity = tokio::select! {
        biased;
        reason = cancellation.wait() => return Err(cancelled_error(reason)),
        result = client.describe_nix_cache_key(
            key_id,
            correlations.batch_id,
            describe_request_id,
        ) => result,
    }
    .with_context(|| format!("describing Nix cache key {key_id}"))?;
    audit.set_identity(&identity.key_name, identity.backend_version);

    if selection.dry_run {
        let (root, selected) = open_preview(selection, explicit)?;
        let operation = old_names
            .as_ref()
            .map_or(Operation::Sign, |names| Operation::Replace {
                old_key_names: names,
            });
        audit.set_selected(selected.len());
        preview_batch_counted_async(
            &root,
            &selected,
            Some(&identity),
            operation,
            output,
            audit,
            cancellation,
        )
        .await?;
        return Ok(());
    }

    let root = acquire_cache_root(
        &selection.cache,
        Duration::from_secs(selection.lock_timeout),
        cancellation,
    )
    .await
    .with_context(|| format!("locking cache root {}", selection.cache.display()))?;
    let selected = select_locked(selection, explicit, &root)?;
    audit.set_selected(selected.len());
    let mut batch = SigningBatch {
        client,
        ids: correlations.ids,
        used_ids: correlations.used_ids,
        key_id,
        batch_id: correlations.batch_id,
        identity: &identity,
        cancellation,
    };
    for target in selected {
        cancellation_checkpoint(batch.cancellation).await?;
        let outcome =
            mutate_signing_target(&root, &target, old_names.as_deref(), &mut batch, audit).await?;
        audit_signing_outcome(audit, &outcome);
        render_commit(&target.relative, outcome.commit, output)?;
    }
    cancellation_checkpoint(batch.cancellation).await?;
    Ok(())
}

struct SigningTargetOutcome {
    commit: NarinfoCommit,
    store_path: String,
    fingerprint: PathInfoV1,
    request_id: Option<[u8; CORRELATION_ID_LEN]>,
    signature_source: SignatureSource,
}

fn audit_signing_outcome<S: AuditSink>(
    audit: &mut BatchAudit<'_, S>,
    outcome: &SigningTargetOutcome,
) {
    match &outcome.commit {
        NarinfoCommit::Unchanged => audit.unchanged(),
        NarinfoCommit::Written => audit.durable_commit(
            outcome.store_path.as_bytes(),
            Some(outcome.fingerprint.as_bytes()),
            outcome.request_id,
            outcome.signature_source,
            "installed",
        ),
        NarinfoCommit::CommittedDurabilityUncertain { .. } => {}
    }
}

struct SigningBatch<'a, C, I, K> {
    client: &'a mut C,
    ids: &'a mut I,
    used_ids: &'a mut BTreeSet<[u8; CORRELATION_ID_LEN]>,
    key_id: &'a str,
    batch_id: [u8; CORRELATION_ID_LEN],
    identity: &'a NixCacheKey,
    cancellation: &'a mut K,
}

async fn mutate_signing_target<C: CacheRpc, I: IdSource, S: AuditSink, K: CancellationSource>(
    root: &LockedCacheRoot,
    target: &SelectedNarinfo,
    old_names: Option<&[&str]>,
    batch: &mut SigningBatch<'_, C, I, K>,
    audit: &mut BatchAudit<'_, S>,
) -> Result<SigningTargetOutcome> {
    let snapshot = root
        .read_narinfo(&target.relative)
        .with_context(|| format!("reading {}", target.relative.display()))?;
    validate_narinfo_for_mutation(snapshot.bytes())
        .with_context(|| format!("validating {}", target.relative.display()))?;
    let fingerprint = fingerprint_from_narinfo(
        snapshot.bytes(),
        target.expected_store_path.as_deref(),
        &target.expected_hash,
    )
    .with_context(|| format!("constructing fingerprint for {}", target.relative.display()))?;
    let existing =
        inspect_existing_signature(snapshot.bytes(), batch.identity, fingerprint.as_bytes());

    let store_path = std::str::from_utf8(exactly_one_field(
        snapshot.bytes(),
        b"StorePath: ",
        "StorePath",
    )?)
    .context("StorePath is not UTF-8")?
    .to_string();
    let (signature, signature_source, request_id) = match (old_names, existing) {
        (None, ExistingSignature::Verified(_)) => {
            audit.signature_observed(SignatureSource::Reused);
            return Ok(SigningTargetOutcome {
                commit: NarinfoCommit::Unchanged,
                store_path,
                fingerprint,
                request_id: None,
                signature_source: SignatureSource::Reused,
            });
        }
        (None, ExistingSignature::Conflict) => return signature_conflict(&target.relative),
        (Some(names), ExistingSignature::Conflict)
            if !names.iter().any(|name| *name == batch.identity.key_name) =>
        {
            return signature_conflict(&target.relative);
        }
        (_, ExistingSignature::Verified(value)) => (value, SignatureSource::Reused, None),
        (_, ExistingSignature::Absent | ExistingSignature::Conflict) => {
            let (signature, request_id) = sign_and_verify(batch, &fingerprint).await?;
            (signature, SignatureSource::Produced, Some(request_id))
        }
    };
    audit.signature_observed(signature_source);
    let mutation = old_names.map_or(
        NarinfoMutation::Add {
            signature: &signature,
        },
        |names| NarinfoMutation::Replace {
            old_key_names: names,
            signature: &signature,
        },
    );
    let edit = edit_narinfo(snapshot.bytes(), mutation)
        .with_context(|| format!("editing {}", target.relative.display()))?;
    let commit = commit_edit(root, &target.relative, &snapshot, edit)?;
    Ok(SigningTargetOutcome {
        commit,
        store_path,
        fingerprint,
        request_id,
        signature_source,
    })
}

#[cfg(test)]
fn run_remove<W: Write>(args: &RemoveArgs, output: &mut W) -> Result<()> {
    require_destructive_confirmation(&args.selection, true)?;
    let names = validate_key_names(&args.key_name)?;
    let explicit = select_explicit(&args.selection)?;
    if args.selection.dry_run {
        let (root, selected) = open_preview(&args.selection, explicit)?;
        return preview_batch(
            &root,
            &selected,
            None,
            Operation::Remove { key_names: &names },
            output,
        );
    }
    let root = LockedCacheRoot::acquire(
        &args.selection.cache,
        Duration::from_secs(args.selection.lock_timeout),
    )
    .with_context(|| format!("locking cache root {}", args.selection.cache.display()))?;
    let selected = select_locked(&args.selection, explicit, &root)?;
    for target in selected {
        let commit = root
            .mutate_narinfo(
                &target.relative,
                NarinfoMutation::Remove { key_names: &names },
            )
            .with_context(|| format!("removing signatures from {}", target.relative.display()))?;
        render_commit(&target.relative, commit, output)?;
    }
    Ok(())
}

async fn run_remove_audited<W: Write, I: IdSource, S: AuditSink>(
    args: &RemoveArgs,
    ids: &mut I,
    output: &mut W,
    audit_sink: &mut S,
) -> Result<()> {
    let mut signals = MutationSignals::register()?;
    run_remove_audited_with(args, ids, output, audit_sink, &mut signals).await
}

async fn run_remove_audited_with<W, I, S, K>(
    args: &RemoveArgs,
    ids: &mut I,
    output: &mut W,
    audit_sink: &mut S,
    cancellation: &mut K,
) -> Result<()>
where
    W: Write,
    I: IdSource,
    S: AuditSink,
    K: CancellationSource,
{
    require_destructive_confirmation(&args.selection, true)?;
    let names = validate_key_names(&args.key_name)?;
    let explicit = select_explicit(&args.selection)?;
    let batch_id = ids.fresh(&BTreeSet::new())?;
    let mut audit = BatchAudit::new(
        audit_sink,
        MutationOp::Remove,
        batch_id,
        args.selection.dry_run,
        args.selection.all,
        None,
    );
    match run_remove_batch_cancelable(args, &names, explicit, output, &mut audit, cancellation)
        .await
    {
        Ok(()) => {
            audit.complete();
            Ok(())
        }
        Err(error) => {
            if let Some(cancellation) = cancellation_reason(&error) {
                record_cancellation(&mut audit, cancellation);
                return cancellation_error(cancellation);
            }
            audit.fail(failure_reason(&error));
            Err(error)
        }
    }
}

#[cfg(test)]
async fn run_remove_batch<W: Write, S: AuditSink>(
    args: &RemoveArgs,
    names: &[&str],
    explicit: Option<Vec<SelectedNarinfo>>,
    output: &mut W,
    audit: &mut BatchAudit<'_, S>,
) -> Result<()> {
    run_remove_batch_cancelable(args, names, explicit, output, audit, &mut NeverCancellation).await
}

async fn run_remove_batch_cancelable<W: Write, S: AuditSink, K: CancellationSource>(
    args: &RemoveArgs,
    names: &[&str],
    explicit: Option<Vec<SelectedNarinfo>>,
    output: &mut W,
    audit: &mut BatchAudit<'_, S>,
    cancellation: &mut K,
) -> Result<()> {
    cancellation_checkpoint(cancellation).await?;
    if args.selection.dry_run {
        let (root, selected) = open_preview(&args.selection, explicit)?;
        audit.set_selected(selected.len());
        preview_batch_counted_async(
            &root,
            &selected,
            None,
            Operation::Remove { key_names: names },
            output,
            audit,
            cancellation,
        )
        .await?;
        return Ok(());
    }
    let root = acquire_cache_root(
        &args.selection.cache,
        Duration::from_secs(args.selection.lock_timeout),
        cancellation,
    )
    .await
    .with_context(|| format!("locking cache root {}", args.selection.cache.display()))?;
    let selected = select_locked(&args.selection, explicit, &root)?;
    audit.set_selected(selected.len());
    for target in selected {
        cancellation_checkpoint(cancellation).await?;
        let snapshot = root
            .read_narinfo(&target.relative)
            .with_context(|| format!("reading {}", target.relative.display()))?;
        validate_narinfo_for_mutation(snapshot.bytes())
            .with_context(|| format!("validating {}", target.relative.display()))?;
        let store_path = selected_store_path(snapshot.bytes(), &target)?;
        let edit = edit_narinfo(
            snapshot.bytes(),
            NarinfoMutation::Remove { key_names: names },
        )?;
        let commit = commit_edit(&root, &target.relative, &snapshot, edit)
            .with_context(|| format!("removing signatures from {}", target.relative.display()))?;
        match &commit {
            NarinfoCommit::Unchanged => audit.unchanged(),
            NarinfoCommit::Written => audit.durable_commit(
                store_path,
                None,
                None,
                SignatureSource::NotApplicable,
                "removed",
            ),
            NarinfoCommit::CommittedDurabilityUncertain { .. } => {}
        }
        render_commit(&target.relative, commit, output)?;
    }
    cancellation_checkpoint(cancellation).await?;
    Ok(())
}

async fn acquire_cache_root<K: CancellationSource>(
    cache_root: &Path,
    timeout: Duration,
    cancellation: &mut K,
) -> Result<LockedCacheRoot> {
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or(NixCacheFileError::InvalidPath)?;
    loop {
        cancellation_checkpoint(cancellation).await?;
        match LockedCacheRoot::try_acquire(cache_root) {
            Ok(root) => return Ok(root),
            Err(NixCacheFileError::LockBusy) => {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(NixCacheFileError::LockTimeout.into());
                }
                let wait = deadline
                    .saturating_duration_since(now)
                    .min(Duration::from_millis(10));
                tokio::select! {
                    biased;
                    reason = cancellation.wait() => return Err(cancelled_error(reason)),
                    () = tokio::time::sleep(wait) => {}
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn selected_store_path<'a>(narinfo: &'a [u8], target: &SelectedNarinfo) -> Result<&'a [u8]> {
    let store_path = exactly_one_field(narinfo, b"StorePath: ", "StorePath")?;
    let text = std::str::from_utf8(store_path).context("StorePath is not UTF-8")?;
    if target
        .expected_store_path
        .as_deref()
        .is_some_and(|expected| expected != text)
    {
        bail!("StorePath does not match the selected cache record");
    }
    if validate_store_path(text)? != target.expected_hash {
        bail!("StorePath hash does not match the selected narinfo filename");
    }
    Ok(store_path)
}

async fn sign_and_verify<C: CacheRpc, I: IdSource, K: CancellationSource>(
    batch: &mut SigningBatch<'_, C, I, K>,
    fingerprint: &PathInfoV1,
) -> Result<(String, [u8; CORRELATION_ID_LEN])> {
    let request_id = batch.ids.fresh(batch.used_ids)?;
    batch.used_ids.insert(request_id);
    let response = tokio::select! {
        biased;
        reason = batch.cancellation.wait() => return Err(cancelled_error(reason)),
        result = batch.client.sign_nix_cache_fingerprint(
            batch.key_id,
            fingerprint.as_bytes(),
            batch.batch_id,
            request_id,
        ) => result,
    }
    .with_context(|| format!("signing Nix path-info fingerprint with {}", batch.key_id))?;
    if response.key != *batch.identity {
        bail!("Basil returned a different Nix cache key identity while signing");
    }
    verify_raw_signature(batch.identity, fingerprint.as_bytes(), &response.signature)
        .context("Basil returned an invalid Nix cache signature")?;
    Ok((
        format!(
            "{}:{}",
            batch.identity.key_name,
            base64::engine::general_purpose::STANDARD.encode(response.signature)
        ),
        request_id,
    ))
}

#[cfg(test)]
fn preview_batch<W: Write>(
    root: &ReadOnlyCacheRoot,
    selected: &[SelectedNarinfo],
    identity: Option<&NixCacheKey>,
    operation: Operation<'_>,
    output: &mut W,
) -> Result<()> {
    let _ = preview_batch_counted(root, selected, identity, operation, output)?;
    Ok(())
}

#[cfg(test)]
fn preview_batch_counted<W: Write>(
    root: &ReadOnlyCacheRoot,
    selected: &[SelectedNarinfo],
    identity: Option<&NixCacheKey>,
    operation: Operation<'_>,
    output: &mut W,
) -> Result<(usize, usize)> {
    let mut changed = 0_usize;
    let mut unchanged = 0_usize;
    for target in selected {
        let edit = preview_target(root, target, identity, operation)?;
        let disposition = if matches!(edit, NarinfoEdit::Unchanged) {
            unchanged = unchanged.saturating_add(1);
            "unchanged"
        } else {
            changed = changed.saturating_add(1);
            "would change"
        };
        writeln!(output, "{}: {disposition}", target.relative.display())?;
    }
    Ok((changed, unchanged))
}

async fn preview_batch_counted_async<W: Write, S: AuditSink, K: CancellationSource>(
    root: &ReadOnlyCacheRoot,
    selected: &[SelectedNarinfo],
    identity: Option<&NixCacheKey>,
    operation: Operation<'_>,
    output: &mut W,
    audit: &mut BatchAudit<'_, S>,
    cancellation: &mut K,
) -> Result<()> {
    for target in selected {
        cancellation_checkpoint(cancellation).await?;
        let edit = preview_target(root, target, identity, operation)?;
        let disposition = if matches!(edit, NarinfoEdit::Unchanged) {
            audit.unchanged();
            "unchanged"
        } else {
            audit.preview_change();
            "would change"
        };
        writeln!(output, "{}: {disposition}", target.relative.display())?;
    }
    cancellation_checkpoint(cancellation).await?;
    Ok(())
}

fn preview_target(
    root: &ReadOnlyCacheRoot,
    target: &SelectedNarinfo,
    identity: Option<&NixCacheKey>,
    operation: Operation<'_>,
) -> Result<NarinfoEdit> {
    let snapshot = root
        .read_narinfo(&target.relative)
        .with_context(|| format!("reading {}", target.relative.display()))?;
    let bytes = snapshot.bytes();
    validate_narinfo_for_mutation(bytes)
        .with_context(|| format!("validating {}", target.relative.display()))?;
    match operation {
        Operation::Remove { key_names } => {
            Ok(edit_narinfo(bytes, NarinfoMutation::Remove { key_names })?)
        }
        Operation::Sign => {
            let identity = identity.context("missing signing identity")?;
            let fingerprint = fingerprint_from_narinfo(
                bytes,
                target.expected_store_path.as_deref(),
                &target.expected_hash,
            )?;
            match inspect_existing_signature(bytes, identity, fingerprint.as_bytes()) {
                ExistingSignature::Verified(_) => Ok(NarinfoEdit::Unchanged),
                ExistingSignature::Conflict => signature_conflict(&target.relative),
                ExistingSignature::Absent => Ok(NarinfoEdit::Changed(Vec::new())),
            }
        }
        Operation::Replace { old_key_names } => {
            let identity = identity.context("missing signing identity")?;
            let fingerprint = fingerprint_from_narinfo(
                bytes,
                target.expected_store_path.as_deref(),
                &target.expected_hash,
            )?;
            let new_name_is_removed = old_key_names.iter().any(|name| *name == identity.key_name);
            match inspect_existing_signature(bytes, identity, fingerprint.as_bytes()) {
                ExistingSignature::Verified(signature) => Ok(edit_narinfo(
                    bytes,
                    NarinfoMutation::Replace {
                        old_key_names,
                        signature: &signature,
                    },
                )?),
                ExistingSignature::Conflict if !new_name_is_removed => {
                    signature_conflict(&target.relative)
                }
                ExistingSignature::Absent | ExistingSignature::Conflict => {
                    Ok(NarinfoEdit::Changed(Vec::new()))
                }
            }
        }
    }
}

fn commit_edit(
    root: &LockedCacheRoot,
    relative: &Path,
    snapshot: &basil_core::core::nix_cache_file::NarinfoSnapshot,
    edit: NarinfoEdit,
) -> Result<NarinfoCommit> {
    let commit = match edit {
        NarinfoEdit::Unchanged => NarinfoCommit::Unchanged,
        NarinfoEdit::Changed(bytes) => root
            .commit_narinfo(relative, snapshot, &bytes)
            .with_context(|| format!("committing {}", relative.display()))?,
    };
    Ok(commit)
}

fn render_commit<W: Write>(relative: &Path, commit: NarinfoCommit, output: &mut W) -> Result<()> {
    match commit {
        NarinfoCommit::Unchanged => {
            writeln!(output, "{}: unchanged", relative.display()).map_err(OutputFailure)?;
        }
        NarinfoCommit::Written => {
            writeln!(output, "{}: written", relative.display()).map_err(OutputFailure)?;
        }
        NarinfoCommit::CommittedDurabilityUncertain { error } => {
            bail!(
                "{}: committed, but directory durability is uncertain: {error}",
                relative.display()
            );
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("writing Nix cache mutation output failed: {0}")]
struct OutputFailure(std::io::Error);

fn failure_reason(error: &anyhow::Error) -> &'static str {
    if error.downcast_ref::<OutputFailure>().is_some() {
        "output_failed"
    } else {
        "operation_failed"
    }
}

fn inspect_existing_signature(
    narinfo: &[u8],
    identity: &NixCacheKey,
    fingerprint: &[u8],
) -> ExistingSignature {
    let prefix = format!("Sig: {}:", identity.key_name);
    let mut verified = None;
    let mut conflict = false;
    for line in narinfo.split(|byte| *byte == b'\n') {
        let Some(encoded) = line.strip_prefix(prefix.as_bytes()) else {
            continue;
        };
        let decoded = base64::engine::general_purpose::STANDARD.decode(encoded);
        let valid = decoded
            .ok()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .filter(|signature| {
                verify_raw_signature(identity, fingerprint, signature).is_ok()
                    && base64::engine::general_purpose::STANDARD
                        .encode(signature)
                        .as_bytes()
                        == encoded
            });
        if let Some(signature) = valid {
            let value = format!(
                "{}:{}",
                identity.key_name,
                base64::engine::general_purpose::STANDARD.encode(signature)
            );
            if verified.as_ref().is_some_and(|current| current != &value) {
                conflict = true;
            } else {
                verified = Some(value);
            }
        } else {
            conflict = true;
        }
    }
    match (verified, conflict) {
        (Some(value), false) => ExistingSignature::Verified(value),
        (Some(_) | None, true) => ExistingSignature::Conflict,
        (None, false) => ExistingSignature::Absent,
    }
}

fn validate_narinfo_for_mutation(narinfo: &[u8]) -> Result<()> {
    let no_names: [&str; 0] = [];
    let edit = edit_narinfo(
        narinfo,
        NarinfoMutation::Remove {
            key_names: &no_names,
        },
    )?;
    if !matches!(edit, NarinfoEdit::Unchanged) {
        bail!("no-op narinfo validation unexpectedly changed the record");
    }
    Ok(())
}

fn verify_raw_signature(
    identity: &NixCacheKey,
    fingerprint: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(&identity.public_key)
        .context("enrolled Nix cache public key is invalid")?;
    key.verify_strict(fingerprint, &Signature::from_bytes(signature))
        .context("Ed25519 signature verification failed")
}

fn fingerprint_from_narinfo(
    narinfo: &[u8],
    expected_store_path: Option<&str>,
    expected_hash: &str,
) -> Result<PathInfoV1> {
    let store_path = exactly_one_field(narinfo, b"StorePath: ", "StorePath")?;
    let nar_hash = exactly_one_field(narinfo, b"NarHash: ", "NarHash")?;
    let nar_size = exactly_one_field(narinfo, b"NarSize: ", "NarSize")?;
    let references = exactly_one_field(narinfo, b"References: ", "References")?;
    let store_path = std::str::from_utf8(store_path).context("StorePath is not UTF-8")?;
    if expected_store_path.is_some_and(|expected| expected != store_path) {
        bail!("StorePath does not match the selected cache record");
    }
    if validate_store_path(store_path)? != expected_hash {
        bail!("StorePath hash does not match the selected narinfo filename");
    }
    let nar_hash = std::str::from_utf8(nar_hash).context("NarHash is not UTF-8")?;
    let nar_size = std::str::from_utf8(nar_size).context("NarSize is not UTF-8")?;
    let references = std::str::from_utf8(references).context("References is not UTF-8")?;
    let references = collect_references(references, |_| {})?;
    if references
        .windows(2)
        .any(|pair| pair.first() == pair.get(1))
    {
        bail!("References contains a duplicate store path");
    }
    let references_len =
        references
            .iter()
            .enumerate()
            .try_fold(0_usize, |length, (index, reference)| {
                length
                    .checked_add(usize::from(index != 0))
                    .and_then(|value| value.checked_add(STORE_PREFIX.len()))
                    .and_then(|value| value.checked_add(reference.len()))
            });
    let rendered_len = references_len
        .and_then(|length| length.checked_add(5))
        .and_then(|length| length.checked_add(store_path.len()))
        .and_then(|length| length.checked_add(nar_hash.len()))
        .and_then(|length| length.checked_add(nar_size.len()))
        .context("PATH_INFO_V1 fingerprint length overflow")?;
    if rendered_len > MAX_PATH_INFO_V1_LEN {
        bail!("PATH_INFO_V1 fingerprint exceeds {MAX_PATH_INFO_V1_LEN} bytes");
    }
    let mut rendered = String::with_capacity(rendered_len);
    write!(rendered, "1;{store_path};{nar_hash};{nar_size};")?;
    for (index, reference) in references.iter().enumerate() {
        if index != 0 {
            rendered.push(',');
        }
        rendered.push_str(STORE_PREFIX);
        rendered.push_str(reference);
    }
    PathInfoV1::parse(rendered.as_bytes())
        .context("narinfo fields do not form canonical PATH_INFO_V1")
}

fn collect_references(references: &str, mut retained: impl FnMut(usize)) -> Result<Vec<&str>> {
    if references.is_empty() {
        return Ok(Vec::new());
    }
    let mut collected = Vec::new();
    for reference in references.split(' ') {
        if collected.len() >= MAX_REFERENCES {
            bail!("References exceeds the {MAX_REFERENCES}-path limit");
        }
        let _ = validate_store_base_name(reference)?;
        collected.push(reference);
        retained(collected.len());
    }
    collected.sort_unstable();
    Ok(collected)
}

fn exactly_one_field<'a>(narinfo: &'a [u8], prefix: &[u8], name: &'static str) -> Result<&'a [u8]> {
    let mut found = None;
    for line in narinfo.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(prefix)
            && found.replace(value).is_some()
        {
            bail!("narinfo contains more than one {name} field");
        }
    }
    found.with_context(|| format!("narinfo is missing the {name} field"))
}

fn validate_key_names(names: &[String]) -> Result<Vec<&str>> {
    let mut unique = BTreeSet::new();
    for name in names {
        if name.is_empty() || !name.is_ascii() || name.contains([':', '\n', '\r']) {
            bail!("invalid Nix cache key name");
        }
        unique.insert(name.as_str());
    }
    Ok(unique.into_iter().collect())
}

fn require_destructive_confirmation(selection: &SelectionArgs, destructive: bool) -> Result<()> {
    if destructive && selection.all && !selection.dry_run && !selection.yes {
        bail!("destructive `--all` requires `--yes`");
    }
    Ok(())
}

fn select_explicit(selection: &SelectionArgs) -> Result<Option<Vec<SelectedNarinfo>>> {
    reject_non_file_cache(&selection.cache)?;
    if selection.all {
        return Ok(None);
    }
    let mut selected = BTreeSet::new();
    for path in &selection.paths {
        let store_path = path.to_str().context("store path is not valid UTF-8")?;
        let hash = validate_store_path(store_path)?;
        selected.insert(SelectedNarinfo {
            relative: PathBuf::from(format!("{hash}.narinfo")),
            expected_store_path: Some(store_path.to_string()),
            expected_hash: hash.to_string(),
        });
        if selected.len() > MAX_SELECTED_NARINFOS {
            bail!("selection exceeds {MAX_SELECTED_NARINFOS} narinfo records");
        }
    }
    if selected.is_empty() {
        bail!("selection contains no narinfo records");
    }
    Ok(Some(selected.into_iter().collect()))
}

fn open_preview(
    selection: &SelectionArgs,
    explicit: Option<Vec<SelectedNarinfo>>,
) -> Result<(ReadOnlyCacheRoot, Vec<SelectedNarinfo>)> {
    let root = ReadOnlyCacheRoot::open(&selection.cache).with_context(|| {
        format!(
            "opening cache root {} for selection",
            selection.cache.display()
        )
    })?;
    let selected = if let Some(selected) = explicit {
        selected
    } else {
        selected_from_names(root.root_narinfo_names(MAX_SELECTED_NARINFOS)?)?
    };
    Ok((root, selected))
}

fn select_locked(
    _selection: &SelectionArgs,
    explicit: Option<Vec<SelectedNarinfo>>,
    root: &LockedCacheRoot,
) -> Result<Vec<SelectedNarinfo>> {
    if let Some(selected) = explicit {
        return Ok(selected);
    }
    selected_from_names(root.root_narinfo_names(MAX_SELECTED_NARINFOS)?)
}

fn selected_from_names(names: Vec<std::ffi::OsString>) -> Result<Vec<SelectedNarinfo>> {
    let mut selected = BTreeSet::new();
    for name in names {
        let Some(name) = name.to_str() else {
            bail!("root narinfo filename is not valid UTF-8");
        };
        let Some(hash) = name.strip_suffix(".narinfo") else {
            continue;
        };
        if hash.len() != 32 || !hash.chars().all(|character| NIX32.contains(character)) {
            bail!("invalid root narinfo filename {name}");
        }
        selected.insert(SelectedNarinfo {
            relative: PathBuf::from(name),
            expected_store_path: None,
            expected_hash: hash.to_string(),
        });
    }
    if selected.is_empty() {
        bail!("selection contains no narinfo records");
    }
    Ok(selected.into_iter().collect())
}

fn validate_store_path(store_path: &str) -> Result<&str> {
    let base = store_path
        .strip_prefix(STORE_PREFIX)
        .context("store path must be under /nix/store")?;
    validate_store_base_name(base)
}

fn validate_store_base_name(base: &str) -> Result<&str> {
    let (hash, name) = base
        .split_once('-')
        .context("store path is missing its name separator")?;
    if hash.len() != 32
        || !hash.chars().all(|character| NIX32.contains(character))
        || name.is_empty()
        || name.len() > 211
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
        })
    {
        bail!("store path is not canonical");
    }
    Ok(hash)
}

fn reject_non_file_cache(cache: &Path) -> Result<()> {
    let value = cache.as_os_str().as_encoded_bytes();
    if value.windows(3).any(|window| window == b"://") {
        bail!("only local file cache directories are supported; pass `--cache DIR`");
    }
    Ok(())
}

fn signature_conflict<T>(relative: &Path) -> Result<T> {
    bail!(
        "{}: SIGNATURE_CONFLICT: use `basil nix cache replace` for the existing Nix cache key name",
        relative.display()
    )
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::sync::atomic::{AtomicU64, Ordering};

    use clap::Parser as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use tokio::sync::watch;

    use super::*;
    use crate::{Cli, Command};
    use serde_json::Value;

    const HASH: &str = "n5wkd9frr45pa74if5gpz9j7mifg27fh";
    const STORE_PATH: &str = "/nix/store/n5wkd9frr45pa74if5gpz9j7mifg27fh-foo";
    const NAR_HASH: &str = "sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm";
    const KEY_NAME: &str = "cache-current";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "basil-nix-cache-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }

        fn write(&self, hash: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(format!("{hash}.narinfo"));
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn narinfo(signatures: &[String]) -> Vec<u8> {
        let mut text =
            format!("StorePath: {STORE_PATH}\nNarHash: {NAR_HASH}\nNarSize: 34878\nReferences: \n");
        for signature in signatures {
            text.push_str("Sig: ");
            text.push_str(signature);
            text.push('\n');
        }
        text.into_bytes()
    }

    fn narinfo_for(store_path: &str) -> Vec<u8> {
        format!("StorePath: {store_path}\nNarHash: {NAR_HASH}\nNarSize: 34878\nReferences: \n")
            .into_bytes()
    }

    fn narinfo_for_with_signatures(store_path: &str, signatures: &[String]) -> Vec<u8> {
        let mut bytes = narinfo_for(store_path);
        for signature in signatures {
            bytes.extend_from_slice(b"Sig: ");
            bytes.extend_from_slice(signature.as_bytes());
            bytes.push(b'\n');
        }
        bytes
    }

    fn narinfo_with_references(store_path: &str, references: &str) -> Vec<u8> {
        format!(
            "StorePath: {store_path}\nNarHash: {NAR_HASH}\nNarSize: 34878\nReferences: {references}\n"
        )
        .into_bytes()
    }

    fn reference_list(count: usize) -> String {
        (0..count)
            .map(|index| format!("{index:032}-reference"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn selection(cache: &Path, dry_run: bool) -> SelectionArgs {
        SelectionArgs {
            cache: cache.to_path_buf(),
            paths: vec![PathBuf::from(STORE_PATH)],
            all: false,
            dry_run,
            lock_timeout: 0,
            yes: false,
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        Describe([u8; 16], [u8; 16]),
        Sign(Vec<u8>, [u8; 16], [u8; 16]),
    }

    struct FakeRpc {
        key_id: String,
        identity: NixCacheKey,
        signing_key: SigningKey,
        calls: Vec<Call>,
        wrong_identity: bool,
        bad_signature: bool,
    }

    impl FakeRpc {
        fn new() -> Self {
            let signing_key = SigningKey::from_bytes(&[7; 32]);
            Self {
                key_id: "catalog-cache".to_string(),
                identity: NixCacheKey {
                    key_name: KEY_NAME.to_string(),
                    public_key: signing_key.verifying_key().to_bytes(),
                    backend_version: 1,
                },
                signing_key,
                calls: Vec::new(),
                wrong_identity: false,
                bad_signature: false,
            }
        }
    }

    impl CacheRpc for FakeRpc {
        async fn describe_nix_cache_key(
            &mut self,
            key_id: &str,
            batch_id: [u8; 16],
            request_id: [u8; 16],
        ) -> basil::Result<NixCacheKey> {
            assert_eq!(key_id, self.key_id);
            self.calls.push(Call::Describe(batch_id, request_id));
            Ok(self.identity.clone())
        }

        async fn sign_nix_cache_fingerprint(
            &mut self,
            key_id: &str,
            fingerprint: &[u8],
            batch_id: [u8; 16],
            request_id: [u8; 16],
        ) -> basil::Result<NixCacheSignature> {
            assert_eq!(key_id, self.key_id);
            self.calls
                .push(Call::Sign(fingerprint.to_vec(), batch_id, request_id));
            let mut signature = self.signing_key.sign(fingerprint).to_bytes();
            if self.bad_signature {
                signature[0] ^= 0x80;
            }
            let mut key = self.identity.clone();
            if self.wrong_identity {
                key.key_name.push_str("-wrong");
            }
            Ok(NixCacheSignature { key, signature })
        }
    }

    struct FixedIds(VecDeque<[u8; 16]>);

    #[derive(Default)]
    struct CapturedAudit(Vec<Value>);

    impl AuditSink for CapturedAudit {
        fn emit(&mut self, value: &Value) {
            self.0.push(value.clone());
        }
    }

    struct TestCancellation {
        receiver: watch::Receiver<Option<CancellationReason>>,
    }

    impl CancellationSource for TestCancellation {
        async fn wait(&mut self) -> CancellationReason {
            loop {
                let pending = *self.receiver.borrow_and_update();
                if let Some(reason) = pending {
                    return reason;
                }
                if self.receiver.changed().await.is_err() {
                    return CancellationReason::Task;
                }
            }
        }
    }

    fn cancellation_channel(
        initial: Option<CancellationReason>,
    ) -> (watch::Sender<Option<CancellationReason>>, TestCancellation) {
        let (sender, receiver) = watch::channel(initial);
        (sender, TestCancellation { receiver })
    }

    struct CancellingAudit {
        values: Vec<Value>,
        sender: watch::Sender<Option<CancellationReason>>,
        cancellation: CancellationReason,
    }

    impl AuditSink for CancellingAudit {
        fn emit(&mut self, value: &Value) {
            self.values.push(value.clone());
            if value["phase"] == "path_commit" {
                let _ = self.sender.send(Some(self.cancellation));
            }
        }
    }

    fn terminal_events(values: &[Value]) -> usize {
        values
            .iter()
            .filter(|value| {
                matches!(
                    value["phase"].as_str(),
                    Some("batch_failure" | "batch_cancellation" | "batch_completion")
                )
            })
            .count()
    }

    impl IdSource for FixedIds {
        fn fresh(&mut self, excluded: &BTreeSet<[u8; 16]>) -> Result<[u8; 16]> {
            let id = self.0.pop_front().context("fixed IDs exhausted")?;
            if id == [0; 16] || excluded.contains(&id) {
                bail!("fixed ID is zero or duplicated");
            }
            Ok(id)
        }
    }

    fn fixed_ids() -> FixedIds {
        FixedIds(VecDeque::from([[1; 16], [2; 16], [3; 16], [4; 16]]))
    }

    fn valid_signature(rpc: &FakeRpc) -> String {
        valid_signature_for(rpc, &narinfo(&[]), STORE_PATH, HASH)
    }

    fn valid_signature_for(rpc: &FakeRpc, narinfo: &[u8], store_path: &str, hash: &str) -> String {
        let fingerprint = fingerprint_from_narinfo(narinfo, Some(store_path), hash).unwrap();
        format!(
            "{KEY_NAME}:{}",
            base64::engine::general_purpose::STANDARD
                .encode(rpc.signing_key.sign(fingerprint.as_bytes()).to_bytes())
        )
    }

    #[test]
    fn fingerprint_construction_sorts_and_prefixes_references() {
        let input = format!(
            "StorePath: {STORE_PATH}\nNarHash: {NAR_HASH}\nNarSize: 9\nReferences: z5wkd9frr45pa74if5gpz9j7mifg27fh-zed a5wkd9frr45pa74if5gpz9j7mifg27fh-alpha\n"
        );
        let fingerprint =
            fingerprint_from_narinfo(input.as_bytes(), Some(STORE_PATH), HASH).unwrap();
        assert_eq!(
            std::str::from_utf8(fingerprint.as_bytes()).unwrap(),
            format!(
                "1;{STORE_PATH};{NAR_HASH};9;/nix/store/a5wkd9frr45pa74if5gpz9j7mifg27fh-alpha,/nix/store/z5wkd9frr45pa74if5gpz9j7mifg27fh-zed"
            )
        );
    }

    #[test]
    fn reference_collector_accepts_exact_normative_limit() {
        let references = reference_list(MAX_REFERENCES);
        let parsed = fingerprint_from_narinfo(
            &narinfo_with_references(STORE_PATH, &references),
            Some(STORE_PATH),
            HASH,
        )
        .unwrap();
        assert_eq!(
            std::str::from_utf8(parsed.as_bytes())
                .unwrap()
                .split(';')
                .nth(4)
                .unwrap()
                .split(',')
                .count(),
            MAX_REFERENCES
        );
    }

    #[test]
    fn reference_collector_rejects_empty_malformed_and_overlong_tokens_during_scan() {
        let valid = "00000000000000000000000000000000-valid";
        let overlong = format!("00000000000000000000000000000000-{}", "x".repeat(212));
        for references in [format!("{valid}  {valid}"), "bad".to_string(), overlong] {
            let retained_maximum = Cell::new(0_usize);
            assert!(
                collect_references(&references, |retained| {
                    retained_maximum.set(retained_maximum.get().max(retained));
                })
                .is_err()
            );
            assert!(retained_maximum.get() <= 1);
        }
    }

    #[tokio::test]
    async fn reference_limit_rejects_before_sign_without_mutation() {
        let directory = TempDir::new();
        let input = narinfo_with_references(STORE_PATH, &reference_list(MAX_REFERENCES + 1));
        let path = directory.write(HASH, &input);
        let before = fs::read(&path).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        let error = run_signing(
            &mut rpc,
            SigningCommand::Sign(SignArgs {
                key_id,
                selection: selection(&directory.0, false),
            }),
            &mut fixed_ids(),
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("constructing fingerprint"));
        assert_eq!(rpc.calls.len(), 1, "only Describe may run");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::metadata(path).unwrap().ino(), inode);
    }

    #[tokio::test]
    async fn near_maximum_one_byte_references_retain_no_unbounded_state() {
        let maximum = usize::try_from(basil_core::core::nix_cache_file::MAX_NARINFO_BYTES).unwrap();
        let fixed = narinfo_with_references(STORE_PATH, "").len();
        let references = "a ".repeat((maximum - fixed - 1) / 2);
        let input = narinfo_with_references(STORE_PATH, references.trim_end());
        assert!(input.len() > maximum - 256);
        assert!(input.len() <= maximum);

        let retained_maximum = Cell::new(0_usize);
        let error = collect_references(references.trim_end(), |retained| {
            retained_maximum.set(retained_maximum.get().max(retained));
        })
        .unwrap_err();
        assert!(error.to_string().contains("name separator"));
        assert!(retained_maximum.get() <= MAX_REFERENCES);

        let directory = TempDir::new();
        let path = directory.write(HASH, &input);
        let before = fs::read(&path).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        assert!(
            run_signing(
                &mut rpc,
                SigningCommand::Sign(SignArgs {
                    key_id,
                    selection: selection(&directory.0, false),
                }),
                &mut fixed_ids(),
                &mut Vec::new(),
            )
            .await
            .is_err()
        );
        assert_eq!(rpc.calls.len(), 1, "only Describe may run");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::metadata(path).unwrap().ino(), inode);
    }

    #[test]
    fn parses_cache_commands_and_selection_contract() {
        for arguments in [
            vec![
                "basil", "nix", "cache", "sign", "--cache", "/cache", "--key", "catalog", "--path",
                STORE_PATH,
            ],
            vec![
                "basil",
                "nix",
                "cache",
                "replace",
                "--cache",
                "/cache",
                "--key",
                "catalog",
                "--old-key-name",
                "old",
                "--all",
                "--dry-run",
            ],
            vec![
                "basil",
                "nix",
                "cache",
                "remove",
                "--cache",
                "/cache",
                "--key-name",
                "old",
                "--all",
                "--yes",
            ],
        ] {
            let parsed = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(
                parsed.command,
                Command::Nix(crate::nix_cli::NixCommand::Cache(_))
            ));
        }
        assert!(
            Cli::try_parse_from([
                "basil", "nix", "cache", "sign", "--cache", "/cache", "--key", "catalog"
            ])
            .is_err()
        );
    }

    #[test]
    fn selection_maps_store_paths_and_sorts_all() {
        let directory = TempDir::new();
        directory.write(HASH, &narinfo(&[]));
        directory.write("05wkd9frr45pa74if5gpz9j7mifg27fh", &narinfo(&[]));
        let explicit = select_explicit(&selection(&directory.0, false))
            .unwrap()
            .unwrap();
        assert_eq!(
            explicit[0].relative,
            PathBuf::from(format!("{HASH}.narinfo"))
        );
        let all_args = SelectionArgs {
            all: true,
            paths: Vec::new(),
            ..selection(&directory.0, false)
        };
        let (_, all) = open_preview(&all_args, select_explicit(&all_args).unwrap()).unwrap();
        assert_eq!(all.len(), 2);
        assert!(all[0].relative < all[1].relative);
    }

    #[tokio::test]
    async fn sign_adds_verified_signature_and_preserves_batch_ids() {
        let directory = TempDir::new();
        let path = directory.write(HASH, &narinfo(&[]));
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        let mut output = Vec::new();
        run_signing(
            &mut rpc,
            SigningCommand::Sign(SignArgs {
                key_id,
                selection: selection(&directory.0, false),
            }),
            &mut fixed_ids(),
            &mut output,
        )
        .await
        .unwrap();
        assert!(
            String::from_utf8(fs::read(path).unwrap())
                .unwrap()
                .contains("Sig: cache-current:")
        );
        assert_eq!(rpc.calls[0], Call::Describe([1; 16], [2; 16]));
        assert!(
            matches!(&rpc.calls[1], Call::Sign(_, batch, request) if *batch == [1; 16] && *request == [3; 16])
        );
        assert_eq!(output, format!("{HASH}.narinfo: written\n").as_bytes());
    }

    #[tokio::test]
    async fn durable_path_audit_joins_the_exact_sign_request() {
        let directory = TempDir::new();
        directory.write(HASH, &narinfo(&[]));
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        let command = SigningCommand::Sign(SignArgs {
            key_id: key_id.clone(),
            selection: selection(&directory.0, false),
        });
        let batch_id = [1; CORRELATION_ID_LEN];
        let mut ids = FixedIds(VecDeque::from([[2; 16], [3; 16]]));
        let mut used_ids = BTreeSet::from([batch_id]);
        let mut captured = CapturedAudit::default();
        {
            let mut audit = BatchAudit::new(
                &mut captured,
                MutationOp::Sign,
                batch_id,
                false,
                false,
                Some(&key_id),
            );
            run_signing_batch(
                &mut rpc,
                command,
                &mut ids,
                &mut used_ids,
                batch_id,
                &mut Vec::new(),
                &mut audit,
            )
            .await
            .unwrap();
            audit.complete();
        }
        assert_eq!(rpc.calls[0], Call::Describe([1; 16], [2; 16]));
        assert!(
            matches!(&rpc.calls[1], Call::Sign(_, batch, request) if *batch == [1; 16] && *request == [3; 16])
        );
        let commit = captured
            .0
            .iter()
            .find(|event| event["phase"] == "path_commit")
            .unwrap();
        assert_eq!(commit["batch_id"], "01010101010101010101010101010101");
        assert_eq!(commit["request_id"], "03030303030303030303030303030303");
        assert_eq!(
            commit["selected_path_sha256"],
            "9b9bcf6622f046d2dde16085514cda17cc29482266532e15f5fd045cb9c99bab"
        );
        assert_eq!(
            commit["fingerprint_sha256"],
            "773dd9b84121bd49afec7280d3945ef355424849474b0e04fc0b9a07977b3cc0"
        );
        assert_eq!(commit["signature_source"], "produced");
        assert_eq!(commit["mutation"], "installed");
        let rendered = serde_json::to_string(&captured.0).unwrap();
        assert!(!rendered.contains(STORE_PATH));
        assert!(!rendered.contains(NAR_HASH));
        assert!(!rendered.contains("Sig:"));
    }

    #[tokio::test]
    async fn pending_connect_cancels_with_exactly_one_terminal_event() {
        let directory = TempDir::new();
        let command = SigningCommand::Sign(SignArgs {
            key_id: "catalog-cache".to_string(),
            selection: selection(&directory.0, false),
        });
        let (_sender, mut cancellation) =
            cancellation_channel(Some(CancellationReason::Signal("SIGINT")));
        let mut ids = FixedIds(VecDeque::from([[1; CORRELATION_ID_LEN]]));
        let mut captured = CapturedAudit::default();
        let error = run_connected_with(
            command,
            &mut ids,
            &mut Vec::new(),
            &mut captured,
            &mut cancellation,
            std::future::pending::<Result<FakeRpc>>,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("SIGINT"));
        assert_eq!(captured.0.len(), 2);
        assert_eq!(captured.0[0]["phase"], "batch_start");
        assert_eq!(captured.0[1]["phase"], "batch_cancellation");
        assert_eq!(captured.0[1]["signal"], "SIGINT");
        assert_eq!(terminal_events(&captured.0), 1);
    }

    #[tokio::test]
    async fn held_lock_wait_is_cancelled_without_mutation() {
        let directory = TempDir::new();
        let path = directory.write(HASH, &narinfo(&[]));
        let before = fs::read(&path).unwrap();
        let holder = LockedCacheRoot::try_acquire(&directory.0).unwrap();
        let args = RemoveArgs {
            key_name: vec!["old".to_string()],
            selection: SelectionArgs {
                lock_timeout: 5,
                ..selection(&directory.0, false)
            },
        };
        let (sender, mut cancellation) = cancellation_channel(None);
        let cancellation_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let _ = sender.send(Some(CancellationReason::Task));
        });
        let mut ids = FixedIds(VecDeque::from([[1; CORRELATION_ID_LEN]]));
        let mut captured = CapturedAudit::default();
        let error = run_remove_audited_with(
            &args,
            &mut ids,
            &mut Vec::new(),
            &mut captured,
            &mut cancellation,
        )
        .await
        .unwrap_err();
        cancellation_task.await.unwrap();
        assert!(holder.holds_lock());
        assert!(error.to_string().contains("task cancelled"));
        assert_eq!(fs::read(path).unwrap(), before);
        assert_eq!(captured.0.len(), 2);
        assert_eq!(captured.0[1]["phase"], "batch_cancellation");
        assert_eq!(captured.0[1]["counts"]["durable_commits"], 0);
        assert_eq!(terminal_events(&captured.0), 1);
    }

    #[tokio::test]
    async fn reused_replace_stops_before_the_second_commit_after_signal_or_task_cancellation() {
        assert_reused_replace_stops(CancellationReason::Task).await;
        assert_reused_replace_stops(CancellationReason::Signal("SIGTERM")).await;
    }

    async fn assert_reused_replace_stops(cancellation_reason: CancellationReason) {
        const FIRST_HASH: &str = "05wkd9frr45pa74if5gpz9j7mifg27fh";
        const FIRST_PATH: &str = "/nix/store/05wkd9frr45pa74if5gpz9j7mifg27fh-first";
        let directory = TempDir::new();
        let rpc = FakeRpc::new();
        let old = "old:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string();
        let first_unsigned = narinfo_for(FIRST_PATH);
        let first_signature = valid_signature_for(&rpc, &first_unsigned, FIRST_PATH, FIRST_HASH);
        let second_signature = valid_signature(&rpc);
        let first = directory.write(
            FIRST_HASH,
            &narinfo_for_with_signatures(FIRST_PATH, &[old.clone(), first_signature]),
        );
        let second = directory.write(HASH, &narinfo(&[old.clone(), second_signature]));
        let second_before = fs::read(&second).unwrap();
        let command = SigningCommand::Replace(ReplaceArgs {
            key_id: rpc.key_id.clone(),
            old_key_name: vec!["old".to_string()],
            selection: SelectionArgs {
                paths: vec![PathBuf::from(STORE_PATH), PathBuf::from(FIRST_PATH)],
                ..selection(&directory.0, false)
            },
        });
        let (sender, mut cancellation) = cancellation_channel(None);
        let mut audit = CancellingAudit {
            values: Vec::new(),
            sender,
            cancellation: cancellation_reason,
        };
        let mut ids = FixedIds(VecDeque::from([[1; 16], [2; 16], [3; 16], [4; 16]]));
        let mut connector = Some(rpc);
        let error = run_connected_with(
            command,
            &mut ids,
            &mut Vec::new(),
            &mut audit,
            &mut cancellation,
            || std::future::ready(Ok(connector.take().unwrap())),
        )
        .await
        .unwrap_err();
        match cancellation_reason {
            CancellationReason::Task => assert!(error.to_string().contains("task cancelled")),
            CancellationReason::Signal(signal) => assert!(error.to_string().contains(signal)),
        }
        assert!(
            !String::from_utf8(fs::read(first).unwrap())
                .unwrap()
                .contains("Sig: old:")
        );
        assert_eq!(fs::read(second).unwrap(), second_before);
        assert_eq!(audit.values.len(), 3);
        assert_eq!(audit.values[1]["phase"], "path_commit");
        assert_eq!(audit.values[1]["signature_source"], "reused");
        assert_eq!(audit.values[1]["request_id"], Value::Null);
        assert_eq!(audit.values[2]["phase"], "batch_cancellation");
        let expected_reason = match cancellation_reason {
            CancellationReason::Task => "task_cancelled",
            CancellationReason::Signal(_) => "signal",
        };
        assert_eq!(audit.values[2]["reason"], expected_reason);
        assert_eq!(audit.values[2]["counts"]["durable_commits"], 1);
        assert_eq!(terminal_events(&audit.values), 1);
    }

    #[test]
    fn directory_durability_uncertainty_emits_no_path_commit() {
        let mut captured = CapturedAudit::default();
        {
            let mut audit = BatchAudit::new(
                &mut captured,
                MutationOp::Sign,
                [1; CORRELATION_ID_LEN],
                false,
                false,
                Some("catalog-cache"),
            );
            audit.set_selected(1);
            let outcome = SigningTargetOutcome {
                commit: NarinfoCommit::CommittedDurabilityUncertain {
                    error: std::io::Error::other("injected directory sync failure"),
                },
                store_path: STORE_PATH.to_string(),
                fingerprint: fingerprint_from_narinfo(&narinfo(&[]), Some(STORE_PATH), HASH)
                    .unwrap(),
                request_id: Some([3; CORRELATION_ID_LEN]),
                signature_source: SignatureSource::Produced,
            };
            audit.signature_observed(SignatureSource::Produced);
            audit_signing_outcome(&mut audit, &outcome);
            audit.fail("operation_failed");
        }
        assert_eq!(captured.0.len(), 2);
        assert_eq!(captured.0[1]["phase"], "batch_failure");
        assert_eq!(captured.0[1]["counts"]["durable_commits"], 0);
        assert_eq!(captured.0[1]["counts"]["signatures_produced"], 1);
        assert_eq!(captured.0[1]["counts"]["signatures_installed"], 0);
        assert!(
            captured
                .0
                .iter()
                .all(|event| event["phase"] != "path_commit")
        );
    }

    struct FailingOutput;

    impl Write for FailingOutput {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected output failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct CancellingOutput {
        bytes: Vec<u8>,
        sender: watch::Sender<Option<CancellationReason>>,
        sent: bool,
    }

    impl Write for CancellingOutput {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buffer);
            if !self.sent {
                self.sent = true;
                let _ = self
                    .sender
                    .send(Some(CancellationReason::Signal("SIGTERM")));
            }
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn output_failure_follows_the_durable_path_event() {
        let directory = TempDir::new();
        directory.write(HASH, &narinfo(&[]));
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        let command = SigningCommand::Sign(SignArgs {
            key_id: key_id.clone(),
            selection: selection(&directory.0, false),
        });
        let batch_id = [1; CORRELATION_ID_LEN];
        let mut ids = FixedIds(VecDeque::from([[2; 16], [3; 16]]));
        let mut used_ids = BTreeSet::from([batch_id]);
        let mut captured = CapturedAudit::default();
        {
            let mut audit = BatchAudit::new(
                &mut captured,
                MutationOp::Sign,
                batch_id,
                false,
                false,
                Some(&key_id),
            );
            let error = run_signing_batch(
                &mut rpc,
                command,
                &mut ids,
                &mut used_ids,
                batch_id,
                &mut FailingOutput,
                &mut audit,
            )
            .await
            .unwrap_err();
            assert_eq!(failure_reason(&error), "output_failed");
            audit.fail(failure_reason(&error));
        }
        assert_eq!(captured.0.len(), 3);
        assert_eq!(captured.0[1]["phase"], "path_commit");
        assert_eq!(captured.0[2]["phase"], "batch_failure");
        assert_eq!(captured.0[2]["reason"], "output_failed");
        assert_eq!(captured.0[2]["counts"]["durable_commits"], 1);
    }

    #[tokio::test]
    async fn dry_run_preview_cancels_between_targets() {
        const FIRST_HASH: &str = "05wkd9frr45pa74if5gpz9j7mifg27fh";
        const FIRST_PATH: &str = "/nix/store/05wkd9frr45pa74if5gpz9j7mifg27fh-first";
        let directory = TempDir::new();
        directory.write(FIRST_HASH, &narinfo_for(FIRST_PATH));
        directory.write(HASH, &narinfo(&[]));
        let args = RemoveArgs {
            key_name: vec!["old".to_string()],
            selection: SelectionArgs {
                paths: vec![PathBuf::from(STORE_PATH), PathBuf::from(FIRST_PATH)],
                dry_run: true,
                ..selection(&directory.0, true)
            },
        };
        let (sender, mut cancellation) = cancellation_channel(None);
        let mut output = CancellingOutput {
            bytes: Vec::new(),
            sender,
            sent: false,
        };
        let mut ids = FixedIds(VecDeque::from([[1; CORRELATION_ID_LEN]]));
        let mut captured = CapturedAudit::default();
        let error = run_remove_audited_with(
            &args,
            &mut ids,
            &mut output,
            &mut captured,
            &mut cancellation,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("SIGTERM"));
        assert_eq!(
            output.bytes,
            format!("{FIRST_HASH}.narinfo: unchanged\n").as_bytes()
        );
        assert_eq!(captured.0.len(), 2);
        assert_eq!(captured.0[1]["phase"], "batch_cancellation");
        assert_eq!(captured.0[1]["counts"]["durable_commits"], 0);
        assert_eq!(captured.0[1]["counts"]["unchanged"], 1);
        assert_eq!(captured.0[1]["counts"]["preview_changes"], 0);
        assert_eq!(terminal_events(&captured.0), 1);
    }

    #[tokio::test]
    async fn remove_audit_has_only_the_selected_path_digest() {
        let directory = TempDir::new();
        let old = "old:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string();
        directory.write(HASH, &narinfo(&[old]));
        let args = RemoveArgs {
            key_name: vec!["old".to_string()],
            selection: selection(&directory.0, false),
        };
        let names = validate_key_names(&args.key_name).unwrap();
        let explicit = select_explicit(&args.selection).unwrap();
        let mut captured = CapturedAudit::default();
        {
            let mut audit = BatchAudit::new(
                &mut captured,
                MutationOp::Remove,
                [4; CORRELATION_ID_LEN],
                false,
                false,
                None,
            );
            run_remove_batch(&args, &names, explicit, &mut Vec::new(), &mut audit)
                .await
                .unwrap();
            audit.complete();
        }
        let commit = &captured.0[1];
        assert_eq!(commit["operation"], "remove");
        assert_eq!(commit["mutation"], "removed");
        assert_eq!(commit["signature_source"], "not_applicable");
        assert_eq!(commit["fingerprint_sha256"], Value::Null);
        assert_eq!(
            commit["selected_path_sha256"],
            "9b9bcf6622f046d2dde16085514cda17cc29482266532e15f5fd045cb9c99bab"
        );
        assert!(
            !serde_json::to_string(&captured.0)
                .unwrap()
                .contains(STORE_PATH)
        );
    }

    #[tokio::test]
    async fn sign_and_replace_dry_runs_describe_without_signing_or_locking() {
        for replace in [false, true] {
            let directory = TempDir::new();
            let path = directory.write(HASH, &narinfo(&[]));
            let before = fs::read(&path).unwrap();
            let inode = fs::metadata(&path).unwrap().ino();
            let mut rpc = FakeRpc::new();
            let key_id = rpc.key_id.clone();
            let command = if replace {
                SigningCommand::Replace(ReplaceArgs {
                    key_id,
                    old_key_name: vec!["old".to_string()],
                    selection: selection(&directory.0, true),
                })
            } else {
                SigningCommand::Sign(SignArgs {
                    key_id,
                    selection: selection(&directory.0, true),
                })
            };
            let mut output = Vec::new();
            run_signing(&mut rpc, command, &mut fixed_ids(), &mut output)
                .await
                .unwrap();
            assert_eq!(rpc.calls.len(), 1, "dry-run performs Describe only");
            assert!(matches!(rpc.calls[0], Call::Describe(_, _)));
            assert_eq!(output, format!("{HASH}.narinfo: would change\n").as_bytes());
            assert_eq!(fs::read(&path).unwrap(), before);
            assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
            assert!(
                !directory
                    .0
                    .join(basil_core::core::nix_cache_file::CACHE_LOCK_FILE)
                    .exists()
            );
        }
    }

    #[tokio::test]
    async fn multi_target_sign_uses_one_batch_and_distinct_request_ids() {
        const FIRST_HASH: &str = "05wkd9frr45pa74if5gpz9j7mifg27fh";
        const FIRST_PATH: &str = "/nix/store/05wkd9frr45pa74if5gpz9j7mifg27fh-first";

        let directory = TempDir::new();
        directory.write(FIRST_HASH, &narinfo_for(FIRST_PATH));
        directory.write(HASH, &narinfo(&[]));
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        run_signing(
            &mut rpc,
            SigningCommand::Sign(SignArgs {
                key_id,
                selection: SelectionArgs {
                    paths: vec![PathBuf::from(STORE_PATH), PathBuf::from(FIRST_PATH)],
                    ..selection(&directory.0, false)
                },
            }),
            &mut fixed_ids(),
            &mut Vec::new(),
        )
        .await
        .unwrap();
        let Call::Describe(batch, describe_request) = rpc.calls[0] else {
            panic!("Describe expected first");
        };
        let Call::Sign(_, first_batch, first_request) = &rpc.calls[1] else {
            panic!("first Sign expected");
        };
        let Call::Sign(_, second_batch, second_request) = &rpc.calls[2] else {
            panic!("second Sign expected");
        };
        assert_eq!(*first_batch, batch);
        assert_eq!(*second_batch, batch);
        assert_ne!(*first_request, describe_request);
        assert_ne!(*second_request, describe_request);
        assert_ne!(*first_request, *second_request);
    }

    #[tokio::test]
    async fn sign_reuses_a_verified_existing_signature_without_sign_rpc() {
        let directory = TempDir::new();
        let rpc_template = FakeRpc::new();
        let signature = valid_signature(&rpc_template);
        let path = directory.write(HASH, &narinfo(&[signature]));
        let before = fs::read(&path).unwrap();
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        run_signing(
            &mut rpc,
            SigningCommand::Sign(SignArgs {
                key_id,
                selection: selection(&directory.0, false),
            }),
            &mut fixed_ids(),
            &mut Vec::new(),
        )
        .await
        .unwrap();
        assert_eq!(rpc.calls.len(), 1);
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[tokio::test]
    async fn sign_rejects_same_name_invalid_signature_before_sign_rpc() {
        let directory = TempDir::new();
        let invalid = format!(
            "{KEY_NAME}:{}",
            base64::engine::general_purpose::STANDARD.encode([0; 64])
        );
        directory.write(HASH, &narinfo(&[invalid]));
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        let error = run_signing(
            &mut rpc,
            SigningCommand::Sign(SignArgs {
                key_id,
                selection: selection(&directory.0, false),
            }),
            &mut fixed_ids(),
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("SIGNATURE_CONFLICT"));
        assert_eq!(rpc.calls.len(), 1);
    }

    #[tokio::test]
    async fn malformed_record_fails_before_sign_rpc() {
        for suffix in [b"X-Future: value\r\n".as_slice(), b"Sig:malformed\n"] {
            let directory = TempDir::new();
            let mut input = narinfo(&[]);
            input.extend_from_slice(suffix);
            directory.write(HASH, &input);
            let mut rpc = FakeRpc::new();
            let key_id = rpc.key_id.clone();
            assert!(
                run_signing(
                    &mut rpc,
                    SigningCommand::Sign(SignArgs {
                        key_id,
                        selection: selection(&directory.0, false),
                    }),
                    &mut fixed_ids(),
                    &mut Vec::new(),
                )
                .await
                .is_err()
            );
            assert_eq!(rpc.calls.len(), 1, "only Describe may run");
        }
    }

    #[tokio::test]
    async fn replace_adds_new_signature_when_old_is_absent_and_preserves_unrelated() {
        let directory = TempDir::new();
        let unrelated = "keep:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string();
        let path = directory.write(HASH, &narinfo(std::slice::from_ref(&unrelated)));
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        run_signing(
            &mut rpc,
            SigningCommand::Replace(ReplaceArgs {
                key_id,
                old_key_name: vec!["absent".to_string()],
                selection: selection(&directory.0, false),
            }),
            &mut fixed_ids(),
            &mut Vec::new(),
        )
        .await
        .unwrap();
        let after = String::from_utf8(fs::read(path).unwrap()).unwrap();
        assert!(after.contains(&format!("Sig: {unrelated}")));
        assert!(after.contains("Sig: cache-current:"));
    }

    #[tokio::test]
    async fn replace_can_remove_a_conflicting_new_key_name() {
        let directory = TempDir::new();
        let invalid = format!(
            "{KEY_NAME}:{}",
            base64::engine::general_purpose::STANDARD.encode([0; 64])
        );
        let path = directory.write(HASH, &narinfo(&[invalid]));
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        run_signing(
            &mut rpc,
            SigningCommand::Replace(ReplaceArgs {
                key_id,
                old_key_name: vec![KEY_NAME.to_string()],
                selection: selection(&directory.0, false),
            }),
            &mut fixed_ids(),
            &mut Vec::new(),
        )
        .await
        .unwrap();
        let after = String::from_utf8(fs::read(path).unwrap()).unwrap();
        assert_eq!(after.matches("Sig: cache-current:").count(), 1);
        assert_eq!(rpc.calls.len(), 2);
    }

    #[test]
    fn remove_deletes_only_exact_names_without_any_rpc() {
        let directory = TempDir::new();
        let old = "old:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string();
        let extra = "old-extra:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string();
        let path = directory.write(HASH, &narinfo(&[old, extra.clone()]));
        run_remove(
            &RemoveArgs {
                key_name: vec!["old".to_string()],
                selection: selection(&directory.0, false),
            },
            &mut Vec::new(),
        )
        .unwrap();
        let after = String::from_utf8(fs::read(path).unwrap()).unwrap();
        assert!(!after.contains("Sig: old:"));
        assert!(after.contains(&format!("Sig: {extra}")));
    }

    #[test]
    fn dry_run_does_not_create_or_open_the_mutation_lock() {
        let directory = TempDir::new();
        let path = directory.write(HASH, &narinfo(&[]));
        let before = fs::read(&path).unwrap();
        let lock = directory
            .0
            .join(basil_core::core::nix_cache_file::CACHE_LOCK_FILE);
        let mut output = Vec::new();
        run_remove(
            &RemoveArgs {
                key_name: vec!["old".to_string()],
                selection: selection(&directory.0, true),
            },
            &mut output,
        )
        .unwrap();
        assert!(!lock.exists());
        assert_eq!(fs::read(path).unwrap(), before);
        assert_eq!(output, format!("{HASH}.narinfo: unchanged\n").as_bytes());
    }

    #[test]
    fn destructive_all_dry_run_needs_no_confirmation() {
        let directory = TempDir::new();
        directory.write(HASH, &narinfo(&[]));
        let mut output = Vec::new();
        run_remove(
            &RemoveArgs {
                key_name: vec!["old".to_string()],
                selection: SelectionArgs {
                    all: true,
                    paths: Vec::new(),
                    dry_run: true,
                    ..selection(&directory.0, true)
                },
            },
            &mut output,
        )
        .unwrap();
        assert!(
            !directory
                .0
                .join(basil_core::core::nix_cache_file::CACHE_LOCK_FILE)
                .exists()
        );
        assert_eq!(output, format!("{HASH}.narinfo: unchanged\n").as_bytes());
    }

    #[test]
    fn destructive_all_requires_yes_before_lock_creation() {
        let directory = TempDir::new();
        directory.write(HASH, &narinfo(&[]));
        let error = run_remove(
            &RemoveArgs {
                key_name: vec!["old".to_string()],
                selection: SelectionArgs {
                    all: true,
                    paths: Vec::new(),
                    ..selection(&directory.0, false)
                },
            },
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("requires `--yes`"));
        assert!(
            !directory
                .0
                .join(basil_core::core::nix_cache_file::CACHE_LOCK_FILE)
                .exists()
        );
    }

    #[tokio::test]
    async fn invalid_sign_response_identity_and_signature_fail_before_mutation() {
        for wrong_identity in [true, false] {
            let directory = TempDir::new();
            let path = directory.write(HASH, &narinfo(&[]));
            let before = fs::read(&path).unwrap();
            let mut rpc = FakeRpc::new();
            rpc.wrong_identity = wrong_identity;
            rpc.bad_signature = !wrong_identity;
            let key_id = rpc.key_id.clone();
            assert!(
                run_signing(
                    &mut rpc,
                    SigningCommand::Sign(SignArgs {
                        key_id,
                        selection: selection(&directory.0, false),
                    }),
                    &mut fixed_ids(),
                    &mut Vec::new(),
                )
                .await
                .is_err()
            );
            assert_eq!(fs::read(path).unwrap(), before);
        }
    }

    #[tokio::test]
    async fn failed_batch_reports_committed_prefix_and_rerun_resumes() {
        const FIRST_HASH: &str = "05wkd9frr45pa74if5gpz9j7mifg27fh";
        const FIRST_PATH: &str = "/nix/store/05wkd9frr45pa74if5gpz9j7mifg27fh-first";

        let directory = TempDir::new();
        let first = directory.write(FIRST_HASH, &narinfo_for(FIRST_PATH));
        directory.write(HASH, b"StorePath: broken\n");
        let batch_selection = SelectionArgs {
            paths: vec![PathBuf::from(STORE_PATH), PathBuf::from(FIRST_PATH)],
            ..selection(&directory.0, false)
        };
        let mut first_rpc = FakeRpc::new();
        let key_id = first_rpc.key_id.clone();
        let mut first_output = Vec::new();
        assert!(
            run_signing(
                &mut first_rpc,
                SigningCommand::Sign(SignArgs {
                    key_id,
                    selection: batch_selection,
                }),
                &mut fixed_ids(),
                &mut first_output,
            )
            .await
            .is_err()
        );
        assert_eq!(
            first_output,
            format!("{FIRST_HASH}.narinfo: written\n").as_bytes()
        );
        assert!(
            String::from_utf8(fs::read(&first).unwrap())
                .unwrap()
                .contains("Sig: cache-current:")
        );

        directory.write(HASH, &narinfo(&[]));
        let mut retry_rpc = FakeRpc::new();
        let key_id = retry_rpc.key_id.clone();
        let mut retry_output = Vec::new();
        run_signing(
            &mut retry_rpc,
            SigningCommand::Sign(SignArgs {
                key_id,
                selection: SelectionArgs {
                    paths: vec![PathBuf::from(STORE_PATH), PathBuf::from(FIRST_PATH)],
                    ..selection(&directory.0, false)
                },
            }),
            &mut fixed_ids(),
            &mut retry_output,
        )
        .await
        .unwrap();
        assert_eq!(
            retry_output,
            format!("{FIRST_HASH}.narinfo: unchanged\n{HASH}.narinfo: written\n").as_bytes()
        );
        assert_eq!(retry_rpc.calls.len(), 2, "Describe plus one resumed Sign");
    }

    #[tokio::test]
    async fn partial_failure_audit_retains_only_the_durable_prefix() {
        const FIRST_HASH: &str = "05wkd9frr45pa74if5gpz9j7mifg27fh";
        const FIRST_PATH: &str = "/nix/store/05wkd9frr45pa74if5gpz9j7mifg27fh-first";

        let directory = TempDir::new();
        directory.write(FIRST_HASH, &narinfo_for(FIRST_PATH));
        directory.write(HASH, b"StorePath: broken\n");
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        let command = SigningCommand::Sign(SignArgs {
            key_id: key_id.clone(),
            selection: SelectionArgs {
                paths: vec![PathBuf::from(STORE_PATH), PathBuf::from(FIRST_PATH)],
                ..selection(&directory.0, false)
            },
        });
        let batch_id = [1; CORRELATION_ID_LEN];
        let mut ids = FixedIds(VecDeque::from([[2; 16], [3; 16], [4; 16]]));
        let mut used_ids = BTreeSet::from([batch_id]);
        let mut captured = CapturedAudit::default();
        {
            let mut audit = BatchAudit::new(
                &mut captured,
                MutationOp::Sign,
                batch_id,
                false,
                false,
                Some(&key_id),
            );
            let error = run_signing_batch(
                &mut rpc,
                command,
                &mut ids,
                &mut used_ids,
                batch_id,
                &mut Vec::new(),
                &mut audit,
            )
            .await
            .unwrap_err();
            audit.fail(failure_reason(&error));
        }
        assert_eq!(captured.0.len(), 3);
        assert_eq!(captured.0[1]["phase"], "path_commit");
        assert_eq!(captured.0[2]["phase"], "batch_failure");
        assert_eq!(captured.0[2]["counts"]["selected"], 2);
        assert_eq!(captured.0[2]["counts"]["durable_commits"], 1);
        let rendered = serde_json::to_string(&captured.0).unwrap();
        assert!(!rendered.contains(FIRST_PATH));
        assert!(!rendered.contains(STORE_PATH));
    }

    #[test]
    fn rejects_non_file_cache_and_store_path_mismatch() {
        let mut remote = selection(Path::new("https://cache.example"), true);
        remote.paths = vec![PathBuf::from(STORE_PATH)];
        assert!(
            select_explicit(&remote)
                .unwrap_err()
                .to_string()
                .contains("only local file")
        );

        let other = "/nix/store/05wkd9frr45pa74if5gpz9j7mifg27fh-other";
        assert!(fingerprint_from_narinfo(&narinfo(&[]), Some(other), HASH).is_err());
    }

    #[test]
    fn explicit_paths_are_deduplicated_and_invalid_names_fail() {
        let directory = TempDir::new();
        let mut args = selection(&directory.0, true);
        args.paths.push(PathBuf::from(STORE_PATH));
        assert_eq!(select_explicit(&args).unwrap().unwrap().len(), 1);
        assert!(validate_key_names(&["bad:name".to_string()]).is_err());
        assert!(validate_store_path("/gnu/store/hash-name").is_err());
        assert!(validate_catalog_key_id("cache.signing").is_ok());
        assert!(validate_catalog_key_id("/secret/cache-key").is_err());
    }

    #[test]
    fn preview_reader_rejects_symlink_and_oversize_targets() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new();
        let target = directory.write(HASH, &narinfo(&[]));
        let link = directory.0.join("link.narinfo");
        symlink(&target, &link).unwrap();
        let root = ReadOnlyCacheRoot::open(&directory.0).unwrap();
        assert!(root.read_narinfo(Path::new("link.narinfo")).is_err());

        let oversized = directory.0.join("oversized.narinfo");
        let file = fs::File::create(&oversized).unwrap();
        file.set_len(basil_core::core::nix_cache_file::MAX_NARINFO_BYTES + 1)
            .unwrap();
        assert!(root.read_narinfo(Path::new("oversized.narinfo")).is_err());
    }

    #[test]
    fn all_selection_is_fail_fast_on_invalid_narinfo_filename() {
        let directory = TempDir::new();
        directory.write(HASH, &narinfo(&[]));
        fs::write(directory.0.join("not-a-hash.narinfo"), b"bad").unwrap();
        let args = SelectionArgs {
            all: true,
            paths: Vec::new(),
            ..selection(&directory.0, true)
        };
        assert!(open_preview(&args, select_explicit(&args).unwrap()).is_err());
    }

    #[test]
    fn all_selection_binds_filename_hash_to_store_path() {
        let directory = TempDir::new();
        directory.write("05wkd9frr45pa74if5gpz9j7mifg27fh", &narinfo(&[]));
        let args = SelectionArgs {
            all: true,
            paths: Vec::new(),
            dry_run: true,
            ..selection(&directory.0, true)
        };
        let explicit = select_explicit(&args).unwrap();
        let (root, selected) = open_preview(&args, explicit).unwrap();
        assert!(
            preview_batch(
                &root,
                &selected,
                Some(&FakeRpc::new().identity),
                Operation::Sign,
                &mut Vec::new(),
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn filename_store_path_mismatch_fails_after_describe_without_signing() {
        const WRONG_HASH: &str = "05wkd9frr45pa74if5gpz9j7mifg27fh";

        let directory = TempDir::new();
        let path = directory.write(WRONG_HASH, &narinfo(&[]));
        let before = fs::read(&path).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        let mut rpc = FakeRpc::new();
        let key_id = rpc.key_id.clone();
        let error = run_signing(
            &mut rpc,
            SigningCommand::Sign(SignArgs {
                key_id,
                selection: SelectionArgs {
                    all: true,
                    paths: Vec::new(),
                    dry_run: true,
                    ..selection(&directory.0, true)
                },
            }),
            &mut fixed_ids(),
            &mut Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("StorePath hash"));
        assert_eq!(rpc.calls.len(), 1, "only Describe may run");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(fs::metadata(path).unwrap().ino(), inode);
    }

    #[tokio::test]
    async fn remove_never_connects_to_basil() {
        let directory = TempDir::new();
        directory.write(HASH, &narinfo(&[]));
        run(
            "/definitely/missing/basil.sock",
            NixCacheCommand::Remove(RemoveArgs {
                key_name: vec!["old".to_string()],
                selection: selection(&directory.0, false),
            }),
        )
        .await
        .unwrap();
    }

    #[test]
    fn os_string_cache_path_check_does_not_require_utf8() {
        use std::os::unix::ffi::OsStrExt as _;

        assert!(
            reject_non_file_cache(Path::new(std::ffi::OsStr::from_bytes(b"cache-\xff"))).is_ok()
        );
    }
}
