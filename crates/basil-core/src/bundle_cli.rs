// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Top-level `basil bundle` sealed-bundle management.
//!
//! This is the pre-release replacement for the old `basil config bundle`
//! scaffolding surface. The command parser uses structured repeatable
//! `--slot TYPE[:field=value,...]` and `--backend id=NAME,type=TYPE,...`
//! values so each source is self-contained and unambiguous.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::seal::{
    self, BackendCred, CredBundle, DepositStatus, MethodRegistry, SlotSpec, UnlockMethod, format,
};
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use rand::RngCore as _;
use serde::Deserialize;
use url::Url;
use zero_secrets::{SecretArray, SecretString};
use zeroize::Zeroizing;

#[cfg(feature = "unlock-age-yubikey")]
use crate::seal::AgeYubikeyMethod;
#[cfg(feature = "unlock-bip39")]
use crate::seal::Bip39Method;
use crate::seal::PassphraseMethod;

const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;
const MAX_EPOCH_BYTES: u64 = 32;

/// `bundle` subcommands.
#[derive(Debug, Subcommand)]
pub enum BundleCommand {
    /// Create a new sealed bundle.
    Create(CreateArgs),
    /// Add one unlock slot to an existing bundle.
    AddSlot(AddSlotArgs),
    /// Set or replace one backend credential in the sealed payload.
    SetBackend(SetBackendArgs),
    /// Append one signed credential deposit without opening the bundle.
    Deposit(DepositArgs),
    /// Allow a contributor signing key to deposit selected backend ids.
    Allow(AllowArgs),
    /// Review or fold authorized deposits into the sealed payload.
    Promote(PromoteArgs),
    /// Export or create the bundle's public deposit recipient.
    DepositKey(DepositKeyArgs),
    /// Check that an unlock method opens a bundle without mutating it.
    Verify(VerifyArgs),
    /// Show non-secret bundle metadata.
    Show(ShowArgs),
}

/// `bundle create` arguments.
#[derive(Debug, clap::Args)]
pub struct CreateArgs {
    /// Where to write the new `0600` bundle.
    bundle: PathBuf,

    /// Load `[[slot]]` and `[[backend]]` tables from this `TOML` manifest.
    #[arg(long = "from", value_name = "FILE")]
    from: Option<PathBuf>,

    /// Add an unlock slot: `TYPE[:field=value,...]`.
    #[arg(long, value_name = "SPEC")]
    slot: Vec<SlotArg>,

    /// Seed one backend credential: `id=NAME,type=TYPE,<fields>`.
    #[arg(long, value_name = "SPEC")]
    backend: Vec<BackendArg>,

    /// Write the public deposit recipient token to this file.
    #[arg(long = "deposit-key", value_name = "OUT")]
    deposit_key: Option<PathBuf>,
}

/// `bundle add-slot` arguments.
#[derive(Debug, clap::Args)]
pub struct AddSlotArgs {
    /// Bundle file to update in place.
    bundle: PathBuf,

    /// New unlock slot: `TYPE[:field=value,...]`.
    #[arg(long, value_name = "SPEC")]
    slot: SlotArg,

    /// Existing unlock method: `TYPE[:field=value,...]`.
    #[arg(long = "open", value_name = "METHOD", required = true)]
    open: Vec<OpenArg>,
}

/// `bundle set-backend` arguments.
#[derive(Debug, clap::Args)]
pub struct SetBackendArgs {
    /// Bundle file to update in place.
    bundle: PathBuf,

    /// Backend credential: `id=NAME,type=TYPE,<fields>`.
    #[arg(long, value_name = "SPEC")]
    backend: BackendArg,

    /// Existing unlock method: `TYPE[:field=value,...]`.
    #[arg(long = "open", value_name = "METHOD", required = true)]
    open: Vec<OpenArg>,
}

/// `bundle deposit` arguments.
#[derive(Debug, clap::Args)]
pub struct DepositArgs {
    /// Bundle file to append to.
    bundle: PathBuf,

    /// Backend credential: `id=NAME,type=TYPE,<fields>`.
    #[arg(long, value_name = "SPEC")]
    backend: BackendArg,

    /// File containing the public deposit recipient token.
    #[arg(short = 'r', long = "recipient", value_name = "FILE")]
    recipient: PathBuf,

    /// `0600` file containing a raw 32-byte Ed25519 signing seed.
    #[arg(short = 'i', long = "identity", value_name = "FILE")]
    identity: PathBuf,

    /// Contributor id recorded in the bundle allow-list. Defaults to the
    /// signing public-key token.
    #[arg(long = "contributor-id", value_name = "ID")]
    contributor_id: Option<String>,

    /// Explicit sequence number. Defaults to max existing sequence for this
    /// contributor/backend plus one.
    #[arg(long)]
    seq: Option<u64>,
}

/// `bundle allow` arguments.
#[derive(Debug, clap::Args)]
pub struct AllowArgs {
    /// Bundle file to update in place.
    bundle: PathBuf,

    /// Contributor Ed25519 public key token.
    #[arg(long, value_name = "PUB")]
    contributor: String,

    /// Contributor id stored in the sealed allow-list. Defaults to `--contributor`.
    #[arg(long = "contributor-id", value_name = "ID")]
    contributor_id: Option<String>,

    /// Backend id this contributor may deposit. Repeat for multiple ids.
    #[arg(long = "backend", value_name = "ID")]
    backend: Vec<String>,

    /// Existing unlock method: `TYPE[:field=value,...]`.
    #[arg(long = "open", value_name = "METHOD", required = true)]
    open: Vec<OpenArg>,
}

/// `bundle promote` arguments.
#[derive(Debug, clap::Args)]
pub struct PromoteArgs {
    /// Bundle file to review or update in place.
    bundle: PathBuf,

    /// Review without mutating the bundle.
    #[arg(long)]
    dry_run: bool,

    /// Promote only these backend ids. Empty promotes every effective deposit.
    #[arg(long = "backend", value_name = "ID")]
    backend: Vec<String>,

    /// Promote only these contributor ids. Empty promotes every effective deposit.
    #[arg(long = "contributor", value_name = "ID")]
    contributor: Vec<String>,

    /// Existing unlock method: `TYPE[:field=value,...]`.
    #[arg(long = "open", value_name = "METHOD", required = true)]
    open: Vec<OpenArg>,
}

/// `bundle deposit-key` arguments.
#[derive(Debug, clap::Args)]
pub struct DepositKeyArgs {
    /// Bundle file to inspect or update.
    bundle: PathBuf,

    /// Write the public deposit recipient token to this file.
    #[arg(long, value_name = "OUT")]
    out: PathBuf,

    /// Existing unlock method.
    #[arg(long = "open", value_name = "METHOD", required = true)]
    open: Vec<OpenArg>,
}

/// `bundle verify` arguments.
#[derive(Debug, clap::Args)]
pub struct VerifyArgs {
    /// Bundle file to check.
    bundle: PathBuf,

    /// Existing unlock method: `TYPE[:field=value,...]`.
    #[arg(long = "open", value_name = "METHOD", required = true)]
    open: Vec<OpenArg>,
}

/// `bundle show` arguments.
#[derive(Debug, clap::Args)]
pub struct ShowArgs {
    /// Bundle file to inspect.
    bundle: PathBuf,

    /// Existing unlock method. When supplied, backend ids and credential kinds
    /// are shown; secret values are never printed.
    #[arg(long = "open", value_name = "METHOD")]
    open: Vec<OpenArg>,
}

/// Structured `--slot` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotArg {
    kind: SlotKind,
    fields: BTreeMap<String, String>,
}

impl FromStr for SlotArg {
    type Err = String;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        parse_slot_arg(raw).map_err(|e| e.to_string())
    }
}

/// Structured `--open` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenArg(SlotArg);

impl FromStr for OpenArg {
    type Err = String;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        parse_slot_arg(raw).map(OpenArg).map_err(|e| e.to_string())
    }
}

/// Structured `--backend` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendArg {
    id: String,
    kind: BackendKind,
    fields: BTreeMap<String, String>,
}

impl FromStr for BackendArg {
    type Err = String;

    fn from_str(raw: &str) -> std::result::Result<Self, Self::Err> {
        parse_backend_arg(raw).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotKind {
    AgeYubikey,
    Bip39,
    Passphrase,
    Tpm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendKind {
    AwsKms,
    DbKeystore,
    GcpKms,
    OnePassword,
    OpenBao,
    Vault,
}

/// Dispatch a `bundle` subcommand.
pub fn run(cmd: BundleCommand) -> Result<()> {
    match cmd {
        BundleCommand::Create(args) => create(&args),
        BundleCommand::AddSlot(args) => add_slot(&args),
        BundleCommand::SetBackend(args) => set_backend(&args),
        BundleCommand::Deposit(args) => deposit(&args),
        BundleCommand::Allow(args) => allow(&args),
        BundleCommand::Promote(args) => promote(&args),
        BundleCommand::DepositKey(args) => deposit_key(&args),
        BundleCommand::Verify(args) => verify(&args),
        BundleCommand::Show(args) => show(&args),
    }
}

fn create(args: &CreateArgs) -> Result<()> {
    let lock = acquire_bundle_maintenance_lock(&args.bundle)?;
    let source = create_source(args)?;
    if source.slots.is_empty() {
        bail!("create requires at least one --slot or [[slot]] manifest table");
    }
    let slot_methods = slot_methods(&source.slots, SlotUse::Create)?;
    let specs = slot_methods.specs();
    let mut creds = cred_bundle_from_backend_args(&source.backends)?;
    if args.deposit_key.is_some() {
        creds.ensure_deposit_identity();
    }
    let file = seal::seal(&creds, &specs).context("sealing new bundle")?;
    let parsed = format::decode(&file).context("parsing sealed bundle after create")?;
    write_0600(&lock, &file)?;
    lock.write_epoch(parsed.body.header.epoch)
        .context("writing epoch sidecar")?;
    if let Some(path) = &args.deposit_key {
        let recipient = creds
            .deposit_recipient()
            .ok_or_else(|| anyhow::anyhow!("deposit identity was not generated"))?;
        write_public_token(path, &seal::public_key_token(&recipient))?;
    }
    print_generated_phrases(&slot_methods.generated_phrases);
    println!("wrote sealed bundle to {}", args.bundle.display());
    Ok(())
}

fn add_slot(args: &AddSlotArgs) -> Result<()> {
    let lock = acquire_bundle_maintenance_lock(&args.bundle)?;
    let bytes = lock.read_bundle()?;
    let parsed = format::decode(&bytes).context("parsing bundle")?;
    let open_methods = open_methods(&args.open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let new_slot = slot_methods(std::slice::from_ref(&args.slot), SlotUse::Create)?;
    let specs = new_slot.specs();
    let Some(spec) = specs.first() else {
        bail!("add-slot requires one --slot");
    };
    let new_file = seal::add_slot(&parsed, &registry, spec).context("adding bundle slot")?;
    write_0600(&lock, &new_file)?;
    lock.write_epoch(parsed.body.header.epoch)
        .context("writing epoch sidecar")?;
    print_generated_phrases(&new_slot.generated_phrases);
    println!("added slot to {}", args.bundle.display());
    Ok(())
}

fn set_backend(args: &SetBackendArgs) -> Result<()> {
    let lock = acquire_bundle_maintenance_lock(&args.bundle)?;
    let bytes = lock.read_bundle()?;
    let parsed = format::decode(&bytes).context("parsing bundle")?;
    let open_methods = open_methods(&args.open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let mut creds =
        seal::open_bundle(&parsed, &registry).context("opening bundle to update backend")?;
    if matches!(
        creds.backends.get(&args.backend.id),
        Some(BackendCred::DbKeystoreDek { .. })
    ) {
        let backend_id = &args.backend.id;
        bail!(
            "backend `{backend_id}` is a db-keystore credential; replace it with `basil keystore rekey`"
        );
    }
    let (backend_id, cred) = backend_cred(&args.backend)?;
    creds.set(backend_id.clone(), cred);
    let new_file =
        seal::reseal_payload(&parsed, &registry, &creds).context("re-sealing bundle payload")?;
    let new_parsed = format::decode(&new_file).context("parsing updated sealed bundle")?;
    drop(creds);
    write_0600(&lock, &new_file)?;
    lock.write_epoch(new_parsed.body.header.epoch)
        .context("writing epoch sidecar")?;
    println!(
        "updated backend `{}` in {}",
        backend_id,
        args.bundle.display()
    );
    Ok(())
}

fn deposit(args: &DepositArgs) -> Result<()> {
    if args.backend.kind == BackendKind::DbKeystore {
        bail!("db-keystore credentials cannot be supplied through bundle deposits");
    }
    let lock = acquire_bundle_maintenance_lock(&args.bundle)?;
    let bytes = lock.read_bundle()?;
    let mut parsed = format::decode(&bytes).context("parsing bundle")?;
    let recipient = read_public_key_token(&args.recipient)?;
    let signing_seed = read_seed_0600(&args.identity)?;
    let contributor_key_id = args
        .contributor_id
        .clone()
        .unwrap_or_else(|| seal::contributor_public_token(&signing_seed));
    let (backend_id, cred) = backend_cred(&args.backend)?;
    let seq = args.seq.unwrap_or_else(|| {
        next_deposit_seq(&parsed.body.deposits, &contributor_key_id, &backend_id)
    });
    let record = seal::create_signed_record(
        &parsed.body.header,
        backend_id.clone(),
        contributor_key_id.clone(),
        seq,
        &recipient,
        &signing_seed,
        &cred,
    )
    .context("creating signed credential deposit")?;
    parsed.body.deposits.push(record);
    let header_aad = parsed.header_aad().to_vec();
    let file = format::encode_with_deposits(
        &parsed.body.header,
        &header_aad,
        parsed.body.slots,
        parsed.body.payload,
        parsed.body.deposits,
    )
    .context("encoding bundle with deposit")?;
    write_0600(&lock, &file)?;
    println!("deposited backend `{backend_id}` as contributor `{contributor_key_id}` seq {seq}");
    Ok(())
}

fn allow(args: &AllowArgs) -> Result<()> {
    let lock = acquire_bundle_maintenance_lock(&args.bundle)?;
    if args.backend.is_empty() {
        bail!("allow requires at least one --backend ID");
    }
    let bytes = lock.read_bundle()?;
    let parsed = format::decode(&bytes).context("parsing bundle")?;
    let open_methods = open_methods(&args.open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let mut creds =
        seal::open_bundle(&parsed, &registry).context("opening bundle to allow contributor")?;
    creds.ensure_deposit_identity();
    let contributor_id = args
        .contributor_id
        .clone()
        .unwrap_or_else(|| args.contributor.clone());
    let public = seal::public_key_from_token(&args.contributor)
        .context("validating contributor public key")?;
    let public_key = seal::public_key_token(&public);
    let allowed_backend_ids = args.backend.iter().cloned().collect::<BTreeSet<_>>();
    creds.deposit.contributors.insert(
        contributor_id.clone(),
        seal::cred::DepositContributor {
            public_key,
            allowed_backend_ids,
        },
    );
    let new_file =
        seal::reseal_payload(&parsed, &registry, &creds).context("re-sealing allow-list")?;
    write_0600(&lock, &new_file)?;
    println!("allowed contributor `{contributor_id}`");
    Ok(())
}

fn promote(args: &PromoteArgs) -> Result<()> {
    let lock = acquire_bundle_maintenance_lock(&args.bundle)?;
    let bytes = lock.read_bundle()?;
    let parsed = format::decode(&bytes).context("parsing bundle")?;
    let open_methods = open_methods(&args.open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let backend_filter = args.backend.iter().cloned().collect::<BTreeSet<_>>();
    let contributor_filter = args.contributor.iter().cloned().collect::<BTreeSet<_>>();
    if args.dry_run {
        let creds =
            seal::open_bundle(&parsed, &registry).context("opening bundle for promote review")?;
        print_deposit_reviews(&seal::review_deposits(&parsed, &creds));
        return Ok(());
    }
    let baseline =
        seal::open_bundle(&parsed, &registry).context("opening bundle for promote validation")?;
    let reviews = seal::review_deposits(&parsed, &baseline);
    let targets_db_keystore = reviews.iter().any(|review| {
        review.status == DepositStatus::Effective
            && (backend_filter.is_empty() || backend_filter.contains(&review.backend_id))
            && (contributor_filter.is_empty()
                || contributor_filter.contains(&review.contributor_key_id))
            && matches!(
                baseline.backends.get(&review.backend_id),
                Some(BackendCred::DbKeystoreDek { .. })
            )
    });
    drop(baseline);
    if targets_db_keystore {
        bail!(
            "an effective deposit targets an existing db-keystore credential; rotate it with `basil keystore rekey`"
        );
    }
    let (new_file, reviews) =
        seal::promote_deposits(&parsed, &registry, &backend_filter, &contributor_filter)
            .context("promoting deposits")?;
    let new_parsed = format::decode(&new_file).context("parsing promoted bundle")?;
    write_0600(&lock, &new_file)?;
    lock.write_epoch(new_parsed.body.header.epoch)
        .context("writing epoch sidecar")?;
    print_deposit_reviews(&reviews);
    println!("promoted selected deposits in {}", args.bundle.display());
    Ok(())
}

fn deposit_key(args: &DepositKeyArgs) -> Result<()> {
    let lock = acquire_bundle_maintenance_lock(&args.bundle)?;
    let bytes = lock.read_bundle()?;
    let parsed = format::decode(&bytes).context("parsing bundle")?;
    let open_methods = open_methods(&args.open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let mut creds =
        seal::open_bundle(&parsed, &registry).context("opening bundle for deposit-key")?;
    creds.ensure_deposit_identity();
    let recipient = creds
        .deposit_recipient()
        .ok_or_else(|| anyhow::anyhow!("deposit identity was not generated"))?;
    let new_file =
        seal::reseal_payload(&parsed, &registry, &creds).context("re-sealing deposit identity")?;
    write_0600(&lock, &new_file)?;
    write_public_token(&args.out, &seal::public_key_token(&recipient))?;
    println!("wrote deposit recipient to {}", args.out.display());
    Ok(())
}

fn verify(args: &VerifyArgs) -> Result<()> {
    let guard = acquire_bundle_startup_guard(&args.bundle)
        .context("acquiring sealed-bundle verification guard")?;
    let bytes = guard.read_bundle()?;
    let parsed = format::decode(&bytes).context("parsing bundle")?;
    let open_methods = open_methods(&args.open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let creds = seal::open_bundle(&parsed, &registry).context("verifying bundle unlock")?;
    drop(creds);
    guard
        .validate()
        .context("revalidating sealed-bundle verification guard")?;
    drop(guard);
    println!("bundle unlock verified");
    Ok(())
}

fn show(args: &ShowArgs) -> Result<()> {
    let guard = if args.open.is_empty() {
        None
    } else {
        Some(
            acquire_bundle_startup_guard(&args.bundle)
                .context("acquiring sealed-bundle show guard")?,
        )
    };
    let bytes = match &guard {
        Some(guard) => guard.read_bundle()?,
        None => read_bundle(&args.bundle)?,
    };
    let parsed = format::decode(&bytes).context("parsing bundle")?;
    println!("bundle: {}", args.bundle.display());
    println!("epoch: {}", parsed.body.header.epoch);
    println!("slots: {}", parsed.body.slots.len());
    println!("deposits: {}", parsed.body.deposits.len());
    for slot in &parsed.body.slots {
        println!(
            "slot {}: method={}, label={}",
            slot.slot_id, slot.method, slot.label
        );
    }
    if args.open.is_empty() {
        for deposit in &parsed.body.deposits {
            println!(
                "deposit: backend={}, contributor={}, epoch={}, seq={}",
                deposit.backend_id, deposit.contributor_key_id, deposit.epoch, deposit.seq
            );
        }
        return Ok(());
    }
    let open_methods = open_methods(&args.open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let creds = seal::open_bundle(&parsed, &registry).context("opening bundle for show")?;
    println!("backends: {}", creds.backends.len());
    for (id, cred) in &creds.backends {
        println!("backend {}: kind={}", id, cred.kind());
    }
    print_deposit_reviews(&seal::review_deposits(&parsed, &creds));
    drop(creds);
    let guard = guard.context("opened bundle show lost its maintenance guard")?;
    guard
        .validate()
        .context("revalidating sealed-bundle show guard")?;
    drop(guard);
    Ok(())
}

#[derive(Debug)]
struct CreateSource {
    slots: Vec<SlotArg>,
    backends: Vec<BackendArg>,
}

fn create_source(args: &CreateArgs) -> Result<CreateSource> {
    match &args.from {
        Some(path) => {
            if !args.slot.is_empty() || !args.backend.is_empty() {
                bail!("--from cannot be mixed with inline --slot or --backend values");
            }
            create_source_from_manifest(path)
        }
        None => Ok(CreateSource {
            slots: args.slot.clone(),
            backends: args.backend.clone(),
        }),
    }
}

#[derive(Debug, Deserialize)]
struct BundleManifest {
    #[serde(default)]
    slot: Vec<ManifestTable>,
    #[serde(default)]
    backend: Vec<ManifestTable>,
}

#[derive(Debug, Deserialize)]
struct ManifestTable {
    #[serde(rename = "type")]
    kind: String,
    #[serde(flatten)]
    fields: BTreeMap<String, toml::Value>,
}

fn create_source_from_manifest(path: &Path) -> Result<CreateSource> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading bundle manifest {}", path.display()))?;
    let manifest: BundleManifest = toml::from_str(&raw).context("parsing bundle manifest")?;
    let slots = manifest
        .slot
        .iter()
        .map(slot_arg_from_manifest)
        .collect::<Result<Vec<_>>>()?;
    let backends = manifest
        .backend
        .iter()
        .map(backend_arg_from_manifest)
        .collect::<Result<Vec<_>>>()?;
    Ok(CreateSource { slots, backends })
}

fn slot_arg_from_manifest(table: &ManifestTable) -> Result<SlotArg> {
    let fields = manifest_fields(&table.fields)?;
    parse_slot_parts(&table.kind, fields)
}

fn backend_arg_from_manifest(table: &ManifestTable) -> Result<BackendArg> {
    let mut fields = manifest_fields(&table.fields)?;
    fields.insert("type".to_string(), table.kind.clone());
    backend_arg_from_fields(fields)
}

fn manifest_fields(input: &BTreeMap<String, toml::Value>) -> Result<BTreeMap<String, String>> {
    input
        .iter()
        .map(|(key, value)| Ok((key.clone(), toml_value_to_string(value)?)))
        .collect()
}

fn toml_value_to_string(value: &toml::Value) -> Result<String> {
    match value {
        toml::Value::String(s) => Ok(s.clone()),
        toml::Value::Integer(n) => Ok(n.to_string()),
        toml::Value::Boolean(v) => Ok(v.to_string()),
        other => bail!("manifest values must be strings, integers, or booleans, got {other:?}"),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotUse {
    Create,
    Open,
}

struct ConfiguredMethods {
    methods: Vec<Box<dyn UnlockMethod>>,
    labels: Vec<String>,
    generated_phrases: Vec<Zeroizing<String>>,
}

impl ConfiguredMethods {
    fn specs(&self) -> Vec<SlotSpec<'_>> {
        self.methods
            .iter()
            .zip(&self.labels)
            .map(|(method, label)| SlotSpec {
                method: method.as_ref(),
                label: label.clone(),
            })
            .collect()
    }
}

fn slot_methods(slots: &[SlotArg], use_case: SlotUse) -> Result<ConfiguredMethods> {
    let mut methods: Vec<Box<dyn UnlockMethod>> = Vec::with_capacity(slots.len());
    let mut labels = Vec::with_capacity(slots.len());
    #[cfg(feature = "unlock-bip39")]
    let mut generated_phrases = Vec::new();
    #[cfg(not(feature = "unlock-bip39"))]
    let generated_phrases = Vec::new();
    for slot in slots {
        let mut fields = slot.fields.clone();
        let label = take_optional(&mut fields, "label")?.unwrap_or_else(|| slot.default_label());
        match slot.kind {
            SlotKind::Passphrase => {
                let file = take_required(&mut fields, "file")?;
                ensure_no_fields(&fields, "passphrase slot")?;
                methods.push(Box::new(PassphraseMethod::new(read_secret_file(
                    Path::new(&file),
                )?)));
            }
            SlotKind::Bip39 => {
                let file = take_optional(&mut fields, "file")?;
                ensure_no_fields(&fields, "bip39 slot")?;
                let phrase = match (file, use_case) {
                    (Some(file), _) => read_bip39_phrase(Path::new(&file))?,
                    (None, SlotUse::Create) => generated_bip39_phrase()?,
                    (None, SlotUse::Open) => bail!("bip39 --open requires file=PATH"),
                };
                #[cfg(feature = "unlock-bip39")]
                {
                    methods.push(Box::new(Bip39Method::new(phrase.clone())));
                    if use_case == SlotUse::Create && !slot.fields.contains_key("file") {
                        generated_phrases.push(phrase);
                    }
                }
                #[cfg(not(feature = "unlock-bip39"))]
                {
                    let _ = phrase;
                    bail!("bip39 slots require the unlock-bip39 feature");
                }
            }
            SlotKind::AgeYubikey => {
                let recipient = take_optional(&mut fields, "recipient")?.unwrap_or_default();
                ensure_no_fields(&fields, "age-yubikey slot")?;
                #[cfg(feature = "unlock-age-yubikey")]
                {
                    let method = if use_case == SlotUse::Open {
                        AgeYubikeyMethod::with_plugin(recipient, "yubikey")
                            .context("configuring age-yubikey plugin")?
                    } else {
                        AgeYubikeyMethod::for_recipient(recipient)
                    };
                    methods.push(Box::new(method));
                }
                #[cfg(not(feature = "unlock-age-yubikey"))]
                {
                    let _ = recipient;
                    bail!("age-yubikey slots require the unlock-age-yubikey feature");
                }
            }
            SlotKind::Tpm => {
                let pcrs = take_optional(&mut fields, "pcrs")?;
                let bank = take_optional(&mut fields, "bank")?.unwrap_or_else(|| "sha256".into());
                ensure_no_fields(&fields, "tpm slot")?;
                #[cfg(feature = "unlock-tpm")]
                {
                    let pcrs = match pcrs {
                        Some(csv) => parse_pcrs(&csv)?,
                        None => vec![0, 2, 4, 7],
                    };
                    methods.push(Box::new(crate::seal::TpmMethod::from_pcr_config(
                        bank, pcrs,
                    )));
                }
                #[cfg(not(feature = "unlock-tpm"))]
                {
                    let _ = (pcrs, bank);
                    bail!("tpm slots require the unlock-tpm feature");
                }
            }
        }
        labels.push(label);
    }
    Ok(ConfiguredMethods {
        methods,
        labels,
        generated_phrases,
    })
}

fn open_methods(open: &[OpenArg]) -> Result<ConfiguredMethods> {
    let slots: Vec<SlotArg> = open.iter().map(|arg| arg.0.clone()).collect();
    slot_methods(&slots, SlotUse::Open)
}

fn registry_from_methods(methods: &[Box<dyn UnlockMethod>]) -> MethodRegistry<'_> {
    let mut registry = MethodRegistry::new();
    for method in methods {
        registry = registry.with(method.as_ref());
    }
    registry
}

fn print_generated_phrases(phrases: &[Zeroizing<String>]) {
    for phrase in phrases {
        /* ubs:ignore */
        println!("=== BIP39 recovery phrase (store offline, shown once) ===");
        println!("{}", phrase.as_str());
        println!("=========================================================");
    }
}

#[cfg(feature = "unlock-bip39")]
fn generated_bip39_phrase() -> Result<Zeroizing<String>> {
    Bip39Method::generate_phrase().context("generating bip39 phrase")
}

#[cfg(not(feature = "unlock-bip39"))]
fn generated_bip39_phrase() -> Result<Zeroizing<String>> {
    bail!("bip39 slots require the unlock-bip39 feature")
}

fn read_bip39_phrase(path: &Path) -> Result<Zeroizing<String>> {
    let bytes = read_secret_file(path)?;
    Ok(Zeroizing::new(
        String::from_utf8(bytes.to_vec())
            .map_err(|_| anyhow::anyhow!("bip39 phrase file is not UTF-8"))?
            .trim()
            .to_string(),
    ))
}

#[cfg(feature = "unlock-tpm")]
fn parse_pcrs(csv: &str) -> Result<Vec<u32>> {
    csv.split(',')
        .map(|tok| {
            let tok = tok.trim();
            tok.parse::<u32>()
                .with_context(|| format!("invalid PCR index `{tok}` in `{csv}`"))
        })
        .collect()
}

fn cred_bundle_from_backend_args(backends: &[BackendArg]) -> Result<CredBundle> {
    let mut creds = CredBundle::empty();
    for backend in backends {
        let (id, cred) = backend_cred(backend)?;
        creds.set(id, cred);
    }
    Ok(creds)
}

fn backend_cred(backend: &BackendArg) -> Result<(String, BackendCred)> {
    let mut fields = backend.fields.clone();
    let cred = match backend.kind {
        BackendKind::OpenBao | BackendKind::Vault => vault_cred(backend, &mut fields)?,
        BackendKind::OnePassword => onepassword_cred(&mut fields)?,
        BackendKind::AwsKms => aws_kms_cred(&mut fields)?,
        BackendKind::GcpKms => gcp_kms_cred(&mut fields)?,
        BackendKind::DbKeystore => db_keystore_cred(&mut fields)?,
    };
    ensure_no_fields(&fields, "backend")?;
    Ok((backend.id.clone(), cred))
}

fn vault_cred(backend: &BackendArg, fields: &mut BTreeMap<String, String>) -> Result<BackendCred> {
    let addr = take_optional(fields, "addr")?;
    if let Some(addr) = &addr {
        validate_backend_addr(addr)?;
    }
    let token_file = take_optional(fields, "token-file")?;
    let role_id = take_optional(fields, "role-id")?;
    let secret_id_file = take_optional(fields, "secret-id-file")?;
    let spiffe_key_file = take_optional(fields, "spiffe-key-file")?;
    let spiffe_id = take_optional(fields, "spiffe-id")?;
    match (
        token_file,
        role_id,
        secret_id_file,
        spiffe_key_file,
        spiffe_id,
    ) {
        (Some(token_file), None, None, None, None) => Ok(BackendCred::VaultToken {
            token: read_secret_string_0600(Path::new(&token_file))?,
            addr,
        }),
        (None, Some(role_id), Some(secret_id_file), None, None) => {
            ensure_non_empty(&backend.id, "backend id")?;
            ensure_non_empty(&role_id, "role-id")?;
            Ok(BackendCred::VaultAppRole {
                role_id,
                secret_id: read_secret_string_0600(Path::new(&secret_id_file))?,
                addr,
            })
        }
        (None, None, None, Some(spiffe_key_file), Some(spiffe_id)) => {
            ensure_non_empty(&spiffe_id, "spiffe-id")?;
            Ok(BackendCred::SpiffeSigner {
                key_pem: read_secret_string_0600(Path::new(&spiffe_key_file))?,
                spiffe_id,
            })
        }
        _ => bail!(
            "openbao/vault backend requires exactly one credential source: \
             token-file; role-id plus secret-id-file; or spiffe-key-file plus spiffe-id"
        ),
    }
}

/// Reject a backend `addr` that isn't a usable base address before it is sealed
/// into a bundle. Without this, a schemeless value like `127.0.0.1:8200` is
/// accepted here and only surfaces much later as an opaque reqwest "builder
/// error" when the agent first probes the backend.
fn validate_backend_addr(addr: &str) -> Result<()> {
    let url = Url::parse(addr).with_context(|| {
        format!(
            "backend `addr` `{addr}` is not a valid URL \
             (expected e.g. `https://vault.example.com:8200`)"
        )
    })?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => bail!(
            "backend `addr` `{addr}` has unsupported scheme `{other}`; \
             expected `http` or `https` (e.g. `https://vault.example.com:8200`)"
        ),
    }
}

fn onepassword_cred(fields: &mut BTreeMap<String, String>) -> Result<BackendCred> {
    let provider_uri = take_required(fields, "provider-uri")?;
    let project = take_required(fields, "project")?;
    let profile = take_required(fields, "profile")?;
    Ok(BackendCred::OnePassword {
        provider_uri,
        project,
        profile,
    })
}

fn aws_kms_cred(fields: &mut BTreeMap<String, String>) -> Result<BackendCred> {
    let region = take_required(fields, "region")?;
    let profile = take_optional(fields, "profile")?.unwrap_or_default();
    Ok(BackendCred::AwsKms { region, profile })
}

fn gcp_kms_cred(fields: &mut BTreeMap<String, String>) -> Result<BackendCred> {
    let project = take_required(fields, "project")?;
    let location = take_required(fields, "location")?;
    let key_ring = take_required(fields, "key-ring")?;
    let service_account_json = take_optional(fields, "key-file")?
        .map(|path| read_secret_string_0600(Path::new(&path)))
        .transpose()?;
    Ok(BackendCred::GcpKms {
        project,
        location,
        key_ring,
        service_account_json,
    })
}

fn db_keystore_cred(fields: &mut BTreeMap<String, String>) -> Result<BackendCred> {
    let _path = take_required(fields, "path")?;
    let _cipher = take_optional(fields, "cipher")?;
    let dek_file = take_required(fields, "dek-file")?;
    Ok(BackendCred::DbKeystoreDek {
        dek: read_dek_0600(Path::new(&dek_file))?,
    })
}

fn parse_slot_arg(raw: &str) -> Result<SlotArg> {
    let (kind, fields) = raw
        .split_once(':')
        .map_or((raw, ""), |(kind, fields)| (kind, fields));
    parse_slot_parts(kind, parse_key_values(fields)?)
}

fn parse_slot_parts(kind: &str, fields: BTreeMap<String, String>) -> Result<SlotArg> {
    let kind = match kind {
        "age-yubikey" => SlotKind::AgeYubikey,
        "bip39" => SlotKind::Bip39,
        "passphrase" => SlotKind::Passphrase,
        "tpm" => SlotKind::Tpm,
        other => bail!("unknown slot type `{other}`"),
    };
    Ok(SlotArg { kind, fields })
}

fn parse_backend_arg(raw: &str) -> Result<BackendArg> {
    backend_arg_from_fields(parse_key_values(raw)?)
}

fn backend_arg_from_fields(mut fields: BTreeMap<String, String>) -> Result<BackendArg> {
    let id = take_required(&mut fields, "id")?;
    let kind = take_required(&mut fields, "type")?;
    let kind = match kind.as_str() {
        "1password" => BackendKind::OnePassword,
        "aws-kms" => BackendKind::AwsKms,
        "db-keystore" => BackendKind::DbKeystore,
        "gcp-kms" => BackendKind::GcpKms,
        "openbao" => BackendKind::OpenBao,
        "vault" => BackendKind::Vault,
        other => bail!("unknown backend type `{other}`"),
    };
    Ok(BackendArg { id, kind, fields })
}

fn parse_key_values(raw: &str) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    let mut current_key: Option<String> = None;
    if raw.is_empty() {
        return Ok(fields);
    }
    for part in raw.split(',') {
        if let Some((key, value)) = part.split_once('=') {
            ensure_non_empty(key, "field name")?;
            ensure_non_empty(value, key)?;
            if fields.insert(key.to_string(), value.to_string()).is_some() {
                bail!("duplicate field `{key}`");
            }
            current_key = Some(key.to_string());
        } else {
            let Some(key) = current_key.as_deref() else {
                bail!("expected key=value field, got `{part}`");
            };
            if key != "pcrs" {
                bail!("expected key=value field, got `{part}`");
            }
            ensure_non_empty(part, key)?;
            let Some(value) = fields.get_mut(key) else {
                bail!("internal parser error for field `{key}`");
            };
            value.push(',');
            value.push_str(part);
        }
    }
    Ok(fields)
}

fn take_required(fields: &mut BTreeMap<String, String>, key: &str) -> Result<String> {
    let Some(value) = fields.remove(key) else {
        bail!("missing required field `{key}`");
    };
    ensure_non_empty(&value, key)?;
    Ok(value)
}

fn take_optional(fields: &mut BTreeMap<String, String>, key: &str) -> Result<Option<String>> {
    let Some(value) = fields.remove(key) else {
        return Ok(None);
    };
    ensure_non_empty(&value, key)?;
    Ok(Some(value))
}

fn ensure_no_fields(fields: &BTreeMap<String, String>, context: &str) -> Result<()> {
    if let Some(key) = fields.keys().next() {
        bail!("{context} has unsupported field `{key}`");
    }
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{label} must be non-empty");
    }
    Ok(())
}

impl SlotArg {
    fn default_label(&self) -> String {
        match self.kind {
            SlotKind::AgeYubikey => "age-yubikey",
            SlotKind::Bip39 => "break-glass",
            SlotKind::Passphrase => "passphrase",
            SlotKind::Tpm => "tpm",
        }
        .to_string()
    }
}

fn read_bundle(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading bundle {}", path.display()))
}

/// Read a secret file into a zeroizing buffer, trimming one trailing newline.
fn read_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes =
        Zeroizing::new(std::fs::read(path).with_context(|| format!("reading {}", path.display()))?);
    /* ubs false positive: timing-constant equality check not required here */
    /* ubs:ignore */
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    /* ubs:ignore */
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    Ok(bytes)
}

fn read_secret_string(path: &Path) -> Result<SecretString> {
    let bytes = read_secret_file(path)?;
    Ok(SecretString::new(
        String::from_utf8(bytes.to_vec())
            .map_err(|_| anyhow::anyhow!("secret file not UTF-8"))?
            .trim()
            .to_string(),
    ))
}

fn read_secret_string_0600(path: &Path) -> Result<SecretString> {
    require_0600(path)?;
    read_secret_string(path)
}

pub(crate) fn read_dek_0600(path: &Path) -> Result<SecretArray<32>> {
    require_0600(path)?;
    let bytes = Zeroizing::new(
        std::fs::read(path).with_context(|| format!("reading raw DEK {}", path.display()))?,
    );
    let dek = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("db-keystore DEK file must contain exactly 32 raw bytes"))?;
    Ok(SecretArray::new(dek))
}

fn read_seed_0600(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    require_0600(path)?;
    let bytes = read_secret_file(path)?;
    let seed = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("Ed25519 identity file must contain exactly 32 bytes"))?;
    Ok(Zeroizing::new(seed))
}

fn read_public_key_token(path: &Path) -> Result<[u8; 32]> {
    let token = std::fs::read_to_string(path)
        .with_context(|| format!("reading deposit recipient {}", path.display()))?;
    Ok(seal::public_key_from_token(token.trim())?)
}

fn write_public_token(path: &Path, token: &str) -> Result<()> {
    std::fs::write(path, format!("{token}\n"))
        .with_context(|| format!("writing public token {}", path.display()))
}

fn next_deposit_seq(
    deposits: &[format::DepositRecord],
    contributor_key_id: &str,
    backend_id: &str,
) -> u64 {
    deposits
        .iter()
        .filter(|deposit| {
            deposit.contributor_key_id == contributor_key_id && deposit.backend_id == backend_id
        })
        .map(|deposit| deposit.seq)
        .max()
        .map_or(1, |seq| seq.saturating_add(1))
}

fn print_deposit_reviews(reviews: &[seal::DepositReview]) {
    for review in reviews {
        let fingerprint = review.fingerprint.as_deref().unwrap_or("-");
        println!(
            "deposit {}: backend={}, contributor={}, epoch={}, seq={}, status={}, action={}, fingerprint={}",
            review.index,
            review.backend_id,
            review.contributor_key_id,
            review.epoch,
            review.seq,
            review.status.as_str(),
            review.action.as_str(),
            fingerprint
        );
    }
}

#[cfg(unix)]
fn require_0600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("stat secret file {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        bail!(
            "secret file {} has mode {:o}, expected 0600",
            path.display(),
            mode
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_0600(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("secret file {} is not a file", path.display());
    }
    Ok(())
}

struct BundleTarget {
    parent: OwnedFd,
    file_name: OsString,
}

struct ProtectedInput {
    bytes: Vec<u8>,
    modified: std::time::SystemTime,
    mode: u32,
}

impl BundleTarget {
    fn new(path: &Path) -> Result<Self> {
        let file_name = path
            .file_name()
            .context("bundle path has no file name")?
            .to_os_string();
        let parent = pin_bundle_parent(normalized_bundle_parent(path))?;
        Ok(Self { parent, file_name })
    }

    fn read_bundle(&self) -> Result<Vec<u8>> {
        Ok(self
            .read_checked(&self.file_name, MAX_BUNDLE_BYTES, "sealed bundle")?
            .bytes)
    }

    fn read_bundle_for_startup(&self) -> Result<(Vec<u8>, std::time::SystemTime, u32)> {
        let input = self
            .read_checked_optional_with_policy(
                &self.file_name,
                MAX_BUNDLE_BYTES,
                "sealed bundle",
                false,
            )?
            .context("sealed bundle is missing")?;
        Ok((input.bytes, input.modified, input.mode))
    }

    fn read_epoch(&self) -> Result<Option<u64>> {
        let name = suffixed_bundle_name(&self.file_name, ".epoch");
        let Some(input) = self.read_checked_optional(&name, MAX_EPOCH_BYTES, "epoch sidecar")?
        else {
            return Ok(None);
        };
        let raw = std::str::from_utf8(&input.bytes).context("epoch sidecar is not UTF-8")?;
        let epoch = raw
            .trim()
            .parse::<u64>()
            .context("epoch sidecar is not an unsigned integer")?;
        Ok(Some(epoch))
    }

    fn read_checked(&self, name: &OsStr, max_bytes: u64, label: &str) -> Result<ProtectedInput> {
        self.read_checked_optional(name, max_bytes, label)?
            .with_context(|| format!("{label} is missing"))
    }

    fn read_checked_optional(
        &self,
        name: &OsStr,
        max_bytes: u64,
        label: &str,
    ) -> Result<Option<ProtectedInput>> {
        self.read_checked_optional_with_policy(name, max_bytes, label, true)
    }

    fn read_checked_optional_with_policy(
        &self,
        name: &OsStr,
        max_bytes: u64,
        label: &str,
        require_owner_only: bool,
    ) -> Result<Option<ProtectedInput>> {
        let fd = match rustix::fs::openat(
            &self.parent,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(bundle_fs_error("opening protected input", error)),
        };
        let stat = rustix::fs::fstat(&fd)
            .map_err(|error| bundle_fs_error("inspecting protected input", error))?;
        validate_owner_regular(&stat, label)?;
        if require_owner_only && stat.st_mode & 0o077 != 0 {
            bail!("{label} must not grant group or other permissions");
        }
        let size = u64::try_from(stat.st_size).unwrap_or(u64::MAX);
        if size > max_bytes {
            bail!("{label} exceeds the {max_bytes}-byte limit");
        }
        let file = std::fs::File::from(fd);
        let modified = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .with_context(|| format!("reading {label} modification time"))?;
        let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {label}"))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
            bail!("{label} exceeds the {max_bytes}-byte limit");
        }
        let entry = rustix::fs::statat(&self.parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| bundle_fs_error("revalidating protected input", error))?;
        if entry.st_dev != stat.st_dev || entry.st_ino != stat.st_ino {
            bail!("{label} changed while it was being read");
        }
        Ok(Some(ProtectedInput {
            bytes,
            modified,
            mode: stat.st_mode & 0o777,
        }))
    }

    fn open_lock(&self) -> Result<std::fs::File> {
        let name = suffixed_bundle_name(&self.file_name, ".basil-lock");
        let fd = rustix::fs::openat(
            &self.parent,
            &name,
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .map_err(|error| bundle_fs_error("opening bundle maintenance lock", error))?;
        let stat = rustix::fs::fstat(&fd)
            .map_err(|error| bundle_fs_error("inspecting bundle maintenance lock", error))?;
        validate_lock_metadata(&stat)?;
        Ok(std::fs::File::from(fd))
    }

    fn validate_lock_entry(&self, file: &std::fs::File) -> Result<()> {
        let name = suffixed_bundle_name(&self.file_name, ".basil-lock");
        let entry = rustix::fs::statat(&self.parent, &name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| bundle_fs_error("revalidating bundle maintenance lock", error))?;
        let held = rustix::fs::fstat(file)
            .map_err(|error| bundle_fs_error("inspecting held bundle maintenance lock", error))?;
        validate_lock_metadata(&held)?;
        if entry.st_dev != held.st_dev || entry.st_ino != held.st_ino {
            bail!("bundle maintenance lock path changed after acquisition");
        }
        Ok(())
    }

    fn write_bundle(&self, bytes: &[u8]) -> Result<()> {
        self.write_name(&self.file_name, bytes, "sealed bundle")
    }

    fn write_epoch(&self, epoch: u64) -> Result<()> {
        self.write_name(
            &suffixed_bundle_name(&self.file_name, ".epoch"),
            format!("{epoch}\n").as_bytes(),
            "epoch sidecar",
        )
    }

    fn write_name(&self, destination: &OsStr, bytes: &[u8], label: &str) -> Result<()> {
        let mut rng = rand::rngs::OsRng;
        for _ in 0..32 {
            let mut entropy = [0u8; 8];
            rng.try_fill_bytes(&mut entropy)
                .with_context(|| format!("generating {label} temporary name"))?;
            let temporary = suffixed_bundle_name(
                destination,
                &format!(
                    ".basil-write-{}-{:016x}.tmp",
                    std::process::id(),
                    u64::from_le_bytes(entropy)
                ),
            );
            let owned = match rustix::fs::openat(
                &self.parent,
                &temporary,
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::from_raw_mode(0o600),
            ) {
                Ok(owned) => owned,
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(bundle_fs_error("opening private temporary file", error)),
            };
            let mut temporary_file = std::fs::File::from(owned);
            let result = (|| {
                temporary_file
                    .write_all(bytes)
                    .with_context(|| format!("writing private {label} temporary file"))?;
                temporary_file
                    .sync_all()
                    .with_context(|| format!("syncing private {label} temporary file"))?;
                drop(temporary_file);
                rustix::fs::renameat(&self.parent, &temporary, &self.parent, destination)
                    .map_err(|error| bundle_fs_error("replacing protected file", error))?;
                rustix::fs::fsync(&self.parent)
                    .map_err(|error| bundle_fs_error("syncing protected parent", error))
            })();
            if result.is_err() {
                let _ =
                    rustix::fs::unlinkat(&self.parent, &temporary, rustix::fs::AtFlags::empty());
            }
            return result;
        }
        bail!("could not allocate a private {label} temporary file")
    }
}

fn normalized_bundle_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn pin_bundle_parent(path: &Path) -> Result<OwnedFd> {
    use std::path::Component;

    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NOFOLLOW;
    let mut directory = rustix::fs::open(
        if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        },
        flags,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| bundle_fs_error("opening bundle path root", error))?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = rustix::fs::openat(&directory, name, flags, rustix::fs::Mode::empty())
                    .map_err(|error| bundle_fs_error("opening bundle parent component", error))?;
            }
            Component::ParentDir => bail!("bundle parent may not contain `..`"),
            Component::Prefix(_) => bail!("bundle path prefix is unsupported"),
        }
    }
    Ok(directory)
}

fn validate_owner_only_regular(stat: &rustix::fs::Stat, label: &str) -> Result<()> {
    validate_owner_regular(stat, label)?;
    if stat.st_mode & 0o077 != 0 {
        bail!("{label} must not grant group or other permissions");
    }
    Ok(())
}

fn validate_owner_regular(stat: &rustix::fs::Stat, label: &str) -> Result<()> {
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile {
        bail!("{label} is not a regular file");
    }
    if stat.st_uid != rustix::process::geteuid().as_raw() {
        bail!("{label} is not owned by the current user");
    }
    Ok(())
}

fn validate_lock_metadata(stat: &rustix::fs::Stat) -> Result<()> {
    validate_owner_only_regular(stat, "bundle maintenance lock")?;
    if stat.st_nlink != 1 {
        bail!("bundle maintenance lock must have exactly one link");
    }
    Ok(())
}

fn bundle_fs_error(operation: &str, error: rustix::io::Errno) -> anyhow::Error {
    anyhow::anyhow!("{operation}: {error}")
}

fn suffixed_bundle_name(name: &OsStr, suffix: &str) -> OsString {
    let mut value = name.to_os_string();
    value.push(suffix);
    value
}

pub(crate) struct BundleMaintenanceLock {
    target: BundleTarget,
    file: std::fs::File,
}

pub(crate) struct BundleStartupGuard {
    target: BundleTarget,
    file: std::fs::File,
}

impl BundleStartupGuard {
    pub(crate) fn read_bundle(&self) -> Result<Vec<u8>> {
        self.target.validate_lock_entry(&self.file)?;
        self.target.read_bundle()
    }

    pub(crate) fn read_bundle_for_startup(&self) -> Result<(Vec<u8>, std::time::SystemTime, u32)> {
        self.target.validate_lock_entry(&self.file)?;
        self.target.read_bundle_for_startup()
    }

    pub(crate) fn verify_and_advance_epoch(&self, current: u64) -> Result<()> {
        self.target.validate_lock_entry(&self.file)?;
        if let Some(seen) = self.target.read_epoch()? {
            if current < seen {
                bail!("bundle epoch rollback: current {current}, last seen {seen}");
            }
            if current == seen {
                return Ok(());
            }
        }
        self.target.write_epoch(current)?;
        self.target.validate_lock_entry(&self.file)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.target.validate_lock_entry(&self.file)
    }
}

impl BundleMaintenanceLock {
    fn read_bundle(&self) -> Result<Vec<u8>> {
        self.target.validate_lock_entry(&self.file)?;
        self.target.read_bundle()
    }

    fn read_epoch(&self) -> Result<Option<u64>> {
        self.target.validate_lock_entry(&self.file)?;
        self.target.read_epoch()
    }

    fn write_bundle(&self, bytes: &[u8]) -> Result<()> {
        self.target.validate_lock_entry(&self.file)?;
        self.target.write_bundle(bytes)
    }

    fn write_epoch(&self, epoch: u64) -> Result<()> {
        self.target.validate_lock_entry(&self.file)?;
        self.target.write_epoch(epoch)
    }
}

impl Drop for BundleMaintenanceLock {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

impl Drop for BundleStartupGuard {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.file, rustix::fs::FlockOperation::Unlock);
    }
}

pub(crate) fn acquire_bundle_maintenance_lock(path: &Path) -> Result<BundleMaintenanceLock> {
    let target = BundleTarget::new(path)?;
    let file = target.open_lock()?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
        .with_context(|| {
            format!(
                "locking bundle {}; another bundle operation may be active",
                path.display()
            )
        })?;
    target.validate_lock_entry(&file)?;
    Ok(BundleMaintenanceLock { target, file })
}

pub(crate) fn acquire_bundle_startup_guard(path: &Path) -> Result<BundleStartupGuard> {
    let target = BundleTarget::new(path)?;
    let file = target.open_lock()?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockShared)
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))
        .with_context(|| {
            format!(
                "locking bundle {} for startup; a bundle operation may be active",
                path.display()
            )
        })?;
    target.validate_lock_entry(&file)?;
    Ok(BundleStartupGuard { target, file })
}

#[cfg(test)]
fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = OsString::from(path.as_os_str());
    value.push(suffix);
    PathBuf::from(value)
}

/// Atomically write bundle bytes relative to the lock's pinned parent.
fn write_0600(lock: &BundleMaintenanceLock, bytes: &[u8]) -> Result<()> {
    lock.write_bundle(bytes)
}

#[cfg(test)]
fn epoch_sidecar_path(bundle_path: &Path) -> PathBuf {
    let mut path = OsString::from(bundle_path.as_os_str());
    path.push(".epoch");
    PathBuf::from(path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleRekeyBinding {
    pub(crate) bundle_id: [u8; 16],
    pub(crate) backend_id: String,
    pub(crate) pre_epoch: u64,
    pub(crate) post_epoch: u64,
    pub(crate) pre_bundle_b3: [u8; 32],
    pub(crate) post_bundle_b3: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleRekeyIdentity {
    pub(crate) bundle_id: [u8; 16],
    pub(crate) backend_id: String,
    pub(crate) epoch: u64,
    pub(crate) bundle_b3: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BundleCommitCheckpoint {
    BeforeBundleReplace,
    AfterBundleReplace,
    BeforeEpochWrite,
    AfterEpochWrite,
}

trait BundleCommitObserver {
    fn checkpoint(&mut self, checkpoint: BundleCommitCheckpoint) -> Result<()>;
}

struct NoopBundleCommitObserver;

impl BundleCommitObserver for NoopBundleCommitObserver {
    fn checkpoint(&mut self, _checkpoint: BundleCommitCheckpoint) -> Result<()> {
        Ok(())
    }
}

pub(crate) struct PreparedBundleRekey {
    lock: BundleMaintenanceLock,
    binding: BundleRekeyBinding,
    observed_epoch_sidecar: Option<u64>,
    post_bytes: Vec<u8>,
    committed: bool,
    observer: Box<dyn BundleCommitObserver>,
}

impl std::fmt::Debug for PreparedBundleRekey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedBundleRekey")
            .field("binding", &self.binding)
            .field("observed_epoch_sidecar", &self.observed_epoch_sidecar)
            .field("committed", &self.committed)
            .finish_non_exhaustive()
    }
}

impl PreparedBundleRekey {
    pub(crate) const fn binding(&self) -> &BundleRekeyBinding {
        &self.binding
    }

    #[cfg(test)]
    const fn observed_epoch_sidecar(&self) -> Option<u64> {
        self.observed_epoch_sidecar
    }

    pub(crate) fn commit_bundle(&mut self) -> Result<()> {
        if self.committed {
            bail!("prepared bundle transition was already committed");
        }
        self.observer
            .checkpoint(BundleCommitCheckpoint::BeforeBundleReplace)?;
        self.lock.write_bundle(&self.post_bytes)?;
        self.committed = true;
        self.observer
            .checkpoint(BundleCommitCheckpoint::AfterBundleReplace)
    }

    pub(crate) fn write_epoch_sidecar(&mut self) -> Result<()> {
        if !self.committed {
            bail!("bundle epoch sidecar cannot advance before bundle commit");
        }
        self.observer
            .checkpoint(BundleCommitCheckpoint::BeforeEpochWrite)?;
        self.lock.write_epoch(self.binding.post_epoch)?;
        self.observer
            .checkpoint(BundleCommitCheckpoint::AfterEpochWrite)
    }
}

pub(crate) struct LockedBundleRekeyState {
    lock: BundleMaintenanceLock,
    identity: BundleRekeyIdentity,
    observed_epoch_sidecar: Option<u64>,
}

impl std::fmt::Debug for LockedBundleRekeyState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LockedBundleRekeyState")
            .field("identity", &self.identity)
            .field("observed_epoch_sidecar", &self.observed_epoch_sidecar)
            .finish_non_exhaustive()
    }
}

impl LockedBundleRekeyState {
    pub(crate) const fn identity(&self) -> &BundleRekeyIdentity {
        &self.identity
    }

    pub(crate) const fn observed_epoch_sidecar(&self) -> Option<u64> {
        self.observed_epoch_sidecar
    }

    pub(crate) fn write_epoch_sidecar(&self, epoch: u64) -> Result<()> {
        self.lock.write_epoch(epoch)
    }
}

fn authenticate_prepared_rekey_bundle(
    pre: &format::ParsedBundle,
    registry: &MethodRegistry<'_>,
    creds: &CredBundle,
    post_bytes: &[u8],
    backend_id: &str,
) -> Result<format::ParsedBundle> {
    let post = format::decode(post_bytes).context("parsing prepared keystore rekey bundle")?;
    if post.body.header.bundle_id != pre.body.header.bundle_id {
        bail!("prepared bundle changed its authenticated bundle id");
    }
    let expected_post_epoch = pre
        .body
        .header
        .epoch
        .checked_add(1)
        .context("bundle epoch overflow")?;
    if post.body.header.epoch != expected_post_epoch {
        bail!("prepared bundle did not advance exactly one epoch");
    }
    if post
        .body
        .deposits
        .iter()
        .any(|deposit| deposit.backend_id == backend_id)
    {
        bail!("prepared bundle retained a deposit for the rekeyed backend");
    }

    let mut reopened = seal::open_bundle(&post, registry)
        .context("authenticating prepared keystore rekey bundle")?;
    let post_reviews = seal::apply_authorized_deposits(&post, &mut reopened);
    if post_reviews
        .iter()
        .any(|review| review.status == DepositStatus::Effective)
    {
        bail!("prepared bundle retained an effective credential deposit");
    }
    let Some(BackendCred::DbKeystoreDek {
        dek: expected_new_dek,
    }) = creds.backends.get(backend_id)
    else {
        bail!("prepared source state lost the replacement db-keystore credential");
    };
    let reopened_new_dek = match reopened.backends.get(backend_id) {
        Some(BackendCred::DbKeystoreDek { dek }) => dek,
        Some(other) => {
            let kind = other.kind();
            bail!("prepared bundle reopened backend `{backend_id}` as `{kind}`");
        }
        None => bail!("prepared bundle reopened without backend `{backend_id}`"),
    };
    if reopened_new_dek.expose_secret() != expected_new_dek.expose_secret() {
        bail!("prepared bundle did not retain the replacement db-keystore credential");
    }
    drop(reopened);
    Ok(post)
}

pub(crate) fn prepare_db_keystore_rekey(
    bundle_path: &Path,
    backend_id: &str,
    open: &[OpenArg],
    new_dek: SecretArray<32>,
) -> Result<(SecretArray<32>, PreparedBundleRekey)> {
    prepare_db_keystore_rekey_with_observer(
        bundle_path,
        backend_id,
        open,
        new_dek,
        Box::new(NoopBundleCommitObserver),
    )
}

fn prepare_db_keystore_rekey_with_observer(
    bundle_path: &Path,
    backend_id: &str,
    open: &[OpenArg],
    new_dek: SecretArray<32>,
    observer: Box<dyn BundleCommitObserver>,
) -> Result<(SecretArray<32>, PreparedBundleRekey)> {
    let lock = acquire_bundle_maintenance_lock(bundle_path)?;
    let pre_bytes = lock.read_bundle()?;
    let parsed = format::decode(&pre_bytes).context("parsing bundle for keystore rekey")?;
    let open_methods = open_methods(open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let mut creds =
        seal::open_bundle(&parsed, &registry).context("opening bundle for keystore rekey")?;
    let reviews = seal::apply_authorized_deposits(&parsed, &mut creds);
    let old_cred = creds
        .backends
        .remove(backend_id)
        .with_context(|| format!("bundle has no credential for backend `{backend_id}`"))?;
    let old_dek = match old_cred {
        BackendCred::DbKeystoreDek { dek } => dek,
        other => {
            let kind = other.kind();
            drop(other);
            bail!(
                "bundle backend `{backend_id}` has credential kind `{kind}`, expected `db-keystore-dek`"
            );
        }
    };
    let replaced = creds.backends.insert(
        backend_id.to_owned(),
        BackendCred::DbKeystoreDek { dek: new_dek },
    );
    if replaced.is_some() {
        drop(replaced);
        bail!("bundle backend changed while preparing keystore rekey");
    }
    let effective_deposits = reviews
        .iter()
        .filter(|review| review.status == DepositStatus::Effective)
        .map(|review| review.index)
        .collect::<BTreeSet<_>>();
    let retained_deposits = parsed
        .body
        .deposits
        .iter()
        .enumerate()
        .filter(|(index, deposit)| {
            !effective_deposits.contains(index) && deposit.backend_id != backend_id
        })
        .map(|(_, deposit)| deposit.clone())
        .collect();
    let post_bytes = seal::reseal_payload_bump_epoch_with_deposits(
        &parsed,
        &registry,
        &creds,
        retained_deposits,
    )
    .context("re-sealing bundle for keystore rekey")?;
    let post_parsed =
        authenticate_prepared_rekey_bundle(&parsed, &registry, &creds, &post_bytes, backend_id)?;
    drop(creds);
    let observed_epoch_sidecar = lock.read_epoch()?;
    if observed_epoch_sidecar.is_some_and(|seen| seen > parsed.body.header.epoch) {
        bail!("bundle epoch is older than its protected epoch sidecar");
    }
    let binding = BundleRekeyBinding {
        bundle_id: parsed.body.header.bundle_id,
        backend_id: backend_id.to_owned(),
        pre_epoch: parsed.body.header.epoch,
        post_epoch: post_parsed.body.header.epoch,
        pre_bundle_b3: *blake3::hash(&pre_bytes).as_bytes(),
        post_bundle_b3: *blake3::hash(&post_bytes).as_bytes(),
    };
    Ok((
        old_dek,
        PreparedBundleRekey {
            lock,
            binding,
            observed_epoch_sidecar,
            post_bytes,
            committed: false,
            observer,
        },
    ))
}

pub(crate) fn resume_db_keystore_rekey(
    bundle_path: &Path,
    backend_id: &str,
    open: &[OpenArg],
) -> Result<LockedBundleRekeyState> {
    let lock = acquire_bundle_maintenance_lock(bundle_path)?;
    let bytes = lock.read_bundle()?;
    let parsed = format::decode(&bytes).context("parsing bundle for keystore rekey resume")?;
    let open_methods = open_methods(open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let mut creds = seal::open_bundle(&parsed, &registry)
        .context("opening bundle for keystore rekey resume")?;
    let _reviews = seal::apply_authorized_deposits(&parsed, &mut creds);
    let credential = creds
        .backends
        .get(backend_id)
        .with_context(|| format!("bundle has no credential for backend `{backend_id}`"))?;
    if !matches!(credential, BackendCred::DbKeystoreDek { .. }) {
        let kind = credential.kind();
        bail!(
            "bundle backend `{backend_id}` has credential kind `{kind}`, expected `db-keystore-dek`"
        );
    }
    drop(creds);
    let observed_epoch_sidecar = lock.read_epoch()?;
    Ok(LockedBundleRekeyState {
        lock,
        identity: BundleRekeyIdentity {
            bundle_id: parsed.body.header.bundle_id,
            backend_id: backend_id.to_owned(),
            epoch: parsed.body.header.epoch,
            bundle_b3: *blake3::hash(&bytes).as_bytes(),
        },
        observed_epoch_sidecar,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::too_many_lines, clippy::unwrap_used)]

    use super::*;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt as _;

    fn temp_path(name: &str) -> PathBuf {
        let unique = format!(
            "basil-bundle-cli-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    fn write_secret_file(path: &Path, contents: &[u8]) {
        std::fs::write(path, contents).expect("write secret file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod secret file");
        }
    }

    fn db_bundle_fixture(bundle: &Path, passphrase_file: &Path, dek: [u8; 32]) -> Vec<u8> {
        write_secret_file(passphrase_file, b"test passphrase\n");
        let passphrase = PassphraseMethod::with_params(
            Zeroizing::new(b"test passphrase".to_vec()),
            seal::Argon2Params {
                m_cost_kib: 256,
                t_cost: 1,
                p_cost: 1,
            },
        );
        let mut creds = CredBundle::empty();
        creds.set(
            "local",
            BackendCred::DbKeystoreDek {
                dek: SecretArray::new(dek),
            },
        );
        let bytes = seal::seal(
            &creds,
            &[SlotSpec {
                method: &passphrase,
                label: "test".to_owned(),
            }],
        )
        .expect("seal db bundle");
        let parsed = format::decode(&bytes).expect("parse db bundle");
        let lock = acquire_bundle_maintenance_lock(bundle).expect("lock db bundle");
        lock.write_bundle(&bytes).expect("write db bundle");
        lock.write_epoch(parsed.body.header.epoch)
            .expect("write db bundle epoch");
        drop(lock);
        bytes
    }

    fn db_bundle_with_effective_deposit(
        bundle: &Path,
        passphrase_file: &Path,
        baseline_dek: [u8; 32],
        deposited_dek: [u8; 32],
    ) -> Vec<u8> {
        write_secret_file(passphrase_file, b"test passphrase\n");
        let passphrase = PassphraseMethod::with_params(
            Zeroizing::new(b"test passphrase".to_vec()),
            seal::Argon2Params {
                m_cost_kib: 256,
                t_cost: 1,
                p_cost: 1,
            },
        );
        let signing_seed = Zeroizing::new([0x51; 32]);
        let contributor = seal::contributor_public_token(&signing_seed);
        let mut creds = CredBundle::empty();
        creds.set(
            "local",
            BackendCred::DbKeystoreDek {
                dek: SecretArray::new(baseline_dek),
            },
        );
        creds.ensure_deposit_identity();
        creds.deposit.contributors.insert(
            contributor.clone(),
            seal::cred::DepositContributor {
                public_key: contributor.clone(),
                allowed_backend_ids: BTreeSet::from(["local".to_owned()]),
            },
        );
        let baseline = seal::seal(
            &creds,
            &[SlotSpec {
                method: &passphrase,
                label: "test".to_owned(),
            }],
        )
        .expect("seal baseline");
        let parsed = format::decode(&baseline).expect("parse baseline");
        let recipient = creds.deposit_recipient().expect("deposit recipient");
        let record = seal::create_signed_record(
            &parsed.body.header,
            "local".to_owned(),
            contributor,
            1,
            &recipient,
            &signing_seed,
            &BackendCred::DbKeystoreDek {
                dek: SecretArray::new(deposited_dek),
            },
        )
        .expect("create db-keystore deposit");
        let bytes = format::encode_with_deposits(
            &parsed.body.header,
            parsed.header_aad(),
            parsed.body.slots.clone(),
            parsed.body.payload.clone(),
            vec![record],
        )
        .expect("encode deposited bundle");
        let lock = acquire_bundle_maintenance_lock(bundle).expect("lock bundle");
        lock.write_bundle(&bytes).expect("write deposited bundle");
        lock.write_epoch(parsed.body.header.epoch)
            .expect("write deposited epoch");
        drop(lock);
        bytes
    }

    fn passphrase_open(path: &Path) -> OpenArg {
        format!("passphrase:file={}", path.display())
            .parse()
            .expect("passphrase open argument")
    }

    struct RecordingCommitObserver {
        checkpoints: std::rc::Rc<std::cell::RefCell<Vec<BundleCommitCheckpoint>>>,
        fail_at: Option<BundleCommitCheckpoint>,
    }

    impl BundleCommitObserver for RecordingCommitObserver {
        fn checkpoint(&mut self, checkpoint: BundleCommitCheckpoint) -> Result<()> {
            self.checkpoints.borrow_mut().push(checkpoint);
            if self.fail_at == Some(checkpoint) {
                bail!("injected bundle commit checkpoint failure");
            }
            Ok(())
        }
    }

    struct AcknowledgedCommitObserver {
        acknowledge_path: PathBuf,
    }

    impl BundleCommitObserver for AcknowledgedCommitObserver {
        fn checkpoint(&mut self, checkpoint: BundleCommitCheckpoint) -> Result<()> {
            use std::io::Write as _;

            if checkpoint != BundleCommitCheckpoint::AfterBundleReplace {
                return Ok(());
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&self.acknowledge_path)
                .context("creating post-commit acknowledgement")?;
            file.write_all(b"bundle-committed\n")
                .context("writing post-commit acknowledgement")?;
            file.sync_all()
                .context("syncing post-commit acknowledgement")?;
            let parent = self
                .acknowledge_path
                .parent()
                .context("post-commit acknowledgement has no parent")?;
            std::fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .context("syncing post-commit acknowledgement parent")?;
            loop {
                std::thread::park();
            }
        }
    }

    #[test]
    fn bundle_maintenance_lock_serializes_writers() {
        let bundle = temp_path("maintenance-lock");
        let first = acquire_bundle_maintenance_lock(&bundle).expect("first lock");
        assert!(acquire_bundle_maintenance_lock(&bundle).is_err());
        drop(first);
        acquire_bundle_maintenance_lock(&bundle).expect("lock after release");
        let _ = std::fs::remove_file(append_path_suffix(&bundle, ".basil-lock"));
    }

    #[test]
    fn startup_guard_and_maintenance_lock_fail_closed_without_waiting() {
        let bundle = temp_path("startup-maintenance-lock-order");
        let startup = acquire_bundle_startup_guard(&bundle).expect("startup guard");
        assert!(acquire_bundle_maintenance_lock(&bundle).is_err());
        drop(startup);

        let maintenance = acquire_bundle_maintenance_lock(&bundle).expect("maintenance lock");
        assert!(acquire_bundle_startup_guard(&bundle).is_err());
        drop(maintenance);
        acquire_bundle_startup_guard(&bundle).expect("startup guard after maintenance release");
        let _ = std::fs::remove_file(append_path_suffix(&bundle, ".basil-lock"));
    }

    #[cfg(unix)]
    #[test]
    fn bundle_maintenance_lock_rejects_hardlinked_inode() {
        let bundle = temp_path("maintenance-lock-hardlink");
        let lock_path = append_path_suffix(&bundle, ".basil-lock");
        let alias = temp_path("maintenance-lock-hardlink-alias");
        write_secret_file(&lock_path, b"");
        std::fs::hard_link(&lock_path, &alias).expect("hardlink lock");

        assert!(acquire_bundle_maintenance_lock(&bundle).is_err());

        let _ = std::fs::remove_file(lock_path);
        let _ = std::fs::remove_file(alias);
    }

    #[cfg(unix)]
    #[test]
    fn held_lock_path_replacement_stops_protected_writes() {
        let bundle = temp_path("maintenance-lock-replacement");
        let lock_path = append_path_suffix(&bundle, ".basil-lock");
        let lock = acquire_bundle_maintenance_lock(&bundle).expect("maintenance lock");
        lock.write_bundle(b"baseline").expect("write baseline");
        std::fs::remove_file(&lock_path).expect("unlink held lock path");
        write_secret_file(&lock_path, b"replacement");

        assert!(lock.write_bundle(b"must-not-commit").is_err());
        assert_eq!(std::fs::read(&bundle).expect("read bundle"), b"baseline");

        drop(lock);
        let _ = std::fs::remove_file(bundle);
        let _ = std::fs::remove_file(lock_path);
    }

    #[cfg(unix)]
    #[test]
    fn bundle_maintenance_lock_rejects_preplaced_symlink() {
        use std::os::unix::fs::symlink;

        let directory = temp_path("maintenance-lock-symlink");
        std::fs::create_dir(&directory).expect("create lock test directory");
        let bundle = directory.join("creds.sealed");
        let victim = directory.join("victim");
        std::fs::write(&victim, b"do-not-touch").expect("write lock symlink target");
        symlink(&victim, append_path_suffix(&bundle, ".basil-lock"))
            .expect("preplace lock symlink");

        assert!(acquire_bundle_maintenance_lock(&bundle).is_err());
        assert_eq!(
            std::fs::read(&victim).expect("read lock symlink target"),
            b"do-not-touch"
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn bare_relative_bundle_and_sidecar_create_and_mutate() {
        const CHILD_ENV: &str = "BASIL_RELATIVE_BUNDLE_WRITER_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let bundle = Path::new("creds.sealed");
            let lock = acquire_bundle_maintenance_lock(bundle).expect("lock bare bundle");
            write_0600(&lock, b"first").expect("create bare bundle");
            lock.write_epoch(1).expect("create bare sidecar");
            write_0600(&lock, b"second").expect("mutate bare bundle");
            lock.write_epoch(2).expect("mutate bare sidecar");
            assert_eq!(std::fs::read(bundle).expect("read bundle"), b"second");
            assert_eq!(
                std::fs::read_to_string("creds.sealed.epoch").expect("read sidecar"),
                "2\n"
            );
            return;
        }

        let directory = temp_path("bare-relative-dir");
        std::fs::create_dir(&directory).expect("create temp current directory");
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "bundle_cli::tests::bare_relative_bundle_and_sidecar_create_and_mutate",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .current_dir(&directory)
            .output()
            .expect("run isolated relative-path test");
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(directory.join("creds.sealed")).unwrap(),
            b"second"
        );
        assert_eq!(
            std::fs::read_to_string(directory.join("creds.sealed.epoch")).unwrap(),
            "2\n"
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn pinned_parent_defeats_ancestor_symlink_substitution() {
        use std::os::unix::fs::symlink;

        let root = temp_path("pinned-parent-root");
        let original = root.join("original");
        let pinned = root.join("pinned");
        let alternate = root.join("alternate");
        std::fs::create_dir_all(&original).expect("create original");
        std::fs::create_dir_all(&alternate).expect("create alternate");
        let bundle = original.join("creds.sealed");
        let lock = acquire_bundle_maintenance_lock(&bundle).expect("pin and lock original");
        write_0600(&lock, b"original-bytes").expect("write original bundle");
        let alternate_bundle = alternate.join("creds.sealed");
        write_secret_file(&alternate_bundle, b"alternate-bytes");
        std::fs::rename(&original, &pinned).expect("move pinned ancestor");
        symlink(&alternate, &original).expect("substitute ancestor symlink");

        assert_eq!(
            lock.read_bundle().expect("read pinned bundle"),
            b"original-bytes"
        );
        write_0600(&lock, b"pinned-bytes").expect("write through pinned descriptor");
        lock.write_epoch(9).expect("write pinned sidecar");
        assert_eq!(
            std::fs::read(pinned.join("creds.sealed")).unwrap(),
            b"pinned-bytes"
        );
        assert_eq!(
            std::fs::read_to_string(pinned.join("creds.sealed.epoch")).unwrap(),
            "9\n"
        );
        assert_eq!(
            std::fs::read(alternate.join("creds.sealed")).unwrap(),
            b"alternate-bytes"
        );
        assert!(!alternate.join("creds.sealed.epoch").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_reads_reject_bundle_and_epoch_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = temp_path("protected-read-symlinks");
        std::fs::create_dir(&directory).expect("create protected read directory");
        let bundle = directory.join("creds.sealed");
        let victim = directory.join("victim");
        write_secret_file(&victim, b"victim");
        let lock = acquire_bundle_maintenance_lock(&bundle).expect("maintenance lock");
        symlink(&victim, &bundle).expect("bundle symlink");
        assert!(lock.read_bundle().is_err());
        std::fs::remove_file(&bundle).expect("remove bundle symlink");
        lock.write_bundle(b"bundle").expect("write regular bundle");
        symlink(&victim, epoch_sidecar_path(&bundle)).expect("epoch symlink");
        assert!(lock.read_epoch().is_err());
        assert_eq!(std::fs::read(&victim).expect("read victim"), b"victim");
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn slot_parser_accepts_supported_shapes() {
        let passphrase: SlotArg = "passphrase:file=/run/pass,label=primary"
            .parse()
            .expect("passphrase slot");
        assert_eq!(passphrase.kind, SlotKind::Passphrase);
        assert_eq!(passphrase.fields["file"], "/run/pass");
        assert_eq!(passphrase.fields["label"], "primary");

        let bip39: SlotArg = "bip39".parse().expect("bip39 slot");
        assert_eq!(bip39.kind, SlotKind::Bip39);

        let tpm: SlotArg = "tpm:pcrs=0,2,4,7".parse().expect("tpm slot");
        assert_eq!(tpm.kind, SlotKind::Tpm);
        assert_eq!(tpm.fields["pcrs"], "0,2,4,7");
    }

    #[test]
    fn parser_rejects_duplicate_fields() {
        let err = "id=a,type=aws-kms,region=us-east-1,region=us-west-2"
            .parse::<BackendArg>()
            .expect_err("duplicate region rejected");
        assert!(err.contains("duplicate field"));
    }

    #[test]
    fn parser_rejects_non_pcrs_comma_continuation() {
        let err = "id=a,type=aws-kms,region=us-east-1,profile"
            .parse::<BackendArg>()
            .expect_err("bare profile rejected");
        assert!(err.contains("expected key=value field"));
    }

    #[test]
    fn backend_parser_separates_id_from_type() {
        let backend: BackendArg = "id=aws1,type=aws-kms,region=us-east-1,profile=prod"
            .parse()
            .expect("aws backend");
        assert_eq!(backend.id, "aws1");
        assert_eq!(backend.kind, BackendKind::AwsKms);
        assert_eq!(backend.fields["region"], "us-east-1");
        assert_eq!(backend.fields["profile"], "prod");
    }

    #[test]
    fn backend_cred_reads_secret_files() {
        let token = temp_path("token");
        write_secret_file(&token, b"s.root\n");
        let backend: BackendArg = format!(
            "id=bao,type=openbao,addr=http://127.0.0.1:8200,token-file={}",
            token.display()
        )
        .parse()
        .expect("backend");

        let (id, cred) = backend_cred(&backend).expect("cred");
        let _ = std::fs::remove_file(&token);

        assert_eq!(id, "bao");
        match cred {
            BackendCred::VaultToken { token, addr } => {
                assert_eq!(token.expose_secret(), "s.root");
                assert_eq!(addr.as_deref(), Some("http://127.0.0.1:8200"));
            }
            other => panic!("wrong cred: {}", other.kind()),
        }
    }

    #[test]
    fn validate_backend_addr_accepts_http_and_https() {
        validate_backend_addr("http://127.0.0.1:8200").expect("plain http ok");
        validate_backend_addr("https://vault.example.com:8200").expect("https ok");
    }

    #[test]
    fn validate_backend_addr_rejects_missing_scheme() {
        // The footgun: `127.0.0.1:8200` parses as a relative URL with no scheme,
        // which reqwest later rejects as an opaque "builder error".
        let err = validate_backend_addr("127.0.0.1:8200")
            .expect_err("schemeless addr rejected")
            .to_string();
        assert!(err.contains("not a valid URL"), "unexpected error: {err}");
    }

    #[test]
    fn validate_backend_addr_rejects_non_http_scheme() {
        let err = validate_backend_addr("ftp://vault.example.com:8200")
            .expect_err("ftp scheme rejected")
            .to_string();
        assert!(
            err.contains("unsupported scheme"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vault_backend_rejects_schemeless_addr_at_parse_time() {
        let token = temp_path("schemeless-token");
        write_secret_file(&token, b"s.root\n");
        let backend: BackendArg = format!(
            "id=bao,type=openbao,addr=127.0.0.1:8200,token-file={}",
            token.display()
        )
        .parse()
        .expect("backend arg parses");

        let err = backend_cred(&backend).expect_err("schemeless addr rejected");
        let _ = std::fs::remove_file(&token);
        assert!(
            err.to_string().contains("not a valid URL"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn gcp_backend_accepts_optional_key_file() {
        let key = temp_path("gcp-key");
        write_secret_file(&key, br#"{"type":"service_account"}"#);
        let backend: BackendArg = format!(
            "id=gcp,type=gcp-kms,project=p,location=global,key-ring=ring,key-file={}",
            key.display()
        )
        .parse()
        .expect("backend");

        let (_, cred) = backend_cred(&backend).expect("cred");
        let _ = std::fs::remove_file(&key);

        match cred {
            BackendCred::GcpKms {
                project,
                location,
                key_ring,
                service_account_json,
            } => {
                assert_eq!(project, "p");
                assert_eq!(location, "global");
                assert_eq!(key_ring, "ring");
                assert_eq!(
                    service_account_json
                        .as_ref()
                        .map(SecretString::expose_secret),
                    Some(r#"{"type":"service_account"}"#)
                );
            }
            other => panic!("wrong cred: {}", other.kind()),
        }
    }

    #[test]
    fn manifest_loads_slots_and_backends() {
        let manifest = temp_path("manifest.toml");
        std::fs::write(
            &manifest,
            r#"
[[slot]]
type = "passphrase"
file = "/run/pass"

[[backend]]
id = "aws1"
type = "aws-kms"
region = "us-east-1"
"#,
        )
        .expect("write manifest");

        let source = create_source_from_manifest(&manifest).expect("manifest source");
        let _ = std::fs::remove_file(&manifest);

        assert_eq!(source.slots.len(), 1);
        assert_eq!(source.slots[0].kind, SlotKind::Passphrase);
        assert_eq!(source.backends.len(), 1);
        assert_eq!(source.backends[0].id, "aws1");
        assert_eq!(source.backends[0].kind, BackendKind::AwsKms);
    }

    #[test]
    fn create_rejects_mixed_manifest_and_inline_sources() {
        let args = CreateArgs {
            bundle: PathBuf::from("bundle.sealed"),
            from: Some(PathBuf::from("bundle.toml")),
            slot: vec!["bip39".parse().expect("slot")],
            backend: Vec::new(),
            deposit_key: None,
        };
        let err = create_source(&args).expect_err("mixed sources rejected");
        assert!(err.to_string().contains("cannot be mixed"));
    }

    #[test]
    fn create_rejects_slotless_bundle() {
        let args = CreateArgs {
            bundle: temp_path("slotless"),
            from: None,
            slot: Vec::new(),
            backend: Vec::new(),
            deposit_key: None,
        };
        let err = create(&args).expect_err("slotless create rejected");
        assert!(err.to_string().contains("requires at least one"));
    }

    #[test]
    fn verify_opens_bundle_and_leaves_passphrase_file() {
        let bundle = temp_path("verify-bundle");
        let passphrase_file = temp_path("verify-passphrase");
        write_secret_file(&passphrase_file, b"passphrase\n");

        let passphrase = PassphraseMethod::with_params(
            Zeroizing::new(b"passphrase".to_vec()),
            seal::Argon2Params {
                m_cost_kib: 256,
                t_cost: 1,
                p_cost: 1,
            },
        );
        let initial_file = seal::seal(
            &CredBundle::empty(),
            &[SlotSpec {
                method: &passphrase,
                label: "passphrase".to_string(),
            }],
        )
        .expect("seal bundle");
        let lock = acquire_bundle_maintenance_lock(&bundle).expect("lock bundle");
        write_0600(&lock, &initial_file).expect("write bundle");
        drop(lock);

        verify(&VerifyArgs {
            bundle: bundle.clone(),
            open: vec![
                format!("passphrase:file={}", passphrase_file.display())
                    .parse()
                    .expect("open arg"),
            ],
        })
        .expect("verify unlock");

        assert!(passphrase_file.exists());
        let _ = std::fs::remove_file(&bundle);
        let _ = std::fs::remove_file(&passphrase_file);
    }

    #[test]
    fn plaintext_inspection_refuses_concurrent_bundle_maintenance() {
        let bundle = temp_path("plaintext-inspection-maintenance");
        let passphrase = temp_path("plaintext-inspection-passphrase");
        db_bundle_fixture(&bundle, &passphrase, [0x61; 32]);
        let maintenance =
            acquire_bundle_maintenance_lock(&bundle).expect("exclusive maintenance lock");

        let verify_error = verify(&VerifyArgs {
            bundle: bundle.clone(),
            open: vec![passphrase_open(&passphrase)],
        })
        .expect_err("verify must fail while maintenance holds the bundle");
        assert!(verify_error.to_string().contains("verification guard"));

        let show_error = show(&ShowArgs {
            bundle: bundle.clone(),
            open: vec![passphrase_open(&passphrase)],
        })
        .expect_err("open show must fail while maintenance holds the bundle");
        assert!(show_error.to_string().contains("show guard"));

        drop(maintenance);
        let _ = std::fs::remove_file(&bundle);
        let _ = std::fs::remove_file(&passphrase);
        let _ = std::fs::remove_file(epoch_sidecar_path(&bundle));
        let _ = std::fs::remove_file(append_path_suffix(&bundle, ".basil-lock"));
    }

    #[test]
    fn raw_dek_reader_preserves_terminal_cr_and_lf_bytes() {
        let path = temp_path("raw-dek-terminal-bytes");
        let mut raw = [0x44; 32];
        raw[30] = b'\r';
        raw[31] = b'\n';
        write_secret_file(&path, &raw);
        let decoded = read_dek_0600(&path).expect("32 raw bytes accepted");
        assert_eq!(decoded.expose_secret(), &raw);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn raw_dek_reader_rejects_appended_newline() {
        let path = temp_path("raw-dek-appended-newline");
        let mut raw = vec![0x55; 32];
        raw.push(b'\n');
        write_secret_file(&path, &raw);
        let error = read_dek_0600(&path).expect_err("33 raw bytes rejected");
        assert!(error.to_string().contains("exactly 32 raw bytes"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn prepared_rekey_commits_bundle_before_epoch_and_retains_lock() {
        let bundle = temp_path("prepared-rekey-bundle");
        let passphrase = temp_path("prepared-rekey-passphrase");
        let pre_bytes = db_bundle_fixture(&bundle, &passphrase, [0x11; 32]);
        let pre_parsed = format::decode(&pre_bytes).expect("parse pre bundle");
        let (old_dek, mut prepared) = prepare_db_keystore_rekey(
            &bundle,
            "local",
            &[passphrase_open(&passphrase)],
            SecretArray::new([0x22; 32]),
        )
        .expect("prepare rekey bundle");
        assert_eq!(old_dek.expose_secret(), &[0x11; 32]);
        assert_eq!(prepared.binding().backend_id, "local");
        assert_eq!(
            prepared.binding().bundle_id,
            pre_parsed.body.header.bundle_id
        );
        assert_eq!(prepared.binding().pre_epoch, pre_parsed.body.header.epoch);
        assert_eq!(
            prepared.binding().post_epoch,
            pre_parsed.body.header.epoch + 1
        );
        assert_eq!(
            prepared.binding().pre_bundle_b3,
            *blake3::hash(&pre_bytes).as_bytes()
        );
        assert_eq!(
            prepared.observed_epoch_sidecar(),
            Some(pre_parsed.body.header.epoch)
        );
        assert_eq!(std::fs::read(&bundle).expect("read pre bundle"), pre_bytes);
        assert!(prepared.write_epoch_sidecar().is_err());
        assert!(acquire_bundle_startup_guard(&bundle).is_err());

        prepared.commit_bundle().expect("commit bundle");
        let post_bytes = std::fs::read(&bundle).expect("read post bundle");
        assert_eq!(
            *blake3::hash(&post_bytes).as_bytes(),
            prepared.binding().post_bundle_b3
        );
        assert_eq!(
            std::fs::read_to_string(epoch_sidecar_path(&bundle)).expect("read old epoch"),
            format!("{}\n", prepared.binding().pre_epoch)
        );
        prepared.write_epoch_sidecar().expect("advance sidecar");
        assert_eq!(
            std::fs::read_to_string(epoch_sidecar_path(&bundle)).expect("read new epoch"),
            format!("{}\n", prepared.binding().post_epoch)
        );
        drop(prepared);

        let resumed = resume_db_keystore_rekey(&bundle, "local", &[passphrase_open(&passphrase)])
            .expect("authenticate committed bundle");
        assert_eq!(
            resumed.identity().bundle_b3,
            *blake3::hash(&post_bytes).as_bytes()
        );
        assert_eq!(resumed.identity().backend_id, "local");
        assert_eq!(
            resumed.observed_epoch_sidecar(),
            Some(resumed.identity().epoch)
        );
        drop(resumed);
        drop(old_dek);

        let _ = std::fs::remove_file(&bundle);
        let _ = std::fs::remove_file(epoch_sidecar_path(&bundle));
        let _ = std::fs::remove_file(append_path_suffix(&bundle, ".basil-lock"));
        let _ = std::fs::remove_file(passphrase);
    }

    #[test]
    fn post_replace_checkpoint_failure_is_classified_from_authenticated_bytes() {
        let bundle = temp_path("rekey-post-replace-fault");
        let passphrase = temp_path("rekey-post-replace-passphrase");
        let pre_bytes = db_bundle_fixture(&bundle, &passphrase, [0x31; 32]);
        let pre_epoch = format::decode(&pre_bytes)
            .expect("parse pre bundle")
            .body
            .header
            .epoch;
        let checkpoints = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let observer = RecordingCommitObserver {
            checkpoints: std::rc::Rc::clone(&checkpoints),
            fail_at: Some(BundleCommitCheckpoint::AfterBundleReplace),
        };
        let (old_dek, mut prepared) = prepare_db_keystore_rekey_with_observer(
            &bundle,
            "local",
            &[passphrase_open(&passphrase)],
            SecretArray::new([0x32; 32]),
            Box::new(observer),
        )
        .expect("prepare bundle");
        let post_b3 = prepared.binding().post_bundle_b3;
        let post_epoch = prepared.binding().post_epoch;
        assert!(prepared.commit_bundle().is_err());
        assert_eq!(
            *checkpoints.borrow(),
            vec![
                BundleCommitCheckpoint::BeforeBundleReplace,
                BundleCommitCheckpoint::AfterBundleReplace
            ]
        );
        drop(prepared);
        drop(old_dek);

        let resumed = resume_db_keystore_rekey(&bundle, "local", &[passphrase_open(&passphrase)])
            .expect("resume after uncertain commit result");
        assert_eq!(resumed.identity().bundle_b3, post_b3);
        assert_eq!(resumed.identity().epoch, post_epoch);
        assert_eq!(resumed.observed_epoch_sidecar(), Some(pre_epoch));
        resumed
            .write_epoch_sidecar(post_epoch)
            .expect("repair epoch sidecar");
        drop(resumed);

        let _ = std::fs::remove_file(&bundle);
        let _ = std::fs::remove_file(epoch_sidecar_path(&bundle));
        let _ = std::fs::remove_file(append_path_suffix(&bundle, ".basil-lock"));
        let _ = std::fs::remove_file(passphrase);
    }

    #[cfg(unix)]
    #[test]
    fn acknowledged_post_bundle_commit_checkpoint_survives_sigkill() {
        const ROLE_ENV: &str = "BASIL_BUNDLE_COMMIT_CHECKPOINT_ROLE";
        const BUNDLE_ENV: &str = "BASIL_BUNDLE_COMMIT_CHECKPOINT_BUNDLE";
        const PASSPHRASE_ENV: &str = "BASIL_BUNDLE_COMMIT_CHECKPOINT_PASSPHRASE";
        const ACK_ENV: &str = "BASIL_BUNDLE_COMMIT_CHECKPOINT_ACK";

        if std::env::var_os(ROLE_ENV).is_some() {
            let bundle = PathBuf::from(std::env::var_os(BUNDLE_ENV).expect("bundle path"));
            let passphrase =
                PathBuf::from(std::env::var_os(PASSPHRASE_ENV).expect("passphrase path"));
            let acknowledge_path =
                PathBuf::from(std::env::var_os(ACK_ENV).expect("acknowledgement path"));
            let observer = AcknowledgedCommitObserver { acknowledge_path };
            let (_old_dek, mut prepared) = prepare_db_keystore_rekey_with_observer(
                &bundle,
                "local",
                &[passphrase_open(&passphrase)],
                SecretArray::new([0x72; 32]),
                Box::new(observer),
            )
            .expect("prepare child bundle transition");
            let result = prepared.commit_bundle();
            panic!("child escaped acknowledged checkpoint: {result:?}");
        }

        let directory = temp_path("acknowledged-commit-directory");
        std::fs::create_dir(&directory).expect("create checkpoint directory");
        let bundle = directory.join("creds.sealed");
        let passphrase = directory.join("passphrase");
        let acknowledge = directory.join("bundle-committed.ack");
        let pre_bytes = db_bundle_fixture(&bundle, &passphrase, [0x71; 32]);
        let pre_epoch = format::decode(&pre_bytes)
            .expect("parse pre bundle")
            .body
            .header
            .epoch;
        let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "bundle_cli::tests::acknowledged_post_bundle_commit_checkpoint_survives_sigkill",
                "--nocapture",
            ])
            .env(ROLE_ENV, "child")
            .env(BUNDLE_ENV, &bundle)
            .env(PASSPHRASE_ENV, &passphrase)
            .env(ACK_ENV, &acknowledge)
            .spawn()
            .expect("spawn checkpoint child");
        for _ in 0..500 {
            if acknowledge.exists() {
                break;
            }
            if let Some(status) = child.try_wait().expect("poll checkpoint child") {
                panic!("checkpoint child exited before acknowledgement: {status}");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            acknowledge.exists(),
            "child must acknowledge the durable post-bundle-commit checkpoint"
        );
        child.kill().expect("SIGKILL checkpoint child");
        let status = child.wait().expect("wait for checkpoint child");
        assert_eq!(status.signal(), Some(9));

        let post_bytes = std::fs::read(&bundle).expect("read committed bundle");
        assert_ne!(post_bytes, pre_bytes);
        let resumed = resume_db_keystore_rekey(&bundle, "local", &[passphrase_open(&passphrase)])
            .expect("resume after post-commit SIGKILL");
        assert_eq!(resumed.observed_epoch_sidecar(), Some(pre_epoch));
        let post_epoch = resumed.identity().epoch;
        resumed
            .write_epoch_sidecar(post_epoch)
            .expect("repair epoch after SIGKILL");
        drop(resumed);

        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn generic_backend_and_deposit_paths_refuse_db_keystore_without_mutation() {
        let bundle = temp_path("generic-db-keystore-refusal");
        let passphrase = temp_path("generic-db-keystore-passphrase");
        let baseline = db_bundle_fixture(&bundle, &passphrase, [0x41; 32]);
        let baseline_epoch =
            std::fs::read(epoch_sidecar_path(&bundle)).expect("read baseline epoch");

        let replacement: BackendArg =
            "id=local,type=vault,addr=http://127.0.0.1:8200,token-file=/must/not/be/read"
                .parse()
                .expect("replacement backend argument");
        assert!(
            set_backend(&SetBackendArgs {
                bundle: bundle.clone(),
                backend: replacement,
                open: vec![passphrase_open(&passphrase)],
            })
            .is_err()
        );
        assert_eq!(std::fs::read(&bundle).expect("read bundle"), baseline);
        assert_eq!(
            std::fs::read(epoch_sidecar_path(&bundle)).expect("read epoch"),
            baseline_epoch
        );

        let deposit_backend: BackendArg =
            "id=local,type=db-keystore,path=unused,dek-file=/must/not/be/read"
                .parse()
                .expect("deposit backend argument");
        assert!(
            deposit(&DepositArgs {
                bundle: bundle.clone(),
                backend: deposit_backend,
                recipient: PathBuf::from("/must/not/be/read"),
                identity: PathBuf::from("/must/not/be/read"),
                contributor_id: None,
                seq: None,
            })
            .is_err()
        );
        assert_eq!(std::fs::read(&bundle).expect("read bundle"), baseline);
        assert_eq!(
            std::fs::read(epoch_sidecar_path(&bundle)).expect("read epoch"),
            baseline_epoch
        );

        let _ = std::fs::remove_file(&bundle);
        let _ = std::fs::remove_file(epoch_sidecar_path(&bundle));
        let _ = std::fs::remove_file(append_path_suffix(&bundle, ".basil-lock"));
        let _ = std::fs::remove_file(passphrase);
    }

    #[test]
    fn promote_refuses_effective_deposit_over_existing_db_keystore() {
        let bundle = temp_path("promote-db-keystore-refusal");
        let passphrase_file = temp_path("promote-db-keystore-passphrase");
        let bytes =
            db_bundle_with_effective_deposit(&bundle, &passphrase_file, [0x52; 32], [0x53; 32]);
        let baseline_epoch =
            std::fs::read(epoch_sidecar_path(&bundle)).expect("read baseline epoch");

        assert!(
            promote(&PromoteArgs {
                bundle: bundle.clone(),
                dry_run: false,
                backend: Vec::new(),
                contributor: Vec::new(),
                open: vec![passphrase_open(&passphrase_file)],
            })
            .is_err()
        );
        assert_eq!(std::fs::read(&bundle).expect("read bundle"), bytes);
        assert_eq!(
            std::fs::read(epoch_sidecar_path(&bundle)).expect("read epoch"),
            baseline_epoch
        );

        let _ = std::fs::remove_file(&bundle);
        let _ = std::fs::remove_file(epoch_sidecar_path(&bundle));
        let _ = std::fs::remove_file(append_path_suffix(&bundle, ".basil-lock"));
        let _ = std::fs::remove_file(passphrase_file);
    }

    #[test]
    fn rekey_materializes_and_prunes_effective_deposit_before_epoch_bump() {
        let bundle = temp_path("rekey-effective-deposit");
        let passphrase_file = temp_path("rekey-effective-deposit-passphrase");
        let _bytes =
            db_bundle_with_effective_deposit(&bundle, &passphrase_file, [0x61; 32], [0x62; 32]);
        let (old_dek, mut prepared) = prepare_db_keystore_rekey(
            &bundle,
            "local",
            &[passphrase_open(&passphrase_file)],
            SecretArray::new([0x63; 32]),
        )
        .expect("prepare bundle with effective deposit");
        assert_eq!(old_dek.expose_secret(), &[0x62; 32]);
        prepared.commit_bundle().expect("commit bundle");
        prepared.write_epoch_sidecar().expect("write epoch");
        drop(prepared);
        drop(old_dek);

        let post_bytes = std::fs::read(&bundle).expect("read post bundle");
        let post = format::decode(&post_bytes).expect("parse post bundle");
        assert!(post.body.deposits.is_empty());
        let methods = open_methods(&[passphrase_open(&passphrase_file)]).expect("open methods");
        let registry = registry_from_methods(&methods.methods);
        let mut reopened = seal::open_bundle(&post, &registry).expect("open post bundle");
        let reviews = seal::apply_authorized_deposits(&post, &mut reopened);
        assert!(
            reviews
                .iter()
                .all(|review| review.status != DepositStatus::Effective)
        );
        match reopened.backends.get("local") {
            Some(BackendCred::DbKeystoreDek { dek }) => {
                assert_eq!(dek.expose_secret(), &[0x63; 32]);
            }
            other => panic!(
                "unexpected reopened credential: {:?}",
                other.map(BackendCred::kind)
            ),
        }

        let _ = std::fs::remove_file(&bundle);
        let _ = std::fs::remove_file(epoch_sidecar_path(&bundle));
        let _ = std::fs::remove_file(append_path_suffix(&bundle, ".basil-lock"));
        let _ = std::fs::remove_file(passphrase_file);
    }

    #[test]
    fn deposit_allow_startup_overlay_and_promote_round_trip() {
        let bundle = temp_path("deposit-bundle");
        let passphrase_file = temp_path("deposit-passphrase");
        let recipient_file = temp_path("deposit-recipient");
        let signer_file = temp_path("deposit-signer");
        let baseline_token = temp_path("deposit-baseline-token");
        let replacement_token = temp_path("deposit-replacement-token");

        write_secret_file(&passphrase_file, b"passphrase\n");
        write_secret_file(&baseline_token, b"s.baseline\n");
        write_secret_file(&replacement_token, b"s.replacement\n");
        write_secret_file(&signer_file, &[11u8; 32]);

        create(&CreateArgs {
            bundle: bundle.clone(),
            from: None,
            slot: vec![
                format!("passphrase:file={}", passphrase_file.display())
                    .parse()
                    .expect("slot"),
            ],
            backend: vec![
                format!(
                    "id=vault,type=vault,addr=http://127.0.0.1:8200,token-file={}",
                    baseline_token.display()
                )
                .parse()
                .expect("backend"),
            ],
            deposit_key: Some(recipient_file.clone()),
        })
        .expect("create");

        let signer_seed = Zeroizing::new([11u8; 32]);
        let contributor = seal::contributor_public_token(&signer_seed);
        allow(&AllowArgs {
            bundle: bundle.clone(),
            contributor,
            contributor_id: None,
            backend: vec!["vault".to_string()],
            open: vec![
                format!("passphrase:file={}", passphrase_file.display())
                    .parse()
                    .expect("open"),
            ],
        })
        .expect("allow");

        deposit(&DepositArgs {
            bundle: bundle.clone(),
            backend: format!(
                "id=vault,type=vault,addr=http://127.0.0.1:8200,token-file={}",
                replacement_token.display()
            )
            .parse()
            .expect("backend"),
            recipient: recipient_file.clone(),
            identity: signer_file.clone(),
            contributor_id: None,
            seq: None,
        })
        .expect("deposit");

        show(&ShowArgs {
            bundle: bundle.clone(),
            open: Vec::new(),
        })
        .expect("metadata show");
        show(&ShowArgs {
            bundle: bundle.clone(),
            open: vec![
                format!("passphrase:file={}", passphrase_file.display())
                    .parse()
                    .expect("open"),
            ],
        })
        .expect("open show");

        let unlocked = crate::unlock::open_bundle_at_startup(
            &bundle,
            &crate::unlock::UnlockArgs {
                age_yubikey: false,
                bip39_phrase_file: None,
                tpm: false,
                passphrase_file: Some(passphrase_file.clone()),
                passphrase_no_wipe: true,
                strict_bundle_perms: false,
            },
        )
        .expect("startup unlock");
        match unlocked.creds().backends.get("vault") {
            Some(BackendCred::VaultToken { token, .. }) => {
                assert_eq!(token.expose_secret(), "s.replacement");
            }
            other => panic!("wrong cred: {:?}", other.map(BackendCred::kind)),
        }
        drop(unlocked);

        promote(&PromoteArgs {
            bundle: bundle.clone(),
            dry_run: false,
            backend: Vec::new(),
            contributor: Vec::new(),
            open: vec![
                format!("passphrase:file={}", passphrase_file.display())
                    .parse()
                    .expect("open"),
            ],
        })
        .expect("promote");

        let bytes = read_bundle(&bundle).expect("read bundle");
        let parsed = format::decode(&bytes).expect("parse promoted");
        assert!(parsed.body.deposits.is_empty());
        let open_methods =
            open_methods(&[format!("passphrase:file={}", passphrase_file.display())
                .parse()
                .expect("open")])
            .expect("open methods");
        let registry = registry_from_methods(&open_methods.methods);
        let promoted = seal::open_bundle(&parsed, &registry).expect("open promoted");
        match promoted.backends.get("vault") {
            Some(BackendCred::VaultToken { token, .. }) => {
                assert_eq!(token.expose_secret(), "s.replacement");
            }
            other => panic!("wrong cred: {:?}", other.map(BackendCred::kind)),
        }

        let _ = std::fs::remove_file(&bundle);
        let _ = std::fs::remove_file(epoch_sidecar_path(&bundle));
        let _ = std::fs::remove_file(&passphrase_file);
        let _ = std::fs::remove_file(&recipient_file);
        let _ = std::fs::remove_file(&signer_file);
        let _ = std::fs::remove_file(&baseline_token);
        let _ = std::fs::remove_file(&replacement_token);
    }
}
