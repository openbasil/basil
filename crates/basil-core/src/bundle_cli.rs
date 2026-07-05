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
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::seal::{self, BackendCred, CredBundle, MethodRegistry, SlotSpec, UnlockMethod, format};
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde::Deserialize;
use zero_secrets::{SecretArray, SecretString};
use zeroize::Zeroizing;

#[cfg(feature = "unlock-age-yubikey")]
use crate::seal::AgeYubikeyMethod;
#[cfg(feature = "unlock-bip39")]
use crate::seal::Bip39Method;
use crate::seal::PassphraseMethod;

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
    write_0600(&args.bundle, &file)?;
    seal::write_epoch_sidecar(&epoch_sidecar_path(&args.bundle), parsed.body.header.epoch)
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
    let bytes = read_bundle(&args.bundle)?;
    let parsed = format::decode(&bytes).context("parsing bundle")?;
    let open_methods = open_methods(&args.open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let new_slot = slot_methods(std::slice::from_ref(&args.slot), SlotUse::Create)?;
    let specs = new_slot.specs();
    let Some(spec) = specs.first() else {
        bail!("add-slot requires one --slot");
    };
    let new_file = seal::add_slot(&parsed, &registry, spec).context("adding bundle slot")?;
    write_0600(&args.bundle, &new_file)?;
    seal::write_epoch_sidecar(&epoch_sidecar_path(&args.bundle), parsed.body.header.epoch)
        .context("writing epoch sidecar")?;
    print_generated_phrases(&new_slot.generated_phrases);
    println!("added slot to {}", args.bundle.display());
    Ok(())
}

fn set_backend(args: &SetBackendArgs) -> Result<()> {
    let bytes = read_bundle(&args.bundle)?;
    let parsed = format::decode(&bytes).context("parsing bundle")?;
    let open_methods = open_methods(&args.open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let mut creds =
        seal::open_bundle(&parsed, &registry).context("opening bundle to update backend")?;
    let (backend_id, cred) = backend_cred(&args.backend)?;
    creds.set(backend_id.clone(), cred);
    let new_file =
        seal::reseal_payload(&parsed, &registry, &creds).context("re-sealing bundle payload")?;
    let new_parsed = format::decode(&new_file).context("parsing updated sealed bundle")?;
    drop(creds);
    write_0600(&args.bundle, &new_file)?;
    seal::write_epoch_sidecar(
        &epoch_sidecar_path(&args.bundle),
        new_parsed.body.header.epoch,
    )
    .context("writing epoch sidecar")?;
    println!(
        "updated backend `{}` in {}",
        backend_id,
        args.bundle.display()
    );
    Ok(())
}

fn deposit(args: &DepositArgs) -> Result<()> {
    let bytes = read_bundle(&args.bundle)?;
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
    write_0600(&args.bundle, &file)?;
    println!("deposited backend `{backend_id}` as contributor `{contributor_key_id}` seq {seq}");
    Ok(())
}

fn allow(args: &AllowArgs) -> Result<()> {
    if args.backend.is_empty() {
        bail!("allow requires at least one --backend ID");
    }
    let bytes = read_bundle(&args.bundle)?;
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
    write_0600(&args.bundle, &new_file)?;
    println!("allowed contributor `{contributor_id}`");
    Ok(())
}

fn promote(args: &PromoteArgs) -> Result<()> {
    let bytes = read_bundle(&args.bundle)?;
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
    let (new_file, reviews) =
        seal::promote_deposits(&parsed, &registry, &backend_filter, &contributor_filter)
            .context("promoting deposits")?;
    let new_parsed = format::decode(&new_file).context("parsing promoted bundle")?;
    write_0600(&args.bundle, &new_file)?;
    seal::write_epoch_sidecar(
        &epoch_sidecar_path(&args.bundle),
        new_parsed.body.header.epoch,
    )
    .context("writing epoch sidecar")?;
    print_deposit_reviews(&reviews);
    println!("promoted selected deposits in {}", args.bundle.display());
    Ok(())
}

fn deposit_key(args: &DepositKeyArgs) -> Result<()> {
    let bytes = read_bundle(&args.bundle)?;
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
    write_0600(&args.bundle, &new_file)?;
    write_public_token(&args.out, &seal::public_key_token(&recipient))?;
    println!("wrote deposit recipient to {}", args.out.display());
    Ok(())
}

fn verify(args: &VerifyArgs) -> Result<()> {
    let bytes = read_bundle(&args.bundle)?;
    let parsed = format::decode(&bytes).context("parsing bundle")?;
    let open_methods = open_methods(&args.open)?;
    let registry = registry_from_methods(&open_methods.methods);
    let creds = seal::open_bundle(&parsed, &registry).context("verifying bundle unlock")?;
    drop(creds);
    println!("bundle unlock verified");
    Ok(())
}

fn show(args: &ShowArgs) -> Result<()> {
    let bytes = read_bundle(&args.bundle)?;
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

fn read_dek_0600(path: &Path) -> Result<SecretArray<32>> {
    require_0600(path)?;
    let bytes = read_secret_file(path)?;
    let dek = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("db-keystore DEK file must contain exactly 32 bytes"))?;
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

/// Atomically write `bytes` to `path` with mode `0600`.
fn write_0600(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = path.with_extension("sealed.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("creating temp bundle {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .context("setting 0600 on temp bundle")?;
        }
        f.write_all(bytes).context("writing temp bundle")?;
        f.sync_all().context("fsync temp bundle")?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

fn epoch_sidecar_path(bundle_path: &Path) -> PathBuf {
    let mut path = OsString::from(bundle_path.as_os_str());
    path.push(".epoch");
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::too_many_lines, clippy::unwrap_used)]

    use super::*;

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
        write_0600(&bundle, &initial_file).expect("write bundle");

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
        match unlocked.backends.get("vault") {
            Some(BackendCred::VaultToken { token, .. }) => {
                assert_eq!(token.expose_secret(), "s.replacement");
            }
            other => panic!("wrong cred: {:?}", other.map(BackendCred::kind)),
        }

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
