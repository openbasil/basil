// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Configuration-corpus loading and startup override validation.
//!
//! One TOML agent document selects corpus schema `3` and explicitly references
//! the catalog, policy, sealed bundle, and named Compose documents. This module
//! owns the source boundary so startup, offline tools, and reload cannot drift
//! into separate discovery or compatibility paths.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;

const MAX_STARTUP_OVERRIDES: usize = 64;
const MAX_OVERRIDE_PATH_LEN: usize = 256;
const MAX_OVERRIDE_VALUE_LEN: usize = 4096;

/// The only unified configuration-corpus version supported by this binary.
pub const CORPUS_SCHEMA_VERSION: i64 = 3;

/// The system bootstrap selected when `--config` is omitted.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/basil/config.toml";

/// One validated startup override supplied as `-o PATH=VALUE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigOverride {
    path: String,
    value: String,
}

impl ConfigOverride {
    /// Parse one typed startup override.
    ///
    /// # Errors
    ///
    /// Returns an error when the input lacks a non-empty path or value.
    pub fn parse(raw: &str) -> Result<Self, ConfigurationError> {
        let Some((path, value)) = raw.split_once('=') else {
            return Err(ConfigurationError::InvalidOverride(
                "expected PATH=VALUE".to_string(),
            ));
        };
        let path = path.trim();
        let value = value.trim();
        if path.is_empty() || value.is_empty() {
            return Err(ConfigurationError::InvalidOverride(
                "override path and value must both be non-empty".to_string(),
            ));
        }
        if path.len() > MAX_OVERRIDE_PATH_LEN || value.len() > MAX_OVERRIDE_VALUE_LEN {
            return Err(ConfigurationError::InvalidOverride(format!(
                "override exceeds the {MAX_OVERRIDE_PATH_LEN}-byte path or {MAX_OVERRIDE_VALUE_LEN}-byte value limit"
            )));
        }
        Ok(Self {
            path: path.to_string(),
            value: value.to_string(),
        })
    }

    /// The dotted schema path targeted by this override.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The command-line value, before target-type parsing.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    fn is_source_path(&self) -> bool {
        matches!(
            self.path.as_str(),
            "config.catalog" | "config.policy" | "config.bundle"
        ) || self.path.starts_with("config.compose.")
    }

    fn is_document_path(&self) -> bool {
        self.path.starts_with("catalog.")
            || self.path.starts_with("policy.")
            || self.path.starts_with("compose.")
    }
}

impl std::str::FromStr for ConfigOverride {
    type Err = ConfigurationError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse(raw)
    }
}

/// Non-secret provenance for one applied startup override.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OverrideProvenance {
    /// Dotted field path that was overridden.
    pub path: String,
    /// Selected bootstrap path whose on-disk value was masked.
    pub masked_source: PathBuf,
}

/// Explicit document paths resolved from one selected bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusSources {
    /// Catalog document path.
    pub catalog: PathBuf,
    /// Policy document path.
    pub policy: PathBuf,
    /// Sealed credential-bundle path.
    pub bundle: PathBuf,
    /// Named Compose documents.
    pub compose: BTreeMap<String, PathBuf>,
}

/// A parsed and validated structured corpus.
#[derive(Debug)]
pub struct CorpusDocuments {
    /// Parsed catalog.
    pub catalog: crate::catalog::Catalog,
    /// Resolved default-deny policy.
    pub policy: crate::catalog::ResolvedPolicy,
    /// Policy name and membership tables.
    pub policy_config: crate::catalog::Config,
    /// Non-fatal catalog warnings.
    pub warnings: Vec<crate::catalog::LoadWarning>,
    /// Validated named Compose documents, retained for later profile compilers.
    pub compose: BTreeMap<String, JsonValue>,
    /// Non-secret provenance for every startup override applied to this corpus.
    pub overrides: Vec<OverrideProvenance>,
}

/// A selected bootstrap after strict schema validation and safe overrides.
#[derive(Debug)]
pub struct LoadedBootstrap {
    /// Selected bootstrap path.
    pub path: PathBuf,
    /// Mutated TOML value ready for typed deserialization.
    pub value: toml::Value,
    /// Explicit, config-parent-resolved document sources.
    pub sources: CorpusSources,
    /// Non-secret override provenance.
    pub overrides: Vec<OverrideProvenance>,
    /// Ordinary document-leaf overrides deferred until documents are parsed.
    pub document_overrides: Vec<ConfigOverride>,
}

/// Result of installing a reviewed Compose document into the authoritative
/// configuration area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeInstallOutcome {
    /// The protected copy and bootstrap reference were installed atomically.
    Installed {
        /// Authoritative protected copy.
        destination: PathBuf,
    },
    /// The caller lacked filesystem privilege, so a protected copy was staged.
    Staged {
        /// Protected staged copy that the privileged command consumes.
        staged_copy: PathBuf,
        /// Exact command to run through the operator's privilege mechanism.
        command: String,
    },
}

/// Configuration loading failure.
#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    /// The selected bootstrap could not be read.
    #[error("reading bootstrap from {path}: {source}")]
    ReadBootstrap {
        /// Selected path.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// The selected bootstrap is not valid TOML.
    #[error("parsing bootstrap from {path}: {source}")]
    ParseBootstrap {
        /// Selected path.
        path: PathBuf,
        /// TOML parser error.
        source: toml::de::Error,
    },
    /// The bootstrap or referenced document violates corpus schema `3`.
    #[error("invalid configuration corpus: {0}")]
    InvalidCorpus(String),
    /// An override is malformed, forbidden, missing, or type-incompatible.
    #[error("invalid startup override: {0}")]
    InvalidOverride(String),
    /// A referenced structured document could not be read.
    #[error("reading {slot} document from {path}: {source}")]
    ReadDocument {
        /// Referencing slot.
        slot: String,
        /// Referenced path.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// A referenced structured document could not be parsed.
    #[error("parsing {slot} document from {path}: {reason}")]
    ParseDocument {
        /// Referencing slot.
        slot: String,
        /// Referenced path.
        path: PathBuf,
        /// Bounded parser diagnostic.
        reason: String,
    },
    /// Catalog or policy semantic validation failed.
    #[error(transparent)]
    Catalog(#[from] crate::catalog::LoadError),
    /// A reviewed Compose document could not be installed safely.
    #[error("installing Compose document: {0}")]
    Install(String),
}

/// Load and validate the selected bootstrap, applying immutable startup
/// overrides in source-path then scalar-leaf order.
///
/// # Errors
///
/// Returns an error for missing files, any schema mismatch, forbidden override,
/// absent target, or target-type mismatch.
pub fn load_bootstrap(
    selected: Option<&Path>,
    overrides: &[ConfigOverride],
) -> Result<LoadedBootstrap, ConfigurationError> {
    validate_override_set(overrides)?;
    let path = selected.map_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH), Path::to_path_buf);
    let raw =
        std::fs::read_to_string(&path).map_err(|source| ConfigurationError::ReadBootstrap {
            path: path.clone(),
            source,
        })?;
    let mut value: toml::Value =
        toml::from_str(&raw).map_err(|source| ConfigurationError::ParseBootstrap {
            path: path.clone(),
            source,
        })?;
    validate_bootstrap_header(&value)?;

    let mut provenance = Vec::with_capacity(overrides.len());
    for config_override in overrides.iter().filter(|item| item.is_source_path()) {
        apply_source_override(&mut value, config_override)?;
        provenance.push(OverrideProvenance {
            path: config_override.path.clone(),
            masked_source: path.clone(),
        });
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let sources = extract_sources(&value, parent)?;
    for config_override in overrides
        .iter()
        .filter(|item| !item.is_source_path() && !item.is_document_path())
    {
        apply_scalar_override(&mut value, config_override)?;
        provenance.push(OverrideProvenance {
            path: config_override.path.clone(),
            masked_source: path.clone(),
        });
    }

    Ok(LoadedBootstrap {
        path,
        value,
        sources,
        overrides: provenance,
        document_overrides: overrides
            .iter()
            .filter(|item| item.is_document_path())
            .cloned()
            .collect(),
    })
}

fn validate_override_set(overrides: &[ConfigOverride]) -> Result<(), ConfigurationError> {
    if overrides.len() > MAX_STARTUP_OVERRIDES {
        return Err(ConfigurationError::InvalidOverride(format!(
            "at most {MAX_STARTUP_OVERRIDES} startup overrides are accepted"
        )));
    }
    let mut paths = BTreeSet::new();
    for config_override in overrides {
        if !paths.insert(config_override.path()) {
            return Err(ConfigurationError::InvalidOverride(format!(
                "duplicate target `{}`",
                config_override.path()
            )));
        }
    }
    Ok(())
}

/// Load every explicitly referenced structured document and validate its slot.
///
/// # Errors
///
/// Returns an error when any referenced file is absent, malformed, has the wrong
/// discriminator or Compose name, or fails catalog/policy semantic validation.
pub fn load_documents(sources: &CorpusSources) -> Result<CorpusDocuments, ConfigurationError> {
    load_documents_with_overrides(sources, &[], Vec::new())
}

/// Load every document and apply validated ordinary scalar overrides.
///
/// Source overrides have already selected `sources`; document overrides are
/// applied only after the complete structured set has parsed, before typed
/// semantic validation. `provenance` contains bootstrap/source overrides and is
/// extended without retaining any override value.
///
/// # Errors
///
/// Returns an error for an unknown, duplicate, structural, secret-bearing,
/// identity-bearing, or type-incompatible document target.
pub fn load_documents_with_overrides(
    sources: &CorpusSources,
    overrides: &[ConfigOverride],
    mut provenance: Vec<OverrideProvenance>,
) -> Result<CorpusDocuments, ConfigurationError> {
    let mut catalog_value = read_structured("catalog", &sources.catalog)?;
    require_schema(&catalog_value, "catalog", &sources.catalog)?;
    let policy_value = read_structured("policy", &sources.policy)?;
    require_schema(&policy_value, "policy", &sources.policy)?;

    for config_override in overrides {
        let masked_source = if config_override.path.starts_with("catalog.") {
            apply_catalog_override(&mut catalog_value, config_override)?;
            &sources.catalog
        } else if config_override.path.starts_with("policy.") {
            apply_policy_override(&policy_value, config_override)?;
            &sources.policy
        } else {
            return Err(ConfigurationError::InvalidOverride(format!(
                "target `{}` is structural or delivery-bearing; only eligible catalog/policy scalar leaves may be overridden",
                config_override.path
            )));
        };
        provenance.push(OverrideProvenance {
            path: config_override.path.clone(),
            masked_source: masked_source.clone(),
        });
    }

    let catalog_json = serde_json::to_string(&catalog_value).map_err(|error| {
        ConfigurationError::InvalidCorpus(format!("serializing catalog candidate: {error}"))
    })?;
    let policy_json = serde_json::to_string(&policy_value).map_err(|error| {
        ConfigurationError::InvalidCorpus(format!("serializing policy candidate: {error}"))
    })?;
    let (catalog, policy, policy_config, warnings) =
        crate::catalog::load(&catalog_json, &policy_json)?;

    let mut compose = BTreeMap::new();
    for (name, path) in &sources.compose {
        let document = read_structured(&format!("compose `{name}`"), path)?;
        require_schema(&document, "compose", path)?;
        let actual_name = document
            .as_object()
            .and_then(|object| object.get("name"))
            .and_then(JsonValue::as_str)
            .ok_or_else(|| {
                ConfigurationError::InvalidCorpus(format!(
                    "Compose document {} must contain a string `name`",
                    path.display()
                ))
            })?;
        if actual_name != name {
            return Err(ConfigurationError::InvalidCorpus(format!(
                "Compose document {} has name `{actual_name}`, expected map key `{name}`",
                path.display()
            )));
        }
        compose.insert(name.clone(), document);
    }

    Ok(CorpusDocuments {
        catalog,
        policy,
        policy_config,
        warnings,
        compose,
        overrides: provenance,
    })
}

fn apply_catalog_override(
    catalog: &mut JsonValue,
    config_override: &ConfigOverride,
) -> Result<(), ConfigurationError> {
    let Some(rest) = config_override.path.strip_prefix("catalog.keys.") else {
        return Err(forbidden_document_target(&config_override.path));
    };
    let keys = catalog
        .as_object_mut()
        .and_then(|object| object.get_mut("keys"))
        .and_then(JsonValue::as_object_mut)
        .ok_or_else(|| missing_document_target(&config_override.path))?;
    let (name, leaf) = split_named_leaf(keys, rest)
        .map(|(name, leaf)| (name.to_string(), leaf.to_string()))
        .ok_or_else(|| missing_document_target(&config_override.path))?;
    let target = keys
        .get_mut(&name)
        .and_then(JsonValue::as_object_mut)
        .and_then(|entry| entry.get_mut(&leaf))
        .ok_or_else(|| missing_document_target(&config_override.path))?;
    if !matches!(leaf.as_str(), "writable" | "missing" | "description") {
        return Err(forbidden_document_target(&config_override.path));
    }
    *target = parse_json_like(target, config_override.value()).map_err(|reason| {
        ConfigurationError::InvalidOverride(format!("target `{}` {reason}", config_override.path))
    })?;
    Ok(())
}

fn apply_policy_override(
    policy: &JsonValue,
    config_override: &ConfigOverride,
) -> Result<(), ConfigurationError> {
    let path = config_override.path();
    let relative = path
        .strip_prefix("policy.")
        .ok_or_else(|| missing_document_target(path))?;
    let top_level = relative.split('.').next().unwrap_or_default();
    let known_section = matches!(
        top_level,
        "schema" | "subjects" | "unauthenticatedSubject" | "roles" | "rules" | "config"
    );
    if known_section
        && policy
            .as_object()
            .is_some_and(|object| object.contains_key(top_level))
    {
        return Err(forbidden_document_target(path));
    }
    Err(missing_document_target(path))
}

fn split_named_leaf<'a>(
    entries: &'a serde_json::Map<String, JsonValue>,
    rest: &'a str,
) -> Option<(&'a str, &'a str)> {
    entries
        .keys()
        .filter_map(|name| {
            rest.strip_prefix(name.as_str())
                .and_then(|suffix| suffix.strip_prefix('.'))
                .map(|leaf| (name.as_str(), leaf))
        })
        .filter(|(_, leaf)| !leaf.is_empty() && !leaf.contains('.'))
        .max_by_key(|(name, _)| name.len())
}

fn missing_document_target(path: &str) -> ConfigurationError {
    ConfigurationError::InvalidOverride(format!("target `{path}` does not already exist"))
}

fn forbidden_document_target(path: &str) -> ConfigurationError {
    ConfigurationError::InvalidOverride(format!(
        "target `{path}` is secret-bearing, structural, versioned, identity-bearing, policy-bearing, or delivery-bearing"
    ))
}

fn parse_json_like(target: &JsonValue, raw: &str) -> Result<JsonValue, &'static str> {
    match target {
        JsonValue::String(_) => Ok(JsonValue::String(parse_string_value(raw))),
        JsonValue::Bool(_) => raw
            .parse::<bool>()
            .map(JsonValue::Bool)
            .map_err(|_| "requires `true` or `false`"),
        JsonValue::Number(number) if number.is_i64() => raw
            .parse::<i64>()
            .map(serde_json::Number::from)
            .map(JsonValue::Number)
            .map_err(|_| "requires a signed integer value"),
        JsonValue::Number(number) if number.is_u64() => raw
            .parse::<u64>()
            .map(serde_json::Number::from)
            .map(JsonValue::Number)
            .map_err(|_| "requires an unsigned integer value"),
        JsonValue::Number(_) => raw
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(JsonValue::Number)
            .ok_or("requires a finite floating-point value"),
        JsonValue::Null | JsonValue::Array(_) | JsonValue::Object(_) => {
            Err("is structural; only scalar leaves may be overridden")
        }
    }
}

/// Install a reviewed named Compose document as a protected copy and register it
/// in the selected bootstrap while preserving unrelated comments and formatting.
///
/// The destination must be beside or below the bootstrap directory. When the
/// caller cannot write that area, this function stages a mode-`0600` copy and
/// returns the exact command to execute with external privilege. It never
/// invokes `sudo`.
///
/// # Errors
///
/// Returns an error for an invalid document/name pair, unsafe destination,
/// existing destination or map entry, or any non-permission filesystem failure.
pub fn install_compose_document(
    config_path: &Path,
    name: &str,
    reviewed_source: &Path,
    destination: &Path,
) -> Result<ComposeInstallOutcome, ConfigurationError> {
    validate_compose_name(name)?;
    validate_compose_source(name, reviewed_source)?;
    ensure_protected_destination(config_path, destination)?;
    match install_compose_document_inner(config_path, name, reviewed_source, destination) {
        Ok(()) => Ok(ComposeInstallOutcome::Installed {
            destination: destination.to_path_buf(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            stage_privileged_install(config_path, name, reviewed_source, destination)
        }
        Err(error) => Err(ConfigurationError::Install(error.to_string())),
    }
}

fn validate_compose_source(name: &str, path: &Path) -> Result<(), ConfigurationError> {
    let document = read_structured(&format!("compose `{name}`"), path)?;
    require_schema(&document, "compose", path)?;
    let actual = document
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            ConfigurationError::InvalidCorpus(format!(
                "Compose document {} must contain a string `name`",
                path.display()
            ))
        })?;
    if actual == name {
        Ok(())
    } else {
        Err(ConfigurationError::InvalidCorpus(format!(
            "Compose document {} has name `{actual}`, expected `{name}`",
            path.display()
        )))
    }
}

fn ensure_protected_destination(
    config_path: &Path,
    destination: &Path,
) -> Result<(), ConfigurationError> {
    let config_parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    if !destination.is_absolute() || !config_parent.is_absolute() {
        return Err(ConfigurationError::Install(
            "bootstrap and install destination must be absolute paths".to_string(),
        ));
    }
    let relative = destination.strip_prefix(config_parent).map_err(|_| {
        ConfigurationError::Install(format!(
            "destination {} must be beside or below bootstrap directory {}",
            destination.display(),
            config_parent.display()
        ))
    })?;
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return Err(ConfigurationError::Install(
            "install destination must not traverse parent directories".to_string(),
        ));
    }
    Ok(())
}

fn install_compose_document_inner(
    config_path: &Path,
    name: &str,
    source: &Path,
    destination: &Path,
) -> std::io::Result<()> {
    let destination_parent = destination
        .parent()
        .ok_or_else(|| std::io::Error::other("install destination has no parent"))?;
    std::fs::create_dir_all(destination_parent)?;
    let destination_temp =
        destination_parent.join(format!(".basil-compose-{}.tmp", uuid::Uuid::new_v4()));
    protected_copy(source, &destination_temp)?;
    if destination.exists() {
        std::fs::remove_file(&destination_temp).ok();
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("destination {} already exists", destination.display()),
        ));
    }
    std::fs::rename(&destination_temp, destination)?;

    if let Err(error) = update_bootstrap_compose(config_path, name, destination) {
        std::fs::remove_file(destination).ok();
        return Err(error);
    }
    Ok(())
}

fn protected_copy(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let bytes = std::fs::read(source)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    file.write_all(&bytes)?;
    file.sync_all()
}

fn update_bootstrap_compose(
    config_path: &Path,
    name: &str,
    destination: &Path,
) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let raw = std::fs::read_to_string(config_path)?;
    let mut document = raw
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let config = document
        .get_mut("config")
        .and_then(toml_edit::Item::as_table_mut)
        .ok_or_else(|| std::io::Error::other("bootstrap lacks `[config]` table"))?;
    if !config.contains_key("compose") {
        config.insert("compose", toml_edit::Item::Table(toml_edit::Table::new()));
    }
    let compose = config
        .get_mut("compose")
        .and_then(toml_edit::Item::as_table_mut)
        .ok_or_else(|| std::io::Error::other("`config.compose` is not a table"))?;
    if compose.contains_key(name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("`config.compose.{name}` already exists"),
        ));
    }
    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));
    let recorded = destination
        .strip_prefix(parent)
        .unwrap_or(destination)
        .to_string_lossy()
        .into_owned();
    compose.insert(name, toml_edit::value(recorded));

    if std::fs::read(config_path)? != raw.as_bytes() {
        return Err(std::io::Error::other(
            "bootstrap changed during Compose install; retry",
        ));
    }
    let metadata = std::fs::metadata(config_path)?;
    let parent = config_path
        .parent()
        .ok_or_else(|| std::io::Error::other("bootstrap has no parent"))?;
    let temp = parent.join(format!(".basil-config-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(metadata.permissions().mode())
            .open(&temp)?;
        output.write_all(document.to_string().as_bytes())?;
        output.sync_all()?;
        std::fs::rename(&temp, config_path)
    })();
    if result.is_err() {
        std::fs::remove_file(temp).ok();
    }
    result
}

fn stage_privileged_install(
    config_path: &Path,
    name: &str,
    source: &Path,
    destination: &Path,
) -> Result<ComposeInstallOutcome, ConfigurationError> {
    let stage_dir = std::env::temp_dir().join(format!(
        "basil-compose-stage-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&stage_dir)
        .map_err(|error| ConfigurationError::Install(error.to_string()))?;
    let staged_copy = stage_dir.join(
        destination
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("compose.yaml")),
    );
    protected_copy(source, &staged_copy)
        .map_err(|error| ConfigurationError::Install(error.to_string()))?;
    let command = format!(
        "basil config install-compose --config {} --name {} --source {} --destination {}",
        shell_quote(config_path),
        shell_quote(Path::new(name)),
        shell_quote(&staged_copy),
        shell_quote(destination)
    );
    Ok(ComposeInstallOutcome::Staged {
        staged_copy,
        command,
    })
}

fn shell_quote(value: &Path) -> String {
    let value = value.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn validate_bootstrap_header(value: &toml::Value) -> Result<(), ConfigurationError> {
    let table = value.as_table().ok_or_else(|| {
        ConfigurationError::InvalidCorpus("bootstrap must be a TOML table".to_string())
    })?;
    match table.get("schema").and_then(toml::Value::as_str) {
        Some("agent") => {}
        Some(other) => {
            return Err(ConfigurationError::InvalidCorpus(format!(
                "bootstrap schema `{other}` is invalid; expected `agent`"
            )));
        }
        None => {
            return Err(ConfigurationError::InvalidCorpus(
                "bootstrap is missing required string `schema = \"agent\"`".to_string(),
            ));
        }
    }
    match table.get("schemaVersion").and_then(toml::Value::as_integer) {
        Some(CORPUS_SCHEMA_VERSION) => Ok(()),
        Some(1 | 2) => Err(ConfigurationError::InvalidCorpus(
            "schemaVersion 1 and 2 are reserved pre-unification versions; migrate the complete corpus to schemaVersion 3".to_string(),
        )),
        Some(other) => Err(ConfigurationError::InvalidCorpus(format!(
            "schemaVersion `{other}` is unsupported; expected 3"
        ))),
        None => Err(ConfigurationError::InvalidCorpus(
            "bootstrap requires exact integer `schemaVersion = 3`".to_string(),
        )),
    }
}

fn extract_sources(
    value: &toml::Value,
    parent: &Path,
) -> Result<CorpusSources, ConfigurationError> {
    let config = value
        .get("config")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            ConfigurationError::InvalidCorpus("bootstrap requires a `[config]` table".to_string())
        })?;
    let required = |name: &str| -> Result<PathBuf, ConfigurationError> {
        let raw = config
            .get(name)
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                ConfigurationError::InvalidCorpus(format!("`config.{name}` must be a string path"))
            })?;
        Ok(resolve_path(parent, raw))
    };
    let compose_table = match config.get("compose") {
        Some(value) => value.as_table().ok_or_else(|| {
            ConfigurationError::InvalidCorpus("`config.compose` must be a table".to_string())
        })?,
        None => &toml::map::Map::new(),
    };
    let mut compose = BTreeMap::new();
    for (name, value) in compose_table {
        validate_compose_name(name)?;
        let raw = value.as_str().ok_or_else(|| {
            ConfigurationError::InvalidCorpus(format!(
                "`config.compose.{name}` must be a string path"
            ))
        })?;
        compose.insert(name.clone(), resolve_path(parent, raw));
    }
    Ok(CorpusSources {
        catalog: required("catalog")?,
        policy: required("policy")?,
        bundle: required("bundle")?,
        compose,
    })
}

fn validate_compose_name(name: &str) -> Result<(), ConfigurationError> {
    let valid = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if valid {
        Ok(())
    } else {
        Err(ConfigurationError::InvalidCorpus(format!(
            "Compose document name `{name}` has an invalid shape"
        )))
    }
}

fn resolve_path(parent: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        parent.join(path)
    }
}

fn apply_source_override(
    value: &mut toml::Value,
    config_override: &ConfigOverride,
) -> Result<(), ConfigurationError> {
    let target = lookup_mut(value, &config_override.path)?;
    if !target.is_str() {
        return Err(ConfigurationError::InvalidOverride(format!(
            "source target `{}` is not an existing string path",
            config_override.path
        )));
    }
    *target = toml::Value::String(parse_string_value(&config_override.value));
    Ok(())
}

fn apply_scalar_override(
    value: &mut toml::Value,
    config_override: &ConfigOverride,
) -> Result<(), ConfigurationError> {
    let path = config_override.path.as_str();
    if matches!(path, "schema" | "schemaVersion")
        || path.starts_with("config.")
        || path.starts_with("unlock.")
        || path.starts_with("broker-identity.")
        || path.starts_with("invocation.")
        || path == "jwks.tls.key-file"
        || matches!(path, "jwt-role" | "jwt-audience")
    {
        return Err(ConfigurationError::InvalidOverride(format!(
            "target `{path}` is secret-bearing, structural, versioned, or identity-bearing"
        )));
    }
    let target = lookup_mut(value, path)?;
    let replacement = parse_like(target, &config_override.value).map_err(|reason| {
        ConfigurationError::InvalidOverride(format!("target `{path}` {reason}"))
    })?;
    *target = replacement;
    Ok(())
}

fn lookup_mut<'a>(
    root: &'a mut toml::Value,
    path: &str,
) -> Result<&'a mut toml::Value, ConfigurationError> {
    let mut current = root;
    for segment in path.split('.') {
        let table = current.as_table_mut().ok_or_else(|| {
            ConfigurationError::InvalidOverride(format!(
                "target `{path}` crosses a non-table value"
            ))
        })?;
        current = table.get_mut(segment).ok_or_else(|| {
            ConfigurationError::InvalidOverride(format!("target `{path}` does not already exist"))
        })?;
    }
    Ok(current)
}

fn parse_like(target: &toml::Value, raw: &str) -> Result<toml::Value, &'static str> {
    match target {
        toml::Value::String(_) => Ok(toml::Value::String(parse_string_value(raw))),
        toml::Value::Integer(_) => raw
            .parse::<i64>()
            .map(toml::Value::Integer)
            .map_err(|_| "requires an integer value"),
        toml::Value::Float(_) => raw
            .parse::<f64>()
            .map(toml::Value::Float)
            .map_err(|_| "requires a floating-point value"),
        toml::Value::Boolean(_) => raw
            .parse::<bool>()
            .map(toml::Value::Boolean)
            .map_err(|_| "requires `true` or `false`"),
        toml::Value::Datetime(_) => raw
            .parse::<toml::value::Datetime>()
            .map(toml::Value::Datetime)
            .map_err(|_| "requires a TOML datetime value"),
        toml::Value::Array(_) | toml::Value::Table(_) => {
            Err("is structural; only scalar leaves may be overridden")
        }
    }
}

fn parse_string_value(raw: &str) -> String {
    let parsed = format!("value = {raw}")
        .parse::<toml::Table>()
        .ok()
        .and_then(|mut table| table.remove("value"))
        .and_then(|value| value.as_str().map(ToOwned::to_owned));
    parsed.unwrap_or_else(|| raw.to_string())
}

fn read_structured(slot: &str, path: &Path) -> Result<JsonValue, ConfigurationError> {
    let raw = std::fs::read_to_string(path).map_err(|source| ConfigurationError::ReadDocument {
        slot: slot.to_string(),
        path: path.to_path_buf(),
        source,
    })?;
    let extension = path.extension().and_then(std::ffi::OsStr::to_str);
    match extension {
        Some("json") => {
            serde_json::from_str(&raw).map_err(|error| ConfigurationError::ParseDocument {
                slot: slot.to_string(),
                path: path.to_path_buf(),
                reason: error.to_string(),
            })
        }
        Some("toml") => {
            let value = toml::from_str::<toml::Value>(&raw).map_err(|error| {
                ConfigurationError::ParseDocument {
                    slot: slot.to_string(),
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                }
            })?;
            serde_json::to_value(value).map_err(|error| ConfigurationError::ParseDocument {
                slot: slot.to_string(),
                path: path.to_path_buf(),
                reason: error.to_string(),
            })
        }
        Some("yaml" | "yml") => {
            serde_yaml::from_str(&raw).map_err(|error| ConfigurationError::ParseDocument {
                slot: slot.to_string(),
                path: path.to_path_buf(),
                reason: error.to_string(),
            })
        }
        _ => Err(ConfigurationError::ParseDocument {
            slot: slot.to_string(),
            path: path.to_path_buf(),
            reason: "structured document path must end in .json, .toml, .yaml, or .yml".to_string(),
        }),
    }
}

fn require_schema(
    value: &JsonValue,
    expected: &str,
    path: &Path,
) -> Result<(), ConfigurationError> {
    let actual = value
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(JsonValue::as_str);
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ConfigurationError::InvalidCorpus(format!(
            "document {} has schema `{actual}`, expected `{expected}`",
            path.display()
        ))),
        None => Err(ConfigurationError::InvalidCorpus(format!(
            "document {} is missing required schema `{expected}`",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, body: &str) {
        std::fs::write(path, body).expect("write fixture");
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "basil-corpus-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        dir
    }

    #[test]
    fn exact_version_and_relative_sources_are_required() {
        let dir = temp_dir();
        let config = dir.join("config.toml");
        write(
            &config,
            r#"schema = "agent"
schemaVersion = 3
socket = "/run/basil.sock"
[config]
catalog = "catalog.json"
policy = "policy.json"
bundle = "bundle.age"
[config.compose]
web = "web.yaml"
"#,
        );
        let loaded = load_bootstrap(Some(&config), &[]).expect("load bootstrap");
        assert_eq!(loaded.sources.catalog, dir.join("catalog.json"));
        assert_eq!(
            loaded.sources.compose.get("web"),
            Some(&dir.join("web.yaml"))
        );

        write(
            &config,
            "schema = \"agent\"\nschemaVersion = 2\n[config]\ncatalog = \"a\"\npolicy = \"b\"\nbundle = \"c\"\n",
        );
        let error = load_bootstrap(Some(&config), &[]).expect_err("version 2 rejects");
        assert!(error.to_string().contains("reserved pre-unification"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn source_then_scalar_overrides_are_typed_and_bounded() {
        let dir = temp_dir();
        let config = dir.join("config.toml");
        write(
            &config,
            r#"schema = "agent"
schemaVersion = 3
max-payload-size = 42
[config]
catalog = "catalog.json"
policy = "policy.json"
bundle = "bundle.age"
"#,
        );
        let overrides = [
            ConfigOverride::parse("config.catalog=other.json").expect("source override"),
            ConfigOverride::parse("max-payload-size=64").expect("scalar override"),
        ];
        let loaded = load_bootstrap(Some(&config), &overrides).expect("load overrides");
        assert_eq!(loaded.sources.catalog, dir.join("other.json"));
        assert_eq!(
            loaded
                .value
                .get("max-payload-size")
                .and_then(toml::Value::as_integer),
            Some(64)
        );

        let forbidden = [ConfigOverride::parse("schemaVersion=4").expect("parse")];
        assert!(load_bootstrap(Some(&config), &forbidden).is_err());
        let structural = [ConfigOverride::parse("config.compose=x").expect("parse")];
        assert!(load_bootstrap(Some(&config), &structural).is_err());
        let duplicate = [
            ConfigOverride::parse("max-payload-size=64").expect("parse"),
            ConfigOverride::parse("max-payload-size=65").expect("parse"),
        ];
        let error = load_bootstrap(Some(&config), &duplicate).expect_err("duplicates reject");
        assert!(error.to_string().contains("duplicate target"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn catalog_scalar_overrides_are_typed_and_policy_identity_is_immutable() {
        let dir = temp_dir();
        let catalog = dir.join("catalog.json");
        let policy = dir.join("policy.json");
        write(
            &catalog,
            r#"{
  "schema": "catalog",
  "backends": {"bao": {"kind": "vault", "addr": "https://127.0.0.1:8200"}},
  "keys": {"web.signer": {
    "class": "asymmetric", "keyType": "ed25519", "backend": "bao",
    "path": "web", "writable": false, "missing": "error",
    "description": "old description"
  }}
}"#,
        );
        write(
            &policy,
            r#"{
  "schema": "policy",
  "subjects": {"svc.web": {"allOf": [{"kind": "unix", "uid": 1000}]}},
  "roles": {}, "rules": [], "config": {}
}"#,
        );
        let sources = CorpusSources {
            catalog: catalog.clone(),
            policy,
            bundle: dir.join("bundle.age"),
            compose: BTreeMap::new(),
        };
        let overrides = [
            ConfigOverride::parse("catalog.keys.web.signer.writable=true").expect("parse"),
            ConfigOverride::parse("catalog.keys.web.signer.description=reviewed").expect("parse"),
        ];
        let documents = load_documents_with_overrides(&sources, &overrides, Vec::new())
            .expect("apply document overrides");
        let key = documents.catalog.keys.get("web.signer").expect("key");
        assert!(key.writable);
        assert_eq!(key.description, "reviewed");
        assert_eq!(documents.overrides.len(), 2);
        assert_eq!(documents.overrides[0].masked_source, catalog);

        let wrong_type =
            [ConfigOverride::parse("catalog.keys.web.signer.writable=yes").expect("parse")];
        let error = load_documents_with_overrides(&sources, &wrong_type, Vec::new())
            .expect_err("type change rejects");
        assert!(error.to_string().contains("requires `true` or `false`"));

        let identity =
            [ConfigOverride::parse("catalog.keys.web.signer.path=other").expect("parse")];
        let error = load_documents_with_overrides(&sources, &identity, Vec::new())
            .expect_err("identity rejects");
        assert!(error.to_string().contains("identity-bearing"));

        let subject =
            [ConfigOverride::parse("policy.subjects.svc.web.allOf=false").expect("parse")];
        let error = load_documents_with_overrides(&sources, &subject, Vec::new())
            .expect_err("subject mutation rejects");
        assert!(error.to_string().contains("policy-bearing"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn compose_install_is_protected_atomic_and_comment_preserving() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp_dir();
        let config = dir.join("config.toml");
        let source = dir.join("reviewed.yaml");
        let destination = dir.join("compose.d/web.yaml");
        write(
            &config,
            "# operator comment\nschema = \"agent\"\nschemaVersion = 3\n[config]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.age\"\n",
        );
        write(&source, "schema: compose\nname: web\n");

        let outcome = install_compose_document(&config, "web", &source, &destination)
            .expect("install Compose document");
        assert!(matches!(outcome, ComposeInstallOutcome::Installed { .. }));
        let installed = std::fs::read_to_string(&destination).expect("read protected copy");
        assert!(installed.contains("schema: compose"));
        let mode = std::fs::metadata(&destination)
            .expect("copy metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let updated = std::fs::read_to_string(&config).expect("read updated bootstrap");
        assert!(updated.contains("# operator comment"));
        let loaded = load_bootstrap(Some(&config), &[]).expect("updated bootstrap validates");
        assert_eq!(loaded.sources.compose.get("web"), Some(&destination));
        std::fs::remove_dir_all(dir).ok();
    }
}
