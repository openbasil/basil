// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Provider-independent runtime-attestor realm configuration and supervision.
//!
//! Realm configuration is trusted routing authority. This module validates the
//! protected schema, keeps one serial session per realm, and provides the
//! failure-atomic preparation boundary used by configuration reload. Provider
//! evidence collection remains behind [`RealmConnector`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::{Notify, watch};

use crate::attestor_protocol::wire;
use crate::attestor_protocol::{
    InventoryResult, MOUNT_SECURITY_CAPABILITY, QueryScope, RequestBudget, ResolvePeerResult,
    VerifiedPeerBinding,
};
use crate::release_admission::{
    ActiveArtifact, ArtifactRole, CapabilityId, CapabilitySet, ProtocolVersion, ReleaseAdmission,
    ReleaseIdentity, Sha256Digest, TargetTriple,
};

/// Maximum number of configured attestor realms.
pub const MAX_REALMS: usize = 64;
/// Maximum byte length of one canonical realm name.
pub const MAX_REALM_NAME_BYTES: usize = 63;
/// Maximum byte length of one canonical service unit.
pub const MAX_UNIT_NAME_BYTES: usize = 128;
/// Maximum byte length of one canonical packaged policy or ACL identity.
pub const MAX_IDENTITY_BYTES: usize = 128;
/// Linux `sockaddr_un.sun_path` payload limit, including the trailing NUL.
pub const MAX_SOCKET_PATH_BYTES: usize = 107;
/// Protocol 1 capabilities required by every configured realm.
pub const REQUIRED_CAPABILITIES: [&str; 3] = ["health", "query-instances", "resolve-peer"];

/// Complete closed capability vocabulary accepted in protocol 1 realm configuration.
const KNOWN_CAPABILITIES: [&str; 4] = [
    "health",
    MOUNT_SECURITY_CAPABILITY,
    "query-instances",
    "resolve-peer",
];

const CONNECT_STEP_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_RECONNECT_BACKOFF: Duration = Duration::from_millis(250);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);
const MAX_RECONNECT_JITTER_MILLIS: u64 = 250;

/// A canonical protected attestor realm name.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RealmName(String);

impl RealmName {
    /// Validate and copy one realm name.
    ///
    /// # Errors
    ///
    /// Returns [`RealmConfigError`] when the name is empty, overlong, or not in
    /// the closed lowercase ASCII grammar.
    pub fn new(raw: &str) -> Result<Self, RealmConfigError> {
        let bytes = raw.as_bytes();
        let valid_edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
        let valid_inner = |byte: u8| valid_edge(byte) || matches!(byte, b'_' | b'-');
        let valid = !bytes.is_empty()
            && bytes.len() <= MAX_REALM_NAME_BYTES
            && bytes.first().copied().is_some_and(valid_edge)
            && bytes.last().copied().is_some_and(valid_edge)
            && bytes.iter().copied().all(valid_inner);
        if !valid {
            return Err(RealmConfigError::InvalidRealmName(raw.to_string()));
        }
        Ok(Self(raw.to_string()))
    }

    /// Borrow the canonical name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RealmName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One canonical decimal user identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmUser {
    spelling: String,
    uid: u32,
}

impl RealmUser {
    fn parse(field: &'static str, raw: &str) -> Result<Self, RealmConfigError> {
        let uid = canonical_decimal_u32(raw).ok_or_else(|| RealmConfigError::InvalidUid {
            field,
            value: raw.to_string(),
        })?;
        Ok(Self {
            spelling: raw.to_string(),
            uid,
        })
    }

    /// Return the parsed user ID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Borrow the protected canonical spelling.
    #[must_use]
    pub fn spelling(&self) -> &str {
        &self.spelling
    }
}

/// One canonical decimal group identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmGroup {
    spelling: String,
    gid: u32,
}

impl RealmGroup {
    fn parse(field: &'static str, raw: &str) -> Result<Self, RealmConfigError> {
        let gid = canonical_decimal_u32(raw).ok_or_else(|| RealmConfigError::InvalidGid {
            field,
            value: raw.to_string(),
        })?;
        Ok(Self {
            spelling: raw.to_string(),
            gid,
        })
    }

    /// Return the parsed group ID.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// Borrow the protected canonical spelling.
    #[must_use]
    pub fn spelling(&self) -> &str {
        &self.spelling
    }
}

/// One exact four-digit octal permission mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OctalMode {
    spelling: String,
    bits: u32,
}

impl OctalMode {
    fn parse(field: &'static str, raw: &str) -> Result<Self, RealmConfigError> {
        let canonical = raw.len() == 4 && raw.bytes().all(|byte| (b'0'..=b'7').contains(&byte));
        let bits = canonical
            .then(|| u32::from_str_radix(raw, 8).ok())
            .flatten()
            .ok_or_else(|| RealmConfigError::InvalidMode {
                field,
                value: raw.to_string(),
            })?;
        Ok(Self {
            spelling: raw.to_string(),
            bits,
        })
    }

    /// Return the parsed permission bits.
    #[must_use]
    pub const fn bits(&self) -> u32 {
        self.bits
    }

    /// Borrow the protected exact four-digit octal spelling.
    #[must_use]
    pub fn spelling(&self) -> &str {
        &self.spelling
    }
}

fn canonical_decimal_u32(raw: &str) -> Option<u32> {
    if raw.is_empty() || raw.len() > 10 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = raw.parse::<u32>().ok()?;
    (value.to_string() == raw).then_some(value)
}

/// Closed runtime-attestor provider set.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RealmProvider {
    /// Rootful Docker provider.
    Docker,
    /// Rootless Podman provider.
    Podman,
}

impl RealmProvider {
    const fn wire_runtime(self) -> wire::RuntimeKind {
        match self {
            Self::Docker => wire::RuntimeKind::Docker,
            Self::Podman => wire::RuntimeKind::Podman,
        }
    }
}

/// Closed provider account and service-manager scope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum RealmMode {
    /// Dedicated host service managed by the system manager.
    RootfulHost,
    /// Non-root runtime owner whose generation-qualified attestor service is
    /// still an administrator-owned system-manager unit.
    RootlessOwner,
}

impl RealmMode {
    const fn wire_runtime(self) -> wire::RuntimeMode {
        match self {
            Self::RootfulHost => wire::RuntimeMode::Rootful,
            Self::RootlessOwner => wire::RuntimeMode::Rootless,
        }
    }
}

/// Fully validated protected configuration for one realm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmConfig {
    /// Closed attestor provider.
    pub provider: RealmProvider,
    /// Provider account and service-manager scope.
    pub runtime_mode: RealmMode,
    /// Exact broker account.
    pub broker_user: RealmUser,
    /// Exact broker service unit, deliberately not generation-qualified.
    pub broker_unit: String,
    /// Exact attestor account (`attestorUid`) and rootless routing scope.
    pub attestor_user: RealmUser,
    /// Required release artifact role.
    pub release_role: ArtifactRole,
    /// Required release target.
    pub target: TargetTriple,
    /// Exact private protocol version.
    pub protocol: ProtocolVersion,
    /// Sorted complete protocol capability set.
    pub capabilities: CapabilitySet,
    /// Indivisible protected measurement authority for this realm.
    pub measurement: MeasurementAuthority,
}

/// One indivisible protected measurement-authority block.
///
/// Every generation qualifier below is a checked binding pinned to the exact
/// decimal [`Self::authority_generation`] (or, for the helper policy, to
/// [`Self::helper_policy_generation`]) — never a naming convention. The same
/// pinned values are revalidated by the authority-installation transaction and
/// at live authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementAuthority {
    /// Immutable nonzero authority installation generation for this realm.
    pub authority_generation: NonZeroU64,
    /// Exact canonical attestor system unit ending in
    /// `-g<authorityGeneration>.service`.
    pub service_unit: String,
    /// The one shared packaged measurement-helper endpoint, deliberately not
    /// generation-qualified.
    pub helper_endpoint: PathBuf,
    /// Exact packaged helper policy identity, generation-qualified by
    /// [`Self::helper_policy_generation`].
    pub helper_policy: String,
    /// Nonzero helper policy generation, checked independently of the broker
    /// configuration generation.
    pub helper_policy_generation: NonZeroU64,
    /// Exact packaged LSM profile identity.
    pub lsm_profile: String,
    /// Exact packaged LSM policy identity.
    pub lsm_policy: String,
    /// Exact packaged lockdown profile identity.
    pub lockdown_profile: String,
    /// Generation-qualified runtime directory whose final segment is exactly
    /// `g<authorityGeneration>`.
    pub runtime_directory: PathBuf,
    /// Runtime directory owner.
    pub runtime_directory_owner: RealmUser,
    /// Runtime directory group.
    pub runtime_directory_group: RealmGroup,
    /// Runtime directory permission mode.
    pub runtime_directory_mode: OctalMode,
    /// Exact packaged runtime-directory ACL identity.
    pub runtime_directory_acl: String,
    /// Canonical private control socket directly beneath the runtime
    /// directory.
    pub socket_path: PathBuf,
    /// Socket owner.
    pub socket_owner: RealmUser,
    /// Socket group.
    pub socket_group: RealmGroup,
    /// Socket permission mode.
    pub socket_mode: OctalMode,
    /// Exact packaged socket ACL identity.
    pub socket_acl: String,
}

/// Bounded protected realm map in deterministic name order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RealmSet(BTreeMap<RealmName, RealmConfig>);

impl RealmSet {
    /// Parse the optional `attestor` object from one schema-3 bootstrap value.
    ///
    /// Each realm must carry its complete nested `measurement` authority; the
    /// block is parsed indivisibly and every embedded generation qualifier is
    /// checked against the exact decimal pinned generations.
    ///
    /// # Errors
    ///
    /// Returns [`RealmConfigError`] for unknown fields, invalid types, bounds,
    /// identifiers, provider/mode combinations, an absent or partial
    /// `measurement` authority, a generation-binding violation, or
    /// socket/account mismatch.
    pub fn from_bootstrap(value: &toml::Value) -> Result<Self, RealmConfigError> {
        let Some(raw) = value.get("attestor") else {
            return Ok(Self::default());
        };
        let document: RawAttestor = raw
            .clone()
            .try_into()
            .map_err(|error: toml::de::Error| RealmConfigError::Schema(error.to_string()))?;
        if document.realms.len() > MAX_REALMS {
            return Err(RealmConfigError::TooManyRealms {
                maximum: MAX_REALMS,
            });
        }
        let mut realms = BTreeMap::new();
        for (raw_name, raw_config) in document.realms {
            let name = RealmName::new(&raw_name)?;
            let config = raw_config.validate(&name)?;
            realms.insert(name, config);
        }
        Ok(Self(realms))
    }

    /// Return the number of configured realms.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no realm is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrow one exact realm configuration.
    #[must_use]
    pub fn get(&self, name: &RealmName) -> Option<&RealmConfig> {
        self.0.get(name)
    }

    /// Iterate in canonical realm-name order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&RealmName, &RealmConfig)> {
        self.0.iter()
    }

    /// Verify that every protected realm names the broker's pinned effective
    /// user ID.
    ///
    /// # Errors
    ///
    /// Returns [`RealmConfigError::BrokerUidMismatch`] on the first mismatch.
    pub fn validate_broker_uid(&self, effective_uid: u32) -> Result<(), RealmConfigError> {
        if self
            .0
            .values()
            .all(|config| config.broker_user.uid() == effective_uid)
        {
            Ok(())
        } else {
            Err(RealmConfigError::BrokerUidMismatch)
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAttestor {
    #[serde(default)]
    realms: BTreeMap<String, RawRealmConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRealmConfig {
    provider: RealmProvider,
    runtime_mode: RealmMode,
    broker_user: String,
    broker_unit: String,
    attestor_uid: String,
    release_role: String,
    target: String,
    protocol: u32,
    capabilities: Vec<String>,
    measurement: Option<RawMeasurement>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawMeasurement {
    authority_generation: u64,
    service_unit: String,
    helper_endpoint: String,
    helper_policy: String,
    helper_policy_generation: u64,
    lsm_profile: String,
    lsm_policy: String,
    lockdown_profile: String,
    runtime_directory: String,
    runtime_directory_owner: String,
    runtime_directory_group: String,
    runtime_directory_mode: String,
    runtime_directory_acl: String,
    socket_path: String,
    socket_owner: String,
    socket_group: String,
    socket_mode: String,
    socket_acl: String,
}

impl RawRealmConfig {
    fn validate(self, name: &RealmName) -> Result<RealmConfig, RealmConfigError> {
        if !matches!(
            (self.provider, self.runtime_mode),
            (RealmProvider::Docker, RealmMode::RootfulHost)
                | (RealmProvider::Podman, RealmMode::RootlessOwner)
        ) {
            return Err(RealmConfigError::ProviderMode {
                provider: self.provider,
                mode: self.runtime_mode,
            });
        }
        let broker_user = RealmUser::parse("brokerUser", &self.broker_user)?;
        let attestor_user = RealmUser::parse("attestorUid", &self.attestor_uid)?;
        validate_unit("brokerUnit", &self.broker_unit)?;
        if self.runtime_mode == RealmMode::RootlessOwner && attestor_user.uid() == 0 {
            return Err(RealmConfigError::RootlessRoot);
        }
        let measurement = self
            .measurement
            .ok_or_else(|| RealmConfigError::MissingMeasurement {
                realm: name.as_str().to_string(),
            })?
            .validate(name)?;
        if self.protocol != 1 {
            return Err(RealmConfigError::UnsupportedProtocol(self.protocol));
        }
        let capabilities = CapabilitySet::try_from_iter(
            self.capabilities
                .iter()
                .map(|item| CapabilityId::new(item))
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let actual = capabilities
            .iter()
            .map(CapabilityId::as_str)
            .collect::<Vec<_>>();
        let has_required = REQUIRED_CAPABILITIES
            .iter()
            .all(|required| actual.binary_search(required).is_ok());
        let all_known = actual
            .iter()
            .all(|capability| KNOWN_CAPABILITIES.binary_search(capability).is_ok());
        if !has_required || !all_known {
            return Err(RealmConfigError::Capabilities);
        }
        Ok(RealmConfig {
            provider: self.provider,
            runtime_mode: self.runtime_mode,
            broker_user,
            broker_unit: self.broker_unit,
            attestor_user,
            release_role: ArtifactRole::new(&self.release_role)?,
            target: TargetTriple::new(&self.target)?,
            protocol: ProtocolVersion::new(self.protocol)?,
            capabilities,
            measurement,
        })
    }
}

impl RawMeasurement {
    /// Validate one indivisible measurement block, pinning every generation
    /// qualifier to the exact decimal authority and helper-policy generations.
    fn validate(self, name: &RealmName) -> Result<MeasurementAuthority, RealmConfigError> {
        let authority_generation =
            NonZeroU64::new(self.authority_generation).ok_or(RealmConfigError::GenerationZero {
                field: "measurement.authorityGeneration",
            })?;
        let helper_policy_generation = NonZeroU64::new(self.helper_policy_generation).ok_or(
            RealmConfigError::GenerationZero {
                field: "measurement.helperPolicyGeneration",
            },
        )?;

        validate_unit("measurement.serviceUnit", &self.service_unit)?;
        validate_generation_binding(
            "measurement.serviceUnit",
            &self.service_unit,
            authority_generation,
        )?;
        let unit_qualifier = format!("-g{authority_generation}.service");
        if !self.service_unit.ends_with(&unit_qualifier) {
            return Err(RealmConfigError::GenerationQualifierMissing {
                field: "measurement.serviceUnit",
            });
        }

        validate_authority_path("measurement.helperEndpoint", &self.helper_endpoint)?;

        for (field, value) in [
            ("measurement.lsmProfile", &self.lsm_profile),
            ("measurement.lsmPolicy", &self.lsm_policy),
            ("measurement.lockdownProfile", &self.lockdown_profile),
            (
                "measurement.runtimeDirectoryAcl",
                &self.runtime_directory_acl,
            ),
            ("measurement.socketAcl", &self.socket_acl),
        ] {
            validate_identity(field, value)?;
            validate_generation_binding(field, value, authority_generation)?;
        }
        validate_identity("measurement.helperPolicy", &self.helper_policy)?;
        validate_generation_binding(
            "measurement.helperPolicy",
            &self.helper_policy,
            helper_policy_generation,
        )?;

        validate_authority_path("measurement.runtimeDirectory", &self.runtime_directory)?;
        validate_generation_binding(
            "measurement.runtimeDirectory",
            &self.runtime_directory,
            authority_generation,
        )?;
        let expected_directory = format!(
            "/run/basil/attestors/{}/g{authority_generation}",
            name.as_str()
        );
        if self.runtime_directory != expected_directory {
            return Err(RealmConfigError::RuntimeDirectoryScope {
                expected: PathBuf::from(expected_directory),
            });
        }

        validate_authority_path("measurement.socketPath", &self.socket_path)?;
        validate_generation_binding(
            "measurement.socketPath",
            &self.socket_path,
            authority_generation,
        )?;
        let expected_socket = format!("{expected_directory}/control.sock");
        if self.socket_path != expected_socket {
            return Err(RealmConfigError::SocketScope {
                expected: PathBuf::from(expected_socket),
            });
        }

        Ok(MeasurementAuthority {
            authority_generation,
            service_unit: self.service_unit,
            helper_endpoint: PathBuf::from(self.helper_endpoint),
            helper_policy: self.helper_policy,
            helper_policy_generation,
            lsm_profile: self.lsm_profile,
            lsm_policy: self.lsm_policy,
            lockdown_profile: self.lockdown_profile,
            runtime_directory: PathBuf::from(self.runtime_directory),
            runtime_directory_owner: RealmUser::parse(
                "measurement.runtimeDirectoryOwner",
                &self.runtime_directory_owner,
            )?,
            runtime_directory_group: RealmGroup::parse(
                "measurement.runtimeDirectoryGroup",
                &self.runtime_directory_group,
            )?,
            runtime_directory_mode: OctalMode::parse(
                "measurement.runtimeDirectoryMode",
                &self.runtime_directory_mode,
            )?,
            runtime_directory_acl: self.runtime_directory_acl,
            socket_path: PathBuf::from(self.socket_path),
            socket_owner: RealmUser::parse("measurement.socketOwner", &self.socket_owner)?,
            socket_group: RealmGroup::parse("measurement.socketGroup", &self.socket_group)?,
            socket_mode: OctalMode::parse("measurement.socketMode", &self.socket_mode)?,
            socket_acl: self.socket_acl,
        })
    }
}

fn validate_unit(field: &'static str, unit: &str) -> Result<(), RealmConfigError> {
    let valid = !unit.is_empty()
        && unit.len() <= MAX_UNIT_NAME_BYTES
        && unit.ends_with(".service")
        && unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.' | b'@' | b'-')
        })
        && !unit.contains("..")
        && !unit.contains("\\x");
    if valid {
        Ok(())
    } else {
        Err(RealmConfigError::InvalidUnit {
            field,
            value: unit.to_string(),
        })
    }
}

fn validate_identity(field: &'static str, value: &str) -> Result<(), RealmConfigError> {
    let bytes = value.as_bytes();
    let valid_edge = |byte: u8| byte.is_ascii_alphanumeric();
    let valid_inner = |byte: u8| valid_edge(byte) || matches!(byte, b'.' | b'_' | b':' | b'-');
    let valid = !bytes.is_empty()
        && bytes.len() <= MAX_IDENTITY_BYTES
        && bytes.first().copied().is_some_and(valid_edge)
        && bytes.last().copied().is_some_and(valid_edge)
        && bytes.iter().copied().all(valid_inner);
    if valid {
        Ok(())
    } else {
        Err(RealmConfigError::InvalidIdentity {
            field,
            value: value.to_string(),
        })
    }
}

fn validate_authority_path(field: &'static str, path: &str) -> Result<(), RealmConfigError> {
    let valid = path.len() > 1
        && path.len() <= MAX_SOCKET_PATH_BYTES
        && path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains('\0')
        && !path.contains("//")
        && Path::new(path).components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        });
    if valid {
        Ok(())
    } else {
        Err(RealmConfigError::InvalidAuthorityPath { field })
    }
}

/// Return every delimited `g<digits>` generation qualifier embedded in
/// `value`. A qualifier is a `g` immediately followed by one or more ASCII
/// digits, with no ASCII-alphanumeric byte on either side.
fn generation_qualifiers(value: &str) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut qualifiers = Vec::new();
    let mut previous: Option<u8> = None;
    let mut index = 0_usize;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'g' && !previous.is_some_and(|before| before.is_ascii_alphanumeric()) {
            let mut end = index.saturating_add(1);
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end = end.saturating_add(1);
            }
            let has_digits = end > index.saturating_add(1);
            let delimited = !bytes.get(end).is_some_and(u8::is_ascii_alphanumeric);
            if has_digits && delimited {
                if let Some(qualifier) = value.get(index..end) {
                    qualifiers.push(qualifier);
                }
                previous = Some(b'0');
                index = end;
                continue;
            }
        }
        previous = Some(byte);
        index = index.saturating_add(1);
    }
    qualifiers
}

/// Enforce the checked generation binding: `value` must embed at least one
/// generation qualifier, and every embedded qualifier must equal the exact
/// decimal `expected` generation.
fn validate_generation_binding(
    field: &'static str,
    value: &str,
    expected: NonZeroU64,
) -> Result<(), RealmConfigError> {
    let expected_qualifier = format!("g{expected}");
    let qualifiers = generation_qualifiers(value);
    if qualifiers.is_empty() {
        return Err(RealmConfigError::GenerationQualifierMissing { field });
    }
    if qualifiers
        .iter()
        .any(|qualifier| *qualifier != expected_qualifier)
    {
        return Err(RealmConfigError::GenerationQualifierMismatch { field });
    }
    Ok(())
}

/// Typed strict realm-configuration failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RealmConfigError {
    /// The `attestor` object did not match its strict schema.
    #[error("invalid `attestor` schema: {0}")]
    Schema(String),
    /// More realms were supplied than the compiled ceiling.
    #[error("realm count exceeds maximum {maximum}")]
    TooManyRealms {
        /// Compiled maximum.
        maximum: usize,
    },
    /// A realm name was not canonical.
    #[error("invalid realm name `{0}`")]
    InvalidRealmName(String),
    /// A UID field did not use canonical decimal form.
    #[error("`{field}` is not a canonical decimal UID")]
    InvalidUid {
        /// Schema field.
        field: &'static str,
        /// Rejected value, retained only in the local typed error.
        value: String,
    },
    /// A GID field did not use canonical decimal form.
    #[error("`{field}` is not a canonical decimal GID")]
    InvalidGid {
        /// Schema field.
        field: &'static str,
        /// Rejected value, retained only in the local typed error.
        value: String,
    },
    /// A mode field was not an exact four-digit octal mode.
    #[error("`{field}` is not an exact four-digit octal mode")]
    InvalidMode {
        /// Schema field.
        field: &'static str,
        /// Rejected value, retained only in the local typed error.
        value: String,
    },
    /// A policy, profile, or ACL identity was not a canonical ASCII
    /// identifier.
    #[error("`{field}` is not a canonical packaged identity")]
    InvalidIdentity {
        /// Schema field.
        field: &'static str,
        /// Rejected value, retained only in the local typed error.
        value: String,
    },
    /// An older schema-3 realm predates the protected measurement authority.
    #[error(
        "realm `{realm}` lacks the `measurement` authority required since revision 1.2; \
         stage a complete generation-qualified `measurement` block as a new immutable \
         authority generation and promote it atomically"
    )]
    MissingMeasurement {
        /// Realm that must be migrated.
        realm: String,
    },
    /// A generation field was zero.
    #[error("`{field}` must be a nonzero generation")]
    GenerationZero {
        /// Schema field.
        field: &'static str,
    },
    /// A generation-qualified field carried no embedded generation qualifier.
    #[error("`{field}` lacks its required embedded generation qualifier")]
    GenerationQualifierMissing {
        /// Schema field.
        field: &'static str,
    },
    /// A field embedded a generation other than the exact pinned decimal
    /// generation.
    #[error("`{field}` embeds a generation qualifier that differs from the pinned generation")]
    GenerationQualifierMismatch {
        /// Schema field.
        field: &'static str,
    },
    /// A service unit was not canonical.
    #[error("`{field}` is not a canonical systemd service unit")]
    InvalidUnit {
        /// Schema field.
        field: &'static str,
        /// Rejected value, retained only in the local typed error.
        value: String,
    },
    /// The provider/mode pair is outside the closed matrix.
    #[error("provider `{provider:?}` does not support mode `{mode:?}`")]
    ProviderMode {
        /// Configured provider.
        provider: RealmProvider,
        /// Configured mode.
        mode: RealmMode,
    },
    /// Rootless mode selected UID 0.
    #[error("rootless attestor UID must be nonzero")]
    RootlessRoot,
    /// A realm names a broker account other than the pinned process account.
    #[error("configured broker UID does not match the pinned effective UID")]
    BrokerUidMismatch,
    /// An authority path was not absolute, normalized, and bounded.
    #[error("`{field}` is not an absolute, normalized path within the Linux socket bound")]
    InvalidAuthorityPath {
        /// Schema field.
        field: &'static str,
    },
    /// The runtime directory did not match the protected realm authority
    /// scope.
    #[error("runtime directory does not match the protected realm authority scope")]
    RuntimeDirectoryScope {
        /// Required path, retained for trusted configuration diagnostics.
        expected: PathBuf,
    },
    /// The socket did not sit directly beneath the runtime directory at the
    /// protected realm scope.
    #[error("socket path does not match the protected realm scope")]
    SocketScope {
        /// Required path, retained for trusted configuration diagnostics.
        expected: PathBuf,
    },
    /// Protocol 1 is the only accepted protocol.
    #[error("unsupported attestor protocol `{0}`")]
    UnsupportedProtocol(u32),
    /// Protocol 1 requires its baseline capabilities and rejects unknown additions.
    #[error("protocol 1 capabilities must contain every required value and only known additions")]
    Capabilities,
    /// A release-admission identity was invalid.
    #[error(transparent)]
    Identity(#[from] crate::release_admission::IdentityError),
    /// A capability collection was invalid.
    #[error(transparent)]
    Collection(#[from] crate::release_admission::CollectionError),
}

/// Stable socket identity captured without following a replacement path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketIdentity {
    /// Filesystem device.
    pub device: u64,
    /// Socket inode.
    pub inode: u64,
    /// Socket owner.
    pub owner: u32,
    /// Permission bits.
    pub mode: u32,
}

/// Public realm serving state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmState {
    /// Expected socket is absent.
    Absent,
    /// Connecting to the configured socket.
    Connecting,
    /// Authenticating the peer and admitted artifact.
    Authenticating,
    /// Binding the private protocol session.
    Handshaking,
    /// Qualifying provider health.
    HealthChecking,
    /// The accepted session can serve.
    Ready,
    /// The accepted session failed closed.
    Degraded,
    /// Same-socket qualification has no serving session.
    Staging,
    /// A removed session is draining.
    Draining,
}

/// Disclosure-safe reason for one realm state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmReason {
    /// No failure.
    None,
    /// Configured socket is absent.
    SocketAbsent,
    /// Connection has not completed.
    Connecting,
    /// Peer authentication failed.
    AuthenticationFailed,
    /// Release admission failed.
    AdmissionFailed,
    /// Private protocol failed.
    ProtocolFailed,
    /// Provider health failed.
    HealthFailed,
    /// Accepted authority is draining.
    Draining,
}

/// Disclosure-safe status for one accepted realm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmStatus {
    /// Canonical protected realm name.
    pub name: RealmName,
    /// Closed provider.
    pub provider: RealmProvider,
    /// Closed runtime mode.
    pub mode: RealmMode,
    /// Public serving-state projection.
    pub state: RealmState,
    /// Accepted configuration generation.
    pub generation: u64,
    /// Current authoritative session epoch, or zero before first success.
    pub session_epoch: u64,
    /// Exact private protocol version.
    pub protocol: u32,
    /// Coarse disclosure-safe reason.
    pub reason: RealmReason,
}

/// Aggregate ungated realm readiness partition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RealmReadiness {
    /// Accepted realms.
    pub total: u32,
    /// Accepted realms projected ready.
    pub ready: u32,
    /// Accepted non-ready, non-absent realms.
    pub degraded: u32,
    /// Accepted absent realms.
    pub absent: u32,
}

/// Provider-independent session failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RealmError {
    /// The configured socket is absent.
    #[error("attestor socket is absent")]
    SocketAbsent,
    /// Connecting failed without provider detail disclosure.
    #[error("attestor connection failed")]
    Connect,
    /// Peer/account/unit authentication failed.
    #[error("attestor authentication failed")]
    Authentication,
    /// Release admission failed.
    #[error("attestor release admission failed")]
    Admission,
    /// Protocol binding or response validation failed.
    #[error("attestor protocol failed")]
    Protocol,
    /// Health qualification failed.
    #[error("attestor health qualification failed")]
    Health,
    /// A generation, revision, epoch, actor, or preparation token went stale.
    #[error("attestor realm result is stale")]
    Stale,
    /// The realm is not ready to serve.
    #[error("attestor realm is unavailable")]
    Unavailable,
    /// The caller's request budget elapsed before attestor dispatch.
    #[error("attestor request budget exhausted")]
    BudgetExhausted,
    /// A checked monotonic counter was exhausted.
    #[error("attestor realm counter exhausted")]
    CounterExhausted,
    /// Another preparation owns an affected realm.
    #[error("attestor realm preparation conflicts with an active preparation")]
    PreparationConflict,
    /// A serial supervisor already owns this realm.
    #[error("attestor realm supervisor is already running")]
    SupervisorRunning,
    /// Dry-run cannot activate a same-socket security change.
    #[error("same-socket realm change requires live qualification")]
    QualificationRequired,
}

/// One measured and admitted provider connection before protocol handshake.
#[async_trait]
pub trait RealmConnection: Send {
    /// Authenticate the peer and return a session holding one active release
    /// guard. Implementations must repeat all checks for every connection.
    async fn authenticate(
        self: Box<Self>,
        config: &RealmConfig,
        generation: u64,
        epoch: u64,
        admission: &ReleaseAdmission,
    ) -> Result<AuthenticatedRealmSession, RealmError>;

    /// Close an unauthenticated connection during cancellation or failure.
    async fn close(self: Box<Self>);
}

/// Provider seam that opens only the one protected configured socket.
///
/// The interface deliberately has no discovery, listener, registration, path
/// mutation, or stale-socket unlink operation.
#[async_trait]
pub trait RealmConnector: Send + Sync {
    /// Open the configured outbound control socket and pin its identity.
    async fn connect(&self, config: &RealmConfig) -> Result<Box<dyn RealmConnection>, RealmError>;

    /// Revalidate one staged socket identity before atomic commit.
    async fn revalidate(
        &self,
        config: &RealmConfig,
        identity: SocketIdentity,
    ) -> Result<(), RealmError>;
}

/// Serial private protocol operations used by a realm supervisor.
#[async_trait]
pub trait RealmSession: Send {
    /// Complete the mandatory fresh handshake.
    async fn handshake(&mut self) -> Result<(), RealmError>;
    /// Return negotiated capabilities after handshake.
    fn negotiated_capabilities(&self) -> &[String];
    /// Run the bounded qualification health call under the caller's budget.
    async fn health(&mut self, budget: RequestBudget) -> Result<wire::HealthFact, RealmError>;
    /// Resolve one pinned broker-observed peer under the caller's budget.
    async fn resolve_peer(
        &mut self,
        peer: wire::PinnedPeer,
        budget: RequestBudget,
    ) -> Result<ResolvePeerResult, RealmError>;
    /// Query one closed inventory scope under the caller's budget.
    async fn query_instances(
        &mut self,
        scope: QueryScope,
        budget: RequestBudget,
    ) -> Result<InventoryResult, RealmError>;
    /// Close the transport. Dropping the owner releases its active artifact.
    async fn close(&mut self);
}

/// Authenticated transport plus the active admitted-artifact reference that
/// spans its complete lifetime.
pub struct AuthenticatedRealmSession {
    session: Box<dyn RealmSession>,
    active_artifact: ActiveArtifact,
    socket_identity: SocketIdentity,
    peer_binding: VerifiedPeerBinding,
}

impl AuthenticatedRealmSession {
    /// Bind a fully authenticated protocol session to its socket, peer, and
    /// active admitted artifact.
    #[must_use]
    pub fn new(
        session: Box<dyn RealmSession>,
        active_artifact: ActiveArtifact,
        socket_identity: SocketIdentity,
        peer_binding: VerifiedPeerBinding,
    ) -> Self {
        Self {
            session,
            active_artifact,
            socket_identity,
            peer_binding,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityState {
    Absent,
    Connecting,
    Authenticating,
    Handshaking,
    HealthChecking,
    Ready,
    Degraded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransitionState {
    None,
    Qualifying,
    Restoring,
}

struct SessionSlot {
    epoch: u64,
    inner: AsyncMutex<AuthenticatedRealmSession>,
}

struct RealmEntry {
    config: RealmConfig,
    revision: u64,
    next_epoch: u64,
    current_epoch: u64,
    actor_version: u64,
    generation: u64,
    authority: AuthorityState,
    transition: TransitionState,
    reason: RealmReason,
    session: Option<Arc<SessionSlot>>,
    connecting: bool,
    supervisor_running: bool,
}

struct DrainingEntry {
    status: RealmStatus,
    _session: Arc<SessionSlot>,
}

struct RegistryState {
    generation: u64,
    entries: BTreeMap<RealmName, RealmEntry>,
    tombstones: BTreeMap<RealmName, u64>,
    draining: BTreeMap<RealmName, DrainingEntry>,
    reservations: BTreeMap<RealmName, u128>,
}

struct RegistryInner {
    state: Mutex<RegistryState>,
    changed: Notify,
}

/// Process-owned realm registry and serial supervisor state.
#[derive(Clone)]
pub struct RealmRegistry {
    inner: Arc<RegistryInner>,
}

impl fmt::Debug for RealmRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock_state();
        formatter
            .debug_struct("RealmRegistry")
            .field("generation", &state.generation)
            .field("realms", &state.entries.len())
            .finish()
    }
}

impl RealmRegistry {
    /// Create an accepted generation whose realms begin absent and isolated.
    ///
    /// # Errors
    ///
    /// Returns [`RealmError::CounterExhausted`] if `generation` is zero.
    pub fn new(realms: &RealmSet, generation: u64) -> Result<Self, RealmError> {
        if generation == 0 {
            return Err(RealmError::CounterExhausted);
        }
        let entries = realms
            .iter()
            .map(|(name, config)| {
                (
                    name.clone(),
                    RealmEntry {
                        config: config.clone(),
                        revision: 1,
                        next_epoch: 0,
                        current_epoch: 0,
                        actor_version: 1,
                        generation,
                        authority: AuthorityState::Absent,
                        transition: TransitionState::None,
                        reason: RealmReason::SocketAbsent,
                        session: None,
                        connecting: false,
                        supervisor_running: false,
                    },
                )
            })
            .collect();
        Ok(Self {
            inner: Arc::new(RegistryInner {
                state: Mutex::new(RegistryState {
                    generation,
                    entries,
                    tombstones: BTreeMap::new(),
                    draining: BTreeMap::new(),
                    reservations: BTreeMap::new(),
                }),
                changed: Notify::new(),
            }),
        })
    }

    /// Current accepted configuration generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.lock_state().generation
    }

    /// Return disclosure-safe accepted realm status, sorted by name.
    #[must_use]
    pub fn statuses(&self) -> Vec<RealmStatus> {
        let state = self.lock_state();
        let mut statuses = state
            .entries
            .iter()
            .map(|(name, entry)| status_for(name, entry))
            .collect::<Vec<_>>();
        statuses.extend(state.draining.values().map(|entry| entry.status.clone()));
        drop(state);
        statuses.sort_by(|left, right| left.name.cmp(&right.name));
        statuses.truncate(MAX_REALMS);
        statuses
    }

    /// Return the ungated accepted-generation readiness partition.
    #[must_use]
    pub fn readiness(&self) -> RealmReadiness {
        let state = self.lock_state();
        let mut result = RealmReadiness::default();
        for (name, entry) in &state.entries {
            result.total = result.total.saturating_add(1);
            match status_for(name, entry).state {
                RealmState::Ready => result.ready = result.ready.saturating_add(1),
                RealmState::Absent => result.absent = result.absent.saturating_add(1),
                RealmState::Connecting
                | RealmState::Authenticating
                | RealmState::Handshaking
                | RealmState::HealthChecking
                | RealmState::Degraded
                | RealmState::Staging
                | RealmState::Draining => {
                    result.degraded = result.degraded.saturating_add(1);
                }
            }
        }
        drop(state);
        result
    }

    /// Perform one complete fresh connection and authentication attempt.
    ///
    /// Every call obtains a new session epoch. No admission result is reused.
    #[allow(clippy::too_many_lines)]
    pub async fn connect_realm(
        &self,
        name: &RealmName,
        connector: &dyn RealmConnector,
        admission: &ReleaseAdmission,
    ) -> Result<(), RealmError> {
        let (config, generation, revision, epoch, old_session) = {
            let mut state = self.lock_state();
            if state.reservations.contains_key(name) {
                return Err(RealmError::PreparationConflict);
            }
            let generation = state.generation;
            let entry = state.entries.get_mut(name).ok_or(RealmError::Unavailable)?;
            if entry.connecting {
                return Err(RealmError::PreparationConflict);
            }
            let epoch = entry
                .next_epoch
                .checked_add(1)
                .ok_or(RealmError::CounterExhausted)?;
            entry.next_epoch = epoch;
            entry.connecting = true;
            transition_entry(entry, AuthorityState::Connecting, RealmReason::Connecting)?;
            let result = (
                entry.config.clone(),
                generation,
                entry.revision,
                epoch,
                entry.session.take(),
            );
            drop(state);
            result
        };
        let _attempt = AttemptLease {
            inner: Arc::clone(&self.inner),
            name: name.clone(),
            revision,
            epoch,
        };
        if let Some(old_session) = old_session {
            close_slot(old_session).await;
        }

        let connection =
            match tokio::time::timeout(CONNECT_STEP_TIMEOUT, connector.connect(&config)).await {
                Ok(Ok(connection)) => connection,
                Ok(Err(error)) => {
                    self.fail_attempt(name, revision, epoch, &error);
                    return Err(error);
                }
                Err(_) => {
                    self.fail_attempt(name, revision, epoch, &RealmError::Connect);
                    return Err(RealmError::Connect);
                }
            };
        self.advance_attempt(name, revision, epoch, AuthorityState::Authenticating)?;
        let mut authenticated = match tokio::time::timeout(
            CONNECT_STEP_TIMEOUT,
            connection.authenticate(&config, generation, epoch, admission),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                self.fail_attempt(name, revision, epoch, &error);
                return Err(error);
            }
            Err(_) => {
                self.fail_attempt(name, revision, epoch, &RealmError::Authentication);
                return Err(RealmError::Authentication);
            }
        };
        self.advance_attempt(name, revision, epoch, AuthorityState::Handshaking)?;
        if tokio::time::timeout(CONNECT_STEP_TIMEOUT, authenticated.session.handshake())
            .await
            .map_err(|_| RealmError::Protocol)?
            .is_err()
        {
            authenticated.session.close().await;
            self.fail_attempt(name, revision, epoch, &RealmError::Protocol);
            return Err(RealmError::Protocol);
        }
        validate_negotiated(&config, authenticated.session.negotiated_capabilities())?;
        self.advance_attempt(name, revision, epoch, AuthorityState::HealthChecking)?;
        let health = tokio::time::timeout(
            CONNECT_STEP_TIMEOUT,
            authenticated
                .session
                .health(RequestBudget::starting_now(CONNECT_STEP_TIMEOUT)),
        )
        .await
        .map_err(|_| RealmError::Health)??;
        if let Err(error) = validate_health(&config, &health) {
            authenticated.session.close().await;
            self.fail_attempt(name, revision, epoch, &error);
            return Err(error);
        }
        let slot = Arc::new(SessionSlot {
            epoch,
            inner: AsyncMutex::new(authenticated),
        });
        let replaced = {
            let mut state = self.lock_state();
            let entry = state.entries.get_mut(name).ok_or(RealmError::Stale)?;
            ensure_attempt(entry, revision, epoch)?;
            let replaced = entry.session.replace(slot);
            entry.current_epoch = epoch;
            entry.connecting = false;
            entry.transition = TransitionState::None;
            transition_entry(entry, AuthorityState::Ready, RealmReason::None)?;
            drop(state);
            replaced
        };
        if let Some(replaced) = replaced {
            close_slot(replaced).await;
        }
        self.inner.changed.notify_waiters();
        Ok(())
    }

    /// Run the single reconnecting supervisor for one realm until shutdown.
    ///
    /// Failed attempts repeat full authentication after exponential backoff
    /// from 250 milliseconds through 30 seconds plus positive bounded jitter.
    /// A state change or shutdown wakes the supervisor immediately.
    ///
    /// # Errors
    ///
    /// Returns [`RealmError::SupervisorRunning`] for a duplicate supervisor or
    /// a typed counter failure if the session epoch cannot advance.
    pub async fn supervise_realm(
        &self,
        name: RealmName,
        connector: Arc<dyn RealmConnector>,
        admission: Arc<ReleaseAdmission>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), RealmError> {
        {
            let mut state = self.lock_state();
            let entry = state
                .entries
                .get_mut(&name)
                .ok_or(RealmError::Unavailable)?;
            if entry.supervisor_running {
                return Err(RealmError::SupervisorRunning);
            }
            entry.supervisor_running = true;
            drop(state);
        }
        let _lease = SupervisorLease {
            inner: Arc::clone(&self.inner),
            name: name.clone(),
        };
        let mut backoff = INITIAL_RECONNECT_BACKOFF;
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            if !self.realm_exists(&name) {
                return Ok(());
            }
            let notified = self.inner.changed.notified();
            if self.realm_is_ready(&name) {
                tokio::select! {
                    _ = shutdown.changed() => {},
                    () = notified => {},
                }
                continue;
            }
            match self
                .connect_realm(&name, connector.as_ref(), admission.as_ref())
                .await
            {
                Ok(()) => backoff = INITIAL_RECONNECT_BACKOFF,
                Err(RealmError::CounterExhausted) => return Err(RealmError::CounterExhausted),
                Err(_) => {
                    let delay = reconnect_delay(backoff)?;
                    backoff = backoff.saturating_mul(2).min(MAX_RECONNECT_BACKOFF);
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {},
                        _ = shutdown.changed() => {},
                        () = self.inner.changed.notified() => {},
                    }
                }
            }
        }
    }

    /// Resolve a peer through the accepted serial session for `name`.
    ///
    /// The caller's monotonic `budget` keeps counting while this call waits
    /// on the serial session, so the attestor-side provider observes the
    /// caller's original remaining deadline rather than a fresh ceiling.
    pub async fn resolve_peer(
        &self,
        name: &RealmName,
        peer: wire::PinnedPeer,
        budget: RequestBudget,
    ) -> Result<ResolvePeerResult, RealmError> {
        let (slot, token, config) = self.pin_ready(name)?;
        let mut session = slot.inner.lock().await;
        self.validate_token(name, token)?;
        require_negotiated(&session, "resolve-peer")?;
        let result = session.session.resolve_peer(peer, budget).await?;
        if let Some(instance) = result.instance.as_ref() {
            validate_instance(name, &config, instance)?;
        }
        self.validate_token(name, token)?;
        drop(session);
        Ok(result)
    }

    /// Query a closed inventory scope through the accepted serial session.
    ///
    /// The caller's monotonic `budget` keeps counting while this call waits
    /// on the serial session, so the attestor-side provider observes the
    /// caller's original remaining deadline rather than a fresh ceiling.
    pub async fn query_instances(
        &self,
        name: &RealmName,
        scope: QueryScope,
        budget: RequestBudget,
    ) -> Result<InventoryResult, RealmError> {
        validate_scope(name, &scope)?;
        let (slot, token, config) = self.pin_ready(name)?;
        let mut session = slot.inner.lock().await;
        self.validate_token(name, token)?;
        require_negotiated(&session, "query-instances")?;
        let result = session.session.query_instances(scope, budget).await?;
        for instance in &result.instances {
            validate_instance(name, &config, instance)?;
        }
        self.validate_token(name, token)?;
        drop(session);
        Ok(result)
    }

    /// Prepare a candidate realm set without publishing candidate authority.
    #[allow(clippy::too_many_lines)]
    pub async fn prepare_reload(
        &self,
        candidate: RealmSet,
        connector: Arc<dyn RealmConnector>,
        admission: Arc<ReleaseAdmission>,
        dry_run: bool,
    ) -> Result<PreparedReload, RealmError> {
        let prepare_id = new_prepare_id()?;
        let (base_generation, candidate_generation, changes, lifecycle_version) = {
            let mut state = self.lock_state();
            let base_generation = state.generation;
            let candidate_generation = base_generation
                .checked_add(1)
                .ok_or(RealmError::CounterExhausted)?;
            let changes = classify_changes(&state, &candidate)?;
            if dry_run
                && changes.iter().any(|change| {
                    matches!(change.kind, ChangeKind::Changed)
                        && change.old_config.as_ref().is_some_and(|old| {
                            change.new_config.as_ref().is_some_and(|new| {
                                old.measurement.socket_path == new.measurement.socket_path
                            })
                        })
                })
            {
                return Err(RealmError::QualificationRequired);
            }
            let names = changes
                .iter()
                .map(|change| change.name.clone())
                .collect::<Vec<_>>();
            for name in &names {
                if state.reservations.contains_key(name)
                    || state
                        .entries
                        .get(name)
                        .is_some_and(|entry| entry.connecting)
                {
                    for acquired in &names {
                        if state.reservations.get(acquired) == Some(&prepare_id) {
                            state.reservations.remove(acquired);
                        }
                    }
                    return Err(RealmError::PreparationConflict);
                }
                state.reservations.insert(name.clone(), prepare_id);
            }
            let result = (
                base_generation,
                candidate_generation,
                changes,
                admission.snapshot().lifecycle_version,
            );
            drop(state);
            result
        };

        let mut preparation = PreparedReload {
            inner: Arc::clone(&self.inner),
            prepare_id,
            base_generation,
            candidate_generation,
            lifecycle_version,
            candidate,
            changes,
            staged: BTreeMap::new(),
            restorations: BTreeMap::new(),
            connector,
            admission,
            activatable: !dry_run,
            committed: false,
        };
        for change in preparation.changes.clone() {
            let Some(config) = change.new_config.as_ref() else {
                continue;
            };
            let same_socket = change
                .old_config
                .as_ref()
                .is_some_and(|old| old.measurement.socket_path == config.measurement.socket_path);
            if same_socket {
                if let Some(old_config) = change.old_config.clone() {
                    preparation
                        .restorations
                        .insert(change.name.clone(), old_config);
                }
                let old_session = {
                    let mut state = self.lock_state();
                    let entry = state
                        .entries
                        .get_mut(&change.name)
                        .ok_or(RealmError::Stale)?;
                    entry.transition = TransitionState::Qualifying;
                    entry.authority = AuthorityState::Degraded;
                    entry.reason = RealmReason::Connecting;
                    bump_actor(entry)?;
                    let result = entry.session.take();
                    drop(state);
                    result
                };
                if let Some(old_session) = old_session {
                    close_slot(old_session).await;
                }
            }
            match qualify_session(
                preparation.connector.as_ref(),
                preparation.admission.as_ref(),
                config,
                candidate_generation,
                change.new_epoch,
            )
            .await
            {
                Ok(mut session) => {
                    session.expected_actor_version = {
                        let state = self.lock_state();
                        state
                            .entries
                            .get(&change.name)
                            .map_or(0, |entry| entry.actor_version)
                    };
                    preparation.staged.insert(change.name.clone(), session);
                }
                Err(error) => {
                    preparation.abort().await;
                    return Err(error);
                }
            }
        }
        Ok(preparation)
    }

    fn advance_attempt(
        &self,
        name: &RealmName,
        revision: u64,
        epoch: u64,
        authority: AuthorityState,
    ) -> Result<(), RealmError> {
        let mut state = self.lock_state();
        let entry = state.entries.get_mut(name).ok_or(RealmError::Stale)?;
        ensure_attempt(entry, revision, epoch)?;
        let result = transition_entry(entry, authority, RealmReason::Connecting);
        drop(state);
        result
    }

    fn fail_attempt(&self, name: &RealmName, revision: u64, epoch: u64, error: &RealmError) {
        let mut state = self.lock_state();
        let Some(entry) = state.entries.get_mut(name) else {
            return;
        };
        if ensure_attempt(entry, revision, epoch).is_err() {
            return;
        }
        entry.session = None;
        entry.connecting = false;
        entry.transition = TransitionState::None;
        entry.authority = if matches!(error, RealmError::SocketAbsent) {
            AuthorityState::Absent
        } else {
            AuthorityState::Degraded
        };
        entry.reason = reason_for_error(error);
        let _ = bump_actor(entry);
        drop(state);
        self.inner.changed.notify_waiters();
    }

    fn pin_ready(
        &self,
        name: &RealmName,
    ) -> Result<(Arc<SessionSlot>, QueryToken, RealmConfig), RealmError> {
        let state = self.lock_state();
        let entry = state.entries.get(name).ok_or(RealmError::Unavailable)?;
        if entry.authority != AuthorityState::Ready {
            return Err(RealmError::Unavailable);
        }
        let session = entry.session.clone().ok_or(RealmError::Unavailable)?;
        Ok((
            session,
            QueryToken {
                base_configuration_generation: state.generation,
                realm_revision: entry.revision,
                session_epoch: entry.current_epoch,
            },
            entry.config.clone(),
        ))
    }

    fn validate_token(&self, name: &RealmName, token: QueryToken) -> Result<(), RealmError> {
        let state = self.lock_state();
        let entry = state.entries.get(name).ok_or(RealmError::Stale)?;
        let current = (
            state.generation,
            entry.generation,
            entry.revision,
            entry.current_epoch,
            entry.authority,
        );
        drop(state);
        let expected = (
            token.base_configuration_generation,
            token.base_configuration_generation,
            token.realm_revision,
            token.session_epoch,
            AuthorityState::Ready,
        );
        if current == expected {
            Ok(())
        } else {
            Err(RealmError::Stale)
        }
    }

    fn realm_is_ready(&self, name: &RealmName) -> bool {
        self.lock_state()
            .entries
            .get(name)
            .is_some_and(|entry| entry.authority == AuthorityState::Ready)
    }

    fn realm_exists(&self, name: &RealmName) -> bool {
        self.lock_state().entries.contains_key(name)
    }

    fn lock_state(&self) -> MutexGuard<'_, RegistryState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Clone, Copy)]
struct QueryToken {
    base_configuration_generation: u64,
    realm_revision: u64,
    session_epoch: u64,
}

struct AttemptLease {
    inner: Arc<RegistryInner>,
    name: RealmName,
    revision: u64,
    epoch: u64,
}

impl Drop for AttemptLease {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = state.entries.get_mut(&self.name)
            && entry.connecting
            && (entry.revision, entry.next_epoch) == (self.revision, self.epoch)
        {
            entry.connecting = false;
            entry.session = None;
            entry.transition = TransitionState::None;
            entry.authority = AuthorityState::Degraded;
            entry.reason = RealmReason::ProtocolFailed;
            let _ = bump_actor(entry);
        }
        drop(state);
        self.inner.changed.notify_waiters();
    }
}

struct SupervisorLease {
    inner: Arc<RegistryInner>,
    name: RealmName,
}

impl Drop for SupervisorLease {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = state.entries.get_mut(&self.name) {
            entry.supervisor_running = false;
        }
        drop(state);
        self.inner.changed.notify_waiters();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone)]
struct RealmChange {
    name: RealmName,
    kind: ChangeKind,
    old_config: Option<RealmConfig>,
    new_config: Option<RealmConfig>,
    old_revision: u64,
    new_revision: u64,
    old_actor_version: u64,
    new_epoch: u64,
}

struct StagedSession {
    slot: Arc<SessionSlot>,
    socket_identity: SocketIdentity,
    peer_binding: VerifiedPeerBinding,
    release: ReleaseIdentity,
    digest: Sha256Digest,
    expected_actor_version: u64,
}

/// Owned preparation handle. Candidate sessions never serve before
/// [`Self::commit`] performs the atomic generation swap.
pub struct PreparedReload {
    inner: Arc<RegistryInner>,
    prepare_id: u128,
    base_generation: u64,
    candidate_generation: u64,
    lifecycle_version: u64,
    candidate: RealmSet,
    changes: Vec<RealmChange>,
    staged: BTreeMap<RealmName, StagedSession>,
    restorations: BTreeMap<RealmName, RealmConfig>,
    connector: Arc<dyn RealmConnector>,
    admission: Arc<ReleaseAdmission>,
    activatable: bool,
    committed: bool,
}

impl PreparedReload {
    /// Revalidate immutable receipts and publish all candidate realm routes or
    /// none of them.
    #[allow(clippy::too_many_lines)]
    pub async fn commit(mut self) -> Result<u64, RealmError> {
        if !self.activatable {
            return Err(RealmError::QualificationRequired);
        }
        if self.admission.snapshot().lifecycle_version != self.lifecycle_version {
            return Err(RealmError::Stale);
        }
        for change in &self.changes {
            if let (Some(config), Some(staged)) =
                (change.new_config.as_ref(), self.staged.get(&change.name))
            {
                self.connector
                    .revalidate(config, staged.socket_identity)
                    .await?;
            }
        }

        let mut draining = Vec::new();
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if state.generation != self.base_generation
                || self.admission.snapshot().lifecycle_version != self.lifecycle_version
            {
                return Err(RealmError::Stale);
            }
            for change in &self.changes {
                if state.reservations.get(&change.name) != Some(&self.prepare_id) {
                    return Err(RealmError::Stale);
                }
                if let Some(entry) = state.entries.get(&change.name) {
                    let expected_actor = self
                        .staged
                        .get(&change.name)
                        .map_or(change.old_actor_version, |staged| {
                            staged.expected_actor_version
                        });
                    if entry.revision != change.old_revision
                        || entry.actor_version != expected_actor
                    {
                        return Err(RealmError::Stale);
                    }
                }
                if let Some(staged) = self.staged.get(&change.name) {
                    let session = staged
                        .slot
                        .inner
                        .try_lock()
                        .map_err(|_| RealmError::Stale)?;
                    if session.socket_identity != staged.socket_identity
                        || session.peer_binding != staged.peer_binding
                        || session.active_artifact.release() != &staged.release
                        || session.active_artifact.artifact().digest() != staged.digest
                    {
                        return Err(RealmError::Stale);
                    }
                    drop(session);
                }
            }

            for (name, config) in self.candidate.iter() {
                if let Some(change) = self.changes.iter().find(|change| &change.name == name) {
                    let staged = self.staged.remove(name).ok_or(RealmError::Stale)?;
                    let supervisor_running = state
                        .entries
                        .get(name)
                        .is_some_and(|entry| entry.supervisor_running);
                    if let Some(old) = state.entries.remove(name)
                        && let Some(session) = old.session
                    {
                        draining.push((name.clone(), session));
                    }
                    let actor_version = staged
                        .expected_actor_version
                        .checked_add(1)
                        .ok_or(RealmError::CounterExhausted)?;
                    state.entries.insert(
                        name.clone(),
                        RealmEntry {
                            config: config.clone(),
                            revision: change.new_revision,
                            next_epoch: change.new_epoch,
                            current_epoch: change.new_epoch,
                            actor_version,
                            generation: self.candidate_generation,
                            authority: AuthorityState::Ready,
                            transition: TransitionState::None,
                            reason: RealmReason::None,
                            session: Some(staged.slot),
                            connecting: false,
                            supervisor_running,
                        },
                    );
                } else if let Some(entry) = state.entries.get_mut(name) {
                    entry.generation = self.candidate_generation;
                }
            }
            for change in &self.changes {
                if change.kind == ChangeKind::Removed
                    && let Some(mut removed) = state.entries.remove(&change.name)
                {
                    state
                        .tombstones
                        .insert(change.name.clone(), removed.revision);
                    if let Some(session) = removed.session.take() {
                        let mut status = status_for(&change.name, &removed);
                        status.state = RealmState::Draining;
                        status.reason = RealmReason::Draining;
                        status.generation = self.candidate_generation;
                        state.draining.insert(
                            change.name.clone(),
                            DrainingEntry {
                                status,
                                _session: Arc::clone(&session),
                            },
                        );
                        draining.push((change.name.clone(), session));
                    }
                }
            }
            for change in &self.changes {
                state.reservations.remove(&change.name);
            }
            state.generation = self.candidate_generation;
        }
        self.committed = true;
        self.restorations.clear();
        for (name, session) in draining {
            let inner = Arc::clone(&self.inner);
            spawn_cleanup(async move {
                close_slot(session).await;
                let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
                state.draining.remove(&name);
            });
        }
        Ok(self.candidate_generation)
    }

    async fn abort(mut self) {
        self.committed = true;
        cleanup_preparation(
            Arc::clone(&self.inner),
            self.prepare_id,
            std::mem::take(&mut self.staged),
            std::mem::take(&mut self.restorations),
            Arc::clone(&self.connector),
            Arc::clone(&self.admission),
            self.base_generation,
        )
        .await;
    }
}

impl Drop for PreparedReload {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let staged = std::mem::take(&mut self.staged);
        let restorations = std::mem::take(&mut self.restorations);
        let inner = Arc::clone(&self.inner);
        let connector = Arc::clone(&self.connector);
        let admission = Arc::clone(&self.admission);
        let prepare_id = self.prepare_id;
        let generation = self.base_generation;
        spawn_cleanup(async move {
            cleanup_preparation(
                inner,
                prepare_id,
                staged,
                restorations,
                connector,
                admission,
                generation,
            )
            .await;
        });
    }
}

fn classify_changes(
    state: &RegistryState,
    candidate: &RealmSet,
) -> Result<Vec<RealmChange>, RealmError> {
    let names = state
        .entries
        .keys()
        .chain(candidate.0.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut changes = Vec::new();
    for name in names {
        let old = state.entries.get(&name);
        let new = candidate.get(&name);
        let kind = match (old, new) {
            (None, Some(_)) => ChangeKind::Added,
            (Some(_), None) => ChangeKind::Removed,
            (Some(old), Some(new)) if old.config != *new => ChangeKind::Changed,
            (Some(_), Some(_)) | (None, None) => continue,
        };
        let old_revision = old.map_or_else(
            || state.tombstones.get(&name).copied().unwrap_or(0),
            |entry| entry.revision,
        );
        let new_revision = if kind == ChangeKind::Removed {
            old_revision
        } else {
            old_revision
                .checked_add(1)
                .ok_or(RealmError::CounterExhausted)?
        };
        let new_epoch = old
            .map_or(0, |entry| entry.next_epoch)
            .checked_add(1)
            .ok_or(RealmError::CounterExhausted)?;
        changes.push(RealmChange {
            name,
            kind,
            old_config: old.map(|entry| entry.config.clone()),
            new_config: new.cloned(),
            old_revision,
            new_revision,
            old_actor_version: old.map_or(0, |entry| entry.actor_version),
            new_epoch,
        });
    }
    Ok(changes)
}

async fn qualify_session(
    connector: &dyn RealmConnector,
    admission: &ReleaseAdmission,
    config: &RealmConfig,
    generation: u64,
    epoch: u64,
) -> Result<StagedSession, RealmError> {
    let connection = tokio::time::timeout(CONNECT_STEP_TIMEOUT, connector.connect(config))
        .await
        .map_err(|_| RealmError::Connect)??;
    let mut session = tokio::time::timeout(
        CONNECT_STEP_TIMEOUT,
        connection.authenticate(config, generation, epoch, admission),
    )
    .await
    .map_err(|_| RealmError::Authentication)??;
    tokio::time::timeout(CONNECT_STEP_TIMEOUT, session.session.handshake())
        .await
        .map_err(|_| RealmError::Protocol)??;
    validate_negotiated(config, session.session.negotiated_capabilities())?;
    let health = tokio::time::timeout(
        CONNECT_STEP_TIMEOUT,
        session
            .session
            .health(RequestBudget::starting_now(CONNECT_STEP_TIMEOUT)),
    )
    .await
    .map_err(|_| RealmError::Health)??;
    validate_health(config, &health)?;
    let socket_identity = session.socket_identity;
    let peer_binding = session.peer_binding;
    let release = session.active_artifact.release().clone();
    let digest = session.active_artifact.artifact().digest();
    Ok(StagedSession {
        slot: Arc::new(SessionSlot {
            epoch,
            inner: AsyncMutex::new(session),
        }),
        socket_identity,
        peer_binding,
        release,
        digest,
        expected_actor_version: 0,
    })
}

async fn cleanup_preparation(
    inner: Arc<RegistryInner>,
    prepare_id: u128,
    staged: BTreeMap<RealmName, StagedSession>,
    restorations: BTreeMap<RealmName, RealmConfig>,
    connector: Arc<dyn RealmConnector>,
    admission: Arc<ReleaseAdmission>,
    generation: u64,
) {
    for staged in staged.into_values() {
        close_slot(staged.slot).await;
    }
    for (name, config) in restorations {
        let epoch = {
            let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(entry) = state.entries.get_mut(&name) else {
                state.reservations.remove(&name);
                continue;
            };
            entry.transition = TransitionState::Restoring;
            let Some(epoch) = entry.next_epoch.checked_add(1) else {
                entry.authority = AuthorityState::Degraded;
                entry.reason = RealmReason::ProtocolFailed;
                state.reservations.remove(&name);
                continue;
            };
            entry.next_epoch = epoch;
            drop(state);
            epoch
        };
        let restored = qualify_session(
            connector.as_ref(),
            admission.as_ref(),
            &config,
            generation,
            epoch,
        )
        .await;
        let reservation_matches = {
            let state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.reservations.get(&name) == Some(&prepare_id)
        };
        if !reservation_matches {
            if let Ok(restored) = restored {
                close_slot(restored.slot).await;
            }
            continue;
        }
        let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = state.entries.get_mut(&name) {
            match restored {
                Ok(restored) => {
                    entry.session = Some(restored.slot);
                    entry.current_epoch = epoch;
                    entry.authority = AuthorityState::Ready;
                    entry.reason = RealmReason::None;
                    entry.transition = TransitionState::None;
                }
                Err(error) => {
                    entry.session = None;
                    entry.authority = AuthorityState::Degraded;
                    entry.reason = reason_for_error(&error);
                    entry.transition = TransitionState::None;
                }
            }
            let _ = bump_actor(entry);
        }
        state.reservations.remove(&name);
    }
    let mut state = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
    state.reservations.retain(|_, owner| *owner != prepare_id);
}

fn new_prepare_id() -> Result<u128, RealmError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| RealmError::CounterExhausted)?;
    Ok(u128::from_be_bytes(bytes))
}

fn reconnect_delay(backoff: Duration) -> Result<Duration, RealmError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| RealmError::CounterExhausted)?;
    let jitter = u64::from_be_bytes(bytes) % (MAX_RECONNECT_JITTER_MILLIS + 1);
    Ok(backoff.saturating_add(Duration::from_millis(jitter)))
}

fn validate_negotiated(config: &RealmConfig, negotiated: &[String]) -> Result<(), RealmError> {
    for capability in config.capabilities.iter() {
        if negotiated
            .binary_search_by(|candidate| candidate.as_str().cmp(capability.as_str()))
            .is_err()
        {
            return Err(RealmError::Protocol);
        }
    }
    Ok(())
}

fn require_negotiated(
    session: &AuthenticatedRealmSession,
    capability: &str,
) -> Result<(), RealmError> {
    if session
        .session
        .negotiated_capabilities()
        .binary_search_by(|candidate| candidate.as_str().cmp(capability))
        .is_ok()
    {
        Ok(())
    } else {
        Err(RealmError::Protocol)
    }
}

const fn validate_health(
    config: &RealmConfig,
    health: &wire::HealthFact,
) -> Result<(), RealmError> {
    if !health.ready
        || !health.missing_capabilities.is_empty()
        || health.runtime != config.provider.wire_runtime() as i32
        || health.runtime_mode != config.runtime_mode.wire_runtime() as i32
    {
        return Err(RealmError::Health);
    }
    Ok(())
}

fn validate_scope(name: &RealmName, scope: &QueryScope) -> Result<(), RealmError> {
    match scope {
        QueryScope::Project { realm, .. } | QueryScope::Service { realm, .. }
            if realm != name.as_str() =>
        {
            Err(RealmError::Protocol)
        }
        QueryScope::InstanceId(_)
        | QueryScope::GlobalDoctor
        | QueryScope::Project { .. }
        | QueryScope::Service { .. } => Ok(()),
    }
}

fn validate_instance(
    name: &RealmName,
    config: &RealmConfig,
    instance: &wire::InstanceFact,
) -> Result<(), RealmError> {
    let provenance = instance.provenance.as_ref().ok_or(RealmError::Protocol)?;
    if provenance.realm != name.as_str()
        || provenance.provider != config.provider.wire_runtime() as i32
        || instance.runtime != config.provider.wire_runtime() as i32
    {
        return Err(RealmError::Protocol);
    }
    Ok(())
}

const fn ensure_attempt(entry: &RealmEntry, revision: u64, epoch: u64) -> Result<(), RealmError> {
    if entry.revision == revision && entry.next_epoch == epoch {
        Ok(())
    } else {
        Err(RealmError::Stale)
    }
}

fn transition_entry(
    entry: &mut RealmEntry,
    authority: AuthorityState,
    reason: RealmReason,
) -> Result<(), RealmError> {
    entry.authority = authority;
    entry.reason = reason;
    bump_actor(entry)
}

fn bump_actor(entry: &mut RealmEntry) -> Result<(), RealmError> {
    entry.actor_version = entry
        .actor_version
        .checked_add(1)
        .ok_or(RealmError::CounterExhausted)?;
    Ok(())
}

const fn reason_for_error(error: &RealmError) -> RealmReason {
    match error {
        RealmError::SocketAbsent => RealmReason::SocketAbsent,
        RealmError::Connect
        | RealmError::PreparationConflict
        | RealmError::SupervisorRunning
        | RealmError::QualificationRequired => RealmReason::Connecting,
        RealmError::Authentication => RealmReason::AuthenticationFailed,
        RealmError::Admission => RealmReason::AdmissionFailed,
        RealmError::Protocol | RealmError::Stale | RealmError::CounterExhausted => {
            RealmReason::ProtocolFailed
        }
        RealmError::Health | RealmError::Unavailable | RealmError::BudgetExhausted => {
            RealmReason::HealthFailed
        }
    }
}

async fn close_slot(slot: Arc<SessionSlot>) {
    let mut session = slot.inner.lock().await;
    let _epoch = slot.epoch;
    session.session.close().await;
    drop(session);
}

fn spawn_cleanup(future: impl std::future::Future<Output = ()> + Send + 'static) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(future);
    }
}

fn status_for(name: &RealmName, entry: &RealmEntry) -> RealmStatus {
    let state = if entry.authority == AuthorityState::Ready {
        RealmState::Ready
    } else {
        match (entry.authority, entry.transition) {
            (_, TransitionState::Qualifying | TransitionState::Restoring) => RealmState::Staging,
            (AuthorityState::Absent, TransitionState::None) => RealmState::Absent,
            (AuthorityState::Connecting, TransitionState::None) => RealmState::Connecting,
            (AuthorityState::Authenticating, TransitionState::None) => RealmState::Authenticating,
            (AuthorityState::Handshaking, TransitionState::None) => RealmState::Handshaking,
            (AuthorityState::HealthChecking, TransitionState::None) => RealmState::HealthChecking,
            (AuthorityState::Degraded, TransitionState::None) => RealmState::Degraded,
            (AuthorityState::Ready, TransitionState::None) => RealmState::Ready,
        }
    };
    RealmStatus {
        name: name.clone(),
        provider: entry.config.provider,
        mode: entry.config.runtime_mode,
        state,
        generation: entry.generation,
        session_epoch: entry.current_epoch,
        protocol: entry.config.protocol.get(),
        reason: entry.reason,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::release_admission::{
        ArtifactRequirement, HistoricalReleaseIdentityCheck, ProductId, ReleaseArtifact, ReleaseId,
        VerifiedReleaseManifest,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn bootstrap(body: &str) -> toml::Value {
        let raw = format!(
            "schema = \"agent\"\nschemaVersion = 3\n[import]\ncatalog = \"catalog.json\"\npolicy = \"policy.json\"\nbundle = \"bundle.json\"\n{body}"
        );
        toml::from_str(&raw).expect("valid test TOML")
    }

    fn realm_body(
        realm: &str,
        provider: &str,
        mode: &str,
        uid: u32,
        role: &str,
        generation: u64,
    ) -> String {
        format!(
            r#"
[attestor.realms.{realm}]
provider = "{provider}"
runtimeMode = "{mode}"
brokerUser = "991"
brokerUnit = "basil-agent.service"
attestorUid = "{uid}"
releaseRole = "{role}"
target = "x86_64-unknown-linux-gnu"
protocol = 1
capabilities = ["health", "query-instances", "resolve-peer"]

[attestor.realms.{realm}.measurement]
authorityGeneration = {generation}
serviceUnit = "basil-attestor-{realm}-g{generation}.service"
helperEndpoint = "/run/basil/measure/control.sock"
helperPolicy = "basil-measure-policy-g{generation}"
helperPolicyGeneration = {generation}
lsmProfile = "selinux:basil_attestor_g{generation}_t"
lsmPolicy = "basil-attestor-policy-g{generation}"
lockdownProfile = "basil-attestor-lockdown-g{generation}"
runtimeDirectory = "/run/basil/attestors/{realm}/g{generation}"
runtimeDirectoryOwner = "0"
runtimeDirectoryGroup = "993"
runtimeDirectoryMode = "0770"
runtimeDirectoryAcl = "basil-attestor-bind-g{generation}"
socketPath = "/run/basil/attestors/{realm}/g{generation}/control.sock"
socketOwner = "{uid}"
socketGroup = "994"
socketMode = "0660"
socketAcl = "basil-attestor-control-g{generation}"
"#
        )
    }

    fn rootful() -> String {
        realm_body(
            "production-docker",
            "docker",
            "rootful-host",
            992,
            "docker-attestor",
            1,
        )
    }

    fn rootless(uid: u32, generation: u64) -> String {
        realm_body(
            "owner-podman",
            "podman",
            "rootless-owner",
            uid,
            "podman-attestor",
            generation,
        )
    }

    fn admission() -> Arc<ReleaseAdmission> {
        let capabilities = CapabilitySet::try_from_iter(
            KNOWN_CAPABILITIES
                .iter()
                .map(|value| CapabilityId::new(value).expect("valid capability")),
        )
        .expect("valid capabilities");
        let artifacts = ["docker-attestor", "podman-attestor"]
            .into_iter()
            .map(|role| {
                ReleaseArtifact::new(
                    ArtifactRole::new(role).expect("valid role"),
                    TargetTriple::new("x86_64-unknown-linux-gnu").expect("valid target"),
                    Sha256Digest::from_bytes([7; 32]),
                    ProtocolVersion::new(1).expect("valid protocol"),
                    capabilities.clone(),
                )
            });
        let manifest = VerifiedReleaseManifest::from_verified_parts(
            HistoricalReleaseIdentityCheck::completed(),
            ProductId::new("basil").expect("valid product"),
            ReleaseId::new("1.0.0").expect("valid release"),
            artifacts,
        )
        .expect("valid manifest");
        Arc::new(ReleaseAdmission::new(manifest))
    }

    #[derive(Clone, Copy)]
    enum FakePlan {
        Success,
        SocketAbsent,
        AuthenticationFailed,
        HealthFailed,
        BlockConnect,
    }

    #[derive(Clone)]
    struct FakeConnector {
        plans: Arc<Mutex<VecDeque<FakePlan>>>,
        connects: Arc<AtomicUsize>,
        authentications: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
        revalidate_failure: Arc<Mutex<bool>>,
        unblock: Arc<Notify>,
        observed_budgets: Arc<Mutex<Vec<Duration>>>,
    }

    impl FakeConnector {
        fn new(plans: impl IntoIterator<Item = FakePlan>) -> Self {
            Self {
                plans: Arc::new(Mutex::new(plans.into_iter().collect())),
                connects: Arc::new(AtomicUsize::new(0)),
                authentications: Arc::new(AtomicUsize::new(0)),
                closes: Arc::new(AtomicUsize::new(0)),
                revalidate_failure: Arc::new(Mutex::new(false)),
                unblock: Arc::new(Notify::new()),
                observed_budgets: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait]
    impl RealmConnector for FakeConnector {
        async fn connect(
            &self,
            _config: &RealmConfig,
        ) -> Result<Box<dyn RealmConnection>, RealmError> {
            self.connects.fetch_add(1, Ordering::SeqCst);
            let plan = self
                .plans
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
                .unwrap_or(FakePlan::Success);
            if matches!(plan, FakePlan::SocketAbsent) {
                return Err(RealmError::SocketAbsent);
            }
            if matches!(plan, FakePlan::BlockConnect) {
                self.unblock.notified().await;
            }
            Ok(Box::new(FakeConnection {
                plan,
                authentications: Arc::clone(&self.authentications),
                closes: Arc::clone(&self.closes),
                observed_budgets: Arc::clone(&self.observed_budgets),
            }))
        }

        async fn revalidate(
            &self,
            _config: &RealmConfig,
            _identity: SocketIdentity,
        ) -> Result<(), RealmError> {
            if *self
                .revalidate_failure
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
            {
                Err(RealmError::Stale)
            } else {
                Ok(())
            }
        }
    }

    struct FakeConnection {
        plan: FakePlan,
        authentications: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
        observed_budgets: Arc<Mutex<Vec<Duration>>>,
    }

    #[async_trait]
    impl RealmConnection for FakeConnection {
        async fn authenticate(
            self: Box<Self>,
            config: &RealmConfig,
            _generation: u64,
            epoch: u64,
            admission: &ReleaseAdmission,
        ) -> Result<AuthenticatedRealmSession, RealmError> {
            self.authentications.fetch_add(1, Ordering::SeqCst);
            if matches!(self.plan, FakePlan::AuthenticationFailed) {
                return Err(RealmError::Authentication);
            }
            let requirement = ArtifactRequirement::new(
                Sha256Digest::from_bytes([7; 32]),
                config.release_role.clone(),
                config.target.clone(),
                config.protocol,
                config.capabilities.clone(),
            );
            let active_artifact = admission
                .begin_preflight(&requirement)
                .map_err(|_| RealmError::Admission)?;
            Ok(AuthenticatedRealmSession::new(
                Box::new(FakeSession {
                    provider: config.provider,
                    mode: config.runtime_mode,
                    health_failure: matches!(self.plan, FakePlan::HealthFailed),
                    capabilities: KNOWN_CAPABILITIES.map(str::to_string).to_vec(),
                    closes: Arc::clone(&self.closes),
                    observed_budgets: Arc::clone(&self.observed_budgets),
                }),
                active_artifact,
                SocketIdentity {
                    device: 1,
                    inode: epoch,
                    owner: config.attestor_user.uid(),
                    mode: 0o140_600,
                },
                VerifiedPeerBinding::from_authenticator(Sha256::digest(epoch.to_be_bytes()).into()),
            ))
        }

        async fn close(self: Box<Self>) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct FakeSession {
        provider: RealmProvider,
        mode: RealmMode,
        health_failure: bool,
        capabilities: Vec<String>,
        closes: Arc<AtomicUsize>,
        observed_budgets: Arc<Mutex<Vec<Duration>>>,
    }

    impl FakeSession {
        fn record_budget(&self, budget: RequestBudget) {
            self.observed_budgets
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(budget.remaining());
        }
    }

    #[async_trait]
    impl RealmSession for FakeSession {
        async fn handshake(&mut self) -> Result<(), RealmError> {
            Ok(())
        }

        fn negotiated_capabilities(&self) -> &[String] {
            &self.capabilities
        }

        async fn health(&mut self, budget: RequestBudget) -> Result<wire::HealthFact, RealmError> {
            self.record_budget(budget);
            if self.health_failure {
                return Err(RealmError::Health);
            }
            Ok(wire::HealthFact {
                runtime: self.provider.wire_runtime() as i32,
                diagnostic_version: "fake".to_string(),
                runtime_mode: self.mode.wire_runtime() as i32,
                cgroup_mode: wire::CgroupMode::V2 as i32,
                ready: true,
                missing_capabilities: Vec::new(),
            })
        }

        async fn resolve_peer(
            &mut self,
            _peer: wire::PinnedPeer,
            budget: RequestBudget,
        ) -> Result<ResolvePeerResult, RealmError> {
            self.record_budget(budget);
            Err(RealmError::Unavailable)
        }

        async fn query_instances(
            &mut self,
            _scope: QueryScope,
            budget: RequestBudget,
        ) -> Result<InventoryResult, RealmError> {
            self.record_budget(budget);
            Err(RealmError::Unavailable)
        }

        async fn close(&mut self) {
            self.closes.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn strict_schema_accepts_closed_rootful_and_rootless_matrix() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootful())).expect("valid realms");
        assert_eq!(realms.len(), 1);
        assert!(realms.validate_broker_uid(991).is_ok());
        assert_eq!(
            realms.validate_broker_uid(992),
            Err(RealmConfigError::BrokerUidMismatch)
        );
        let mount_security = rootful().replace(
            "[\"health\", \"query-instances\", \"resolve-peer\"]",
            "[\"health\", \"mount-security.v1\", \"query-instances\", \"resolve-peer\"]",
        );
        let realms = RealmSet::from_bootstrap(&bootstrap(&mount_security))
            .expect("valid additive capability");
        let name = RealmName::new("production-docker").expect("valid realm name");
        assert!(
            realms
                .get(&name)
                .expect("configured realm")
                .capabilities
                .iter()
                .any(|capability| capability.as_str() == MOUNT_SECURITY_CAPABILITY)
        );

        let realms =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1000, 1))).expect("valid rootless realm");
        assert_eq!(realms.len(), 1);
    }

    fn parse(body: &str) -> Result<RealmSet, RealmConfigError> {
        RealmSet::from_bootstrap(&bootstrap(body))
    }

    #[test]
    fn measurement_authority_pins_typed_generations_and_identities() {
        let realms = parse(&rootful()).expect("valid realm");
        let name = RealmName::new("production-docker").expect("valid realm name");
        let config = realms.get(&name).expect("configured realm");
        let measurement = &config.measurement;
        assert_eq!(measurement.authority_generation.get(), 1);
        assert_eq!(measurement.helper_policy_generation.get(), 1);
        assert_eq!(
            measurement.service_unit,
            "basil-attestor-production-docker-g1.service"
        );
        assert_eq!(
            measurement.helper_endpoint,
            Path::new("/run/basil/measure/control.sock")
        );
        assert_eq!(
            measurement.runtime_directory,
            Path::new("/run/basil/attestors/production-docker/g1")
        );
        assert_eq!(
            measurement.socket_path,
            Path::new("/run/basil/attestors/production-docker/g1/control.sock")
        );
        assert_eq!(measurement.runtime_directory_owner.uid(), 0);
        assert_eq!(measurement.runtime_directory_group.gid(), 993);
        assert_eq!(measurement.runtime_directory_mode.bits(), 0o770);
        assert_eq!(measurement.runtime_directory_mode.spelling(), "0770");
        assert_eq!(measurement.socket_owner.uid(), 992);
        assert_eq!(measurement.socket_owner.spelling(), "992");
        assert_eq!(measurement.socket_group.gid(), 994);
        assert_eq!(measurement.socket_mode.bits(), 0o660);
        assert_eq!(measurement.lsm_profile, "selinux:basil_attestor_g1_t");
        assert_eq!(measurement.socket_acl, "basil-attestor-control-g1");
    }

    #[test]
    fn helper_policy_generation_is_independent_of_authority_generation() {
        let body = rootful()
            .replace("helperPolicyGeneration = 1", "helperPolicyGeneration = 7")
            .replace(
                "helperPolicy = \"basil-measure-policy-g1\"",
                "helperPolicy = \"basil-measure-policy-g7\"",
            );
        let realms = parse(&body).expect("independent helper policy generation");
        let name = RealmName::new("production-docker").expect("valid realm name");
        let measurement = &realms.get(&name).expect("configured realm").measurement;
        assert_eq!(measurement.authority_generation.get(), 1);
        assert_eq!(measurement.helper_policy_generation.get(), 7);
    }

    #[test]
    fn missing_measurement_rejects_with_migration_diagnostic() {
        let start = rootful();
        let legacy = start
            .split("\n[attestor.realms.production-docker.measurement]")
            .next()
            .expect("realm body prefix")
            .to_string();
        let error = parse(&legacy).expect_err("older schema-3 realm rejects");
        assert_eq!(
            error,
            RealmConfigError::MissingMeasurement {
                realm: "production-docker".to_string(),
            }
        );
        assert!(error.to_string().contains("measurement"));
    }

    #[test]
    fn measurement_block_is_indivisible() {
        // A socket unit, unknown fields, a missing identity, and partial
        // legacy top-level shapes all reject the complete candidate.
        for (case, invalid) in [
            ("socketUnit", format!("{}socketUnit = \"x.socket\"\n", rootful())),
            ("unknown field", format!("{}extra = \"y\"\n", rootful())),
            (
                "missing identity",
                rootful().replace("lsmPolicy = \"basil-attestor-policy-g1\"\n", ""),
            ),
            (
                "legacy attestorUnit",
                rootful().replace(
                    "protocol = 1",
                    "protocol = 1\nattestorUnit = \"basil-attestor-production-docker.service\"",
                ),
            ),
            (
                "legacy top-level socketPath",
                rootful().replace(
                    "protocol = 1",
                    "protocol = 1\nsocketPath = \"/run/basil/attestors/production-docker/control.sock\"",
                ),
            ),
            (
                "legacy attestorUser spelling",
                rootful().replace("attestorUid = \"992\"", "attestorUser = \"992\""),
            ),
            (
                "missing attestorUid",
                rootful().replace("attestorUid = \"992\"\n", ""),
            ),
        ] {
            assert!(
                matches!(parse(&invalid), Err(RealmConfigError::Schema(_))),
                "case `{case}` must reject as a strict schema failure"
            );
        }
    }

    #[test]
    fn duplicate_measurement_keys_reject_at_parse_time() {
        let raw = format!(
            "schema = \"agent\"\nschemaVersion = 3\n{}",
            rootful().replace(
                "authorityGeneration = 1",
                "authorityGeneration = 1\nauthorityGeneration = 1",
            )
        );
        assert!(toml::from_str::<toml::Value>(&raw).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn generation_qualifiers_are_checked_bindings() {
        for (case, from, to, expected) in [
            (
                "unqualified service unit",
                "serviceUnit = \"basil-attestor-production-docker-g1.service\"",
                "serviceUnit = \"basil-attestor-production-docker.service\"",
                RealmConfigError::GenerationQualifierMissing {
                    field: "measurement.serviceUnit",
                },
            ),
            (
                "service unit bound to a foreign generation",
                "serviceUnit = \"basil-attestor-production-docker-g1.service\"",
                "serviceUnit = \"basil-attestor-production-docker-g2.service\"",
                RealmConfigError::GenerationQualifierMismatch {
                    field: "measurement.serviceUnit",
                },
            ),
            (
                "service unit with an extra foreign qualifier",
                "serviceUnit = \"basil-attestor-production-docker-g1.service\"",
                "serviceUnit = \"basil-attestor-production-docker-g2-g1.service\"",
                RealmConfigError::GenerationQualifierMismatch {
                    field: "measurement.serviceUnit",
                },
            ),
            (
                "service unit with a zero-padded qualifier",
                "serviceUnit = \"basil-attestor-production-docker-g1.service\"",
                "serviceUnit = \"basil-attestor-production-docker-g01.service\"",
                RealmConfigError::GenerationQualifierMismatch {
                    field: "measurement.serviceUnit",
                },
            ),
            (
                "qualifier in the right unit but wrong position",
                "serviceUnit = \"basil-attestor-production-docker-g1.service\"",
                "serviceUnit = \"basil-g1-attestor-production-docker.service\"",
                RealmConfigError::GenerationQualifierMissing {
                    field: "measurement.serviceUnit",
                },
            ),
            (
                "LSM profile bound to a foreign generation",
                "lsmProfile = \"selinux:basil_attestor_g1_t\"",
                "lsmProfile = \"selinux:basil_attestor_g2_t\"",
                RealmConfigError::GenerationQualifierMismatch {
                    field: "measurement.lsmProfile",
                },
            ),
            (
                "unqualified LSM policy",
                "lsmPolicy = \"basil-attestor-policy-g1\"",
                "lsmPolicy = \"basil-attestor-policy\"",
                RealmConfigError::GenerationQualifierMissing {
                    field: "measurement.lsmPolicy",
                },
            ),
            (
                "lockdown profile bound to a foreign generation",
                "lockdownProfile = \"basil-attestor-lockdown-g1\"",
                "lockdownProfile = \"basil-attestor-lockdown-g2\"",
                RealmConfigError::GenerationQualifierMismatch {
                    field: "measurement.lockdownProfile",
                },
            ),
            (
                "helper policy bound to the authority generation",
                "helperPolicyGeneration = 1",
                "helperPolicyGeneration = 2",
                RealmConfigError::GenerationQualifierMismatch {
                    field: "measurement.helperPolicy",
                },
            ),
            (
                "runtime directory bound to a foreign generation",
                "runtimeDirectory = \"/run/basil/attestors/production-docker/g1\"",
                "runtimeDirectory = \"/run/basil/attestors/production-docker/g2\"",
                RealmConfigError::GenerationQualifierMismatch {
                    field: "measurement.runtimeDirectory",
                },
            ),
            (
                "socket basename bound to a foreign generation",
                "socketPath = \"/run/basil/attestors/production-docker/g1/control.sock\"",
                "socketPath = \"/run/basil/attestors/production-docker/g1/control-g2.sock\"",
                RealmConfigError::GenerationQualifierMismatch {
                    field: "measurement.socketPath",
                },
            ),
            (
                "unqualified runtime directory ACL",
                "runtimeDirectoryAcl = \"basil-attestor-bind-g1\"",
                "runtimeDirectoryAcl = \"basil-attestor-bind\"",
                RealmConfigError::GenerationQualifierMissing {
                    field: "measurement.runtimeDirectoryAcl",
                },
            ),
            (
                "socket ACL bound to a foreign generation",
                "socketAcl = \"basil-attestor-control-g1\"",
                "socketAcl = \"basil-attestor-control-g2\"",
                RealmConfigError::GenerationQualifierMismatch {
                    field: "measurement.socketAcl",
                },
            ),
        ] {
            let body = rootful().replace(from, to);
            assert_ne!(body, rootful(), "case `{case}` must change the fixture");
            assert_eq!(parse(&body).expect_err(case), expected, "{case}");
        }
    }

    #[test]
    fn zero_generations_reject() {
        for (from, to, field) in [
            (
                "authorityGeneration = 1",
                "authorityGeneration = 0",
                "measurement.authorityGeneration",
            ),
            (
                "helperPolicyGeneration = 1",
                "helperPolicyGeneration = 0",
                "measurement.helperPolicyGeneration",
            ),
        ] {
            assert_eq!(
                parse(&rootful().replace(from, to)),
                Err(RealmConfigError::GenerationZero { field })
            );
        }
        assert!(matches!(
            parse(&rootful().replace("authorityGeneration = 1", "authorityGeneration = -1")),
            Err(RealmConfigError::Schema(_))
        ));
    }

    #[test]
    fn authority_paths_and_scopes_reject_normalization_edges() {
        for (case, from, to, expected) in [
            (
                "trailing slash",
                "runtimeDirectory = \"/run/basil/attestors/production-docker/g1\"",
                "runtimeDirectory = \"/run/basil/attestors/production-docker/g1/\"",
                RealmConfigError::InvalidAuthorityPath {
                    field: "measurement.runtimeDirectory",
                },
            ),
            (
                "parent traversal",
                "runtimeDirectory = \"/run/basil/attestors/production-docker/g1\"",
                "runtimeDirectory = \"/run/basil/attestors/production-docker/x/../g1\"",
                RealmConfigError::InvalidAuthorityPath {
                    field: "measurement.runtimeDirectory",
                },
            ),
            (
                "relative helper endpoint",
                "helperEndpoint = \"/run/basil/measure/control.sock\"",
                "helperEndpoint = \"run/basil/measure/control.sock\"",
                RealmConfigError::InvalidAuthorityPath {
                    field: "measurement.helperEndpoint",
                },
            ),
            (
                "repeated separator",
                "helperEndpoint = \"/run/basil/measure/control.sock\"",
                "helperEndpoint = \"/run//basil/measure/control.sock\"",
                RealmConfigError::InvalidAuthorityPath {
                    field: "measurement.helperEndpoint",
                },
            ),
            (
                "runtime directory outside the realm scope",
                "runtimeDirectory = \"/run/basil/attestors/production-docker/g1\"",
                "runtimeDirectory = \"/run/basil/attestors/other-realm/g1\"",
                RealmConfigError::RuntimeDirectoryScope {
                    expected: PathBuf::from("/run/basil/attestors/production-docker/g1"),
                },
            ),
            (
                "socket not directly beneath the runtime directory",
                "socketPath = \"/run/basil/attestors/production-docker/g1/control.sock\"",
                "socketPath = \"/run/basil/attestors/production-docker/g1/nested/control.sock\"",
                RealmConfigError::SocketScope {
                    expected: PathBuf::from(
                        "/run/basil/attestors/production-docker/g1/control.sock",
                    ),
                },
            ),
        ] {
            let body = rootful().replace(from, to);
            assert_ne!(body, rootful(), "case `{case}` must change the fixture");
            assert_eq!(parse(&body).expect_err(case), expected, "{case}");
        }
    }

    #[test]
    fn socket_path_byte_ceiling_is_enforced() {
        let long_realm = format!("a{}", "b".repeat(62));
        let body = realm_body(
            &long_realm,
            "docker",
            "rootful-host",
            992,
            "docker-attestor",
            1_099_511_627_776,
        );
        assert_eq!(
            parse(&body),
            Err(RealmConfigError::InvalidAuthorityPath {
                field: "measurement.socketPath",
            })
        );
    }

    #[test]
    fn realm_name_embedding_a_foreign_qualifier_fails_closed() {
        // A realm literally named with a delimited foreign `g<digits>` token
        // makes every derived generation-qualified value ambiguous; the
        // checked binding rejects it rather than guessing.
        let body = realm_body(
            "app-g2",
            "docker",
            "rootful-host",
            992,
            "docker-attestor",
            1,
        );
        assert_eq!(
            parse(&body),
            Err(RealmConfigError::GenerationQualifierMismatch {
                field: "measurement.serviceUnit",
            })
        );
    }

    #[test]
    fn ownership_and_mode_fields_require_canonical_spellings() {
        for (case, from, to) in [
            (
                "zero-padded runtime directory owner",
                "runtimeDirectoryOwner = \"0\"",
                "runtimeDirectoryOwner = \"00\"",
            ),
            (
                "named runtime directory group",
                "runtimeDirectoryGroup = \"993\"",
                "runtimeDirectoryGroup = \"basil\"",
            ),
            (
                "three-digit mode",
                "runtimeDirectoryMode = \"0770\"",
                "runtimeDirectoryMode = \"770\"",
            ),
            (
                "non-octal socket mode",
                "socketMode = \"0660\"",
                "socketMode = \"0668\"",
            ),
            (
                "five-digit socket mode",
                "socketMode = \"0660\"",
                "socketMode = \"00660\"",
            ),
            (
                "socket owner above the UID ceiling",
                "socketOwner = \"992\"",
                "socketOwner = \"4294967296\"",
            ),
            (
                "zero-padded socket group",
                "socketGroup = \"994\"",
                "socketGroup = \"0994\"",
            ),
        ] {
            let body = rootful().replace(from, to);
            assert_ne!(body, rootful(), "case `{case}` must change the fixture");
            assert!(parse(&body).is_err(), "{case}");
        }
        let ceiling = rootful().replace("socketOwner = \"992\"", "socketOwner = \"4294967295\"");
        assert!(parse(&ceiling).is_ok(), "exact u32 ceiling is canonical");
    }

    #[test]
    fn qualifier_scanner_extracts_only_delimited_tokens() {
        assert_eq!(
            generation_qualifiers("basil-attestor-g12.service"),
            vec!["g12"]
        );
        assert_eq!(
            generation_qualifiers("selinux:basil_attestor_g1_t"),
            vec!["g1"]
        );
        assert_eq!(generation_qualifiers("g1"), vec!["g1"]);
        assert_eq!(generation_qualifiers("/run/x/g7/control.sock"), vec!["g7"]);
        assert_eq!(generation_qualifiers("a-g2-g1"), vec!["g2", "g1"]);
        assert!(generation_qualifiers("cgroup2").is_empty());
        assert!(generation_qualifiers("gen1").is_empty());
        assert!(generation_qualifiers("g1a").is_empty());
        assert!(generation_qualifiers("x1g2").is_empty());
        assert!(generation_qualifiers("g1g2").is_empty());
        assert!(generation_qualifiers("").is_empty());
    }

    proptest::proptest! {
        #[test]
        fn any_pinned_generation_accepts_and_any_foreign_qualifier_rejects(
            generation in 1_u64..=9_223_372_036_854_775_807_u64,
            foreign in 1_u64..=9_223_372_036_854_775_807_u64,
        ) {
            let body = realm_body(
                "production-docker",
                "docker",
                "rootful-host",
                992,
                "docker-attestor",
                generation,
            );
            proptest::prop_assert!(parse(&body).is_ok());
            if foreign != generation {
                let mismatched = body.replace(
                    &format!("lsmPolicy = \"basil-attestor-policy-g{generation}\""),
                    &format!("lsmPolicy = \"basil-attestor-policy-g{foreign}\""),
                );
                proptest::prop_assert_eq!(
                    parse(&mismatched),
                    Err(RealmConfigError::GenerationQualifierMismatch {
                        field: "measurement.lsmPolicy",
                    })
                );
            }
        }
    }

    #[test]
    fn schema_rejects_unknowns_matrix_uid_paths_and_capability_drift() {
        for invalid in [
            rootful().replace("protocol = 1", "protocol = 1\nunknown = true"),
            rootful().replace("rootful-host", "rootless-owner"),
            rootful().replace("brokerUser = \"991\"", "brokerUser = \"0991\""),
            rootful().replace(
                "socketPath = \"/run/basil/attestors/production-docker/g1/control.sock\"",
                "socketPath = \"/tmp/control.sock\"",
            ),
            rootful().replace(
                "[\"health\", \"query-instances\", \"resolve-peer\"]",
                "[\"health\", \"resolve-peer\"]",
            ),
            rootful().replace(
                "[\"health\", \"query-instances\", \"resolve-peer\"]",
                "[\"health\", \"query-instances\", \"resolve-peer\", \"unknown.v1\"]",
            ),
        ] {
            assert!(RealmSet::from_bootstrap(&bootstrap(&invalid)).is_err());
        }
    }

    #[tokio::test]
    async fn additive_mount_security_capability_is_admitted_and_negotiated() {
        let body = rootful().replace(
            "[\"health\", \"query-instances\", \"resolve-peer\"]",
            "[\"health\", \"mount-security.v1\", \"query-instances\", \"resolve-peer\"]",
        );
        let realms = RealmSet::from_bootstrap(&bootstrap(&body)).expect("valid realm");
        let name = RealmName::new("production-docker").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = FakeConnector::new([FakePlan::Success]);

        registry
            .connect_realm(&name, &connector, admission().as_ref())
            .await
            .expect("mount-security session connects");

        assert_eq!(registry.statuses()[0].state, RealmState::Ready);
    }

    #[test]
    fn absent_realms_are_isolated_and_partition_readiness() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootful())).expect("valid realms");
        let registry = RealmRegistry::new(&realms, 1).expect("valid generation");
        assert_eq!(
            registry.readiness(),
            RealmReadiness {
                total: 1,
                ready: 0,
                degraded: 0,
                absent: 1,
            }
        );
        assert_eq!(registry.statuses()[0].state, RealmState::Absent);
    }

    #[tokio::test]
    async fn reconnect_repeats_authentication_and_spans_guard_lifetime() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootful())).expect("valid realms");
        let name = RealmName::new("production-docker").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = FakeConnector::new([FakePlan::Success, FakePlan::Success]);
        let admission = admission();

        registry
            .connect_realm(&name, &connector, admission.as_ref())
            .await
            .expect("first connection");
        assert_eq!(admission.snapshot().current.active_preflights, 1);
        registry
            .connect_realm(&name, &connector, admission.as_ref())
            .await
            .expect("fresh reconnect");

        assert_eq!(connector.connects.load(Ordering::SeqCst), 2);
        assert_eq!(connector.authentications.load(Ordering::SeqCst), 2);
        assert_eq!(connector.closes.load(Ordering::SeqCst), 1);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
        assert_eq!(registry.statuses()[0].session_epoch, 2);
    }

    #[tokio::test]
    async fn dispatch_passes_caller_budget_through_the_serial_session() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootful())).expect("valid realms");
        let name = RealmName::new("production-docker").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = FakeConnector::new([FakePlan::Success]);
        let admission = admission();
        registry
            .connect_realm(&name, &connector, admission.as_ref())
            .await
            .expect("connection");
        let budgets = connector
            .observed_budgets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert_eq!(budgets.len(), 1, "qualification health carries a budget");
        assert!(!budgets[0].is_zero());
        assert!(budgets[0] <= CONNECT_STEP_TIMEOUT);
        let caller_budget = Duration::from_millis(250);
        let result = registry
            .resolve_peer(
                &name,
                wire::PinnedPeer {
                    pid: 123,
                    start_time_ticks: 456,
                    cgroup: "/system.slice/example.scope".to_string(),
                    namespaces: None,
                },
                RequestBudget::starting_now(caller_budget),
            )
            .await;
        assert_eq!(result, Err(RealmError::Unavailable));
        let budgets = connector
            .observed_budgets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert_eq!(budgets.len(), 2);
        assert!(!budgets[1].is_zero());
        assert!(
            budgets[1] <= caller_budget,
            "provider dispatch observes the caller's remaining budget"
        );
    }

    #[tokio::test]
    async fn realm_failure_is_isolated() {
        let body = format!("{}{}", rootful(), rootless(1000, 1));
        let realms = RealmSet::from_bootstrap(&bootstrap(&body)).expect("valid realms");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = FakeConnector::new([FakePlan::Success, FakePlan::SocketAbsent]);
        let admission = admission();
        let first = RealmName::new("owner-podman").expect("valid realm");
        let second = RealmName::new("production-docker").expect("valid realm");
        registry
            .connect_realm(&first, &connector, admission.as_ref())
            .await
            .expect("first realm ready");
        assert_eq!(
            registry
                .connect_realm(&second, &connector, admission.as_ref())
                .await,
            Err(RealmError::SocketAbsent)
        );
        assert_eq!(
            registry.readiness(),
            RealmReadiness {
                total: 2,
                ready: 1,
                degraded: 0,
                absent: 1,
            }
        );
    }

    #[tokio::test]
    async fn authentication_failure_degrades_only_the_reconnecting_realm() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootful())).expect("valid realms");
        let name = RealmName::new("production-docker").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = FakeConnector::new([FakePlan::Success, FakePlan::AuthenticationFailed]);
        let admission = admission();
        registry
            .connect_realm(&name, &connector, admission.as_ref())
            .await
            .expect("initial connection");
        assert_eq!(
            registry
                .connect_realm(&name, &connector, admission.as_ref())
                .await,
            Err(RealmError::Authentication)
        );
        assert_eq!(registry.statuses()[0].state, RealmState::Degraded);
        assert_eq!(admission.snapshot().current.active_preflights, 0);
    }

    #[tokio::test]
    async fn same_socket_failure_restores_accepted_generation() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootful())).expect("valid realms");
        let name = RealmName::new("production-docker").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([
            FakePlan::Success,
            FakePlan::HealthFailed,
            FakePlan::Success,
        ]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");

        let changed = rootful().replace("socketGroup = \"994\"", "socketGroup = \"995\"");
        let candidate = RealmSet::from_bootstrap(&bootstrap(&changed)).expect("valid candidate");
        assert_eq!(
            registry
                .prepare_reload(candidate, connector, Arc::clone(&admission), false)
                .await
                .map(|_| ()),
            Err(RealmError::Health)
        );
        assert_eq!(registry.generation(), 1);
        assert_eq!(registry.statuses()[0].state, RealmState::Ready);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
    }

    #[tokio::test]
    async fn staged_candidate_never_serves_early_and_commit_is_atomic() {
        let realms =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1000, 1))).expect("valid realms");
        let name = RealmName::new("owner-podman").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([FakePlan::Success, FakePlan::Success]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");

        let candidate =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1000, 2))).expect("valid candidate");
        let prepared = registry
            .prepare_reload(candidate, connector, Arc::clone(&admission), false)
            .await
            .expect("candidate qualifies");
        assert_eq!(registry.generation(), 1);
        assert_eq!(registry.statuses()[0].session_epoch, 1);
        assert_eq!(admission.snapshot().current.active_preflights, 2);

        assert_eq!(prepared.commit().await.expect("commit"), 2);
        tokio::task::yield_now().await;
        assert_eq!(registry.generation(), 2);
        assert_eq!(registry.statuses()[0].session_epoch, 2);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
    }

    #[tokio::test]
    async fn dropped_prepare_cleans_candidate_and_retains_authority() {
        let realms =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1000, 1))).expect("valid realms");
        let name = RealmName::new("owner-podman").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([FakePlan::Success, FakePlan::Success]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");
        let candidate =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1000, 2))).expect("valid candidate");
        let prepared = registry
            .prepare_reload(candidate, connector, Arc::clone(&admission), false)
            .await
            .expect("candidate qualifies");
        drop(prepared);
        tokio::task::yield_now().await;
        assert_eq!(registry.generation(), 1);
        assert_eq!(registry.statuses()[0].state, RealmState::Ready);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
    }

    #[tokio::test]
    async fn cancelled_same_socket_prepare_restores_before_releasing_lease() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootful())).expect("valid realms");
        let name = RealmName::new("production-docker").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([
            FakePlan::Success,
            FakePlan::BlockConnect,
            FakePlan::Success,
        ]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");
        let changed = rootful().replace("socketGroup = \"994\"", "socketGroup = \"995\"");
        let candidate = RealmSet::from_bootstrap(&bootstrap(&changed)).expect("valid candidate");
        let task_registry = registry.clone();
        let task_connector = Arc::clone(&connector);
        let task_admission = Arc::clone(&admission);
        let task = tokio::spawn(async move {
            task_registry
                .prepare_reload(candidate, task_connector, task_admission, false)
                .await
        });
        while connector.connects.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;
        for _ in 0..100 {
            if registry.statuses()[0].state == RealmState::Ready {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(registry.generation(), 1);
        assert_eq!(registry.statuses()[0].state, RealmState::Ready);
        assert_eq!(connector.connects.load(Ordering::SeqCst), 3);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
    }

    #[tokio::test]
    async fn stale_revalidation_rejects_without_publishing_candidate() {
        let realms =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1000, 1))).expect("valid realms");
        let name = RealmName::new("owner-podman").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([FakePlan::Success, FakePlan::Success]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");
        let candidate =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1000, 2))).expect("valid candidate");
        let prepared = registry
            .prepare_reload(
                candidate,
                Arc::clone(&connector) as Arc<dyn RealmConnector>,
                Arc::clone(&admission),
                false,
            )
            .await
            .expect("candidate qualifies");
        *connector
            .revalidate_failure
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        assert_eq!(prepared.commit().await, Err(RealmError::Stale));
        tokio::task::yield_now().await;
        assert_eq!(registry.generation(), 1);
        assert_eq!(registry.statuses()[0].session_epoch, 1);
        assert_eq!(admission.snapshot().current.active_preflights, 1);
    }

    #[test]
    fn poisoned_registry_lock_is_recovered() {
        let realms = RealmSet::from_bootstrap(&bootstrap(&rootful())).expect("valid realms");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let inner = Arc::clone(&registry.inner);
        let _ = std::thread::spawn(move || {
            let _guard = inner.state.lock().unwrap_or_else(PoisonError::into_inner);
            panic!("poison test lock");
        })
        .join();
        assert_eq!(registry.generation(), 1);
    }

    #[test]
    fn reconnect_backoff_is_capped_with_positive_bounded_jitter() {
        for backoff in [INITIAL_RECONNECT_BACKOFF, MAX_RECONNECT_BACKOFF] {
            for _ in 0..32 {
                let delay = reconnect_delay(backoff).expect("random jitter");
                assert!(delay >= backoff);
                assert!(delay <= backoff + Duration::from_millis(250));
            }
        }
    }

    #[tokio::test]
    async fn remove_readd_uses_tombstone_revision() {
        let realms =
            RealmSet::from_bootstrap(&bootstrap(&rootless(1000, 1))).expect("valid realms");
        let name = RealmName::new("owner-podman").expect("valid realm");
        let registry = RealmRegistry::new(&realms, 1).expect("valid registry");
        let connector = Arc::new(FakeConnector::new([FakePlan::Success, FakePlan::Success]));
        let admission = admission();
        registry
            .connect_realm(&name, connector.as_ref(), admission.as_ref())
            .await
            .expect("initial connection");

        registry
            .prepare_reload(
                RealmSet::default(),
                Arc::clone(&connector) as Arc<dyn RealmConnector>,
                Arc::clone(&admission),
                false,
            )
            .await
            .expect("removal prepares")
            .commit()
            .await
            .expect("removal commits");
        assert_eq!(registry.lock_state().tombstones.get(&name), Some(&1));

        registry
            .prepare_reload(realms, connector, Arc::clone(&admission), false)
            .await
            .expect("re-add prepares")
            .commit()
            .await
            .expect("re-add commits");
        assert_eq!(registry.lock_state().entries[&name].revision, 2);
    }
}
