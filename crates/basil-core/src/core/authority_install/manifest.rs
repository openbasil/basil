// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Staged authority manifests.
//!
//! A staged manifest is the root-owned durable statement of everything one
//! authority installation will install: the complete realm configuration
//! fingerprint, the helper allowlist and policy generation, the
//! generation-qualified attestor unit identity, LSM policy/profile, lockdown
//! profile, bind group and ACL identities, runtime directory, socket, their
//! ownership metadata, and packaged-byte fingerprints. Staging validates that
//! the candidate generation is new and that the candidate runtime directory
//! and socket are distinct from every active or rollback generation; the old
//! authority stays installed and serving throughout preparation.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::core::attestor_realm::{RealmConfig, RealmName};
use crate::release_admission::Sha256Digest;

/// Maximum number of packaged-byte fingerprints one manifest may carry.
pub const MAX_PACKAGED_FINGERPRINTS: usize = 64;

/// Identity of one authority manifest: the SHA-256 of its canonical encoding.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManifestId(Sha256Digest);

impl ManifestId {
    /// Construct a manifest identity from fixed digest bytes.
    #[must_use]
    pub const fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    /// The underlying digest.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

impl fmt::Display for ManifestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

impl fmt::Debug for ManifestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ManifestId({})", self.0)
    }
}

impl Serialize for ManifestId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        super::journal::digest_serde::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for ManifestId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(super::journal::digest_serde::deserialize(
            deserializer,
        )?))
    }
}

/// One retained (active or rollback) generation the candidate must be
/// distinct from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedGeneration {
    /// The retained authority generation.
    pub generation: NonZeroU64,
    /// Its installed manifest identity.
    pub manifest: ManifestId,
    /// Its runtime directory.
    pub runtime_directory: PathBuf,
    /// Its control socket.
    pub socket_path: PathBuf,
}

/// Ownership metadata pinned by a staged manifest, spelled exactly as the
/// realm configuration declares it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnershipMetadata {
    /// Runtime directory owner UID.
    pub runtime_directory_owner: u32,
    /// Runtime directory group GID (the protected bind group).
    pub runtime_directory_group: u32,
    /// Runtime directory mode bits.
    pub runtime_directory_mode: u32,
    /// Socket owner UID.
    pub socket_owner: u32,
    /// Socket group GID.
    pub socket_group: u32,
    /// Socket mode bits.
    pub socket_mode: u32,
}

/// A validated staged authority manifest.
///
/// Constructed only through [`StagedManifest::stage`], which enforces the
/// candidate-distinctness rules. The generation bindings inside the source
/// [`RealmConfig`] were already checked at parse time; the manifest copies
/// those exact pinned values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedManifest {
    realm: RealmName,
    authority_generation: NonZeroU64,
    service_unit: String,
    helper_policy: String,
    helper_policy_generation: NonZeroU64,
    lsm_policy: String,
    lsm_profile: String,
    lockdown_profile: String,
    runtime_directory: PathBuf,
    runtime_directory_acl: String,
    socket_path: PathBuf,
    socket_acl: String,
    ownership: OwnershipMetadata,
    packaged_fingerprints: BTreeMap<String, Sha256Digest>,
    realm_config_fingerprint: Sha256Digest,
    previous_manifest: Option<ManifestId>,
}

/// Typed staging failure. Every rejection leaves the old authority
/// untouched and serving.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ManifestError {
    /// The candidate reuses a retained authority generation. A
    /// measurement-authority change always allocates a new generation.
    #[error("candidate authority generation reuses a retained generation")]
    GenerationReuse,
    /// The candidate runtime directory collides with a retained generation.
    #[error("candidate runtime directory collides with a retained generation")]
    RuntimeDirectoryCollision,
    /// The candidate socket path collides with a retained generation.
    #[error("candidate socket path collides with a retained generation")]
    SocketPathCollision,
    /// Too many packaged fingerprints.
    #[error("packaged fingerprint set exceeds the bound")]
    FingerprintBound,
}

impl StagedManifest {
    /// Build and validate a staged manifest for `realm` from its parsed
    /// candidate configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when the candidate generation reuses a
    /// retained generation, when its runtime directory or socket collides
    /// with any retained generation, or when the packaged fingerprint set
    /// exceeds its bound.
    pub fn stage(
        realm: &RealmName,
        config: &RealmConfig,
        packaged_fingerprints: BTreeMap<String, Sha256Digest>,
        retained: &[RetainedGeneration],
        previous_manifest: Option<ManifestId>,
    ) -> Result<Self, ManifestError> {
        if packaged_fingerprints.len() > MAX_PACKAGED_FINGERPRINTS {
            return Err(ManifestError::FingerprintBound);
        }
        let measurement = &config.measurement;
        for retained_generation in retained {
            if retained_generation.generation == measurement.authority_generation {
                return Err(ManifestError::GenerationReuse);
            }
            if retained_generation.runtime_directory == measurement.runtime_directory {
                return Err(ManifestError::RuntimeDirectoryCollision);
            }
            if retained_generation.socket_path == measurement.socket_path {
                return Err(ManifestError::SocketPathCollision);
            }
        }
        Ok(Self {
            realm: realm.clone(),
            authority_generation: measurement.authority_generation,
            service_unit: measurement.service_unit.clone(),
            helper_policy: measurement.helper_policy.clone(),
            helper_policy_generation: measurement.helper_policy_generation,
            lsm_policy: measurement.lsm_policy.clone(),
            lsm_profile: measurement.lsm_profile.clone(),
            lockdown_profile: measurement.lockdown_profile.clone(),
            runtime_directory: measurement.runtime_directory.clone(),
            runtime_directory_acl: measurement.runtime_directory_acl.clone(),
            socket_path: measurement.socket_path.clone(),
            socket_acl: measurement.socket_acl.clone(),
            ownership: OwnershipMetadata {
                runtime_directory_owner: measurement.runtime_directory_owner.uid(),
                runtime_directory_group: measurement.runtime_directory_group.gid(),
                runtime_directory_mode: measurement.runtime_directory_mode.bits(),
                socket_owner: measurement.socket_owner.uid(),
                socket_group: measurement.socket_group.gid(),
                socket_mode: measurement.socket_mode.bits(),
            },
            packaged_fingerprints,
            realm_config_fingerprint: fingerprint_realm_config(realm, config),
            previous_manifest,
        })
    }

    /// The canonical manifest identity: SHA-256 over the manifest's
    /// unambiguous length-prefixed encoding.
    #[must_use]
    pub fn manifest_id(&self) -> ManifestId {
        let mut hasher = Sha256::new();
        hash_component(&mut hasher, "realm", self.realm.as_str());
        hash_component(
            &mut hasher,
            "authorityGeneration",
            &self.authority_generation.to_string(),
        );
        hash_component(&mut hasher, "serviceUnit", &self.service_unit);
        hash_component(&mut hasher, "helperPolicy", &self.helper_policy);
        hash_component(
            &mut hasher,
            "helperPolicyGeneration",
            &self.helper_policy_generation.to_string(),
        );
        hash_component(&mut hasher, "lsmPolicy", &self.lsm_policy);
        hash_component(&mut hasher, "lsmProfile", &self.lsm_profile);
        hash_component(&mut hasher, "lockdownProfile", &self.lockdown_profile);
        hash_component(
            &mut hasher,
            "runtimeDirectory",
            &self.runtime_directory.to_string_lossy(),
        );
        hash_component(
            &mut hasher,
            "runtimeDirectoryAcl",
            &self.runtime_directory_acl,
        );
        hash_component(
            &mut hasher,
            "socketPath",
            &self.socket_path.to_string_lossy(),
        );
        hash_component(&mut hasher, "socketAcl", &self.socket_acl);
        hash_component(
            &mut hasher,
            "ownership",
            &format!(
                "{}:{}:{:o}:{}:{}:{:o}",
                self.ownership.runtime_directory_owner,
                self.ownership.runtime_directory_group,
                self.ownership.runtime_directory_mode,
                self.ownership.socket_owner,
                self.ownership.socket_group,
                self.ownership.socket_mode,
            ),
        );
        for (name, digest) in &self.packaged_fingerprints {
            hash_component(&mut hasher, "packaged", name);
            hasher.update(digest.as_bytes());
        }
        hash_component(
            &mut hasher,
            "realmConfig",
            &self.realm_config_fingerprint.to_string(),
        );
        if let Some(previous) = &self.previous_manifest {
            hash_component(&mut hasher, "previousManifest", &previous.to_string());
        }
        ManifestId(Sha256Digest::from_bytes(hasher.finalize().into()))
    }

    /// The target realm.
    #[must_use]
    pub const fn realm(&self) -> &RealmName {
        &self.realm
    }

    /// The candidate authority generation.
    #[must_use]
    pub const fn authority_generation(&self) -> NonZeroU64 {
        self.authority_generation
    }

    /// The candidate helper-policy generation.
    #[must_use]
    pub const fn helper_policy_generation(&self) -> NonZeroU64 {
        self.helper_policy_generation
    }

    /// The generation-qualified candidate service unit.
    #[must_use]
    pub fn service_unit(&self) -> &str {
        &self.service_unit
    }

    /// The candidate runtime directory.
    #[must_use]
    pub fn runtime_directory(&self) -> &Path {
        &self.runtime_directory
    }

    /// The candidate socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// The identity of the manifest being superseded, if any.
    #[must_use]
    pub const fn previous_manifest(&self) -> Option<ManifestId> {
        self.previous_manifest
    }

    /// The complete realm-configuration fingerprint the manifest commits to.
    #[must_use]
    pub const fn realm_config_fingerprint(&self) -> &Sha256Digest {
        &self.realm_config_fingerprint
    }
}

/// Hash one tagged component with length prefixes so adjacent components can
/// never be confused.
fn hash_component(hasher: &mut Sha256, tag: &str, value: &str) {
    let tag_length = u64::try_from(tag.len()).unwrap_or(u64::MAX);
    let value_length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    hasher.update(tag_length.to_be_bytes());
    hasher.update(tag.as_bytes());
    hasher.update(value_length.to_be_bytes());
    hasher.update(value.as_bytes());
}

/// Fingerprint the complete candidate realm configuration (routing identity,
/// release requirements, capabilities, and the full measurement authority).
fn fingerprint_realm_config(realm: &RealmName, config: &RealmConfig) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hash_component(&mut hasher, "realm", realm.as_str());
    hash_component(&mut hasher, "provider", config.provider.as_str());
    hash_component(&mut hasher, "runtimeMode", config.runtime_mode.as_str());
    hash_component(&mut hasher, "brokerUser", config.broker_user.spelling());
    hash_component(&mut hasher, "brokerUnit", &config.broker_unit);
    hash_component(&mut hasher, "attestorUser", config.attestor_user.spelling());
    hash_component(&mut hasher, "releaseRole", config.release_role.as_str());
    hash_component(&mut hasher, "target", config.target.as_str());
    hash_component(&mut hasher, "protocol", &config.protocol.to_string());
    for capability in config.capabilities.iter() {
        hash_component(&mut hasher, "capability", capability.as_str());
    }
    let measurement = &config.measurement;
    hash_component(
        &mut hasher,
        "authorityGeneration",
        &measurement.authority_generation.to_string(),
    );
    hash_component(&mut hasher, "serviceUnit", &measurement.service_unit);
    hash_component(
        &mut hasher,
        "helperEndpoint",
        &measurement.helper_endpoint.to_string_lossy(),
    );
    hash_component(&mut hasher, "helperPolicy", &measurement.helper_policy);
    hash_component(
        &mut hasher,
        "helperPolicyGeneration",
        &measurement.helper_policy_generation.to_string(),
    );
    hash_component(&mut hasher, "lsmProfile", &measurement.lsm_profile);
    hash_component(&mut hasher, "lsmPolicy", &measurement.lsm_policy);
    hash_component(
        &mut hasher,
        "lockdownProfile",
        &measurement.lockdown_profile,
    );
    hash_component(
        &mut hasher,
        "runtimeDirectory",
        &measurement.runtime_directory.to_string_lossy(),
    );
    hash_component(
        &mut hasher,
        "runtimeDirectoryOwner",
        measurement.runtime_directory_owner.spelling(),
    );
    hash_component(
        &mut hasher,
        "runtimeDirectoryGroup",
        measurement.runtime_directory_group.spelling(),
    );
    hash_component(
        &mut hasher,
        "runtimeDirectoryMode",
        measurement.runtime_directory_mode.spelling(),
    );
    hash_component(
        &mut hasher,
        "runtimeDirectoryAcl",
        &measurement.runtime_directory_acl,
    );
    hash_component(
        &mut hasher,
        "socketPath",
        &measurement.socket_path.to_string_lossy(),
    );
    hash_component(
        &mut hasher,
        "socketOwner",
        measurement.socket_owner.spelling(),
    );
    hash_component(
        &mut hasher,
        "socketGroup",
        measurement.socket_group.spelling(),
    );
    hash_component(
        &mut hasher,
        "socketMode",
        measurement.socket_mode.spelling(),
    );
    hash_component(&mut hasher, "socketAcl", &measurement.socket_acl);
    Sha256Digest::from_bytes(hasher.finalize().into())
}
