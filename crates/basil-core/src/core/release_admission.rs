// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Bounded, wire-format-independent admission for Basil release artifacts.
//!
//! This module deliberately starts after signature verification. A future
//! verifier may construct [`VerifiedReleaseManifest`] through the crate-private
//! boundary; unverified callers cannot. No serialized manifest, signer policy,
//! package path, filename, or semantic-version inference is defined here.
//!
//! Admission is exact by full-file SHA-256 digest plus artifact role. Target and
//! protocol must equal the admitted entry, and every requested capability must
//! be in the entry's advertised set. The process-owned model is intended to back
//! one machine admission instance and retains one current and at most one
//! previous release. Active preflight handles prevent removal of the release
//! they use and release their reference automatically on drop. The module does
//! not itself enforce an operating-system-wide singleton.
//!
//! Live-slot conflict checks cover only current and previous. Before constructing
//! a [`VerifiedReleaseManifest`], the reviewed verifier and persistent
//! integration must also reject any historical product/release identity rebound
//! to different contents. Historical persistence is intentionally outside this
//! bounded in-memory model; it keeps no unbounded release history.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use thiserror::Error;

/// Maximum UTF-8 bytes in a product identifier.
pub const MAX_PRODUCT_ID_BYTES: usize = 64;
/// Maximum UTF-8 bytes in a release identifier.
pub const MAX_RELEASE_ID_BYTES: usize = 128;
/// Maximum UTF-8 bytes in an artifact role.
pub const MAX_ARTIFACT_ROLE_BYTES: usize = 64;
/// Maximum UTF-8 bytes in an exact target triple.
pub const MAX_TARGET_TRIPLE_BYTES: usize = 128;
/// Maximum UTF-8 bytes in a stable capability identifier.
pub const MAX_CAPABILITY_ID_BYTES: usize = 64;
/// Maximum capabilities advertised or required by one artifact.
pub const MAX_CAPABILITIES_PER_ARTIFACT: usize = 32;
/// Maximum artifacts in one verified release manifest.
pub const MAX_ARTIFACTS_PER_MANIFEST: usize = 256;
/// Maximum concurrent artifact preflights tracked by this model.
pub const MAX_ACTIVE_PREFLIGHTS: usize = 4_096;

/// The identity field whose value failed validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityKind {
    /// Product identifier.
    Product,
    /// Release identifier.
    Release,
    /// Artifact role.
    Role,
    /// Exact target triple.
    Target,
    /// Stable capability identifier.
    Capability,
}

impl fmt::Display for IdentityKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Product => "product",
            Self::Release => "release",
            Self::Role => "role",
            Self::Target => "target",
            Self::Capability => "capability",
        })
    }
}

/// A malformed or out-of-bounds release identity value.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IdentityError {
    /// A required token was empty.
    #[error("{kind} identifier is empty")]
    Empty {
        /// Rejected field kind.
        kind: IdentityKind,
    },
    /// A token exceeded its compiled byte ceiling.
    #[error("{kind} identifier has {actual} bytes; maximum is {maximum}")]
    TooLong {
        /// Rejected field kind.
        kind: IdentityKind,
        /// Observed byte count.
        actual: usize,
        /// Compiled maximum.
        maximum: usize,
    },
    /// A token used a non-canonical character or separator shape.
    #[error("{kind} identifier has an invalid canonical shape")]
    InvalidShape {
        /// Rejected field kind.
        kind: IdentityKind,
    },
    /// A digest was not exactly one SHA-256 output.
    #[error("SHA-256 digest has {actual} bytes; required length is 32")]
    DigestLength {
        /// Observed byte count.
        actual: usize,
    },
    /// Zero is reserved and cannot identify a protocol.
    #[error("protocol version must be a nonzero exact integer")]
    ZeroProtocol,
}

fn validate_identifier(raw: &str, kind: IdentityKind, maximum: usize) -> Result<(), IdentityError> {
    if raw.is_empty() {
        return Err(IdentityError::Empty { kind });
    }
    if raw.len() > maximum {
        return Err(IdentityError::TooLong {
            kind,
            actual: raw.len(),
            maximum,
        });
    }
    let mut previous_was_separator = false;
    for (index, byte) in raw.bytes().enumerate() {
        let alphanumeric = byte.is_ascii_lowercase() || byte.is_ascii_digit();
        let separator = matches!(byte, b'.' | b'_' | b'-');
        if !alphanumeric && !separator {
            return Err(IdentityError::InvalidShape { kind });
        }
        if separator && (index == 0 || previous_was_separator) {
            return Err(IdentityError::InvalidShape { kind });
        }
        previous_was_separator = separator;
    }
    if previous_was_separator {
        return Err(IdentityError::InvalidShape { kind });
    }
    Ok(())
}

fn validate_release_identifier(raw: &str) -> Result<(), IdentityError> {
    const KIND: IdentityKind = IdentityKind::Release;
    if raw.is_empty() {
        return Err(IdentityError::Empty { kind: KIND });
    }
    if raw.len() > MAX_RELEASE_ID_BYTES {
        return Err(IdentityError::TooLong {
            kind: KIND,
            actual: raw.len(),
            maximum: MAX_RELEASE_ID_BYTES,
        });
    }
    let bytes = raw.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphanumeric) {
        return Err(IdentityError::InvalidShape { kind: KIND });
    }
    let mut previous = None;
    let mut plus_seen = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'+') {
            return Err(IdentityError::InvalidShape { kind: KIND });
        }
        if byte == b'.'
            && (index == 0
                || index.checked_add(1) == Some(bytes.len())
                || matches!(previous, Some(b'.' | b'+')))
        {
            return Err(IdentityError::InvalidShape { kind: KIND });
        }
        if byte == b'+' {
            if plus_seen
                || index == 0
                || index.checked_add(1) == Some(bytes.len())
                || previous == Some(b'.')
            {
                return Err(IdentityError::InvalidShape { kind: KIND });
            }
            plus_seen = true;
        }
        previous = Some(byte);
    }
    Ok(())
}

macro_rules! identifier_type {
    ($name:ident, $kind:expr, $maximum:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Validate and copy an exact identifier.
            ///
            /// # Errors
            ///
            /// Returns [`IdentityError`] for an empty, overlong, or
            /// non-canonical value.
            pub fn new(raw: &str) -> Result<Self, IdentityError> {
                validate_identifier(raw, $kind, $maximum)?;
                Ok(Self(raw.to_owned()))
            }

            /// Borrow the exact validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdentityError;

            fn try_from(raw: &str) -> Result<Self, Self::Error> {
                Self::new(raw)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

identifier_type!(
    ProductId,
    IdentityKind::Product,
    MAX_PRODUCT_ID_BYTES,
    "A bounded, canonical product identifier."
);
identifier_type!(
    ArtifactRole,
    IdentityKind::Role,
    MAX_ARTIFACT_ROLE_BYTES,
    "A bounded artifact role used in the exact admission key."
);
identifier_type!(
    TargetTriple,
    IdentityKind::Target,
    MAX_TARGET_TRIPLE_BYTES,
    "A bounded exact target triple."
);
identifier_type!(
    CapabilityId,
    IdentityKind::Capability,
    MAX_CAPABILITY_ID_BYTES,
    "A bounded stable artifact capability identifier."
);

/// A bounded, opaque ASCII release identifier with no inferred ordering.
///
/// The grammar accepts ASCII alphanumerics, dots, hyphens, and one non-final
/// plus separator. It is compatible with SemVer/Cargo release forms while
/// deliberately remaining opaque: repeated and trailing internal hyphens are
/// retained exactly, and no ordering is derived from the token.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReleaseId(String);

impl ReleaseId {
    /// Validate and copy an opaque release identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError`] for an empty, overlong, non-ASCII, or malformed
    /// value.
    pub fn new(raw: &str) -> Result<Self, IdentityError> {
        validate_release_identifier(raw)?;
        Ok(Self(raw.to_owned()))
    }

    /// Borrow the exact validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ReleaseId {
    type Error = IdentityError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        Self::new(raw)
    }
}

impl fmt::Display for ReleaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A full-file SHA-256 digest.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Construct a digest from one complete SHA-256 output.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Validate and copy a SHA-256 output.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::DigestLength`] unless `bytes` is exactly 32
    /// bytes. This method does not define a signed-manifest text encoding.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, IdentityError> {
        let array = <[u8; 32]>::try_from(bytes).map_err(|_| IdentityError::DigestLength {
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// Borrow the fixed digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("sha256:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// A nonzero exact artifact protocol version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion(NonZeroU32);

impl ProtocolVersion {
    /// Validate an exact protocol integer.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::ZeroProtocol`] for zero.
    pub fn new(version: u32) -> Result<Self, IdentityError> {
        NonZeroU32::new(version)
            .map(Self)
            .ok_or(IdentityError::ZeroProtocol)
    }

    /// Return the exact protocol integer.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

/// A nonempty, duplicate-free, bounded capability set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilitySet(BTreeSet<CapabilityId>);

impl CapabilitySet {
    /// Validate capability cardinality and uniqueness.
    ///
    /// # Errors
    ///
    /// Returns [`CollectionError`] for an empty, oversized, or duplicate set.
    pub fn try_from_iter<I>(capabilities: I) -> Result<Self, CollectionError>
    where
        I: IntoIterator<Item = CapabilityId>,
    {
        let mut set = BTreeSet::new();
        for capability in capabilities {
            if set.len() == MAX_CAPABILITIES_PER_ARTIFACT {
                return Err(CollectionError::TooManyCapabilities {
                    maximum: MAX_CAPABILITIES_PER_ARTIFACT,
                });
            }
            if !set.insert(capability.clone()) {
                return Err(CollectionError::DuplicateCapability { capability });
            }
        }
        if set.is_empty() {
            return Err(CollectionError::EmptyCapabilities);
        }
        Ok(Self(set))
    }

    /// Iterate in deterministic identifier order.
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &CapabilityId> {
        self.0.iter()
    }

    fn missing_from(&self, provided: &Self) -> Vec<CapabilityId> {
        self.0.difference(&provided.0).cloned().collect()
    }
}

/// A malformed or out-of-bounds release collection.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CollectionError {
    /// An artifact declared no capabilities.
    #[error("artifact capability set is empty")]
    EmptyCapabilities,
    /// An artifact declared too many capabilities.
    #[error("artifact capability set exceeds maximum {maximum}")]
    TooManyCapabilities {
        /// Compiled maximum.
        maximum: usize,
    },
    /// A capability appeared more than once.
    #[error("duplicate artifact capability `{capability}`")]
    DuplicateCapability {
        /// Duplicated validated capability.
        capability: CapabilityId,
    },
    /// A verified manifest declared no artifacts.
    #[error("verified release manifest contains no artifacts")]
    EmptyArtifacts,
    /// A verified manifest declared too many artifacts.
    #[error("verified release manifest exceeds maximum {maximum} artifacts")]
    TooManyArtifacts {
        /// Compiled maximum.
        maximum: usize,
    },
    /// Two artifacts occupied the same exact digest-and-role key.
    #[error("duplicate release artifact for digest `{digest}` and role `{role}`")]
    DuplicateArtifact {
        /// Duplicated full-file digest.
        digest: Sha256Digest,
        /// Duplicated role.
        role: ArtifactRole,
    },
}

/// One validated artifact record from a verified release manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseArtifact {
    role: ArtifactRole,
    target: TargetTriple,
    digest: Sha256Digest,
    protocol: ProtocolVersion,
    capabilities: CapabilitySet,
}

impl ReleaseArtifact {
    /// Construct one artifact from already-validated bounded values.
    #[must_use]
    pub const fn new(
        role: ArtifactRole,
        target: TargetTriple,
        digest: Sha256Digest,
        protocol: ProtocolVersion,
        capabilities: CapabilitySet,
    ) -> Self {
        Self {
            role,
            target,
            digest,
            protocol,
            capabilities,
        }
    }

    /// Artifact role.
    #[must_use]
    pub const fn role(&self) -> &ArtifactRole {
        &self.role
    }

    /// Exact target triple.
    #[must_use]
    pub const fn target(&self) -> &TargetTriple {
        &self.target
    }

    /// Full-file digest.
    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    /// Exact artifact protocol.
    #[must_use]
    pub const fn protocol(&self) -> ProtocolVersion {
        self.protocol
    }

    /// Advertised capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ArtifactKey {
    digest: Sha256Digest,
    role: ArtifactRole,
}

/// Exact requirements for admitting a measured artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRequirement {
    key: ArtifactKey,
    target: TargetTriple,
    protocol: ProtocolVersion,
    capabilities: CapabilitySet,
}

impl ArtifactRequirement {
    /// Construct an exact artifact requirement.
    #[must_use]
    pub const fn new(
        digest: Sha256Digest,
        role: ArtifactRole,
        target: TargetTriple,
        protocol: ProtocolVersion,
        capabilities: CapabilitySet,
    ) -> Self {
        Self {
            key: ArtifactKey { digest, role },
            target,
            protocol,
            capabilities,
        }
    }
}

/// A manifest whose source bytes and verification evidence were accepted by a
/// verifier.
///
/// Fields are private, this type implements no deserializer, and its only
/// constructor is crate-private. Public callers therefore cannot promote raw or
/// merely well-formed data into the verified state. Its constructor also
/// consumes [`HistoricalReleaseIdentityCheck`], making the reviewed verifier's
/// persistent historical-identity check explicit at the integration boundary.
/// This in-memory type checks current/previous conflicts but stores no unbounded
/// historical index.
///
/// Public code cannot perform authoritative lookup on a verified manifest
/// directly:
///
/// ```compile_fail
/// use basil_core::release_admission::{ArtifactRequirement, VerifiedReleaseManifest};
///
/// fn bypass_lifecycle(
///     manifest: &VerifiedReleaseManifest,
///     requirement: &ArtifactRequirement,
/// ) {
///     let _ = manifest.lookup(requirement);
/// }
/// ```
///
/// Public code also cannot clone the verified state:
///
/// ```compile_fail
/// use basil_core::release_admission::VerifiedReleaseManifest;
///
/// fn clone_verified(manifest: &VerifiedReleaseManifest) -> VerifiedReleaseManifest {
///     Clone::clone(manifest)
/// }
/// ```
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedReleaseManifest {
    product: ProductId,
    release: ReleaseId,
    artifacts: BTreeMap<ArtifactKey, ReleaseArtifact>,
}

/// Proof that the reviewed persistent integration rejected historical identity
/// rebinding before manifest construction.
///
/// This marker adds no history to the bounded model. The future verifier and
/// persistence integration owns the durable product/release uniqueness check
/// and creates this value only after it succeeds.
#[allow(dead_code)]
pub(crate) struct HistoricalReleaseIdentityCheck(());

impl HistoricalReleaseIdentityCheck {
    /// Mark completion of the external persistent historical-identity check.
    #[allow(dead_code)]
    pub(crate) const fn completed() -> Self {
        Self(())
    }
}

impl VerifiedReleaseManifest {
    /// Assemble verifier-approved parts into the exact duplicate-safe index.
    ///
    /// Kept unused until the signed verifier slice lands. Tests exercise the
    /// boundary directly without exposing it outside `basil-core`.
    #[allow(dead_code)]
    pub(crate) fn from_verified_parts<I>(
        _historical_identity: HistoricalReleaseIdentityCheck,
        product: ProductId,
        release: ReleaseId,
        artifacts: I,
    ) -> Result<Self, CollectionError>
    where
        I: IntoIterator<Item = ReleaseArtifact>,
    {
        let mut index = BTreeMap::new();
        for artifact in artifacts {
            if index.len() == MAX_ARTIFACTS_PER_MANIFEST {
                return Err(CollectionError::TooManyArtifacts {
                    maximum: MAX_ARTIFACTS_PER_MANIFEST,
                });
            }
            let key = ArtifactKey {
                digest: artifact.digest,
                role: artifact.role.clone(),
            };
            match index.entry(key) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(artifact);
                }
                std::collections::btree_map::Entry::Occupied(slot) => {
                    return Err(CollectionError::DuplicateArtifact {
                        digest: slot.key().digest,
                        role: slot.key().role.clone(),
                    });
                }
            }
        }
        if index.is_empty() {
            return Err(CollectionError::EmptyArtifacts);
        }
        Ok(Self {
            product,
            release,
            artifacts: index,
        })
    }

    /// Verified product identity.
    #[must_use]
    pub const fn product(&self) -> &ProductId {
        &self.product
    }

    /// Verified release identity.
    #[must_use]
    pub const fn release(&self) -> &ReleaseId {
        &self.release
    }

    /// Number of uniquely indexed artifacts.
    #[must_use]
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    /// Perform exact admission within this verified manifest.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for absence or any target, protocol, or
    /// capability mismatch.
    fn lookup(
        &self,
        requirement: &ArtifactRequirement,
    ) -> Result<&ReleaseArtifact, AdmissionError> {
        let artifact = self.artifacts.get(&requirement.key).ok_or_else(|| {
            AdmissionError::ArtifactNotFound {
                digest: requirement.key.digest,
                role: requirement.key.role.clone(),
            }
        })?;
        if artifact.target != requirement.target {
            return Err(AdmissionError::TargetMismatch {
                required: requirement.target.clone(),
                admitted: artifact.target.clone(),
            });
        }
        if artifact.protocol != requirement.protocol {
            return Err(AdmissionError::ProtocolMismatch {
                required: requirement.protocol,
                admitted: artifact.protocol,
            });
        }
        let missing = requirement
            .capabilities
            .missing_from(&artifact.capabilities);
        if !missing.is_empty() {
            return Err(AdmissionError::MissingCapabilities { missing });
        }
        Ok(artifact)
    }

    fn identity(&self) -> ReleaseIdentity {
        ReleaseIdentity {
            product: self.product.clone(),
            release: self.release.clone(),
        }
    }
}

/// A typed, fail-closed artifact-admission denial.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AdmissionError {
    /// No exact digest-and-role key exists.
    #[error("no admitted artifact for digest `{digest}` and role `{role}`")]
    ArtifactNotFound {
        /// Requested digest.
        digest: Sha256Digest,
        /// Requested role.
        role: ArtifactRole,
    },
    /// The key exists under another target.
    #[error("artifact target mismatch: required `{required}`, admitted `{admitted}`")]
    TargetMismatch {
        /// Required target.
        required: TargetTriple,
        /// Admitted target.
        admitted: TargetTriple,
    },
    /// The key exists under another protocol.
    #[error("artifact protocol mismatch: required {required}, admitted {admitted}")]
    ProtocolMismatch {
        /// Required exact protocol.
        required: ProtocolVersion,
        /// Admitted exact protocol.
        admitted: ProtocolVersion,
    },
    /// The entry does not advertise every required capability.
    #[error("artifact is missing required capabilities")]
    MissingCapabilities {
        /// Missing capabilities in deterministic identifier order.
        missing: Vec<CapabilityId>,
    },
    /// The bounded active-preflight registry is full.
    #[error("active artifact preflight limit {maximum} reached")]
    ActivePreflightLimit {
        /// Compiled maximum.
        maximum: usize,
    },
}

/// Exact product and release identity for one admitted manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseIdentity {
    product: ProductId,
    release: ReleaseId,
}

impl ReleaseIdentity {
    /// Product identity.
    #[must_use]
    pub const fn product(&self) -> &ProductId {
        &self.product
    }

    /// Release identity.
    #[must_use]
    pub const fn release(&self) -> &ReleaseId {
        &self.release
    }
}

#[derive(Debug)]
struct ReleaseSlot {
    manifest: Arc<VerifiedReleaseManifest>,
    active_preflights: usize,
}

impl ReleaseSlot {
    fn new(manifest: VerifiedReleaseManifest) -> Self {
        Self {
            manifest: Arc::new(manifest),
            active_preflights: 0,
        }
    }

    fn status(&self) -> ReleaseStatus {
        ReleaseStatus {
            identity: self.manifest.identity(),
            active_preflights: self.active_preflights,
        }
    }
}

#[derive(Debug)]
struct AdmissionState {
    current: ReleaseSlot,
    previous: Option<ReleaseSlot>,
    active_preflights: usize,
}

/// Process-owned bounded model for machine-wide current/previous admission.
///
/// Crate integration must construct exactly one instance for the process and
/// make that instance authoritative for machine admission. This pure module
/// does not claim to enforce an operating-system-wide singleton. It exposes no
/// public constructor or clone path that could create a competing state.
///
/// The internal lock is never held across caller work, I/O, or an await point.
/// Poisoning is recovered because a panic must not permanently strand release
/// administration.
///
/// Public code cannot construct a competing admission state:
///
/// ```compile_fail
/// use basil_core::release_admission::{ReleaseAdmission, VerifiedReleaseManifest};
///
/// fn create_competing_state(manifest: VerifiedReleaseManifest) -> ReleaseAdmission {
///     ReleaseAdmission::new(manifest)
/// }
/// ```
#[derive(Debug)]
pub struct ReleaseAdmission {
    state: Arc<Mutex<AdmissionState>>,
}

impl ReleaseAdmission {
    /// Begin with one verifier-produced current release and no previous release.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn new(initial: VerifiedReleaseManifest) -> Self {
        Self {
            state: Arc::new(Mutex::new(AdmissionState {
                current: ReleaseSlot::new(initial),
                previous: None,
                active_preflights: 0,
            })),
        }
    }

    /// Snapshot bounded release identities and active-reference counts.
    #[must_use]
    pub fn snapshot(&self) -> ReleaseSnapshot {
        let state = self.lock_state();
        ReleaseSnapshot {
            current: state.current.status(),
            previous: state.previous.as_ref().map(ReleaseSlot::status),
        }
    }

    /// Admit an artifact and hold its release active for one preflight.
    ///
    /// The current release is authoritative when it contains the exact
    /// digest-and-role key. A mismatch in that entry is returned immediately;
    /// it never falls through to previous. Previous is consulted only when the
    /// current key is absent.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] for an exact mismatch or when the bounded
    /// preflight registry is full.
    pub fn begin_preflight(
        &self,
        requirement: &ArtifactRequirement,
    ) -> Result<ActiveArtifact, AdmissionError> {
        let mut state = self.lock_state();
        if state.active_preflights == MAX_ACTIVE_PREFLIGHTS {
            return Err(AdmissionError::ActivePreflightLimit {
                maximum: MAX_ACTIVE_PREFLIGHTS,
            });
        }

        let current_result = state.current.manifest.lookup(requirement);
        let (identity, artifact, use_previous) =
            match current_result {
                Ok(artifact) => (state.current.manifest.identity(), artifact.clone(), false),
                Err(AdmissionError::ArtifactNotFound { .. }) => {
                    let previous = state.previous.as_ref().ok_or_else(|| {
                        AdmissionError::ArtifactNotFound {
                            digest: requirement.key.digest,
                            role: requirement.key.role.clone(),
                        }
                    })?;
                    let artifact = previous.manifest.lookup(requirement)?.clone();
                    (previous.manifest.identity(), artifact, true)
                }
                Err(error) => return Err(error),
            };

        if use_previous {
            if let Some(previous) = state.previous.as_mut() {
                previous.active_preflights = previous.active_preflights.saturating_add(1);
            }
        } else {
            state.current.active_preflights = state.current.active_preflights.saturating_add(1);
        }
        state.active_preflights = state.active_preflights.saturating_add(1);
        drop(state);

        Ok(ActiveArtifact {
            owner: Arc::downgrade(&self.state),
            identity,
            artifact,
            active: true,
        })
    }

    /// Promote a verifier-produced release as the new current release.
    ///
    /// This operation does not infer ordering from the opaque release id.
    /// Callers use [`Self::downgrade`] when the intended direction is backward.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] without mutation for product/identity conflicts
    /// or when promotion would evict an actively referenced previous release.
    pub fn promote(
        &self,
        candidate: VerifiedReleaseManifest,
    ) -> Result<TransitionOutcome, LifecycleError> {
        self.replace_current(candidate, TransitionKind::Promotion)
    }

    /// Explicitly install a verifier-produced older release as current.
    ///
    /// No package-semver comparison is performed; the distinct method makes the
    /// operator/integration intent explicit and auditable.
    ///
    /// # Errors
    ///
    /// The same fail-closed errors as [`Self::promote`].
    pub fn downgrade(
        &self,
        candidate: VerifiedReleaseManifest,
    ) -> Result<TransitionOutcome, LifecycleError> {
        self.replace_current(candidate, TransitionKind::Downgrade)
    }

    /// Swap the admitted current and previous releases explicitly.
    ///
    /// Active references move with their release and remain protected.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::NoPreviousRelease`] without mutation when no
    /// rollback target exists.
    pub fn rollback(&self) -> Result<TransitionOutcome, LifecycleError> {
        let mut state = self.lock_state();
        let Some(mut previous) = state.previous.take() else {
            return Err(LifecycleError::NoPreviousRelease);
        };
        std::mem::swap(&mut state.current, &mut previous);
        state.previous = Some(previous);
        let outcome = transition_outcome(&state, TransitionKind::Rollback);
        drop(state);
        Ok(outcome)
    }

    /// Remove the previous release when no preflight is using it.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError`] without mutation when there is no previous
    /// release or it has active preflight references.
    pub fn remove_previous(&self) -> Result<ReleaseIdentity, LifecycleError> {
        let mut state = self.lock_state();
        let previous = state
            .previous
            .as_ref()
            .ok_or(LifecycleError::NoPreviousRelease)?;
        if previous.active_preflights != 0 {
            return Err(LifecycleError::PreviousReleaseActive {
                release: previous.manifest.identity(),
                active_preflights: previous.active_preflights,
            });
        }
        let removed = state
            .previous
            .take()
            .map(|slot| slot.manifest.identity())
            .ok_or(LifecycleError::NoPreviousRelease)?;
        drop(state);
        Ok(removed)
    }

    fn replace_current(
        &self,
        candidate: VerifiedReleaseManifest,
        kind: TransitionKind,
    ) -> Result<TransitionOutcome, LifecycleError> {
        let mut state = self.lock_state();
        validate_candidate_identity(&state, &candidate)?;
        if let Some(previous) = &state.previous
            && previous.active_preflights != 0
        {
            return Err(LifecycleError::PreviousReleaseActive {
                release: previous.manifest.identity(),
                active_preflights: previous.active_preflights,
            });
        }
        let new_current = ReleaseSlot::new(candidate);
        let old_current = std::mem::replace(&mut state.current, new_current);
        state.previous = Some(old_current);
        let outcome = transition_outcome(&state, kind);
        drop(state);
        Ok(outcome)
    }

    fn lock_state(&self) -> MutexGuard<'_, AdmissionState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn validate_candidate_identity(
    state: &AdmissionState,
    candidate: &VerifiedReleaseManifest,
) -> Result<(), LifecycleError> {
    if candidate.product != state.current.manifest.product {
        return Err(LifecycleError::ProductMismatch {
            current: state.current.manifest.product.clone(),
            candidate: candidate.product.clone(),
        });
    }
    if candidate.release == state.current.manifest.release {
        return Err(if candidate == state.current.manifest.as_ref() {
            LifecycleError::AlreadyCurrent {
                release: candidate.identity(),
            }
        } else {
            LifecycleError::ReleaseIdentityConflict {
                release: candidate.identity(),
            }
        });
    }
    if let Some(previous) = &state.previous
        && candidate.release == previous.manifest.release
    {
        return Err(if candidate == previous.manifest.as_ref() {
            LifecycleError::RollbackRequired {
                release: candidate.identity(),
            }
        } else {
            LifecycleError::ReleaseIdentityConflict {
                release: candidate.identity(),
            }
        });
    }
    Ok(())
}

fn transition_outcome(state: &AdmissionState, kind: TransitionKind) -> TransitionOutcome {
    TransitionOutcome {
        kind,
        current: state.current.manifest.identity(),
        previous: state.previous.as_ref().map(|slot| slot.manifest.identity()),
    }
}

/// Kind of explicit machine-wide release transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionKind {
    /// Install a new release in the forward direction.
    Promotion,
    /// Install a release with explicit backward intent.
    Downgrade,
    /// Swap the existing current and previous releases.
    Rollback,
}

/// Result of a successful release transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionOutcome {
    /// Explicit transition kind.
    pub kind: TransitionKind,
    /// New current release.
    pub current: ReleaseIdentity,
    /// New previous release.
    pub previous: Option<ReleaseIdentity>,
}

/// One release's observable bounded lifecycle status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStatus {
    /// Exact release identity.
    pub identity: ReleaseIdentity,
    /// Number of active artifact preflights using this release.
    pub active_preflights: usize,
}

/// Atomic snapshot of the machine-wide release slots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseSnapshot {
    /// Current admitted release.
    pub current: ReleaseStatus,
    /// Previous admitted release, when retained.
    pub previous: Option<ReleaseStatus>,
}

/// A typed, fail-closed machine-wide release lifecycle error.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LifecycleError {
    /// A candidate belongs to another product.
    #[error("candidate product `{candidate}` does not match current product `{current}`")]
    ProductMismatch {
        /// Current product.
        current: ProductId,
        /// Candidate product.
        candidate: ProductId,
    },
    /// An identical candidate is already current.
    #[error("release is already current")]
    AlreadyCurrent {
        /// Conflicting release identity.
        release: ReleaseIdentity,
    },
    /// The same product/release identity names different contents.
    #[error("release identity is already bound to different manifest contents")]
    ReleaseIdentityConflict {
        /// Conflicting release identity.
        release: ReleaseIdentity,
    },
    /// The candidate is exactly the retained previous release.
    #[error("retained previous release requires explicit rollback")]
    RollbackRequired {
        /// Previous release identity.
        release: ReleaseIdentity,
    },
    /// No previous release exists for rollback or removal.
    #[error("no previous release is admitted")]
    NoPreviousRelease,
    /// Removing or replacing previous would invalidate an active preflight.
    #[error("previous release has {active_preflights} active preflight references")]
    PreviousReleaseActive {
        /// Active previous release.
        release: ReleaseIdentity,
        /// Bounded active reference count.
        active_preflights: usize,
    },
}

/// An admitted artifact that keeps its release active for one preflight.
///
/// The reference is cancellation-safe: [`Drop`] releases it. Call
/// [`Self::finish`] to release it at a known preflight boundary.
#[derive(Debug)]
pub struct ActiveArtifact {
    owner: Weak<Mutex<AdmissionState>>,
    identity: ReleaseIdentity,
    artifact: ReleaseArtifact,
    active: bool,
}

impl ActiveArtifact {
    /// Release that admitted this artifact.
    #[must_use]
    pub const fn release(&self) -> &ReleaseIdentity {
        &self.identity
    }

    /// Exact admitted artifact record.
    #[must_use]
    pub const fn artifact(&self) -> &ReleaseArtifact {
        &self.artifact
    }

    /// Finish the preflight and release its active reference immediately.
    pub fn finish(mut self) {
        self.release_reference();
    }

    fn release_reference(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let mut state = owner.lock().unwrap_or_else(PoisonError::into_inner);
        let slot = if state.current.manifest.identity() == self.identity {
            Some(&mut state.current)
        } else {
            state
                .previous
                .as_mut()
                .filter(|previous| previous.manifest.identity() == self.identity)
        };
        if let Some(slot) = slot {
            slot.active_preflights = slot.active_preflights.saturating_sub(1);
            state.active_preflights = state.active_preflights.saturating_sub(1);
        }
    }
}

impl Drop for ActiveArtifact {
    fn drop(&mut self) {
        self.release_reference();
    }
}

#[cfg(test)]
mod tests {
    use proptest::collection::{btree_set, vec};
    use proptest::prelude::*;

    use super::*;

    fn product(value: &str) -> ProductId {
        ProductId::new(value).expect("valid test product")
    }

    fn release(value: &str) -> ReleaseId {
        ReleaseId::new(value).expect("valid test release")
    }

    fn role(value: &str) -> ArtifactRole {
        ArtifactRole::new(value).expect("valid test role")
    }

    fn target(value: &str) -> TargetTriple {
        TargetTriple::new(value).expect("valid test target")
    }

    fn capability(value: &str) -> CapabilityId {
        CapabilityId::new(value).expect("valid test capability")
    }

    fn capabilities(values: &[&str]) -> CapabilitySet {
        CapabilitySet::try_from_iter(values.iter().map(|value| capability(value)))
            .expect("valid test capabilities")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn protocol(value: u32) -> ProtocolVersion {
        ProtocolVersion::new(value).expect("valid test protocol")
    }

    const fn historical_check() -> HistoricalReleaseIdentityCheck {
        HistoricalReleaseIdentityCheck::completed()
    }

    fn artifact(
        digest_byte: u8,
        role_name: &str,
        target_name: &str,
        protocol_number: u32,
        capability_names: &[&str],
    ) -> ReleaseArtifact {
        ReleaseArtifact::new(
            role(role_name),
            target(target_name),
            digest(digest_byte),
            protocol(protocol_number),
            capabilities(capability_names),
        )
    }

    fn manifest(release_name: &str, artifacts: Vec<ReleaseArtifact>) -> VerifiedReleaseManifest {
        VerifiedReleaseManifest::from_verified_parts(
            historical_check(),
            product("basil"),
            release(release_name),
            artifacts,
        )
        .expect("valid test manifest")
    }

    fn requirement(
        digest_byte: u8,
        role_name: &str,
        target_name: &str,
        protocol_number: u32,
        capability_names: &[&str],
    ) -> ArtifactRequirement {
        ArtifactRequirement::new(
            digest(digest_byte),
            role(role_name),
            target(target_name),
            protocol(protocol_number),
            capabilities(capability_names),
        )
    }

    fn standard_manifest(release_name: &str, digest_byte: u8) -> VerifiedReleaseManifest {
        manifest(
            release_name,
            vec![artifact(
                digest_byte,
                "entrypoint",
                "x86_64-unknown-linux-musl",
                1,
                &["deliver", "tmpfs"],
            )],
        )
    }

    #[test]
    fn identifiers_enforce_empty_shape_and_bounds() {
        assert_eq!(
            ProductId::new(""),
            Err(IdentityError::Empty {
                kind: IdentityKind::Product
            })
        );
        assert!(ProductId::new(&"a".repeat(MAX_PRODUCT_ID_BYTES)).is_ok());
        assert!(matches!(
            ProductId::new(&"a".repeat(MAX_PRODUCT_ID_BYTES + 1)),
            Err(IdentityError::TooLong { .. })
        ));
        for invalid in [
            "Basil",
            "-basil",
            "basil-",
            "basil..core",
            "basil core",
            "básil",
        ] {
            assert!(matches!(
                ProductId::new(invalid),
                Err(IdentityError::InvalidShape { .. })
            ));
        }
        assert!(TargetTriple::new("x86_64-unknown-linux-musl").is_ok());
        assert!(CapabilityId::new("startup.deliver_tmpfs").is_ok());
    }

    #[test]
    fn release_identifiers_use_a_separate_opaque_semver_compatible_grammar() {
        for valid in [
            "0.8.0",
            "0.8.0-RC.1+BUILD-7",
            "1.2.3-alpha--tail-",
            "1---",
            "1-",
            "1.0.0+build.20260715",
        ] {
            assert!(
                ReleaseId::new(valid).is_ok(),
                "valid release token: {valid}"
            );
        }
        assert!(ReleaseId::new(&"a".repeat(MAX_RELEASE_ID_BYTES)).is_ok());
        assert!(matches!(
            ReleaseId::new(&"a".repeat(MAX_RELEASE_ID_BYTES + 1)),
            Err(IdentityError::TooLong { .. })
        ));
        assert_eq!(
            ReleaseId::new(""),
            Err(IdentityError::Empty {
                kind: IdentityKind::Release
            })
        );
        for invalid in [
            "-1.0.0",
            ".1.0.0",
            "+build",
            "1.0.0+",
            "1.0.0+build+again",
            "1..0",
            "1.+build",
            "1.0.0 build",
            "1/2",
            "1_2",
            "β.1",
        ] {
            assert!(
                matches!(
                    ReleaseId::new(invalid),
                    Err(IdentityError::InvalidShape { .. })
                ),
                "invalid release token: {invalid}"
            );
        }
    }

    #[test]
    fn digest_and_protocol_are_exact() {
        assert!(Sha256Digest::try_from_slice(&[0; 31]).is_err());
        assert!(Sha256Digest::try_from_slice(&[0; 32]).is_ok());
        assert!(Sha256Digest::try_from_slice(&[0; 33]).is_err());
        assert_eq!(ProtocolVersion::new(0), Err(IdentityError::ZeroProtocol));
        assert_eq!(protocol(1).get(), 1);
    }

    #[test]
    fn capability_sets_reject_empty_duplicate_and_oversized_inputs() {
        assert_eq!(
            CapabilitySet::try_from_iter(Vec::new()),
            Err(CollectionError::EmptyCapabilities)
        );
        assert!(matches!(
            CapabilitySet::try_from_iter([capability("deliver"), capability("deliver")]),
            Err(CollectionError::DuplicateCapability { .. })
        ));
        let oversized =
            (0..=MAX_CAPABILITIES_PER_ARTIFACT).map(|index| capability(&format!("cap{index}")));
        assert!(matches!(
            CapabilitySet::try_from_iter(oversized),
            Err(CollectionError::TooManyCapabilities { .. })
        ));
    }

    #[test]
    fn manifest_rejects_empty_duplicate_and_oversized_indexes() {
        assert_eq!(
            VerifiedReleaseManifest::from_verified_parts(
                historical_check(),
                product("basil"),
                release("0.8.0"),
                Vec::new()
            ),
            Err(CollectionError::EmptyArtifacts)
        );
        let first = artifact(1, "entrypoint", "x86_64-linux", 1, &["deliver"]);
        let conflicting = artifact(1, "entrypoint", "aarch64-linux", 2, &["other"]);
        assert!(matches!(
            VerifiedReleaseManifest::from_verified_parts(
                historical_check(),
                product("basil"),
                release("0.8.0"),
                [first, conflicting]
            ),
            Err(CollectionError::DuplicateArtifact { .. })
        ));
        let oversized = (0..=MAX_ARTIFACTS_PER_MANIFEST).map(|index| {
            let mut bytes = [0_u8; 32];
            bytes[..std::mem::size_of::<usize>()].copy_from_slice(&index.to_be_bytes());
            ReleaseArtifact::new(
                role("entrypoint"),
                target("x86_64-linux"),
                Sha256Digest::from_bytes(bytes),
                protocol(1),
                capabilities(&["deliver"]),
            )
        });
        assert!(matches!(
            VerifiedReleaseManifest::from_verified_parts(
                historical_check(),
                product("basil"),
                release("0.8.0"),
                oversized
            ),
            Err(CollectionError::TooManyArtifacts { .. })
        ));
    }

    #[test]
    fn same_digest_different_role_and_same_role_different_digest_are_distinct() {
        let verified = manifest(
            "0.8.0",
            vec![
                artifact(1, "entrypoint", "x86_64-linux", 1, &["deliver"]),
                artifact(1, "attestor", "x86_64-linux", 1, &["resolve"]),
                artifact(2, "entrypoint", "aarch64-linux", 1, &["deliver"]),
            ],
        );
        assert_eq!(verified.artifact_count(), 3);
    }

    #[test]
    fn lookup_is_exact_and_capabilities_are_required_subsets() {
        let verified = standard_manifest("0.8.0", 1);
        assert!(
            verified
                .lookup(&requirement(
                    1,
                    "entrypoint",
                    "x86_64-unknown-linux-musl",
                    1,
                    &["deliver"]
                ))
                .is_ok()
        );
        assert!(matches!(
            verified.lookup(&requirement(
                2,
                "entrypoint",
                "x86_64-unknown-linux-musl",
                1,
                &["deliver"]
            )),
            Err(AdmissionError::ArtifactNotFound { .. })
        ));
        assert!(matches!(
            verified.lookup(&requirement(
                1,
                "attestor",
                "x86_64-unknown-linux-musl",
                1,
                &["deliver"]
            )),
            Err(AdmissionError::ArtifactNotFound { .. })
        ));
        assert!(matches!(
            verified.lookup(&requirement(
                1,
                "entrypoint",
                "aarch64-unknown-linux-musl",
                1,
                &["deliver"]
            )),
            Err(AdmissionError::TargetMismatch { .. })
        ));
        assert!(matches!(
            verified.lookup(&requirement(
                1,
                "entrypoint",
                "x86_64-unknown-linux-musl",
                2,
                &["deliver"]
            )),
            Err(AdmissionError::ProtocolMismatch { .. })
        ));
        assert!(matches!(
            verified.lookup(&requirement(
                1,
                "entrypoint",
                "x86_64-unknown-linux-musl",
                1,
                &["deliver", "unknown"]
            )),
            Err(AdmissionError::MissingCapabilities { .. })
        ));
    }

    #[test]
    fn current_key_mismatch_never_falls_back_to_previous() {
        let admission = ReleaseAdmission::new(standard_manifest("0.8.0", 1));
        admission
            .promote(manifest(
                "0.9.0",
                vec![artifact(
                    1,
                    "entrypoint",
                    "aarch64-unknown-linux-musl",
                    1,
                    &["deliver", "tmpfs"],
                )],
            ))
            .expect("promotion succeeds");
        assert!(matches!(
            admission.begin_preflight(&requirement(
                1,
                "entrypoint",
                "x86_64-unknown-linux-musl",
                1,
                &["deliver"]
            )),
            Err(AdmissionError::TargetMismatch { .. })
        ));
    }

    #[test]
    fn previous_is_used_only_when_current_key_is_absent() {
        let admission = ReleaseAdmission::new(standard_manifest("0.8.0", 1));
        admission
            .promote(standard_manifest("0.9.0", 2))
            .expect("promotion succeeds");
        let active = admission
            .begin_preflight(&requirement(
                1,
                "entrypoint",
                "x86_64-unknown-linux-musl",
                1,
                &["deliver"],
            ))
            .expect("previous artifact admitted");
        assert_eq!(active.release().release().as_str(), "0.8.0");
    }

    #[test]
    fn promotion_downgrade_and_rollback_are_explicit_and_deterministic() {
        let admission = ReleaseAdmission::new(standard_manifest("0.8.0", 1));
        let promoted = admission
            .promote(standard_manifest("0.9.0", 2))
            .expect("promotion succeeds");
        assert_eq!(promoted.kind, TransitionKind::Promotion);
        assert_eq!(promoted.current.release().as_str(), "0.9.0");
        assert_eq!(
            promoted
                .previous
                .as_ref()
                .expect("previous exists")
                .release()
                .as_str(),
            "0.8.0"
        );
        let rolled_back = admission.rollback().expect("rollback succeeds");
        assert_eq!(rolled_back.kind, TransitionKind::Rollback);
        assert_eq!(rolled_back.current.release().as_str(), "0.8.0");
        let rolled_forward = admission.rollback().expect("second rollback succeeds");
        assert_eq!(rolled_forward.current.release().as_str(), "0.9.0");
        let downgraded = admission
            .downgrade(standard_manifest("0.7.1", 3))
            .expect("explicit downgrade succeeds");
        assert_eq!(downgraded.kind, TransitionKind::Downgrade);
        assert_eq!(downgraded.current.release().as_str(), "0.7.1");
    }

    #[test]
    fn lifecycle_identity_errors_are_atomic() {
        let admission = ReleaseAdmission::new(standard_manifest("0.8.0", 1));
        let initial = admission.snapshot();
        assert!(matches!(
            admission.promote(standard_manifest("0.8.0", 1)),
            Err(LifecycleError::AlreadyCurrent { .. })
        ));
        assert_eq!(admission.snapshot(), initial);

        let conflict = manifest(
            "0.8.0",
            vec![artifact(9, "entrypoint", "x86_64-linux", 1, &["deliver"])],
        );
        assert!(matches!(
            admission.promote(conflict),
            Err(LifecycleError::ReleaseIdentityConflict { .. })
        ));
        assert_eq!(admission.snapshot(), initial);

        let other_product = VerifiedReleaseManifest::from_verified_parts(
            historical_check(),
            product("other"),
            release("1.0.0"),
            [artifact(2, "entrypoint", "x86_64-linux", 1, &["deliver"])],
        )
        .expect("valid other product manifest");
        assert!(matches!(
            admission.promote(other_product),
            Err(LifecycleError::ProductMismatch { .. })
        ));
        assert_eq!(admission.snapshot(), initial);
    }

    #[test]
    fn retained_previous_requires_rollback_not_repromotion() {
        let admission = ReleaseAdmission::new(standard_manifest("0.8.0", 1));
        admission
            .promote(standard_manifest("0.9.0", 2))
            .expect("promotion succeeds");
        assert!(matches!(
            admission.promote(standard_manifest("0.8.0", 1)),
            Err(LifecycleError::RollbackRequired { .. })
        ));
    }

    #[test]
    fn active_previous_blocks_removal_and_replacement_until_drop() {
        let admission = ReleaseAdmission::new(standard_manifest("0.8.0", 1));
        admission
            .promote(standard_manifest("0.9.0", 2))
            .expect("promotion succeeds");
        let active = admission
            .begin_preflight(&requirement(
                1,
                "entrypoint",
                "x86_64-unknown-linux-musl",
                1,
                &["deliver"],
            ))
            .expect("previous artifact admitted");
        let before = admission.snapshot();
        assert!(matches!(
            admission.remove_previous(),
            Err(LifecycleError::PreviousReleaseActive { .. })
        ));
        assert!(matches!(
            admission.promote(standard_manifest("1.0.0", 3)),
            Err(LifecycleError::PreviousReleaseActive { .. })
        ));
        assert_eq!(admission.snapshot(), before);
        drop(active);
        assert_eq!(
            admission
                .snapshot()
                .previous
                .expect("previous")
                .active_preflights,
            0
        );
        assert!(admission.remove_previous().is_ok());
    }

    #[test]
    fn active_current_moves_with_promotion_and_finish_releases_once() {
        let admission = ReleaseAdmission::new(standard_manifest("0.8.0", 1));
        let active = admission
            .begin_preflight(&requirement(
                1,
                "entrypoint",
                "x86_64-unknown-linux-musl",
                1,
                &["deliver"],
            ))
            .expect("current artifact admitted");
        admission
            .promote(standard_manifest("0.9.0", 2))
            .expect("promotion succeeds");
        assert!(matches!(
            admission.remove_previous(),
            Err(LifecycleError::PreviousReleaseActive { .. })
        ));
        active.finish();
        assert_eq!(
            admission
                .snapshot()
                .previous
                .expect("previous")
                .active_preflights,
            0
        );
        assert!(admission.remove_previous().is_ok());
    }

    #[test]
    fn remove_and_rollback_without_previous_fail_without_mutation() {
        let admission = ReleaseAdmission::new(standard_manifest("0.8.0", 1));
        let initial = admission.snapshot();
        assert_eq!(
            admission.remove_previous(),
            Err(LifecycleError::NoPreviousRelease)
        );
        assert_eq!(admission.rollback(), Err(LifecycleError::NoPreviousRelease));
        assert_eq!(admission.snapshot(), initial);
    }

    proptest! {
        #[test]
        fn identifier_validation_never_panics(raw in any::<String>()) {
            let _ = ProductId::new(&raw);
            let _ = ReleaseId::new(&raw);
            let _ = ArtifactRole::new(&raw);
            let _ = TargetTriple::new(&raw);
            let _ = CapabilityId::new(&raw);
        }

        #[test]
        fn artifact_order_does_not_change_the_index(
            bytes in vec(any::<u8>(), 1..32)
        ) {
            let mut unique = BTreeSet::new();
            for byte in bytes {
                unique.insert(byte);
            }
            prop_assume!(!unique.is_empty());
            let artifacts: Vec<_> = unique
                .iter()
                .map(|byte| artifact(*byte, "entrypoint", "x86_64-linux", 1, &["deliver"]))
                .collect();
            let mut reversed = artifacts.clone();
            reversed.reverse();
            let first = manifest("0.8.0", artifacts);
            let second = manifest("0.8.0", reversed);
            prop_assert_eq!(first, second);
        }

        #[test]
        fn required_capability_subset_exactly_controls_admission(
            provided in btree_set(0_u8..8, 1..8),
            required in btree_set(0_u8..8, 1..8),
        ) {
            let provided_names: Vec<_> = provided.iter().map(|value| format!("cap{value}")).collect();
            let required_names: Vec<_> = required.iter().map(|value| format!("cap{value}")).collect();
            let provided_refs: Vec<_> = provided_names.iter().map(String::as_str).collect();
            let required_refs: Vec<_> = required_names.iter().map(String::as_str).collect();
            let verified = manifest(
                "0.8.0",
                vec![artifact(1, "entrypoint", "x86_64-linux", 1, &provided_refs)],
            );
            let result = verified.lookup(&requirement(
                1,
                "entrypoint",
                "x86_64-linux",
                1,
                &required_refs,
            ));
            prop_assert_eq!(result.is_ok(), required.is_subset(&provided));
        }

        #[test]
        fn duplicate_artifact_injection_always_fails(byte in any::<u8>()) {
            let first = artifact(byte, "entrypoint", "x86_64-linux", 1, &["deliver"]);
            let second = artifact(byte, "entrypoint", "aarch64-linux", 2, &["other"]);
            let result = VerifiedReleaseManifest::from_verified_parts(
                historical_check(),
                product("basil"),
                release("0.8.0"),
                [first, second],
            );
            let duplicate = matches!(result, Err(CollectionError::DuplicateArtifact { .. }));
            prop_assert!(duplicate);
        }
    }
}
