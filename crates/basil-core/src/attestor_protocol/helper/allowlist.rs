// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Root-owned, generation-versioned measurement-helper allowlist.
//!
//! The helper's expectations never come from request content: they are
//! immutable root-owned policy files installed additively by the external
//! authority installation transaction. During authority overlap the old and
//! candidate helper-policy generations are both installed, so the single
//! helper endpoint serves old serving sessions and new qualifiers
//! concurrently. A request names a `(policy identity, generation, realm)`
//! triple, which only *selects* among installed expectations; a request
//! naming an uninstalled generation, or a realm absent from that generation,
//! rejects.
//!
//! One policy file per installed generation, named
//! `<policyIdentity>.toml` (the identity embeds its own `-g<generation>`
//! qualifier):
//!
//! ```toml
//! schema = "basil-measure-helper-policy"
//! schemaVersion = 1
//! policyIdentity = "basil-measure-policy-g1"
//! policyGeneration = 1
//!
//! [realms.production-docker]
//! authorityGeneration = 1
//! serviceUnit = "basil-attestor-production-docker-g1.service"
//! attestorUid = "992"
//! lsmProfile = "selinux:basil_attestor_g1_t"
//! lockdownProfile = "basil-attestor-lockdown-g1"
//! ```
//!
//! Every generation-qualified identity must embed the exact decimal
//! generation it is bound to (see `ident::embeds_exact_generation`); a
//! mismatch rejects the whole directory load, fail closed.

use std::collections::BTreeMap;
use std::io::Read;
use std::num::NonZeroU64;
use std::path::Path;

use rustix::fs::{Dir, FileType, Mode, OFlags};
use serde::Deserialize;
use thiserror::Error;

use super::ident;

/// Maximum installed helper-policy generations (files) in one directory.
pub const MAX_INSTALLED_GENERATIONS: usize = 64;
/// Maximum realms in one installed policy generation.
pub const MAX_REALMS_PER_GENERATION: usize = 64;
/// Maximum bytes in one policy file.
pub const MAX_POLICY_FILE_BYTES: usize = 64 * 1024;
/// Exact `schema` value of a helper policy file.
pub const POLICY_SCHEMA: &str = "basil-measure-helper-policy";
/// Exact `schemaVersion` value of a helper policy file.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Load-time options for the allowlist directory.
///
/// Production loads with `required_owner_uid = 0`: the directory and every
/// policy file must be root-owned and writable only by their owner.
/// Conformance tests substitute the test UID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllowlistLoadOptions {
    /// Exact owner UID required for the directory and every policy file.
    pub required_owner_uid: u32,
}

/// The installed expectation for one `(policy generation, realm)` pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmExpectation {
    /// Immutable measurement-authority generation this expectation serves.
    pub authority_generation: NonZeroU64,
    /// Exact generation-qualified attestor system service unit.
    pub service_unit: String,
    /// Exact attestor UID the stream peer must present.
    pub attestor_uid: u32,
    /// Exact LSM profile identity the peer must run under.
    pub lsm_profile: String,
    /// Exact post-init lockdown profile identity the peer must prove.
    pub lockdown_profile: String,
}

/// One `(identity, generation, realms)` part for [`InstalledAllowlist::from_parts`].
pub type AllowlistPart = (String, NonZeroU64, Vec<(String, RealmExpectation)>);

/// The set of installed helper-policy generations.
#[derive(Clone, Debug, Default)]
pub struct InstalledAllowlist {
    generations: BTreeMap<(String, u64), BTreeMap<String, RealmExpectation>>,
}

/// Typed lookup failure; maps one-to-one onto wire rejection codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum AllowlistLookupError {
    /// The named helper-policy identity/generation pair is not installed.
    #[error("helper policy generation not installed")]
    PolicyNotInstalled,
    /// The named realm is absent from the installed generation.
    #[error("realm not installed for this policy generation")]
    RealmNotInstalled,
}

/// Typed allowlist directory load failure.
#[derive(Debug, Error)]
pub enum AllowlistError {
    /// The directory or a policy file could not be opened or read.
    #[error("allowlist I/O failure on `{path}`: {source}")]
    Io {
        /// Offending directory entry name (never a full caller path).
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The directory or a file has the wrong owner or a group/other write bit.
    #[error("allowlist entry `{0}` is not exclusively owned by the required owner")]
    Untrusted(String),
    /// A directory entry is not a regular `<identity>.toml` policy file.
    #[error("allowlist entry `{0}` is not a policy file")]
    UnexpectedEntry(String),
    /// A policy file exceeds [`MAX_POLICY_FILE_BYTES`].
    #[error("allowlist entry `{0}` exceeds the policy file size ceiling")]
    Oversized(String),
    /// A policy file failed strict TOML parsing.
    #[error("allowlist entry `{0}` failed strict parsing")]
    Parse(String),
    /// A policy file violates a schema or binding rule.
    #[error("allowlist entry `{entry}` invalid: {reason}")]
    Invalid {
        /// Offending directory entry name.
        entry: String,
        /// Violated rule.
        reason: &'static str,
    },
    /// More than [`MAX_INSTALLED_GENERATIONS`] policy files are installed.
    #[error("too many installed policy generations")]
    TooManyGenerations,
    /// Two files declare the same `(identity, generation)` pair.
    #[error("duplicate installed policy generation `{0}`")]
    DuplicateGeneration(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyFile {
    schema: String,
    schema_version: u32,
    policy_identity: String,
    policy_generation: u64,
    realms: BTreeMap<String, RealmEntryFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RealmEntryFile {
    authority_generation: u64,
    service_unit: String,
    attestor_uid: String,
    lsm_profile: String,
    lockdown_profile: String,
}

impl InstalledAllowlist {
    /// Load every installed policy generation from a protected directory.
    ///
    /// The directory and each file are opened without following symlinks,
    /// must be owned by `options.required_owner_uid`, and must carry no
    /// group or other write bit. Any unexpected entry, bound violation,
    /// binding mismatch, or duplicate rejects the whole load.
    ///
    /// # Errors
    ///
    /// Returns [`AllowlistError`] describing the first violation.
    pub fn load_dir(
        directory: &Path,
        options: &AllowlistLoadOptions,
    ) -> Result<Self, AllowlistError> {
        let dir_fd = rustix::fs::open(
            directory,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
            Mode::empty(),
        )
        .map_err(|errno| AllowlistError::Io {
            path: ".".to_owned(),
            source: errno.into(),
        })?;
        let dir_stat = rustix::fs::fstat(&dir_fd).map_err(|errno| AllowlistError::Io {
            path: ".".to_owned(),
            source: errno.into(),
        })?;
        check_exclusive(&dir_stat, options.required_owner_uid, ".")?;

        let mut names = Vec::new();
        let mut reader = Dir::read_from(&dir_fd).map_err(|errno| AllowlistError::Io {
            path: ".".to_owned(),
            source: errno.into(),
        })?;
        for entry in reader.by_ref() {
            let entry = entry.map_err(|errno| AllowlistError::Io {
                path: ".".to_owned(),
                source: errno.into(),
            })?;
            let name_bytes = entry.file_name().to_bytes();
            if name_bytes == b"." || name_bytes == b".." {
                continue;
            }
            let name = String::from_utf8(name_bytes.to_vec())
                .map_err(|_| AllowlistError::UnexpectedEntry("<non-utf8>".to_owned()))?;
            names.push(name);
        }
        if names.len() > MAX_INSTALLED_GENERATIONS {
            return Err(AllowlistError::TooManyGenerations);
        }
        names.sort_unstable();

        let mut generations: BTreeMap<(String, u64), BTreeMap<String, RealmExpectation>> =
            BTreeMap::new();
        for name in names {
            let (identity, generation, realms) = load_policy_file(&dir_fd, &name, *options)?;
            let key = (identity, generation.get());
            if generations.contains_key(&key) {
                return Err(AllowlistError::DuplicateGeneration(name));
            }
            generations.insert(key, realms);
        }
        Ok(Self { generations })
    }

    /// Build an allowlist directly from validated parts (conformance tests).
    #[must_use]
    pub fn from_parts(parts: Vec<AllowlistPart>) -> Self {
        let mut generations = BTreeMap::new();
        for (identity, generation, realms) in parts {
            generations.insert(
                (identity, generation.get()),
                realms.into_iter().collect::<BTreeMap<_, _>>(),
            );
        }
        Self { generations }
    }

    /// Select the installed expectation for one request-named triple.
    ///
    /// # Errors
    ///
    /// Returns [`AllowlistLookupError`] when the generation or realm is not
    /// installed.
    pub fn lookup(
        &self,
        policy_identity: &str,
        policy_generation: NonZeroU64,
        realm: &str,
    ) -> Result<&RealmExpectation, AllowlistLookupError> {
        let key = (policy_identity.to_owned(), policy_generation.get());
        let realms = self
            .generations
            .get(&key)
            .ok_or(AllowlistLookupError::PolicyNotInstalled)?;
        realms
            .get(realm)
            .ok_or(AllowlistLookupError::RealmNotInstalled)
    }

    /// Number of installed policy generations.
    #[must_use]
    pub fn generation_count(&self) -> usize {
        self.generations.len()
    }
}

fn check_exclusive(
    stat: &rustix::fs::Stat,
    required_owner: u32,
    entry: &str,
) -> Result<(), AllowlistError> {
    let group_or_other_write = 0o022;
    if stat.st_uid != required_owner || (stat.st_mode & group_or_other_write) != 0 {
        return Err(AllowlistError::Untrusted(entry.to_owned()));
    }
    Ok(())
}

fn load_policy_file(
    dir_fd: &rustix::fd::OwnedFd,
    name: &str,
    options: AllowlistLoadOptions,
) -> Result<(String, NonZeroU64, BTreeMap<String, RealmExpectation>), AllowlistError> {
    let Some(stem) = name.strip_suffix(".toml") else {
        return Err(AllowlistError::UnexpectedEntry(name.to_owned()));
    };
    let file_fd = rustix::fs::openat(
        dir_fd,
        name,
        OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
        Mode::empty(),
    )
    .map_err(|errno| AllowlistError::Io {
        path: name.to_owned(),
        source: errno.into(),
    })?;
    let stat = rustix::fs::fstat(&file_fd).map_err(|errno| AllowlistError::Io {
        path: name.to_owned(),
        source: errno.into(),
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(AllowlistError::UnexpectedEntry(name.to_owned()));
    }
    check_exclusive(&stat, options.required_owner_uid, name)?;

    let mut file = std::fs::File::from(file_fd);
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_POLICY_FILE_BYTES).unwrap_or(u64::MAX);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| AllowlistError::Io {
            path: name.to_owned(),
            source,
        })?;
    if bytes.len() > MAX_POLICY_FILE_BYTES {
        return Err(AllowlistError::Oversized(name.to_owned()));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| AllowlistError::Parse(name.to_owned()))?;
    let parsed: PolicyFile =
        toml::from_str(text).map_err(|_| AllowlistError::Parse(name.to_owned()))?;
    let (identity, generation, realms) = validate_policy(name, stem, parsed)?;
    Ok((identity, generation, realms))
}

fn validate_policy(
    name: &str,
    stem: &str,
    parsed: PolicyFile,
) -> Result<(String, NonZeroU64, BTreeMap<String, RealmExpectation>), AllowlistError> {
    let invalid = |reason: &'static str| AllowlistError::Invalid {
        entry: name.to_owned(),
        reason,
    };
    if parsed.schema != POLICY_SCHEMA {
        return Err(invalid("schema"));
    }
    if parsed.schema_version != POLICY_SCHEMA_VERSION {
        return Err(invalid("schemaVersion"));
    }
    if !ident::is_valid_identity(&parsed.policy_identity) {
        return Err(invalid("policyIdentity"));
    }
    if parsed.policy_identity != stem {
        return Err(invalid("file name must equal policyIdentity"));
    }
    let generation =
        NonZeroU64::new(parsed.policy_generation).ok_or_else(|| invalid("policyGeneration"))?;
    if !ident::embeds_exact_generation(&parsed.policy_identity, generation.get()) {
        return Err(invalid("policyIdentity generation qualifier"));
    }
    if parsed.realms.is_empty() {
        return Err(invalid("realms empty"));
    }
    if parsed.realms.len() > MAX_REALMS_PER_GENERATION {
        return Err(invalid("too many realms"));
    }
    let mut realms = BTreeMap::new();
    for (realm, entry) in parsed.realms {
        if !ident::is_valid_realm_name(&realm) {
            return Err(invalid("realm name"));
        }
        let authority_generation = NonZeroU64::new(entry.authority_generation)
            .ok_or_else(|| invalid("authorityGeneration"))?;
        if !ident::is_valid_service_unit(&entry.service_unit) {
            return Err(invalid("serviceUnit"));
        }
        if !ident::unit_has_generation_suffix(&entry.service_unit, authority_generation.get()) {
            return Err(invalid("serviceUnit generation qualifier"));
        }
        if !ident::embeds_exact_generation(
            entry.service_unit.trim_end_matches(".service"),
            authority_generation.get(),
        ) {
            return Err(invalid("serviceUnit embeds a foreign generation"));
        }
        let attestor_uid =
            ident::parse_decimal_uid(&entry.attestor_uid).ok_or_else(|| invalid("attestorUid"))?;
        if !ident::is_valid_identity(&entry.lsm_profile)
            || !ident::embeds_exact_generation(&entry.lsm_profile, authority_generation.get())
        {
            return Err(invalid("lsmProfile"));
        }
        if !ident::is_valid_identity(&entry.lockdown_profile)
            || !ident::embeds_exact_generation(&entry.lockdown_profile, authority_generation.get())
        {
            return Err(invalid("lockdownProfile"));
        }
        realms.insert(
            realm,
            RealmExpectation {
                authority_generation,
                service_unit: entry.service_unit,
                attestor_uid,
                lsm_profile: entry.lsm_profile,
                lockdown_profile: entry.lockdown_profile,
            },
        );
    }
    Ok((parsed.policy_identity, generation, realms))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn owner() -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn options() -> AllowlistLoadOptions {
        AllowlistLoadOptions {
            required_owner_uid: owner(),
        }
    }

    const GOOD: &str = r#"
schema = "basil-measure-helper-policy"
schemaVersion = 1
policyIdentity = "basil-measure-policy-g1"
policyGeneration = 1

[realms.production-docker]
authorityGeneration = 1
serviceUnit = "basil-attestor-production-docker-g1.service"
attestorUid = "992"
lsmProfile = "selinux:basil_attestor_g1_t"
lockdownProfile = "basil-attestor-lockdown-g1"
"#;

    fn write_dir(files: &[(&str, &str)]) -> tempdir::TempDirHandle {
        tempdir::write_dir(files)
    }

    /// Minimal private tempdir helper (no tempfile dev-dependency).
    mod tempdir {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};

        pub struct TempDirHandle {
            pub path: PathBuf,
        }

        impl Drop for TempDirHandle {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        pub fn write_dir(files: &[(&str, &str)]) -> TempDirHandle {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "basil-helper-allowlist-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            for (name, contents) in files {
                std::fs::write(path.join(name), contents).expect("write policy file");
            }
            TempDirHandle { path }
        }
    }

    #[test]
    fn loads_a_valid_directory() {
        let dir = write_dir(&[("basil-measure-policy-g1.toml", GOOD)]);
        let allowlist = InstalledAllowlist::load_dir(&dir.path, &options()).expect("load");
        assert_eq!(allowlist.generation_count(), 1);
        let expectation = allowlist
            .lookup(
                "basil-measure-policy-g1",
                NonZeroU64::MIN,
                "production-docker",
            )
            .expect("lookup");
        assert_eq!(expectation.attestor_uid, 992);
        assert_eq!(
            expectation.service_unit,
            "basil-attestor-production-docker-g1.service"
        );
    }

    #[test]
    fn coexisting_generations_are_both_selectable() {
        let g2 = GOOD
            .replace("-g1", "-g2")
            .replace("_g1_", "_g2_")
            .replace("policyGeneration = 1", "policyGeneration = 2")
            .replace("authorityGeneration = 1", "authorityGeneration = 2");
        let dir = write_dir(&[
            ("basil-measure-policy-g1.toml", GOOD),
            ("basil-measure-policy-g2.toml", &g2),
        ]);
        let allowlist = InstalledAllowlist::load_dir(&dir.path, &options()).expect("load");
        assert_eq!(allowlist.generation_count(), 2);
        assert!(
            allowlist
                .lookup(
                    "basil-measure-policy-g1",
                    NonZeroU64::MIN,
                    "production-docker"
                )
                .is_ok()
        );
        let two = NonZeroU64::new(2).expect("nonzero");
        assert!(
            allowlist
                .lookup("basil-measure-policy-g2", two, "production-docker")
                .is_ok()
        );
    }

    #[test]
    fn uninstalled_generation_and_realm_reject() {
        let dir = write_dir(&[("basil-measure-policy-g1.toml", GOOD)]);
        let allowlist = InstalledAllowlist::load_dir(&dir.path, &options()).expect("load");
        let two = NonZeroU64::new(2).expect("nonzero");
        assert_eq!(
            allowlist
                .lookup("basil-measure-policy-g2", two, "production-docker")
                .unwrap_err(),
            AllowlistLookupError::PolicyNotInstalled
        );
        // Same identity, wrong generation.
        assert_eq!(
            allowlist
                .lookup("basil-measure-policy-g1", two, "production-docker")
                .unwrap_err(),
            AllowlistLookupError::PolicyNotInstalled
        );
        assert_eq!(
            allowlist
                .lookup("basil-measure-policy-g1", NonZeroU64::MIN, "other-realm")
                .unwrap_err(),
            AllowlistLookupError::RealmNotInstalled
        );
    }

    #[test]
    fn rejects_binding_violations() {
        for (mutation, replacement) in [
            // Identity qualifier disagrees with policyGeneration.
            ("policyGeneration = 1", "policyGeneration = 3"),
            // Unit qualifier disagrees with authorityGeneration.
            ("authorityGeneration = 1", "authorityGeneration = 3"),
            // LSM identity loses its qualifier.
            (
                "lsmProfile = \"selinux:basil_attestor_g1_t\"",
                "lsmProfile = \"selinux:basil_attestor_t\"",
            ),
            // Username instead of a decimal UID.
            ("attestorUid = \"992\"", "attestorUid = \"basil\""),
            // Unknown field.
            ("policyGeneration = 1", "policyGeneration = 1\nextra = 1"),
        ] {
            let mutated = GOOD.replace(mutation, replacement);
            let dir = write_dir(&[("basil-measure-policy-g1.toml", &mutated)]);
            assert!(
                InstalledAllowlist::load_dir(&dir.path, &options()).is_err(),
                "expected rejection for `{replacement}`"
            );
        }
    }

    #[test]
    fn rejects_identity_file_name_mismatch() {
        let dir = write_dir(&[("wrong-name-g1.toml", GOOD)]);
        assert!(matches!(
            InstalledAllowlist::load_dir(&dir.path, &options()),
            Err(AllowlistError::Invalid { .. })
        ));
    }

    #[test]
    fn rejects_unexpected_entries_and_wrong_owner() {
        let dir = write_dir(&[("README", "not a policy")]);
        assert!(matches!(
            InstalledAllowlist::load_dir(&dir.path, &options()),
            Err(AllowlistError::UnexpectedEntry(_))
        ));

        let dir = write_dir(&[("basil-measure-policy-g1.toml", GOOD)]);
        assert!(matches!(
            InstalledAllowlist::load_dir(
                &dir.path,
                &AllowlistLoadOptions {
                    required_owner_uid: owner().wrapping_add(1),
                }
            ),
            Err(AllowlistError::Untrusted(_))
        ));
    }

    #[test]
    fn rejects_group_writable_policy_files() {
        let dir = write_dir(&[("basil-measure-policy-g1.toml", GOOD)]);
        let file = dir.path.join("basil-measure-policy-g1.toml");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o664)).expect("chmod policy file");
        assert!(matches!(
            InstalledAllowlist::load_dir(&dir.path, &options()),
            Err(AllowlistError::Untrusted(_))
        ));
    }

    #[test]
    fn rejects_duplicate_generation_pairs() {
        // Two file names, same declared identity: the stem check rejects the
        // second file before the duplicate map check can fire.
        let dir = write_dir(&[
            ("basil-measure-policy-g1.toml", GOOD),
            ("basil-measure-policy-g1x.toml", GOOD),
        ]);
        assert!(InstalledAllowlist::load_dir(&dir.path, &options()).is_err());
    }
}
