// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Private-registry credential and certificate-authority isolation.
//!
//! One protected Docker authentication document is loaded at broker startup.
//! Each verifier request receives at most one exact-authority credential and
//! certificate-authority bundle in its private temporary directory.

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

/// Default systemd credential containing the Docker authentication document.
pub const DEFAULT_REGISTRY_AUTH_CREDENTIAL: &str = "basil-registry-auth";
/// Maximum protected Docker authentication document size.
pub const MAX_REGISTRY_AUTH_BYTES: u64 = 64 * 1024;
/// Maximum exact registry authorities in one authentication document.
pub const MAX_REGISTRY_AUTHORITIES: usize = 256;
/// Maximum static authentication value size.
pub const MAX_REGISTRY_CREDENTIAL_BYTES: usize = 16 * 1024;
/// Maximum one-authority PEM certificate-authority bundle size.
pub const MAX_REGISTRY_CA_BYTES: u64 = 1024 * 1024;
/// Maximum exact-authority certificate-authority mappings.
pub const MAX_REGISTRY_CA_AUTHORITIES: usize = 64;
/// Maximum aggregate bytes across all certificate-authority bundles.
pub const MAX_REGISTRY_CA_TOTAL_BYTES: usize = 4 * 1024 * 1024;
/// Maximum X.509 certificates in one certificate-authority bundle.
pub const MAX_REGISTRY_CA_CERTIFICATES: usize = 64;

/// Protected source for the one Docker authentication document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryAuthSource {
    /// Named credential below systemd's `CREDENTIALS_DIRECTORY`.
    SystemdCredential {
        /// Exact credential name. The default is
        /// [`DEFAULT_REGISTRY_AUTH_CREDENTIAL`].
        name: String,
    },
    /// Exact absolute protected compatibility file.
    ProtectedFile(PathBuf),
}

impl Default for RegistryAuthSource {
    fn default() -> Self {
        Self::SystemdCredential {
            name: DEFAULT_REGISTRY_AUTH_CREDENTIAL.to_string(),
        }
    }
}

/// Disclosure-safe private-registry configuration or authentication failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RegistryIsolationError {
    /// The selected source, authority, or certificate-authority mapping is invalid.
    #[error("private-registry configuration is invalid")]
    Configuration,
    /// The protected authentication document is unavailable or unsafe.
    #[error("REGISTRY_AUTH_FAILED")]
    Authentication,
    /// A private verifier view could not be created or populated.
    #[error("private-registry verifier view is unavailable")]
    Unavailable,
}

/// One exact normalized registry authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegistryAuthority(String);

impl RegistryAuthority {
    /// Parse and normalize a DNS name, IPv4 address, or bracketed IPv6 address
    /// with an optional exact port.
    pub fn parse(value: &str) -> Result<Self, RegistryIsolationError> {
        if value.is_empty()
            || value.len() > 512
            || value.contains('*')
            || value.contains('/')
            || value.contains('@')
            || value.contains('?')
            || value.contains('#')
            || value.chars().any(char::is_control)
        {
            return Err(RegistryIsolationError::Configuration);
        }
        let url = url::Url::parse(&format!("https://{value}/"))
            .map_err(|_| RegistryIsolationError::Configuration)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(RegistryIsolationError::Configuration);
        }
        let host = url.host().ok_or(RegistryIsolationError::Configuration)?;
        let normalized_host = match host {
            url::Host::Domain(domain) => domain.to_ascii_lowercase(),
            url::Host::Ipv4(address) => address.to_string(),
            url::Host::Ipv6(address) => format!("[{address}]"),
        };
        let normalized = url.port().map_or_else(
            || normalized_host.clone(),
            |port| format!("{normalized_host}:{port}"),
        );
        Ok(Self(normalized))
    }

    /// Derive the explicit registry authority from an exact OCI repository.
    pub fn from_repository(repository: &str) -> Result<Self, RegistryIsolationError> {
        if repository.is_empty() || repository.ends_with('/') {
            return Err(RegistryIsolationError::Configuration);
        }
        let first = repository
            .split('/')
            .next()
            .ok_or(RegistryIsolationError::Configuration)?;
        if first.contains('.') || first.contains(':') || first == "localhost" {
            Self::parse(first)
        } else {
            Self::parse("docker.io")
        }
    }

    /// Return the normalized authority including its non-default port.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn manifest_url(
        &self,
        repository: &str,
        digest: &str,
    ) -> Result<url::Url, RegistryIsolationError> {
        let first = repository
            .split('/')
            .next()
            .ok_or(RegistryIsolationError::Configuration)?;
        let explicit_authority = first.contains('.') || first.contains(':') || first == "localhost";
        let repository_path = if explicit_authority {
            repository
                .strip_prefix(first)
                .and_then(|value| value.strip_prefix('/'))
                .ok_or(RegistryIsolationError::Configuration)?
        } else {
            repository
        };
        if repository_path.is_empty() || repository_path.split('/').any(str::is_empty) {
            return Err(RegistryIsolationError::Configuration);
        }
        let mut url = url::Url::parse(&format!("https://{}/", self.as_str()))
            .map_err(|_| RegistryIsolationError::Configuration)?;
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| RegistryIsolationError::Configuration)?;
        segments.push("v2");
        for segment in repository_path.split('/') {
            segments.push(segment);
        }
        segments.push("manifests").push(digest);
        drop(segments);
        Ok(url)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialKind {
    Auth,
    IdentityToken,
}

#[derive(Clone)]
struct RegistryCredential {
    kind: CredentialKind,
    value: Zeroizing<String>,
}

impl std::fmt::Debug for RegistryCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryCredential")
            .field("kind", &self.kind)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Loaded startup snapshot of exact-authority registry credentials.
#[derive(Clone, Default)]
pub struct RegistryAuthDocument {
    credentials: BTreeMap<RegistryAuthority, RegistryCredential>,
}

impl std::fmt::Debug for RegistryAuthDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryAuthDocument")
            .field("authority_count", &self.credentials.len())
            .finish()
    }
}

impl RegistryAuthDocument {
    /// Load the configured systemd credential or exact protected file.
    pub fn load(source: &RegistryAuthSource) -> Result<Self, RegistryIsolationError> {
        match source {
            RegistryAuthSource::SystemdCredential { name } => {
                validate_credential_name(name)?;
                let directory = env::var_os("CREDENTIALS_DIRECTORY")
                    .map(PathBuf::from)
                    .ok_or(RegistryIsolationError::Authentication)?;
                Self::load_systemd_credential(&directory, name)
            }
            RegistryAuthSource::ProtectedFile(path) => Self::load_protected_file(path),
        }
    }

    /// Load one named credential from an explicit systemd credentials directory.
    ///
    /// This form supports startup adapters and deterministic tests without
    /// trusting a caller-supplied complete credential path.
    pub fn load_systemd_credential(
        directory: &Path,
        name: &str,
    ) -> Result<Self, RegistryIsolationError> {
        validate_credential_name(name)?;
        if !directory.is_absolute() {
            return Err(RegistryIsolationError::Configuration);
        }
        Self::load_protected_file(&directory.join(name))
    }

    /// Load one exact absolute protected compatibility file.
    pub fn load_protected_file(path: &Path) -> Result<Self, RegistryIsolationError> {
        let bytes = read_bounded_file(path, MAX_REGISTRY_AUTH_BYTES, FileProtection::Secret)?;
        let raw: RawDockerConfig =
            serde_json::from_slice(&bytes).map_err(|_| RegistryIsolationError::Authentication)?;
        let mut credentials = BTreeMap::new();
        if raw.auths.0.is_empty() || raw.auths.0.len() > MAX_REGISTRY_AUTHORITIES {
            return Err(RegistryIsolationError::Authentication);
        }
        for (authority, entry) in raw.auths.0 {
            let authority = RegistryAuthority::parse(&authority)
                .map_err(|_| RegistryIsolationError::Authentication)?;
            let credential = entry.into_credential()?;
            if credentials.insert(authority, credential).is_some() {
                return Err(RegistryIsolationError::Authentication);
            }
        }
        Ok(Self { credentials })
    }

    fn get(&self, authority: &RegistryAuthority) -> Option<&RegistryCredential> {
        self.credentials.get(authority)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDockerConfig {
    auths: RawAuthEntries,
}

struct RawAuthEntries(Vec<(String, RawAuthEntry)>);

impl<'de> Deserialize<'de> for RawAuthEntries {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EntriesVisitor;

        impl<'de> Visitor<'de> for EntriesVisitor {
            type Value = RawAuthEntries;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded map of exact registry authorities")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries = Vec::new();
                while let Some((authority, entry)) = map.next_entry::<String, RawAuthEntry>()? {
                    if entries.len() >= MAX_REGISTRY_AUTHORITIES {
                        return Err(de::Error::custom("too many registry authorities"));
                    }
                    entries.push((authority, entry));
                }
                Ok(RawAuthEntries(entries))
            }
        }

        deserializer.deserialize_map(EntriesVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthEntry {
    auth: Option<SecretString>,
    #[serde(rename = "identitytoken")]
    identity_token: Option<SecretString>,
}

impl RawAuthEntry {
    fn into_credential(self) -> Result<RegistryCredential, RegistryIsolationError> {
        match (self.auth, self.identity_token) {
            (Some(auth), None) => {
                validate_static_auth(&auth.0)?;
                Ok(RegistryCredential {
                    kind: CredentialKind::Auth,
                    value: auth.0,
                })
            }
            (None, Some(token)) if valid_secret(&token.0) => Ok(RegistryCredential {
                kind: CredentialKind::IdentityToken,
                value: token.0,
            }),
            (None, None | Some(_)) | (Some(_), Some(_)) => {
                Err(RegistryIsolationError::Authentication)
            }
        }
    }
}

struct SecretString(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self(Zeroizing::new(value)))
    }
}

fn valid_secret(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REGISTRY_CREDENTIAL_BYTES
        && !value.chars().any(char::is_control)
}

fn validate_static_auth(value: &str) -> Result<(), RegistryIsolationError> {
    if !valid_secret(value) {
        return Err(RegistryIsolationError::Authentication);
    }
    let mut decoded = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|_| RegistryIsolationError::Authentication)?,
    );
    if decoded.len() > MAX_REGISTRY_CREDENTIAL_BYTES || decoded.iter().any(u8::is_ascii_control) {
        return Err(RegistryIsolationError::Authentication);
    }
    let decoded_text =
        std::str::from_utf8(&decoded).map_err(|_| RegistryIsolationError::Authentication)?;
    let Some((username, password)) = decoded_text.split_once(':') else {
        return Err(RegistryIsolationError::Authentication);
    };
    if username.is_empty() || password.is_empty() {
        return Err(RegistryIsolationError::Authentication);
    }
    decoded.zeroize();
    Ok(())
}

fn validate_credential_name(name: &str) -> Result<(), RegistryIsolationError> {
    if name.is_empty()
        || name.len() > 128
        || name.contains('*')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(RegistryIsolationError::Configuration);
    }
    Ok(())
}

/// Startup registry access snapshot and exact-authority public CA mappings.
#[derive(Clone, Debug, Default)]
pub struct RegistryAccess {
    authentication: Option<RegistryAuthDocument>,
    certificate_authorities: BTreeMap<RegistryAuthority, Vec<u8>>,
}

impl RegistryAccess {
    /// Construct an access snapshot, loading at most one authentication source.
    pub fn load(
        source: Option<&RegistryAuthSource>,
        certificate_authorities: BTreeMap<String, PathBuf>,
    ) -> Result<Self, RegistryIsolationError> {
        let authentication = source.map(RegistryAuthDocument::load).transpose()?;
        Self::with_document(authentication, certificate_authorities)
    }

    /// Construct using an explicit systemd credentials directory.
    ///
    /// Production startup normally uses [`Self::load`]. Startup adapters and
    /// tests can inject the already-authenticated systemd directory without
    /// modifying process environment.
    pub fn load_with_credentials_directory(
        source: Option<&RegistryAuthSource>,
        certificate_authorities: BTreeMap<String, PathBuf>,
        credentials_directory: &Path,
    ) -> Result<Self, RegistryIsolationError> {
        let authentication = match source {
            Some(RegistryAuthSource::SystemdCredential { name }) => Some(
                RegistryAuthDocument::load_systemd_credential(credentials_directory, name)?,
            ),
            Some(RegistryAuthSource::ProtectedFile(path)) => {
                Some(RegistryAuthDocument::load_protected_file(path)?)
            }
            None => None,
        };
        Self::with_document(authentication, certificate_authorities)
    }

    /// Construct from an already loaded authentication snapshot.
    pub fn with_document(
        authentication: Option<RegistryAuthDocument>,
        certificate_authorities: BTreeMap<String, PathBuf>,
    ) -> Result<Self, RegistryIsolationError> {
        if certificate_authorities.len() > MAX_REGISTRY_CA_AUTHORITIES {
            return Err(RegistryIsolationError::Configuration);
        }
        let mut normalized = BTreeMap::new();
        let mut aggregate_bytes = 0_usize;
        for (authority, path) in certificate_authorities {
            let authority = RegistryAuthority::parse(&authority)?;
            let bytes = read_bounded_file(&path, MAX_REGISTRY_CA_BYTES, FileProtection::Public)?;
            validate_pem_ca(&bytes)?;
            aggregate_bytes = aggregate_bytes
                .checked_add(bytes.len())
                .filter(|total| *total <= MAX_REGISTRY_CA_TOTAL_BYTES)
                .ok_or(RegistryIsolationError::Configuration)?;
            if normalized.insert(authority, bytes.to_vec()).is_some() {
                return Err(RegistryIsolationError::Configuration);
            }
        }
        Ok(Self {
            authentication,
            certificate_authorities: normalized,
        })
    }

    /// Project only the selected repository authority into `private_root`.
    pub(crate) fn project(
        &self,
        repository: &str,
        private_root: &Path,
    ) -> Result<RegistryProjection, RegistryIsolationError> {
        let authority = RegistryAuthority::from_repository(repository)?;
        let credential = self
            .authentication
            .as_ref()
            .and_then(|document| document.get(&authority));
        let ca = self
            .certificate_authorities
            .get(&authority)
            .map(Vec::as_slice);
        RegistryProjection::create(private_root, &authority, credential, ca)
    }

    /// Verify exact-repository registry reachability and authentication before
    /// invoking the signer verifier.
    pub(crate) async fn preflight(
        &self,
        repository: &str,
        digest: &str,
        deadline: Instant,
    ) -> Result<(), RegistryIsolationError> {
        // The public-registry constructor deliberately carries no registry
        // configuration. Let Cosign perform its normal challenge flow in that
        // case; a raw manifest request cannot safely reproduce arbitrary
        // registry token exchanges. Any configured auth document or CA bundle
        // opts into the exact-authority preflight below.
        if self.authentication.is_none() && self.certificate_authorities.is_empty() {
            return Ok(());
        }
        let authority = RegistryAuthority::from_repository(repository)?;
        let url = authority.manifest_url(repository, digest)?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(RegistryIsolationError::Unavailable)?;
        let connect_timeout = remaining.min(Duration::from_secs(5));
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(connect_timeout)
            .timeout(remaining);
        if let Some(bundle) = self.certificate_authorities.get(&authority) {
            let certificates = reqwest::Certificate::from_pem_bundle(bundle)
                .map_err(|_| RegistryIsolationError::Configuration)?;
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder
            .build()
            .map_err(|_| RegistryIsolationError::Configuration)?;
        let mut request = client.head(url);
        if let Some(credential) = self
            .authentication
            .as_ref()
            .and_then(|document| document.get(&authority))
        {
            let prefix = match credential.kind {
                CredentialKind::Auth => "Basic ",
                CredentialKind::IdentityToken => "Bearer ",
            };
            let authorization = Zeroizing::new(format!("{prefix}{}", credential.value.as_str()));
            let mut header = reqwest::header::HeaderValue::from_str(&authorization)
                .map_err(|_| RegistryIsolationError::Authentication)?;
            header.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, header);
        }
        let response = request
            .send()
            .await
            .map_err(|_| RegistryIsolationError::Unavailable)?;
        match response.status() {
            status if status.is_success() => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                Err(RegistryIsolationError::Authentication)
            }
            _ => Err(RegistryIsolationError::Unavailable),
        }
    }
}

/// Paths and state for one exact-authority verifier invocation.
#[derive(Debug, Default)]
pub(crate) struct RegistryProjection {
    pub(crate) docker_config: Option<PathBuf>,
    pub(crate) ca_bundle: Option<PathBuf>,
}

impl RegistryProjection {
    fn create(
        private_root: &Path,
        authority: &RegistryAuthority,
        credential: Option<&RegistryCredential>,
        ca: Option<&[u8]>,
    ) -> Result<Self, RegistryIsolationError> {
        let docker_config = credential
            .map(|credential| write_docker_view(private_root, authority, credential))
            .transpose()?;
        let ca_bundle = ca
            .map(|bytes| write_ca_view(private_root, bytes))
            .transpose()?;
        Ok(Self {
            docker_config,
            ca_bundle,
        })
    }
}

#[derive(Serialize)]
struct ProjectedDockerConfig<'a> {
    auths: BTreeMap<&'a str, ProjectedAuthEntry<'a>>,
}

#[derive(Serialize)]
struct ProjectedAuthEntry<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<&'a str>,
    #[serde(rename = "identitytoken", skip_serializing_if = "Option::is_none")]
    identity_token: Option<&'a str>,
}

fn write_docker_view(
    private_root: &Path,
    authority: &RegistryAuthority,
    credential: &RegistryCredential,
) -> Result<PathBuf, RegistryIsolationError> {
    let directory = private_root.join("docker");
    create_private_dir(&directory)?;
    let path = directory.join("config.json");
    let (auth, identity_token) = match credential.kind {
        CredentialKind::Auth => (Some(credential.value.as_str()), None),
        CredentialKind::IdentityToken => (None, Some(credential.value.as_str())),
    };
    let mut auths = BTreeMap::new();
    auths.insert(
        authority.as_str(),
        ProjectedAuthEntry {
            auth,
            identity_token,
        },
    );
    let document = ProjectedDockerConfig { auths };
    let mut file = create_private_file(&path)?;
    serde_json::to_writer(&mut file, &document).map_err(|_| RegistryIsolationError::Unavailable)?;
    file.sync_all()
        .map_err(|_| RegistryIsolationError::Unavailable)?;
    Ok(directory)
}

fn write_ca_view(private_root: &Path, bytes: &[u8]) -> Result<PathBuf, RegistryIsolationError> {
    let path = private_root.join("registry-ca.pem");
    let mut file = create_private_file(&path)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| RegistryIsolationError::Unavailable)?;
    Ok(path)
}

fn validate_pem_ca(bytes: &[u8]) -> Result<(), RegistryIsolationError> {
    let mut remaining = bytes;
    let mut certificate_count = 0_usize;
    loop {
        remaining = remaining.trim_ascii();
        if remaining.is_empty() {
            break;
        }
        if !remaining.starts_with(b"-----BEGIN CERTIFICATE-----") {
            return Err(RegistryIsolationError::Configuration);
        }
        let (rest, pem) = x509_parser::pem::parse_x509_pem(remaining)
            .map_err(|_| RegistryIsolationError::Configuration)?;
        if pem.label != "CERTIFICATE" {
            return Err(RegistryIsolationError::Configuration);
        }
        let (der_rest, certificate) = x509_parser::parse_x509_certificate(&pem.contents)
            .map_err(|_| RegistryIsolationError::Configuration)?;
        if !der_rest.is_empty()
            || !certificate
                .tbs_certificate
                .basic_constraints()
                .map_err(|_| RegistryIsolationError::Configuration)?
                .is_some_and(|constraints| constraints.value.ca)
        {
            return Err(RegistryIsolationError::Configuration);
        }
        certificate_count += 1;
        if certificate_count > MAX_REGISTRY_CA_CERTIFICATES {
            return Err(RegistryIsolationError::Configuration);
        }
        remaining = rest;
    }
    if certificate_count == 0 {
        return Err(RegistryIsolationError::Configuration);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum FileProtection {
    Secret,
    Public,
}

fn read_bounded_file(
    path: &Path,
    limit: u64,
    protection: FileProtection,
) -> Result<Zeroizing<Vec<u8>>, RegistryIsolationError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(RegistryIsolationError::Configuration);
    }
    let mut file = open_absolute_file_no_follow(path).map_err(|_| match protection {
        FileProtection::Secret => RegistryIsolationError::Authentication,
        FileProtection::Public => RegistryIsolationError::Configuration,
    })?;
    validate_open_file(&file, protection)?;
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| match protection {
            FileProtection::Secret => RegistryIsolationError::Authentication,
            FileProtection::Public => RegistryIsolationError::Configuration,
        })?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > limit) {
        return Err(match protection {
            FileProtection::Secret => RegistryIsolationError::Authentication,
            FileProtection::Public => RegistryIsolationError::Configuration,
        });
    }
    Ok(bytes)
}

fn open_absolute_file_no_follow(path: &Path) -> Result<File, rustix::io::Errno> {
    let relative = path
        .strip_prefix(Path::new("/"))
        .map_err(|_| rustix::io::Errno::INVAL)?;
    let mut components = relative.components().peekable();
    let mut directory = rustix::fs::open(
        "/",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    while let Some(component) = components.next() {
        let std::path::Component::Normal(name) = component else {
            return Err(rustix::io::Errno::INVAL);
        };
        if components.peek().is_none() {
            let file = rustix::fs::openat(
                &directory,
                name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )?;
            return Ok(File::from(file));
        }
        directory = rustix::fs::openat(
            &directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )?;
    }
    Err(rustix::io::Errno::INVAL)
}

fn validate_open_file(
    file: &File,
    protection: FileProtection,
) -> Result<(), RegistryIsolationError> {
    let metadata = file
        .metadata()
        .map_err(|_| RegistryIsolationError::Configuration)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    let owner_is_safe = metadata.uid() == 0 || metadata.uid() == effective_uid;
    let mode_is_safe = match protection {
        FileProtection::Secret => metadata.permissions().mode().trailing_zeros() >= 6,
        FileProtection::Public => metadata.permissions().mode() & 0o022 == 0,
    };
    if !metadata.is_file() || metadata.nlink() != 1 || !owner_is_safe || !mode_is_safe {
        return Err(match protection {
            FileProtection::Secret => RegistryIsolationError::Authentication,
            FileProtection::Public => RegistryIsolationError::Configuration,
        });
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<(), RegistryIsolationError> {
    fs::create_dir(path).map_err(|_| RegistryIsolationError::Unavailable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| RegistryIsolationError::Unavailable)
}

fn create_private_file(path: &Path) -> Result<File, RegistryIsolationError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| RegistryIsolationError::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let root = env::temp_dir().join(format!("basil-registry-isolation-{suffix}"));
            fs::create_dir(&root).expect("create fixture");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect fixture");
            Self { root }
        }

        fn protected(&self, name: &str, contents: &str) -> PathBuf {
            let path = self.root.join(name);
            fs::write(&path, contents).expect("write protected file");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("protect file");
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn exact_static_auth_and_identity_tokens_load() {
        let fixture = Fixture::new();
        let path = fixture.protected(
            "auth.json",
            r#"{"auths":{"REGISTRY.EXAMPLE:5443":{"auth":"dXNlcjpwYXNz"},"tokens.example":{"identitytoken":"opaque-token"}}}"#,
        );
        let document = RegistryAuthDocument::load_protected_file(&path).expect("valid document");
        assert!(
            document
                .get(&RegistryAuthority::parse("registry.example:5443").expect("authority"))
                .is_some()
        );
        assert!(
            document
                .get(&RegistryAuthority::parse("tokens.example").expect("authority"))
                .is_some()
        );
        assert!(!format!("{document:?}").contains("opaque-token"));
    }

    #[test]
    fn helpers_plugins_dual_empty_malformed_and_wildcards_are_rejected() {
        let fixture = Fixture::new();
        let invalid = [
            r#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz"}},"credsStore":"helper"}"#,
            r#"{"auths":{"registry.example":{"credHelper":"plugin"}}}"#,
            r#"{"auths":{"registry.example":{"auth":"dXNlcjpwYXNz","identitytoken":"token"}}}"#,
            r#"{"auths":{"registry.example":{"auth":""}}}"#,
            r#"{"auths":{"registry.example":{"auth":"not-base64"}}}"#,
            r#"{"auths":{"registry.example":{"auth":"bm9jb2xvbg=="}}}"#,
            r#"{"auths":{"*.example":{"identitytoken":"token"}}}"#,
            r#"{"auths":{"registry.example":{"registrytoken":"token"}}}"#,
            r#"{"auths":{}}"#,
        ];
        for (index, document) in invalid.iter().enumerate() {
            let path = fixture.protected(&format!("invalid-{index}.json"), document);
            assert!(
                matches!(
                    RegistryAuthDocument::load_protected_file(&path),
                    Err(RegistryIsolationError::Authentication)
                ),
                "case {index}"
            );
        }
    }

    #[test]
    fn duplicate_normalized_authorities_are_rejected() {
        let fixture = Fixture::new();
        let path = fixture.protected(
            "duplicate.json",
            r#"{"auths":{"REGISTRY.EXAMPLE":{"identitytoken":"one"},"registry.example":{"identitytoken":"two"}}}"#,
        );
        assert!(matches!(
            RegistryAuthDocument::load_protected_file(&path),
            Err(RegistryIsolationError::Authentication)
        ));
    }

    #[test]
    fn unsafe_file_shapes_fail_with_redacted_errors() {
        let fixture = Fixture::new();
        let path = fixture.protected(
            "unsafe.json",
            r#"{"auths":{"registry.example":{"identitytoken":"secret-token"}}}"#,
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("change mode");
        let error = RegistryAuthDocument::load_protected_file(&path).expect_err("unsafe mode");
        assert_eq!(error, RegistryIsolationError::Authentication);
        assert!(!format!("{error:?} {error}").contains("secret-token"));

        let link = fixture.root.join("link.json");
        std::os::unix::fs::symlink(&path, &link).expect("create symlink");
        assert!(matches!(
            RegistryAuthDocument::load_protected_file(&link),
            Err(RegistryIsolationError::Authentication)
        ));
    }

    #[test]
    fn projection_contains_only_the_exact_authority() {
        let fixture = Fixture::new();
        let path = fixture.protected(
            "auth.json",
            r#"{"auths":{"one.example":{"identitytoken":"token-one"},"two.example":{"identitytoken":"token-two"}}}"#,
        );
        let auth = RegistryAuthDocument::load_protected_file(&path).expect("load auth");
        let access = RegistryAccess::with_document(Some(auth), BTreeMap::new()).expect("access");
        let view = fixture.root.join("view");
        fs::create_dir(&view).expect("create view");
        fs::set_permissions(&view, fs::Permissions::from_mode(0o700)).expect("protect view");
        let projection = access
            .project("one.example/team/app", &view)
            .expect("project auth");
        let config = fs::read_to_string(
            projection
                .docker_config
                .expect("docker config")
                .join("config.json"),
        )
        .expect("read view");
        assert!(config.contains("token-one"));
        assert!(!config.contains("token-two"));
    }

    #[test]
    fn public_and_cross_registry_requests_receive_no_credential() {
        let fixture = Fixture::new();
        let path = fixture.protected(
            "auth.json",
            r#"{"auths":{"private.example":{"identitytoken":"private-token"}}}"#,
        );
        let auth = RegistryAuthDocument::load_protected_file(&path).expect("load auth");
        let access = RegistryAccess::with_document(Some(auth), BTreeMap::new()).expect("access");
        for repository in [
            "public.example/team/app",
            "other.example/team/app",
            "library/alpine",
        ] {
            let view = fixture
                .root
                .join(format!("view-{}", repository.replace('/', "-")));
            fs::create_dir(&view).expect("create view");
            let projection = access.project(repository, &view).expect("project");
            assert!(projection.docker_config.is_none());
        }
    }

    #[test]
    fn restart_reload_is_required_for_rotation() {
        let fixture = Fixture::new();
        let path = fixture.protected(
            "auth.json",
            r#"{"auths":{"private.example":{"identitytoken":"old-token"}}}"#,
        );
        let old = RegistryAuthDocument::load_protected_file(&path).expect("old snapshot");
        fs::write(
            &path,
            r#"{"auths":{"private.example":{"identitytoken":"new-token"}}}"#,
        )
        .expect("rotate source");
        let new = RegistryAuthDocument::load_protected_file(&path).expect("new snapshot");
        assert_eq!(
            old.get(&RegistryAuthority::parse("private.example").expect("authority"))
                .expect("old credential")
                .value
                .as_str(),
            "old-token"
        );
        assert_eq!(
            new.get(&RegistryAuthority::parse("private.example").expect("authority"))
                .expect("new credential")
                .value
                .as_str(),
            "new-token"
        );
    }

    #[test]
    fn exact_authority_ca_is_copied_into_private_view() {
        let fixture = Fixture::new();
        let ca = fixture.protected("ca.pem", include_str!("../../testdata/jwks_tls_cert.pem"));
        let access = RegistryAccess::with_document(
            None,
            BTreeMap::from([("registry.example:5443".to_string(), ca)]),
        )
        .expect("access");
        let view = fixture.root.join("ca-view");
        fs::create_dir(&view).expect("create view");
        let projection = access
            .project("registry.example:5443/team/app", &view)
            .expect("project ca");
        let copied = projection.ca_bundle.expect("ca bundle");
        assert_eq!(copied.parent(), Some(view.as_path()));
        assert!(copied.exists());
    }

    #[test]
    fn fake_non_x509_and_non_ca_pem_are_rejected() {
        let fixture = Fixture::new();
        let fake = fixture.protected(
            "fake.pem",
            "-----BEGIN CERTIFICATE-----\nY2E=\n-----END CERTIFICATE-----\n",
        );
        assert!(matches!(
            RegistryAccess::with_document(
                None,
                BTreeMap::from([("registry.example".to_string(), fake)])
            ),
            Err(RegistryIsolationError::Configuration)
        ));
    }

    #[test]
    fn wrong_authority_receives_no_ca_projection() {
        let fixture = Fixture::new();
        let ca = fixture.protected("ca.pem", include_str!("../../testdata/jwks_tls_cert.pem"));
        let access = RegistryAccess::with_document(
            None,
            BTreeMap::from([("registry.example".to_string(), ca)]),
        )
        .expect("valid CA mapping");
        let view = fixture.root.join("wrong-ca-view");
        fs::create_dir(&view).expect("create view");
        let projection = access
            .project("other.example/team/app", &view)
            .expect("project other authority");
        assert!(projection.ca_bundle.is_none());
    }

    #[test]
    fn symlinked_parent_component_is_rejected() {
        let fixture = Fixture::new();
        let real = fixture.root.join("real");
        fs::create_dir(&real).expect("create real parent");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("protect parent");
        let auth = real.join("auth.json");
        fs::write(
            &auth,
            r#"{"auths":{"registry.example":{"identitytoken":"secret-token"}}}"#,
        )
        .expect("write auth");
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600)).expect("protect auth");
        let linked = fixture.root.join("linked");
        std::os::unix::fs::symlink(&real, &linked).expect("link parent");
        assert!(matches!(
            RegistryAuthDocument::load_protected_file(&linked.join("auth.json")),
            Err(RegistryIsolationError::Authentication)
        ));
    }

    #[test]
    fn authentication_document_size_and_authority_count_are_bounded() {
        let fixture = Fixture::new();
        let oversized = fixture.root.join("oversized-auth.json");
        fs::write(
            &oversized,
            vec![b' '; usize::try_from(MAX_REGISTRY_AUTH_BYTES + 1).expect("bound fits")],
        )
        .expect("write oversized auth");
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))
            .expect("protect oversized auth");
        assert!(matches!(
            RegistryAuthDocument::load_protected_file(&oversized),
            Err(RegistryIsolationError::Authentication)
        ));

        let mut entries = Vec::new();
        for index in 0..=MAX_REGISTRY_AUTHORITIES {
            entries.push(format!(
                "\"registry-{index}.example\":{{\"identitytoken\":\"token\"}}"
            ));
        }
        let document = format!("{{\"auths\":{{{}}}}}", entries.join(","));
        let too_many = fixture.protected("too-many-auth.json", &document);
        assert!(matches!(
            RegistryAuthDocument::load_protected_file(&too_many),
            Err(RegistryIsolationError::Authentication)
        ));
    }

    #[test]
    fn ca_authority_individual_and_aggregate_bounds_are_enforced() {
        let fixture = Fixture::new();
        let ca = fixture.protected("ca.pem", include_str!("../../testdata/jwks_tls_cert.pem"));
        let too_many = (0..=MAX_REGISTRY_CA_AUTHORITIES)
            .map(|index| (format!("ca-{index}.example"), ca.clone()))
            .collect();
        assert!(matches!(
            RegistryAccess::with_document(None, too_many),
            Err(RegistryIsolationError::Configuration)
        ));

        let oversized_ca = fixture.root.join("oversized-ca.pem");
        fs::write(
            &oversized_ca,
            vec![b' '; usize::try_from(MAX_REGISTRY_CA_BYTES + 1).expect("bound fits")],
        )
        .expect("write oversized CA");
        fs::set_permissions(&oversized_ca, fs::Permissions::from_mode(0o600))
            .expect("protect oversized CA");
        assert!(matches!(
            RegistryAccess::with_document(
                None,
                BTreeMap::from([("registry.example".to_string(), oversized_ca)])
            ),
            Err(RegistryIsolationError::Configuration)
        ));

        let mut padded = include_bytes!("../../testdata/jwks_tls_cert.pem").to_vec();
        padded.resize(900_000, b' ');
        let padded_ca = fixture.root.join("padded-ca.pem");
        fs::write(&padded_ca, padded).expect("write padded CA");
        fs::set_permissions(&padded_ca, fs::Permissions::from_mode(0o600))
            .expect("protect padded CA");
        let aggregate = (0..5)
            .map(|index| (format!("aggregate-{index}.example"), padded_ca.clone()))
            .collect();
        assert!(matches!(
            RegistryAccess::with_document(None, aggregate),
            Err(RegistryIsolationError::Configuration)
        ));
    }
}
