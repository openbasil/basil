// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Hermetic contract tests for the CI qualification evidence inventory.
//!
//! The checked-in records are deliberately synthetic. Passing this verifier
//! establishes bounded parsing, byte integrity, and cross-record consistency;
//! it is not evidence that an external provider ran a Basil workflow.

#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::HashSet;
use std::fs::{self, File, Metadata};
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, symlink};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

const MANIFEST_NAME: &str = "manifest.json";
const CLIENT_NAME: &str = "client.json";
const AUDIT_NAME: &str = "broker-audit.json";
const MAX_MANIFEST_BYTES: usize = 8 * 1024;
const MAX_RECORD_BYTES: usize = 8 * 1024;
const MAX_RECORD_BYTES_U64: u64 = 8 * 1024;
const MAX_RECORDS: usize = 2;
const MAX_PATH_BYTES: usize = 64;
const MAX_TARGET_BYTES: usize = 128;
const INVOCATION_ID_BYTES: usize = 43;
const MANIFEST_SCHEMA: &str = "basil.ci.qualification-evidence";
const CLIENT_SCHEMA: &str = "basil.ci.qualification.client";
const AUDIT_SCHEMA: &str = "basil.ci.qualification.broker-audit";
const SUPPORTED_VERSION: u64 = 1;
static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum QualificationStatus {
    NotQualified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum RecordRole {
    Client,
    BrokerAudit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum Provider {
    #[serde(rename = "github")]
    Github,
    #[serde(rename = "forgejoActions")]
    ForgejoActions,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum Profile {
    ArtifactSign,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum EvidenceResult {
    Success,
    Denied,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceManifest {
    schema: String,
    version: u64,
    fixture_only: bool,
    qualification_status: QualificationStatus,
    provider: Provider,
    profile: Profile,
    target_key: String,
    invocation_id: String,
    result: EvidenceResult,
    records: Vec<RecordReference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordReference {
    role: RecordRole,
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRecord {
    schema: String,
    version: u64,
    fixture_only: bool,
    provider: Provider,
    profile: Profile,
    target_key: String,
    invocation_id: String,
    result: EvidenceResult,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedEvidence {
    fixture_only: bool,
    qualification_status: QualificationStatus,
    provider: Provider,
    profile: Profile,
    target_key: String,
    invocation_id: String,
    result: EvidenceResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifyError {
    Io,
    NotRegularFile,
    MultipleLinks,
    FileIdentityChanged,
    ManifestTooLarge,
    RecordTooLarge,
    UnsafeEncoding,
    ManifestSyntax,
    RecordSyntax,
    UnsupportedVersion,
    UnsupportedSchema,
    NotFixture,
    UnsafePath,
    InvalidDigest,
    DuplicateRecord,
    MissingRecord,
    UnexpectedRecord,
    SizeMismatch,
    DigestMismatch,
    InvalidField,
    CorrelationMismatch,
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/ci-qualification-evidence/v1")
}

#[derive(Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    links: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn metadata_identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn read_pinned_file(
    path: &Path,
    limit: usize,
    too_large: VerifyError,
) -> Result<Vec<u8>, VerifyError> {
    let before = fs::symlink_metadata(path).map_err(|_| VerifyError::Io)?;
    if !before.file_type().is_file() {
        return Err(VerifyError::NotRegularFile);
    }
    if before.nlink() != 1 {
        return Err(VerifyError::MultipleLinks);
    }

    let mut file = File::open(path).map_err(|_| VerifyError::Io)?;
    let opened = file.metadata().map_err(|_| VerifyError::Io)?;
    let after_open = fs::symlink_metadata(path).map_err(|_| VerifyError::Io)?;
    if opened.nlink() != 1 || after_open.nlink() != 1 {
        return Err(VerifyError::MultipleLinks);
    }
    if metadata_identity(&before) != metadata_identity(&opened)
        || metadata_identity(&opened) != metadata_identity(&after_open)
    {
        return Err(VerifyError::FileIdentityChanged);
    }
    if opened.len() > u64::try_from(limit).map_err(|_| too_large)? {
        return Err(too_large);
    }

    let initial_capacity = usize::try_from(opened.len()).unwrap_or(limit).min(limit);
    let mut bytes = Vec::with_capacity(initial_capacity);
    {
        let mut limited = (&mut file).take(u64::try_from(limit).map_err(|_| too_large)? + 1);
        limited
            .read_to_end(&mut bytes)
            .map_err(|_| VerifyError::Io)?;
    }
    if bytes.len() > limit {
        return Err(too_large);
    }

    let after_read = file.metadata().map_err(|_| VerifyError::Io)?;
    let final_path = fs::symlink_metadata(path).map_err(|_| VerifyError::Io)?;
    if after_read.nlink() != 1 || final_path.nlink() != 1 {
        return Err(VerifyError::MultipleLinks);
    }
    if metadata_identity(&opened) != metadata_identity(&after_read)
        || metadata_identity(&after_read) != metadata_identity(&final_path)
    {
        return Err(VerifyError::FileIdentityChanged);
    }
    Ok(bytes)
}

fn validate_text(bytes: &[u8]) -> Result<&str, VerifyError> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf])
        || !bytes.ends_with(b"\n")
        || bytes.iter().any(|byte| *byte < 0x20 && *byte != b'\n')
    {
        return Err(VerifyError::UnsafeEncoding);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| VerifyError::UnsafeEncoding)?;
    if text.chars().any(is_unsafe_scalar) {
        return Err(VerifyError::UnsafeEncoding);
    }
    Ok(text)
}

fn is_unsafe_scalar(character: char) -> bool {
    (character.is_control() && character != '\n')
        || matches!(
            character,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

fn validate_filename(raw: &str) -> Result<(), VerifyError> {
    let bytes = raw.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-'))
    {
        return Err(VerifyError::UnsafePath);
    }
    let mut components = Path::new(raw).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(VerifyError::UnsafePath);
    }
    Ok(())
}

fn validate_digest(raw: &str) -> Result<(), VerifyError> {
    if raw.len() != 64
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(VerifyError::InvalidDigest);
    }
    Ok(())
}

fn validate_target(raw: &str) -> Result<(), VerifyError> {
    if raw.is_empty()
        || raw.len() > MAX_TARGET_BYTES
        || !raw.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/' | b'@')
        })
    {
        return Err(VerifyError::InvalidField);
    }
    Ok(())
}

fn validate_invocation_id(raw: &str) -> Result<(), VerifyError> {
    if raw.len() != INVOCATION_ID_BYTES
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(VerifyError::InvalidField);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| VerifyError::InvalidField)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != raw {
        return Err(VerifyError::InvalidField);
    }
    Ok(())
}

fn validate_record(
    record: &EvidenceRecord,
    role: RecordRole,
    manifest: &EvidenceManifest,
) -> Result<(), VerifyError> {
    let expected_schema = match role {
        RecordRole::Client => CLIENT_SCHEMA,
        RecordRole::BrokerAudit => AUDIT_SCHEMA,
    };
    if record.version != SUPPORTED_VERSION {
        return Err(VerifyError::UnsupportedVersion);
    }
    if record.schema != expected_schema {
        return Err(VerifyError::UnsupportedSchema);
    }
    if !record.fixture_only {
        return Err(VerifyError::NotFixture);
    }
    validate_target(&record.target_key)?;
    validate_invocation_id(&record.invocation_id)?;
    if record.provider != manifest.provider
        || record.profile != manifest.profile
        || record.target_key != manifest.target_key
        || record.invocation_id != manifest.invocation_id
        || record.result != manifest.result
    {
        return Err(VerifyError::CorrelationMismatch);
    }
    Ok(())
}

fn verify_fixture(root: &Path) -> Result<VerifiedEvidence, VerifyError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| VerifyError::Io)?;
    if !root_metadata.file_type().is_dir() {
        return Err(VerifyError::NotRegularFile);
    }
    let manifest_bytes = read_pinned_file(
        &root.join(MANIFEST_NAME),
        MAX_MANIFEST_BYTES,
        VerifyError::ManifestTooLarge,
    )?;
    let manifest_text = validate_text(&manifest_bytes)?;
    let manifest: EvidenceManifest =
        serde_json::from_str(manifest_text).map_err(|_| VerifyError::ManifestSyntax)?;

    if manifest.version != SUPPORTED_VERSION {
        return Err(VerifyError::UnsupportedVersion);
    }
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(VerifyError::UnsupportedSchema);
    }
    if !manifest.fixture_only || manifest.qualification_status != QualificationStatus::NotQualified
    {
        return Err(VerifyError::NotFixture);
    }
    validate_target(&manifest.target_key)?;
    validate_invocation_id(&manifest.invocation_id)?;
    if manifest.records.len() < MAX_RECORDS {
        return Err(VerifyError::MissingRecord);
    }
    if manifest.records.len() > MAX_RECORDS {
        return Err(VerifyError::UnexpectedRecord);
    }

    let mut roles = HashSet::with_capacity(MAX_RECORDS);
    let mut paths = HashSet::with_capacity(MAX_RECORDS);
    let mut client = None;
    let mut audit = None;
    for reference in &manifest.records {
        if !roles.insert(reference.role) || !paths.insert(reference.path.as_str()) {
            return Err(VerifyError::DuplicateRecord);
        }
        validate_filename(&reference.path)?;
        validate_digest(&reference.sha256)?;
        if reference.size > MAX_RECORD_BYTES_U64 {
            return Err(VerifyError::RecordTooLarge);
        }

        let bytes = read_pinned_file(
            &root.join(&reference.path),
            MAX_RECORD_BYTES,
            VerifyError::RecordTooLarge,
        )?;
        let byte_len = u64::try_from(bytes.len()).map_err(|_| VerifyError::RecordTooLarge)?;
        if reference.size != byte_len {
            return Err(VerifyError::SizeMismatch);
        }
        if reference.sha256 != hex::encode(Sha256::digest(&bytes)) {
            return Err(VerifyError::DigestMismatch);
        }
        let text = validate_text(&bytes)?;
        let record: EvidenceRecord =
            serde_json::from_str(text).map_err(|_| VerifyError::RecordSyntax)?;
        validate_record(&record, reference.role, &manifest)?;
        match reference.role {
            RecordRole::Client => client = Some(record),
            RecordRole::BrokerAudit => audit = Some(record),
        }
    }
    if client.is_none() || audit.is_none() {
        return Err(VerifyError::MissingRecord);
    }

    Ok(VerifiedEvidence {
        fixture_only: manifest.fixture_only,
        qualification_status: manifest.qualification_status,
        provider: manifest.provider,
        profile: manifest.profile,
        target_key: manifest.target_key,
        invocation_id: manifest.invocation_id,
        result: manifest.result,
    })
}

struct TestTree {
    base: PathBuf,
    root: PathBuf,
}

impl TestTree {
    fn copy_fixture() -> Self {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "basil-ci-evidence-fixture-{}-{now}-{sequence}",
            std::process::id()
        ));
        let root = base.join("bundle");
        fs::create_dir_all(&root).expect("create isolated fixture directory");
        for name in [MANIFEST_NAME, CLIENT_NAME, AUDIT_NAME] {
            fs::copy(fixture_root().join(name), root.join(name)).expect("copy checked-in fixture");
        }
        Self { base, root }
    }

    fn rewrite_manifest(&self, mutate: impl FnOnce(&mut Value)) {
        let path = self.root.join(MANIFEST_NAME);
        let mut value: Value = serde_json::from_slice(&fs::read(&path).expect("read manifest"))
            .expect("parse manifest for mutation");
        mutate(&mut value);
        write_json(&path, &value);
    }

    fn rewrite_record(&self, name: &str, mutate: impl FnOnce(&mut Value)) {
        let path = self.root.join(name);
        let mut value: Value = serde_json::from_slice(&fs::read(&path).expect("read record"))
            .expect("parse record for mutation");
        mutate(&mut value);
        write_json(&path, &value);
        self.rebind_record(name);
    }

    fn rebind_record(&self, name: &str) {
        let bytes = fs::read(self.root.join(name)).expect("read record bytes");
        self.rewrite_manifest(|manifest| {
            let records = manifest["records"]
                .as_array_mut()
                .expect("manifest records are an array");
            let reference = records
                .iter_mut()
                .find(|record| record["path"].as_str() == Some(name))
                .expect("record reference exists");
            reference["size"] = json!(bytes.len());
            reference["sha256"] = json!(hex::encode(Sha256::digest(&bytes)));
        });
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn write_json(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize mutation");
    bytes.push(b'\n');
    fs::write(path, bytes).expect("write fixture mutation");
}

#[test]
fn checked_in_v1_fixture_verifies_from_local_bytes_only() {
    let verified = verify_fixture(&fixture_root()).expect("checked-in fixture verifies");
    assert_eq!(
        verified,
        VerifiedEvidence {
            fixture_only: true,
            qualification_status: QualificationStatus::NotQualified,
            provider: Provider::Github,
            profile: Profile::ArtifactSign,
            target_key: "ci.qualification.artifact-sign".to_string(),
            invocation_id: "wDCICmc4kiZM703GRgSLywl8oAtFK40VjZQWlJUsHNY".to_string(),
            result: EvidenceResult::Success,
        }
    );
}

#[test]
fn provider_kind_uses_exact_action_and_config_spelling() {
    let forgejo = TestTree::copy_fixture();
    forgejo.rewrite_record(CLIENT_NAME, |record| {
        record["provider"] = json!("forgejoActions");
    });
    forgejo.rewrite_record(AUDIT_NAME, |record| {
        record["provider"] = json!("forgejoActions");
    });
    forgejo.rewrite_manifest(|manifest| {
        manifest["provider"] = json!("forgejoActions");
    });
    let verified = verify_fixture(&forgejo.root).expect("exact Forgejo Actions kind verifies");
    assert_eq!(verified.provider, Provider::ForgejoActions);

    let generic = TestTree::copy_fixture();
    generic.rewrite_manifest(|manifest| {
        manifest["provider"] = json!("forgejo");
    });
    assert_eq!(
        verify_fixture(&generic.root),
        Err(VerifyError::ManifestSyntax)
    );
}

#[test]
fn invocation_id_requires_canonical_unpadded_sha3_256_shape() {
    for invalid in [
        "00000000-0000-4000-8000-000000000001",
        "wDCICmc4kiZM703GRgSLywl8oAtFK40VjZQWlJUsHNY=",
        "wDCICmc4kiZM703GRgSLywl8oAtFK40VjZQWlJUsHNZ",
    ] {
        let tree = TestTree::copy_fixture();
        tree.rewrite_manifest(|manifest| {
            manifest["invocation_id"] = json!(invalid);
        });
        assert_eq!(
            verify_fixture(&tree.root),
            Err(VerifyError::InvalidField),
            "invalid invocation ID {invalid:?}"
        );
    }
}

#[test]
fn manifest_rejects_unknown_duplicate_and_missing_records() {
    let unknown = TestTree::copy_fixture();
    unknown.rewrite_manifest(|manifest| {
        manifest["records"]
            .as_array_mut()
            .expect("records")
            .push(json!({
                "role": "driver-log",
                "path": "driver.json",
                "size": 1,
                "sha256": "00".repeat(32),
            }));
    });
    assert_eq!(
        verify_fixture(&unknown.root),
        Err(VerifyError::ManifestSyntax)
    );

    let duplicate = TestTree::copy_fixture();
    duplicate.rewrite_manifest(|manifest| {
        let records = manifest["records"].as_array_mut().expect("records");
        records[1]["role"] = json!("client");
    });
    assert_eq!(
        verify_fixture(&duplicate.root),
        Err(VerifyError::DuplicateRecord)
    );

    let duplicate_path = TestTree::copy_fixture();
    duplicate_path.rewrite_manifest(|manifest| {
        let records = manifest["records"].as_array_mut().expect("records");
        records[1]["path"] = json!(CLIENT_NAME);
    });
    assert_eq!(
        verify_fixture(&duplicate_path.root),
        Err(VerifyError::DuplicateRecord)
    );

    let missing = TestTree::copy_fixture();
    missing.rewrite_manifest(|manifest| {
        manifest["records"].as_array_mut().expect("records").pop();
    });
    assert_eq!(
        verify_fixture(&missing.root),
        Err(VerifyError::MissingRecord)
    );
}

#[test]
fn closed_json_schemas_reject_unknown_missing_and_duplicate_fields() {
    let unknown_manifest_field = TestTree::copy_fixture();
    unknown_manifest_field.rewrite_manifest(|manifest| {
        manifest["credential"] = json!("must-not-be-admitted");
    });
    assert_eq!(
        verify_fixture(&unknown_manifest_field.root),
        Err(VerifyError::ManifestSyntax)
    );

    let duplicate_manifest_field = TestTree::copy_fixture();
    let manifest_path = duplicate_manifest_field.root.join(MANIFEST_NAME);
    let raw = fs::read_to_string(&manifest_path).expect("read manifest");
    let duplicate = raw.replacen("\"version\": 1,", "\"version\": 1,\n  \"version\": 1,", 1);
    assert_ne!(duplicate, raw, "duplicate-key mutation applied");
    fs::write(manifest_path, duplicate).expect("write duplicate-key manifest");
    assert_eq!(
        verify_fixture(&duplicate_manifest_field.root),
        Err(VerifyError::ManifestSyntax)
    );

    let unknown_record_field = TestTree::copy_fixture();
    unknown_record_field.rewrite_record(CLIENT_NAME, |record| {
        record["token"] = json!("must-not-be-admitted");
    });
    assert_eq!(
        verify_fixture(&unknown_record_field.root),
        Err(VerifyError::RecordSyntax)
    );

    let missing_record_field = TestTree::copy_fixture();
    missing_record_field.rewrite_record(CLIENT_NAME, |record| {
        record
            .as_object_mut()
            .expect("record object")
            .remove("result");
    });
    assert_eq!(
        verify_fixture(&missing_record_field.root),
        Err(VerifyError::RecordSyntax)
    );
}

#[test]
fn paths_reject_traversal_absolute_nested_and_backslash_forms() {
    for unsafe_path in [
        "../client.json",
        "/tmp/client.json",
        "sub/client.json",
        r"sub\client.json",
        ".",
    ] {
        let tree = TestTree::copy_fixture();
        tree.rewrite_manifest(|manifest| {
            manifest["records"][0]["path"] = json!(unsafe_path);
        });
        assert_eq!(
            verify_fixture(&tree.root),
            Err(VerifyError::UnsafePath),
            "unsafe path {unsafe_path:?}"
        );
    }
}

#[test]
fn symlink_escape_is_rejected_before_record_read() {
    let tree = TestTree::copy_fixture();
    let outside = tree.base.join("outside.json");
    fs::copy(tree.root.join(CLIENT_NAME), &outside).expect("copy outside record");
    fs::remove_file(tree.root.join(CLIENT_NAME)).expect("remove regular client record");
    symlink("../outside.json", tree.root.join(CLIENT_NAME)).expect("create escape symlink");
    assert_eq!(verify_fixture(&tree.root), Err(VerifyError::NotRegularFile));
}

#[test]
fn multiply_linked_record_is_rejected_before_record_read() {
    let tree = TestTree::copy_fixture();
    fs::hard_link(
        tree.root.join(CLIENT_NAME),
        tree.base.join("client-hard-link.json"),
    )
    .expect("create external hard link");
    assert_eq!(verify_fixture(&tree.root), Err(VerifyError::MultipleLinks));
}

#[test]
fn exact_size_and_digest_bind_each_record() {
    let wrong_size = TestTree::copy_fixture();
    wrong_size.rewrite_manifest(|manifest| {
        let size = manifest["records"][0]["size"].as_u64().expect("size");
        manifest["records"][0]["size"] = json!(size + 1);
    });
    assert_eq!(
        verify_fixture(&wrong_size.root),
        Err(VerifyError::SizeMismatch)
    );

    let wrong_digest = TestTree::copy_fixture();
    let client_path = wrong_digest.root.join(CLIENT_NAME);
    let bytes = fs::read_to_string(&client_path)
        .expect("read client")
        .replace("github", "gitlab");
    fs::write(client_path, bytes).expect("write same-length mutation");
    assert_eq!(
        verify_fixture(&wrong_digest.root),
        Err(VerifyError::DigestMismatch)
    );
}

#[test]
fn unsupported_manifest_and_record_versions_are_rejected() {
    let manifest = TestTree::copy_fixture();
    manifest.rewrite_manifest(|value| value["version"] = json!(2));
    assert_eq!(
        verify_fixture(&manifest.root),
        Err(VerifyError::UnsupportedVersion)
    );

    let record = TestTree::copy_fixture();
    record.rewrite_record(CLIENT_NAME, |value| value["version"] = json!(2));
    assert_eq!(
        verify_fixture(&record.root),
        Err(VerifyError::UnsupportedVersion)
    );
}

#[test]
fn unsafe_text_encodings_are_rejected() {
    let manifest_bom = TestTree::copy_fixture();
    let path = manifest_bom.root.join(MANIFEST_NAME);
    let mut bytes = vec![0xef, 0xbb, 0xbf];
    bytes.extend(fs::read(&path).expect("read manifest"));
    fs::write(path, bytes).expect("write BOM manifest");
    assert_eq!(
        verify_fixture(&manifest_bom.root),
        Err(VerifyError::UnsafeEncoding)
    );

    let invalid_utf8 = TestTree::copy_fixture();
    fs::write(invalid_utf8.root.join(CLIENT_NAME), [0xff, b'\n'])
        .expect("write invalid UTF-8 record");
    invalid_utf8.rebind_record(CLIENT_NAME);
    assert_eq!(
        verify_fixture(&invalid_utf8.root),
        Err(VerifyError::UnsafeEncoding)
    );

    let unsafe_scalar = TestTree::copy_fixture();
    unsafe_scalar.rewrite_record(CLIENT_NAME, |record| {
        record["target_key"] = json!("ci.qualification.\u{202e}artifact");
    });
    assert_eq!(
        verify_fixture(&unsafe_scalar.root),
        Err(VerifyError::UnsafeEncoding)
    );
}

#[test]
fn byte_bounds_are_enforced_before_unbounded_parsing() {
    let manifest = TestTree::copy_fixture();
    fs::write(
        manifest.root.join(MANIFEST_NAME),
        vec![b' '; MAX_MANIFEST_BYTES + 1],
    )
    .expect("write oversized manifest");
    assert_eq!(
        verify_fixture(&manifest.root),
        Err(VerifyError::ManifestTooLarge)
    );

    let record = TestTree::copy_fixture();
    record.rewrite_manifest(|value| {
        value["records"][0]["size"] = json!(MAX_RECORD_BYTES + 1);
    });
    assert_eq!(
        verify_fixture(&record.root),
        Err(VerifyError::RecordTooLarge)
    );
}

#[test]
fn cross_record_redirection_is_rejected_after_valid_hash_binding() {
    let tree = TestTree::copy_fixture();
    tree.rewrite_record(AUDIT_NAME, |record| {
        record["invocation_id"] = json!("xDCICmc4kiZM703GRgSLywl8oAtFK40VjZQWlJUsHNY");
    });
    assert_eq!(
        verify_fixture(&tree.root),
        Err(VerifyError::CorrelationMismatch)
    );
}
