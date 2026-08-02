// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Strict canonical Nix `PATH_INFO_V1` fingerprint validation.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use thiserror::Error;

/// Maximum accepted fingerprint size, matching the dedicated protobuf codec.
pub const MAX_PATH_INFO_V1_LEN: usize = 524_626;
/// Maximum number of store-path references in one fingerprint.
pub const MAX_REFERENCES: usize = 2_048;

const NIX32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
const STORE_PREFIX: &str = "/nix/store/";

/// A byte-for-byte canonical Nix `PATH_INFO_V1` fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathInfoV1 {
    bytes: Vec<u8>,
}

impl PathInfoV1 {
    /// Parse and canonical-round-trip validate one fingerprint.
    pub fn parse(input: &[u8]) -> Result<Self, PathInfoV1Error> {
        if input.is_empty() || input.len() > MAX_PATH_INFO_V1_LEN {
            return Err(PathInfoV1Error::Length);
        }
        let text = std::str::from_utf8(input).map_err(|_| PathInfoV1Error::Utf8)?;
        if text.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(PathInfoV1Error::ControlCharacter);
        }

        let mut fields = text.split(';');
        let version = fields.next().ok_or(PathInfoV1Error::FieldCount)?;
        let path = fields.next().ok_or(PathInfoV1Error::FieldCount)?;
        let nar_hash = fields.next().ok_or(PathInfoV1Error::FieldCount)?;
        let nar_size = fields.next().ok_or(PathInfoV1Error::FieldCount)?;
        let references = fields.next().ok_or(PathInfoV1Error::FieldCount)?;
        if fields.next().is_some() {
            return Err(PathInfoV1Error::FieldCount);
        }
        if version != "1" {
            return Err(PathInfoV1Error::Version);
        }
        validate_store_path(path)?;
        validate_nar_hash(nar_hash)?;
        validate_nar_size(nar_size)?;

        let mut previous = None;
        let mut reference_count = 0usize;
        if !references.is_empty() {
            for reference in references.split(',') {
                reference_count = reference_count.saturating_add(1);
                if reference_count > MAX_REFERENCES {
                    return Err(PathInfoV1Error::ReferenceCount);
                }
                validate_store_path(reference)?;
                if previous.is_some_and(|prior| prior >= reference) {
                    return Err(PathInfoV1Error::ReferenceOrder);
                }
                previous = Some(reference);
            }
        }

        // Re-render every parsed field. Equality rejects alternate spellings,
        // omitted or additional separators, and noncanonical decimal values.
        let rendered = format!("1;{path};{nar_hash};{nar_size};{references}");
        if rendered.as_bytes() != input {
            return Err(PathInfoV1Error::NonCanonical);
        }
        Ok(Self {
            bytes: input.to_vec(),
        })
    }

    /// Return the exact canonical bytes that must be signed.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the lowercase hexadecimal SHA-256 digest used by audit records.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        let digest = Sha256::digest(&self.bytes);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }
}

fn validate_nar_hash(value: &str) -> Result<(), PathInfoV1Error> {
    let Some(encoded) = value.strip_prefix("sha256:") else {
        return Err(PathInfoV1Error::NarHash);
    };
    if encoded.len() != 52 || !encoded.chars().all(|character| NIX32.contains(character)) {
        return Err(PathInfoV1Error::NarHash);
    }
    Ok(())
}

fn validate_nar_size(value: &str) -> Result<(), PathInfoV1Error> {
    if value.is_empty()
        || value == "0"
        || (value.starts_with('0') && value.len() > 1)
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.parse::<u64>().is_err()
    {
        return Err(PathInfoV1Error::NarSize);
    }
    Ok(())
}

fn validate_store_path(value: &str) -> Result<(), PathInfoV1Error> {
    let Some(base_name) = value.strip_prefix(STORE_PREFIX) else {
        return Err(PathInfoV1Error::StorePath);
    };
    let Some((hash, name)) = base_name.split_once('-') else {
        return Err(PathInfoV1Error::StorePath);
    };
    if hash.len() != 32
        || !hash.chars().all(|character| NIX32.contains(character))
        || name.is_empty()
        || name.len() > 211
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || !name.bytes().all(is_store_name_byte)
    {
        return Err(PathInfoV1Error::StorePath);
    }
    Ok(())
}

const fn is_store_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
}

/// Why a Nix `PATH_INFO_V1` fingerprint was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PathInfoV1Error {
    /// The fingerprint was empty or exceeded the protocol bound.
    #[error("fingerprint length is outside the accepted bound")]
    Length,
    /// The fingerprint is not UTF-8.
    #[error("fingerprint is not UTF-8")]
    Utf8,
    /// The fingerprint contains a control character.
    #[error("fingerprint contains a control character")]
    ControlCharacter,
    /// The fingerprint does not contain exactly five fields.
    #[error("fingerprint must contain exactly five fields")]
    FieldCount,
    /// The fingerprint version is not exactly one.
    #[error("fingerprint version must be exactly `1`")]
    Version,
    /// A store path is not canonical.
    #[error("fingerprint contains a noncanonical store path")]
    StorePath,
    /// The NAR hash is not canonical Nix-base32 SHA-256.
    #[error("fingerprint contains a noncanonical NAR hash")]
    NarHash,
    /// The NAR size is not a canonical positive decimal integer.
    #[error("fingerprint contains a noncanonical NAR size")]
    NarSize,
    /// References are not strictly sorted and unique.
    #[error("fingerprint references are not strictly sorted and unique")]
    ReferenceOrder,
    /// The fingerprint has more than the normative reference bound.
    #[error("fingerprint contains too many references")]
    ReferenceCount,
    /// Re-rendering the parsed fingerprint did not reproduce the input.
    #[error("fingerprint is not canonical")]
    NonCanonical,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-package-1.0";
    const REF: &str = "/nix/store/1123456789abcdfghijklmnpqrsvwxyz-dependency";
    const HASH: &str = "sha256:0123456789abcdfghijklmnpqrsvwxyz0123456789abcdfghijk";

    fn valid(references: &str) -> Vec<u8> {
        format!("1;{PATH};{HASH};42;{references}").into_bytes()
    }

    #[test]
    fn accepts_and_round_trips_canonical_fingerprint() {
        let input = valid(REF);
        let parsed = PathInfoV1::parse(&input).expect("canonical fingerprint");
        assert_eq!(parsed.as_bytes(), input);
        assert_eq!(parsed.sha256_hex().len(), 64);
        assert!(
            parsed
                .sha256_hex()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn rejects_noncanonical_structure_and_values() {
        let cases = [
            format!("2;{PATH};{HASH};42;"),
            format!("1;relative;{HASH};42;"),
            format!("1;{PATH};sha256:abc;42;"),
            format!("1;{PATH};{HASH};042;"),
            format!("1;{PATH};{HASH};0;"),
            format!("1;{PATH};{HASH};42;{REF},{REF}"),
            format!("1;{PATH};{HASH};42;{REF}\n"),
            format!("1;{PATH};{HASH};42;;"),
        ];
        for input in cases {
            assert!(
                PathInfoV1::parse(input.as_bytes()).is_err(),
                "accepted {input:?}"
            );
        }
    }

    #[test]
    fn enforces_reference_and_exact_byte_bounds() {
        let short_references = (0..=MAX_REFERENCES)
            .map(|index| format!("/nix/store/{index:032}-r"))
            .collect::<Vec<_>>();
        let accepted = valid(&short_references[..MAX_REFERENCES].join(","));
        assert!(PathInfoV1::parse(&accepted).is_ok());
        let rejected = valid(&short_references.join(","));
        assert!(matches!(
            PathInfoV1::parse(&rejected),
            Err(PathInfoV1Error::ReferenceCount)
        ));

        let long_name = "n".repeat(211);
        let references = (0..MAX_REFERENCES)
            .map(|index| format!("/nix/store/{index:032}-{long_name}"))
            .collect::<Vec<_>>()
            .join(",");
        let max_path = format!("/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-{long_name}");
        let exact_max = format!("1;{max_path};{HASH};18446744073709551615;{references}");
        assert_eq!(exact_max.len(), MAX_PATH_INFO_V1_LEN);
        assert!(PathInfoV1::parse(exact_max.as_bytes()).is_ok());

        let overlong = format!("{exact_max}x");
        assert_eq!(overlong.len(), MAX_PATH_INFO_V1_LEN + 1);
        assert!(matches!(
            PathInfoV1::parse(overlong.as_bytes()),
            Err(PathInfoV1Error::Length)
        ));
    }
}
