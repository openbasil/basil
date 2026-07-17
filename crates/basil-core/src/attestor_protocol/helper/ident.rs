// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared canonical-identifier validation for the measurement-helper contract.
//!
//! These rules mirror the schema-3 ceilings in
//! `docs/attestor-realm-contract/SPEC.md`: realm names, helper-policy
//! identities, service units, and the checked generation-qualifier binding.

/// Maximum bytes in a realm name.
pub const MAX_REALM_BYTES: usize = 63;
/// Maximum bytes in a helper-policy, LSM, or lockdown identity.
pub const MAX_IDENTITY_BYTES: usize = 128;
/// Maximum bytes in a systemd service unit name.
pub const MAX_UNIT_BYTES: usize = 128;

/// Return whether `name` is a canonical realm name.
///
/// Exact ASCII `[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?`, 1 to 63 bytes.
pub fn is_valid_realm_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_REALM_BYTES {
        return false;
    }
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let inner = |b: u8| edge(b) || b == b'-' || b == b'_';
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    let Some((&last, middle)) = rest.split_last() else {
        return edge(first);
    };
    edge(first) && edge(last) && middle.iter().all(|&b| inner(b))
}

/// Return whether `identity` is a canonical ASCII policy/profile identity.
///
/// 1 to 128 bytes of `[a-z0-9._:-]`, starting with a lowercase letter or
/// digit. The `:` separator admits LSM identities such as
/// `selinux:basil_attestor_g1_t`; the underscore admits `SELinux` type names.
pub fn is_valid_identity(identity: &str) -> bool {
    let bytes = identity.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_IDENTITY_BYTES {
        return false;
    }
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let inner = |b: u8| edge(b) || b == b'.' || b == b'_' || b == b':' || b == b'-';
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    edge(first) && rest.iter().all(|&b| inner(b))
}

/// Return whether `unit` is an acceptable systemd service unit name.
///
/// 1 to 128 bytes of ASCII graphic characters without `/`, ending in
/// `.service`. Exact unit equality against the installed expectation is the
/// authoritative check; this bound only rejects garbage early.
pub fn is_valid_service_unit(unit: &str) -> bool {
    let bytes = unit.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_UNIT_BYTES
        && bytes.iter().all(|&b| b.is_ascii_graphic() && b != b'/')
        && unit.ends_with(".service")
        && unit.len() > ".service".len()
}

/// Check the generation-qualifier binding of an identity or unit name.
///
/// A qualifier token is a `g` followed by one or more decimal digits, where
/// the `g` is preceded by a non-alphanumeric byte (`-`, `_`, `:`, `.`) or the
/// start of the string and the digits end at a non-digit boundary. The name
/// must embed at least one qualifier token, and every embedded token must
/// equal the exact decimal `generation` with no leading zeros; a token naming
/// any other generation fails closed.
pub fn embeds_exact_generation(name: &str, generation: u64) -> bool {
    let expected = generation.to_string();
    let bytes = name.as_bytes();
    let mut found = false;
    let mut previous: Option<u8> = None;
    let mut index = 0usize;
    while let Some(&byte) = bytes.get(index) {
        let boundary = previous.is_none_or(|p| !p.is_ascii_alphanumeric());
        if byte == b'g' && boundary {
            let digits_start = index + 1;
            let mut digits_end = digits_start;
            while bytes.get(digits_end).is_some_and(u8::is_ascii_digit) {
                digits_end += 1;
            }
            if digits_end > digits_start {
                let Some(digits) = name.get(digits_start..digits_end) else {
                    return false;
                };
                if digits != expected {
                    return false;
                }
                found = true;
                previous = bytes.get(digits_end - 1).copied();
                index = digits_end;
                continue;
            }
        }
        previous = Some(byte);
        index += 1;
    }
    found
}

/// Return whether `unit` ends in the exact `-g<generation>.service` qualifier.
pub fn unit_has_generation_suffix(unit: &str, generation: u64) -> bool {
    let suffix = format!("-g{generation}.service");
    unit.ends_with(&suffix) && unit.len() > suffix.len()
}

/// Parse a canonical decimal UID string (1 to 10 bytes, no leading zeros).
pub fn parse_decimal_uid(value: &str) -> Option<u32> {
    if value.is_empty() || value.len() > 10 {
        return None;
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if value.len() > 1 && value.starts_with('0') {
        return None;
    }
    value.parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_names() {
        assert!(is_valid_realm_name("a"));
        assert!(is_valid_realm_name("production-docker"));
        assert!(is_valid_realm_name("a1_b2-c3"));
        assert!(!is_valid_realm_name(""));
        assert!(!is_valid_realm_name("-leading"));
        assert!(!is_valid_realm_name("trailing-"));
        assert!(!is_valid_realm_name("UPPER"));
        assert!(!is_valid_realm_name(&"x".repeat(64)));
        assert!(is_valid_realm_name(&"x".repeat(63)));
    }

    #[test]
    fn identities() {
        assert!(is_valid_identity("basil-measure-policy-g1"));
        assert!(is_valid_identity("selinux:basil_attestor_g1_t"));
        assert!(!is_valid_identity(""));
        assert!(!is_valid_identity(":leading"));
        assert!(!is_valid_identity("has space"));
        assert!(!is_valid_identity(&"x".repeat(129)));
    }

    #[test]
    fn service_units() {
        assert!(is_valid_service_unit(
            "basil-attestor-production-docker-g1.service"
        ));
        assert!(!is_valid_service_unit(".service"));
        assert!(!is_valid_service_unit("no-suffix"));
        assert!(!is_valid_service_unit("bad/unit.service"));
    }

    #[test]
    fn generation_binding() {
        assert!(embeds_exact_generation("basil-measure-policy-g1", 1));
        assert!(embeds_exact_generation("selinux:basil_attestor_g7_t", 7));
        assert!(embeds_exact_generation(
            "basil-attestor-production-docker-g12.service",
            12
        ));
        // No token at all.
        assert!(!embeds_exact_generation("basil-measure-policy", 1));
        // A token naming another generation fails closed.
        assert!(!embeds_exact_generation("basil-g1-policy-g2", 2));
        assert!(!embeds_exact_generation("basil-measure-policy-g01", 1));
        // `g` embedded in a word is not a token.
        assert!(!embeds_exact_generation("config2", 2));
        assert!(embeds_exact_generation("cfg.g2", 2));
    }

    #[test]
    fn unit_suffixes() {
        assert!(unit_has_generation_suffix("a-g3.service", 3));
        assert!(!unit_has_generation_suffix("-g3.service", 3));
        assert!(!unit_has_generation_suffix("a-g30.service", 3));
    }

    #[test]
    fn decimal_uids() {
        assert_eq!(parse_decimal_uid("0"), Some(0));
        assert_eq!(parse_decimal_uid("992"), Some(992));
        assert_eq!(parse_decimal_uid("4294967295"), Some(u32::MAX));
        assert_eq!(parse_decimal_uid("4294967296"), None);
        assert_eq!(parse_decimal_uid("01"), None);
        assert_eq!(parse_decimal_uid(""), None);
        assert_eq!(parse_decimal_uid("12a"), None);
    }
}
