//! The basil private label registry and canonical label ordering.
//!
//! Labels live in the RFC 9052 private range (below -65536). This module is
//! the single source of truth for the codepoints and for the deterministic
//! (RFC 8949 §4.2.1) ordering of integer labels used throughout the profile.

/// In-reply-to message id (bstr). Responses only.
pub const IN_REPLY_TO: i64 = -70001;
/// SHA3-256 hash of the complete request bytes (bstr, 32 bytes). Responses only.
pub const REQUEST_HASH: i64 = -70002;
/// Sender key id (bstr); must equal the outer `kid`.
pub const SENDER_KEY_ID: i64 = -70003;
/// Response key id (tstr-encoded key id). Requests only.
pub const RESPONSE_KEY_ID: i64 = -70004;
/// Response subject (tstr). Requests only, optional.
pub const RESPONSE_SUBJECT: i64 = -70005;
/// Compact signer certificate JWT chain (array of tstr).
pub const SIGNER_CERTIFICATES_JWT: i64 = -70006;

/// COSE header parameter: algorithm.
pub(crate) const HDR_ALG: i64 = 1;
/// COSE header parameter: criticality.
pub(crate) const HDR_CRIT: i64 = 2;
/// COSE header parameter: content type.
pub(crate) const HDR_CONTENT_TYPE: i64 = 3;
/// COSE header parameter: key id.
pub(crate) const HDR_KID: i64 = 4;
/// COSE header parameter: initialization vector.
pub(crate) const HDR_IV: i64 = 5;
/// COSE header parameter: CWT claims map (RFC 9597).
pub(crate) const HDR_CWT_CLAIMS: i64 = 15;
/// COSE ECDH header algorithm parameter: ephemeral key.
pub(crate) const HDR_EPHEMERAL_KEY: i64 = -1;
/// COSE ECDH header algorithm parameter: `PartyU` identity.
pub(crate) const HDR_PARTY_U_IDENTITY: i64 = -21;
/// COSE ECDH header algorithm parameter: `PartyV` identity.
pub(crate) const HDR_PARTY_V_IDENTITY: i64 = -24;

/// CWT claim key: issuer.
pub(crate) const CWT_ISS: i64 = 1;
/// CWT claim key: audience.
pub(crate) const CWT_AUD: i64 = 3;
/// CWT claim key: expiry.
pub(crate) const CWT_EXP: i64 = 4;
/// CWT claim key: issued-at.
pub(crate) const CWT_IAT: i64 = 6;
/// CWT claim key: CWT id (the profile message id).
pub(crate) const CWT_CTI: i64 = 7;

/// The RFC 8949 §4.2.1 deterministic sort key for an integer label: the
/// bytewise-lexicographic order of the label's own deterministic encoding.
///
/// Non-negative integers (major type 0) sort before negatives (major type 1);
/// within a major type, minimal encodings sort by length then big-endian
/// value, which for integers is simply magnitude order.
#[must_use]
#[allow(clippy::cast_sign_loss)]
pub(crate) const fn canonical_sort_key(label: i64) -> (u8, u64) {
    if label >= 0 {
        (0, label as u64)
    } else {
        // The encoded argument is `-1 - label`; `!(label as u64)` computes it
        // without overflow for the full i64 range.
        (1, !(label as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether a slice of integer labels is in strictly ascending
    /// deterministic order (no duplicates).
    fn is_canonical_order(labels: &[i64]) -> bool {
        labels.is_sorted_by(|a, b| canonical_sort_key(*a) < canonical_sort_key(*b))
    }

    #[test]
    fn sort_key_orders_like_encoded_bytes() {
        // 0 < 1 < 23 < 24 < 256 < -1 < -24 < -25 < -70001 < -70002
        let order = [0, 1, 23, 24, 256, -1, -24, -25, -70001, -70002];
        assert!(is_canonical_order(&order));
        assert!(!is_canonical_order(&[-70002, -70001]));
        assert!(!is_canonical_order(&[-1, 3]));
        assert!(!is_canonical_order(&[3, 3]));
    }
}
