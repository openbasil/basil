// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! SHA3-256 request-hash helper (claim `-70002`).

use sha3::{Digest, Sha3_256};

/// A SHA3-256 digest of the complete tagged request bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHash(pub [u8; 32]);

/// SHA3-256 over the complete tagged request `COSE_Sign1` bytes.
///
/// Used by a responder when building the `-70002` claim and by a requester
/// when checking a response against the request it sent.
#[must_use]
pub fn request_hash(request_cose_sign1: &[u8]) -> RequestHash {
    RequestHash(Sha3_256::digest(request_cose_sign1).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_sha3_256_vector() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let RequestHash(digest) = request_hash(b"");
        assert_eq!(
            digest[..4],
            [0xa7, 0xff, 0xc6, 0xf8],
            "SHA3-256 empty-string prefix"
        );
        assert_eq!(digest[28..], [0x80, 0xf8, 0x43, 0x4a]);
    }

    #[test]
    fn distinct_inputs_distinct_hashes() {
        assert_ne!(request_hash(b"a").0, request_hash(b"b").0);
        assert_eq!(request_hash(b"a").0, request_hash(b"a").0);
    }
}
