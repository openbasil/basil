// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest as _, Sha256};

const PATH_INFO_V1: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/nix-cache-signing/path-info-v1.json"
));
const PATH_INFO_V1_SHA256: &str =
    "b1de9eac413f548934b0aeee5a56f8a566616bf9590ad55a2ebca8094170e49b";

const NARINFO_FIDELITY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/nix-cache-signing/narinfo-fidelity.json"
));
const NARINFO_FIDELITY_SHA256: &str =
    "c7d4588ffd21025b00a8609b17183aede72bc63cf788aec2bac490559c6a7542";

#[test]
fn corpus_digests_match() {
    assert_eq!(
        hex::encode(Sha256::digest(PATH_INFO_V1)),
        PATH_INFO_V1_SHA256,
        "PATH_INFO_V1 corpus changed without updating its digest pin"
    );
    assert_eq!(
        hex::encode(Sha256::digest(NARINFO_FIDELITY)),
        NARINFO_FIDELITY_SHA256,
        "narinfo fidelity corpus changed without updating its digest pin"
    );
}
