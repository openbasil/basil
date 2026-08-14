// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest as _, Sha256};

const PATH_INFO_V1: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/nix-cache-signing/path-info-v1.json"
));
const PATH_INFO_V1_SHA256: &str =
    "c4d31875e779e11d2a8b9dcd071e34fc832f545dca5784f0c72540dff8ee3823";

const NARINFO_FIDELITY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/nix-cache-signing/narinfo-fidelity.json"
));
const NARINFO_FIDELITY_SHA256: &str =
    "fef4433a5fdfab4220f795ce8e85c092d2cb472d676645cef8cc7b59a3212548";

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
