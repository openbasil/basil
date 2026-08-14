// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

use basil_core::nix_cache_fingerprint::{MAX_REFERENCES, PathInfoV1};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const CORPUS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/nix-cache-signing/path-info-v1.json"
));

#[derive(Debug, Deserialize)]
struct Corpus {
    version: u32,
    profile: String,
    generator_rules: Vec<String>,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    result: String,
    input: Option<String>,
    canonical: Option<String>,
    construction: Option<Construction>,
    input_length: Option<usize>,
    input_sha256: Option<String>,
    canonical_length: Option<usize>,
    canonical_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Construction {
    rule: String,
    parameters: ConstructionParameters,
}

#[derive(Debug, Deserialize)]
struct ConstructionParameters {
    version: String,
    store_hash: String,
    store_name_byte: String,
    store_name_length: usize,
    nar_hash: String,
    nar_size: String,
    reference_hash_alphabet: String,
    reference_hash_prefix: String,
    reference_hash_counter_width: usize,
    reference_hash_counter_start: usize,
    reference_name_byte: String,
    reference_name_length: usize,
    last_reference_name_length: usize,
    reference_count: usize,
}

#[test]
fn all_normative_path_info_v1_vectors_conform() {
    let corpus: Corpus = serde_json::from_slice(CORPUS).expect("valid pinned corpus JSON");
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, "PATH_INFO_V1");

    for vector in corpus.vectors {
        let input = match (&vector.input, &vector.construction) {
            (Some(encoded), None) => hex::decode(encoded).expect("corpus input is hexadecimal"),
            (None, Some(construction)) => construct(construction),
            _ => panic!("{} has ambiguous input representation", vector.name),
        };
        if let Some(length) = vector.input_length {
            assert_eq!(input.len(), length, "{} input length", vector.name);
        }
        if let Some(digest) = &vector.input_sha256 {
            assert_eq!(
                hex::encode(Sha256::digest(&input)),
                *digest,
                "{} input digest",
                vector.name
            );
        }
        match vector.result.as_str() {
            "accept" => {
                let parsed = PathInfoV1::parse(&input)
                    .unwrap_or_else(|error| panic!("{} should be accepted: {error}", vector.name));
                let canonical = vector.canonical.as_deref().map_or_else(
                    || input.clone(),
                    |encoded| hex::decode(encoded).expect("canonical bytes are hexadecimal"),
                );
                assert_eq!(
                    parsed.as_bytes(),
                    canonical,
                    "{} canonical bytes",
                    vector.name
                );
                if let Some(length) = vector.canonical_length {
                    assert_eq!(canonical.len(), length, "{} canonical length", vector.name);
                }
                if let Some(digest) = &vector.canonical_sha256 {
                    assert_eq!(
                        hex::encode(Sha256::digest(&canonical)),
                        *digest,
                        "{} canonical digest",
                        vector.name
                    );
                }
            }
            "reject" => assert!(
                PathInfoV1::parse(&input).is_err(),
                "{} should be rejected",
                vector.name
            ),
            result => panic!("unknown corpus result {result:?}"),
        }
    }
}

fn construct(construction: &Construction) -> Vec<u8> {
    assert_eq!(construction.rule, "sequential-max-store-path-references-v1");
    let parameters = &construction.parameters;
    let store_name = parameters
        .store_name_byte
        .repeat(parameters.store_name_length);
    let store_path = format!("/nix/store/{}-{store_name}", parameters.store_hash);
    let mut references = Vec::with_capacity(parameters.reference_count);
    for offset in 0..parameters.reference_count {
        let counter = fixed_nix32(
            parameters.reference_hash_counter_start + offset,
            parameters.reference_hash_counter_width,
            parameters.reference_hash_alphabet.as_bytes(),
        );
        let hash = format!("{}{counter}", parameters.reference_hash_prefix);
        let name_length = if offset + 1 == parameters.reference_count {
            parameters.last_reference_name_length
        } else {
            parameters.reference_name_length
        };
        references.push(format!(
            "/nix/store/{hash}-{}",
            parameters.reference_name_byte.repeat(name_length)
        ));
    }
    format!(
        "{};{store_path};sha256:{};{};{}",
        parameters.version,
        parameters.nar_hash,
        parameters.nar_size,
        references.join(",")
    )
    .into_bytes()
}

fn fixed_nix32(mut value: usize, width: usize, alphabet: &[u8]) -> String {
    let mut encoded = vec![b'0'; width];
    for slot in encoded.iter_mut().rev() {
        let index = value % alphabet.len();
        *slot = *alphabet.get(index).expect("counter digit in alphabet");
        value /= alphabet.len();
    }
    assert_eq!(value, 0, "counter exceeds fixed width");
    String::from_utf8(encoded).expect("Nix alphabet is UTF-8")
}

#[test]
fn all_normative_generator_rules_conform() {
    let corpus: Corpus = serde_json::from_slice(CORPUS).expect("valid pinned corpus JSON");
    assert_eq!(
        corpus.generator_rules,
        ["sequential-max-store-path-references-v1"]
    );

    let references = (0..=MAX_REFERENCES)
        .map(|index| format!("/nix/store/{index:032}-reference"))
        .collect::<Vec<_>>();
    let prefix = concat!(
        "1;/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-root;",
        "sha256:0000000000000000000000000000000000000000000000000000;1;"
    );
    let at_limit = format!("{prefix}{}", references[..MAX_REFERENCES].join(","));
    let parsed = PathInfoV1::parse(at_limit.as_bytes()).expect("2,048 references are canonical");
    assert_eq!(parsed.as_bytes(), at_limit.as_bytes());

    let over_limit = format!("{prefix}{}", references.join(","));
    assert!(
        PathInfoV1::parse(over_limit.as_bytes()).is_err(),
        "2,049 references must be rejected"
    );
}
