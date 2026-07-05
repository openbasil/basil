// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for the streaming encryption container. No live broker is needed:
//! the ML-KEM path is exercised through [`LocalSeedCekRecovery`].

use super::format::{FIXED_HEADER_LEN, TAG_LEN};
use super::*;

const SEED: [u8; 64] = [0x42; 64];

/// Build a deterministic multi-chunk payload of `len` bytes.
fn payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

async fn encrypt_aead_vec(suite: AeadSuite, data: &[u8], chunk_size: usize) -> (Vec<u8>, Vec<u8>) {
    let mut ciphertext = Vec::new();
    let cek = encrypt_aead(
        data,
        &mut ciphertext,
        suite,
        CekSource::Generate,
        chunk_size,
    )
    .await
    .expect("encrypt_aead");
    (ciphertext, cek.to_vec())
}

async fn decrypt_aead_vec(ciphertext: &[u8], cek: &[u8; 32]) -> StreamResult<Vec<u8>> {
    let mut plaintext = Vec::new();
    decrypt_aead(ciphertext, &mut plaintext, cek).await?;
    Ok(plaintext)
}

async fn encrypt_ml_kem_vec(suite: MlKemSuite, data: &[u8], chunk_size: usize) -> Vec<u8> {
    let public = kem::public_from_seed(&SEED, suite).expect("public");
    let mut ciphertext = Vec::new();
    encrypt_ml_kem(data, &mut ciphertext, suite, &public, chunk_size)
        .await
        .expect("encrypt_ml_kem");
    ciphertext
}

async fn decrypt_ml_kem_vec(suite: MlKemSuite, ciphertext: &[u8]) -> StreamResult<Vec<u8>> {
    let recovery = LocalSeedCekRecovery::new(SEED.to_vec(), suite);
    let mut plaintext = Vec::new();
    decrypt_ml_kem(ciphertext, &mut plaintext, &recovery).await?;
    Ok(plaintext)
}

#[tokio::test]
async fn aead_suites_round_trip_multi_chunk() {
    let data = payload(200);
    for suite in [AeadSuite::Aes256Gcm, AeadSuite::ChaCha20Poly1305] {
        let (ciphertext, cek) = encrypt_aead_vec(suite, &data, 64).await;
        let key: [u8; 32] = cek.as_slice().try_into().expect("cek len");
        let recovered = decrypt_aead_vec(&ciphertext, &key).await.expect("decrypt");
        assert_eq!(recovered, data, "{suite:?} round-trip");
    }
}

#[tokio::test]
async fn ml_kem_suites_round_trip_multi_chunk() {
    let data = payload(500);
    for suite in [
        MlKemSuite::MlKem512,
        MlKemSuite::MlKem768,
        MlKemSuite::MlKem1024,
    ] {
        let ciphertext = encrypt_ml_kem_vec(suite, &data, 128).await;
        let recovered = decrypt_ml_kem_vec(suite, &ciphertext)
            .await
            .expect("decrypt");
        assert_eq!(recovered, data, "{suite:?} round-trip");
    }
}

#[tokio::test]
async fn empty_payload_round_trips() {
    let (ciphertext, cek) = encrypt_aead_vec(AeadSuite::Aes256Gcm, b"", 64).await;
    let key: [u8; 32] = cek.as_slice().try_into().expect("cek len");
    let recovered = decrypt_aead_vec(&ciphertext, &key).await.expect("decrypt");
    assert!(recovered.is_empty());
}

#[tokio::test]
async fn caller_provided_cek_round_trips() {
    let cek = Zeroizing::new([0x11u8; 32]);
    let data = payload(150);
    let mut ciphertext = Vec::new();
    encrypt_aead(
        data.as_slice(),
        &mut ciphertext,
        AeadSuite::Aes256Gcm,
        CekSource::Provided(cek.clone()),
        64,
    )
    .await
    .expect("encrypt");
    let recovered = decrypt_aead_vec(&ciphertext, &cek).await.expect("decrypt");
    assert_eq!(recovered, data);
}

#[tokio::test]
async fn short_and_malformed_headers_fail_closed() {
    let key = [0u8; 32];
    // Empty input: nothing to read.
    assert!(matches!(
        decrypt_aead_vec(b"", &key).await,
        Err(StreamError::ShortHeader)
    ));
    // Shorter than the fixed header.
    assert!(matches!(
        decrypt_aead_vec(&[0u8; 10], &key).await,
        Err(StreamError::ShortHeader)
    ));
    // Full-length header with the wrong magic.
    let bad_magic = [0xFFu8; FIXED_HEADER_LEN];
    assert!(matches!(
        decrypt_aead_vec(&bad_magic, &key).await,
        Err(StreamError::BadMagic)
    ));
}

#[tokio::test]
async fn tampered_ciphertext_fails_closed() {
    let data = payload(96);
    let (mut ciphertext, cek) = encrypt_aead_vec(AeadSuite::Aes256Gcm, &data, 32).await;
    let key: [u8; 32] = cek.as_slice().try_into().expect("cek");
    // Flip a byte inside the first record body (header 61 + 4-byte length prefix).
    ciphertext[FIXED_HEADER_LEN + 4] ^= 0xFF;
    assert!(matches!(
        decrypt_aead_vec(&ciphertext, &key).await,
        Err(StreamError::AuthFailed)
    ));
}

#[tokio::test]
async fn reordered_chunks_fail_closed() {
    let data = payload(96); // three full 32-byte chunks
    let (mut ciphertext, cek) = encrypt_aead_vec(AeadSuite::Aes256Gcm, &data, 32).await;
    let key: [u8; 32] = cek.as_slice().try_into().expect("cek");
    let record_body = 32 + TAG_LEN; // 48
    let r0 = FIXED_HEADER_LEN + 4;
    let r1 = r0 + record_body + 4;
    let (a, b) = (r0, r1);
    for offset in 0..record_body {
        ciphertext.swap(a + offset, b + offset);
    }
    assert!(matches!(
        decrypt_aead_vec(&ciphertext, &key).await,
        Err(StreamError::AuthFailed)
    ));
}

#[tokio::test]
async fn dropped_final_chunk_is_detected() {
    let data = payload(96); // three full 32-byte chunks
    let (ciphertext, cek) = encrypt_aead_vec(AeadSuite::Aes256Gcm, &data, 32).await;
    let key: [u8; 32] = cek.as_slice().try_into().expect("cek");
    let record_body = 32 + TAG_LEN;
    // Keep header + record 0 + record 1, drop the final record entirely.
    let truncated_len = FIXED_HEADER_LEN + 2 * (4 + record_body);
    let truncated = &ciphertext[..truncated_len];
    assert!(matches!(
        decrypt_aead_vec(truncated, &key).await,
        Err(StreamError::AuthFailed)
    ));
}

#[tokio::test]
async fn mid_record_truncation_is_detected() {
    let data = payload(96);
    let (ciphertext, cek) = encrypt_aead_vec(AeadSuite::Aes256Gcm, &data, 32).await;
    let key: [u8; 32] = cek.as_slice().try_into().expect("cek");
    // Cut in the middle of the last record body.
    let truncated = &ciphertext[..ciphertext.len() - 8];
    assert!(matches!(
        decrypt_aead_vec(truncated, &key).await,
        Err(StreamError::Truncated | StreamError::AuthFailed)
    ));
}

#[tokio::test]
async fn downgraded_suite_id_fails_closed() {
    let data = payload(96);
    let (mut ciphertext, cek) = encrypt_aead_vec(AeadSuite::Aes256Gcm, &data, 32).await;
    let key: [u8; 32] = cek.as_slice().try_into().expect("cek");
    // suite_id is at offset 7. AES-256-GCM is 1; rewrite to ChaCha20 (2).
    assert_eq!(ciphertext[7], 1);
    ciphertext[7] = 2;
    assert!(matches!(
        decrypt_aead_vec(&ciphertext, &key).await,
        Err(StreamError::AuthFailed)
    ));
}

#[tokio::test]
async fn unknown_suite_id_is_rejected() {
    let data = payload(64);
    let (mut ciphertext, cek) = encrypt_aead_vec(AeadSuite::Aes256Gcm, &data, 32).await;
    let key: [u8; 32] = cek.as_slice().try_into().expect("cek");
    ciphertext[7] = 99;
    assert!(matches!(
        decrypt_aead_vec(&ciphertext, &key).await,
        Err(StreamError::UnsupportedSuite(99))
    ));
}

#[tokio::test]
async fn nonzero_reserved_flags_rejected() {
    let data = payload(64);
    let (mut ciphertext, cek) = encrypt_aead_vec(AeadSuite::Aes256Gcm, &data, 32).await;
    let key: [u8; 32] = cek.as_slice().try_into().expect("cek");
    // Reserved flags byte is at offset 8.
    ciphertext[8] = 1;
    assert!(matches!(
        decrypt_aead_vec(&ciphertext, &key).await,
        Err(StreamError::ReservedFlags)
    ));
}

#[tokio::test]
async fn aead_decrypt_on_ml_kem_stream_is_suite_mismatch() {
    let data = payload(128);
    let ciphertext = encrypt_ml_kem_vec(MlKemSuite::MlKem768, &data, 64).await;
    let key = [0u8; 32];
    assert!(matches!(
        decrypt_aead_vec(&ciphertext, &key).await,
        Err(StreamError::SuiteMismatch { actual }) if actual == 4
    ));
}

#[tokio::test]
async fn ml_kem_decrypt_on_aead_stream_is_suite_mismatch() {
    let data = payload(128);
    let (ciphertext, _cek) = encrypt_aead_vec(AeadSuite::Aes256Gcm, &data, 64).await;
    assert!(matches!(
        decrypt_ml_kem_vec(MlKemSuite::MlKem768, &ciphertext).await,
        Err(StreamError::SuiteMismatch { actual }) if actual == 1
    ));
}

#[tokio::test]
async fn ml_kem_tampered_ciphertext_fails_closed() {
    let data = payload(300);
    let suite = MlKemSuite::MlKem768;
    let mut ciphertext = encrypt_ml_kem_vec(suite, &data, 128).await;
    // Flip a byte well past the KEM header, inside the first chunk record.
    let kem_header = 4 + suite.ciphertext_len() + 12 + 4 + (32 + TAG_LEN);
    let first_record_body = FIXED_HEADER_LEN + kem_header + 4;
    ciphertext[first_record_body] ^= 0xFF;
    assert!(matches!(
        decrypt_ml_kem_vec(suite, &ciphertext).await,
        Err(StreamError::AuthFailed)
    ));
}

#[tokio::test]
async fn ml_kem_envelope_header_appears_exactly_once() {
    let data = payload(700); // several 128-byte chunks
    let suite = MlKemSuite::MlKem768;
    let ciphertext = encrypt_ml_kem_vec(suite, &data, 128).await;

    // Extract the encapsulated key (the unique, large KEM ciphertext) from the
    // header and confirm it occurs exactly once across the whole container.
    let ct_len_off = FIXED_HEADER_LEN;
    let kem_ct_len = u32::from_be_bytes(
        ciphertext[ct_len_off..ct_len_off + 4]
            .try_into()
            .expect("len"),
    ) as usize;
    assert_eq!(kem_ct_len, suite.ciphertext_len());
    let enc_key = ciphertext[ct_len_off + 4..ct_len_off + 4 + kem_ct_len].to_vec();

    let mut occurrences = 0;
    let mut search_from = 0;
    while let Some(pos) = find_subslice(&ciphertext[search_from..], &enc_key) {
        occurrences += 1;
        search_from += pos + 1;
    }
    assert_eq!(occurrences, 1, "KEM envelope must appear exactly once");
}

#[tokio::test]
async fn ml_kem_wrong_seed_fails_closed() {
    let data = payload(128);
    let suite = MlKemSuite::MlKem768;
    let ciphertext = encrypt_ml_kem_vec(suite, &data, 64).await;
    let wrong = LocalSeedCekRecovery::new(vec![0x07u8; 64], suite);
    let mut out = Vec::new();
    let result = decrypt_ml_kem(ciphertext.as_slice(), &mut out, &wrong).await;
    // A wrong decapsulation key yields a different shared secret, so the CEK-wrap
    // AEAD fails to open.
    assert!(matches!(result, Err(StreamError::AuthFailed)));
}

#[tokio::test]
async fn wrong_cek_fails_closed() {
    let data = payload(96);
    let (ciphertext, _cek) = encrypt_aead_vec(AeadSuite::Aes256Gcm, &data, 32).await;
    let wrong = [0u8; 32];
    assert!(matches!(
        decrypt_aead_vec(&ciphertext, &wrong).await,
        Err(StreamError::AuthFailed)
    ));
}

#[test]
fn oversized_chunk_size_rejected() {
    let too_big = MAX_CHUNK_SIZE + 1;
    assert!(matches!(
        super::validate_chunk_size(too_big),
        Err(StreamError::BadChunkSize(n)) if n == too_big
    ));
    assert!(matches!(
        super::validate_chunk_size(0),
        Err(StreamError::BadChunkSize(0))
    ));
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}
