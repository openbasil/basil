//! Cross-engine LIVE end-to-end for the post-quantum (PQC) local-software
//! provider over the broker gRPC, on BOTH a dev `OpenBao` AND a dev `Vault`
//! store, driven entirely through the published `basil` client.
//!
//! Provisioning (basil-yfg7): the PQC software-custody keys are minted here at
//! runtime through the client `NewKey` RPC (the basil-o5qx seam): the broker
//! generates the seed, AEAD-seals it under the catalog storage key, writes the
//! custody record, and returns only the public half. The prefill no longer seeds
//! byte-identical custody records out of band; it provisions only the catalog
//! entries, grants, and the transit AEAD wrap key `NewKey` needs.
//!
//! What it proves, per engine, over the broker's unix socket:
//!   (0) **`NewKey` provisioning**: `client.new_key` mints the ML-DSA-65 signer and
//!       the ML-KEM-768 sealing key end to end; each returns only its public half.
//!   (1) **ML-DSA-65 signing**: `client.sign`/`verify` round-trip through the
//!       local-software provider against the freshly minted seed; the broker's own
//!       verify accepts the signature and rejects a tampered message; AND the
//!       signature verifies **independently** under the verifying key the broker
//!       PUBLISHED (`NewKey` response == `GetPublicKey`), proving the broker signed
//!       with the seed it custodied.
//!   (2) **ML-KEM-768 envelope encryption**: `client.wrap_envelope` /
//!       `unwrap_envelope` round-trip; a wrong AAD and a tampered ciphertext both
//!       fail closed.
//!   (3) **Client streaming ML-KEM CEK-wrap unwrapped by the live broker**
//!       (basil-jcnr): fetch the encapsulation key via `GetPublicKey` (basil-4ybx),
//!       run `basil::stream::encrypt_ml_kem` to wrap a per-stream CEK into an
//!       ML-KEM+AES-256-GCM envelope, then decrypt where the CEK is recovered
//!       through the broker's `UnwrapEnvelope` (`BrokerCekRecovery`). The first
//!       proof the production (non-local-seed) CEK recovery works end to end, and
//!       that the broker IGNORES `KemEnvelope.key_version` for software-custody
//!       ML-KEM unwrap (the client sends 0; the broker uses the latest record).
//!   (4) **Unsupported algorithm/provider combinations return canonical errors**:
//!       a software-custody key the uid may sign but is NOT granted
//!       `op:use_software_custody` is denied with `PermissionDenied` (the denial
//!       fails at provider selection, so the key needs no custody record); a
//!       backend-required ML-DSA key with no backend-native ML-DSA support returns
//!       a canonical, opaque error (no internal/seed detail) to the client.
//!
//! GATING: each engine leg is gated on its CLI (`bao`/`vault`) being on PATH; an
//! absent engine prints an EXPLICIT skip line. `ran_any` asserts at least one leg
//! ran, so an all-absent environment FAILS loudly rather than passing vacuously.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::allow_attributes
)]

use basil::stream::{self, BrokerCekRecovery, MlKemSuite};
use basil::{Client, EnvelopeAlgorithm, Error, KemAlgorithm, KeyType, SigningAlgorithm};
use basil_core::ml_dsa_sign::{self, MlDsaAlgorithm};
use basil_tests::{Engine, alloc_addr, boot_basil, on_path};
use tonic::Code;

/// Catalog names the prefill declares for PQC software-custody keys.
const SIGN_KEY: &str = "pqc.sign";
const DENIED_KEY: &str = "pqc.denied";
const BACKEND_KEY: &str = "pqc.backend";
const SEAL_KEY: &str = "pqc.seal";

/// FIPS 204 encoded signature length for ML-DSA-65.
const ML_DSA_65_SIG_LEN: usize = 3309;
/// FIPS 203 encapsulation (public) key length for ML-KEM-768.
const ML_KEM_768_ENCAP_KEY_LEN: usize = 1184;

/// Drive one engine end to end against a freshly-prefilled `engine` store.
async fn drive_engine(engine: Engine, tag: &str, addr: &str) {
    let harness = boot_basil(tag, engine, addr);
    let socket = harness.socket();
    let socket_str = socket.to_str().expect("socket path is UTF-8");
    let eng = engine.prefill_name();

    let mut client = Client::connect(socket_str)
        .await
        .expect("connect basil client to the broker socket");

    // ===== (0) provision the PQC software-custody keys via NewKey (basil-yfg7) =====
    // The broker generates the seed, seals it, writes the custody record, and
    // returns only the public half, proving the client provisioning path end to
    // end (replacing the prefill's out-of-band custody-record seeding).
    let sign_key = client
        .new_key(SIGN_KEY, KeyType::MlDsa65)
        .await
        .expect("provision ml-dsa-65 software-custody signer via NewKey");
    assert_eq!(
        sign_key.key_id, SIGN_KEY,
        "[{eng}] NewKey echoes the catalog id"
    );
    assert!(
        !sign_key.public_key.is_empty(),
        "[{eng}] NewKey returns the ml-dsa-65 verifying key"
    );
    let seal_key = client
        .new_key(SEAL_KEY, KeyType::MlKem768)
        .await
        .expect("provision ml-kem-768 software-custody sealing key via NewKey");
    assert_eq!(
        seal_key.public_key.len(),
        ML_KEM_768_ENCAP_KEY_LEN,
        "[{eng}] NewKey returns the ml-kem-768 encapsulation key"
    );

    // ===== (1) ML-DSA-65 sign / verify through the client =====
    let message = b"basil ml-dsa-65 live e2e payload";
    let signature = client
        .sign_with_algorithm(SIGN_KEY, message, SigningAlgorithm::MlDsa65)
        .await
        .expect("ml-dsa sign through the local-software provider");
    assert_eq!(
        signature.len(),
        ML_DSA_65_SIG_LEN,
        "[{eng}] ml-dsa-65 signature length"
    );

    assert!(
        client
            .verify_with_algorithm(SIGN_KEY, message, &signature, SigningAlgorithm::MlDsa65)
            .await
            .expect("broker verify of its own ml-dsa signature"),
        "[{eng}] broker accepts its own ml-dsa signature"
    );
    assert!(
        !client
            .verify_with_algorithm(
                SIGN_KEY,
                b"a different message",
                &signature,
                SigningAlgorithm::MlDsa65
            )
            .await
            .expect("broker verify of a tampered ml-dsa message"),
        "[{eng}] broker rejects an ml-dsa signature over a different message"
    );

    // Independent verify against the verifying key the broker PUBLISHED for the
    // freshly minted seed: NewKey's response and GetPublicKey (basil-4ybx/a36l)
    // must agree, and the broker's signature must verify under it: proving the
    // broker signed with the seed it custodied, not merely self-consistently.
    let published = client
        .get_public_key(SIGN_KEY, None)
        .await
        .expect("get_public_key for the ml-dsa software-custody signer");
    assert_eq!(
        published.public_key, sign_key.public_key,
        "[{eng}] GetPublicKey matches NewKey's published ml-dsa verifying key"
    );
    assert!(
        ml_dsa_sign::verify(
            MlDsaAlgorithm::MlDsa65,
            &published.public_key,
            message,
            &signature
        )
        .expect("independent ml-dsa verify"),
        "[{eng}] broker's ml-dsa signature verifies under the published verifying key"
    );

    // ===== (2) ML-KEM-768 envelope encryption through the client =====
    let plaintext = b"basil ml-kem-768 enrollment payload";
    let aad = b"basil-pqc-ctx";
    let envelope = client
        .wrap_envelope(
            SEAL_KEY,
            KemAlgorithm::MlKem768,
            EnvelopeAlgorithm::Aes256Gcm,
            plaintext,
            Some(aad),
        )
        .await
        .expect("ml-kem wrap_envelope through the local-software provider");
    let recovered = client
        .unwrap_envelope(SEAL_KEY, envelope.clone(), Some(aad))
        .await
        .expect("ml-kem unwrap_envelope through the local-software provider");
    assert_eq!(
        recovered, plaintext,
        "[{eng}] ml-kem-768 wrap/unwrap round-trips the plaintext"
    );

    // Wrong AAD fails closed.
    assert!(
        client
            .unwrap_envelope(SEAL_KEY, envelope.clone(), Some(b"wrong-ctx"))
            .await
            .is_err(),
        "[{eng}] ml-kem unwrap with the wrong AAD fails closed"
    );
    // Tampered ciphertext fails closed.
    let mut tampered = envelope.clone();
    if let Some(byte) = tampered.ciphertext.first_mut() {
        *byte ^= 0xFF;
    }
    assert!(
        client
            .unwrap_envelope(SEAL_KEY, tampered, Some(aad))
            .await
            .is_err(),
        "[{eng}] ml-kem unwrap of a tampered ciphertext fails closed"
    );

    // ===== (3) client streaming ML-KEM CEK-wrap -> live broker UnwrapEnvelope (basil-jcnr) =====
    // Fetch the encapsulation key via GetPublicKey (basil-4ybx); it must match
    // NewKey's. Encrypt a stream whose per-stream CEK is wrapped into an
    // ML-KEM+AES-256-GCM envelope, then decrypt where the CEK is recovered through
    // the LIVE broker's UnwrapEnvelope (BrokerCekRecovery): the first end-to-end
    // proof of the production (non-local-seed) CEK recovery path.
    let encap = client
        .get_public_key(SEAL_KEY, None)
        .await
        .expect("get_public_key returns the ml-kem-768 encapsulation key (basil-4ybx)");
    assert_eq!(
        encap.public_key, seal_key.public_key,
        "[{eng}] GetPublicKey matches NewKey's ml-kem-768 encapsulation key"
    );
    assert_eq!(
        encap.public_key.len(),
        ML_KEM_768_ENCAP_KEY_LEN,
        "[{eng}] published encapsulation key is ML-KEM-768 sized"
    );

    let stream_plaintext: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let mut sealed_stream = Vec::new();
    stream::encrypt_ml_kem(
        &stream_plaintext[..],
        &mut sealed_stream,
        MlKemSuite::MlKem768,
        &encap.public_key,
        stream::DEFAULT_CHUNK_SIZE,
    )
    .await
    .expect("encrypt_ml_kem wraps the CEK against the published encapsulation key");
    assert_ne!(
        sealed_stream, stream_plaintext,
        "[{eng}] the stream is actually encrypted"
    );

    // key_version PINNING (basil-jcnr): BrokerCekRecovery sends KemEnvelope
    // key_version = 0, and the broker IGNORES it for software-custody ML-KEM
    // unwrap (it materializes the LATEST custody record, version 1 for a freshly
    // minted key). A successful recovery is the live proof key_version is unused
    // for this path; no specific version need be threaded by the client.
    let recovery = BrokerCekRecovery::new(client.clone(), SEAL_KEY, MlKemSuite::MlKem768);
    let mut recovered_stream = Vec::new();
    stream::decrypt_ml_kem(&sealed_stream[..], &mut recovered_stream, &recovery)
        .await
        .expect("decrypt_ml_kem recovers the CEK via the live broker UnwrapEnvelope");
    assert_eq!(
        recovered_stream, stream_plaintext,
        "[{eng}] broker-recovered CEK decrypts the stream to the original plaintext"
    );
    eprintln!(
        "PQC-E2E[{eng}]: client streaming ML-KEM CEK-wrap recovered by live broker UnwrapEnvelope OK"
    );

    // ===== (4) unsupported algorithm/provider combinations -> canonical errors =====
    // (a) software-custody op without the op:use_software_custody grant -> denied.
    // pqc.denied is intentionally NOT provisioned: the denial fails at provider
    // selection, before any custody record is read.
    let denied = client
        .sign_with_algorithm(DENIED_KEY, message, SigningAlgorithm::MlDsa65)
        .await
        .expect_err(
            "sign on a software-custody key lacking op:use_software_custody must be denied",
        );
    match &denied {
        Error::Status {
            code, message: m, ..
        } => {
            assert_eq!(
                *code,
                Code::PermissionDenied,
                "[{eng}] local-software without grant -> PermissionDenied (got {denied})"
            );
            assert!(
                !m.contains("seed") && !m.to_lowercase().contains("private"),
                "[{eng}] denied error stays opaque (no private/seed detail): {m}"
            );
        }
        other => panic!("[{eng}] unexpected denied error shape: {other}"),
    }
    eprintln!("PQC-E2E[{eng}]: software custody without grant denied: {denied}");

    // (b) backend-required ML-DSA with no backend-native support -> canonical, opaque.
    let unsupported = client
        .sign_with_algorithm(BACKEND_KEY, message, SigningAlgorithm::MlDsa65)
        .await
        .expect_err("sign on a backend-required ML-DSA key with no native backend must fail");
    match &unsupported {
        Error::Status {
            code, message: m, ..
        } => {
            assert!(
                matches!(
                    *code,
                    Code::Unimplemented
                        | Code::FailedPrecondition
                        | Code::InvalidArgument
                        | Code::Internal
                ),
                "[{eng}] backend-required ML-DSA returns a canonical error code (got {unsupported})"
            );
            assert!(
                !m.contains("seed"),
                "[{eng}] unsupported error stays opaque (no seed detail): {m}"
            );
        }
        other => panic!("[{eng}] unexpected unsupported error shape: {other}"),
    }
    eprintln!(
        "PQC-E2E[{eng}]: backend-required ML-DSA without native support -> canonical error: {unsupported}"
    );

    drop(client);
    eprintln!(
        "PQC-E2E[{eng}]: NewKey-provisioned ml-dsa sign/verify + ml-kem wrap/unwrap + streaming \
         CEK-wrap through the client OK; unsupported combos returned canonical errors"
    );
    drop(harness);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pqc_through_client_cross_engine() {
    let ran_bao = if on_path("bao") {
        drive_engine(Engine::OpenBao, "pqc-bao", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: bao not found on PATH; PQC live e2e needs a live OpenBao");
        false
    };

    let ran_vault = if on_path("vault") {
        drive_engine(Engine::Vault, "pqc-vault", &alloc_addr()).await;
        true
    } else {
        eprintln!("SKIP: vault not found on PATH; PQC live e2e needs a live Vault");
        false
    };

    assert!(
        ran_bao || ran_vault,
        "neither bao nor vault was on PATH; the PQC live cross-engine e2e ran no engine leg \
         (it must not pass vacuously)"
    );
}
