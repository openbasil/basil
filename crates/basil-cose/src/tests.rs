// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Crate-level tests: round trips for all three constructions with both
//! content algorithms, adversarial tampering, and encoding-strictness
//! negatives (hand-crafted hostile CBOR).

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use minicbor::Encoder;
use zeroize::Zeroizing;

use crate::codec::{self, ClaimsExpectation, Sign1Layer};
use crate::*;

/// Poll a ready-immediately future to completion (local key impls never
/// yield; a `Pending` here is a test bug).
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = core::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("local future pended"),
    }
}

fn kid(s: &str) -> KeyId {
    KeyId::from_text(s).unwrap()
}

fn ct() -> ContentType {
    ContentType::new("application/basil.test".to_string()).unwrap()
}

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_bytes(kid("alice"), &Zeroizing::new([7u8; 32]))
}

fn verifier_for(s: &Ed25519Signer) -> Ed25519Verifier {
    Ed25519Verifier::from_key(s.key_id().clone(), &s.public_key_bytes()).unwrap()
}

fn recipient() -> X25519Recipient {
    X25519Recipient::new(kid("bob"), Zeroizing::new([9u8; 32]))
}

fn peer_claims(sender: &KeyId) -> Claims {
    Claims {
        issuer: None,
        audience: None,
        expires_at: None,
        issued_at: UnixTime(1_000),
        message_id: MessageId::from_bytes(vec![0xAB, 0xCD]).unwrap(),
        sender_key_id: Some(sender.clone()),
        response_key_id: None,
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
        freshness_challenge: None,
        response_public_key_cose: None,
    }
}

fn validation(role: MessageRole) -> ValidationParams {
    ValidationParams {
        now: UnixTime(1_010),
        max_clock_skew: Duration::from_secs(5),
        max_ttl: Duration::from_mins(5),
        default_ttl: Duration::from_mins(1),
        allowed_audiences: BTreeSet::new(),
        role,
    }
}

fn seal_params(
    plaintext: &[u8],
    alg: ContentAlgorithm,
    recipient_pub: X25519RecipientPublic,
) -> SealParams<'_> {
    SealParams {
        content_type: ct(),
        plaintext,
        claims: peer_claims(&kid("alice")),
        role: MessageRole::Peer,
        recipient: recipient_pub,
        content_algorithm: alg,
        aad: SealedAad::empty(),
        kdf_parties: KdfParties::anonymous(),
    }
}

// ---------------------------------------------------------------------------
// Signed construction
// ---------------------------------------------------------------------------

#[test]
fn signed_round_trip_without_claims() {
    let s = signer();
    let v = verifier_for(&s);
    let msg = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"hello",
            claims: None,
            external_aad: ExternalAad::empty(),
        },
        &s,
    ))
    .unwrap();
    let out = block_on(verify_signed(
        msg.as_bytes(),
        &v,
        &VerifySignedParams {
            external_aad: ExternalAad::empty(),
            validation: None,
        },
    ))
    .unwrap();
    assert_eq!(out.payload, b"hello");
    assert_eq!(out.content_type, ct());
    assert_eq!(out.signer_key_id, kid("alice"));
    assert!(out.claims.is_none());
    assert!(out.protected_headers.signer_certificates_jwt.is_empty());
}

#[test]
fn signed_round_trip_with_signer_certificate_headers() {
    let s = signer();
    let v = verifier_for(&s);
    let protected_headers = ProtectedHeaders {
        signer_certificates_jwt: vec![
            "eyJhbGciOiJFZERTQSJ9.cert.one.sig".to_string(),
            "eyJhbGciOiJFZERTQSJ9.cert.two.sig".to_string(),
        ],
        signer_public_key_cose: None,
    };
    let msg = block_on(build_signed_with_headers(
        &SignParams {
            content_type: ct(),
            payload: b"hello",
            claims: Some(peer_claims(s.key_id())),
            external_aad: ExternalAad::empty(),
        },
        &protected_headers,
        &s,
    ))
    .unwrap();
    let out = block_on(verify_signed(
        msg.as_bytes(),
        &v,
        &VerifySignedParams {
            external_aad: ExternalAad::empty(),
            validation: Some(&validation(MessageRole::Peer)),
        },
    ))
    .unwrap();
    assert_eq!(out.payload, b"hello");
    assert_eq!(out.protected_headers, protected_headers);
}

#[test]
fn signed_round_trip_with_claims_and_external_aad() {
    let s = signer();
    let v = verifier_for(&s);
    let aad = ExternalAad::from_bytes(b"nats.subject.v1".to_vec());
    let msg = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"control",
            claims: Some(peer_claims(&kid("alice"))),
            external_aad: aad.clone(),
        },
        &s,
    ))
    .unwrap();
    let out = block_on(verify_signed(
        msg.as_bytes(),
        &v,
        &VerifySignedParams {
            external_aad: aad,
            validation: Some(&validation(MessageRole::Peer)),
        },
    ))
    .unwrap();
    assert_eq!(out.claims.unwrap().message_id.as_bytes(), &[0xAB, 0xCD]);

    // Wrong external AAD must fail the signature, not decode.
    let err = block_on(verify_signed(
        msg.as_bytes(),
        &v,
        &VerifySignedParams {
            external_aad: ExternalAad::from_bytes(b"other".to_vec()),
            validation: Some(&validation(MessageRole::Peer)),
        },
    ))
    .unwrap_err();
    assert_eq!(err, VerifyError::SignatureInvalid);
}

#[test]
fn signed_claims_presence_mismatch() {
    let s = signer();
    let v = verifier_for(&s);
    let with_claims = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"x",
            claims: Some(peer_claims(&kid("alice"))),
            external_aad: ExternalAad::empty(),
        },
        &s,
    ))
    .unwrap();
    let without_claims = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"x",
            claims: None,
            external_aad: ExternalAad::empty(),
        },
        &s,
    ))
    .unwrap();
    let val = validation(MessageRole::Peer);
    // Claims present, no validation supplied.
    assert_eq!(
        block_on(verify_signed(
            with_claims.as_bytes(),
            &v,
            &VerifySignedParams {
                external_aad: ExternalAad::empty(),
                validation: None
            },
        ))
        .unwrap_err(),
        VerifyError::ClaimsPresenceMismatch
    );
    // Validation supplied, no claims present.
    assert_eq!(
        block_on(verify_signed(
            without_claims.as_bytes(),
            &v,
            &VerifySignedParams {
                external_aad: ExternalAad::empty(),
                validation: Some(&val)
            },
        ))
        .unwrap_err(),
        VerifyError::ClaimsPresenceMismatch
    );
}

#[test]
fn signed_tampered_payload_fails() {
    let s = signer();
    let v = verifier_for(&s);
    let msg = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"hello",
            claims: None,
            external_aad: ExternalAad::empty(),
        },
        &s,
    ))
    .unwrap();
    let mut bytes = msg.into_vec();
    // Flip a bit in the payload "hello" (search for it).
    let pos = bytes.windows(5).position(|w| w == b"hello").unwrap();
    bytes[pos] ^= 0x01;
    let err = block_on(verify_signed(
        &bytes,
        &v,
        &VerifySignedParams {
            external_aad: ExternalAad::empty(),
            validation: None,
        },
    ))
    .unwrap_err();
    assert_eq!(err, VerifyError::SignatureInvalid);
}

#[test]
fn signed_build_rejects_sender_mismatch() {
    let s = signer();
    let err = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"x",
            claims: Some(peer_claims(&kid("mallory"))),
            external_aad: ExternalAad::empty(),
        },
        &s,
    ))
    .unwrap_err();
    assert_eq!(err, BuildError::SenderKeyMismatch);
}

#[test]
fn signed_verifier_rejects_unknown_kid_and_bad_key() {
    let s = signer();
    let other = Ed25519Signer::from_secret_bytes(kid("carol"), &Zeroizing::new([8u8; 32]));
    let v_other = verifier_for(&other); // knows carol, not alice
    let msg = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"x",
            claims: None,
            external_aad: ExternalAad::empty(),
        },
        &s,
    ))
    .unwrap();
    assert_eq!(
        block_on(verify_signed(
            msg.as_bytes(),
            &v_other,
            &VerifySignedParams {
                external_aad: ExternalAad::empty(),
                validation: None
            },
        ))
        .unwrap_err(),
        VerifyError::UnknownKeyId
    );
    // A verifier that maps alice's kid to carol's key: wrong key.
    let v_wrong = Ed25519Verifier::from_key(kid("alice"), &other.public_key_bytes()).unwrap();
    assert_eq!(
        block_on(verify_signed(
            msg.as_bytes(),
            &v_wrong,
            &VerifySignedParams {
                external_aad: ExternalAad::empty(),
                validation: None
            },
        ))
        .unwrap_err(),
        VerifyError::SignatureInvalid
    );
}

// ---------------------------------------------------------------------------
// ES256 signature algorithm
// ---------------------------------------------------------------------------

fn es256_signer() -> Es256Signer {
    Es256Signer::from_secret_bytes(kid("alice"), &Zeroizing::new([7u8; 32])).unwrap()
}

fn es256_verifier_for(s: &Es256Signer) -> P256Verifier {
    P256Verifier::from_sec1(s.key_id().clone(), &s.public_key_sec1()).unwrap()
}

#[test]
fn es256_signed_round_trip_wire_alg_is_minus_seven() {
    let s = es256_signer();
    let v = es256_verifier_for(&s);
    let msg = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"es256 payload",
            claims: Some(peer_claims(&kid("alice"))),
            external_aad: ExternalAad::empty(),
        },
        &s,
    ))
    .unwrap();
    // The wire alg is ES256/-7.
    let d = codec::decode_sign1_strict(msg.as_bytes(), Sign1Layer::Bare).unwrap();
    assert_eq!(d.algorithm, SignatureAlgorithm::Es256);
    assert_eq!(d.algorithm.codepoint(), -7);

    let out = block_on(verify_signed(
        msg.as_bytes(),
        &v,
        &VerifySignedParams {
            external_aad: ExternalAad::empty(),
            validation: Some(&validation(MessageRole::Peer)),
        },
    ))
    .unwrap();
    assert_eq!(out.payload, b"es256 payload");
    assert_eq!(out.content_type, ct());
    assert_eq!(out.signer_key_id, kid("alice"));
}

#[test]
fn es256_signature_is_deterministic() {
    // RFC 6979 + low-S: re-signing the same structure is byte-identical.
    let s = es256_signer();
    let params = SignParams {
        content_type: ct(),
        payload: b"determinism",
        claims: None,
        external_aad: ExternalAad::empty(),
    };
    let a = block_on(build_signed(&params, &s)).unwrap();
    let b = block_on(build_signed(&params, &s)).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
}

#[test]
fn es256_tampered_payload_and_signature_fail() {
    let s = es256_signer();
    let v = es256_verifier_for(&s);
    let msg = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"hello",
            claims: None,
            external_aad: ExternalAad::empty(),
        },
        &s,
    ))
    .unwrap();
    // Flip a payload byte.
    let mut bytes = msg.clone().into_vec();
    let pos = bytes.windows(5).position(|w| w == b"hello").unwrap();
    bytes[pos] ^= 0x01;
    assert_eq!(
        block_on(verify_signed(
            &bytes,
            &v,
            &VerifySignedParams {
                external_aad: ExternalAad::empty(),
                validation: None
            },
        ))
        .unwrap_err(),
        VerifyError::SignatureInvalid
    );
    // Flip the last signature byte.
    let mut bytes = msg.into_vec();
    *bytes.last_mut().unwrap() ^= 0x01;
    assert_eq!(
        block_on(verify_signed(
            &bytes,
            &v,
            &VerifySignedParams {
                external_aad: ExternalAad::empty(),
                validation: None
            },
        ))
        .unwrap_err(),
        VerifyError::SignatureInvalid
    );
}

#[test]
fn es256_wrong_key_and_unknown_kid() {
    let s = es256_signer();
    let msg = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"x",
            claims: None,
            external_aad: ExternalAad::empty(),
        },
        &s,
    ))
    .unwrap();
    // Verifier knows a different P-256 key under the same kid: wrong key.
    let other = Es256Signer::from_secret_bytes(kid("alice"), &Zeroizing::new([9u8; 32])).unwrap();
    let v_wrong = P256Verifier::from_sec1(kid("alice"), &other.public_key_sec1()).unwrap();
    assert_eq!(
        block_on(verify_signed(
            msg.as_bytes(),
            &v_wrong,
            &VerifySignedParams {
                external_aad: ExternalAad::empty(),
                validation: None
            },
        ))
        .unwrap_err(),
        VerifyError::SignatureInvalid
    );
    // Verifier that does not know the kid.
    let v_unknown = P256Verifier::from_sec1(kid("carol"), &s.public_key_sec1()).unwrap();
    assert_eq!(
        block_on(verify_signed(
            msg.as_bytes(),
            &v_unknown,
            &VerifySignedParams {
                external_aad: ExternalAad::empty(),
                validation: None
            },
        ))
        .unwrap_err(),
        VerifyError::UnknownKeyId
    );
}

#[test]
fn signature_algorithm_verifiers_reject_the_other_algorithm() {
    // An ES256 message handed to an EdDSA verifier fails closed with an
    // algorithm mismatch (before any key lookup); and vice versa.
    let ecdsa_signer = es256_signer();
    let ecdsa_message = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"x",
            claims: None,
            external_aad: ExternalAad::empty(),
        },
        &ecdsa_signer,
    ))
    .unwrap();
    let dalek_signer = signer();
    let dalek_verifier =
        Ed25519Verifier::from_key(kid("alice"), &dalek_signer.public_key_bytes()).unwrap();
    assert_eq!(
        block_on(verify_signed(
            ecdsa_message.as_bytes(),
            &dalek_verifier,
            &VerifySignedParams {
                external_aad: ExternalAad::empty(),
                validation: None
            },
        ))
        .unwrap_err(),
        VerifyError::AlgorithmMismatch
    );

    let dalek_message = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"x",
            claims: None,
            external_aad: ExternalAad::empty(),
        },
        &dalek_signer,
    ))
    .unwrap();
    let ecdsa_verifier = es256_verifier_for(&ecdsa_signer);
    assert_eq!(
        block_on(verify_signed(
            dalek_message.as_bytes(),
            &ecdsa_verifier,
            &VerifySignedParams {
                external_aad: ExternalAad::empty(),
                validation: None
            },
        ))
        .unwrap_err(),
        VerifyError::AlgorithmMismatch
    );
}

#[test]
fn es256_sealed_round_trip() {
    // The sealed outer COSE_Sign1 may be signed with ES256 as well.
    let s = es256_signer();
    let v = es256_verifier_for(&s);
    let r = recipient();
    let msg = block_on(build_sealed(
        &seal_params(b"sealed es256", ContentAlgorithm::A256Gcm, r.public()),
        &s,
    ))
    .unwrap();
    let outer = codec::decode_sign1_strict(msg.as_bytes(), Sign1Layer::SealedOuter).unwrap();
    assert_eq!(outer.algorithm, SignatureAlgorithm::Es256);
    let verified = block_on(verify_sealed(
        msg.as_bytes(),
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Peer),
        },
    ))
    .unwrap();
    assert_eq!(verified.signer_key_id, kid("alice"));
    let opened = block_on(verified.open(&r, &ExternalAad::empty(), None)).unwrap();
    assert_eq!(opened.plaintext.as_slice(), b"sealed es256");
}

#[test]
fn es256_invalid_private_key_rejected() {
    // The all-zero scalar is not a valid P-256 signing key. `Es256Signer` is
    // not `Debug` (it holds secret material), so match the error arm directly.
    assert!(matches!(
        Es256Signer::from_secret_bytes(kid("alice"), &Zeroizing::new([0u8; 32])),
        Err(KeyError::InvalidPrivateKey)
    ));
}

// ---------------------------------------------------------------------------
// Sealed construction
// ---------------------------------------------------------------------------

#[test]
fn sealed_round_trip_both_algorithms() {
    for alg in [
        ContentAlgorithm::A256Gcm,
        ContentAlgorithm::ChaCha20Poly1305,
    ] {
        let s = signer();
        let v = verifier_for(&s);
        let r = recipient();
        let msg = block_on(build_sealed(
            &seal_params(b"secret payload", alg, r.public()),
            &s,
        ))
        .unwrap();
        let verified = block_on(verify_sealed(
            msg.as_bytes(),
            &v,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation(MessageRole::Peer),
            },
        ))
        .unwrap();
        assert_eq!(verified.signer_key_id, kid("alice"));
        assert_eq!(verified.recipient_key_id, kid("bob"));
        assert_eq!(verified.content_algorithm, alg);
        assert_eq!(verified.claims.sender_key_id, Some(kid("alice")));
        let opened = block_on(verified.open(&r, &ExternalAad::empty(), None)).unwrap();
        assert_eq!(opened.plaintext.as_slice(), b"secret payload");
        assert_eq!(opened.content_type, ct());
    }
}

#[test]
fn sealed_proof_key_header_round_trips_and_is_critical() {
    let public = Ed25519Signer::from_secret_bytes(kid("proof-kid"), &Zeroizing::new([11u8; 32]))
        .public_key_bytes();
    let mut cose_key = Vec::new();
    Encoder::new(&mut cose_key)
        .map(3)
        .unwrap()
        .i64(1)
        .unwrap()
        .i64(1)
        .unwrap()
        .i64(-1)
        .unwrap()
        .i64(6)
        .unwrap()
        .i64(-2)
        .unwrap()
        .bytes(&public)
        .unwrap();
    let signer = Ed25519Signer::from_secret_bytes(kid("proof-kid"), &Zeroizing::new([11u8; 32]));
    let mut params = seal_params(b"proof", ContentAlgorithm::A256Gcm, recipient().public());
    params.claims.sender_key_id = Some(signer.key_id().clone());
    params.claims.audience = Some(Subject::new("urn:basil:ci:jkt:test".to_string()).unwrap());
    let headers = ProtectedHeaders {
        signer_certificates_jwt: vec!["token".to_string()],
        signer_public_key_cose: Some(cose_key),
    };
    let message = block_on(build_sealed_with_headers(&params, &headers, &signer)).unwrap();
    let verified = block_on(verify_sealed(
        message.as_bytes(),
        &verifier_for(&signer),
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Peer),
        },
    ))
    .unwrap();
    assert_eq!(verified.protected_headers, headers);
}

#[test]
fn sealed_fresh_randomness_per_message() {
    let s = signer();
    let r = recipient();
    let a = block_on(build_sealed(
        &seal_params(b"same", ContentAlgorithm::A256Gcm, r.public()),
        &s,
    ))
    .unwrap();
    let b = block_on(build_sealed(
        &seal_params(b"same", ContentAlgorithm::A256Gcm, r.public()),
        &s,
    ))
    .unwrap();
    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn sealed_build_rejects_sender_mismatch_and_role_shape() {
    let s = signer();
    let r = recipient();
    let mut p = seal_params(b"x", ContentAlgorithm::A256Gcm, r.public());
    p.claims.sender_key_id = Some(kid("mallory"));
    assert_eq!(
        block_on(build_sealed(&p, &s)).unwrap_err(),
        BuildError::SenderKeyMismatch
    );
    let mut p = seal_params(b"x", ContentAlgorithm::A256Gcm, r.public());
    p.role = MessageRole::Request; // missing response_key_id
    assert!(matches!(
        block_on(build_sealed(&p, &s)).unwrap_err(),
        BuildError::RoleShape(ClaimsError::MissingClaim { .. })
    ));
}

#[test]
fn sealed_tampered_ciphertext_fails_signature() {
    let s = signer();
    let v = verifier_for(&s);
    let r = recipient();
    let msg = block_on(build_sealed(
        &seal_params(b"payload", ContentAlgorithm::A256Gcm, r.public()),
        &s,
    ))
    .unwrap();
    // Tamper one byte somewhere inside the embedded encrypt (the payload of
    // the outer Sign1 sits before the trailing 64-byte signature).
    let mut bytes = msg.into_vec();
    let idx = bytes.len() - 70;
    bytes[idx] ^= 0xFF;
    let err = block_on(verify_sealed(
        &bytes,
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Peer),
        },
    ))
    .unwrap_err();
    // Either strict decode of the embedded structure or the signature check
    // rejects, never an accept.
    assert!(matches!(
        err,
        VerifyError::SignatureInvalid | VerifyError::Decode(_)
    ));
}

#[test]
fn sealed_signature_aad_mismatch_fails() {
    let s = signer();
    let v = verifier_for(&s);
    let r = recipient();
    let mut p = seal_params(b"x", ContentAlgorithm::A256Gcm, r.public());
    p.aad = SealedAad {
        signature: ExternalAad::from_bytes(b"subject-a".to_vec()),
        encryption: ExternalAad::empty(),
    };
    let msg = block_on(build_sealed(&p, &s)).unwrap();
    let err = block_on(verify_sealed(
        msg.as_bytes(),
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::from_bytes(b"subject-b".to_vec()),
            validation: &validation(MessageRole::Peer),
        },
    ))
    .unwrap_err();
    assert_eq!(err, VerifyError::SignatureInvalid);
}

#[test]
fn sealed_encryption_aad_mismatch_fails_open() {
    let s = signer();
    let v = verifier_for(&s);
    let r = recipient();
    let mut p = seal_params(b"x", ContentAlgorithm::A256Gcm, r.public());
    p.aad = SealedAad {
        signature: ExternalAad::empty(),
        encryption: ExternalAad::from_bytes(b"purpose-v1".to_vec()),
    };
    let msg = block_on(build_sealed(&p, &s)).unwrap();
    let verified = block_on(verify_sealed(
        msg.as_bytes(),
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Peer),
        },
    ))
    .unwrap();
    // Right AAD opens.
    assert!(
        block_on(verified.open(&r, &ExternalAad::from_bytes(b"purpose-v1".to_vec()), None)).is_ok()
    );
    // Wrong AAD is an opaque open failure.
    assert_eq!(
        block_on(verified.open(&r, &ExternalAad::empty(), None)).unwrap_err(),
        OpenError::OpenFailed
    );
}

#[test]
fn sealed_wrong_recipient_key() {
    let s = signer();
    let v = verifier_for(&s);
    let r = recipient();
    let msg = block_on(build_sealed(
        &seal_params(b"x", ContentAlgorithm::A256Gcm, r.public()),
        &s,
    ))
    .unwrap();
    let verified = block_on(verify_sealed(
        msg.as_bytes(),
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Peer),
        },
    ))
    .unwrap();
    // Different key id: rejected before any crypto.
    let other_id = X25519Recipient::new(kid("carol"), Zeroizing::new([9u8; 32]));
    assert_eq!(
        block_on(verified.open(&other_id, &ExternalAad::empty(), None)).unwrap_err(),
        OpenError::RecipientKeyMismatch
    );
    // Right key id, wrong private key: opaque open failure.
    let wrong_key = X25519Recipient::new(kid("bob"), Zeroizing::new([42u8; 32]));
    assert_eq!(
        block_on(verified.open(&wrong_key, &ExternalAad::empty(), None)).unwrap_err(),
        OpenError::OpenFailed
    );
}

#[test]
fn sealed_expired_and_future_iat_rejected() {
    let s = signer();
    let v = verifier_for(&s);
    let r = recipient();
    let msg = block_on(build_sealed(
        &seal_params(b"x", ContentAlgorithm::A256Gcm, r.public()),
        &s,
    ))
    .unwrap();
    for (now, expected) in [
        (2_000, ClaimsError::Expired),
        (900, ClaimsError::IssuedInFuture),
    ] {
        let mut val = validation(MessageRole::Peer);
        val.now = UnixTime(now);
        let err = block_on(verify_sealed(
            msg.as_bytes(),
            &v,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &val,
            },
        ))
        .unwrap_err();
        assert_eq!(err, VerifyError::Claims(expected));
    }
}

#[test]
fn sealed_audience_enforcement_end_to_end() {
    let s = signer();
    let v = verifier_for(&s);
    let r = recipient();
    let mut p = seal_params(b"x", ContentAlgorithm::A256Gcm, r.public());
    p.claims.audience = Some(Subject::new("svc-b".to_string()).unwrap());
    let msg = block_on(build_sealed(&p, &s)).unwrap();
    let mut val = validation(MessageRole::Peer);
    val.allowed_audiences
        .insert(Subject::new("svc-a".to_string()).unwrap());
    let err = block_on(verify_sealed(
        msg.as_bytes(),
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &val,
        },
    ))
    .unwrap_err();
    assert_eq!(err, VerifyError::Claims(ClaimsError::AudienceRejected));
}

#[test]
fn sealed_request_response_roles_round_trip() {
    let s = signer();
    let v = verifier_for(&s);
    let r = recipient();
    // Request: requires sender + response key id.
    let mut p = seal_params(b"req", ContentAlgorithm::A256Gcm, r.public());
    p.role = MessageRole::Request;
    p.claims.response_key_id = Some(kid("alice-response"));
    p.claims.response_subject = Some(ResponseSubject::new("inbox.alice".to_string()).unwrap());
    let req = block_on(build_sealed(&p, &s)).unwrap();
    let verified = block_on(verify_sealed(
        req.as_bytes(),
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Request),
        },
    ))
    .unwrap();
    assert_eq!(verified.claims.response_key_id, Some(kid("alice-response")));

    // Response: correlates via in_reply_to + request hash.
    let mut p = seal_params(b"resp", ContentAlgorithm::A256Gcm, r.public());
    p.role = MessageRole::Response;
    p.claims.in_reply_to = Some(verified.claims.message_id);
    p.claims.request_hash = Some(request_hash(req.as_bytes()));
    let resp = block_on(build_sealed(&p, &s)).unwrap();
    let verified_resp = block_on(verify_sealed(
        resp.as_bytes(),
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Response),
        },
    ))
    .unwrap();
    assert_eq!(
        verified_resp.claims.request_hash,
        Some(request_hash(req.as_bytes()))
    );
    // A response validated as a request fails the role shape (a response has
    // no -70004, which the request role requires).
    assert_eq!(
        block_on(verify_sealed(
            resp.as_bytes(),
            &v,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation(MessageRole::Request),
            },
        ))
        .unwrap_err(),
        VerifyError::Claims(ClaimsError::MissingClaim {
            label: label::RESPONSE_KEY_ID
        })
    );
    // And a request validated as a response carries forbidden labels.
    assert!(matches!(
        block_on(verify_sealed(
            req.as_bytes(),
            &v,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation(MessageRole::Response),
            },
        ))
        .unwrap_err(),
        VerifyError::Claims(ClaimsError::MissingClaim { .. } | ClaimsError::ForbiddenClaim { .. })
    ));
}

#[test]
fn sealed_request_freshness_challenge_round_trips() {
    let s = signer();
    let v = verifier_for(&s);
    let r = recipient();
    let mut challenge_bytes = [0x41_u8; 32];
    challenge_bytes[0] = 0x01; // distinct instance-ID prefix byte
    let challenge = FreshnessChallenge::new(challenge_bytes);

    let mut p = seal_params(b"req", ContentAlgorithm::A256Gcm, r.public());
    p.role = MessageRole::Request;
    p.claims.response_key_id = Some(kid("alice-response"));
    p.claims.freshness_challenge = Some(challenge);
    let req = block_on(build_sealed(&p, &s)).unwrap();

    // The challenge is signature-trusted and readable pre-decrypt.
    let verified = block_on(verify_sealed(
        req.as_bytes(),
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Request),
        },
    ))
    .unwrap();
    assert_eq!(verified.claims.freshness_challenge, Some(challenge));
    assert_eq!(
        verified
            .claims
            .freshness_challenge
            .as_ref()
            .map(|c| *c.as_bytes()),
        Some(challenge_bytes)
    );

    // The strict decoder re-encodes and byte-compares, so a verified message
    // proves the -70008 claim encoding (position and crit entry) canonical.
    let opened = block_on(verified.open(&r, &ExternalAad::empty(), None)).unwrap();
    assert_eq!(opened.plaintext.as_slice(), b"req");

    // A request without the claim stays valid: the shape is optional at the
    // profile layer; the broker enforces presence for remote CI requests.
    let mut p = seal_params(b"req", ContentAlgorithm::A256Gcm, r.public());
    p.role = MessageRole::Request;
    p.claims.response_key_id = Some(kid("alice-response"));
    let bare = block_on(build_sealed(&p, &s)).unwrap();
    let verified_bare = block_on(verify_sealed(
        bare.as_bytes(),
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Request),
        },
    ))
    .unwrap();
    assert_eq!(verified_bare.claims.freshness_challenge, None);
}

fn response_public_key() -> X25519ResponsePublicKey {
    let mut public = [0; 32];
    public[0] = 9;
    X25519ResponsePublicKey::from_public_bytes(public).unwrap()
}

#[test]
fn sealed_request_response_public_key_is_exact_and_critical() {
    let s = signer();
    let v = verifier_for(&s);
    let r = recipient();
    let response_public = response_public_key();
    let mut p = seal_params(b"req", ContentAlgorithm::A256Gcm, r.public());
    p.role = MessageRole::Request;
    p.claims.response_key_id = Some(kid(&response_public.thumbprint()));
    p.claims.freshness_challenge = Some(FreshnessChallenge::new([0x41; 32]));
    p.claims.response_public_key_cose = Some(response_public);
    let req = block_on(build_sealed(&p, &s)).unwrap();

    let outer = codec::decode_sign1_strict(req.as_bytes(), codec::Sign1Layer::SealedOuter).unwrap();
    let embedded =
        codec::decode_encrypt_strict(&outer.payload, codec::ClaimsExpectation::Required).unwrap();
    let encoded_key = response_public.to_cose_key_bytes();
    assert!(
        embedded
            .protected
            .windows(encoded_key.len())
            .any(|window| window == encoded_key)
    );
    assert_eq!(
        embedded
            .claims
            .as_ref()
            .and_then(|claims| claims.response_public_key_cose),
        Some(response_public)
    );

    let verified = block_on(verify_sealed(
        req.as_bytes(),
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Request),
        },
    ))
    .unwrap();
    assert_eq!(
        verified.claims.response_public_key_cose,
        Some(response_public)
    );

    // Mutate the first -70009 occurrence (the crit entry) to -70008 while
    // leaving the actual map member intact. Strict decode must diagnose the
    // missing critical declaration before any authenticated opening.
    let mut response_label = Vec::new();
    minicbor::Encoder::new(&mut response_label)
        .i64(label::RESPONSE_PUBLIC_KEY_COSE)
        .unwrap();
    let mut freshness_label = Vec::new();
    minicbor::Encoder::new(&mut freshness_label)
        .i64(label::FRESHNESS_CHALLENGE)
        .unwrap();
    let mut mutated_protected = embedded.protected.clone();
    let offset = mutated_protected
        .windows(response_label.len())
        .position(|window| window == response_label)
        .unwrap();
    mutated_protected[offset..offset + response_label.len()].copy_from_slice(&freshness_label);
    let mutated = codec::assemble_encrypt(&codec::EncryptAssembly {
        protected: &mutated_protected,
        iv: &embedded.iv,
        ciphertext: &embedded.ciphertext,
        recipient_protected: &embedded.recipient_protected,
        recipient_kid: &embedded.recipient_kid,
        ephemeral_x: &embedded.ephemeral_x,
    })
    .unwrap();
    assert_eq!(
        codec::decode_encrypt_strict(&mutated, codec::ClaimsExpectation::Required).unwrap_err(),
        DecodeError::CritIncomplete {
            label: label::RESPONSE_PUBLIC_KEY_COSE
        }
    );
}

#[test]
fn strict_decoder_rejects_response_key_id_and_public_key_substitution() {
    let s = signer();
    let r = recipient();
    let response_public = response_public_key();
    let mut p = seal_params(b"req", ContentAlgorithm::A256Gcm, r.public());
    p.role = MessageRole::Request;
    p.claims.response_key_id = Some(kid(&response_public.thumbprint()));
    p.claims.response_public_key_cose = Some(response_public);
    let req = block_on(build_sealed(&p, &s)).unwrap();
    let outer = codec::decode_sign1_strict(req.as_bytes(), codec::Sign1Layer::SealedOuter).unwrap();
    let embedded =
        codec::decode_encrypt_strict(&outer.payload, codec::ClaimsExpectation::Required).unwrap();

    // Keep the protected map structurally canonical but substitute one ASCII
    // byte in the response key id. Strict decoding must reject the binding at
    // the codec boundary, before signature verification or opening.
    let thumbprint = response_public.thumbprint();
    let mut mismatched_protected = embedded.protected.clone();
    let id_offset = mismatched_protected
        .windows(thumbprint.len())
        .position(|window| window == thumbprint.as_bytes())
        .unwrap();
    mismatched_protected[id_offset] ^= 1;
    let mismatched = codec::assemble_encrypt(&codec::EncryptAssembly {
        protected: &mismatched_protected,
        iv: &embedded.iv,
        ciphertext: &embedded.ciphertext,
        recipient_protected: &embedded.recipient_protected,
        recipient_kid: &embedded.recipient_kid,
        ephemeral_x: &embedded.ephemeral_x,
    })
    .unwrap();
    assert_eq!(
        codec::decode_encrypt_strict(&mismatched, codec::ClaimsExpectation::Required).unwrap_err(),
        DecodeError::ResponseKeyIdMismatch
    );

    // Substituting a different valid X25519 key under the unchanged key id
    // is the symmetric attack and must fail at the same boundary.
    let encoded_key = response_public.to_cose_key_bytes();
    let substituted_public =
        X25519ResponsePublicKey::from_public_bytes(recipient().public().public).unwrap();
    assert_ne!(substituted_public, response_public);
    let mut substituted_protected = embedded.protected.clone();
    let key_offset = substituted_protected
        .windows(encoded_key.len())
        .position(|window| window == encoded_key)
        .unwrap();
    substituted_protected[key_offset..key_offset + encoded_key.len()]
        .copy_from_slice(&substituted_public.to_cose_key_bytes());
    let substituted = codec::assemble_encrypt(&codec::EncryptAssembly {
        protected: &substituted_protected,
        iv: &embedded.iv,
        ciphertext: &embedded.ciphertext,
        recipient_protected: &embedded.recipient_protected,
        recipient_kid: &embedded.recipient_kid,
        ephemeral_x: &embedded.ephemeral_x,
    })
    .unwrap();
    assert_eq!(
        codec::decode_encrypt_strict(&substituted, codec::ClaimsExpectation::Required).unwrap_err(),
        DecodeError::ResponseKeyIdMismatch
    );
}

#[test]
fn protected_encoder_rejects_response_key_id_substitution() {
    let response_public = response_public_key();
    let mut claims = peer_claims(&kid("alice"));
    claims.response_key_id = Some(kid("substituted-catalog-key"));
    claims.response_public_key_cose = Some(response_public);
    assert_eq!(
        codec::encode_encrypt_protected(ContentAlgorithm::A256Gcm, &ct(), Some(&claims),),
        Err(codec::CodecError)
    );
}

#[test]
fn legacy_request_protected_bytes_are_unchanged_without_response_public_key() {
    let mut claims = peer_claims(&kid("alice"));
    claims.response_key_id = Some(kid("alice-response"));
    let protected =
        codec::encode_encrypt_protected(ContentAlgorithm::A256Gcm, &ct(), Some(&claims)).unwrap();
    // Frozen revision-4.1 bytes. Adding an absent optional field must not
    // perturb existing catalog-mode request signatures or ciphertext AAD.
    assert_eq!(
        protected,
        vec![
            166, 1, 3, 2, 132, 3, 15, 58, 0, 1, 17, 114, 58, 0, 1, 17, 115, 3, 118, 97, 112, 112,
            108, 105, 99, 97, 116, 105, 111, 110, 47, 98, 97, 115, 105, 108, 46, 116, 101, 115,
            116, 15, 162, 6, 25, 3, 232, 7, 66, 171, 205, 58, 0, 1, 17, 114, 69, 97, 108, 105, 99,
            101, 58, 0, 1, 17, 115, 110, 97, 108, 105, 99, 101, 45, 114, 101, 115, 112, 111, 110,
            115, 101,
        ]
    );
}

#[test]
fn response_public_key_is_rejected_on_bare_signed_layer() {
    let s = signer();
    let response_public = response_public_key();
    let mut claims = peer_claims(s.key_id());
    claims.response_key_id = Some(kid(&response_public.thumbprint()));
    claims.response_public_key_cose = Some(response_public);
    assert_eq!(
        block_on(build_signed(
            &SignParams {
                content_type: ct(),
                payload: b"not encrypted",
                claims: Some(claims),
                external_aad: ExternalAad::empty(),
            },
            &s,
        ))
        .unwrap_err(),
        BuildError::ResponsePublicKeyRequiresEncryption
    );
}

#[test]
fn strict_decoder_rejects_canonical_bare_sign1_with_response_public_key() {
    let s = signer();
    let response_public = response_public_key();
    let mut claims = peer_claims(s.key_id());
    claims.response_key_id = Some(kid(&response_public.thumbprint()));
    claims.response_public_key_cose = Some(response_public);

    // Bypass the public signed-message builder and manually assemble a
    // structurally canonical bare COSE_Sign1. The protected encoder is used
    // only to obtain deterministic map bytes; the signature is deliberately
    // opaque because strict shape rejection precedes signature verification.
    let protected = codec::encode_sign1_protected_bare_with_headers(
        SignatureAlgorithm::EdDsa,
        s.key_id(),
        &ct(),
        Some(&claims),
        None,
    )
    .unwrap();
    let message = codec::assemble_sign1(&protected, b"payload", &[0x5a; 64]).unwrap();
    assert_eq!(
        codec::decode_sign1_strict(&message, codec::Sign1Layer::Bare).unwrap_err(),
        DecodeError::UnknownLabel {
            label: label::RESPONSE_PUBLIC_KEY_COSE
        }
    );
}

#[test]
fn freshness_challenge_is_forbidden_outside_requests() {
    let challenge = FreshnessChallenge::new([0x41; 32]);

    // Response role.
    let mut c = peer_claims(&kid("alice"));
    c.in_reply_to = Some(MessageId::from_bytes(vec![1]).unwrap());
    c.request_hash = Some(RequestHash([0; 32]));
    c.freshness_challenge = Some(challenge);
    assert_eq!(
        c.validate_role(MessageRole::Response),
        Err(ClaimsError::ForbiddenClaim {
            label: label::FRESHNESS_CHALLENGE
        })
    );

    // Peer role.
    let mut c = peer_claims(&kid("alice"));
    c.freshness_challenge = Some(challenge);
    assert_eq!(
        c.validate_role(MessageRole::Peer),
        Err(ClaimsError::ForbiddenClaim {
            label: label::FRESHNESS_CHALLENGE
        })
    );

    // Building a sealed response carrying the claim is rejected before any
    // crypto.
    let s = signer();
    let r = recipient();
    let mut p = seal_params(b"resp", ContentAlgorithm::A256Gcm, r.public());
    p.role = MessageRole::Response;
    p.claims.in_reply_to = Some(MessageId::from_bytes(vec![1]).unwrap());
    p.claims.request_hash = Some(RequestHash([0; 32]));
    p.claims.freshness_challenge = Some(challenge);
    assert_eq!(
        block_on(build_sealed(&p, &s)).unwrap_err(),
        BuildError::RoleShape(ClaimsError::ForbiddenClaim {
            label: label::FRESHNESS_CHALLENGE
        })
    );
}

#[test]
fn freshness_challenge_wire_length_is_exactly_32_bytes() {
    assert!(FreshnessChallenge::from_bytes(&[0x41; 32]).is_ok());
    for wrong in [0_usize, 16, 31, 33, 64] {
        assert_eq!(
            FreshnessChallenge::from_bytes(&vec![0x41; wrong]),
            Err(ProfileError::FreshnessChallengeLength { actual: wrong }),
            "{wrong}"
        );
    }
}

#[test]
fn signed_request_orders_freshness_challenge_after_signer_headers() {
    // In a bare signed message the claims and the -70006/-70007 signer
    // headers share one protected map; -70008 must sort after both or the
    // strict decoder's re-encode comparison rejects the message.
    let s = signer();
    let v = verifier_for(&s);
    let mut claims = peer_claims(s.key_id());
    claims.response_key_id = Some(kid("alice-response"));
    claims.freshness_challenge = Some(FreshnessChallenge::new([0x42; 32]));
    let protected_headers = ProtectedHeaders {
        signer_certificates_jwt: vec!["eyJhbGciOiJFZERTQSJ9.cert.one.sig".to_string()],
        signer_public_key_cose: Some(vec![0xA0]),
    };
    let msg = block_on(build_signed_with_headers(
        &SignParams {
            content_type: ct(),
            payload: b"hello",
            claims: Some(claims),
            external_aad: ExternalAad::empty(),
        },
        &protected_headers,
        &s,
    ))
    .unwrap();
    let out = block_on(verify_signed(
        msg.as_bytes(),
        &v,
        &VerifySignedParams {
            external_aad: ExternalAad::empty(),
            validation: Some(&validation(MessageRole::Request)),
        },
    ))
    .unwrap();
    assert_eq!(
        out.claims.as_ref().and_then(|c| c.freshness_challenge),
        Some(FreshnessChallenge::new([0x42; 32]))
    );
    assert_eq!(out.protected_headers, protected_headers);
}

// ---------------------------------------------------------------------------
// Seal-only construction
// ---------------------------------------------------------------------------

fn encrypt_params(plaintext: &[u8], alg: ContentAlgorithm) -> EncryptParams<'_> {
    EncryptParams {
        content_type: ct(),
        plaintext,
        recipient: recipient().public(),
        content_algorithm: alg,
        external_aad: ExternalAad::empty(),
        kdf_parties: KdfParties::anonymous(),
    }
}

#[test]
fn seal_only_round_trip_both_algorithms() {
    for alg in [
        ContentAlgorithm::A256Gcm,
        ContentAlgorithm::ChaCha20Poly1305,
    ] {
        let r = recipient();
        let msg = build_encrypted(&encrypt_params(b"enrollment", alg)).unwrap();
        let decoded = decode_encrypted(msg.as_bytes()).unwrap();
        assert_eq!(decoded.recipient_key_id, kid("bob"));
        assert_eq!(decoded.content_algorithm, alg);
        let opened = block_on(decoded.open(&r, &ExternalAad::empty(), None)).unwrap();
        assert_eq!(opened.plaintext.as_slice(), b"enrollment");
    }
}

#[test]
fn seal_only_party_identities_round_trip_and_pinning() {
    let r = recipient();
    let parties = KdfParties {
        party_u: PartyIdentity::from_bytes(b"d2h".to_vec()).unwrap(),
        party_v: PartyIdentity::from_bytes(b"h2d".to_vec()).unwrap(),
    };
    let mut p = encrypt_params(b"directional", ContentAlgorithm::ChaCha20Poly1305);
    p.kdf_parties = parties.clone();
    let msg = build_encrypted(&p).unwrap();
    let decoded = decode_encrypted(msg.as_bytes()).unwrap();
    assert_eq!(decoded.parties, parties);
    // Pinned match opens; pinned mismatch is rejected before crypto.
    assert!(block_on(decoded.open(&r, &ExternalAad::empty(), Some(&parties))).is_ok());
    let wrong = KdfParties {
        party_u: PartyIdentity::from_bytes(b"h2d".to_vec()).unwrap(),
        party_v: PartyIdentity::from_bytes(b"d2h".to_vec()).unwrap(),
    };
    assert_eq!(
        block_on(decoded.open(&r, &ExternalAad::empty(), Some(&wrong))).unwrap_err(),
        OpenError::PartyMismatch
    );
}

#[test]
fn seal_only_party_identities_bind_the_kdf() {
    // Same bytes, different wire parties => different derived CEK => open fails.
    let r = recipient();
    let parties = KdfParties {
        party_u: PartyIdentity::from_bytes(b"d2h".to_vec()).unwrap(),
        party_v: PartyIdentity::nil(),
    };
    let mut p = encrypt_params(b"directional", ContentAlgorithm::A256Gcm);
    p.kdf_parties = parties;
    let msg = build_encrypted(&p).unwrap();
    // Re-assemble the message with the party identity stripped from the
    // recipient protected header: strict decode succeeds (it is a valid
    // canonical message) but the KDF context no longer matches.
    let d = codec::decode_encrypt_strict(msg.as_bytes(), ClaimsExpectation::Forbidden).unwrap();
    let stripped = codec::encode_recipient_protected(&KdfParties::anonymous()).unwrap();
    let forged = codec::assemble_encrypt(&codec::EncryptAssembly {
        protected: &d.protected,
        iv: &d.iv,
        ciphertext: &d.ciphertext,
        recipient_protected: &stripped,
        recipient_kid: &d.recipient_kid,
        ephemeral_x: &d.ephemeral_x,
    })
    .unwrap();
    let decoded = decode_encrypted(&forged).unwrap();
    assert_eq!(
        block_on(decoded.open(&r, &ExternalAad::empty(), None)).unwrap_err(),
        OpenError::OpenFailed
    );
}

#[test]
fn seal_only_tampered_ciphertext_and_aad() {
    let r = recipient();
    let mut p = encrypt_params(b"data", ContentAlgorithm::A256Gcm);
    p.external_aad = ExternalAad::from_bytes(b"ctx".to_vec());
    let msg = build_encrypted(&p).unwrap();
    let decoded = decode_encrypted(msg.as_bytes()).unwrap();
    // Wrong AAD.
    assert_eq!(
        block_on(decoded.open(&r, &ExternalAad::empty(), None)).unwrap_err(),
        OpenError::OpenFailed
    );
    // Tampered ciphertext: re-assemble with one flipped byte.
    let d = codec::decode_encrypt_strict(msg.as_bytes(), ClaimsExpectation::Forbidden).unwrap();
    let mut ciphertext = d.ciphertext.clone();
    ciphertext[0] ^= 0xFF;
    let forged = codec::assemble_encrypt(&codec::EncryptAssembly {
        protected: &d.protected,
        iv: &d.iv,
        ciphertext: &ciphertext,
        recipient_protected: &d.recipient_protected,
        recipient_kid: &d.recipient_kid,
        ephemeral_x: &d.ephemeral_x,
    })
    .unwrap();
    let decoded = decode_encrypted(&forged).unwrap();
    assert_eq!(
        block_on(decoded.open(&r, &ExternalAad::from_bytes(b"ctx".to_vec()), None)).unwrap_err(),
        OpenError::OpenFailed
    );
}

#[test]
fn low_order_ephemeral_rejected_on_open() {
    // An all-zero ephemeral is the canonical low-order point: the shared
    // secret is non-contributory, forcing a known AEAD key. The open must
    // fail closed BEFORE the AEAD step, with the opaque error.
    let r = recipient();
    let msg = build_encrypted(&encrypt_params(b"x", ContentAlgorithm::A256Gcm)).unwrap();
    let d = codec::decode_encrypt_strict(msg.as_bytes(), ClaimsExpectation::Forbidden).unwrap();
    let forged = codec::assemble_encrypt(&codec::EncryptAssembly {
        protected: &d.protected,
        iv: &d.iv,
        ciphertext: &d.ciphertext,
        recipient_protected: &d.recipient_protected,
        recipient_kid: &d.recipient_kid,
        ephemeral_x: &[0u8; 32],
    })
    .unwrap();
    let decoded = decode_encrypted(&forged).unwrap();
    assert_eq!(
        block_on(decoded.open(&r, &ExternalAad::empty(), None)).unwrap_err(),
        OpenError::OpenFailed
    );
}

#[test]
fn seal_only_rejects_claims_bearing_message() {
    // The embedded encrypt of a sealed message carries claims; the seal-only
    // decoder must reject it.
    let s = signer();
    let r = recipient();
    let msg = block_on(build_sealed(
        &seal_params(b"x", ContentAlgorithm::A256Gcm, r.public()),
        &s,
    ))
    .unwrap();
    let outer = codec::decode_sign1_strict(msg.as_bytes(), Sign1Layer::SealedOuter).unwrap();
    let err = decode_encrypted(&outer.payload).unwrap_err();
    assert_eq!(
        err,
        DecodeError::UnknownLabel {
            label: label::HDR_CWT_CLAIMS
        }
    );
}

// ---------------------------------------------------------------------------
// Encoding strictness (hostile bytes)
// ---------------------------------------------------------------------------

fn valid_signed() -> Vec<u8> {
    block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"p",
            claims: Some(peer_claims(&kid("alice"))),
            external_aad: ExternalAad::empty(),
        },
        &signer(),
    ))
    .unwrap()
    .into_vec()
}

fn verify_bytes(bytes: &[u8]) -> Result<VerifiedSigned, VerifyError> {
    let s = signer();
    let v = verifier_for(&s);
    let val = validation(MessageRole::Peer);
    block_on(verify_signed(
        bytes,
        &v,
        &VerifySignedParams {
            external_aad: ExternalAad::empty(),
            validation: Some(&val),
        },
    ))
}

#[test]
fn strict_rejects_untagged_and_wrong_tag() {
    let bytes = valid_signed();
    // Tag 18 encodes as a single 0xD2 head byte; stripping it untags.
    assert_eq!(bytes[0], 0xD2);
    assert_eq!(
        verify_bytes(&bytes[1..]).unwrap_err(),
        VerifyError::Decode(DecodeError::NotTagged)
    );
    // Replace with tag 97 (0xD8 0x61).
    let mut wrong = vec![0xD8, 0x61];
    wrong.extend_from_slice(&bytes[1..]);
    assert_eq!(
        verify_bytes(&wrong).unwrap_err(),
        VerifyError::Decode(DecodeError::WrongTag {
            expected: 18,
            actual: 97
        })
    );
    // A COSE_Encrypt where a COSE_Sign1 is expected.
    let enc = build_encrypted(&encrypt_params(b"x", ContentAlgorithm::A256Gcm))
        .unwrap()
        .into_vec();
    assert!(matches!(
        verify_bytes(&enc).unwrap_err(),
        VerifyError::Decode(DecodeError::WrongTag {
            expected: 18,
            actual: 96
        })
    ));
}

#[test]
fn strict_rejects_indefinite_length() {
    let bytes = valid_signed();
    // Definite 4-array (0x84) after the tag -> indefinite array + break.
    assert_eq!(bytes[1], 0x84);
    let mut hostile = bytes;
    hostile[1] = 0x9F;
    hostile.push(0xFF);
    assert_eq!(
        verify_bytes(&hostile).unwrap_err(),
        VerifyError::Decode(DecodeError::IndefiniteLength)
    );
}

#[test]
fn strict_rejects_non_minimal_encoding() {
    let bytes = valid_signed();
    // Re-encode the 4-array head with a one-byte argument (0x98 0x04).
    let mut hostile = vec![bytes[0], 0x98, 0x04];
    hostile.extend_from_slice(&bytes[2..]);
    assert_eq!(
        verify_bytes(&hostile).unwrap_err(),
        VerifyError::Decode(DecodeError::NonMinimalEncoding)
    );
}

/// Hand-assemble a tagged `COSE_Sign1` from raw parts (no canonicality).
fn raw_sign1(protected: &[u8], unprotected: impl FnOnce(&mut Encoder<&mut Vec<u8>>)) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.tag(minicbor::data::Tag::new(18)).unwrap();
    e.array(4).unwrap();
    e.bytes(protected).unwrap();
    unprotected(&mut e);
    e.bytes(b"payload").unwrap();
    e.bytes(&[0u8; 64]).unwrap();
    out
}

fn sealed_outer_protected(alg: i64, kid_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.map(2).unwrap();
    e.i64(1).unwrap();
    e.i64(alg).unwrap();
    e.i64(4).unwrap();
    e.bytes(kid_bytes).unwrap();
    out
}

#[test]
fn strict_rejects_duplicate_labels() {
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(2).unwrap();
    e.i64(1).unwrap();
    e.i64(-8).unwrap();
    e.i64(1).unwrap();
    e.i64(-8).unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::DuplicateLabel
    );
}

#[test]
fn strict_rejects_non_canonical_label_order() {
    // {4: kid, 1: -8}: labels out of canonical order.
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(2).unwrap();
    e.i64(4).unwrap();
    e.bytes(b"alice").unwrap();
    e.i64(1).unwrap();
    e.i64(-8).unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::NonDeterministicEncoding
    );
}

#[test]
fn strict_rejects_unknown_and_text_labels() {
    // Unknown integer label 99 in a sealed-outer protected header.
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(3).unwrap();
    e.i64(1).unwrap();
    e.i64(-8).unwrap();
    e.i64(4).unwrap();
    e.bytes(b"alice").unwrap();
    e.i64(99).unwrap();
    e.i64(1).unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::UnknownLabel { label: 99 }
    );

    // Text label.
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(1).unwrap();
    e.str("alg").unwrap();
    e.i64(-8).unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::TextLabel
    );
}

#[test]
fn strict_rejects_unknown_algorithm() {
    // ES384 (-35) is a registered COSE algorithm but outside the profile
    // allow-set (which admits EdDSA/-8 and ES256/-7 only).
    let protected = sealed_outer_protected(-35, b"alice");
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::UnknownAlgorithm { alg: -35 }
    );
}

#[test]
fn strict_rejects_wrong_type_for_known_label() {
    // alg as a text value.
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(2).unwrap();
    e.i64(1).unwrap();
    e.str("EdDSA").unwrap();
    e.i64(4).unwrap();
    e.bytes(b"alice").unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::WrongType { label: 1 }
    );
}

#[test]
fn strict_rejects_claims_in_unprotected() {
    let protected = sealed_outer_protected(-8, b"alice");
    // Unprotected {15: {}}.
    let bytes = raw_sign1(&protected, |e| {
        e.map(1).unwrap();
        e.i64(15).unwrap();
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::ClaimsInUnprotected
    );
    // A basil label in unprotected is likewise claims-in-unprotected.
    let bytes = raw_sign1(&protected, |e| {
        e.map(1).unwrap();
        e.i64(label::SENDER_KEY_ID).unwrap();
        e.bytes(b"alice").unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::ClaimsInUnprotected
    );
    // Any other unprotected header is an unknown label.
    let bytes = raw_sign1(&protected, |e| {
        e.map(1).unwrap();
        e.i64(33).unwrap();
        e.bytes(b"x5chain?").unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::UnknownLabel { label: 33 }
    );
}

#[test]
fn strict_rejects_missing_payload_and_missing_headers() {
    let protected = sealed_outer_protected(-8, b"alice");
    // Null payload (detached).
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.tag(minicbor::data::Tag::new(18)).unwrap();
    e.array(4).unwrap();
    e.bytes(&protected).unwrap();
    e.map(0).unwrap();
    e.null().unwrap();
    e.bytes(&[0u8; 64]).unwrap();
    assert_eq!(
        codec::decode_sign1_strict(&out, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::MissingPayload
    );

    // Missing alg.
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(1).unwrap();
    e.i64(4).unwrap();
    e.bytes(b"alice").unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::MissingHeader { label: 1 }
    );

    // Empty protected header bstr.
    let bytes = raw_sign1(&[], |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::SealedOuter).unwrap_err(),
        DecodeError::MissingHeader { label: 1 }
    );
}

#[test]
fn strict_rejects_crit_violations() {
    // Bare header without crit.
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(3).unwrap();
    e.i64(1).unwrap();
    e.i64(-8).unwrap();
    e.i64(3).unwrap();
    e.str("application/basil.test").unwrap();
    e.i64(4).unwrap();
    e.bytes(b"alice").unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::Bare).unwrap_err(),
        DecodeError::CritMissing
    );

    // Crit listing a label the profile does not place here.
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(4).unwrap();
    e.i64(1).unwrap();
    e.i64(-8).unwrap();
    e.i64(2).unwrap();
    e.array(2).unwrap();
    e.i64(3).unwrap();
    e.i64(-70001).unwrap();
    e.i64(3).unwrap();
    e.str("application/basil.test").unwrap();
    e.i64(4).unwrap();
    e.bytes(b"alice").unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::Bare).unwrap_err(),
        DecodeError::CritUnexpected { label: -70001 }
    );
}

#[test]
fn strict_rejects_crit_incomplete() {
    // Claims present with -70003 but crit only lists [3, 15].
    let s = signer();
    let msg = block_on(build_signed(
        &SignParams {
            content_type: ct(),
            payload: b"p",
            claims: Some(peer_claims(&kid("alice"))),
            external_aad: ExternalAad::empty(),
        },
        &s,
    ))
    .unwrap();
    let decoded = codec::decode_sign1_strict(msg.as_bytes(), Sign1Layer::Bare).unwrap();
    // Rebuild the protected header with a truncated crit: hand-encode.
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(6).unwrap();
    e.i64(1).unwrap();
    e.i64(-8).unwrap();
    e.i64(2).unwrap();
    e.array(2).unwrap();
    e.i64(3).unwrap();
    e.i64(15).unwrap();
    e.i64(3).unwrap();
    e.str("application/basil.test").unwrap();
    e.i64(4).unwrap();
    e.bytes(b"alice").unwrap();
    e.i64(15).unwrap();
    e.map(2).unwrap();
    e.i64(6).unwrap();
    e.i64(1_000).unwrap();
    e.i64(7).unwrap();
    e.bytes(&[0xAB, 0xCD]).unwrap();
    e.i64(label::SENDER_KEY_ID).unwrap();
    e.bytes(b"alice").unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::Bare).unwrap_err(),
        DecodeError::CritIncomplete {
            label: label::SENDER_KEY_ID
        }
    );
    drop(decoded);
}

#[test]
fn strict_rejects_cwt_violations() {
    // Unknown CWT claim key (2 = sub).
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(5).unwrap();
    e.i64(1).unwrap();
    e.i64(-8).unwrap();
    e.i64(2).unwrap();
    e.array(2).unwrap();
    e.i64(3).unwrap();
    e.i64(15).unwrap();
    e.i64(3).unwrap();
    e.str("a/b").unwrap();
    e.i64(4).unwrap();
    e.bytes(b"alice").unwrap();
    e.i64(15).unwrap();
    e.map(3).unwrap();
    e.i64(2).unwrap();
    e.str("sub").unwrap();
    e.i64(6).unwrap();
    e.i64(1_000).unwrap();
    e.i64(7).unwrap();
    e.bytes(&[1]).unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::Bare).unwrap_err(),
        DecodeError::UnknownClaim { claim: 2 }
    );

    // Missing iat.
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(5).unwrap();
    e.i64(1).unwrap();
    e.i64(-8).unwrap();
    e.i64(2).unwrap();
    e.array(2).unwrap();
    e.i64(3).unwrap();
    e.i64(15).unwrap();
    e.i64(3).unwrap();
    e.str("a/b").unwrap();
    e.i64(4).unwrap();
    e.bytes(b"alice").unwrap();
    e.i64(15).unwrap();
    e.map(1).unwrap();
    e.i64(7).unwrap();
    e.bytes(&[1]).unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::Bare).unwrap_err(),
        DecodeError::MissingClaim { claim: 6 }
    );

    // Fractional iat.
    let mut protected = Vec::new();
    let mut e = Encoder::new(&mut protected);
    e.map(5).unwrap();
    e.i64(1).unwrap();
    e.i64(-8).unwrap();
    e.i64(2).unwrap();
    e.array(2).unwrap();
    e.i64(3).unwrap();
    e.i64(15).unwrap();
    e.i64(3).unwrap();
    e.str("a/b").unwrap();
    e.i64(4).unwrap();
    e.bytes(b"alice").unwrap();
    e.i64(15).unwrap();
    e.map(2).unwrap();
    e.i64(6).unwrap();
    e.f64(1000.5).unwrap();
    e.i64(7).unwrap();
    e.bytes(&[1]).unwrap();
    let bytes = raw_sign1(&protected, |e| {
        e.map(0).unwrap();
    });
    assert_eq!(
        codec::decode_sign1_strict(&bytes, Sign1Layer::Bare).unwrap_err(),
        DecodeError::FractionalTime
    );
}

#[test]
#[allow(clippy::too_many_lines)] // four hand-encoded hostile messages
fn strict_rejects_recipient_shape_violations() {
    let msg = build_encrypted(&encrypt_params(b"x", ContentAlgorithm::A256Gcm))
        .unwrap()
        .into_vec();
    let d = codec::decode_encrypt_strict(&msg, ClaimsExpectation::Forbidden).unwrap();

    // Two recipients.
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.tag(minicbor::data::Tag::new(96)).unwrap();
    e.array(4).unwrap();
    e.bytes(&d.protected).unwrap();
    e.map(1).unwrap();
    e.i64(5).unwrap();
    e.bytes(&d.iv).unwrap();
    e.bytes(&d.ciphertext).unwrap();
    e.array(2).unwrap();
    for _ in 0..2 {
        e.array(3).unwrap();
        e.bytes(&d.recipient_protected).unwrap();
        e.map(2).unwrap();
        e.i64(4).unwrap();
        e.bytes(d.recipient_kid.as_bytes()).unwrap();
        e.i64(-1).unwrap();
        e.map(3).unwrap();
        e.i64(1).unwrap();
        e.i64(1).unwrap();
        e.i64(-1).unwrap();
        e.i64(4).unwrap();
        e.i64(-2).unwrap();
        e.bytes(&d.ephemeral_x).unwrap();
        e.null().unwrap();
    }
    assert_eq!(
        decode_encrypted(&out).unwrap_err(),
        DecodeError::RecipientCount { count: 2 }
    );

    // Recipient ciphertext present (empty bstr instead of null).
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.tag(minicbor::data::Tag::new(96)).unwrap();
    e.array(4).unwrap();
    e.bytes(&d.protected).unwrap();
    e.map(1).unwrap();
    e.i64(5).unwrap();
    e.bytes(&d.iv).unwrap();
    e.bytes(&d.ciphertext).unwrap();
    e.array(1).unwrap();
    e.array(3).unwrap();
    e.bytes(&d.recipient_protected).unwrap();
    e.map(2).unwrap();
    e.i64(4).unwrap();
    e.bytes(d.recipient_kid.as_bytes()).unwrap();
    e.i64(-1).unwrap();
    e.map(3).unwrap();
    e.i64(1).unwrap();
    e.i64(1).unwrap();
    e.i64(-1).unwrap();
    e.i64(4).unwrap();
    e.i64(-2).unwrap();
    e.bytes(&d.ephemeral_x).unwrap();
    e.bytes(b"").unwrap();
    assert_eq!(
        decode_encrypted(&out).unwrap_err(),
        DecodeError::RecipientCiphertextPresent
    );

    // Ephemeral key with the wrong curve (Ed25519 = 6).
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.tag(minicbor::data::Tag::new(96)).unwrap();
    e.array(4).unwrap();
    e.bytes(&d.protected).unwrap();
    e.map(1).unwrap();
    e.i64(5).unwrap();
    e.bytes(&d.iv).unwrap();
    e.bytes(&d.ciphertext).unwrap();
    e.array(1).unwrap();
    e.array(3).unwrap();
    e.bytes(&d.recipient_protected).unwrap();
    e.map(2).unwrap();
    e.i64(4).unwrap();
    e.bytes(d.recipient_kid.as_bytes()).unwrap();
    e.i64(-1).unwrap();
    e.map(3).unwrap();
    e.i64(1).unwrap();
    e.i64(1).unwrap();
    e.i64(-1).unwrap();
    e.i64(6).unwrap();
    e.i64(-2).unwrap();
    e.bytes(&d.ephemeral_x).unwrap();
    e.null().unwrap();
    assert_eq!(
        decode_encrypted(&out).unwrap_err(),
        DecodeError::EphemeralKeyShape
    );

    // IV of the wrong length.
    let mut out = Vec::new();
    let mut e = Encoder::new(&mut out);
    e.tag(minicbor::data::Tag::new(96)).unwrap();
    e.array(4).unwrap();
    e.bytes(&d.protected).unwrap();
    e.map(1).unwrap();
    e.i64(5).unwrap();
    e.bytes(&d.iv[..11]).unwrap();
    e.bytes(&d.ciphertext).unwrap();
    e.array(1).unwrap();
    e.array(3).unwrap();
    e.bytes(&d.recipient_protected).unwrap();
    e.map(2).unwrap();
    e.i64(4).unwrap();
    e.bytes(d.recipient_kid.as_bytes()).unwrap();
    e.i64(-1).unwrap();
    e.map(3).unwrap();
    e.i64(1).unwrap();
    e.i64(1).unwrap();
    e.i64(-1).unwrap();
    e.i64(4).unwrap();
    e.i64(-2).unwrap();
    e.bytes(&d.ephemeral_x).unwrap();
    e.null().unwrap();
    assert_eq!(
        decode_encrypted(&out).unwrap_err(),
        DecodeError::InvalidLength {
            label: 5,
            expected: 12,
            actual: 11
        }
    );
}

#[test]
fn sealed_rejects_non_encrypt_payload() {
    // A sealed outer whose payload is a (valid) COSE_Sign1: rejected as
    // wrong nesting before any signature check.
    let s = signer();
    let v = verifier_for(&s);
    let inner = valid_signed();
    let protected =
        codec::encode_sign1_protected_sealed_outer(SignatureAlgorithm::EdDsa, &kid("alice"))
            .unwrap();
    let bytes = codec::assemble_sign1(&protected, &inner, &[0u8; 64]).unwrap();
    let err = block_on(verify_sealed(
        &bytes,
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Peer),
        },
    ))
    .unwrap_err();
    assert_eq!(err, VerifyError::Decode(DecodeError::EmbeddedNotEncrypt));
}

#[test]
fn sealed_sender_kid_cross_check() {
    // Sign a sealed message whose claims name a different sender than the
    // outer kid: assembled by hand with a real signature so only the
    // cross-check can reject it.
    let s = signer();
    let v = verifier_for(&s);
    let r = recipient();

    // Claims name "mallory" but alice signs. Build the embedded encrypt via
    // the codec (claims are only checked by the entry points).
    let claims = peer_claims(&kid("mallory"));
    let embedded = {
        let core = crate::encrypt::EncryptCore {
            content_algorithm: ContentAlgorithm::A256Gcm,
            content_type: &ct(),
            claims: Some(&claims),
            plaintext: b"x",
            recipient: &r.public(),
            external_aad: &ExternalAad::empty(),
            kdf_parties: &KdfParties::anonymous(),
        };
        let eph = Zeroizing::new([3u8; 32]);
        crate::encrypt::build_encrypt_core(&core, &eph, [1u8; 12]).unwrap()
    };
    let protected =
        codec::encode_sign1_protected_sealed_outer(SignatureAlgorithm::EdDsa, s.key_id()).unwrap();
    let sig_structure = codec::sig_structure(&protected, &[], &embedded).unwrap();
    let signature = block_on(s.sign(&sig_structure)).unwrap();
    let bytes = codec::assemble_sign1(&protected, &embedded, signature.as_bytes()).unwrap();

    let err = block_on(verify_sealed(
        &bytes,
        &v,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation(MessageRole::Peer),
        },
    ))
    .unwrap_err();
    assert_eq!(err, VerifyError::SenderKeyMismatch);
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn decode_reencode_is_byte_identical() {
    // The strict decoders re-encode and compare on every decode; this test
    // additionally proves the assembled output round-trips through the
    // public entry points unchanged.
    let s = signer();
    let r = recipient();
    let signed = valid_signed();
    let d = codec::decode_sign1_strict(&signed, Sign1Layer::Bare).unwrap();
    let rebuilt = codec::assemble_sign1(
        &codec::encode_sign1_protected_bare_with_headers(
            d.algorithm,
            &d.kid,
            &ct(),
            d.claims.as_ref(),
            None,
        )
        .unwrap(),
        &d.payload,
        &d.signature,
    )
    .unwrap();
    assert_eq!(rebuilt, signed);

    let sealed = block_on(build_sealed(
        &seal_params(b"x", ContentAlgorithm::A256Gcm, r.public()),
        &s,
    ))
    .unwrap();
    assert!(codec::decode_sign1_strict(sealed.as_bytes(), Sign1Layer::SealedOuter).is_ok());
}

#[test]
fn identifier_validation() {
    assert!(KeyId::from_text("").is_err());
    assert!(KeyId::from_bytes(vec![0u8; 129]).is_err());
    assert!(KeyId::from_bytes(vec![0u8; 128]).is_ok());
    assert!(MessageId::from_bytes(vec![]).is_err());
    assert!(MessageId::from_bytes(vec![0u8; 65]).is_err());
    assert!(Subject::new(String::new()).is_err());
    assert!(ContentType::new("noslash".to_string()).is_err());
    assert!(ContentType::new(" a/b".to_string()).is_err());
    assert!(ContentType::new("a/b/c".to_string()).is_err());
    assert!(ContentType::new("a/b".to_string()).is_ok());
    assert!(PartyIdentity::from_bytes(vec![]).is_err());
}

#[cfg(feature = "fixtures")]
mod fixtures {
    use super::*;
    use crate::encrypt::SealParts;

    fn parts() -> SealParts {
        SealParts {
            ephemeral_private: Zeroizing::new([0x11u8; 32]),
            nonce: [0x22u8; 12],
        }
    }

    #[test]
    fn fixture_builds_are_deterministic() {
        let first = build_encrypted_with_parts(
            &encrypt_params(b"vector", ContentAlgorithm::A256Gcm),
            &parts(),
        )
        .unwrap();
        let second = build_encrypted_with_parts(
            &encrypt_params(b"vector", ContentAlgorithm::A256Gcm),
            &parts(),
        )
        .unwrap();
        assert_eq!(first, second);

        let alice = signer();
        let sealed_first = block_on(build_sealed_with_parts(
            &seal_params(
                b"vector",
                ContentAlgorithm::ChaCha20Poly1305,
                recipient().public(),
            ),
            &alice,
            &parts(),
        ))
        .unwrap();
        let sealed_second = block_on(build_sealed_with_parts(
            &seal_params(
                b"vector",
                ContentAlgorithm::ChaCha20Poly1305,
                recipient().public(),
            ),
            &alice,
            &parts(),
        ))
        .unwrap();
        assert_eq!(sealed_first, sealed_second);
    }

    /// The seal-only vector must match an independently hand-encoded
    /// expectation (structure hand-built with raw minicbor writes; the
    /// ciphertext and ephemeral public are spliced from the library output,
    /// which fixture determinism pins).
    #[test]
    fn seal_only_matches_hand_encoded_expectation() {
        let msg = build_encrypted_with_parts(
            &encrypt_params(b"vector", ContentAlgorithm::A256Gcm),
            &parts(),
        )
        .unwrap();
        let d = codec::decode_encrypt_strict(msg.as_bytes(), ClaimsExpectation::Forbidden).unwrap();

        let mut expected = Vec::new();
        let mut e = Encoder::new(&mut expected);
        e.tag(minicbor::data::Tag::new(96)).unwrap();
        e.array(4).unwrap();
        // protected: {1: 3 (A256GCM), 2: [3], 3: "application/basil.test"}
        let mut protected = Vec::new();
        let mut pe = Encoder::new(&mut protected);
        pe.map(3).unwrap();
        pe.i64(1).unwrap();
        pe.i64(3).unwrap();
        pe.i64(2).unwrap();
        pe.array(1).unwrap();
        pe.i64(3).unwrap();
        pe.i64(3).unwrap();
        pe.str("application/basil.test").unwrap();
        e.bytes(&protected).unwrap();
        // unprotected: {5: nonce}
        e.map(1).unwrap();
        e.i64(5).unwrap();
        e.bytes(&[0x22u8; 12]).unwrap();
        // ciphertext (AEAD output; pinned by the deterministic fixture).
        e.bytes(&d.ciphertext).unwrap();
        // recipients: [[<<{1: -25}>>, {4: 'bob', -1: {1:1, -1:4, -2: eph}}, null]]
        e.array(1).unwrap();
        e.array(3).unwrap();
        let mut rp = Vec::new();
        let mut rpe = Encoder::new(&mut rp);
        rpe.map(1).unwrap();
        rpe.i64(1).unwrap();
        rpe.i64(-25).unwrap();
        e.bytes(&rp).unwrap();
        e.map(2).unwrap();
        e.i64(4).unwrap();
        e.bytes(b"bob").unwrap();
        e.i64(-1).unwrap();
        e.map(3).unwrap();
        e.i64(1).unwrap();
        e.i64(1).unwrap();
        e.i64(-1).unwrap();
        e.i64(4).unwrap();
        e.i64(-2).unwrap();
        e.bytes(&d.ephemeral_x).unwrap();
        e.null().unwrap();

        assert_eq!(msg.as_bytes(), expected.as_slice());
    }

    /// The signed vector likewise matches a hand-encoded expectation
    /// (Ed25519 is deterministic, so even the signature bytes are pinned by
    /// construction; only the signature value is spliced).
    #[test]
    fn signed_matches_hand_encoded_expectation() {
        let s = signer();
        let msg = block_on(build_signed(
            &SignParams {
                content_type: ct(),
                payload: b"vector",
                claims: None,
                external_aad: ExternalAad::empty(),
            },
            &s,
        ))
        .unwrap();
        let d = codec::decode_sign1_strict(msg.as_bytes(), Sign1Layer::Bare).unwrap();

        let mut expected = Vec::new();
        let mut e = Encoder::new(&mut expected);
        e.tag(minicbor::data::Tag::new(18)).unwrap();
        e.array(4).unwrap();
        // protected: {1: -8, 2: [3], 3: ct, 4: 'alice'}
        let mut protected = Vec::new();
        let mut pe = Encoder::new(&mut protected);
        pe.map(4).unwrap();
        pe.i64(1).unwrap();
        pe.i64(-8).unwrap();
        pe.i64(2).unwrap();
        pe.array(1).unwrap();
        pe.i64(3).unwrap();
        pe.i64(3).unwrap();
        pe.str("application/basil.test").unwrap();
        pe.i64(4).unwrap();
        pe.bytes(b"alice").unwrap();
        e.bytes(&protected).unwrap();
        e.map(0).unwrap();
        e.bytes(b"vector").unwrap();
        e.bytes(&d.signature).unwrap();

        assert_eq!(msg.as_bytes(), expected.as_slice());
    }
}
