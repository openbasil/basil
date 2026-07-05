//! COSE sealed-invocation fixtures (plan §8.3).
//!
//! Builds the six invocation message types (request + response for sign,
//! mint-jwt, mint-nats-user) as complete tagged COSE bytes with the
//! `basil-cose` deterministic `fixtures` constructors, checks them against
//! the checked-in JSON byte-for-byte, and round-trips every vector through
//! the strict verify/open entry points. Reject vectors must fail with the
//! recorded reason.
//!
//! Regenerate with:
//! `BASIL_REGEN_FIXTURES=1 cargo test -p basil-proto --test cose_fixtures`
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use basil_cose::{
    Claims, ContentAlgorithm, ContentType, Ed25519Signer, Ed25519Verifier, ExternalAad, KdfParties,
    KeyId, MessageId, MessageRole, OpenError, PartyIdentity, RequestHash, ResponseSubject,
    SealParams, SealParts, SealedAad, Subject, UnixTime, ValidationParams, VerifyError,
    VerifySealedParams, X25519Recipient, Zeroizing, build_sealed_with_parts, request_hash,
    verify_sealed,
};
use basil_proto::invocation::{
    CONTENT_TYPE_MINT_JWT_REQUEST, CONTENT_TYPE_MINT_JWT_RESPONSE,
    CONTENT_TYPE_MINT_NATS_USER_REQUEST, CONTENT_TYPE_MINT_NATS_USER_RESPONSE,
    CONTENT_TYPE_SIGN_REQUEST, CONTENT_TYPE_SIGN_RESPONSE, INVOCATION_CONTENT_TYPES,
    InvocationStatus, MintJwtInvocationRequest, MintJwtInvocationResponse,
    MintNatsUserInvocationRequest, MintNatsUserInvocationResponse, SignInvocationRequest,
    SignInvocationResponse,
};
use serde_json::{Value, json};

/// Poll a ready-immediately future to completion (local key implementations
/// never yield; a `Pending` here is a test bug).
fn block_on<F: Future>(fut: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut fut = std::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("local future pended"),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// --- deterministic test key material (test keys only) ----------------------

const CLIENT_SIGNING_PRIVATE: [u8; 32] = [0x11; 32];
const BROKER_SIGNING_PRIVATE: [u8; 32] = [0x22; 32];
const BROKER_ENCRYPTION_PRIVATE: [u8; 32] = [0x33; 32];
const CLIENT_RESPONSE_ENCRYPTION_PRIVATE: [u8; 32] = [0x44; 32];

const CLIENT_SIGNING_KID: &str = "client.signing.test";
const BROKER_SIGNING_KID: &str = "broker.signing.test";
const BROKER_ENCRYPTION_KID: &str = "broker.invocation-encryption.test";
const CLIENT_RESPONSE_ENCRYPTION_KID: &str = "client.response.test";

const IAT: i64 = 1_782_740_000;
const EXP: i64 = 1_782_740_060;
const NOW: i64 = 1_782_740_010;
const AUDIENCE: &str = "basil://broker.test";

fn kid(s: &str) -> KeyId {
    KeyId::from_text(s).unwrap()
}

fn client_signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_bytes(
        kid(CLIENT_SIGNING_KID),
        &Zeroizing::new(CLIENT_SIGNING_PRIVATE),
    )
}

fn broker_signer() -> Ed25519Signer {
    Ed25519Signer::from_secret_bytes(
        kid(BROKER_SIGNING_KID),
        &Zeroizing::new(BROKER_SIGNING_PRIVATE),
    )
}

fn broker_recipient() -> X25519Recipient {
    X25519Recipient::new(
        kid(BROKER_ENCRYPTION_KID),
        Zeroizing::new(BROKER_ENCRYPTION_PRIVATE),
    )
}

fn client_response_recipient() -> X25519Recipient {
    X25519Recipient::new(
        kid(CLIENT_RESPONSE_ENCRYPTION_KID),
        Zeroizing::new(CLIENT_RESPONSE_ENCRYPTION_PRIVATE),
    )
}

fn nats_parties() -> KdfParties {
    KdfParties {
        party_u: PartyIdentity::from_bytes(b"svc-a.test".to_vec()).unwrap(),
        party_v: PartyIdentity::from_bytes(b"basil-broker.test".to_vec()).unwrap(),
    }
}

fn validation(role: MessageRole) -> ValidationParams {
    ValidationParams {
        now: UnixTime(NOW),
        max_clock_skew: Duration::from_secs(30),
        // `Duration::from_mins` needs 1.91; basil-proto's MSRV is 1.85.
        max_ttl: Duration::from_secs(300),
        default_ttl: Duration::from_secs(60),
        allowed_audiences: BTreeSet::from([Subject::new(AUDIENCE.to_string()).unwrap()]),
        role,
    }
}

// --- vector construction ----------------------------------------------------

/// Which of the fixture keys signs / receives / verifies a vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyRef {
    ClientSigning,
    BrokerSigning,
    BrokerEncryption,
    ClientResponseEncryption,
}

impl KeyRef {
    const fn name(self) -> &'static str {
        match self {
            Self::ClientSigning => "client-signing",
            Self::BrokerSigning => "broker-signing",
            Self::BrokerEncryption => "broker-encryption",
            Self::ClientResponseEncryption => "client-response-encryption",
        }
    }

    fn from_name(name: &str) -> Self {
        match name {
            "client-signing" => Self::ClientSigning,
            "broker-signing" => Self::BrokerSigning,
            "broker-encryption" => Self::BrokerEncryption,
            "client-response-encryption" => Self::ClientResponseEncryption,
            other => panic!("unknown fixture key {other}"),
        }
    }

    fn signer(self) -> Ed25519Signer {
        match self {
            Self::ClientSigning => client_signer(),
            Self::BrokerSigning => broker_signer(),
            _ => panic!("{} is not a signing key", self.name()),
        }
    }

    fn verifier(self) -> Ed25519Verifier {
        let s = self.signer();
        Ed25519Verifier::from_key(kid(self.kid_str()), &s.public_key_bytes()).unwrap()
    }

    fn recipient(self) -> X25519Recipient {
        match self {
            Self::BrokerEncryption => broker_recipient(),
            Self::ClientResponseEncryption => client_response_recipient(),
            _ => panic!("{} is not an encryption key", self.name()),
        }
    }

    const fn kid_str(self) -> &'static str {
        match self {
            Self::ClientSigning => CLIENT_SIGNING_KID,
            Self::BrokerSigning => BROKER_SIGNING_KID,
            Self::BrokerEncryption => BROKER_ENCRYPTION_KID,
            Self::ClientResponseEncryption => CLIENT_RESPONSE_ENCRYPTION_KID,
        }
    }
}

struct VectorSpec {
    name: &'static str,
    content_type: &'static str,
    role: MessageRole,
    content_algorithm: ContentAlgorithm,
    signer: KeyRef,
    recipient: KeyRef,
    parties: Option<KdfParties>,
    claims: Claims,
    body_schema: &'static str,
    body_fields: Value,
    plaintext: Vec<u8>,
    ephemeral_private: [u8; 32],
    nonce: [u8; 12],
}

struct Built {
    spec: VectorSpec,
    bytes: Vec<u8>,
}

fn seal(spec: &VectorSpec) -> Vec<u8> {
    let recipient = spec.recipient.recipient().public();
    let params = SealParams {
        content_type: ContentType::new(spec.content_type.to_string()).unwrap(),
        plaintext: &spec.plaintext,
        claims: spec.claims.clone(),
        role: spec.role,
        recipient,
        content_algorithm: spec.content_algorithm,
        aad: SealedAad::empty(),
        kdf_parties: spec.parties.clone().unwrap_or_else(KdfParties::anonymous),
    };
    let parts = SealParts {
        ephemeral_private: Zeroizing::new(spec.ephemeral_private),
        nonce: spec.nonce,
    };
    block_on(build_sealed_with_parts(
        &params,
        &spec.signer.signer(),
        &parts,
    ))
    .unwrap()
    .into_vec()
}

fn request_claims(message_id: [u8; 16], sender: KeyRef, response_subject: Option<&str>) -> Claims {
    Claims {
        issuer: None,
        audience: Some(Subject::new(AUDIENCE.to_string()).unwrap()),
        expires_at: Some(UnixTime(EXP)),
        issued_at: UnixTime(IAT),
        message_id: MessageId::from_bytes(message_id.to_vec()).unwrap(),
        sender_key_id: Some(kid(sender.kid_str())),
        response_key_id: Some(kid(CLIENT_RESPONSE_ENCRYPTION_KID)),
        response_subject: response_subject.map(|s| ResponseSubject::new(s.to_string()).unwrap()),
        in_reply_to: None,
        request_hash: None,
    }
}

fn response_claims(message_id: [u8; 16], in_reply_to: [u8; 16], request: &[u8]) -> Claims {
    Claims {
        issuer: None,
        audience: None,
        expires_at: Some(UnixTime(EXP)),
        issued_at: UnixTime(IAT),
        message_id: MessageId::from_bytes(message_id.to_vec()).unwrap(),
        sender_key_id: Some(kid(BROKER_SIGNING_KID)),
        response_key_id: None,
        response_subject: None,
        in_reply_to: Some(MessageId::from_bytes(in_reply_to.to_vec()).unwrap()),
        request_hash: Some(request_hash(request)),
    }
}

fn build_vectors() -> Vec<Built> {
    let sign_request = VectorSpec {
        name: "sign-request",
        content_type: CONTENT_TYPE_SIGN_REQUEST,
        role: MessageRole::Request,
        content_algorithm: ContentAlgorithm::A256Gcm,
        signer: KeyRef::ClientSigning,
        recipient: KeyRef::BrokerEncryption,
        parties: None,
        claims: request_claims(
            [0xA1; 16],
            KeyRef::ClientSigning,
            Some("svc-a.replies.test"),
        ),
        body_schema: "SignInvocationRequest",
        body_fields: json!({
            "key_id": "app.signing.test",
            "message_hex": hex(b"payload-to-sign"),
            "algorithm": 1,
        }),
        plaintext: SignInvocationRequest {
            key_id: "app.signing.test".to_string(),
            message: b"payload-to-sign".to_vec(),
            algorithm: 1,
        }
        .to_cbor_bytes(),
        ephemeral_private: [0x51; 32],
        nonce: [0x61; 12],
    };
    let sign_request_bytes = seal(&sign_request);

    let sign_response = VectorSpec {
        name: "sign-response",
        content_type: CONTENT_TYPE_SIGN_RESPONSE,
        role: MessageRole::Response,
        content_algorithm: ContentAlgorithm::A256Gcm,
        signer: KeyRef::BrokerSigning,
        recipient: KeyRef::ClientResponseEncryption,
        parties: None,
        claims: response_claims([0xB1; 16], [0xA1; 16], &sign_request_bytes),
        body_schema: "SignInvocationResponse",
        body_fields: json!({
            "status": {"code": 1, "reason": "OK", "message": null, "retryable": false},
            "policy_generation": 42,
            "signature_hex": hex(&[0xAB; 64]),
        }),
        plaintext: SignInvocationResponse {
            status: InvocationStatus::ok(),
            policy_generation: 42,
            signature: Some(vec![0xAB; 64]),
        }
        .to_cbor_bytes(),
        ephemeral_private: [0x52; 32],
        nonce: [0x62; 12],
    };

    let mint_jwt_request = VectorSpec {
        name: "mint-jwt-request",
        content_type: CONTENT_TYPE_MINT_JWT_REQUEST,
        role: MessageRole::Request,
        content_algorithm: ContentAlgorithm::A256Gcm,
        signer: KeyRef::ClientSigning,
        recipient: KeyRef::BrokerEncryption,
        parties: None,
        claims: request_claims([0xA2; 16], KeyRef::ClientSigning, None),
        body_schema: "MintJwtInvocationRequest",
        body_fields: json!({
            "key_id": "app.jwt.test",
            "subject": "svc-a",
            "ttl_secs": 300,
            "claims_json_hex": hex(br#"{"scope":"read"}"#),
        }),
        plaintext: MintJwtInvocationRequest {
            key_id: "app.jwt.test".to_string(),
            subject: Some("svc-a".to_string()),
            ttl_secs: Some(300),
            claims_json: br#"{"scope":"read"}"#.to_vec(),
        }
        .to_cbor_bytes(),
        ephemeral_private: [0x53; 32],
        nonce: [0x63; 12],
    };
    let mint_jwt_request_bytes = seal(&mint_jwt_request);

    let mint_jwt_response = VectorSpec {
        name: "mint-jwt-response",
        content_type: CONTENT_TYPE_MINT_JWT_RESPONSE,
        role: MessageRole::Response,
        content_algorithm: ContentAlgorithm::A256Gcm,
        signer: KeyRef::BrokerSigning,
        recipient: KeyRef::ClientResponseEncryption,
        parties: None,
        claims: response_claims([0xB2; 16], [0xA2; 16], &mint_jwt_request_bytes),
        body_schema: "MintJwtInvocationResponse",
        body_fields: json!({
            "status": {"code": 1, "reason": "OK", "message": null, "retryable": false},
            "policy_generation": 42,
            "jwt": "eyJhbGciOiJFZERTQSJ9.test.jwt",
            "expires_at_unix": 1_782_740_300_u64,
        }),
        plaintext: MintJwtInvocationResponse {
            status: InvocationStatus::ok(),
            policy_generation: 42,
            jwt: Some("eyJhbGciOiJFZERTQSJ9.test.jwt".to_string()),
            expires_at_unix: Some(1_782_740_300),
        }
        .to_cbor_bytes(),
        ephemeral_private: [0x54; 32],
        nonce: [0x64; 12],
    };

    let mint_nats_request = VectorSpec {
        name: "mint-nats-user-request",
        content_type: CONTENT_TYPE_MINT_NATS_USER_REQUEST,
        role: MessageRole::Request,
        content_algorithm: ContentAlgorithm::ChaCha20Poly1305,
        signer: KeyRef::ClientSigning,
        recipient: KeyRef::BrokerEncryption,
        parties: Some(nats_parties()),
        claims: request_claims([0xA3; 16], KeyRef::ClientSigning, None),
        body_schema: "MintNatsUserInvocationRequest",
        body_fields: json!({
            "account_key_id": "nats.account.test",
            "user_nkey": "UDXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4",
            "name": "svc-a",
            "ttl_secs": 300,
            "issuer_account": "ADXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4",
        }),
        plaintext: MintNatsUserInvocationRequest {
            account_key_id: "nats.account.test".to_string(),
            user_nkey: "UDXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4".to_string(),
            name: "svc-a".to_string(),
            ttl_secs: Some(300),
            issuer_account: Some(
                "ADXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4".to_string(),
            ),
        }
        .to_cbor_bytes(),
        ephemeral_private: [0x55; 32],
        nonce: [0x65; 12],
    };
    let mint_nats_request_bytes = seal(&mint_nats_request);

    let mint_nats_response = VectorSpec {
        name: "mint-nats-user-response",
        content_type: CONTENT_TYPE_MINT_NATS_USER_RESPONSE,
        role: MessageRole::Response,
        content_algorithm: ContentAlgorithm::ChaCha20Poly1305,
        signer: KeyRef::BrokerSigning,
        recipient: KeyRef::ClientResponseEncryption,
        parties: Some(nats_parties()),
        claims: response_claims([0xB3; 16], [0xA3; 16], &mint_nats_request_bytes),
        body_schema: "MintNatsUserInvocationResponse",
        body_fields: json!({
            "status": {"code": 1, "reason": "OK", "message": null, "retryable": false},
            "policy_generation": 42,
            "jwt": "eyJ0eXAiOiJKV1QifQ.natsuser.jwt",
            "expires_at_unix": 1_782_740_300_u64,
        }),
        plaintext: MintNatsUserInvocationResponse {
            status: InvocationStatus::ok(),
            policy_generation: 42,
            jwt: Some("eyJ0eXAiOiJKV1QifQ.natsuser.jwt".to_string()),
            expires_at_unix: Some(1_782_740_300),
        }
        .to_cbor_bytes(),
        ephemeral_private: [0x56; 32],
        nonce: [0x66; 12],
    };

    [
        (sign_request, Some(sign_request_bytes)),
        (sign_response, None),
        (mint_jwt_request, Some(mint_jwt_request_bytes)),
        (mint_jwt_response, None),
        (mint_nats_request, Some(mint_nats_request_bytes)),
        (mint_nats_response, None),
    ]
    .into_iter()
    .map(|(spec, prebuilt)| {
        let bytes = prebuilt.unwrap_or_else(|| seal(&spec));
        Built { spec, bytes }
    })
    .collect()
}

struct RejectSpec {
    name: &'static str,
    bytes: Vec<u8>,
    verifier: KeyRef,
    role: MessageRole,
    stage: &'static str,
    reason: &'static str,
    recipient: Option<KeyRef>,
    open_aad: Option<&'static [u8]>,
    description: &'static str,
}

fn build_rejects(sign_request_bytes: &[u8]) -> Vec<RejectSpec> {
    // A fully valid seal whose claims expired long before `validation.now`.
    let expired = VectorSpec {
        name: "expired-request",
        content_type: CONTENT_TYPE_SIGN_REQUEST,
        role: MessageRole::Request,
        content_algorithm: ContentAlgorithm::A256Gcm,
        signer: KeyRef::ClientSigning,
        recipient: KeyRef::BrokerEncryption,
        parties: None,
        claims: Claims {
            issued_at: UnixTime(1_782_600_000),
            expires_at: Some(UnixTime(1_782_600_060)),
            message_id: MessageId::from_bytes(vec![0xE1; 16]).unwrap(),
            ..request_claims([0xE1; 16], KeyRef::ClientSigning, None)
        },
        body_schema: "SignInvocationRequest",
        body_fields: Value::Null,
        plaintext: SignInvocationRequest {
            key_id: "app.signing.test".to_string(),
            message: b"payload-to-sign".to_vec(),
            algorithm: 1,
        }
        .to_cbor_bytes(),
        ephemeral_private: [0x57; 32],
        nonce: [0x67; 12],
    };
    let expired_bytes = seal(&expired);

    let mut tampered_signature = sign_request_bytes.to_vec();
    *tampered_signature.last_mut().unwrap() ^= 0x01;

    let mut wrong_tag = sign_request_bytes.to_vec();
    assert_eq!(
        wrong_tag[0], 0xd2,
        "tagged COSE_Sign1 must start with tag 18"
    );
    wrong_tag[0] = 0xd3;

    let truncated = sign_request_bytes[..sign_request_bytes.len() - 1].to_vec();

    vec![
        RejectSpec {
            name: "expired-request",
            bytes: expired_bytes,
            verifier: KeyRef::ClientSigning,
            role: MessageRole::Request,
            stage: "verify",
            reason: "claims-expired",
            recipient: None,
            open_aad: None,
            description: "valid seal; claims expired before validation.now_unix",
        },
        RejectSpec {
            name: "tampered-signature",
            bytes: tampered_signature,
            verifier: KeyRef::ClientSigning,
            role: MessageRole::Request,
            stage: "verify",
            reason: "signature-invalid",
            recipient: None,
            open_aad: None,
            description: "sign-request with the last signature byte flipped",
        },
        RejectSpec {
            name: "wrong-outer-tag",
            bytes: wrong_tag,
            verifier: KeyRef::ClientSigning,
            role: MessageRole::Request,
            stage: "verify",
            reason: "decode-wrong-tag",
            recipient: None,
            open_aad: None,
            description: "sign-request with outer tag 18 rewritten to tag 19",
        },
        RejectSpec {
            name: "truncated",
            bytes: truncated,
            verifier: KeyRef::ClientSigning,
            role: MessageRole::Request,
            stage: "verify",
            reason: "decode-malformed",
            recipient: None,
            open_aad: None,
            description: "sign-request with the final byte removed",
        },
        RejectSpec {
            name: "aad-mismatch",
            bytes: sign_request_bytes.to_vec(),
            verifier: KeyRef::ClientSigning,
            role: MessageRole::Request,
            stage: "open",
            reason: "open-failed",
            recipient: Some(KeyRef::BrokerEncryption),
            open_aad: Some(b"mismatch"),
            description: "valid sign-request opened with a different encryption external AAD",
        },
        RejectSpec {
            name: "role-mismatch",
            bytes: sign_request_bytes.to_vec(),
            verifier: KeyRef::ClientSigning,
            role: MessageRole::Response,
            stage: "verify",
            reason: "claims-role-shape",
            recipient: None,
            open_aad: None,
            description: "sign-request validated with the response role shape",
        },
    ]
}

// --- JSON document -----------------------------------------------------------

fn key_entry(algorithm: &str, key_id: &str, private: &[u8; 32], public: &[u8; 32]) -> Value {
    json!({
        "algorithm": algorithm,
        "key_id": key_id,
        "private_hex": hex(private),
        "public_hex": hex(public),
    })
}

fn claims_json(claims: &Claims) -> Value {
    json!({
        "issuer": claims.issuer.as_ref().map(Subject::as_str),
        "audience": claims.audience.as_ref().map(Subject::as_str),
        "expires_at_unix": claims.expires_at.map(|t| t.0),
        "issued_at_unix": claims.issued_at.0,
        "message_id_hex": hex(claims.message_id.as_bytes()),
        "sender_key_id": claims
            .sender_key_id
            .as_ref()
            .and_then(KeyId::as_catalog_name),
        "response_key_id": claims
            .response_key_id
            .as_ref()
            .and_then(KeyId::as_catalog_name),
        "response_subject": claims.response_subject.as_ref().map(ResponseSubject::as_str),
        "in_reply_to_hex": claims.in_reply_to.as_ref().map(|m| hex(m.as_bytes())),
        "request_hash_sha3_256_hex": claims.request_hash.as_ref().map(|h| hex(&h.0)),
    })
}

fn build_doc() -> (Value, Vec<Built>, Vec<RejectSpec>) {
    let vectors = build_vectors();
    let rejects = build_rejects(&vectors[0].bytes);

    let vector_values: Vec<Value> = vectors
        .iter()
        .map(|built| {
            let spec = &built.spec;
            json!({
                "name": spec.name,
                "verdict": "accept",
                "content_type": spec.content_type,
                "role": match spec.role {
                    MessageRole::Request => "request",
                    MessageRole::Response => "response",
                    MessageRole::Peer => "peer",
                },
                "content_algorithm": spec.content_algorithm.codepoint(),
                "signer": spec.signer.name(),
                "recipient": spec.recipient.name(),
                "kdf": {
                    "party_u_hex": spec
                        .parties
                        .as_ref()
                        .and_then(|p| p.party_u.as_bytes())
                        .map(hex),
                    "party_v_hex": spec
                        .parties
                        .as_ref()
                        .and_then(|p| p.party_v.as_bytes())
                        .map(hex),
                },
                "claims": claims_json(&spec.claims),
                "body": {
                    "schema": spec.body_schema,
                    "fields": spec.body_fields,
                    "plaintext_cbor_hex": hex(&spec.plaintext),
                },
                "parts": {
                    "ephemeral_private_hex": hex(&spec.ephemeral_private),
                    "nonce_hex": hex(&spec.nonce),
                },
                "cose_sign1_hex": hex(&built.bytes),
            })
        })
        .collect();

    let reject_values: Vec<Value> = rejects
        .iter()
        .map(|r| {
            json!({
                "name": r.name,
                "verdict": "reject",
                "stage": r.stage,
                "reason": r.reason,
                "verifier": r.verifier.name(),
                "role": match r.role {
                    MessageRole::Request => "request",
                    MessageRole::Response => "response",
                    MessageRole::Peer => "peer",
                },
                "recipient": r.recipient.map(KeyRef::name),
                "open_aad_hex": r.open_aad.map(hex),
                "cose_sign1_hex": hex(&r.bytes),
                "description": r.description,
            })
        })
        .collect();

    let client_sign = client_signer();
    let broker_sign = broker_signer();
    let doc = json!({
        "format": "basil-cose-sealed-invocation-fixtures",
        "version": 1,
        "description": "Complete tagged COSE bytes (COSE_Sign1 over embedded tagged \
    COSE_Encrypt, EdDSA/-8 + ECDH-ES+HKDF-256/-25) for the six basil invocation message \
    types, built with deterministic parts. Test keys only. Consumers must reproduce and \
    verify these byte-for-byte.",
        "validation": {
            "now_unix": NOW,
            "max_clock_skew_secs": 30,
            "max_ttl_secs": 300,
            "default_ttl_secs": 60,
            "allowed_audiences": [AUDIENCE],
        },
        "keys": {
            "client-signing": key_entry(
                "ed25519",
                CLIENT_SIGNING_KID,
                &CLIENT_SIGNING_PRIVATE,
                &client_sign.public_key_bytes(),
            ),
            "broker-signing": key_entry(
                "ed25519",
                BROKER_SIGNING_KID,
                &BROKER_SIGNING_PRIVATE,
                &broker_sign.public_key_bytes(),
            ),
            "broker-encryption": key_entry(
                "x25519",
                BROKER_ENCRYPTION_KID,
                &BROKER_ENCRYPTION_PRIVATE,
                &broker_recipient().public().public,
            ),
            "client-response-encryption": key_entry(
                "x25519",
                CLIENT_RESPONSE_ENCRYPTION_KID,
                &CLIENT_RESPONSE_ENCRYPTION_PRIVATE,
                &client_response_recipient().public().public,
            ),
        },
        "vectors": vector_values,
        "rejects": reject_values,
    });
    (doc, vectors, rejects)
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/cose-sealed-invocation-v1.json")
}

fn checked_in_doc() -> Value {
    let raw = std::fs::read_to_string(fixture_path()).unwrap();
    serde_json::from_str(&raw).unwrap()
}

// --- tests -------------------------------------------------------------------

#[test]
fn registry_content_types_parse_via_basil_cose() {
    for value in INVOCATION_CONTENT_TYPES {
        let parsed = ContentType::new(value.to_string()).unwrap();
        assert_eq!(parsed.as_str(), value);
    }
}

#[test]
fn checked_in_fixtures_match_generated_bytes() {
    let (doc, _, _) = build_doc();
    if std::env::var_os("BASIL_REGEN_FIXTURES").is_some() {
        let mut pretty = serde_json::to_string_pretty(&doc).unwrap();
        pretty.push('\n');
        std::fs::write(fixture_path(), pretty).unwrap();
    }
    assert_eq!(
        checked_in_doc(),
        doc,
        "checked-in fixtures do not match generated bytes; regenerate with \
BASIL_REGEN_FIXTURES=1 if the change is intentional"
    );
}

#[test]
fn accept_vectors_round_trip_through_strict_entry_points() {
    let file = checked_in_doc();
    let vectors = build_vectors();
    assert_eq!(file["vectors"].as_array().unwrap().len(), vectors.len());

    for (built, entry) in vectors.iter().zip(file["vectors"].as_array().unwrap()) {
        let spec = &built.spec;
        assert_eq!(entry["name"], spec.name);
        let bytes = unhex(entry["cose_sign1_hex"].as_str().unwrap());
        // Deterministic rebuild from parts reproduces the checked-in bytes.
        assert_eq!(bytes, built.bytes, "{}: rebuild differs", spec.name);

        let params = validation(spec.role);
        let verified = block_on(verify_sealed(
            &bytes,
            &spec.signer.verifier(),
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &params,
            },
        ))
        .unwrap_or_else(|e| panic!("{}: verify failed: {e}", spec.name));

        assert_eq!(verified.claims, spec.claims, "{}", spec.name);
        assert_eq!(verified.content_type.as_str(), spec.content_type);
        assert_eq!(verified.signer_key_id, kid(spec.signer.kid_str()));
        assert_eq!(verified.recipient_key_id, kid(spec.recipient.kid_str()));

        let opened = block_on(verified.open(
            &spec.recipient.recipient(),
            &ExternalAad::empty(),
            spec.parties.as_ref(),
        ))
        .unwrap_or_else(|e| panic!("{}: open failed: {e}", spec.name));
        let expected_plaintext = unhex(entry["body"]["plaintext_cbor_hex"].as_str().unwrap());
        assert_eq!(*opened.plaintext, expected_plaintext, "{}", spec.name);

        // The plaintext parses as the declared basil-proto body schema.
        match spec.body_schema {
            "SignInvocationRequest" => {
                let body = SignInvocationRequest::from_cbor_bytes(&opened.plaintext).unwrap();
                assert_eq!(body.to_cbor_bytes(), *opened.plaintext);
            }
            "SignInvocationResponse" => {
                let body = SignInvocationResponse::from_cbor_bytes(&opened.plaintext).unwrap();
                assert_eq!(body.to_cbor_bytes(), *opened.plaintext);
            }
            // The mint bodies have encode-only codecs today; the generated
            // plaintext equality above already pins their bytes.
            _ => assert_eq!(*opened.plaintext, spec.plaintext),
        }
    }
}

#[test]
fn reject_vectors_fail_with_the_recorded_reason() {
    let file = checked_in_doc();
    for entry in file["rejects"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let bytes = unhex(entry["cose_sign1_hex"].as_str().unwrap());
        let role = match entry["role"].as_str().unwrap() {
            "request" => MessageRole::Request,
            "response" => MessageRole::Response,
            other => panic!("{name}: unexpected role {other}"),
        };
        let verifier = KeyRef::from_name(entry["verifier"].as_str().unwrap()).verifier();
        let params = validation(role);
        let result = block_on(verify_sealed(
            &bytes,
            &verifier,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &params,
            },
        ));
        let stage = entry["stage"].as_str().unwrap();
        let reason = entry["reason"].as_str().unwrap();
        match stage {
            "verify" => {
                let err = result.expect_err(name);
                assert_reason(name, reason, &err);
            }
            "open" => {
                let sealed = result.unwrap_or_else(|e| panic!("{name}: verify failed: {e}"));
                let recipient = KeyRef::from_name(entry["recipient"].as_str().unwrap()).recipient();
                let aad = ExternalAad::from_bytes(unhex(entry["open_aad_hex"].as_str().unwrap()));
                let err = block_on(sealed.open(&recipient, &aad, None)).expect_err(name);
                assert!(
                    reason == "open-failed" && matches!(err, OpenError::OpenFailed),
                    "{name}: expected {reason}, got {err:?}"
                );
            }
            other => panic!("{name}: unexpected stage {other}"),
        }
    }
}

fn assert_reason(name: &str, reason: &str, err: &VerifyError) {
    use basil_cose::{ClaimsError, DecodeError};
    let ok = match reason {
        "claims-expired" => matches!(err, VerifyError::Claims(ClaimsError::Expired)),
        "signature-invalid" => matches!(err, VerifyError::SignatureInvalid),
        "decode-wrong-tag" => matches!(
            err,
            VerifyError::Decode(DecodeError::WrongTag {
                expected: 18,
                actual: 19
            })
        ),
        "decode-malformed" => matches!(err, VerifyError::Decode(DecodeError::Malformed)),
        "claims-role-shape" => {
            matches!(err, VerifyError::Claims(ClaimsError::MissingClaim { .. }))
        }
        other => panic!("{name}: unknown reason token {other}"),
    };
    assert!(ok, "{name}: expected {reason}, got {err:?}");
}

/// The request-hash claim in each response vector matches SHA3-256 of the
/// corresponding request vector's complete tagged bytes.
#[test]
fn response_request_hashes_bind_request_bytes() {
    let file = checked_in_doc();
    let vectors = file["vectors"].as_array().unwrap();
    for (request_name, response_name) in [
        ("sign-request", "sign-response"),
        ("mint-jwt-request", "mint-jwt-response"),
        ("mint-nats-user-request", "mint-nats-user-response"),
    ] {
        let find = |name: &str| {
            vectors
                .iter()
                .find(|v| v["name"] == name)
                .unwrap_or_else(|| panic!("missing vector {name}"))
        };
        let request = find(request_name);
        let response = find(response_name);
        let RequestHash(expected) =
            request_hash(&unhex(request["cose_sign1_hex"].as_str().unwrap()));
        assert_eq!(
            response["claims"]["request_hash_sha3_256_hex"]
                .as_str()
                .unwrap(),
            hex(&expected),
            "{response_name}"
        );
        assert_eq!(
            response["claims"]["in_reply_to_hex"].as_str().unwrap(),
            request["claims"]["message_id_hex"].as_str().unwrap(),
            "{response_name}"
        );
    }
}
