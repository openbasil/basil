// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! LIVE adversarial acceptance corpus for proof-bound sealed invocations
//! (`basil-jjgi.3.3.1`), driven over the REAL `InvocationService.Invoke` RPC of
//! a booted broker with `[invocation]` and `[federation]` enabled.
//!
//! Every case in this file is an ATTACK: a sealed COSE request forged the way a
//! hostile CI client would forge it. The acceptance property is that each one is
//! denied, and that the denial is attributable to the defence under test rather
//! than to some accidental earlier rejection. Each case therefore carries two
//! oracles:
//!
//! 1. a LOCAL structural oracle — `basil_cose::verify_sealed` run in-process
//!    against a verifier that mirrors the broker's proof-key rule
//!    (`kid == RFC 7638 thumbprint`, `alg == EdDSA`, signature under the proof
//!    key). It pins the exact wire-level cause: a `crit` case must fail with a
//!    `crit` decode error, a key-substitution case with `SignatureInvalid`, and
//!    the honest baseline must VERIFY, proving the corpus differs from the
//!    baseline only in the mutation under test;
//! 2. the LIVE broker's gRPC status over the real socket.
//!
//! Provider matrix: the body runs parametrized over [`ProviderArm`]. Both the
//! GitHub arm and the opt-in experimental Forgejo arm run here.
//!
//! Deliberately out of scope (and why): no case presents a provider token that
//! a real issuer signed, so no case is ever ACCEPTED end to end. Token
//! acceptance needs live GitHub OIDC material and belongs to the runner lanes
//! (`basil-jjgi.6`). To keep this lane hermetic the provider tokens here carry
//! no `kid` header, so the broker fails closed at token-header decode and never
//! reaches out to a provider JWKS endpoint.
//!
//! GATING: needs a live `bao`; prints an explicit skip line when absent.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use basil_core::ci_federation::{proof_audience, proof_key_kid, proof_key_thumbprint};
use basil_cose::{
    Claims, ContentAlgorithm, ContentType, Ed25519Signer, ExternalAad, KdfParties, KeyId,
    MessageId, MessageRole, ProtectedHeaders, SealParams, SealedAad, Signature, SignatureAlgorithm,
    Signer, Subject, UnixTime, ValidationParams, Verifier, VerifyError, VerifySealedParams,
    X25519RecipientPublic, Zeroizing, build_sealed_with_headers, verify_sealed,
};
use basil_proto::broker::v1::SealedRequest;
use basil_proto::broker::v1::invocation_service_client::InvocationServiceClient;
use basil_tests::{
    Engine, INVOCATION_AUDIENCE, INVOCATION_RESPONSE_KEY_ID, InvocationBootSpec, ProviderArm,
    alloc_addr, boot_basil_invocation, on_path,
};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Status};
use tower::service_fn;

/// COSE header label 1 (`alg`). Not re-exported by `basil-cose` (the codec is
/// private), so the forge spells the RFC 9052 numbers itself.
const HDR_ALG: i64 = 1;
/// COSE header label 2 (`crit`).
const HDR_CRIT: i64 = 2;
/// COSE header label 4 (`kid`).
const HDR_KID: i64 = 4;
/// CBOR tag 18 (`COSE_Sign1`).
const TAG_SIGN1: u64 = 18;
/// `RS256`: a JOSE algorithm outside the COSE signature profile.
const ALG_RS256: i64 = -257;

/// Deterministic Ed25519 seed of the honest remote workload's proof key.
const PROOF_SEED: [u8; 32] = [0x11; 32];
/// Deterministic Ed25519 seed of a SECOND proof key used for substitution.
const OTHER_SEED: [u8; 32] = [0x22; 32];
/// Deterministic Ed25519 seed of the subject-key invocation signer.
const SUBJECT_SEED: [u8; 32] = [0x33; 32];
/// Deterministic X25519 public half provisioned as the response key.
const RESPONSE_PUBLIC: [u8; 32] = [0x44; 32];
/// Deterministic X25519 public half the caller seals its request to.
const REQUEST_PUBLIC: [u8; 32] = [0x55; 32];

// ---------------------------------------------------------------------------
// The two tests: one per provider arm of the matrix.
// ---------------------------------------------------------------------------

#[test]
fn github_arm_denies_the_adversarial_proof_corpus() {
    run_arm(ProviderArm::GithubActions, "jjgi-matrix-gh");
}

/// The Forgejo arm of the same matrix. Forgejo is an experimental provider, so
/// this test also proves that the explicit experimental-provider opt-in loads.
/// The arm runs under the standard focused test command alongside GitHub.
#[test]
fn forgejo_arm_denies_the_adversarial_proof_corpus() {
    run_arm(ProviderArm::ForgejoActions, "jjgi-matrix-fj");
}

fn run_arm(arm: ProviderArm, tag: &str) {
    if !on_path("bao") {
        eprintln!("SKIP: `bao` not on PATH; skipping the {arm:?} proof-bound acceptance matrix");
        return;
    }
    let addr = alloc_addr();
    let spec = InvocationBootSpec {
        provider: arm,
        // Courier-shaped deployment: a challenge-less subject-key request is
        // denied, which is what makes the response-key checks reachable
        // without ever decrypting a request body.
        require_challenge: true,
        subject_signature_key: URL_SAFE_NO_PAD.encode(
            Ed25519Signer::from_secret_bytes(text_key("subject"), &Zeroizing::new(SUBJECT_SEED))
                .public_key_bytes(),
        ),
        second_subject_signature_key: None,
        response_public: RESPONSE_PUBLIC,
        challenge: None,
    };
    let harness = boot_basil_invocation(tag, Engine::OpenBao, &addr, &spec);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    runtime.block_on(async {
        let mut client = InvocationServiceClient::new(uds_channel(&harness.socket()).await);
        let corpus = proof_bound_corpus().await;
        for case in &corpus {
            check_local_oracle(case);
            let status = invoke_expecting_denial(&mut client, case).await;
            case.expect.assert_status(case.name, &status);
        }
        assert!(
            corpus.len() >= 25,
            "the adversarial corpus shrank to {} cases; rows must not be dropped silently",
            corpus.len()
        );
        response_key_substitution_is_denied(&mut client).await;
        one_proof_key_survives_a_token_refresh(&mut client).await;
    });
}

// ---------------------------------------------------------------------------
// Expected outcomes.
// ---------------------------------------------------------------------------

/// What a corpus case must produce, at both oracles.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// The honest baseline: locally valid, and denied live only because the
    /// provider token cannot be verified.
    BaselineDeniedAtProvider,
    /// Rejected by strict decode; the message must contain this fragment.
    Decode(&'static str),
    /// Rejected by signature/algorithm verification.
    Unauthorized,
    /// Rejected, but the layer is mutation-dependent (bit flips in structural
    /// bytes can land at either decode or signature verification).
    Denied,
}

impl Expect {
    fn assert_status(self, name: &str, status: &Status) {
        match self {
            Self::BaselineDeniedAtProvider | Self::Unauthorized => assert_eq!(
                status.code(),
                Code::PermissionDenied,
                "{name}: expected a permission denial, got {status:?}"
            ),
            Self::Decode(fragment) => {
                assert_eq!(
                    status.code(),
                    Code::InvalidArgument,
                    "{name}: expected a strict-decode rejection, got {status:?}"
                );
                assert!(
                    status.message().contains(fragment),
                    "{name}: denial message {:?} does not name `{fragment}`",
                    status.message()
                );
            }
            Self::Denied => assert!(
                matches!(
                    status.code(),
                    Code::InvalidArgument | Code::PermissionDenied
                ),
                "{name}: expected a denial, got {status:?}"
            ),
        }
    }
}

/// One forged request plus the outcome it must produce.
struct Case {
    name: &'static str,
    message: Vec<u8>,
    expect: Expect,
}

// ---------------------------------------------------------------------------
// The corpus.
// ---------------------------------------------------------------------------

async fn proof_bound_corpus() -> Vec<Case> {
    let proof =
        Ed25519Signer::from_secret_bytes(proof_kid(&PROOF_SEED), &Zeroizing::new(PROOF_SEED));
    let other =
        Ed25519Signer::from_secret_bytes(proof_kid(&OTHER_SEED), &Zeroizing::new(OTHER_SEED));
    let proof_public = proof.public_key_bytes();
    let other_public = other.public_key_bytes();
    let token = provider_token("run-1");

    let baseline = build_baseline(&proof, &token).await;
    let payload = sign1_payload(&baseline);
    let kid = proof_key_kid(&proof_public).into_bytes();
    let other_kid = proof_key_kid(&other_public).into_bytes();
    let key = proof_key_cose(&proof_public);
    let jwts = vec![token.clone()];

    let mut cases = vec![Case {
        name: "baseline: honest proof-bound request",
        message: baseline.clone(),
        expect: Expect::BaselineDeniedAtProvider,
    }];

    // -- malformed proof COSE_Key corpus. Every variant must land on the SAME
    // denial as a wrong signature: a malformed key must not be a distinguishing
    // oracle for the shape the broker expects.
    for (name, malformed) in malformed_proof_keys(&proof_public) {
        cases.push(Case {
            name,
            message: forge(
                &proof,
                &Outer {
                    alg: SignatureAlgorithm::EdDsa.codepoint(),
                    crit: Some(vec![
                        basil_cose::label::SIGNER_CERTIFICATES_JWT,
                        basil_cose::label::SIGNER_PUBLIC_KEY_COSE,
                    ]),
                    kid: kid.clone(),
                    jwts: Some(jwts.clone()),
                    proof_key: Some(malformed),
                },
                &payload,
            ),
            expect: Expect::Unauthorized,
        });
    }

    // -- critical protected header (-70007) enforcement.
    cases.push(Case {
        name: "crit omits -70007 while the proof key is present",
        message: forge(
            &proof,
            &Outer {
                alg: SignatureAlgorithm::EdDsa.codepoint(),
                crit: Some(vec![basil_cose::label::SIGNER_CERTIFICATES_JWT]),
                kid: kid.clone(),
                jwts: Some(jwts.clone()),
                proof_key: Some(key.clone()),
            },
            &payload,
        ),
        expect: Expect::Decode("not listed in crit"),
    });
    cases.push(Case {
        name: "crit absent while both proof headers are present",
        message: forge(
            &proof,
            &Outer {
                alg: SignatureAlgorithm::EdDsa.codepoint(),
                crit: None,
                kid: kid.clone(),
                jwts: Some(jwts.clone()),
                proof_key: Some(key.clone()),
            },
            &payload,
        ),
        expect: Expect::Decode("missing crit header"),
    });
    cases.push(Case {
        name: "crit lists -70007 but the proof key header is absent",
        message: forge(
            &proof,
            &Outer {
                alg: SignatureAlgorithm::EdDsa.codepoint(),
                crit: Some(vec![
                    basil_cose::label::SIGNER_CERTIFICATES_JWT,
                    basil_cose::label::SIGNER_PUBLIC_KEY_COSE,
                ]),
                kid: kid.clone(),
                jwts: Some(jwts.clone()),
                proof_key: None,
            },
            &payload,
        ),
        expect: Expect::Decode("unexpected crit entry -70007"),
    });
    cases.push(Case {
        name: "crit entries in non-canonical order",
        message: forge(
            &proof,
            &Outer {
                alg: SignatureAlgorithm::EdDsa.codepoint(),
                crit: Some(vec![
                    basil_cose::label::SIGNER_PUBLIC_KEY_COSE,
                    basil_cose::label::SIGNER_CERTIFICATES_JWT,
                ]),
                kid: kid.clone(),
                jwts: Some(jwts.clone()),
                proof_key: Some(key.clone()),
            },
            &payload,
        ),
        expect: Expect::Decode("non-deterministic encoding"),
    });

    // -- algorithm confusion.
    cases.push(Case {
        name: "alg claims ES256 over an Ed25519 proof-key signature",
        message: forge(
            &proof,
            &Outer {
                alg: SignatureAlgorithm::Es256.codepoint(),
                crit: Some(vec![
                    basil_cose::label::SIGNER_CERTIFICATES_JWT,
                    basil_cose::label::SIGNER_PUBLIC_KEY_COSE,
                ]),
                kid: kid.clone(),
                jwts: Some(jwts.clone()),
                proof_key: Some(key.clone()),
            },
            &payload,
        ),
        expect: Expect::Unauthorized,
    });
    cases.push(Case {
        name: "alg claims RS256, outside the COSE signature profile",
        message: forge(
            &proof,
            &Outer {
                alg: ALG_RS256,
                crit: Some(vec![
                    basil_cose::label::SIGNER_CERTIFICATES_JWT,
                    basil_cose::label::SIGNER_PUBLIC_KEY_COSE,
                ]),
                kid: kid.clone(),
                jwts: Some(jwts.clone()),
                proof_key: Some(key.clone()),
            },
            &payload,
        ),
        expect: Expect::Decode("outside the profile"),
    });

    // -- key substitution.
    cases.push(Case {
        name: "proof key swapped, attacker kid, victim signature",
        message: forge(
            &proof,
            &Outer {
                alg: SignatureAlgorithm::EdDsa.codepoint(),
                crit: Some(vec![
                    basil_cose::label::SIGNER_CERTIFICATES_JWT,
                    basil_cose::label::SIGNER_PUBLIC_KEY_COSE,
                ]),
                kid: other_kid,
                jwts: Some(jwts.clone()),
                proof_key: Some(proof_key_cose(&other_public)),
            },
            &payload,
        ),
        expect: Expect::Unauthorized,
    });
    cases.push(Case {
        name: "proof key swapped while the victim kid is kept",
        message: forge(
            &proof,
            &Outer {
                alg: SignatureAlgorithm::EdDsa.codepoint(),
                crit: Some(vec![
                    basil_cose::label::SIGNER_CERTIFICATES_JWT,
                    basil_cose::label::SIGNER_PUBLIC_KEY_COSE,
                ]),
                kid: kid.clone(),
                jwts: Some(jwts.clone()),
                proof_key: Some(proof_key_cose(&other_public)),
            },
            &payload,
        ),
        expect: Expect::Unauthorized,
    });
    cases.push(Case {
        name: "kid substituted for a name that is not the thumbprint",
        message: forge(
            &proof,
            &Outer {
                alg: SignatureAlgorithm::EdDsa.codepoint(),
                crit: Some(vec![
                    basil_cose::label::SIGNER_CERTIFICATES_JWT,
                    basil_cose::label::SIGNER_PUBLIC_KEY_COSE,
                ]),
                kid: b"ci.request.seal".to_vec(),
                jwts: Some(jwts.clone()),
                proof_key: Some(key.clone()),
            },
            &payload,
        ),
        expect: Expect::Unauthorized,
    });
    cases.push(Case {
        name: "attacker signature under a second key it controls",
        message: forge(
            &other,
            &Outer {
                alg: SignatureAlgorithm::EdDsa.codepoint(),
                crit: Some(vec![
                    basil_cose::label::SIGNER_CERTIFICATES_JWT,
                    basil_cose::label::SIGNER_PUBLIC_KEY_COSE,
                ]),
                kid: kid.clone(),
                jwts: Some(jwts),
                proof_key: Some(key),
            },
            &payload,
        ),
        expect: Expect::Unauthorized,
    });
    cases.push(Case {
        name: "proof headers stripped to downgrade onto the subject-key path",
        message: forge(
            &proof,
            &Outer {
                alg: SignatureAlgorithm::EdDsa.codepoint(),
                crit: None,
                kid,
                jwts: None,
                proof_key: None,
            },
            &payload,
        ),
        expect: Expect::Unauthorized,
    });

    // -- COSE mutation corpus over the honest baseline bytes.
    cases.extend(mutation_corpus(&baseline));
    cases
}

/// Byte-level mutations of an otherwise honest sealed request.
fn mutation_corpus(baseline: &[u8]) -> Vec<Case> {
    let flip = |at_end: usize| -> Vec<u8> {
        let mut bytes = baseline.to_vec();
        let index = bytes.len() - at_end;
        bytes[index] ^= 0x01;
        bytes
    };
    let mut truncated = baseline.to_vec();
    truncated.pop();
    let mut extended = baseline.to_vec();
    extended.push(0x00);
    let mut head_flipped = baseline.to_vec();
    head_flipped[8] ^= 0x01;

    vec![
        Case {
            name: "mutation: last signature byte flipped",
            message: flip(1),
            expect: Expect::Unauthorized,
        },
        Case {
            name: "mutation: first signature byte flipped",
            message: flip(64),
            expect: Expect::Unauthorized,
        },
        Case {
            name: "mutation: ciphertext byte flipped",
            message: flip(80),
            expect: Expect::Denied,
        },
        Case {
            name: "mutation: message truncated",
            message: truncated,
            expect: Expect::Denied,
        },
        Case {
            name: "mutation: trailing byte appended",
            message: extended,
            expect: Expect::Denied,
        },
        Case {
            name: "mutation: protected-header byte flipped",
            message: head_flipped,
            expect: Expect::Denied,
        },
        Case {
            name: "mutation: empty message",
            message: Vec::new(),
            expect: Expect::Decode("missing sealed COSE message"),
        },
        Case {
            name: "mutation: not COSE at all",
            message: b"this is not a COSE_Sign1".to_vec(),
            expect: Expect::Denied,
        },
    ]
}

/// The malformed `COSE_Key` corpus for the `-70007` proof key. The only
/// accepted shape is deterministic CBOR `{1: 1, -1: 6, -2: <32 bytes>}`.
fn malformed_proof_keys(public: &[u8; 32]) -> Vec<(&'static str, Vec<u8>)> {
    let x = public.to_vec();
    vec![
        ("malformed proof key: two members", {
            let mut e = Cbor::default();
            e.map(2);
            e.i64(1);
            e.i64(1);
            e.i64(-1);
            e.i64(6);
            e.done()
        }),
        ("malformed proof key: extra member", {
            let mut e = Cbor::default();
            e.map(4);
            e.i64(1);
            e.i64(1);
            e.i64(3);
            e.i64(0);
            e.i64(-1);
            e.i64(6);
            e.i64(-2);
            e.bytes(&x);
            e.done()
        }),
        (
            "malformed proof key: kty is not OKP",
            proof_key_parts(2, 6, &x),
        ),
        (
            "malformed proof key: crv is not Ed25519",
            proof_key_parts(1, 1, &x),
        ),
        (
            "malformed proof key: 31-byte public",
            proof_key_parts(1, 6, &x[..31]),
        ),
        ("malformed proof key: 33-byte public", {
            let mut long = x.clone();
            long.push(0);
            proof_key_parts(1, 6, &long)
        }),
        (
            "malformed proof key: empty public",
            proof_key_parts(1, 6, &[]),
        ),
        ("malformed proof key: non-canonical label order", {
            let mut e = Cbor::default();
            e.map(3);
            e.i64(1);
            e.i64(1);
            e.i64(-2);
            e.bytes(&x);
            e.i64(-1);
            e.i64(6);
            e.done()
        }),
        ("malformed proof key: trailing bytes", {
            let mut bytes = proof_key_parts(1, 6, &x);
            bytes.push(0x00);
            bytes
        }),
        ("malformed proof key: indefinite-length map", {
            let mut bytes = vec![0xbf_u8];
            let mut e = Cbor::default();
            e.i64(1);
            e.i64(1);
            e.i64(-1);
            e.i64(6);
            e.i64(-2);
            e.bytes(&x);
            bytes.extend(e.done());
            bytes.push(0xff);
            bytes
        }),
        ("malformed proof key: public encoded as text", {
            let mut e = Cbor::default();
            e.map(3);
            e.i64(1);
            e.i64(1);
            e.i64(-1);
            e.i64(6);
            e.i64(-2);
            e.text(&URL_SAFE_NO_PAD.encode(&x));
            e.done()
        }),
        (
            "malformed proof key: not CBOR",
            b"\xff\xff\xff\xff".to_vec(),
        ),
        ("malformed proof key: empty", Vec::new()),
    ]
}

/// A `COSE_Key` map with caller-chosen `kty`, `crv`, and public bytes.
fn proof_key_parts(kty: i64, crv: i64, public: &[u8]) -> Vec<u8> {
    let mut e = Cbor::default();
    e.map(3);
    e.i64(1);
    e.i64(kty);
    e.i64(-1);
    e.i64(crv);
    e.i64(-2);
    e.bytes(public);
    e.done()
}

/// The one accepted deterministic proof `COSE_Key` encoding.
fn proof_key_cose(public: &[u8; 32]) -> Vec<u8> {
    proof_key_parts(1, 6, public)
}

// ---------------------------------------------------------------------------
// Response-key substitution (subject-key path).
// ---------------------------------------------------------------------------

/// A sealed request may only name the broker's designated response-encryption
/// key. Naming any other catalog key — an unknown name, a non-sealing key, or a
/// sealing key that does not carry `broker_key_use=response-encryption` — must
/// be refused, so a caller can never steer the broker into sealing its answer
/// to an X25519 key the caller controls.
async fn response_key_substitution_is_denied(client: &mut InvocationServiceClient<Channel>) {
    let signer =
        Ed25519Signer::from_secret_bytes(text_key("subject"), &Zeroizing::new(SUBJECT_SEED));
    for (response_key, fragment) in [
        ("no.such.key", "unknown response encryption key"),
        ("web.tls.signing_key", "must be class `sealing`"),
        ("pqc.seal", "broker_key_use"),
    ] {
        let message = build_subject_request(&signer, response_key).await;
        let status = client
            .invoke(SealedRequest {
                message: message.clone(),
            })
            .await
            .err()
            .unwrap_or_else(|| panic!("response key `{response_key}` must not be accepted"));
        assert_eq!(
            status.code(),
            Code::InvalidArgument,
            "response key `{response_key}`: unexpected status {status:?}"
        );
        assert!(
            status.message().contains(fragment),
            "response key `{response_key}`: message {:?} does not name `{fragment}`",
            status.message()
        );
    }

    // Control: the designated key IS accepted as a response key, so the three
    // denials above are attributable to the substitution and not to the
    // subject-key request being malformed. The broker answers the missing
    // freshness challenge with a SEALED denial rather than a bare error.
    let message = build_subject_request(&signer, INVOCATION_RESPONSE_KEY_ID).await;
    let sealed = client
        .invoke(SealedRequest { message })
        .await
        .expect("the designated response key yields a sealed denial")
        .into_inner();
    assert!(
        !sealed.message.is_empty(),
        "a sealed challenge denial must carry COSE response bytes"
    );
    assert_eq!(
        sealed.message.first().copied(),
        Some(0xd2),
        "the sealed denial must be a tagged COSE_Sign1"
    );
}

// ---------------------------------------------------------------------------
// One proof key across a provider token refresh.
// ---------------------------------------------------------------------------

/// A CI job that refreshes its provider token mid-run keeps ONE proof key. The
/// binding the broker uses — the RFC 7638 thumbprint (`jkt`), the outer `kid`,
/// and the `urn:basil:ci:jkt:` audience — must be a function of that key alone,
/// so a token refresh changes neither the audience the workload must claim nor
/// the challenge binding, and both requests are denied identically.
async fn one_proof_key_survives_a_token_refresh(client: &mut InvocationServiceClient<Channel>) {
    let proof =
        Ed25519Signer::from_secret_bytes(proof_kid(&PROOF_SEED), &Zeroizing::new(PROOF_SEED));
    let public = proof.public_key_bytes();

    let first = build_baseline(&proof, &provider_token("run-1")).await;
    let second = build_baseline(&proof, &provider_token("run-2")).await;
    assert_ne!(first, second, "the refresh must change the request bytes");

    let expected_kid = proof_key_kid(&public);
    let expected_audience = proof_audience(&public);
    assert_eq!(
        expected_audience,
        format!(
            "urn:basil:ci:jkt:{}",
            URL_SAFE_NO_PAD.encode(proof_key_thumbprint(&public))
        ),
        "the audience must be exactly the base64url thumbprint of the proof key"
    );

    let mut statuses = Vec::new();
    for message in [first, second] {
        let verified = verify_sealed(
            &message,
            &ProofKeyVerifier,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation_params(),
            },
        )
        .await
        .expect("a token refresh must not invalidate the sealed request");
        assert_eq!(
            verified.signer_key_id.as_bytes(),
            expected_kid.as_bytes(),
            "the outer kid must stay the proof-key thumbprint across a refresh"
        );
        assert_eq!(
            verified.claims.audience.as_ref().map(Subject::as_str),
            Some(expected_audience.as_str()),
            "the audience must stay bound to the proof key across a refresh"
        );
        statuses.push(
            client
                .invoke(SealedRequest { message })
                .await
                .expect_err("an unverifiable provider token must be denied")
                .code(),
        );
    }
    assert_eq!(
        statuses[0], statuses[1],
        "a token refresh must not change the broker's decision for one proof key"
    );
}

// ---------------------------------------------------------------------------
// Oracles and transport.
// ---------------------------------------------------------------------------

/// Run the local structural oracle for one case, pinning the wire-level cause
/// of its denial before the live broker is consulted.
fn check_local_oracle(case: &Case) {
    let outcome = futures_lite_block_on(verify_sealed(
        &case.message,
        &ProofKeyVerifier,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation_params(),
        },
    ));
    match case.expect {
        Expect::BaselineDeniedAtProvider => {
            outcome.unwrap_or_else(|error| {
                panic!(
                    "{}: the baseline must verify locally, got {error}",
                    case.name
                )
            });
        }
        Expect::Decode(fragment) => {
            let error = outcome
                .err()
                .unwrap_or_else(|| panic!("{}: expected a decode rejection", case.name));
            // The empty-message case never reaches `verify_sealed` on the
            // broker (the RPC rejects it first), so only assert the fragment
            // when the local decoder can see it.
            assert!(
                matches!(error, VerifyError::Decode(_)),
                "{}: expected a decode rejection, got {error}",
                case.name
            );
            assert!(
                error.to_string().contains(fragment) || case.message.is_empty(),
                "{}: local error {error} does not name `{fragment}`",
                case.name
            );
        }
        Expect::Unauthorized => {
            let error = outcome
                .err()
                .unwrap_or_else(|| panic!("{}: expected a signature rejection", case.name));
            assert!(
                matches!(
                    error,
                    VerifyError::SignatureInvalid | VerifyError::AlgorithmMismatch
                ),
                "{}: expected a signature rejection, got {error}",
                case.name
            );
        }
        Expect::Denied => {
            assert!(
                outcome.is_err(),
                "{}: a mutated message must never verify locally",
                case.name
            );
        }
    }
}

async fn invoke_expecting_denial(
    client: &mut InvocationServiceClient<Channel>,
    case: &Case,
) -> Status {
    client
        .invoke(SealedRequest {
            message: case.message.clone(),
        })
        .await
        .err()
        .unwrap_or_else(|| panic!("{}: the broker ACCEPTED an adversarial request", case.name))
}

/// A verifier that mirrors the broker's proof-key rule exactly: the outer `kid`
/// must be the RFC 7638 thumbprint of the presented `-70007` key, the algorithm
/// must be `EdDSA`, and the signature must verify under that key. Requests
/// without a proof key are refused (this lane never uses the subject-key path
/// through this oracle).
struct ProofKeyVerifier;

impl Verifier for ProofKeyVerifier {
    async fn verify(
        &self,
        key_id: &KeyId,
        algorithm: SignatureAlgorithm,
        protected_headers: &ProtectedHeaders,
        sig_structure: &[u8],
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        let Some(encoded) = protected_headers.signer_public_key_cose.as_deref() else {
            return Err(VerifyError::SignatureInvalid);
        };
        let public = basil_core::ci_federation::decode_proof_key_cose(encoded)
            .map_err(|_| VerifyError::SignatureInvalid)?;
        if key_id.as_bytes() != proof_key_kid(&public).as_bytes()
            || algorithm != SignatureAlgorithm::EdDsa
        {
            return Err(VerifyError::SignatureInvalid);
        }
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|_| VerifyError::SignatureInvalid)?;
        let bytes: [u8; 64] = signature
            .as_bytes()
            .try_into()
            .map_err(|_| VerifyError::SignatureInvalid)?;
        verifying
            .verify_strict(sig_structure, &ed25519_dalek::Signature::from_bytes(&bytes))
            .map_err(|_| VerifyError::SignatureInvalid)
    }
}

async fn uds_channel(path: &std::path::Path) -> Channel {
    let path = path.to_path_buf();
    Endpoint::try_from("http://[::]:50051")
        .expect("static endpoint parses")
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { UnixStream::connect(path).await.map(TokioIo::new) }
        }))
        .await
        .expect("connect to the broker unix socket")
}

// ---------------------------------------------------------------------------
// Building honest and forged messages.
// ---------------------------------------------------------------------------

/// Build the honest proof-bound sealed request every forged case derives from.
async fn build_baseline(proof: &Ed25519Signer, token: &str) -> Vec<u8> {
    let public = proof.public_key_bytes();
    let claims = Claims {
        issuer: None,
        audience: Some(Subject::new(proof_audience(&public)).expect("proof audience is a subject")),
        expires_at: None,
        issued_at: UnixTime(now_unix()),
        message_id: MessageId::from_bytes(uuid_like(token)).expect("message id"),
        sender_key_id: Some(proof_kid(&PROOF_SEED)),
        response_key_id: Some(text_key(INVOCATION_RESPONSE_KEY_ID)),
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
        freshness_challenge: Some(
            basil_cose::FreshnessChallenge::from_bytes(&[0x5a; 32]).expect("challenge"),
        ),
        response_public_key_cose: None,
    };
    build_sealed_with_headers(
        &seal_params(claims),
        &ProtectedHeaders {
            signer_certificates_jwt: vec![token.to_string()],
            signer_public_key_cose: Some(proof_key_cose(&public)),
        },
        proof,
    )
    .await
    .expect("build the honest proof-bound request")
    .into_vec()
}

/// Build a subject-key (non-federated) sealed request naming `response_key`.
async fn build_subject_request(signer: &Ed25519Signer, response_key: &str) -> Vec<u8> {
    let claims = Claims {
        issuer: None,
        audience: Some(Subject::new(INVOCATION_AUDIENCE.to_string()).expect("broker audience")),
        expires_at: None,
        issued_at: UnixTime(now_unix()),
        message_id: MessageId::from_bytes(uuid_like(response_key)).expect("message id"),
        sender_key_id: Some(signer.key_id().clone()),
        response_key_id: Some(text_key(response_key)),
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
        freshness_challenge: None,
        response_public_key_cose: None,
    };
    basil_cose::build_sealed(&seal_params(claims), signer)
        .await
        .expect("build the subject-key request")
        .into_vec()
}

fn seal_params(claims: Claims) -> SealParams<'static> {
    SealParams {
        content_type: ContentType::new("application/vnd.basil.sign-request".to_string())
            .expect("content type"),
        plaintext: b"proof-bound acceptance corpus",
        claims,
        role: MessageRole::Request,
        recipient: X25519RecipientPublic {
            key_id: text_key(basil_tests::INVOCATION_REQUEST_KEY_ID),
            public: REQUEST_PUBLIC,
        },
        content_algorithm: ContentAlgorithm::A256Gcm,
        aad: SealedAad::empty(),
        kdf_parties: KdfParties::anonymous(),
    }
}

/// The outer protected header of a forged `COSE_Sign1`.
struct Outer {
    alg: i64,
    crit: Option<Vec<i64>>,
    kid: Vec<u8>,
    jwts: Option<Vec<String>>,
    proof_key: Option<Vec<u8>>,
}

/// Forge a `COSE_Sign1` with a caller-chosen outer protected header over an
/// existing sealed payload, signed for real by `signer`. This is the client a
/// hostile CI job would write: the signature is always genuine over whatever
/// header the attacker chose, so nothing here is rejected merely because the
/// bytes are inconsistent with themselves.
fn forge(signer: &Ed25519Signer, outer: &Outer, payload: &[u8]) -> Vec<u8> {
    let protected = encode_outer(outer);
    let mut sig = Cbor::default();
    sig.array(4);
    sig.text("Signature1");
    sig.bytes(&protected);
    sig.bytes(&[]);
    sig.bytes(payload);
    let signature =
        futures_lite_block_on(signer.sign(&sig.done())).expect("sign the forged Sig_structure");

    let mut out = Cbor::default();
    out.tag(TAG_SIGN1);
    out.array(4);
    out.bytes(&protected);
    out.map(0);
    out.bytes(payload);
    out.bytes(signature.as_bytes());
    out.done()
}

fn encode_outer(outer: &Outer) -> Vec<u8> {
    let mut entries = 2_u64;
    entries += u64::from(outer.crit.is_some());
    entries += u64::from(outer.jwts.is_some());
    entries += u64::from(outer.proof_key.is_some());

    let mut e = Cbor::default();
    e.map(entries);
    e.i64(HDR_ALG);
    e.i64(outer.alg);
    if let Some(crit) = &outer.crit {
        e.i64(HDR_CRIT);
        e.array(crit.len() as u64);
        for label in crit {
            e.i64(*label);
        }
    }
    e.i64(HDR_KID);
    e.bytes(&outer.kid);
    if let Some(jwts) = &outer.jwts {
        e.i64(basil_cose::label::SIGNER_CERTIFICATES_JWT);
        e.array(jwts.len() as u64);
        for jwt in jwts {
            e.text(jwt);
        }
    }
    if let Some(key) = &outer.proof_key {
        e.i64(basil_cose::label::SIGNER_PUBLIC_KEY_COSE);
        e.bytes(key);
    }
    e.done()
}

/// Extract the embedded tagged `COSE_Encrypt` payload of a `COSE_Sign1`.
fn sign1_payload(bytes: &[u8]) -> Vec<u8> {
    let mut decoder = minicbor::Decoder::new(bytes);
    decoder.tag().expect("tagged COSE_Sign1");
    assert_eq!(decoder.array().expect("array header"), Some(4));
    decoder.bytes().expect("protected header");
    decoder.skip().expect("unprotected header");
    decoder.bytes().expect("payload").to_vec()
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

/// A syntactically valid compact JWT with NO `kid` header, so the broker fails
/// closed at token-header decode and this lane never contacts a provider.
fn provider_token(run: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = URL_SAFE_NO_PAD.encode(
        format!(
            r#"{{"iss":"https://token.actions.githubusercontent.com","jti":"{run}","iat":{now}}}"#,
            now = now_unix()
        )
        .as_bytes(),
    );
    format!("{header}.{claims}.{}", URL_SAFE_NO_PAD.encode([0_u8; 8]))
}

fn validation_params() -> ValidationParams {
    ValidationParams {
        now: UnixTime(now_unix()),
        max_clock_skew: Duration::from_secs(30),
        max_ttl: Duration::from_mins(5),
        default_ttl: Duration::from_mins(2),
        allowed_audiences: std::collections::BTreeSet::new(),
        role: MessageRole::Request,
    }
}

fn proof_kid(seed: &[u8; 32]) -> KeyId {
    let signer = Ed25519Signer::from_secret_bytes(text_key("bootstrap"), &Zeroizing::new(*seed));
    text_key(&proof_key_kid(&signer.public_key_bytes()))
}

fn text_key(name: &str) -> KeyId {
    KeyId::from_text(name).expect("key id is text")
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs(),
    )
    .expect("unix seconds fit in i64")
}

/// A deterministic 16-byte message id derived from `seed`.
fn uuid_like(seed: &str) -> Vec<u8> {
    let mut bytes = vec![0_u8; 16];
    for (index, byte) in seed.bytes().enumerate() {
        bytes[index % 16] ^= byte;
    }
    bytes[0] |= 0x40;
    bytes
}

/// Poll a future that never awaits real I/O to completion on the current
/// thread. `build_sealed*`, `verify_sealed`, and `Signer::sign` are async only
/// because the production signer/recipient live behind an RPC; the local
/// Ed25519 implementations complete on the first poll.
fn futures_lite_block_on<F: Future>(future: F) -> F::Output {
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("a local COSE future must complete on the first poll"),
    }
}

/// Minimal deterministic CBOR writer for the forge. Only the encodings the
/// COSE profile uses are supported; every integer is written in its shortest
/// form so a forged header is byte-comparable with a legitimate one.
#[derive(Default)]
struct Cbor(Vec<u8>);

impl Cbor {
    fn head(&mut self, major: u8, argument: u64) {
        let major = major << 5;
        match argument {
            0..=23 => self.0.push(major | u8::try_from(argument).expect("small")),
            24..=0xff => {
                self.0.push(major | 0x18);
                self.0.push(u8::try_from(argument).expect("one byte"));
            }
            0x100..=0xffff => {
                self.0.push(major | 0x19);
                self.0
                    .extend(u16::try_from(argument).expect("two bytes").to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(major | 0x1a);
                self.0
                    .extend(u32::try_from(argument).expect("four bytes").to_be_bytes());
            }
            _ => {
                self.0.push(major | 0x1b);
                self.0.extend(argument.to_be_bytes());
            }
        }
    }

    fn i64(&mut self, value: i64) {
        if value >= 0 {
            self.head(0, value.cast_unsigned());
        } else {
            self.head(1, !value.cast_unsigned());
        }
    }

    fn bytes(&mut self, value: &[u8]) {
        self.head(2, value.len() as u64);
        self.0.extend_from_slice(value);
    }

    fn text(&mut self, value: &str) {
        self.head(3, value.len() as u64);
        self.0.extend_from_slice(value.as_bytes());
    }

    fn array(&mut self, len: u64) {
        self.head(4, len);
    }

    fn map(&mut self, len: u64) {
        self.head(5, len);
    }

    fn tag(&mut self, tag: u64) {
        self.head(6, tag);
    }

    fn done(self) -> Vec<u8> {
        self.0
    }
}
