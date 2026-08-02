// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! LIVE acceptance rows for the broker's freshness-challenge state machine
//! (`basil-jjgi.3.3.2`), driven over the REAL `InvocationService` RPCs
//! (`GetInvocationChallenge` + `Invoke`) of a booted broker.
//!
//! Covers the challenge rows of `docs/ci-oidc-federation/SPEC.md` "Required
//! acceptance": issuance shape, single-use consumption, concurrent duplicate
//! consumption, expiry boundary, wrong-`jkt` rejection (without burning the
//! rightful holder's challenge), wrong-generation rejection across a live
//! SIGHUP reload, restart invalidation (fresh instance ID), unknown-instance-
//! prefix routing, per-`jkt` and global capacity limits, per-source issuance
//! rate limiting, and capacity pressure degrading issuance while an
//! outstanding valid challenge still succeeds.
//!
//! Oracles. Consumption runs through the subject-key path (`invocation.
//! require-challenge = true`), which binds the challenge to the verified
//! Ed25519 subject key's RFC 7638 thumbprint — the same `ChallengeTable::
//! consume` call the proof-bound path uses, without needing a provider-signed
//! token (hermetic; see `basil-abdh` for the provider seam). Every consume
//! attempt lands on exactly one of two mutually exclusive wire outcomes:
//!
//! - **denied at freshness**: gRPC `Ok` carrying a SEALED `COSE_Sign1`
//!   response. The test opens it with the response key's X25519 private half
//!   (held by the test, provisioned as the boot's out-of-band public) after
//!   verifying the broker's transit signature, and asserts the encrypted body
//!   status is `CHALLENGE_UNKNOWN` (code 5, `retryable = false`);
//! - **consumed**: the flow proceeds past freshness, quota, and
//!   authorization into the request-body decrypt, which fails closed as a
//!   bare gRPC error because the request key's X25519 private half is
//!   deliberately not provisioned (the `basil-jjgi.3.3.1` boot invariant).
//!   Where a row's meaning depends on consumption having happened, a replay
//!   probe of the same challenge asserts the sealed `CHALLENGE_UNKNOWN`.
//!
//! Provider arm: the challenge table is provider-agnostic (issuance is
//! unauthenticated, and this lane consumes through the subject-key path), so
//! this matrix runs once on the GitHub-arm boot rather than per provider —
//! re-running it under the Forgejo `[federation]` stanza would change nothing
//! the table can observe.
//!
//! GATING: needs a live `bao`; prints an explicit skip line when absent.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use basil_core::ci_federation::proof_key_thumbprint;
use basil_cose::{
    Claims, ContentAlgorithm, ContentType, Ed25519Signer, Ed25519Verifier, ExternalAad,
    FreshnessChallenge, KdfParties, KeyId, MessageId, MessageRole, SealParams, SealedAad, Signer,
    Subject, UnixTime, ValidationParams, VerifySealedParams, X25519Recipient,
    X25519RecipientPublic, Zeroizing, build_sealed, verify_sealed,
};
use basil_proto::broker::v1::invocation_service_client::InvocationServiceClient;
use basil_proto::broker::v1::{GetInvocationChallengeRequest, SealedRequest};
use basil_proto::invocation::{
    CONTENT_TYPE_SIGN_REQUEST, InvocationStatusCode, REASON_CHALLENGE_UNKNOWN,
    SignInvocationResponse,
};
use basil_tests::{
    ChallengeTableBoot, Engine, INVOCATION_AUDIENCE, INVOCATION_RESPONSE_KEY_ID,
    INVOCATION_SIGNING_KEY_ID, InvocationBootSpec, ProviderArm, alloc_addr, boot_basil_invocation,
    on_path,
};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Status};
use tower::service_fn;

/// Deterministic Ed25519 seed of the primary subject-key signer (subject A).
const SUBJECT_A_SEED: [u8; 32] = [0x33; 32];
/// Deterministic Ed25519 seed of the second admitted signer (subject B).
const SUBJECT_B_SEED: [u8; 32] = [0x77; 32];
/// Deterministic X25519 private half of the broker response key. The test
/// holds it so sealed denials can be OPENED and their status asserted.
const RESPONSE_SECRET: [u8; 32] = [0x66; 32];
/// Deterministic X25519 public half the caller seals its request to. Its
/// private half is deliberately NEVER provisioned (boot invariant), so a
/// consumed challenge deterministically lands on the body-decrypt failure.
const REQUEST_PUBLIC: [u8; 32] = [0x55; 32];

/// The boot's `[invocation.challenge]` shape. Capacity is shrunk so global
/// exhaustion is reachable in-test; the per-`jkt` rate burst is raised ABOVE
/// the SPEC-fixed outstanding cap (8) so a per-`jkt` issuance decline is
/// attributable to the cap and not to rate limiting; the per-source bucket is
/// pinned burst-only (refill 0) so the per-source row's decline lands exactly
/// on issuance `burst + 1` instead of racing the bucket's integer-second
/// wall-clock refill (a refilling bucket can gain tokens mid-loop whenever a
/// second boundary falls inside it, letting the probe issuance succeed).
/// Requests without a courier-observed source never touch this bucket, so the
/// pin cannot starve the other rows.
const CHALLENGE_SHAPE: ChallengeTableBoot = ChallengeTableBoot {
    capacity: 256,
    per_jkt_rate_burst: 32,
    per_jkt_rate_refill_per_sec: 16,
    per_source_rate_burst: PER_SOURCE_RATE_BURST,
    per_source_rate_refill_per_sec: 0,
};

/// The pinned per-source burst (matches the SPEC default of 64).
const PER_SOURCE_RATE_BURST: u32 = 64;

/// SPEC-fixed bounds this matrix asserts against (`docs/ci-oidc-federation/
/// SPEC.md`, Freshness). Deliberately restated here rather than imported so a
/// broker-side drift fails the acceptance row.
const CHALLENGE_LEN: usize = 32;
const INSTANCE_ID_LEN: usize = 16;
const MAX_TTL_SECS: i64 = 60;
const PER_JKT_OUTSTANDING_CAP: usize = 8;

/// Process-wide uniqueness for request message IDs.
static MESSAGE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn challenge_lifecycle_and_capacity_over_the_real_rpc() {
    if !on_path("bao") {
        eprintln!("SKIP: `bao` not on PATH; skipping the challenge lifecycle acceptance matrix");
        return;
    }
    let addr = alloc_addr();
    let subject_a =
        Ed25519Signer::from_secret_bytes(text_key("subject-a"), &Zeroizing::new(SUBJECT_A_SEED));
    let subject_b =
        Ed25519Signer::from_secret_bytes(text_key("subject-b"), &Zeroizing::new(SUBJECT_B_SEED));
    let response_recipient = X25519Recipient::new(
        text_key(INVOCATION_RESPONSE_KEY_ID),
        Zeroizing::new(RESPONSE_SECRET),
    );
    let spec = InvocationBootSpec {
        provider: ProviderArm::GithubActions,
        require_challenge: true,
        subject_signature_key: URL_SAFE_NO_PAD.encode(subject_a.public_key_bytes()),
        second_subject_signature_key: Some(URL_SAFE_NO_PAD.encode(subject_b.public_key_bytes())),
        response_public: response_recipient.public().public,
        challenge: Some(CHALLENGE_SHAPE),
    };
    let mut harness = boot_basil_invocation("jjgi-challenge", Engine::OpenBao, &addr, &spec);
    let verifier = broker_signing_verifier(harness.backend_addr());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    runtime.block_on(async {
        let socket = harness.socket();
        let mut client = InvocationServiceClient::new(uds_channel(&socket).await);
        let jkt_a = proof_key_thumbprint(&subject_a.public_key_bytes());
        let jkt_b = proof_key_thumbprint(&subject_b.public_key_bytes());
        let ctx = Ctx {
            subject_a: &subject_a,
            subject_b: &subject_b,
            verifier: &verifier,
            response_recipient: &response_recipient,
        };

        // --- Row A: issuance shape (+ the two challenges the expiry row will
        // use ~60s from now, so the TTL clock overlaps the other rows).
        let expiry_control = issue(&mut client, jkt_a, None).await.expect("issue E1");
        let expiry_probe = issue(&mut client, jkt_a, None).await.expect("issue E2");
        issuance_shape_rows(&mut client, jkt_a, &expiry_control, &expiry_probe).await;

        // --- Row B: single-use consumption, then replay of the consumed
        // challenge.
        single_use_row(&mut client, &ctx, jkt_a).await;

        // --- Row C: concurrent duplicate consumption of ONE challenge.
        concurrent_duplicates_row(&socket, &ctx, jkt_a).await;

        // --- Row D: wrong-jkt consumption is denied WITHOUT burning the
        // rightful holder's challenge.
        wrong_jkt_row(&mut client, &ctx, jkt_b).await;

        // --- Row E: unknown-instance-prefix routing, record preserved.
        routing_row(&mut client, &ctx, jkt_a).await;

        // --- Row F: per-jkt outstanding cap degrades issuance for THAT jkt
        // only (rate burst is configured above the cap, so the decline is the
        // cap's).
        per_jkt_capacity_row(&mut client).await;

        // --- Row G: per-source issuance rate limiting, partitioned by
        // courier-observed source.
        per_source_rate_row(&mut client).await;

        // --- Row H: expiry boundary. The twin issued in row A proves the
        // pair was valid just before the boundary; the probe after it is
        // denied, so the only varying input is time.
        expiry_boundary_row(&socket, &ctx, &expiry_control, &expiry_probe).await;

        // Fresh channel after the expiry waits (the old one may have idled
        // out) for the remaining rows.
        let mut client = InvocationServiceClient::new(uds_channel(&socket).await);

        // --- Row I: wrong-generation rejection across a live SIGHUP reload.
        let generation_after_reload =
            wrong_generation_row(&mut client, &ctx, jkt_a, &harness).await;

        // --- Row J: global capacity pressure degrades issuance while an
        // outstanding valid challenge still succeeds. Also pre-issues the
        // restart row's challenge (issuance is impossible once the table is
        // full).
        let pre_restart =
            global_capacity_row(&mut client, &ctx, jkt_a, generation_after_reload).await;

        // --- Row K: restart invalidation — fresh instance ID, cleared table.
        restart_row(&mut harness, &ctx, jkt_a, &pre_restart).await;
    });
}

/// Shared per-row context: the two admitted signers and the response-opening
/// material.
struct Ctx<'a> {
    subject_a: &'a Ed25519Signer,
    subject_b: &'a Ed25519Signer,
    verifier: &'a Ed25519Verifier,
    response_recipient: &'a X25519Recipient,
}

/// One issued challenge as returned over the wire.
#[derive(Clone, Debug)]
struct Issued {
    challenge: Vec<u8>,
    generation: u64,
    expires_at_unix: i64,
}

/// The two mutually exclusive wire outcomes of a consume attempt.
enum Consume {
    /// The broker answered a SEALED denial; the opened body status was
    /// `CHALLENGE_UNKNOWN`.
    DeniedAtFreshness,
    /// The request got past the freshness step (the broker proceeded into
    /// the post-freshness pipeline and failed there as a bare gRPC error,
    /// by boot construction at the body decrypt — `classify` pins the
    /// layer before returning this variant).
    PassedFreshness,
}

// ---------------------------------------------------------------------------
// Rows.
// ---------------------------------------------------------------------------

async fn issuance_shape_rows(
    client: &mut InvocationServiceClient<Channel>,
    jkt: [u8; 32],
    first: &Issued,
    second: &Issued,
) {
    let now = now_unix();
    for (name, issued) in [("E1", first), ("E2", second)] {
        assert_eq!(
            issued.challenge.len(),
            CHALLENGE_LEN,
            "{name}: a challenge is exactly 32 bytes"
        );
        assert_eq!(issued.generation, 1, "{name}: issued under generation 1");
        assert!(
            issued.expires_at_unix > now - 2 && issued.expires_at_unix <= now + MAX_TTL_SECS + 2,
            "{name}: expires_at {} must be at most 60s out (now {now})",
            issued.expires_at_unix
        );
    }
    assert_eq!(
        first.challenge[..INSTANCE_ID_LEN],
        second.challenge[..INSTANCE_ID_LEN],
        "one issuing instance stamps one 16-byte prefix on every challenge"
    );
    assert_ne!(
        first.challenge[INSTANCE_ID_LEN..],
        second.challenge[INSTANCE_ID_LEN..],
        "CSPRNG suffixes must differ between issuances"
    );

    // Malformed issuance requests are rejected typed, not declined.
    for (name, bad_jkt) in [
        ("31-byte jkt", vec![0_u8; 31]),
        ("33-byte jkt", vec![0_u8; 33]),
    ] {
        let status = client
            .get_invocation_challenge(GetInvocationChallengeRequest {
                jkt: bad_jkt,
                courier_observed_source: None,
            })
            .await
            .expect_err(name)
            .code();
        assert_eq!(status, Code::InvalidArgument, "{name}: typed rejection");
    }
    let oversize = "s".repeat(129);
    let status = client
        .get_invocation_challenge(GetInvocationChallengeRequest {
            jkt: jkt.to_vec(),
            courier_observed_source: Some(oversize),
        })
        .await
        .expect_err("oversize courier_observed_source")
        .code();
    assert_eq!(
        status,
        Code::InvalidArgument,
        "courier_observed_source over 128 bytes: typed rejection"
    );
    eprintln!("ROW issuance-shape: ok");
}

async fn single_use_row(
    client: &mut InvocationServiceClient<Channel>,
    ctx: &Ctx<'_>,
    jkt: [u8; 32],
) {
    let issued = issue(client, jkt, None).await.expect("issue C1");
    let first = consume(
        client,
        ctx,
        ctx.subject_a,
        &issued.challenge,
        "single-use-1",
    )
    .await;
    assert!(
        matches!(first, Consume::PassedFreshness),
        "a freshly issued challenge must consume, got a freshness denial"
    );
    let replay = consume(
        client,
        ctx,
        ctx.subject_a,
        &issued.challenge,
        "single-use-2",
    )
    .await;
    assert!(
        matches!(replay, Consume::DeniedAtFreshness),
        "replaying a consumed challenge (fresh message ID) must be the sealed CHALLENGE_UNKNOWN"
    );
    eprintln!("ROW single-use: ok");
}

async fn concurrent_duplicates_row(socket: &std::path::Path, ctx: &Ctx<'_>, jkt: [u8; 32]) {
    let mut client_one = InvocationServiceClient::new(uds_channel(socket).await);
    let mut client_two = InvocationServiceClient::new(uds_channel(socket).await);
    let issued = issue(&mut client_one, jkt, None).await.expect("issue C2");
    // Two DISTINCT sealed messages carrying the SAME challenge, raced over
    // two connections: exactly one consumes, the other is denied.
    let message_one =
        build_challenge_request(ctx.subject_a, &issued.challenge, "concurrent-1").await;
    let message_two =
        build_challenge_request(ctx.subject_a, &issued.challenge, "concurrent-2").await;
    let (one, two) = tokio::join!(
        client_one.invoke(SealedRequest {
            message: message_one
        }),
        client_two.invoke(SealedRequest {
            message: message_two
        }),
    );
    let outcomes = [
        classify(ctx, one, "concurrent duplicate one").await,
        classify(ctx, two, "concurrent duplicate two").await,
    ];
    let denied = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Consume::DeniedAtFreshness))
        .count();
    assert_eq!(
        denied, 1,
        "concurrent duplicates must resolve to exactly one consumption and one denial"
    );
    eprintln!("ROW concurrent-duplicates: ok");
}

async fn wrong_jkt_row(
    client: &mut InvocationServiceClient<Channel>,
    ctx: &Ctx<'_>,
    jkt_b: [u8; 32],
) {
    // Challenge bound to subject B's thumbprint; subject A learned the bytes.
    let issued = issue(client, jkt_b, None).await.expect("issue C3");
    let stolen = consume(client, ctx, ctx.subject_a, &issued.challenge, "wrong-jkt-a").await;
    assert!(
        matches!(stolen, Consume::DeniedAtFreshness),
        "a consume attempt under the wrong jkt must be the sealed CHALLENGE_UNKNOWN"
    );
    // The record must survive for its rightful holder: B consumes it now.
    let rightful = consume(client, ctx, ctx.subject_b, &issued.challenge, "wrong-jkt-b").await;
    assert!(
        matches!(rightful, Consume::PassedFreshness),
        "the wrong-jkt attempt must not burn the rightful holder's challenge"
    );
    // And it was CONSUMED by B (single-use still holds after the mismatch).
    let replay = consume(
        client,
        ctx,
        ctx.subject_b,
        &issued.challenge,
        "wrong-jkt-b2",
    )
    .await;
    assert!(
        matches!(replay, Consume::DeniedAtFreshness),
        "the rightful holder's consumption is still single-use"
    );
    eprintln!("ROW wrong-jkt: ok");
}

async fn routing_row(client: &mut InvocationServiceClient<Channel>, ctx: &Ctx<'_>, jkt: [u8; 32]) {
    let issued = issue(client, jkt, None).await.expect("issue C4");
    let mut foreign = issued.challenge.clone();
    foreign[0] ^= 0x01; // an instance-ID prefix this agent never generated
    let routed = consume(client, ctx, ctx.subject_a, &foreign, "routing-foreign").await;
    assert!(
        matches!(routed, Consume::DeniedAtFreshness),
        "an unknown instance prefix must be answered as the sealed CHALLENGE_UNKNOWN"
    );
    // Answered without consulting the table: the real record is untouched.
    let intact = consume(
        client,
        ctx,
        ctx.subject_a,
        &issued.challenge,
        "routing-intact",
    )
    .await;
    assert!(
        matches!(intact, Consume::PassedFreshness),
        "a foreign-prefix probe must not burn the real record"
    );
    eprintln!("ROW routing: ok");
}

async fn per_jkt_capacity_row(client: &mut InvocationServiceClient<Channel>) {
    let jkt_x = fill_jkt(0xA0, 0);
    for index in 0..PER_JKT_OUTSTANDING_CAP {
        issue(client, jkt_x, None).await.unwrap_or_else(|status| {
            panic!("issuance {index} within the per-jkt cap must succeed, got {status:?}")
        });
    }
    // The 9th is declined. The boot configures the per-jkt rate burst (32)
    // ABOVE the cap (8), so this decline is the outstanding cap's.
    let declined = issue(client, jkt_x, None)
        .await
        .expect_err("the 9th outstanding challenge for one jkt must be declined");
    assert_issuance_declined("per-jkt cap", &declined);
    // Partition isolation: a different jkt still issues.
    issue(client, fill_jkt(0xA1, 0), None)
        .await
        .expect("a different jkt is not affected by another jkt's cap");
    eprintln!("ROW per-jkt-capacity: ok");
}

async fn per_source_rate_row(client: &mut InvocationServiceClient<Channel>) {
    // 64 issuances (the pinned burst-only per-source burst) across 64
    // DISTINCT jkts, all attributed to ONE courier-observed source: per-jkt
    // state is fresh for every request, and the boot pins the source
    // bucket's refill to 0, so the 65th decline is deterministically the
    // source bucket's regardless of where wall-clock second boundaries fall.
    let source_a = Some("matrix-source-a".to_string());
    for index in 0..PER_SOURCE_RATE_BURST {
        let jkt = fill_jkt(0xB0, u8::try_from(index).expect("burst fits a jkt index"));
        issue(client, jkt, source_a.clone())
            .await
            .unwrap_or_else(|status| {
                panic!("issuance {index} within the source burst must succeed, got {status:?}")
            });
    }
    let declined = issue(client, fill_jkt(0xB1, 0), source_a)
        .await
        .expect_err("the 65th issuance for one source must be rate limited");
    assert_issuance_declined("per-source rate", &declined);
    // A different source is a different partition.
    issue(
        client,
        fill_jkt(0xB1, 1),
        Some("matrix-source-b".to_string()),
    )
    .await
    .expect("a different courier-observed source still issues");
    eprintln!("ROW per-source-rate: ok");
}

async fn expiry_boundary_row(
    socket: &std::path::Path,
    ctx: &Ctx<'_>,
    control: &Issued,
    probe: &Issued,
) {
    // Just BEFORE the boundary the twin consumes (so the pair was valid)…
    // Fresh connections after each wait: an idle channel dropped during the
    // sleep must not surface as a transport error inside a consume oracle.
    sleep_until_unix(control.expires_at_unix - 5).await;
    let mut client = InvocationServiceClient::new(uds_channel(socket).await);
    let pre = consume(
        &mut client,
        ctx,
        ctx.subject_a,
        &control.challenge,
        "expiry-pre",
    )
    .await;
    assert!(
        matches!(pre, Consume::PassedFreshness),
        "a challenge consumes right up to its expiry boundary"
    );
    // …and just AFTER it the probe is denied: the only varying input is time.
    sleep_until_unix(probe.expires_at_unix + 3).await;
    let mut client = InvocationServiceClient::new(uds_channel(socket).await);
    let post = consume(
        &mut client,
        ctx,
        ctx.subject_a,
        &probe.challenge,
        "expiry-post",
    )
    .await;
    assert!(
        matches!(post, Consume::DeniedAtFreshness),
        "an expired challenge must be the sealed CHALLENGE_UNKNOWN"
    );
    eprintln!("ROW expiry-boundary: ok");
}

async fn wrong_generation_row(
    client: &mut InvocationServiceClient<Channel>,
    ctx: &Ctx<'_>,
    jkt: [u8; 32],
    harness: &basil_tests::Harness,
) -> u64 {
    let old = issue(client, jkt, None)
        .await
        .expect("issue G1 under generation 1");
    // Benign policy nudge (an extra grant with a fresh id) so the SIGHUP
    // reload is a REAL config change installing a new serving generation.
    append_benign_policy_rule(&harness.policy_path());
    harness.sighup_agent();
    // Poll the serving generation with a ROTATING throwaway jkt per attempt:
    // polling under `jkt` itself would strand a never-consumed gen-1
    // challenge each iteration, hit the SPEC-fixed per-jkt outstanding cap
    // (8) about 1.5s after SIGHUP (`old` already holds one slot), and turn a
    // slow reload into a spurious CHALLENGE_ISSUANCE_DECLINED panic instead
    // of ever reaching the 30s deadline below. Throwaway jkts keep every
    // partitioned limit fresh (150 polls stay far under the global capacity
    // and global rate), so the deadline tolerance is real.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut poll: u8 = 0;
    let fresh = loop {
        let probe = issue(client, fill_jkt(0xD0, poll), None)
            .await
            .expect("issue generation probe post-SIGHUP");
        if probe.generation > old.generation {
            // The reload landed: issue the row's real challenge for `jkt`
            // under the new serving generation (its second outstanding slot,
            // well under the cap).
            break issue(client, jkt, None)
                .await
                .expect("issue post-SIGHUP under the new generation");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the SIGHUP reload never installed a new serving generation"
        );
        poll = poll.wrapping_add(1);
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    // The old-generation challenge can never validate again.
    let stale = consume(client, ctx, ctx.subject_a, &old.challenge, "generation-old").await;
    assert!(
        matches!(stale, Consume::DeniedAtFreshness),
        "a challenge bound to a previous serving generation must be the sealed CHALLENGE_UNKNOWN"
    );
    // The table keeps serving across the reload: a current-generation
    // challenge consumes.
    let live = consume(
        client,
        ctx,
        ctx.subject_a,
        &fresh.challenge,
        "generation-new",
    )
    .await;
    assert!(
        matches!(live, Consume::PassedFreshness),
        "a challenge issued under the new generation consumes after the reload"
    );
    eprintln!(
        "ROW wrong-generation: ok (generation {} -> {})",
        old.generation, fresh.generation
    );
    fresh.generation
}

async fn global_capacity_row(
    client: &mut InvocationServiceClient<Channel>,
    ctx: &Ctx<'_>,
    jkt: [u8; 32],
    generation: u64,
) -> Issued {
    // Pre-issue the outstanding-valid control and the restart row's
    // challenge BEFORE filling the table (a full table declines issuance).
    let outstanding = issue(client, jkt, None).await.expect("issue C5 pre-fill");
    let pre_restart = issue(client, jkt, None).await.expect("issue R1 pre-fill");
    assert_eq!(
        pre_restart.generation, generation,
        "R1 rides the reloaded generation"
    );

    // Fill: distinct jkts (8 outstanding each, under the per-jkt cap), no
    // courier source (the per-source bucket stays out of the way), until the
    // global capacity declines issuance.
    let mut filled = 0_u32;
    let declined = loop {
        assert!(
            filled <= 300,
            "global capacity ({}) never declined issuance after {filled} fills",
            CHALLENGE_SHAPE.capacity
        );
        let jkt_fill = fill_jkt(0xC0, u8::try_from(filled / 8).expect("fill fits"));
        match issue(client, jkt_fill, None).await {
            Ok(_) => filled += 1,
            Err(status) => break status,
        }
    };
    assert_issuance_declined("global capacity", &declined);
    // Consumption never consults capacity: the outstanding valid challenge
    // still succeeds under full-table pressure.
    let consumed = consume(
        client,
        ctx,
        ctx.subject_a,
        &outstanding.challenge,
        "capacity-c5",
    )
    .await;
    assert!(
        matches!(consumed, Consume::PassedFreshness),
        "an outstanding valid challenge must still consume while issuance is declined"
    );
    eprintln!("ROW global-capacity: ok ({filled} fills to decline)");
    pre_restart
}

async fn restart_row(
    harness: &mut basil_tests::Harness,
    ctx: &Ctx<'_>,
    jkt: [u8; 32],
    pre_restart: &Issued,
) {
    harness.restart_agent();
    let mut client = InvocationServiceClient::new(uds_channel(&harness.socket()).await);
    // The restarted broker issues immediately even though the pre-restart
    // table was at capacity: restart cleared it. It also stamps a FRESH
    // instance-ID prefix and is back at generation 1.
    let fresh = issue(&mut client, jkt, None)
        .await
        .expect("a restarted broker issues from an empty table");
    assert_eq!(
        fresh.generation, 1,
        "a restarted broker serves generation 1"
    );
    assert_ne!(
        fresh.challenge[..INSTANCE_ID_LEN],
        pre_restart.challenge[..INSTANCE_ID_LEN],
        "a restart generates a fresh 16-byte instance ID"
    );
    // Every pre-restart challenge is invalidated (foreign instance).
    let stale = consume(
        &mut client,
        ctx,
        ctx.subject_a,
        &pre_restart.challenge,
        "restart-old",
    )
    .await;
    assert!(
        matches!(stale, Consume::DeniedAtFreshness),
        "a pre-restart challenge must be the sealed CHALLENGE_UNKNOWN after restart"
    );
    // And the restarted instance's own challenge consumes.
    let live = consume(
        &mut client,
        ctx,
        ctx.subject_a,
        &fresh.challenge,
        "restart-new",
    )
    .await;
    assert!(
        matches!(live, Consume::PassedFreshness),
        "a challenge issued by the restarted instance consumes"
    );
    eprintln!("ROW restart-invalidation: ok");
}

// ---------------------------------------------------------------------------
// Wire helpers.
// ---------------------------------------------------------------------------

async fn issue(
    client: &mut InvocationServiceClient<Channel>,
    jkt: [u8; 32],
    courier_observed_source: Option<String>,
) -> Result<Issued, Status> {
    let response = client
        .get_invocation_challenge(GetInvocationChallengeRequest {
            jkt: jkt.to_vec(),
            courier_observed_source,
        })
        .await?
        .into_inner();
    Ok(Issued {
        challenge: response.challenge,
        generation: response.generation,
        expires_at_unix: response.expires_at_unix,
    })
}

/// Submit a subject-key sealed request carrying `challenge` and classify the
/// broker's answer into one of the two freshness outcomes.
async fn consume(
    client: &mut InvocationServiceClient<Channel>,
    ctx: &Ctx<'_>,
    signer: &Ed25519Signer,
    challenge: &[u8],
    marker: &str,
) -> Consume {
    let message = build_challenge_request(signer, challenge, marker).await;
    let outcome = client.invoke(SealedRequest { message }).await;
    classify(ctx, outcome, marker).await
}

/// Classify an `Invoke` outcome. gRPC `Ok` must be a sealed denial whose
/// opened body is `CHALLENGE_UNKNOWN`; any gRPC error means the request got
/// past the freshness step (this boot cannot decrypt a request body, so an
/// accepted invocation is impossible by construction).
async fn classify(
    ctx: &Ctx<'_>,
    outcome: Result<tonic::Response<basil_proto::broker::v1::SealedResponse>, Status>,
    marker: &str,
) -> Consume {
    match outcome {
        Ok(response) => {
            let sealed = response.into_inner();
            assert!(
                !sealed.message.is_empty(),
                "{marker}: a sealed denial carries COSE bytes"
            );
            let body = open_sealed_response(ctx, &sealed.message, marker).await;
            assert_eq!(
                body.status.code,
                InvocationStatusCode::ChallengeUnknown,
                "{marker}: sealed status must be CHALLENGE_UNKNOWN, got {:?}",
                body.status
            );
            assert_eq!(
                body.status.reason, REASON_CHALLENGE_UNKNOWN,
                "{marker}: stable reason token"
            );
            assert!(
                !body.status.retryable,
                "{marker}: CHALLENGE_UNKNOWN is never retryable with the same message"
            );
            Consume::DeniedAtFreshness
        }
        Err(status) => {
            // Pin the exact layer: the request-body decrypt ("open failed"),
            // which sits PAST freshness, quota, and authorization. Anything
            // else (transport faults, earlier envelope rejections) must not
            // masquerade as a consumed challenge.
            assert_eq!(
                status.code(),
                Code::InvalidArgument,
                "{marker}: a consumed request fails at the body decrypt, got {status:?}"
            );
            assert!(
                status.message().contains("open failed"),
                "{marker}: expected the body-decrypt failure, got {:?}",
                status.message()
            );
            Consume::PassedFreshness
        }
    }
}

fn assert_issuance_declined(name: &str, status: &Status) {
    assert_eq!(
        status.code(),
        Code::ResourceExhausted,
        "{name}: declined issuance is RESOURCE_EXHAUSTED, got {status:?}"
    );
    assert!(
        status.message().contains("challenge issuance declined"),
        "{name}: the decline is the stable retryable CHALLENGE_ISSUANCE_DECLINED, got {:?}",
        status.message()
    );
}

/// Verify (broker transit signature) and open (test-held response key) a
/// sealed denial, returning the encrypted status body.
async fn open_sealed_response(
    ctx: &Ctx<'_>,
    message: &[u8],
    marker: &str,
) -> SignInvocationResponse {
    let validation = ValidationParams {
        now: UnixTime(now_unix()),
        max_clock_skew: Duration::from_secs(30),
        max_ttl: Duration::from_mins(5),
        default_ttl: Duration::from_mins(2),
        allowed_audiences: std::collections::BTreeSet::new(),
        role: MessageRole::Response,
    };
    let verified = verify_sealed(
        message,
        ctx.verifier,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation,
        },
    )
    .await
    .unwrap_or_else(|error| panic!("{marker}: broker-signed sealed denial verifies: {error}"));
    let opened = verified
        .open(
            ctx.response_recipient,
            &ExternalAad::empty(),
            Some(&KdfParties::anonymous()),
        )
        .await
        .unwrap_or_else(|error| panic!("{marker}: open sealed denial: {error}"));
    SignInvocationResponse::from_cbor_bytes(opened.plaintext.as_slice())
        .unwrap_or_else(|error| panic!("{marker}: decode sealed denial body: {error}"))
}

/// Build a subject-key sealed request carrying `challenge`.
async fn build_challenge_request(
    signer: &Ed25519Signer,
    challenge: &[u8],
    marker: &str,
) -> Vec<u8> {
    let claims = Claims {
        issuer: None,
        audience: Some(Subject::new(INVOCATION_AUDIENCE.to_string()).expect("broker audience")),
        expires_at: None,
        issued_at: UnixTime(now_unix()),
        message_id: unique_message_id(marker),
        sender_key_id: Some(signer.key_id().clone()),
        response_key_id: Some(text_key(INVOCATION_RESPONSE_KEY_ID)),
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
        freshness_challenge: Some(
            FreshnessChallenge::from_bytes(challenge).expect("wire challenge is 32 bytes"),
        ),
    };
    build_sealed(
        &SealParams {
            content_type: ContentType::new(CONTENT_TYPE_SIGN_REQUEST.to_string())
                .expect("content type"),
            plaintext: b"challenge lifecycle acceptance matrix",
            claims,
            role: MessageRole::Request,
            recipient: X25519RecipientPublic {
                key_id: text_key(basil_tests::INVOCATION_REQUEST_KEY_ID),
                public: REQUEST_PUBLIC,
            },
            content_algorithm: ContentAlgorithm::A256Gcm,
            aad: SealedAad::empty(),
            kdf_parties: KdfParties::anonymous(),
        },
        signer,
    )
    .await
    .expect("build the subject-key request")
    .into_vec()
}

/// The broker's transit response-signing public key, fetched from the live
/// dev engine so the sealed-denial oracle verifies the REAL signature.
fn broker_signing_verifier(addr: &str) -> Ed25519Verifier {
    let output = std::process::Command::new("bao")
        .args(["read", "-format=json", "transit/keys/ci-broker-signing"])
        .env("VAULT_ADDR", addr)
        .env("VAULT_TOKEN", "root")
        .output()
        .expect("read the transit response-signing key");
    assert!(
        output.status.success(),
        "bao read transit/keys/ci-broker-signing failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse transit key JSON");
    let encoded = json["data"]["keys"]["1"]["public_key"]
        .as_str()
        .expect("transit key carries a version-1 public key");
    let public: [u8; 32] = STANDARD
        .decode(encoded)
        .expect("decode transit public key")
        .try_into()
        .expect("transit Ed25519 public key is 32 bytes");
    Ed25519Verifier::from_key(text_key(INVOCATION_SIGNING_KEY_ID), &public)
        .expect("build broker verifier")
}

/// Append one benign extra grant so a reload has a real config delta.
fn append_benign_policy_rule(policy_path: &std::path::Path) {
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(policy_path).expect("read live policy"))
            .expect("parse live policy");
    policy
        .get_mut("rules")
        .and_then(serde_json::Value::as_array_mut)
        .expect("policy carries a rules array")
        .push(serde_json::json!({
            "id": "ci-invoker-decrypt-reload-nudge",
            "subjects": [basil_tests::INVOCATION_SUBJECT],
            "action": ["op:decrypt"],
            "target": [basil_tests::INVOCATION_REQUEST_KEY_ID]
        }));
    std::fs::write(
        policy_path,
        serde_json::to_vec_pretty(&policy).expect("serialize nudged policy"),
    )
    .expect("write nudged policy");
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

/// A deterministic self-asserted jkt for fill/rate partitions (never signed
/// with; issuance is unauthenticated and the thumbprint grants nothing).
const fn fill_jkt(family: u8, index: u8) -> [u8; 32] {
    let mut jkt = [family; 32];
    jkt[31] = index;
    jkt
}

/// A process-unique 16-byte message ID tagged with `marker` bytes.
fn unique_message_id(marker: &str) -> MessageId {
    let counter = MESSAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut bytes = vec![0_u8; 16];
    bytes[..8].copy_from_slice(&counter.to_be_bytes());
    for (index, byte) in marker.bytes().enumerate() {
        bytes[8 + (index % 8)] ^= byte;
    }
    MessageId::from_bytes(bytes).expect("message id")
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

/// Sleep until the wall clock passes `target_unix` (no-op when already past).
async fn sleep_until_unix(target_unix: i64) {
    loop {
        let now = now_unix();
        if now >= target_unix {
            return;
        }
        let remaining = u64::try_from(target_unix - now).expect("positive remaining");
        tokio::time::sleep(Duration::from_secs(remaining.min(5))).await;
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
