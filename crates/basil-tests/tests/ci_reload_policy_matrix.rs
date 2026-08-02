// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! LIVE acceptance rows for reload pinning, the federation kill switch, and
//! default-deny policy separation (`basil-jjgi.3.3.3`), driven over the REAL
//! `InvocationService` RPCs of one booted broker across three live SIGHUP
//! reloads (policy delta, policy nudge, config delta).
//!
//! Covers these rows of `docs/ci-oidc-federation/SPEC.md` "Required
//! acceptance":
//!
//! - **default-deny separation among gateway UID, remote subject, operation,
//!   and key**: six probes over a live-reloaded policy, each flipping exactly
//!   one dimension against a positive control, with the wire status AND the
//!   broker's own audit line (decision, resolved actor, generation) pinning
//!   the layer that denied;
//! - **pinned-generation reload races**: subject-key requests carrying
//!   generation-A challenges race a SIGHUP swap; every response lands on
//!   exactly one of two whole-generation outcomes (consumed under A, or the
//!   sealed `CHALLENGE_UNKNOWN` whose encrypted body names generation B) —
//!   never a torn mix — while audit stamps allow-decisions with A and
//!   freshness denials with B;
//! - **kill switch: reload without the rule denies new requests while a
//!   pinned in-flight request completes**: removing `[federation]` flips the
//!   SAME proof-bound request shape from the provider-verification denial to
//!   the invocation-audience rejection at the entry gate, while reserved
//!   generation-A challenges racing the swap complete coherently and the
//!   non-federated subject lane keeps working.
//!
//! Oracles (shared with `ci_challenge_lifecycle_matrix`): a subject-key
//! request that PASSES policy fails closed at the request-body decrypt (the
//! X25519 request private half is deliberately unprovisioned), so `Ok` sealed
//! answers are freshness denials and bare gRPC errors pin the exact layer.
//! The JWKS-trust half of the reload boundary (same issuer and `kid`, rotated
//! key material) is the hermetic `ci_trust_reload_matrix.rs` — a live
//! rendition needs the provider-origin seam (`basil-abdh`).
//!
//! GATING: needs a live `bao`; prints an explicit skip line when absent.

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::os::unix::fs::MetadataExt as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use basil_core::ci_federation::{proof_audience, proof_key_kid, proof_key_thumbprint};
use basil_cose::{
    Claims, ContentAlgorithm, ContentType, Ed25519Signer, Ed25519Verifier, ExternalAad,
    FreshnessChallenge, KdfParties, KeyId, MessageId, MessageRole, ProtectedHeaders, SealParams,
    SealedAad, Signer, Subject, UnixTime, ValidationParams, VerifySealedParams, X25519Recipient,
    X25519RecipientPublic, Zeroizing, build_sealed, build_sealed_with_headers, verify_sealed,
};
use basil_proto::broker::v1::invocation_service_client::InvocationServiceClient;
use basil_proto::broker::v1::{GetInvocationChallengeRequest, SealedRequest};
use basil_proto::invocation::{
    CONTENT_TYPE_SIGN_REQUEST, InvocationStatusCode, REASON_CHALLENGE_UNKNOWN,
    SignInvocationResponse,
};
use basil_tests::{
    ChallengeTableBoot, Engine, INVOCATION_AUDIENCE, INVOCATION_REQUEST_KEY_ID,
    INVOCATION_RESPONSE_KEY_ID, INVOCATION_SIGNING_KEY_ID, INVOCATION_SUBJECT, InvocationBootSpec,
    ProviderArm, alloc_addr, boot_basil_invocation, on_path,
};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Status};
use tower::service_fn;

/// Deterministic Ed25519 seed of the boot's primary subject signer (the
/// all-dimensions-correct positive control).
const SUBJECT_A_SEED: [u8; 32] = [0x33; 32];
/// Signer admitted with a `process.uid` predicate matching OUR uid.
const SEP_UID_OK_SEED: [u8; 32] = [0x51; 32];
/// Signer admitted only for a DIFFERENT gateway uid.
const SEP_UID_WRONG_SEED: [u8; 32] = [0x52; 32];
/// Signer granted the WRONG operation (`op:sign`) on the request key.
const SEP_OP_SEED: [u8; 32] = [0x53; 32];
/// Signer granted `op:decrypt` on the WRONG key.
const SEP_KEY_SEED: [u8; 32] = [0x54; 32];
/// Signer admitted by no policy subject at all.
const SEP_UNKNOWN_SEED: [u8; 32] = [0x57; 32];
/// Deterministic Ed25519 seed of the kill-switch row's proof key.
const PROOF_SEED: [u8; 32] = [0x11; 32];
/// X25519 private half of the broker response key, held by the test so
/// sealed denials can be OPENED and their status + generation asserted.
const RESPONSE_SECRET: [u8; 32] = [0x66; 32];
/// X25519 public half requests are sealed to; its private half is NEVER
/// provisioned, so an authorized request deterministically fails at the
/// body decrypt.
const REQUEST_PUBLIC: [u8; 32] = [0x55; 32];

/// Process-wide uniqueness for request message IDs.
static MESSAGE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[test]
fn reload_pinning_kill_switch_and_policy_separation_over_the_real_rpc() {
    if !on_path("bao") {
        eprintln!("SKIP: `bao` not on PATH; skipping the reload/policy acceptance matrix");
        return;
    }
    let addr = alloc_addr();
    let subject_a = signer("subject-a", &SUBJECT_A_SEED);
    let response_recipient = X25519Recipient::new(
        text_key(INVOCATION_RESPONSE_KEY_ID),
        Zeroizing::new(RESPONSE_SECRET),
    );
    let spec = InvocationBootSpec {
        provider: ProviderArm::GithubActions,
        // The separation rows exercise the pure policy dimensions, so a
        // challenge-less subject request must reach subject resolution; the
        // race rows attach challenges VOLUNTARILY (present means enforced).
        require_challenge: false,
        subject_signature_key: URL_SAFE_NO_PAD.encode(subject_a.public_key_bytes()),
        second_subject_signature_key: None,
        response_public: response_recipient.public().public,
        // The race and kill-switch rows both reserve challenge batches for
        // subject A's jkt in quick succession; the SPEC-default per-jkt rate
        // (burst 8, integer-second refill 4/s) would make the second batch
        // decline whenever less than a wall-clock second separates the rows.
        // Raise the per-jkt rate well above every batch (the SPEC-fixed
        // outstanding cap of 8 still applies and no batch exceeds 6); rate
        // limiting itself is row G of `ci_challenge_lifecycle_matrix`.
        challenge: Some(ChallengeTableBoot {
            capacity: 1024,
            per_jkt_rate_burst: 32,
            per_jkt_rate_refill_per_sec: 16,
            per_source_rate_burst: 64,
            per_source_rate_refill_per_sec: 16,
        }),
    };
    let harness = boot_basil_invocation("jjgi-reload-pol", Engine::OpenBao, &addr, &spec);
    let verifier = broker_signing_verifier(harness.backend_addr());

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    runtime.block_on(async {
        let socket = harness.socket();
        let mut client = InvocationServiceClient::new(uds_channel(&socket).await);
        let ctx = Ctx {
            verifier: &verifier,
            response_recipient: &response_recipient,
        };
        let mut audit = AuditTail::new(harness.audit_log_path());

        // --- Row P: default-deny separation among gateway UID, remote
        // subject, operation, and key (via live policy reload #1).
        policy_separation_rows(&mut client, &subject_a, &harness, &mut audit).await;

        // --- Row R: pinned-generation reload race (live reload #2).
        reload_race_row(&socket, &ctx, &subject_a, &harness, &mut audit).await;

        // --- Row K: kill switch (live reload #3, config delta).
        kill_switch_row(&socket, &ctx, &subject_a, &harness).await;
    });
}

/// Response-opening material shared by the freshness oracles.
struct Ctx<'a> {
    verifier: &'a Ed25519Verifier,
    response_recipient: &'a X25519Recipient,
}

/// One issued challenge as returned over the wire.
#[derive(Clone, Debug)]
struct Issued {
    challenge: Vec<u8>,
    generation: u64,
}

/// The two mutually exclusive whole-generation outcomes of a consume attempt.
#[derive(Clone, Copy, Debug)]
enum Consume {
    /// Sealed `CHALLENGE_UNKNOWN`; the encrypted body named this serving
    /// generation.
    DeniedAtFreshness { policy_generation: u64 },
    /// The request got past freshness and failed closed at the body decrypt
    /// (the layer is pinned by `classify`).
    PassedFreshness,
}

// ---------------------------------------------------------------------------
// Row P: default-deny policy separation.
// ---------------------------------------------------------------------------

async fn policy_separation_rows(
    client: &mut InvocationServiceClient<Channel>,
    subject_a: &Ed25519Signer,
    harness: &basil_tests::Harness,
    audit: &mut AuditTail,
) {
    let uid_ok = process_uid();
    let uid_wrong = if uid_ok == u32::MAX {
        uid_ok - 1
    } else {
        uid_ok + 1
    };
    let sep_uid_ok = signer("sep-uid-ok", &SEP_UID_OK_SEED);
    let sep_uid_wrong = signer("sep-uid-wrong", &SEP_UID_WRONG_SEED);
    let sep_op = signer("sep-op", &SEP_OP_SEED);
    let sep_key = signer("sep-key", &SEP_KEY_SEED);
    let sep_unknown = signer("sep-unknown", &SEP_UNKNOWN_SEED);

    let before = serving_generation(client, 0xA0).await;
    add_separation_policy(
        &harness.policy_path(),
        uid_ok,
        uid_wrong,
        &[
            ("ci.sep.uid-ok", &sep_uid_ok),
            ("ci.sep.uid-wrong", &sep_uid_wrong),
            ("ci.sep.op", &sep_op),
            ("ci.sep.key", &sep_key),
        ],
    );
    harness.sighup_agent();
    let generation = await_generation_after(client, before, 0xA1).await;
    audit.drain_authz();

    // Positive control: every dimension correct -> authorized past policy,
    // failing closed only at the body decrypt.
    probe_authorized(
        client,
        audit,
        subject_a,
        generation,
        INVOCATION_SUBJECT,
        "sep-baseline",
    )
    .await;
    // Gateway-UID positive control: signature key + `process.uid` == ours.
    probe_authorized(
        client,
        audit,
        &sep_uid_ok,
        generation,
        "ci.sep.uid-ok",
        "sep-uid-ok",
    )
    .await;
    // GATEWAY UID: identical shape, uid selector flipped to a foreign uid.
    // The valid signature alone must not resolve the subject.
    probe_denied_unresolved(client, audit, &sep_uid_wrong, generation, "sep-uid-wrong").await;
    // REMOTE SUBJECT: a signer no policy subject admits.
    probe_denied_unresolved(client, audit, &sep_unknown, generation, "sep-unknown").await;
    // OPERATION: subject resolves, but its only grant is `op:sign` and the
    // invocation needs `op:decrypt` — denied at the decision, by name.
    probe_denied_at_decision(client, audit, &sep_op, generation, "ci.sep.op", "sep-op").await;
    // KEY: subject resolves with `op:decrypt`, but on a DIFFERENT key.
    probe_denied_at_decision(client, audit, &sep_key, generation, "ci.sep.key", "sep-key").await;
    eprintln!("ROW policy-separation: ok (generation {generation})");
}

/// Send a challenge-less subject-key request and demand it was AUTHORIZED
/// past policy: the only acceptable failure is the request-body decrypt, and
/// the audit trail must carry exactly one allow decision for `subject` at
/// `generation`.
async fn probe_authorized(
    client: &mut InvocationServiceClient<Channel>,
    audit: &mut AuditTail,
    signer: &Ed25519Signer,
    generation: u64,
    subject: &str,
    marker: &str,
) {
    let message = build_subject_message(signer, None, marker).await;
    let status = client
        .invoke(SealedRequest { message })
        .await
        .expect_err(marker);
    assert_eq!(
        status.code(),
        Code::InvalidArgument,
        "{marker}: an authorized probe fails only at the body decrypt, got {status:?}"
    );
    assert!(
        status.message().contains("open failed"),
        "{marker}: expected the body-decrypt failure, got {:?}",
        status.message()
    );
    let line = single_authz_line(audit, marker);
    assert_eq!(
        line["decision"], "allow",
        "{marker}: audit decision ({line})"
    );
    assert_eq!(line["actor_id"], subject, "{marker}: audit actor ({line})");
    assert_eq!(
        line["target_id"], INVOCATION_REQUEST_KEY_ID,
        "{marker}: audit target ({line})"
    );
    assert_eq!(
        line["generation"].as_u64(),
        Some(generation),
        "{marker}: audit generation ({line})"
    );
}

/// Send a challenge-less subject-key request and demand the deny happened at
/// SUBJECT RESOLUTION: wire `PermissionDenied`, audited as an unresolved
/// actor with the `invalid_actor_proof` reason.
async fn probe_denied_unresolved(
    client: &mut InvocationServiceClient<Channel>,
    audit: &mut AuditTail,
    signer: &Ed25519Signer,
    generation: u64,
    marker: &str,
) {
    let status = expect_permission_denied(client, signer, marker).await;
    assert!(
        status.message().contains("not authorized"),
        "{marker}: expected the uniform denial, got {:?}",
        status.message()
    );
    let line = single_authz_line(audit, marker);
    assert_eq!(
        line["decision"], "deny",
        "{marker}: audit decision ({line})"
    );
    assert_eq!(
        line["actor_id"], "unresolved",
        "{marker}: the subject must NOT have resolved ({line})"
    );
    let reason = line["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("invalid_actor_proof"),
        "{marker}: audit reason must name the resolution failure ({line})"
    );
    assert_eq!(
        line["generation"].as_u64(),
        Some(generation),
        "{marker}: audit generation ({line})"
    );
}

/// Send a challenge-less subject-key request and demand the subject RESOLVED
/// but the decision denied it (`not_permitted`): the operation/key dimension
/// separated, not the identity.
async fn probe_denied_at_decision(
    client: &mut InvocationServiceClient<Channel>,
    audit: &mut AuditTail,
    signer: &Ed25519Signer,
    generation: u64,
    subject: &str,
    marker: &str,
) {
    let status = expect_permission_denied(client, signer, marker).await;
    assert!(
        status.message().contains("not authorized"),
        "{marker}: expected the uniform denial, got {:?}",
        status.message()
    );
    let line = single_authz_line(audit, marker);
    assert_eq!(
        line["decision"], "deny",
        "{marker}: audit decision ({line})"
    );
    assert_eq!(
        line["actor_id"], subject,
        "{marker}: the subject resolved and was denied by the decision ({line})"
    );
    assert_eq!(
        line["reason"], "not_permitted",
        "{marker}: audit reason ({line})"
    );
    assert_eq!(
        line["target_id"], INVOCATION_REQUEST_KEY_ID,
        "{marker}: audit target ({line})"
    );
    assert_eq!(
        line["generation"].as_u64(),
        Some(generation),
        "{marker}: audit generation ({line})"
    );
}

async fn expect_permission_denied(
    client: &mut InvocationServiceClient<Channel>,
    signer: &Ed25519Signer,
    marker: &str,
) -> Status {
    let message = build_subject_message(signer, None, marker).await;
    let status = client
        .invoke(SealedRequest { message })
        .await
        .expect_err(marker);
    assert_eq!(
        status.code(),
        Code::PermissionDenied,
        "{marker}: expected a policy denial, got {status:?}"
    );
    status
}

// ---------------------------------------------------------------------------
// Row R: pinned-generation reload race.
// ---------------------------------------------------------------------------

async fn reload_race_row(
    socket: &std::path::Path,
    ctx: &Ctx<'_>,
    subject_a: &Ed25519Signer,
    harness: &basil_tests::Harness,
    audit: &mut AuditTail,
) {
    let mut client = InvocationServiceClient::new(uds_channel(socket).await);
    let jkt = proof_key_thumbprint(&subject_a.public_key_bytes());
    let old = serving_generation(&mut client, 0xB0).await;

    // Reserve six generation-A challenges (under the SPEC-fixed per-jkt
    // outstanding cap of 8) BEFORE the reload is triggered.
    let mut reserved = Vec::new();
    for _ in 0..6 {
        let issued = issue(&mut client, jkt).await.expect("issue race reserve");
        assert_eq!(issued.generation, old, "reserve rides generation A");
        reserved.push(issued);
    }

    // A request dispatched and completed BEFORE the swap consumes under A.
    let pre = consume(
        &mut client,
        ctx,
        subject_a,
        &reserved[0].challenge,
        "race-pre",
    )
    .await;
    assert!(
        matches!(pre, Consume::PassedFreshness),
        "race-pre: an in-flight request before the reload completes under generation A"
    );
    audit.drain_authz();

    // Trigger the swap and race four concurrent consumes against it. tonic
    // multiplexes the clones over one connection, so the requests genuinely
    // overlap the reload window.
    nudge_policy(&harness.policy_path(), "race");
    harness.sighup_agent();
    let outcomes = concurrent_burst(socket, subject_a, &reserved[1..5], "race-burst").await;

    let new = await_generation_after(&mut client, old, 0xB1).await;

    // Every racing response is EXACTLY one of the two whole-generation
    // outcomes; a denial's encrypted body must name the new generation (the
    // request was pinned to B), never a torn mix.
    let mut consumed = 0_u32;
    let mut denied = 0_u32;
    for (index, outcome) in outcomes {
        let marker = format!("race-burst-{index}");
        match classify(ctx, outcome, &marker).await {
            Consume::PassedFreshness => consumed += 1,
            Consume::DeniedAtFreshness { policy_generation } => {
                assert_eq!(
                    policy_generation, new,
                    "{marker}: a post-swap denial is pinned to generation B"
                );
                denied += 1;
            }
        }
    }
    assert_eq!(consumed + denied, 4, "every racing request got one outcome");

    // Deterministic post-swap probe: a remaining generation-A challenge can
    // never validate again, and the sealed denial names generation B.
    let post = consume(
        &mut client,
        ctx,
        subject_a,
        &reserved[5].challenge,
        "race-post",
    )
    .await;
    match post {
        Consume::DeniedAtFreshness { policy_generation } => {
            assert_eq!(policy_generation, new, "race-post: denial pinned to B");
        }
        Consume::PassedFreshness => {
            panic!("race-post: a generation-A challenge consumed after the swap")
        }
    }

    // Audit corroboration: every allow decision in the race window was made
    // under generation A (pinned in-flight work), every freshness denial
    // under generation B — no line may mix the two.
    let lines = audit.drain_authz();
    let mut allow_lines = 0_u32;
    for line in &lines {
        let generation = line["generation"].as_u64();
        let reason = line["reason"].as_str().unwrap_or_default();
        if line["decision"] == "allow" {
            allow_lines += 1;
            assert_eq!(
                generation,
                Some(old),
                "an allow decision in the race window must be pinned to generation A ({line})"
            );
        } else if reason.starts_with("freshness_challenge_denied") {
            assert_eq!(
                generation,
                Some(new),
                "a freshness denial in the race window must be pinned to generation B ({line})"
            );
        }
    }
    assert_eq!(
        u64::from(allow_lines),
        u64::from(consumed),
        "one allow decision per consumed racing request"
    );
    eprintln!(
        "ROW reload-race: ok (generation {old} -> {new}; burst consumed {consumed}, denied {denied})"
    );
}

// ---------------------------------------------------------------------------
// Row K: the federation kill switch.
// ---------------------------------------------------------------------------

async fn kill_switch_row(
    socket: &std::path::Path,
    ctx: &Ctx<'_>,
    subject_a: &Ed25519Signer,
    harness: &basil_tests::Harness,
) {
    let mut client = InvocationServiceClient::new(uds_channel(socket).await);
    let jkt = proof_key_thumbprint(&subject_a.public_key_bytes());
    let proof = Ed25519Signer::from_secret_bytes(
        text_key(&proof_key_kid(
            &Ed25519Signer::from_secret_bytes(text_key("boot"), &Zeroizing::new(PROOF_SEED))
                .public_key_bytes(),
        )),
        &Zeroizing::new(PROOF_SEED),
    );
    let old = serving_generation(&mut client, 0xC0).await;

    // Baseline WITH the rule: the proof-bound shape reaches provider
    // verification (its jkt audience is admitted because a federation
    // catalog is serving) and is denied THERE — hermetically, the no-`kid`
    // token can never verify.
    let message = build_proof_bound_message(&proof, "kill-pre").await;
    let status = client
        .invoke(SealedRequest { message })
        .await
        .expect_err("kill-pre");
    assert_eq!(
        status.code(),
        Code::PermissionDenied,
        "kill-pre: with the rule serving, the denial is the provider verification, got {status:?}"
    );
    assert!(
        status.message().contains("not authorized"),
        "kill-pre: got {:?}",
        status.message()
    );

    // Reserve generation-A challenges, prove one completes pre-swap.
    let mut reserved = Vec::new();
    for _ in 0..4 {
        let issued = issue(&mut client, jkt).await.expect("issue kill reserve");
        assert_eq!(issued.generation, old, "reserve rides generation A");
        reserved.push(issued);
    }
    let pre = consume(
        &mut client,
        ctx,
        subject_a,
        &reserved[0].challenge,
        "kill-in-flight",
    )
    .await;
    assert!(
        matches!(pre, Consume::PassedFreshness),
        "kill-in-flight: a pinned request before the kill switch completes"
    );

    // Throw the kill switch: remove `[federation]` from the on-disk config
    // and SIGHUP, while two reserved-challenge requests race the swap.
    strip_federation(&harness.config_path());
    harness.sighup_agent();
    let outcomes = concurrent_burst(socket, subject_a, &reserved[1..3], "kill-burst").await;
    for (index, outcome) in outcomes {
        // Coherence only: each racing request lands on exactly one of the
        // two whole-generation outcomes (classify panics on anything else).
        let marker = format!("kill-burst-{index}");
        let _ = classify(ctx, outcome, &marker).await;
    }
    let new = await_generation_after(&mut client, old, 0xC1).await;

    // New federation requests are DENIED AT THE ENTRY GATE: without a
    // serving catalog the jkt audience itself is rejected, before any
    // provider or key logic — a different, earlier layer than the baseline.
    let message = build_proof_bound_message(&proof, "kill-post").await;
    let status = client
        .invoke(SealedRequest { message })
        .await
        .expect_err("kill-post");
    assert_eq!(
        status.code(),
        Code::InvalidArgument,
        "kill-post: without the rule, the proof-bound shape dies at claim validation, got {status:?}"
    );
    assert!(
        status.message().contains("audience not allowed"),
        "kill-post: got {:?}",
        status.message()
    );

    // A leftover generation-A challenge is sealed-denied under B…
    let stale = consume(
        &mut client,
        ctx,
        subject_a,
        &reserved[3].challenge,
        "kill-stale",
    )
    .await;
    match stale {
        Consume::DeniedAtFreshness { policy_generation } => {
            assert_eq!(policy_generation, new, "kill-stale: denial pinned to B");
        }
        Consume::PassedFreshness => {
            panic!("kill-stale: a generation-A challenge consumed after the kill switch")
        }
    }
    // …while the non-federated subject lane is alive and well: the kill
    // switch killed exactly the federation lane, not the broker.
    let fresh = issue(&mut client, jkt).await.expect("issue under B");
    assert_eq!(fresh.generation, new, "fresh challenge rides generation B");
    let live = consume(&mut client, ctx, subject_a, &fresh.challenge, "kill-live").await;
    assert!(
        matches!(live, Consume::PassedFreshness),
        "kill-live: the subject-key lane keeps working after the kill switch"
    );
    eprintln!("ROW kill-switch: ok (generation {old} -> {new})");
}

// ---------------------------------------------------------------------------
// Wire helpers.
// ---------------------------------------------------------------------------

async fn issue(
    client: &mut InvocationServiceClient<Channel>,
    jkt: [u8; 32],
) -> Result<Issued, Status> {
    let response = client
        .get_invocation_challenge(GetInvocationChallengeRequest {
            jkt: jkt.to_vec(),
            courier_observed_source: None,
        })
        .await?
        .into_inner();
    Ok(Issued {
        challenge: response.challenge,
        generation: response.generation,
    })
}

/// The serving generation, observed through one throwaway-jkt issuance.
async fn serving_generation(client: &mut InvocationServiceClient<Channel>, family: u8) -> u64 {
    issue(client, fill_jkt(family, 0xFF))
        .await
        .expect("issue generation probe")
        .generation
}

/// Poll (rotating throwaway jkts, so no partitioned limit backs up) until the
/// serving generation moves past `old`.
async fn await_generation_after(
    client: &mut InvocationServiceClient<Channel>,
    old: u64,
    family: u8,
) -> u64 {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut poll: u8 = 0;
    loop {
        let probe = issue(client, fill_jkt(family, poll))
            .await
            .expect("issue generation probe post-SIGHUP");
        if probe.generation > old {
            return probe.generation;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the SIGHUP reload never installed a new serving generation"
        );
        poll = poll.wrapping_add(1);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Fire one sealed consume per reserved challenge as GENUINELY concurrent
/// tasks (tonic multiplexes the channel clones over one connection), lightly
/// staggered so the dispatches spread across the reload window; outcomes come
/// back tagged with their index, in index order.
async fn concurrent_burst(
    socket: &std::path::Path,
    signer: &Ed25519Signer,
    reserved: &[Issued],
    marker: &str,
) -> Vec<(
    usize,
    Result<tonic::Response<basil_proto::broker::v1::SealedResponse>, Status>,
)> {
    let channel = uds_channel(socket).await;
    let mut tasks = tokio::task::JoinSet::new();
    for (index, issued) in reserved.iter().enumerate() {
        let message = build_subject_message(
            signer,
            Some(&issued.challenge),
            &format!("{marker}-{index}"),
        )
        .await;
        let mut task_client = InvocationServiceClient::new(channel.clone());
        let stagger = u64::try_from(index).expect("small index");
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_millis(10 * stagger)).await;
            (index, task_client.invoke(SealedRequest { message }).await)
        });
    }
    let mut outcomes = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        outcomes.push(joined.expect("burst task completes"));
    }
    outcomes.sort_by_key(|(index, _)| *index);
    outcomes
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
    let message = build_subject_message(signer, Some(challenge), marker).await;
    let outcome = client.invoke(SealedRequest { message }).await;
    classify(ctx, outcome, marker).await
}

/// Classify an `Invoke` outcome. gRPC `Ok` must be a sealed denial whose
/// opened body is `CHALLENGE_UNKNOWN` (its `policy_generation` is returned
/// for pinning assertions); a gRPC error must be the request-body decrypt
/// failure, which sits PAST freshness, quota, and authorization (this boot
/// cannot decrypt a request body, so an accepted invocation is impossible by
/// construction).
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
            Consume::DeniedAtFreshness {
                policy_generation: body.policy_generation,
            }
        }
        Err(status) => {
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

/// Build a subject-key sealed request, with or without a freshness challenge.
async fn build_subject_message(
    signer: &Ed25519Signer,
    challenge: Option<&[u8]>,
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
        freshness_challenge: challenge.map(|bytes| {
            FreshnessChallenge::from_bytes(bytes).expect("wire challenge is 32 bytes")
        }),
        response_public_key_cose: None,
    };
    build_sealed(&seal_params(claims), signer)
        .await
        .expect("build the subject-key request")
        .into_vec()
}

/// Build the kill-switch row's proof-bound request: embedded proof
/// `COSE_Key`, jkt-bound audience, and a well-formed provider token WITHOUT a
/// `kid` header (hermetic: the broker fails closed at token-header decode
/// while a federation catalog is serving, and never contacts the pinned
/// provider origin).
async fn build_proof_bound_message(proof: &Ed25519Signer, marker: &str) -> Vec<u8> {
    let public = proof.public_key_bytes();
    let claims = Claims {
        issuer: None,
        audience: Some(Subject::new(proof_audience(&public)).expect("proof audience")),
        expires_at: None,
        issued_at: UnixTime(now_unix()),
        message_id: unique_message_id(marker),
        sender_key_id: Some(proof.key_id().clone()),
        response_key_id: Some(text_key(INVOCATION_RESPONSE_KEY_ID)),
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
        freshness_challenge: None,
        response_public_key_cose: None,
    };
    build_sealed_with_headers(
        &seal_params(claims),
        &ProtectedHeaders {
            signer_certificates_jwt: vec![provider_token(marker)],
            signer_public_key_cose: Some(proof_key_cose(&public)),
        },
        proof,
    )
    .await
    .expect("build the proof-bound request")
    .into_vec()
}

fn seal_params(claims: Claims) -> SealParams<'static> {
    SealParams {
        content_type: ContentType::new(CONTENT_TYPE_SIGN_REQUEST.to_string())
            .expect("content type"),
        plaintext: b"reload/policy acceptance matrix",
        claims,
        role: MessageRole::Request,
        recipient: X25519RecipientPublic {
            key_id: text_key(INVOCATION_REQUEST_KEY_ID),
            public: REQUEST_PUBLIC,
        },
        content_algorithm: ContentAlgorithm::A256Gcm,
        aad: SealedAad::empty(),
        kdf_parties: KdfParties::anonymous(),
    }
}

/// The one accepted deterministic proof `COSE_Key` encoding
/// (`{1:1, -1:6, -2:<32 bytes>}`, canonical label order).
fn proof_key_cose(public: &[u8; 32]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .map(3)
        .and_then(|e| e.i8(1))
        .and_then(|e| e.i8(1))
        .and_then(|e| e.i8(-1))
        .and_then(|e| e.i8(6))
        .and_then(|e| e.i8(-2))
        .and_then(|e| e.bytes(public))
        .expect("encode proof COSE_Key");
    encoder.into_writer()
}

/// A syntactically valid compact JWT with NO `kid` header (see
/// [`build_proof_bound_message`]).
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

// ---------------------------------------------------------------------------
// Live config/policy edits (reload inputs are re-read from DISK).
// ---------------------------------------------------------------------------

/// Add the four separation subjects and their single-dimension-flipped
/// grants to the live policy.
fn add_separation_policy(
    policy_path: &std::path::Path,
    uid_ok: u32,
    uid_wrong: u32,
    subjects: &[(&str, &Ed25519Signer)],
) {
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(policy_path).expect("read live policy"))
            .expect("parse live policy");
    let match_for = |name: &str, signer: &Ed25519Signer| {
        let key = serde_json::json!({
            "invocation.signature-key": {
                "algorithm": "ed25519",
                "public": URL_SAFE_NO_PAD.encode(signer.public_key_bytes()),
            }
        });
        match name {
            "ci.sep.uid-ok" => serde_json::json!({ "all": [key, { "process.uid": uid_ok }] }),
            "ci.sep.uid-wrong" => serde_json::json!({ "all": [key, { "process.uid": uid_wrong }] }),
            _ => key,
        }
    };
    for (name, signer) in subjects {
        policy
            .get_mut("subjects")
            .and_then(serde_json::Value::as_object_mut)
            .expect("policy carries a subjects object")
            .insert(
                (*name).to_string(),
                serde_json::json!({
                    "domain": "host-process",
                    "match": match_for(name, signer),
                }),
            );
    }
    let rules = policy
        .get_mut("rules")
        .and_then(serde_json::Value::as_array_mut)
        .expect("policy carries a rules array");
    for (id, subject, action, target) in [
        (
            "sep-uid-ok-decrypt",
            "ci.sep.uid-ok",
            "op:decrypt",
            INVOCATION_REQUEST_KEY_ID,
        ),
        (
            "sep-uid-wrong-decrypt",
            "ci.sep.uid-wrong",
            "op:decrypt",
            INVOCATION_REQUEST_KEY_ID,
        ),
        // The OPERATION flip: a real grant on the right key, wrong op.
        (
            "sep-op-sign",
            "ci.sep.op",
            "op:sign",
            INVOCATION_REQUEST_KEY_ID,
        ),
        // The KEY flip: the right op, on a different key.
        (
            "sep-key-decrypt",
            "ci.sep.key",
            "op:decrypt",
            INVOCATION_RESPONSE_KEY_ID,
        ),
    ] {
        rules.push(serde_json::json!({
            "id": id,
            "subjects": [subject],
            "action": [action],
            "target": [target],
        }));
    }
    std::fs::write(
        policy_path,
        serde_json::to_vec_pretty(&policy).expect("serialize separation policy"),
    )
    .expect("write separation policy");
}

/// Append one benign extra grant so a reload has a real config delta.
fn nudge_policy(policy_path: &std::path::Path, suffix: &str) {
    let mut policy: serde_json::Value =
        serde_json::from_slice(&std::fs::read(policy_path).expect("read live policy"))
            .expect("parse live policy");
    policy
        .get_mut("rules")
        .and_then(serde_json::Value::as_array_mut)
        .expect("policy carries a rules array")
        .push(serde_json::json!({
            "id": format!("ci-invoker-decrypt-nudge-{suffix}"),
            "subjects": [INVOCATION_SUBJECT],
            "action": ["op:decrypt"],
            "target": [INVOCATION_REQUEST_KEY_ID],
        }));
    std::fs::write(
        policy_path,
        serde_json::to_vec_pretty(&policy).expect("serialize nudged policy"),
    )
    .expect("write nudged policy");
}

/// The kill switch: drop the whole `[federation]` section from the on-disk
/// agent config (the boot renders it as the final section).
fn strip_federation(config_path: &std::path::Path) {
    let config = std::fs::read_to_string(config_path).expect("read live agent config");
    let index = config
        .find("[federation]")
        .expect("agent config carries a [federation] section");
    std::fs::write(config_path, &config[..index]).expect("write kill-switch config");
}

// ---------------------------------------------------------------------------
// Audit-trail tailing.
// ---------------------------------------------------------------------------

/// Incremental reader of the broker's JSONL audit trail. `record_decision`
/// appends and flushes each line BEFORE the RPC answers, so lines for a
/// completed request are always visible.
struct AuditTail {
    path: std::path::PathBuf,
    offset: usize,
}

impl AuditTail {
    fn new(path: std::path::PathBuf) -> Self {
        let offset = std::fs::read(&path).map_or(0, |bytes| bytes.len());
        Self { path, offset }
    }

    /// All complete `basil.audit.authz` lines appended since the last drain.
    fn drain_authz(&mut self) -> Vec<serde_json::Value> {
        let bytes = std::fs::read(&self.path).unwrap_or_default();
        let fresh = bytes.get(self.offset..).unwrap_or_default();
        let complete = fresh
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |position| position + 1);
        let (lines, _) = fresh.split_at(complete);
        self.offset += complete;
        lines
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .filter_map(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
            .filter(|line| line["event_kind"] == "basil.audit.authz")
            .collect()
    }
}

/// Exactly one authz line was appended for the probe; return it.
fn single_authz_line(audit: &mut AuditTail, marker: &str) -> serde_json::Value {
    let mut lines = audit.drain_authz();
    assert_eq!(
        lines.len(),
        1,
        "{marker}: expected exactly one audit decision line, got {lines:?}"
    );
    lines.remove(0)
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

fn signer(name: &str, seed: &[u8; 32]) -> Ed25519Signer {
    Ed25519Signer::from_secret_bytes(text_key(name), &Zeroizing::new(*seed))
}

/// The uid the broker's `SO_PEERCRED` gateway evidence reports for us.
fn process_uid() -> u32 {
    std::fs::metadata("/proc/self")
        .expect("stat /proc/self")
        .uid()
}

/// A deterministic self-asserted jkt for generation probes (never signed
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
