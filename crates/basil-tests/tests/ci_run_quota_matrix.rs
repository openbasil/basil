// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Per-run quota state-machine acceptance rows (`basil-jjgi.3.3.2`), driven
//! against the broker's public [`RunQuotaTable`] API plus the pinned sealed
//! wire statuses its denials map onto.
//!
//! Covers the quota rows of `docs/ci-oidc-federation/SPEC.md` "Required
//! acceptance": exhaustion at the rule's `max_operations_per_run`, the denial
//! status contract, reset on a new `run_attempt`, and reset on restart —
//! plus the recorded retention/allowance semantics (basil-jjgi.3.4):
//! generation-scoped reset on reload without old-generation wipe-backs,
//! bounded per-rule bucket allowance with `Untracked` pressure denials,
//! retention-refresh on denied charges, and per-rule isolation.
//!
//! Why not over the `Invoke` RPC: a run-quota charge happens only after a
//! SUCCESSFUL provider-token verification, and the live broker performs a
//! real JWKS fetch against the pinned provider origin for any token that
//! could verify — there is no hermetic seam yet (tracked as `basil-abdh`;
//! the wire-facing sealed `PER_RUN_QUOTA_EXCEEDED` / `RUN_QUOTA_UNTRACKED`
//! mapping is pinned by broker unit tests in `service/invocation.rs`, and
//! the sealed-status constants are re-asserted here). When `basil-abdh`
//! lands a seam, these rows extend to the real RPC alongside the challenge
//! lifecycle matrix.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use basil_core::ci_federation::{RunQuotaDenied, RunQuotaKey, RunQuotaTable};
use basil_proto::invocation::{
    InvocationStatus, InvocationStatusCode, REASON_PER_RUN_QUOTA_EXCEEDED,
    REASON_RUN_QUOTA_UNTRACKED,
};

const NOW: i64 = 1_754_000_000;
/// A rule retention window (`max_token_age_secs + clock_skew_secs`).
const RETENTION: u64 = 330;
const GEN: u64 = 1;

fn key(rule: &str, run_id: u64, run_attempt: u64) -> RunQuotaKey {
    RunQuotaKey {
        rule_id: rule.to_string(),
        run_id,
        run_attempt,
    }
}

/// Exhaustion at the limit; a denied charge consumes no quota and stays
/// denied for the same run attempt.
#[test]
fn quota_exhausts_at_the_limit_and_stays_exhausted() {
    let mut table = RunQuotaTable::new(64);
    let run = key("github-release", 900, 1);
    for charge in 0..3 {
        table
            .charge(GEN, &run, Some(3), RETENTION, NOW)
            .unwrap_or_else(|denied| panic!("charge {charge} within the limit: {denied}"));
    }
    for _ in 0..4 {
        assert_eq!(
            table.charge(GEN, &run, Some(3), RETENTION, NOW),
            Err(RunQuotaDenied::Exhausted),
            "every further charge in the same run attempt is exhausted"
        );
    }
}

/// A rerun (`run_attempt + 1`) opens a fresh bucket with the full quota,
/// while the exhausted attempt stays exhausted.
#[test]
fn quota_resets_on_a_new_run_attempt() {
    let mut table = RunQuotaTable::new(64);
    let first = key("github-release", 900, 1);
    let rerun = key("github-release", 900, 2);
    for _ in 0..2 {
        table
            .charge(GEN, &first, Some(2), RETENTION, NOW)
            .expect("fill attempt 1");
    }
    assert_eq!(
        table.charge(GEN, &first, Some(2), RETENTION, NOW),
        Err(RunQuotaDenied::Exhausted)
    );
    for charge in 0..2 {
        table
            .charge(GEN, &rerun, Some(2), RETENTION, NOW)
            .unwrap_or_else(|denied| panic!("rerun charge {charge} gets a fresh bucket: {denied}"));
    }
    assert_eq!(
        table.charge(GEN, &rerun, Some(2), RETENTION, NOW),
        Err(RunQuotaDenied::Exhausted),
        "the rerun bucket enforces the same limit"
    );
    assert_eq!(
        table.charge(GEN, &first, Some(2), RETENTION, NOW),
        Err(RunQuotaDenied::Exhausted),
        "the first attempt stays exhausted after the rerun opened"
    );
}

/// Restart resets the counter (the table is process memory), and a reload
/// resets it generation-scoped: a charge under a NEWER serving generation
/// clears the counters, while a charge from an older pinned generation
/// counts into the current counters instead of wiping them.
#[test]
fn quota_resets_on_restart_and_on_a_newer_generation_only() {
    let mut table = RunQuotaTable::new(64);
    let run = key("github-release", 900, 1);
    table
        .charge(GEN, &run, Some(1), RETENTION, NOW)
        .expect("exhaust the bucket");
    assert_eq!(
        table.charge(GEN, &run, Some(1), RETENTION, NOW),
        Err(RunQuotaDenied::Exhausted)
    );

    // Restart: a fresh process means a fresh table.
    let mut restarted = RunQuotaTable::new(64);
    restarted
        .charge(GEN, &run, Some(1), RETENTION, NOW)
        .expect("a restarted broker admits the run again");

    // Reload: the SAME table under a newer serving generation resets.
    table
        .charge(GEN + 1, &run, Some(1), RETENTION, NOW)
        .expect("a newer serving generation resets the quota");
    // An old-generation pinned in-flight charge counts against the CURRENT
    // counters (fail-closed over-counting, never a wipe-back).
    assert_eq!(
        table.charge(GEN, &run, Some(1), RETENTION, NOW),
        Err(RunQuotaDenied::Exhausted),
        "an old-generation charge must not reset the current counters"
    );
}

/// The bounded per-rule allowance denies NEW runs as retryable `Untracked`
/// pressure (never evicting live quota state), reclaims idle buckets past
/// retention, and never lets one rule's pressure deny another rule.
#[test]
fn quota_allowance_pressure_is_untracked_reclaimable_and_rule_isolated() {
    let mut table = RunQuotaTable::new(1);
    let tracked = key("github-release", 900, 1);
    let crowded_out = key("github-release", 901, 1);
    let other_rule = key("forgejo-release", 902, 1);
    table
        .charge(GEN, &tracked, Some(8), RETENTION, NOW)
        .expect("track the first run");
    assert_eq!(
        table.charge(GEN, &crowded_out, Some(8), RETENTION, NOW),
        Err(RunQuotaDenied::Untracked),
        "a full per-rule allowance denies a new run as retryable pressure"
    );
    table
        .charge(GEN, &other_rule, Some(8), RETENTION, NOW)
        .expect("another rule's allowance is unaffected");

    // Verified activity refreshes retention even on a DENIED charge, so an
    // exhausted-but-live bucket is never reclaimed out from under its run.
    let mut exhausted = RunQuotaTable::new(1);
    exhausted
        .charge(GEN, &tracked, Some(1), RETENTION, NOW)
        .expect("exhaust");
    let later = NOW + i64::try_from(RETENTION).expect("retention fits") - 10;
    assert_eq!(
        exhausted.charge(GEN, &tracked, Some(1), RETENTION, later),
        Err(RunQuotaDenied::Exhausted),
        "denied charge; refreshes retention"
    );
    let past_original_expiry = NOW + i64::try_from(RETENTION).expect("retention fits") + 10;
    assert_eq!(
        exhausted.charge(GEN, &crowded_out, Some(1), RETENTION, past_original_expiry),
        Err(RunQuotaDenied::Untracked),
        "the refreshed bucket is still live past its original expiry"
    );

    // Once truly idle past retention, the bucket is reclaimed and the new
    // run is admitted.
    let reclaimable = past_original_expiry + i64::try_from(RETENTION).expect("retention fits");
    exhausted
        .charge(GEN, &crowded_out, Some(1), RETENTION, reclaimable)
        .expect("an idle bucket past retention is reclaimed under pressure");
}

/// Fail-closed limit handling: an absent limit is denied (unreachable for a
/// loaded rule, by catalog validation), and a zero limit admits nothing.
#[test]
fn quota_limit_edge_cases_fail_closed() {
    let mut table = RunQuotaTable::new(64);
    let run = key("github-release", 900, 1);
    assert_eq!(
        table.charge(GEN, &run, None, RETENTION, NOW),
        Err(RunQuotaDenied::QuotaUnavailable)
    );
    assert_eq!(
        table.charge(GEN, &run, Some(0), RETENTION, NOW),
        Err(RunQuotaDenied::Exhausted)
    );
}

/// The sealed wire statuses the two denial families map onto (the mapping
/// itself is pinned by broker unit tests in `service/invocation.rs`):
/// genuine exhaustion is `PER_RUN_QUOTA_EXCEEDED` and never retryable within
/// the run attempt; allowance pressure is `RUN_QUOTA_UNTRACKED` and
/// retryable.
#[test]
fn quota_denial_wire_statuses_are_pinned() {
    let exhausted = InvocationStatus::per_run_quota_exceeded();
    assert_eq!(exhausted.code, InvocationStatusCode::PerRunQuotaExceeded);
    assert_eq!(exhausted.reason, REASON_PER_RUN_QUOTA_EXCEEDED);
    assert!(
        !exhausted.retryable,
        "exhaustion is retryable-never in the run attempt"
    );

    let untracked = InvocationStatus::run_quota_untracked();
    assert_eq!(untracked.code, InvocationStatusCode::InternalError);
    assert_eq!(untracked.reason, REASON_RUN_QUOTA_UNTRACKED);
    assert!(
        untracked.retryable,
        "allowance pressure is retryable after backoff"
    );
}
