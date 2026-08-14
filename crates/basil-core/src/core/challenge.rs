// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Broker-side single-use freshness-challenge state for sealed invocations.
//!
//! Implements the Freshness section of `docs/ci-oidc-federation/SPEC.md`
//! (revision 4): a bounded in-memory table mapping each issued challenge to
//! `(jkt, generation, expiry)`, issuance rate limiting per `jkt`, per
//! immutable accepted-listener source partition, and globally, plus
//! exactly-once consumption. The table is deliberately safe to lose: restart or eviction invalidates
//! outstanding challenges and the client obtains a fresh one.
//!
//! Every mutating operation takes `&mut self`; the caller serializes access
//! behind one mutex, which is what makes consumption atomic (one remove under
//! one lock, no await points). Capacity and rate-limit pressure degrade
//! *issuance* only — consumption never consults capacity, so an invocation
//! presenting a valid unconsumed challenge always succeeds.

use std::collections::{HashMap, VecDeque};

const EXPIRY_CLEANUP_LIMIT: usize = 64;
const SOURCE_PARTITION_DOMAIN: &[u8] = b"basil.challenge-source-partition.v1\0";

/// Total challenge length on the wire: instance-ID prefix plus CSPRNG suffix.
pub const CHALLENGE_LEN: usize = 32;

/// Length of the per-agent instance-ID prefix generated at startup.
pub const INSTANCE_ID_LEN: usize = 16;

/// Length of the per-challenge CSPRNG suffix.
pub const CHALLENGE_SUFFIX_LEN: usize = CHALLENGE_LEN - INSTANCE_ID_LEN;

/// Maximum challenge lifetime in seconds (matches the maximum request
/// lifetime bound in the spec: `expires_at` is at most 60 seconds out).
pub const MAX_CHALLENGE_TTL_SECS: i64 = 60;

/// Maximum outstanding challenges per proof-key thumbprint.
pub const MAX_OUTSTANDING_PER_JKT: usize = 8;

/// Default configurable global maximum of outstanding challenges.
pub const DEFAULT_GLOBAL_CAPACITY: usize = 16_384;

/// Stable, secret-free rate-limit partition derived by the broker server.
///
/// The digest binds the closed listener type, exact listener name, kernel peer
/// UID, and the courier-observed source when the listener is a courier. Raw
/// source text is not retained in challenge state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ChallengeSourcePartition([u8; 32]);

impl ChallengeSourcePartition {
    /// Build a host-listener partition.
    #[must_use]
    pub(crate) fn host(listener_name: &str, uid: u32) -> Self {
        Self::derive(0, listener_name, uid, None)
    }

    /// Build a courier-listener partition with its validated observed source.
    #[must_use]
    pub(crate) fn courier(listener_name: &str, uid: u32, source: &str) -> Self {
        Self::derive(2, listener_name, uid, Some(source))
    }

    fn derive(kind: u8, listener_name: &str, uid: u32, source: Option<&str>) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SOURCE_PARTITION_DOMAIN);
        hasher.update(&[kind]);
        update_length_prefixed(&mut hasher, listener_name.as_bytes());
        hasher.update(&uid.to_be_bytes());
        if let Some(source) = source {
            hasher.update(&[1]);
            update_length_prefixed(&mut hasher, source.as_bytes());
        } else {
            hasher.update(&[0]);
        }
        Self(*hasher.finalize().as_bytes())
    }
}

fn update_length_prefixed(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

/// A token bucket's shape: maximum burst and sustained refill per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBucketConfig {
    /// Maximum tokens held (and the initial fill).
    pub burst: u32,
    /// Tokens restored per elapsed second, up to `burst`.
    pub refill_per_sec: u32,
}

/// One integer-second token bucket.
#[derive(Debug, Clone, Copy)]
struct TokenBucket {
    tokens: u32,
    last_refill_unix: i64,
}

impl TokenBucket {
    const fn new(config: TokenBucketConfig, now_unix: i64) -> Self {
        Self {
            tokens: config.burst,
            last_refill_unix: now_unix,
        }
    }

    fn refill(&mut self, config: TokenBucketConfig, now_unix: i64) {
        if now_unix < self.last_refill_unix {
            // The clock moved backwards: re-anchor without refilling so a
            // later forward jump cannot mint a large burst twice.
            self.last_refill_unix = now_unix;
            return;
        }
        let elapsed = now_unix.saturating_sub(self.last_refill_unix);
        if elapsed == 0 {
            return;
        }
        let refill = u32::try_from(elapsed)
            .unwrap_or(u32::MAX)
            .saturating_mul(config.refill_per_sec);
        self.tokens = self.tokens.saturating_add(refill).min(config.burst);
        self.last_refill_unix = now_unix;
    }

    fn try_take(&mut self, config: TokenBucketConfig, now_unix: i64) -> bool {
        self.refill(config, now_unix);
        if let Some(rest) = self.tokens.checked_sub(1) {
            self.tokens = rest;
            true
        } else {
            false
        }
    }

    /// Whether the bucket would be full after refilling: an idle partition
    /// whose tracking entry can be dropped without losing rate-limit state.
    fn is_idle(&mut self, config: TokenBucketConfig, now_unix: i64) -> bool {
        self.refill(config, now_unix);
        self.tokens >= config.burst
    }
}

/// Tunable bounds for the challenge table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeTableConfig {
    /// Global maximum of outstanding challenge records.
    pub global_capacity: usize,
    /// Maximum outstanding challenges per proof-key thumbprint.
    pub per_jkt_capacity: usize,
    /// Challenge lifetime in seconds (bounded by [`MAX_CHALLENGE_TTL_SECS`]).
    pub ttl_secs: i64,
    /// Global issuance token bucket.
    pub global_rate: TokenBucketConfig,
    /// Per-`jkt` issuance token bucket.
    pub per_jkt_rate: TokenBucketConfig,
    /// Per accepted-listener source partition issuance token bucket.
    pub per_source_rate: TokenBucketConfig,
    /// Maximum tracked rate-limit partitions per partition kind. When a new
    /// partition cannot be tracked (map full of non-idle buckets), issuance
    /// is declined rather than served unmetered.
    pub tracked_partitions: usize,
}

impl Default for ChallengeTableConfig {
    fn default() -> Self {
        Self {
            global_capacity: DEFAULT_GLOBAL_CAPACITY,
            per_jkt_capacity: MAX_OUTSTANDING_PER_JKT,
            ttl_secs: MAX_CHALLENGE_TTL_SECS,
            global_rate: TokenBucketConfig {
                burst: 512,
                refill_per_sec: 128,
            },
            per_jkt_rate: TokenBucketConfig {
                burst: 8,
                refill_per_sec: 4,
            },
            per_source_rate: TokenBucketConfig {
                burst: 64,
                refill_per_sec: 16,
            },
            tracked_partitions: DEFAULT_GLOBAL_CAPACITY,
        }
    }
}

/// One outstanding challenge record.
#[derive(Debug, Clone, Copy)]
struct ChallengeRecord {
    jkt: [u8; 32],
    generation: u64,
    expires_at_unix: i64,
}

/// A successfully issued challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuedChallenge {
    /// The full 32 challenge bytes: instance-ID prefix plus CSPRNG suffix.
    pub challenge: [u8; CHALLENGE_LEN],
    /// Unix seconds when the challenge expires.
    pub expires_at_unix: i64,
}

/// Why issuance was declined. Every variant maps to the retryable
/// `CHALLENGE_ISSUANCE_DECLINED` wire status; the split exists for logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IssueDecline {
    /// A global, per-`jkt`, or per-source token bucket is empty, or a new
    /// rate-limit partition cannot be tracked.
    #[error("issuance rate limited")]
    RateLimited,
    /// The global table or the per-`jkt` slice is full of unexpired records.
    #[error("challenge capacity exhausted")]
    CapacityExhausted,
    /// The system CSPRNG is unavailable; nothing was issued.
    #[error("entropy unavailable")]
    EntropyUnavailable,
}

/// Why consumption was denied. Every variant maps to the non-retryable
/// sealed `CHALLENGE_UNKNOWN` status; the split exists for logs and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConsumeDenied {
    /// The challenge is malformed, absent, or already consumed.
    #[error("challenge unknown")]
    Unknown,
    /// The instance-ID prefix names a different issuing agent; answered
    /// without consulting the table.
    #[error("challenge issued by another instance")]
    ForeignInstance,
    /// The record exists but is bound to a different proof-key thumbprint.
    /// The record is left in place for its rightful holder.
    #[error("challenge bound to a different proof key")]
    JktMismatch,
    /// The record was issued under a different serving generation; it can
    /// never become valid again and is dropped.
    #[error("challenge bound to a different serving generation")]
    GenerationMismatch,
    /// The record expired before consumption and was dropped.
    #[error("challenge expired")]
    Expired,
}

/// Bounded in-memory single-use challenge table.
///
/// The 16-byte instance ID is generated from the system CSPRNG at
/// construction; if entropy is unavailable then, generation is retried on
/// the next issuance and issuance fails closed until it succeeds.
#[derive(Debug)]
pub struct ChallengeTable {
    config: ChallengeTableConfig,
    instance_id: Option<[u8; INSTANCE_ID_LEN]>,
    records: HashMap<[u8; CHALLENGE_SUFFIX_LEN], ChallengeRecord>,
    outstanding_per_jkt: HashMap<[u8; 32], usize>,
    global_bucket: TokenBucket,
    jkt_buckets: HashMap<[u8; 32], TokenBucket>,
    source_buckets: HashMap<ChallengeSourcePartition, TokenBucket>,
    expiry_queue: VecDeque<([u8; CHALLENGE_SUFFIX_LEN], i64)>,
    #[cfg(test)]
    entropy_available: bool,
    #[cfg(test)]
    fail_next_reserve: bool,
}

impl ChallengeTable {
    /// Build a table with an explicit configuration.
    #[must_use]
    pub fn with_config(config: ChallengeTableConfig) -> Self {
        let config = ChallengeTableConfig {
            global_capacity: config.global_capacity.max(1),
            per_jkt_capacity: config.per_jkt_capacity.clamp(1, MAX_OUTSTANDING_PER_JKT),
            ttl_secs: config.ttl_secs.clamp(1, MAX_CHALLENGE_TTL_SECS),
            tracked_partitions: config.tracked_partitions.max(1),
            ..config
        };
        Self {
            config,
            instance_id: random_bytes::<INSTANCE_ID_LEN>(),
            records: HashMap::new(),
            outstanding_per_jkt: HashMap::new(),
            global_bucket: TokenBucket::new(config.global_rate, 0),
            jkt_buckets: HashMap::new(),
            source_buckets: HashMap::new(),
            expiry_queue: VecDeque::new(),
            #[cfg(test)]
            entropy_available: true,
            #[cfg(test)]
            fail_next_reserve: false,
        }
    }

    /// The number of outstanding (possibly expired, not yet purged) records.
    #[must_use]
    pub fn outstanding(&self) -> usize {
        self.records.len()
    }

    /// Issue a single-use challenge bound to `jkt` and `generation`.
    ///
    /// Under pressure, expired records are dropped first; if pressure
    /// remains, issuance is declined with a retryable condition. `source` is
    /// derived from the accepted listener and kernel UID before this method is
    /// called. Entropy, capacity, partition tracking, and map reservation are
    /// checked before the planned token debits commit.
    ///
    /// # Errors
    /// [`IssueDecline`] when rate limited, at capacity, or without entropy.
    pub fn issue(
        &mut self,
        jkt: [u8; 32],
        source: ChallengeSourcePartition,
        generation: u64,
        now_unix: i64,
    ) -> Result<IssuedChallenge, IssueDecline> {
        self.purge_expired(now_unix);
        let Some(instance_id) = self.instance_id.or_else(|| self.draw_random()) else {
            return Err(IssueDecline::EntropyUnavailable);
        };
        if self.records.len() >= self.config.global_capacity {
            return Err(IssueDecline::CapacityExhausted);
        }
        let outstanding = self.outstanding_per_jkt.get(&jkt).copied().unwrap_or(0);
        if outstanding >= self.config.per_jkt_capacity {
            return Err(IssueDecline::CapacityExhausted);
        }
        let mut global_bucket = self.global_bucket;
        if !global_bucket.try_take(self.config.global_rate, now_unix) {
            return Err(IssueDecline::RateLimited);
        }
        let source_debit = plan_partition_token(
            &self.source_buckets,
            source,
            self.config.per_source_rate,
            self.config.tracked_partitions,
            now_unix,
        )
        .ok_or(IssueDecline::RateLimited)?;
        let jkt_debit = plan_partition_token(
            &self.jkt_buckets,
            jkt,
            self.config.per_jkt_rate,
            self.config.tracked_partitions,
            now_unix,
        )
        .ok_or(IssueDecline::RateLimited)?;
        let suffix = self
            .unused_suffix()
            .ok_or(IssueDecline::EntropyUnavailable)?;
        self.reserve_issue_maps(&jkt, &source_debit, &jkt_debit)?;

        let expires_at_unix = now_unix.saturating_add(self.config.ttl_secs);
        self.instance_id = Some(instance_id);
        self.global_bucket = global_bucket;
        source_debit.commit(&mut self.source_buckets);
        jkt_debit.commit(&mut self.jkt_buckets);
        self.records.insert(
            suffix,
            ChallengeRecord {
                jkt,
                generation,
                expires_at_unix,
            },
        );
        self.expiry_queue.push_back((suffix, expires_at_unix));
        *self.outstanding_per_jkt.entry(jkt).or_insert(0) = outstanding.saturating_add(1);
        let mut challenge = [0_u8; CHALLENGE_LEN];
        challenge
            .iter_mut()
            .zip(instance_id.iter().chain(suffix.iter()))
            .for_each(|(out, byte)| *out = *byte);
        Ok(IssuedChallenge {
            challenge,
            expires_at_unix,
        })
    }

    /// Atomically consume `challenge` for the verified thumbprint `jkt` under
    /// the pinned serving `generation`.
    ///
    /// Exactly-once: callers serialize on the surrounding mutex, and the
    /// record is removed in the same critical section that validates it, so
    /// concurrent duplicates resolve to one success and one denial.
    ///
    /// # Errors
    /// [`ConsumeDenied`] when the record is absent, foreign, mismatched, or
    /// expired. All variants surface as the sealed `CHALLENGE_UNKNOWN`.
    pub fn consume(
        &mut self,
        challenge: &[u8],
        jkt: &[u8; 32],
        generation: u64,
        now_unix: i64,
    ) -> Result<(), ConsumeDenied> {
        let Some((prefix, suffix)) = challenge.split_at_checked(INSTANCE_ID_LEN) else {
            return Err(ConsumeDenied::Unknown);
        };
        let Ok(suffix) = <[u8; CHALLENGE_SUFFIX_LEN]>::try_from(suffix) else {
            return Err(ConsumeDenied::Unknown);
        };
        // An unknown instance-ID prefix is answered without consulting the
        // table: another replica issued it (or this agent restarted).
        if self.instance_id.is_none_or(|id| id != prefix) {
            return Err(ConsumeDenied::ForeignInstance);
        }
        let Some(record) = self.records.get(&suffix).copied() else {
            return Err(ConsumeDenied::Unknown);
        };
        if now_unix > record.expires_at_unix {
            self.remove_record(&suffix);
            return Err(ConsumeDenied::Expired);
        }
        if record.jkt != *jkt {
            // Leave the record: a caller who learned the challenge bytes but
            // holds a different proof key must not burn the rightful
            // holder's challenge.
            return Err(ConsumeDenied::JktMismatch);
        }
        if record.generation != generation {
            // The serving generation only moves forward; the record can
            self.remove_record(&suffix);
            return Err(ConsumeDenied::GenerationMismatch);
        }
        self.remove_record(&suffix);
        Ok(())
    }

    /// Draw a CSPRNG suffix not currently in the table. A collision among
    /// 16 random bytes is cryptographically negligible; the bounded retry
    /// exists to keep the no-panic guarantee explicit.
    fn unused_suffix(&self) -> Option<[u8; CHALLENGE_SUFFIX_LEN]> {
        for _ in 0_u8..4 {
            let suffix = self.draw_random::<CHALLENGE_SUFFIX_LEN>()?;
            if !self.records.contains_key(&suffix) {
                return Some(suffix);
            }
        }
        None
    }

    #[allow(
        clippy::unused_self,
        reason = "the receiver carries the test-only entropy failure seam"
    )]
    fn draw_random<const N: usize>(&self) -> Option<[u8; N]> {
        #[cfg(test)]
        if !self.entropy_available {
            return None;
        }
        random_bytes::<N>()
    }

    fn reserve_issue_maps(
        &mut self,
        jkt: &[u8; 32],
        source_debit: &PartitionDebit<ChallengeSourcePartition>,
        jkt_debit: &PartitionDebit<[u8; 32]>,
    ) -> Result<(), IssueDecline> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next_reserve) {
            return Err(IssueDecline::CapacityExhausted);
        }
        self.records
            .try_reserve(1)
            .map_err(|_| IssueDecline::CapacityExhausted)?;
        self.expiry_queue
            .try_reserve(1)
            .map_err(|_| IssueDecline::CapacityExhausted)?;
        if !self.outstanding_per_jkt.contains_key(jkt) {
            self.outstanding_per_jkt
                .try_reserve(1)
                .map_err(|_| IssueDecline::CapacityExhausted)?;
        }
        source_debit.reserve_if_growing(&mut self.source_buckets)?;
        jkt_debit.reserve_if_growing(&mut self.jkt_buckets)?;
        Ok(())
    }

    fn remove_record(&mut self, suffix: &[u8; CHALLENGE_SUFFIX_LEN]) {
        if let Some(record) = self.records.remove(suffix)
            && let Some(count) = self.outstanding_per_jkt.get_mut(&record.jkt)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.outstanding_per_jkt.remove(&record.jkt);
            }
        }
    }

    fn purge_expired(&mut self, now_unix: i64) {
        let examined = self.expiry_queue.len().min(EXPIRY_CLEANUP_LIMIT);
        for _ in 0..examined {
            let Some((suffix, queued_expiry)) = self.expiry_queue.pop_front() else {
                break;
            };
            match self.records.get(&suffix).copied() {
                Some(record)
                    if record.expires_at_unix == queued_expiry
                        && now_unix > record.expires_at_unix =>
                {
                    self.remove_record(&suffix);
                }
                Some(record) if record.expires_at_unix == queued_expiry => {
                    self.expiry_queue.push_back((suffix, queued_expiry));
                }
                Some(_) | None => {}
            }
        }
    }
}

enum PartitionDebit<K> {
    Update {
        key: K,
        bucket: TokenBucket,
    },
    Insert {
        key: K,
        bucket: TokenBucket,
        evict: Option<K>,
    },
}

impl<K: std::hash::Hash + Eq> PartitionDebit<K> {
    fn reserve_if_growing(
        &self,
        buckets: &mut HashMap<K, TokenBucket>,
    ) -> Result<(), IssueDecline> {
        if matches!(self, Self::Insert { evict: None, .. }) {
            buckets
                .try_reserve(1)
                .map_err(|_| IssueDecline::CapacityExhausted)?;
        }
        Ok(())
    }

    fn commit(self, buckets: &mut HashMap<K, TokenBucket>) {
        match self {
            Self::Update { key, bucket } => {
                buckets.insert(key, bucket);
            }
            Self::Insert { key, bucket, evict } => {
                if let Some(evict) = evict {
                    buckets.remove(&evict);
                }
                buckets.insert(key, bucket);
            }
        }
    }
}

/// Plan one partition debit without mutating the tracked bucket map.
fn plan_partition_token<K: std::hash::Hash + Eq + Clone>(
    buckets: &HashMap<K, TokenBucket>,
    key: K,
    config: TokenBucketConfig,
    tracked_partitions: usize,
    now_unix: i64,
) -> Option<PartitionDebit<K>> {
    if let Some(bucket) = buckets.get(&key) {
        let mut bucket = *bucket;
        return bucket
            .try_take(config, now_unix)
            .then_some(PartitionDebit::Update { key, bucket });
    }
    let evict = (buckets.len() >= tracked_partitions)
        .then(|| {
            buckets.iter().find_map(|(key, bucket)| {
                let mut bucket = *bucket;
                bucket.is_idle(config, now_unix).then(|| key.clone())
            })
        })
        .flatten();
    if buckets.len() >= tracked_partitions && evict.is_none() {
        return None;
    }
    let mut bucket = TokenBucket::new(config, now_unix);
    bucket
        .try_take(config, now_unix)
        .then_some(PartitionDebit::Insert { key, bucket, evict })
}

/// Fill an array from the system CSPRNG, `None` on failure (fail closed,
/// never panic).
fn random_bytes<const N: usize>() -> Option<[u8; N]> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).ok().map(|()| bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000;
    const GEN: u64 = 7;

    fn generous_rates() -> ChallengeTableConfig {
        ChallengeTableConfig {
            global_rate: TokenBucketConfig {
                burst: 1_000,
                refill_per_sec: 1_000,
            },
            per_jkt_rate: TokenBucketConfig {
                burst: 1_000,
                refill_per_sec: 1_000,
            },
            per_source_rate: TokenBucketConfig {
                burst: 1_000,
                refill_per_sec: 1_000,
            },
            ..ChallengeTableConfig::default()
        }
    }

    fn table() -> ChallengeTable {
        ChallengeTable::with_config(generous_rates())
    }

    fn jkt(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn source(uid: u32) -> ChallengeSourcePartition {
        ChallengeSourcePartition::host("test", uid)
    }

    fn courier_source(value: &str) -> ChallengeSourcePartition {
        ChallengeSourcePartition::courier("edge", 1_000, value)
    }

    #[test]
    fn issued_challenge_is_instance_prefixed_with_bounded_expiry() {
        let mut table = table();
        let issued = table.issue(jkt(1), source(1), GEN, NOW).expect("issues");
        assert_eq!(issued.expires_at_unix, NOW + MAX_CHALLENGE_TTL_SECS);
        let again = table.issue(jkt(1), source(1), GEN, NOW).expect("issues");
        assert_eq!(
            issued.challenge[..INSTANCE_ID_LEN],
            again.challenge[..INSTANCE_ID_LEN],
            "prefix is the stable per-agent instance ID"
        );
        assert_ne!(issued.challenge, again.challenge);
        assert_eq!(table.outstanding(), 2);
    }

    #[test]
    fn consume_is_exactly_once() {
        let mut table = table();
        let issued = table.issue(jkt(1), source(1), GEN, NOW).unwrap();
        assert_eq!(table.consume(&issued.challenge, &jkt(1), GEN, NOW), Ok(()));
        assert_eq!(
            table.consume(&issued.challenge, &jkt(1), GEN, NOW),
            Err(ConsumeDenied::Unknown)
        );
    }

    #[test]
    fn concurrent_duplicates_resolve_to_one_success_and_one_unknown() {
        use std::sync::{Arc, Barrier, Mutex};
        let shared = Arc::new(Mutex::new(table()));
        let issued = shared
            .lock()
            .unwrap()
            .issue(jkt(1), source(1), GEN, NOW)
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let spawn_consumer = || {
            let shared = Arc::clone(&shared);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                shared
                    .lock()
                    .unwrap()
                    .consume(&issued.challenge, &jkt(1), GEN, NOW)
            })
        };
        // Both threads must be running before either joins, or the barrier
        // deadlocks; spawn first, then join.
        let first = spawn_consumer();
        let second = spawn_consumer();
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == Err(ConsumeDenied::Unknown))
                .count(),
            1
        );
    }

    #[test]
    fn expiry_boundary_is_inclusive_at_expires_at() {
        let mut table = table();
        let issued = table.issue(jkt(1), source(1), GEN, NOW).unwrap();
        // Exactly at expires_at the challenge is still valid.
        assert_eq!(
            table.consume(&issued.challenge, &jkt(1), GEN, issued.expires_at_unix),
            Ok(())
        );
        let issued = table.issue(jkt(1), source(1), GEN, NOW).unwrap();
        // One second past, it is expired and dropped.
        assert_eq!(
            table.consume(&issued.challenge, &jkt(1), GEN, issued.expires_at_unix + 1),
            Err(ConsumeDenied::Expired)
        );
        assert_eq!(table.outstanding(), 0);
    }

    #[test]
    fn wrong_jkt_is_denied_and_preserves_the_record() {
        let mut table = table();
        let issued = table.issue(jkt(1), source(1), GEN, NOW).unwrap();
        assert_eq!(
            table.consume(&issued.challenge, &jkt(2), GEN, NOW),
            Err(ConsumeDenied::JktMismatch)
        );
        // The rightful holder can still consume it.
        assert_eq!(table.consume(&issued.challenge, &jkt(1), GEN, NOW), Ok(()));
    }

    #[test]
    fn wrong_generation_is_denied_and_drops_the_record() {
        let mut table = table();
        let issued = table.issue(jkt(1), source(1), GEN, NOW).unwrap();
        assert_eq!(
            table.consume(&issued.challenge, &jkt(1), GEN + 1, NOW),
            Err(ConsumeDenied::GenerationMismatch)
        );
        assert_eq!(
            table.consume(&issued.challenge, &jkt(1), GEN, NOW),
            Err(ConsumeDenied::Unknown)
        );
        assert_eq!(table.outstanding(), 0);
    }

    #[test]
    fn restart_invalidates_outstanding_challenges_via_instance_prefix() {
        let mut before = table();
        let issued = before.issue(jkt(1), source(1), GEN, NOW).unwrap();
        let mut after = table();
        assert_eq!(
            after.consume(&issued.challenge, &jkt(1), GEN, NOW),
            Err(ConsumeDenied::ForeignInstance)
        );
    }

    #[test]
    fn malformed_lengths_are_unknown() {
        let mut table = table();
        assert_eq!(
            table.consume(&[0_u8; 31], &jkt(1), GEN, NOW),
            Err(ConsumeDenied::Unknown)
        );
        assert_eq!(
            table.consume(&[], &jkt(1), GEN, NOW),
            Err(ConsumeDenied::Unknown)
        );
    }

    #[test]
    fn per_jkt_capacity_is_eight_and_scoped_to_the_thumbprint() {
        let mut table = table();
        for _ in 0..MAX_OUTSTANDING_PER_JKT {
            table
                .issue(jkt(1), source(1), GEN, NOW)
                .expect("under the cap");
        }
        assert_eq!(
            table.issue(jkt(1), source(1), GEN, NOW),
            Err(IssueDecline::CapacityExhausted)
        );
        // A different thumbprint is unaffected.
        table
            .issue(jkt(2), source(1), GEN, NOW)
            .expect("other jkt issues");
    }

    #[test]
    fn global_capacity_declines_issuance_but_never_consumption() {
        let mut table = ChallengeTable::with_config(ChallengeTableConfig {
            global_capacity: 4,
            ..generous_rates()
        });
        let mut issued = Vec::new();
        for seed in 0..4_u8 {
            issued.push((seed, table.issue(jkt(seed), source(1), GEN, NOW).unwrap()));
        }
        assert_eq!(
            table.issue(jkt(9), source(1), GEN, NOW),
            Err(IssueDecline::CapacityExhausted)
        );
        // Capacity pressure never denies a valid unconsumed challenge.
        for (seed, challenge) in issued {
            assert_eq!(
                table.consume(&challenge.challenge, &jkt(seed), GEN, NOW),
                Ok(())
            );
        }
        table
            .issue(jkt(9), source(1), GEN, NOW)
            .expect("space reclaimed");
    }

    #[test]
    fn expired_records_are_dropped_before_declining_issuance() {
        let mut table = ChallengeTable::with_config(ChallengeTableConfig {
            global_capacity: 2,
            ..generous_rates()
        });
        table.issue(jkt(1), source(1), GEN, NOW).unwrap();
        table.issue(jkt(2), source(1), GEN, NOW).unwrap();
        // Past expiry, the full table degrades by dropping expired records
        // first instead of declining.
        let later = NOW + MAX_CHALLENGE_TTL_SECS + 1;
        table
            .issue(jkt(3), source(1), GEN, later)
            .expect("expired dropped first");
        assert_eq!(table.outstanding(), 1);
    }

    #[test]
    fn capacity_declines_do_not_consume_rate_tokens() {
        // Exactly enough per-jkt tokens for the per-jkt capacity: if a
        // capacity decline burned a token, the declines below would surface
        // as RateLimited and a retry-after-consume would be starved.
        let mut table = ChallengeTable::with_config(ChallengeTableConfig {
            global_rate: TokenBucketConfig {
                burst: 9,
                refill_per_sec: 0,
            },
            per_jkt_rate: TokenBucketConfig {
                burst: 9,
                refill_per_sec: 0,
            },
            per_source_rate: TokenBucketConfig {
                burst: 9,
                refill_per_sec: 0,
            },
            ..generous_rates()
        });
        let mut issued = Vec::new();
        for _ in 0..MAX_OUTSTANDING_PER_JKT {
            issued.push(
                table
                    .issue(jkt(1), source(1), GEN, NOW)
                    .expect("under the cap"),
            );
        }
        for _ in 0..3 {
            assert_eq!(
                table.issue(jkt(1), source(1), GEN, NOW),
                Err(IssueDecline::CapacityExhausted),
                "capacity is reported before (and without burning) rate tokens"
            );
        }
        assert_eq!(
            table.consume(&issued[0].challenge, &jkt(1), GEN, NOW),
            Ok(())
        );
        table
            .issue(jkt(1), source(1), GEN, NOW)
            .expect("capacity decline consumed no global, source, or jkt token");
    }

    #[test]
    fn per_jkt_issuance_rate_limit_declines_then_refills() {
        let mut table = ChallengeTable::with_config(ChallengeTableConfig {
            per_jkt_rate: TokenBucketConfig {
                burst: 2,
                refill_per_sec: 1,
            },
            ..generous_rates()
        });
        table.issue(jkt(1), source(1), GEN, NOW).unwrap();
        table.issue(jkt(1), source(1), GEN, NOW).unwrap();
        assert_eq!(
            table.issue(jkt(1), source(1), GEN, NOW),
            Err(IssueDecline::RateLimited)
        );
        // A different jkt has its own bucket.
        table
            .issue(jkt(2), source(2), GEN, NOW)
            .expect("other jkt issues");
        // One second later one token refilled.
        table
            .issue(jkt(1), source(1), GEN, NOW + 1)
            .expect("refilled");
    }

    #[test]
    fn per_source_rate_limit_partitions_by_courier_observed_source() {
        let mut table = ChallengeTable::with_config(ChallengeTableConfig {
            per_source_rate: TokenBucketConfig {
                burst: 1,
                refill_per_sec: 1,
            },
            ..generous_rates()
        });
        table
            .issue(jkt(1), courier_source("10.0.0.1"), GEN, NOW)
            .unwrap();
        assert_eq!(
            table.issue(jkt(2), courier_source("10.0.0.1"), GEN, NOW),
            Err(IssueDecline::RateLimited)
        );
        table
            .issue(jkt(2), courier_source("10.0.0.2"), GEN, NOW)
            .expect("distinct source issues");
        table
            .issue(jkt(3), source(1_000), GEN, NOW)
            .expect("host partition is independent from courier sources");
    }

    #[test]
    fn source_partition_binds_listener_kind_name_uid_and_courier_source() {
        let host = ChallengeSourcePartition::host("edge", 1_000);
        assert_ne!(
            host,
            ChallengeSourcePartition::courier("edge", 1_000, "source-a")
        );
        assert_ne!(host, ChallengeSourcePartition::host("other", 1_000));
        assert_ne!(host, ChallengeSourcePartition::host("edge", 1_001));
        assert_ne!(
            ChallengeSourcePartition::courier("edge", 1_000, "source-a"),
            ChallengeSourcePartition::courier("edge", 1_000, "source-b")
        );
    }

    #[test]
    fn source_partition_failure_rolls_back_global_and_jkt_debits() {
        let mut table = ChallengeTable::with_config(ChallengeTableConfig {
            tracked_partitions: 1,
            global_rate: TokenBucketConfig {
                burst: 2,
                refill_per_sec: 0,
            },
            per_source_rate: TokenBucketConfig {
                burst: 2,
                refill_per_sec: 0,
            },
            per_jkt_rate: TokenBucketConfig {
                burst: 1,
                refill_per_sec: 1,
            },
            ..ChallengeTableConfig::default()
        });
        table
            .issue(jkt(1), courier_source("a"), GEN, NOW)
            .expect("first partition issues");
        assert_eq!(
            table.issue(jkt(2), courier_source("b"), GEN, NOW),
            Err(IssueDecline::RateLimited)
        );
        table
            .issue(jkt(2), courier_source("a"), GEN, NOW + 1)
            .expect("failed source plan consumed no global or jkt token");
    }

    #[test]
    fn jkt_partition_failure_rolls_back_global_and_source_debits() {
        let mut table = ChallengeTable::with_config(ChallengeTableConfig {
            tracked_partitions: 1,
            global_rate: TokenBucketConfig {
                burst: 2,
                refill_per_sec: 0,
            },
            per_source_rate: TokenBucketConfig {
                burst: 2,
                refill_per_sec: 0,
            },
            per_jkt_rate: TokenBucketConfig {
                burst: 2,
                refill_per_sec: 0,
            },
            ..ChallengeTableConfig::default()
        });
        table
            .issue(jkt(1), courier_source("a"), GEN, NOW)
            .expect("first partition issues");
        assert_eq!(
            table.issue(jkt(2), courier_source("a"), GEN, NOW),
            Err(IssueDecline::RateLimited)
        );
        table
            .issue(jkt(1), courier_source("a"), GEN, NOW)
            .expect("failed jkt plan consumed no global or source token");
    }

    #[test]
    fn entropy_and_map_reservation_failures_consume_no_debits() {
        let one_shot = ChallengeTableConfig {
            global_rate: TokenBucketConfig {
                burst: 1,
                refill_per_sec: 0,
            },
            per_source_rate: TokenBucketConfig {
                burst: 1,
                refill_per_sec: 0,
            },
            per_jkt_rate: TokenBucketConfig {
                burst: 1,
                refill_per_sec: 0,
            },
            ..ChallengeTableConfig::default()
        };
        let mut entropy = ChallengeTable::with_config(one_shot);
        entropy.instance_id = None;
        entropy.entropy_available = false;
        assert_eq!(
            entropy.issue(jkt(1), source(1), GEN, NOW),
            Err(IssueDecline::EntropyUnavailable)
        );
        entropy.entropy_available = true;
        entropy
            .issue(jkt(1), source(1), GEN, NOW)
            .expect("entropy failure consumed no token");

        let mut reserve = ChallengeTable::with_config(one_shot);
        reserve.fail_next_reserve = true;
        assert_eq!(
            reserve.issue(jkt(1), source(1), GEN, NOW),
            Err(IssueDecline::CapacityExhausted)
        );
        reserve
            .issue(jkt(1), source(1), GEN, NOW)
            .expect("reservation failure consumed no token");
    }

    #[test]
    fn issuance_expiry_cleanup_work_is_bounded() {
        let mut table = ChallengeTable::with_config(ChallengeTableConfig {
            global_capacity: 128,
            ..generous_rates()
        });
        for seed in 0..100_u8 {
            table.issue(jkt(seed), source(1), GEN, NOW).unwrap();
        }
        table
            .issue(jkt(200), source(1), GEN, NOW + MAX_CHALLENGE_TTL_SECS + 1)
            .expect("bounded cleanup makes room");
        assert_eq!(table.outstanding(), 100 - EXPIRY_CLEANUP_LIMIT + 1);
    }

    #[test]
    fn global_rate_limit_declines_all_issuance() {
        let mut table = ChallengeTable::with_config(ChallengeTableConfig {
            global_rate: TokenBucketConfig {
                burst: 1,
                refill_per_sec: 1,
            },
            ..generous_rates()
        });
        table.issue(jkt(1), source(1), GEN, NOW).unwrap();
        assert_eq!(
            table.issue(jkt(2), source(2), GEN, NOW),
            Err(IssueDecline::RateLimited)
        );
    }

    #[test]
    fn untrackable_new_partition_declines_instead_of_unmetered_service() {
        let mut table = ChallengeTable::with_config(ChallengeTableConfig {
            tracked_partitions: 1,
            per_source_rate: TokenBucketConfig {
                burst: 2,
                refill_per_sec: 0,
            },
            ..generous_rates()
        });
        table.issue(jkt(1), courier_source("a"), GEN, NOW).unwrap();
        // "a" holds a non-idle bucket; a second source cannot be tracked.
        assert_eq!(
            table.issue(jkt(2), courier_source("b"), GEN, NOW),
            Err(IssueDecline::RateLimited)
        );
        // Idle partitions are evicted to make room.
        let mut roomy = ChallengeTable::with_config(ChallengeTableConfig {
            tracked_partitions: 1,
            per_source_rate: TokenBucketConfig {
                burst: 2,
                refill_per_sec: 2,
            },
            ..generous_rates()
        });
        roomy.issue(jkt(1), courier_source("a"), GEN, NOW).unwrap();
        roomy
            .issue(jkt(2), courier_source("b"), GEN, NOW + 5)
            .expect("idle partition evicted");
    }
}
