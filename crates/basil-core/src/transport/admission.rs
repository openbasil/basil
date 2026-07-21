// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Pre-dispatch admission core: finite work-class lanes and queues
//! (`basil-cx25`, admission design rev 1.1 §3–§6).
//!
//! Every Unix-socket RPC is admitted through exactly one work-class lane
//! before any dispatch work happens, routed by the compiled
//! [`RpcMethod`] classification ([`super::rpc_registry`]):
//!
//! - class `U` (unary): concurrency cap plus a bounded FIFO wait queue whose
//!   wait is bounded by `min(caller deadline, unary-queue-wait)`;
//! - class `F` (finite stream): separate cap plus a small bounded queue,
//!   waiting only under the caller's deadline;
//! - class `O` (operator/recovery): a disjoint reserved lane, never queued,
//!   so recovery stays admittable while `U`/`F`/`L` are saturated;
//! - class `L` (long-lived stream): admit-or-reject against the global
//!   stream bound — never queued (a queued stream open would retain
//!   transport state while waiting for capacity that may never free).
//!
//! Admission owns the typed `OVERLOADED` rejection: the reason constant and
//! its status constructor are private to this module, so no service path can
//! mint an `OVERLOADED` status — a received `OVERLOADED` provably came from
//! pre-dispatch admission and therefore proves the work did not execute
//! (invariant I1a; the source-scan test below enforces the privacy). The
//! rejection carries `BrokerErrorInfo` plus a server-jittered, deliberately
//! load-independent `google.rpc.RetryInfo`. `ATTESTATION_UNAVAILABLE` stays
//! distinct: admission never emits it and attestation never emits
//! `OVERLOADED`.
//!
//! Deadline race (design §6.2, condition C4): every admission request
//! resolves to exactly one of *admitted* (permit acquired) or *rejected
//! `OVERLOADED`* — never both, never neither. A queue waiter whose bound
//! elapses concurrently with a permit grant either receives the permit (the
//! grant is observed before the timer) or is rejected with the permit
//! returned to the lane; an expired waiter is rejected `OVERLOADED`, never
//! `DeadlineExceeded`, and the `OVERLOADED` promise is only made for waits
//! this module bounded — once the transport cancels the request future the
//! wait is abandoned without any response, releasing exactly what was held.
//!
//! This module is the admission mechanism only. Deliberately elsewhere:
//! dispatch wiring and the explicit HTTP/2 stream ceiling (`basil-iht1` /
//! `basil-4ohg`, coupled only through
//! [`COMPILED_ADMISSION_HEAD_BOUND`]), per-identity/presenter fairness
//! (`basil-mnjn`), class-O sub-lanes (`basil-s5wy`), the `[admission]`
//! config schema and reload (`basil-62ji`), and class-L charge conversion
//! into the connection registry (`basil-9tj.16`). Limits here are compiled
//! defaults with non-removable compiled ceilings; there is no configuration
//! that disables admission.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use prost::Message as _;
use thiserror::Error;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tonic::{Code, Status};

use super::RetryInfoDetail;
use super::rpc_registry::{RpcMethod, WorkClass};

/// Compiled ceiling for class `U` in-flight concurrency.
pub const UNARY_CONCURRENCY_CEILING: usize = 1024;

/// Compiled ceiling for the class `U` wait-queue depth.
pub const UNARY_QUEUE_DEPTH_CEILING: usize = 512;

/// Compiled ceiling for the class `U` queue wait bound.
pub const UNARY_QUEUE_WAIT_CEILING: Duration = Duration::from_secs(5);

/// Compiled ceiling for class `F` in-flight concurrency.
pub const FINITE_STREAM_CONCURRENCY_CEILING: usize = 128;

/// Compiled ceiling for the class `F` wait-queue depth.
pub const FINITE_STREAM_QUEUE_DEPTH_CEILING: usize = 128;

/// Compiled floor for the reserved class `O` lane.
///
/// The floor is the class-O sub-lane minimum — one `Readiness`, one
/// recovery, one observation, and one shared slot (design §4.4);
/// `basil-s5wy` lands the sub-lane accounting itself.
pub const RESERVED_OPERATOR_CONCURRENCY_FLOOR: usize = 4;

/// Compiled ceiling for the reserved class `O` lane.
pub const RESERVED_OPERATOR_CONCURRENCY_CEILING: usize = 64;

/// Compiled ceiling for the global class `L` stream bound.
pub const STREAMS_GLOBAL_CEILING: usize = 4096;

/// Compiled bound on request heads that admission can concurrently admit or
/// queue across every lane at the compiled ceilings.
///
/// This is the shared coupling constant with `basil-iht1` (transport
/// condition C3): the explicit HTTP/2 `max_concurrent_streams` ceiling must
/// leave headroom above this bound so that admission — not an HTTP/2 reset —
/// is the rejection a classified request receives at saturation.
pub const COMPILED_ADMISSION_HEAD_BOUND: usize = UNARY_CONCURRENCY_CEILING
    + UNARY_QUEUE_DEPTH_CEILING
    + FINITE_STREAM_CONCURRENCY_CEILING
    + FINITE_STREAM_QUEUE_DEPTH_CEILING
    + RESERVED_OPERATOR_CONCURRENCY_CEILING
    + STREAMS_GLOBAL_CEILING;

/// The `OVERLOADED` reason token — private by design (condition C1).
///
/// Kept out of every public constant table so no service path can mint the
/// outcome-safe rejection; the `overloaded_literal_is_private_to_this_module`
/// test enforces that this crate spells the quoted literal only here.
const OVERLOADED_REASON: &str = "OVERLOADED";

/// Server-jittered retry floor for `OVERLOADED` responses (design §6.1).
const OVERLOADED_RETRY_MIN_MILLIS: i64 = 250;

/// Server-jittered retry ceiling for `OVERLOADED` responses (design §6.1).
const OVERLOADED_RETRY_MAX_MILLIS: i64 = 1000;

/// Broker-wide admission limits (design §4.2 and §5.1).
///
/// Values are compiled defaults until the `[admission]` config table lands
/// (`basil-62ji`); every field is bounded by a non-removable compiled
/// ceiling enforced by [`AdmissionLimits::validate`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionLimits {
    /// Class `U` in-flight concurrency cap.
    pub unary_concurrency: usize,
    /// Class `U` bounded FIFO wait-queue depth.
    pub unary_queue_depth: usize,
    /// Class `U` maximum queue wait; the effective wait bound is
    /// `min(caller deadline, this bound)`.
    pub unary_queue_wait: Duration,
    /// Class `F` in-flight concurrency cap.
    pub finite_stream_concurrency: usize,
    /// Class `F` bounded FIFO wait-queue depth.
    pub finite_stream_queue_depth: usize,
    /// Reserved class `O` lane size, disjoint from every other lane.
    pub reserved_operator_concurrency: usize,
    /// Global class `L` stream bound (admit-or-reject, never queued).
    pub streams_global: usize,
}

impl AdmissionLimits {
    /// The compiled default limits (design §4.2/§5.1 defaults).
    #[must_use]
    pub const fn compiled() -> Self {
        Self {
            unary_concurrency: 256,
            unary_queue_depth: 128,
            unary_queue_wait: Duration::from_secs(1),
            finite_stream_concurrency: 32,
            finite_stream_queue_depth: 32,
            reserved_operator_concurrency: 16,
            streams_global: 2000,
        }
    }

    /// Validate every limit against its compiled floor and ceiling.
    ///
    /// # Errors
    ///
    /// Returns the first limit outside its compiled range. Callers must fail
    /// closed: there is no admissible configuration outside the ranges.
    pub fn validate(&self) -> Result<(), AdmissionLimitsError> {
        check_range(
            "unary-concurrency",
            self.unary_concurrency,
            1,
            UNARY_CONCURRENCY_CEILING,
        )?;
        check_range(
            "unary-queue-depth",
            self.unary_queue_depth,
            0,
            UNARY_QUEUE_DEPTH_CEILING,
        )?;
        check_millis_range(
            "unary-queue-wait-ms",
            self.unary_queue_wait,
            1,
            UNARY_QUEUE_WAIT_CEILING,
        )?;
        check_range(
            "finite-stream-concurrency",
            self.finite_stream_concurrency,
            1,
            FINITE_STREAM_CONCURRENCY_CEILING,
        )?;
        check_range(
            "finite-stream-queue-depth",
            self.finite_stream_queue_depth,
            0,
            FINITE_STREAM_QUEUE_DEPTH_CEILING,
        )?;
        check_range(
            "reserved-operator-concurrency",
            self.reserved_operator_concurrency,
            RESERVED_OPERATOR_CONCURRENCY_FLOOR,
            RESERVED_OPERATOR_CONCURRENCY_CEILING,
        )?;
        check_range(
            "streams-global",
            self.streams_global,
            1,
            STREAMS_GLOBAL_CEILING,
        )?;
        Ok(())
    }
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self::compiled()
    }
}

/// A limit outside its compiled floor/ceiling range.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AdmissionLimitsError {
    /// The named limit is outside its compiled range.
    #[error("admission limit `{key}` is {value}, allowed range is {floor}..={ceiling}")]
    OutOfRange {
        /// Config-schema key of the limit (kebab case, `basil-62ji`).
        key: &'static str,
        /// The rejected value (milliseconds for duration limits).
        value: u128,
        /// Inclusive compiled floor.
        floor: u128,
        /// Inclusive compiled ceiling.
        ceiling: u128,
    },
}

const fn check_range(
    key: &'static str,
    value: usize,
    floor: usize,
    ceiling: usize,
) -> Result<(), AdmissionLimitsError> {
    if value < floor || value > ceiling {
        return Err(AdmissionLimitsError::OutOfRange {
            key,
            value: value as u128,
            floor: floor as u128,
            ceiling: ceiling as u128,
        });
    }
    Ok(())
}

const fn check_millis_range(
    key: &'static str,
    value: Duration,
    floor_millis: u128,
    ceiling: Duration,
) -> Result<(), AdmissionLimitsError> {
    let millis = value.as_millis();
    if millis < floor_millis || millis > ceiling.as_millis() {
        return Err(AdmissionLimitsError::OutOfRange {
            key,
            value: millis,
            floor: floor_millis,
            ceiling: ceiling.as_millis(),
        });
    }
    Ok(())
}

/// RAII admission permit for one admitted request.
///
/// Dispatch wiring must hold the permit for the full response lifetime —
/// through response-body completion or cancellation, not just handler return
/// (design §4.1) — and dropping it releases exactly the one lane slot that
/// was charged. Release is infallible and idempotent by construction.
#[must_use = "dropping the permit immediately releases the admitted capacity"]
#[derive(Debug)]
pub struct AdmissionPermit {
    _permit: OwnedSemaphorePermit,
    class: WorkClass,
}

impl AdmissionPermit {
    /// Work class whose lane this permit occupies.
    #[must_use]
    pub const fn class(&self) -> WorkClass {
        self.class
    }
}

/// Lane-level rejection cause, converted to a typed status by
/// [`AdmissionController::admit`].
enum LaneRejection {
    /// The lane is at its bound (cap, queue depth, or queue wait).
    Overloaded,
    /// The lane semaphore was closed — a broker defect, never reachable
    /// because admission never closes its lanes; kept typed so the no-panic
    /// rule holds even against future regressions.
    Closed,
}

impl From<AcquireError> for LaneRejection {
    fn from(_: AcquireError) -> Self {
        Self::Closed
    }
}

/// One concurrency-cap lane with a bounded FIFO wait queue.
struct QueueLane {
    permits: Arc<Semaphore>,
    queued: AtomicUsize,
    depth: usize,
    /// Compiled wait bound applied on top of the caller deadline; `None`
    /// bounds the wait by the caller deadline alone (class `F`).
    wait_bound: Option<Duration>,
}

impl QueueLane {
    fn new(concurrency: usize, depth: usize, wait_bound: Option<Duration>) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(concurrency.min(Semaphore::MAX_PERMITS))),
            queued: AtomicUsize::new(0),
            depth,
            wait_bound,
        }
    }

    async fn acquire(
        &self,
        caller_deadline: Option<Instant>,
    ) -> Result<OwnedSemaphorePermit, LaneRejection> {
        match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => return Ok(permit),
            Err(TryAcquireError::Closed) => return Err(LaneRejection::Closed),
            Err(TryAcquireError::NoPermits) => {}
        }
        let Some(_slot) = QueueSlot::reserve(&self.queued, self.depth) else {
            return Err(LaneRejection::Overloaded);
        };
        let wait_deadline = match (self.wait_bound, caller_deadline) {
            (None, None) => None,
            (None, Some(deadline)) => Some(deadline),
            (Some(bound), caller) => {
                // A failed `checked_add` means the bound is unreachable on
                // this clock; the caller deadline (if any) still applies.
                match (Instant::now().checked_add(bound), caller) {
                    (Some(bounded), Some(deadline)) => Some(bounded.min(deadline)),
                    (Some(bounded), None) => Some(bounded),
                    (None, caller) => caller,
                }
            }
        };
        let acquire = Arc::clone(&self.permits).acquire_owned();
        match wait_deadline {
            Some(deadline) => {
                // `timeout_at` polls the acquire future before the timer, so
                // a permit granted concurrently with expiry is observed as a
                // grant: every wait resolves to exactly one of admitted or
                // rejected (design §6.2). Dropping the unfinished acquire on
                // expiry hands any concurrently assigned permit to the next
                // waiter — nothing leaks.
                match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), acquire)
                    .await
                {
                    Ok(result) => result.map_err(LaneRejection::from),
                    Err(_expired) => Err(LaneRejection::Overloaded),
                }
            }
            None => acquire.await.map_err(LaneRejection::from),
        }
    }
}

/// Bounded-queue slot guard: reserved before waiting, always released.
struct QueueSlot<'lane> {
    queued: &'lane AtomicUsize,
}

impl<'lane> QueueSlot<'lane> {
    fn reserve(queued: &'lane AtomicUsize, depth: usize) -> Option<Self> {
        queued
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |occupied| {
                if occupied < depth {
                    occupied.checked_add(1)
                } else {
                    None
                }
            })
            .ok()
            .map(|_| Self { queued })
    }
}

impl Drop for QueueSlot<'_> {
    fn drop(&mut self) {
        self.queued.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One admit-or-reject lane with no queue (classes `O` and `L`).
struct DirectLane {
    permits: Arc<Semaphore>,
}

impl DirectLane {
    fn new(concurrency: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(concurrency.min(Semaphore::MAX_PERMITS))),
        }
    }

    fn acquire(&self) -> Result<OwnedSemaphorePermit, LaneRejection> {
        match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => Ok(permit),
            Err(TryAcquireError::NoPermits) => Err(LaneRejection::Overloaded),
            Err(TryAcquireError::Closed) => Err(LaneRejection::Closed),
        }
    }
}

/// Broker-wide pre-dispatch admission controller.
///
/// One controller instance covers every listener (listeners carry no
/// admission authority); all lanes are disjoint, so class `U`/`F`/`L` work
/// can never occupy a reserved class `O` slot and class `O` never borrows
/// from the general lanes. All accounting is checked or saturating and every
/// bound produces a typed rejection — the controller contains no panic path.
pub struct AdmissionController {
    limits: AdmissionLimits,
    unary: QueueLane,
    finite: QueueLane,
    operator: DirectLane,
    streams_global: DirectLane,
}

impl std::fmt::Debug for AdmissionController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmissionController")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl AdmissionController {
    /// Construct a controller with the compiled default limits.
    #[must_use]
    pub fn compiled() -> Self {
        Self::from_limits(AdmissionLimits::compiled())
    }

    /// Construct a controller with validated limits.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionLimitsError`] when any limit is outside its
    /// compiled floor/ceiling range; callers must fail closed.
    pub fn new(limits: AdmissionLimits) -> Result<Self, AdmissionLimitsError> {
        limits.validate()?;
        Ok(Self::from_limits(limits))
    }

    fn from_limits(limits: AdmissionLimits) -> Self {
        Self {
            limits,
            unary: QueueLane::new(
                limits.unary_concurrency,
                limits.unary_queue_depth,
                Some(limits.unary_queue_wait),
            ),
            finite: QueueLane::new(
                limits.finite_stream_concurrency,
                limits.finite_stream_queue_depth,
                None,
            ),
            operator: DirectLane::new(limits.reserved_operator_concurrency),
            streams_global: DirectLane::new(limits.streams_global),
        }
    }

    /// The limits this controller enforces.
    #[must_use]
    pub const fn limits(&self) -> &AdmissionLimits {
        &self.limits
    }

    /// Admit one classified request head, or reject it before dispatch.
    ///
    /// Resolves to exactly one of an RAII [`AdmissionPermit`] (dispatch may
    /// proceed) or a fully built rejection status (the request provably did
    /// not execute — the inner router must never be polled after a
    /// rejection). Queue waits are bounded by
    /// `min(caller_deadline, compiled wait bound)` for class `U` and by the
    /// caller deadline for class `F`; classes `O` and `L` never wait.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable`/`OVERLOADED` with jittered `RetryInfo` at any
    /// lane bound, or `Internal` on an admission accounting defect (a closed
    /// lane, which this module never produces).
    pub async fn admit(
        &self,
        method: &RpcMethod,
        caller_deadline: Option<Instant>,
    ) -> Result<AdmissionPermit, Status> {
        let class = method.class();
        let outcome = match class {
            WorkClass::Unary => self.unary.acquire(caller_deadline).await,
            WorkClass::FiniteStream => self.finite.acquire(caller_deadline).await,
            WorkClass::Operator => self.operator.acquire(),
            WorkClass::LongLivedStream => self.streams_global.acquire(),
        };
        match outcome {
            Ok(permit) => Ok(AdmissionPermit {
                _permit: permit,
                class,
            }),
            Err(LaneRejection::Overloaded) => Err(overloaded_status(method.overload_op())),
            Err(LaneRejection::Closed) => Err(closed_lane_status(method.overload_op())),
        }
    }
}

/// Build the pre-dispatch `OVERLOADED` rejection (private, condition C1).
///
/// `Unavailable` + `BrokerErrorInfo{reason: OVERLOADED, op}` + a
/// `google.rpc.RetryInfo` delay drawn uniformly from the compiled
/// `[250 ms, 1000 ms]` window — deliberately coarse and load-independent so
/// no saturation oracle leaks to untrusted callers (design §6.1).
fn overloaded_status(op: &str) -> Status {
    let millis = rand::Rng::gen_range(
        &mut rand::thread_rng(),
        OVERLOADED_RETRY_MIN_MILLIS..=OVERLOADED_RETRY_MAX_MILLIS,
    );
    let nanos = i32::try_from(millis % 1000)
        .unwrap_or(0)
        .saturating_mul(1_000_000);
    let retry = RetryInfoDetail {
        retry_delay: Some(prost_types::Duration {
            seconds: millis / 1000,
            nanos,
        }),
    };
    let detail = prost_types::Any {
        type_url: "type.googleapis.com/google.rpc.RetryInfo".to_string(),
        value: retry.encode_to_vec(),
    };
    super::broker_status_with_details(
        Code::Unavailable,
        OVERLOADED_REASON,
        op,
        "broker overloaded",
        vec![detail],
    )
}

/// Typed defect status for a closed lane (never reachable; no-panic rule).
fn closed_lane_status(op: &str) -> Status {
    super::broker_status_with_details(
        Code::Internal,
        "INTERNAL",
        op,
        "admission accounting unavailable",
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use basil_proto::broker::v1::BrokerErrorInfo;
    use basil_proto::google::rpc::Status as RpcStatus;
    use prost::Message as _;

    use super::super::rpc_registry::RpcMethodRegistry;
    use super::*;

    const SIGN: &str = "/basil.broker.v1.SigningService/Sign";
    const LIST_CATALOG: &str = "/basil.broker.v1.SecretService/ListCatalog";
    const STATUS: &str = "/basil.broker.v1.AdminService/Status";
    const WATCH: &str = "/basil.broker.v1.AdminService/Watch";

    fn registry() -> &'static RpcMethodRegistry {
        RpcMethodRegistry::shared().expect("compiled registry validates")
    }

    fn method(path: &str) -> RpcMethod {
        registry()
            .classify(path)
            .expect("path is classified")
            .clone()
    }

    fn tiny_limits() -> AdmissionLimits {
        AdmissionLimits {
            unary_concurrency: 1,
            unary_queue_depth: 1,
            unary_queue_wait: Duration::from_millis(50),
            finite_stream_concurrency: 1,
            finite_stream_queue_depth: 1,
            reserved_operator_concurrency: RESERVED_OPERATOR_CONCURRENCY_FLOOR,
            streams_global: 1,
        }
    }

    fn controller(limits: AdmissionLimits) -> AdmissionController {
        AdmissionController::new(limits).expect("test limits validate")
    }

    struct DecodedRejection {
        code: Code,
        info: BrokerErrorInfo,
        retry_delay: Option<Duration>,
    }

    fn decode_rejection(status: &Status) -> DecodedRejection {
        let rpc = RpcStatus::decode(status.details()).expect("google.rpc.Status decodes");
        let info_detail = &rpc.details[0];
        assert_eq!(
            info_detail.type_url,
            "type.googleapis.com/basil.broker.v1.BrokerErrorInfo"
        );
        let info = BrokerErrorInfo::decode(info_detail.value.as_slice()).expect("info decodes");
        let retry_delay = rpc.details.iter().find_map(|detail| {
            if detail.type_url != "type.googleapis.com/google.rpc.RetryInfo" {
                return None;
            }
            let retry =
                RetryInfoDetail::decode(detail.value.as_slice()).expect("retry info decodes");
            let delay = retry.retry_delay.expect("retry delay present");
            Some(
                Duration::from_secs(u64::try_from(delay.seconds).unwrap())
                    + Duration::from_nanos(u64::try_from(delay.nanos).unwrap()),
            )
        });
        DecodedRejection {
            code: status.code(),
            info,
            retry_delay,
        }
    }

    fn assert_overloaded(status: &Status, op: &str, expect_retry: bool) {
        let decoded = decode_rejection(status);
        assert_eq!(decoded.code, Code::Unavailable);
        assert_eq!(decoded.info.reason, "OVERLOADED");
        assert_eq!(decoded.info.op, op);
        assert_eq!(status.message(), "broker overloaded");
        if expect_retry {
            let delay = decoded.retry_delay.expect("OVERLOADED carries RetryInfo");
            assert!(delay >= Duration::from_millis(250), "delay {delay:?}");
            assert!(delay <= Duration::from_secs(1), "delay {delay:?}");
        }
    }

    /// The compiled defaults validate, match the design table, and the
    /// shared `basil-iht1` coupling constant is the exact ceiling sum.
    #[test]
    fn compiled_defaults_validate_and_match_the_design() {
        let limits = AdmissionLimits::compiled();
        limits.validate().expect("compiled defaults validate");
        assert_eq!(limits, AdmissionLimits::default());
        assert_eq!(limits.unary_concurrency, 256);
        assert_eq!(limits.unary_queue_depth, 128);
        assert_eq!(limits.unary_queue_wait, Duration::from_secs(1));
        assert_eq!(limits.finite_stream_concurrency, 32);
        assert_eq!(limits.finite_stream_queue_depth, 32);
        assert_eq!(limits.reserved_operator_concurrency, 16);
        assert_eq!(limits.streams_global, 2000);
        assert_eq!(
            COMPILED_ADMISSION_HEAD_BOUND,
            1024 + 512 + 128 + 128 + 64 + 4096
        );
        let compiled = AdmissionController::compiled();
        assert_eq!(compiled.limits(), &limits);
    }

    /// Out-of-range limits fail closed with the offending config key.
    #[test]
    fn out_of_range_limits_fail_closed() {
        let checks: [(AdmissionLimits, &str); 5] = [
            (
                AdmissionLimits {
                    unary_concurrency: 0,
                    ..AdmissionLimits::compiled()
                },
                "unary-concurrency",
            ),
            (
                AdmissionLimits {
                    unary_queue_wait: Duration::ZERO,
                    ..AdmissionLimits::compiled()
                },
                "unary-queue-wait-ms",
            ),
            (
                AdmissionLimits {
                    unary_queue_wait: Duration::from_secs(6),
                    ..AdmissionLimits::compiled()
                },
                "unary-queue-wait-ms",
            ),
            (
                AdmissionLimits {
                    reserved_operator_concurrency: RESERVED_OPERATOR_CONCURRENCY_FLOOR - 1,
                    ..AdmissionLimits::compiled()
                },
                "reserved-operator-concurrency",
            ),
            (
                AdmissionLimits {
                    streams_global: STREAMS_GLOBAL_CEILING + 1,
                    ..AdmissionLimits::compiled()
                },
                "streams-global",
            ),
        ];
        for (limits, expected_key) in checks {
            match AdmissionController::new(limits) {
                Err(AdmissionLimitsError::OutOfRange { key, .. }) => {
                    assert_eq!(key, expected_key);
                }
                Ok(_) => panic!("limits with bad `{expected_key}` must fail closed"),
            }
        }
    }

    /// C1: the quoted `OVERLOADED` literal exists nowhere in this crate's
    /// sources outside this module, so no service path can mint the
    /// outcome-safe rejection. (The compiler already keeps the constant and
    /// constructor private; this pins the literal itself.)
    #[test]
    fn overloaded_literal_is_private_to_this_module() {
        let needle = "\"OVERLOADED\"";
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources = vec![root];
        let mut spelled_in = Vec::new();
        while let Some(directory) = sources.pop() {
            for entry in std::fs::read_dir(&directory).expect("source directory reads") {
                let path = entry.expect("directory entry reads").path();
                if path.is_dir() {
                    sources.push(path);
                } else if path.extension().is_some_and(|extension| extension == "rs")
                    && std::fs::read_to_string(&path)
                        .expect("source file reads")
                        .contains(needle)
                {
                    spelled_in.push(path);
                }
            }
        }
        let expected =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/transport/admission.rs");
        assert_eq!(
            spelled_in,
            vec![expected],
            "the OVERLOADED literal must stay private to transport/admission.rs"
        );
    }

    /// Saturating class U rejects with `Unavailable`/`OVERLOADED`, the
    /// method's op token, and jittered `RetryInfo` inside the compiled
    /// window (varying across responses).
    #[tokio::test]
    async fn unary_saturation_rejects_overloaded_with_jittered_retry_info() {
        let admission = controller(AdmissionLimits {
            unary_queue_depth: 0,
            ..tiny_limits()
        });
        let sign = method(SIGN);
        let held = admission.admit(&sign, None).await.expect("first admits");
        assert_eq!(held.class(), WorkClass::Unary);
        let mut delays = Vec::new();
        for _ in 0..32 {
            let rejected = admission
                .admit(&sign, None)
                .await
                .expect_err("saturated lane rejects");
            assert_overloaded(&rejected, "sign", true);
            delays.push(decode_rejection(&rejected).retry_delay.unwrap());
        }
        assert!(
            delays.iter().any(|delay| delay != &delays[0]),
            "retry delays must jitter across responses"
        );
        drop(held);
        let readmitted = admission
            .admit(&sign, None)
            .await
            .expect("released slot readmits");
        drop(readmitted);
    }

    /// A queue waiter admits when capacity frees; above the queue depth the
    /// rejection is immediate.
    #[tokio::test]
    async fn queue_admits_on_release_and_bounds_depth() {
        let admission = Arc::new(controller(AdmissionLimits {
            unary_queue_wait: Duration::from_secs(2),
            ..tiny_limits()
        }));
        let sign = method(SIGN);
        let held = admission.admit(&sign, None).await.expect("first admits");
        let waiting = tokio::spawn({
            let admission = Arc::clone(&admission);
            let sign = sign.clone();
            async move { admission.admit(&sign, None).await }
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        // Queue depth 1 is occupied by the spawned waiter: the next request
        // is rejected immediately, well inside the 2 s wait bound.
        let started = Instant::now();
        let rejected = admission
            .admit(&sign, None)
            .await
            .expect_err("full queue rejects immediately");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_overloaded(&rejected, "sign", true);
        drop(held);
        let admitted = waiting
            .await
            .expect("waiter task joins")
            .expect("waiter admits");
        drop(admitted);
    }

    /// C4: a waiter whose compiled wait bound elapses is rejected
    /// `OVERLOADED` (never a deadline status), and the lane stays coherent.
    #[tokio::test]
    async fn expired_queue_wait_rejects_overloaded() {
        let admission = controller(tiny_limits());
        let sign = method(SIGN);
        let held = admission.admit(&sign, None).await.expect("first admits");
        let started = Instant::now();
        let rejected = admission
            .admit(&sign, None)
            .await
            .expect_err("expired wait rejects");
        assert!(started.elapsed() >= Duration::from_millis(45));
        assert_overloaded(&rejected, "sign", true);
        drop(held);
        let readmitted = admission.admit(&sign, None).await.expect("lane recovered");
        drop(readmitted);
    }

    /// C4: the caller deadline bounds the wait below the compiled bound and
    /// the rejection is still `OVERLOADED`.
    #[tokio::test]
    async fn caller_deadline_bounds_queue_wait() {
        let admission = controller(AdmissionLimits {
            unary_queue_wait: UNARY_QUEUE_WAIT_CEILING,
            ..tiny_limits()
        });
        let sign = method(SIGN);
        let held = admission.admit(&sign, None).await.expect("first admits");
        let started = Instant::now();
        let deadline = Instant::now() + Duration::from_millis(50);
        let rejected = admission
            .admit(&sign, Some(deadline))
            .await
            .expect_err("caller deadline expires the wait");
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(45), "elapsed {elapsed:?}");
        assert!(elapsed < Duration::from_secs(4), "elapsed {elapsed:?}");
        assert_overloaded(&rejected, "sign", true);
        drop(held);
    }

    /// C4 race: a permit released concurrently with waiter expiry resolves
    /// to exactly one outcome — admitted XOR rejected `OVERLOADED` — and the
    /// lane's capacity is fully restored either way (no leak, no double
    /// grant).
    #[tokio::test]
    async fn deadline_race_resolves_to_exactly_one_outcome() {
        let admission = Arc::new(controller(AdmissionLimits {
            unary_queue_wait: Duration::from_millis(20),
            unary_queue_depth: 4,
            ..tiny_limits()
        }));
        let sign = method(SIGN);
        let executed = AtomicUsize::new(0);
        let mut admitted = 0_usize;
        let mut rejected = 0_usize;
        for round in 0_u64..60 {
            let held = admission.admit(&sign, None).await.expect("holder admits");
            let releaser = tokio::spawn(async move {
                // Straddle the 20 ms waiter expiry from both sides.
                tokio::time::sleep(Duration::from_millis(17 + (round % 7))).await;
                drop(held);
            });
            match admission.admit(&sign, None).await {
                Ok(permit) => {
                    executed.fetch_add(1, Ordering::Relaxed);
                    admitted += 1;
                    drop(permit);
                }
                Err(status) => {
                    assert_overloaded(&status, "sign", true);
                    rejected += 1;
                }
            }
            releaser.await.expect("releaser joins");
            // Whatever the race outcome, exactly one full lane slot must be
            // available again: a rejected waiter's concurrently granted
            // permit is handed back, an admitted waiter's permit was
            // dropped.
            let probe = admission.admit(&sign, None).await.expect("lane restored");
            drop(probe);
        }
        assert_eq!(admitted + rejected, 60, "exactly one outcome per request");
        assert_eq!(
            executed.load(Ordering::Relaxed),
            admitted,
            "rejected requests never execute"
        );
        assert!(admitted > 0, "race straddle admitted at least once");
        assert!(rejected > 0, "race straddle rejected at least once");
    }

    /// Lanes are disjoint: with class U saturated, operator, finite-stream,
    /// and long-lived admissions still succeed; the reserved lane rejects
    /// immediately above its own cap and is never consumable by class U.
    #[tokio::test]
    async fn lanes_are_disjoint_and_operator_lane_is_reserved() {
        let admission = controller(AdmissionLimits {
            unary_queue_depth: 0,
            ..tiny_limits()
        });
        let unary_held = admission
            .admit(&method(SIGN), None)
            .await
            .expect("U admits");
        let rejected = admission
            .admit(&method(SIGN), None)
            .await
            .expect_err("U saturated");
        assert_overloaded(&rejected, "sign", true);

        let finite = admission
            .admit(&method(LIST_CATALOG), None)
            .await
            .expect("F lane is disjoint from U");
        assert_eq!(finite.class(), WorkClass::FiniteStream);

        let mut operator_permits = Vec::new();
        for _ in 0..RESERVED_OPERATOR_CONCURRENCY_FLOOR {
            operator_permits.push(
                admission
                    .admit(&method(STATUS), None)
                    .await
                    .expect("O lane is disjoint and reserved"),
            );
        }
        let started = Instant::now();
        let over_reserved = admission
            .admit(&method(STATUS), None)
            .await
            .expect_err("O lane rejects above its cap");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "O never queues"
        );
        assert_overloaded(&over_reserved, "status", true);

        // Releasing class U capacity never frees an O slot and vice versa.
        drop(unary_held);
        let still_over = admission
            .admit(&method(STATUS), None)
            .await
            .expect_err("U release frees no O slot");
        assert_overloaded(&still_over, "status", true);
        drop(operator_permits);
        drop(finite);
    }

    /// Class L admits or rejects against the global stream bound with no
    /// queue; releasing one stream re-admits exactly one.
    #[tokio::test]
    async fn long_lived_global_lane_is_admit_or_reject() {
        let admission = controller(tiny_limits());
        let watch = method(WATCH);
        let held = admission
            .admit(&watch, None)
            .await
            .expect("first stream admits");
        assert_eq!(held.class(), WorkClass::LongLivedStream);
        let started = Instant::now();
        let rejected = admission
            .admit(&watch, None)
            .await
            .expect_err("global bound rejects");
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "L never queues"
        );
        assert_overloaded(&rejected, "watch", true);
        drop(held);
        let readmitted = admission
            .admit(&watch, None)
            .await
            .expect("released stream re-admits");
        drop(readmitted);
    }

    /// Concurrency accounting under contention: admitted work equals
    /// executed work, rejected work never executes, and the totals cover
    /// every request (dispatched XOR rejected).
    #[tokio::test]
    async fn rejected_work_provably_did_not_execute() {
        let admission = Arc::new(controller(AdmissionLimits {
            unary_concurrency: 2,
            unary_queue_depth: 2,
            unary_queue_wait: Duration::from_millis(40),
            ..tiny_limits()
        }));
        let sign = method(SIGN);
        let executed = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..12 {
            let admission = Arc::clone(&admission);
            let executed = Arc::clone(&executed);
            let sign = sign.clone();
            tasks.push(tokio::spawn(async move {
                match admission.admit(&sign, None).await {
                    Ok(permit) => {
                        executed.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(120)).await;
                        drop(permit);
                        true
                    }
                    Err(status) => {
                        let decoded = decode_rejection(&status);
                        assert_eq!(decoded.info.reason, "OVERLOADED");
                        false
                    }
                }
            }));
        }
        let mut admitted = 0_usize;
        let mut rejected = 0_usize;
        for task in tasks {
            if task.await.expect("worker joins") {
                admitted += 1;
            } else {
                rejected += 1;
            }
        }
        assert_eq!(admitted + rejected, 12);
        assert_eq!(executed.load(Ordering::Relaxed), admitted);
        // Cap 2, queue depth 2, and every admitted hold (120 ms) outlasts
        // the 40 ms queue-wait bound: exactly the two fast-path requests
        // admit, both queue waiters expire `OVERLOADED`, and the remaining
        // eight reject immediately at the queue-depth bound.
        assert_eq!(admitted, 2);
        assert_eq!(rejected, 10);
    }
}
