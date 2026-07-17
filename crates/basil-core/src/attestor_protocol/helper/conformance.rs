// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Helper-side protocol conformance tests (SPEC conformance test 16).
//!
//! Covered here: malformed/oversized records, missing/surplus/wrong-type
//! descriptors, ancillary truncation, stale/uninstalled policy generations,
//! wrong realm, unit disagreement, wrong peer UID, confinement mismatch, PID
//! reuse (start-time sandwich), helper outage/restart, generation overlap on
//! one endpoint, and exact pidfd/executable/cookie association. Broker-side
//! items (substituted cookies checked against the broker's own socket,
//! replayed-nonce tracking, release admission) belong to `basil-nxw5`.

use std::collections::VecDeque;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Mutex;

use rustix::net::sockopt;
use rustix::net::{AddressFamily, SocketFlags, SocketType};

use super::allowlist::{InstalledAllowlist, RealmExpectation};
use super::service::{
    ConfinementFacts, ExecutableError, ExecutableOpener, HelperOutcome, HelperService,
    InspectError, PeerPidfdError, PeerPidfdSource, ProcessIdentity, ProcessInspector, ResolvedUnit,
    UnitResolveError, UnitResolver, serve_connection,
};
use super::transport::{HelperConnection, ReceivedDatagram};
use super::wire::{
    HELPER_PROTOCOL_VERSION, HelperResponse, MAX_REQUEST_BYTES, MeasurementRequest, NONCE_BYTES,
    RejectCode,
};

const REALM: &str = "production-docker";
const POLICY: &str = "basil-measure-policy-g1";
const UNIT: &str = "basil-attestor-production-docker-g1.service";
const LSM: &str = "selinux:basil_attestor_g1_t";
const LOCKDOWN: &str = "basil-attestor-lockdown-g1";

fn own_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

fn own_gid() -> u32 {
    rustix::process::getgid().as_raw()
}

fn expectation() -> RealmExpectation {
    RealmExpectation {
        authority_generation: NonZeroU64::MIN,
        service_unit: UNIT.to_owned(),
        attestor_uid: own_uid(),
        lsm_profile: LSM.to_owned(),
        lockdown_profile: LOCKDOWN.to_owned(),
    }
}

fn allowlist() -> InstalledAllowlist {
    InstalledAllowlist::from_parts(vec![(
        POLICY.to_owned(),
        NonZeroU64::MIN,
        vec![(REALM.to_owned(), expectation())],
    )])
}

fn request() -> MeasurementRequest {
    MeasurementRequest {
        protocol: HELPER_PROTOCOL_VERSION,
        broker_generation: 7,
        policy_generation: NonZeroU64::MIN,
        nonce: [3u8; NONCE_BYTES],
        realm: REALM.to_owned(),
        policy_identity: POLICY.to_owned(),
    }
}

struct FakePeerSource {
    result: Option<PeerPidfdError>,
}

impl FakePeerSource {
    const fn ok() -> Self {
        Self { result: None }
    }
}

impl PeerPidfdSource for FakePeerSource {
    fn peer_pidfd(&self, _stream: BorrowedFd<'_>) -> Result<OwnedFd, PeerPidfdError> {
        self.result.map_or_else(
            || {
                rustix::process::pidfd_open(
                    rustix::process::getpid(),
                    rustix::process::PidfdFlags::empty(),
                )
                .map_err(|_| PeerPidfdError::Io)
            },
            Err,
        )
    }
}

struct FakeUnitResolver {
    result: Result<String, UnitResolveError>,
}

impl UnitResolver for FakeUnitResolver {
    fn unit_by_pidfd(&self, _pidfd: BorrowedFd<'_>) -> Result<ResolvedUnit, UnitResolveError> {
        self.result
            .as_ref()
            .map(|unit| ResolvedUnit { unit: unit.clone() })
            .map_err(|error| *error)
    }
}

struct FakeInspector {
    identities: Mutex<VecDeque<Result<ProcessIdentity, InspectError>>>,
    confinement: Result<ConfinementFacts, InspectError>,
}

impl FakeInspector {
    fn steady() -> Self {
        let identity = ProcessIdentity {
            uid: own_uid(),
            gid: own_gid(),
            start_time_ticks: 1000,
        };
        Self {
            identities: Mutex::new(VecDeque::from(vec![Ok(identity); 8])),
            confinement: Ok(ConfinementFacts {
                lsm_profile: LSM.to_owned(),
                lockdown_profile: LOCKDOWN.to_owned(),
            }),
        }
    }

    fn with_identity_sequence(sequence: Vec<Result<ProcessIdentity, InspectError>>) -> Self {
        Self {
            identities: Mutex::new(sequence.into()),
            ..Self::steady()
        }
    }
}

impl ProcessInspector for FakeInspector {
    fn identity(&self, _pid: u32, _pidfd: BorrowedFd<'_>) -> Result<ProcessIdentity, InspectError> {
        self.identities
            .lock()
            .map_err(|_| InspectError::Io)?
            .pop_front()
            .unwrap_or(Err(InspectError::PeerVanished))
    }

    fn confinement(
        &self,
        _pid: u32,
        _pidfd: BorrowedFd<'_>,
    ) -> Result<ConfinementFacts, InspectError> {
        self.confinement.clone()
    }
}

struct FakeExecutableOpener {
    result: Option<ExecutableError>,
}

impl FakeExecutableOpener {
    const fn ok() -> Self {
        Self { result: None }
    }
}

impl ExecutableOpener for FakeExecutableOpener {
    fn open_executable(
        &self,
        _pid: u32,
        _pidfd: BorrowedFd<'_>,
    ) -> Result<OwnedFd, ExecutableError> {
        self.result.map_or_else(
            || {
                rustix::fs::open(
                    "/proc/self/exe",
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|_| ExecutableError::Io)
            },
            Err,
        )
    }
}

type Service = HelperService<FakePeerSource, FakeUnitResolver, FakeInspector, FakeExecutableOpener>;

fn service() -> Service {
    service_with(allowlist(), FakeInspector::steady())
}

fn service_with(allowlist: InstalledAllowlist, inspector: FakeInspector) -> Service {
    HelperService::new(
        allowlist,
        FakePeerSource::ok(),
        FakeUnitResolver {
            result: Ok(UNIT.to_owned()),
        },
        inspector,
        FakeExecutableOpener::ok(),
    )
}

fn stream_pair() -> (OwnedFd, OwnedFd) {
    rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("stream socketpair")
}

fn dup_fd(fd: BorrowedFd<'_>) -> OwnedFd {
    fd.try_clone_to_owned().expect("dup")
}

fn datagram(bytes: Vec<u8>, descriptors: Vec<OwnedFd>) -> ReceivedDatagram {
    ReceivedDatagram {
        bytes,
        descriptors,
        oversized: false,
        ancillary_truncated: false,
    }
}

fn valid_datagram(stream: BorrowedFd<'_>) -> ReceivedDatagram {
    datagram(request().encode().expect("encode"), vec![dup_fd(stream)])
}

fn expect_reject(outcome: &HelperOutcome, code: RejectCode) {
    match outcome {
        HelperOutcome::Rejected(rejection) => assert_eq!(rejection.code, code),
        HelperOutcome::Measured { .. } => panic!("expected rejection {code:?}"),
    }
}

#[test]
fn measures_a_valid_request_and_binds_the_cookie() {
    let (broker_end, _attestor_end) = stream_pair();
    let outcome = service().handle(valid_datagram(broker_end.as_fd()));
    match outcome {
        HelperOutcome::Measured {
            record,
            pidfd,
            executable,
        } => {
            // The record is bound to the duplicated stream's own cookie.
            let cookie = sockopt::socket_cookie(broker_end.as_fd()).expect("cookie");
            assert_eq!(record.cookie, cookie);
            assert_eq!(record.peer_uid, own_uid());
            assert_eq!(record.peer_pid, std::process::id());
            assert_eq!(record.realm, REALM);
            assert_eq!(record.policy_identity, POLICY);
            assert_eq!(record.policy_generation, NonZeroU64::MIN);
            assert_eq!(record.service_unit, UNIT);
            assert_eq!(record.nonce, [3u8; NONCE_BYTES]);
            assert_eq!(record.broker_generation, 7);
            // Exact descriptor association: the pidfd names this process and
            // the executable descriptor is a regular file whose identity is
            // in the record.
            let stat = rustix::fs::fstat(&executable).expect("fstat");
            assert_eq!(stat.st_ino, record.executable_inode);
            assert_eq!(
                rustix::fs::FileType::from_raw_mode(stat.st_mode),
                rustix::fs::FileType::RegularFile
            );
            drop(pidfd);
        }
        HelperOutcome::Rejected(rejection) => {
            panic!("expected measurement, got {:?}", rejection.code)
        }
    }
}

#[test]
fn rejects_malformed_and_oversized_records() {
    let (broker_end, _attestor_end) = stream_pair();
    // Garbage bytes.
    let outcome = service().handle(datagram(vec![0u8; 16], vec![dup_fd(broker_end.as_fd())]));
    expect_reject(&outcome, RejectCode::MalformedRequest);
    // Truncated valid prefix.
    let mut short = request().encode().expect("encode");
    short.truncate(short.len() - 1);
    let outcome = service().handle(datagram(short, vec![dup_fd(broker_end.as_fd())]));
    expect_reject(&outcome, RejectCode::MalformedRequest);
    // Kernel-flagged oversize.
    let mut oversized = datagram(
        request().encode().expect("encode"),
        vec![dup_fd(broker_end.as_fd())],
    );
    oversized.oversized = true;
    expect_reject(&service().handle(oversized), RejectCode::MalformedRequest);
}

#[test]
fn rejects_an_unsupported_protocol_version() {
    let (broker_end, _attestor_end) = stream_pair();
    let mut bytes = request().encode().expect("encode");
    // The protocol field occupies bytes 4..8.
    if let Some(byte) = bytes.get_mut(7) {
        *byte = 2;
    }
    let outcome = service().handle(datagram(bytes, vec![dup_fd(broker_end.as_fd())]));
    expect_reject(&outcome, RejectCode::UnsupportedProtocol);
}

#[test]
fn rejects_descriptor_count_violations() {
    let (broker_end, _attestor_end) = stream_pair();
    // Missing descriptor.
    let outcome = service().handle(datagram(request().encode().expect("encode"), vec![]));
    expect_reject(&outcome, RejectCode::DescriptorMissing);
    // Surplus descriptors.
    let outcome = service().handle(datagram(
        request().encode().expect("encode"),
        vec![dup_fd(broker_end.as_fd()), dup_fd(broker_end.as_fd())],
    ));
    expect_reject(&outcome, RejectCode::DescriptorSurplus);
}

#[test]
fn rejects_wrong_type_descriptors() {
    // A datagram socket is not a stream.
    let (dgram, _peer) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .expect("dgram socketpair");
    let outcome = service().handle(datagram(
        request().encode().expect("encode"),
        vec![dup_fd(dgram.as_fd())],
    ));
    expect_reject(&outcome, RejectCode::DescriptorType);

    // A regular file is not a socket at all.
    let file = rustix::fs::open(
        "/proc/self/exe",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .expect("open file");
    let outcome = service().handle(datagram(request().encode().expect("encode"), vec![file]));
    expect_reject(&outcome, RejectCode::DescriptorType);
}

#[test]
fn rejects_kernel_ancillary_truncation() {
    let (broker_end, _attestor_end) = stream_pair();
    let mut truncated = valid_datagram(broker_end.as_fd());
    truncated.ancillary_truncated = true;
    expect_reject(&service().handle(truncated), RejectCode::AncillaryTruncated);
}

#[test]
fn rejects_stale_or_uninstalled_generations_and_realms() {
    let (broker_end, _attestor_end) = stream_pair();
    // A generation that was never installed for this identity.
    let mut stale = request();
    stale.policy_generation = NonZeroU64::new(9).expect("nonzero");
    let outcome = service().handle(datagram(
        stale.encode().expect("encode"),
        vec![dup_fd(broker_end.as_fd())],
    ));
    expect_reject(&outcome, RejectCode::PolicyNotInstalled);
    // An identity that was never installed.
    let mut unknown = request();
    unknown.policy_identity = "basil-measure-policy-g9".to_owned();
    unknown.policy_generation = NonZeroU64::new(9).expect("nonzero");
    let outcome = service().handle(datagram(
        unknown.encode().expect("encode"),
        vec![dup_fd(broker_end.as_fd())],
    ));
    expect_reject(&outcome, RejectCode::PolicyNotInstalled);
    // A realm absent from the installed generation.
    let mut wrong_realm = request();
    wrong_realm.realm = "other-realm".to_owned();
    let outcome = service().handle(datagram(
        wrong_realm.encode().expect("encode"),
        vec![dup_fd(broker_end.as_fd())],
    ));
    expect_reject(&outcome, RejectCode::RealmNotInstalled);
}

#[test]
fn one_endpoint_serves_overlapping_generations() {
    // Old and candidate helper-policy generations are both installed; the
    // request-named generation selects the expectations to apply.
    let two = NonZeroU64::new(2).expect("nonzero");
    let old_unit = UNIT;
    let new_unit = "basil-attestor-production-docker-g2.service";
    // The candidate expectation changes only its unit here so the fake
    // inspector's steady confinement stays valid: the disagreement under
    // test is the unit binding, not confinement.
    let mut new_expectation = expectation();
    new_expectation.authority_generation = two;
    new_expectation.service_unit = new_unit.to_owned();
    let overlap = InstalledAllowlist::from_parts(vec![
        (
            POLICY.to_owned(),
            NonZeroU64::MIN,
            vec![(REALM.to_owned(), expectation())],
        ),
        (
            "basil-measure-policy-g2".to_owned(),
            two,
            vec![(REALM.to_owned(), new_expectation)],
        ),
    ]);

    // The old-generation session measures under the old expectations.
    let (broker_end, _attestor_end) = stream_pair();
    let old_service = service_with(overlap, FakeInspector::steady());
    let outcome = old_service.handle(valid_datagram(broker_end.as_fd()));
    match outcome {
        HelperOutcome::Measured { record, .. } => assert_eq!(record.service_unit, old_unit),
        HelperOutcome::Rejected(rejection) => panic!("old generation: {:?}", rejection.code),
    }

    // A candidate qualifier names generation 2; the resolved unit must match
    // the *new* expectation, so a resolver still reporting the old unit is a
    // unit disagreement.
    let mut candidate = request();
    candidate.policy_identity = "basil-measure-policy-g2".to_owned();
    candidate.policy_generation = two;
    let outcome = old_service.handle(datagram(
        candidate.encode().expect("encode"),
        vec![dup_fd(broker_end.as_fd())],
    ));
    expect_reject(&outcome, RejectCode::UnitMismatch);
}

#[test]
fn rejects_unit_disagreement_and_resolution_outage() {
    let (broker_end, _attestor_end) = stream_pair();
    let disagreeing = HelperService::new(
        allowlist(),
        FakePeerSource::ok(),
        FakeUnitResolver {
            result: Ok("basil-attestor-other-g1.service".to_owned()),
        },
        FakeInspector::steady(),
        FakeExecutableOpener::ok(),
    );
    expect_reject(
        &disagreeing.handle(valid_datagram(broker_end.as_fd())),
        RejectCode::UnitMismatch,
    );

    let unavailable = HelperService::new(
        allowlist(),
        FakePeerSource::ok(),
        FakeUnitResolver {
            result: Err(UnitResolveError::Unavailable),
        },
        FakeInspector::steady(),
        FakeExecutableOpener::ok(),
    );
    expect_reject(
        &unavailable.handle(valid_datagram(broker_end.as_fd())),
        RejectCode::UnitResolutionFailed,
    );
}

#[test]
fn rejects_a_wrong_peer_uid() {
    let (broker_end, _attestor_end) = stream_pair();
    let mut foreign = expectation();
    foreign.attestor_uid = own_uid().wrapping_add(1);
    let wrong_uid = InstalledAllowlist::from_parts(vec![(
        POLICY.to_owned(),
        NonZeroU64::MIN,
        vec![(REALM.to_owned(), foreign)],
    )]);
    expect_reject(
        &service_with(wrong_uid, FakeInspector::steady())
            .handle(valid_datagram(broker_end.as_fd())),
        RejectCode::PeerIdentityMismatch,
    );
}

#[test]
fn rejects_confinement_mismatch() {
    let (broker_end, _attestor_end) = stream_pair();
    let inspector = FakeInspector {
        confinement: Ok(ConfinementFacts {
            lsm_profile: "selinux:unconfined_t".to_owned(),
            lockdown_profile: LOCKDOWN.to_owned(),
        }),
        ..FakeInspector::steady()
    };
    expect_reject(
        &service_with(allowlist(), inspector).handle(valid_datagram(broker_end.as_fd())),
        RejectCode::ConfinementMismatch,
    );
}

#[test]
fn rejects_pid_reuse_via_the_start_time_sandwich() {
    let (broker_end, _attestor_end) = stream_pair();
    let steady = ProcessIdentity {
        uid: own_uid(),
        gid: own_gid(),
        start_time_ticks: 1000,
    };
    let reused = ProcessIdentity {
        start_time_ticks: 2000,
        ..steady
    };
    let inspector = FakeInspector::with_identity_sequence(vec![Ok(steady), Ok(reused)]);
    expect_reject(
        &service_with(allowlist(), inspector).handle(valid_datagram(broker_end.as_fd())),
        RejectCode::PeerExited,
    );
}

#[test]
fn rejects_a_peer_that_exits_during_measurement() {
    let (broker_end, _attestor_end) = stream_pair();
    let steady = ProcessIdentity {
        uid: own_uid(),
        gid: own_gid(),
        start_time_ticks: 1000,
    };
    let inspector =
        FakeInspector::with_identity_sequence(vec![Ok(steady), Err(InspectError::PeerVanished)]);
    expect_reject(
        &service_with(allowlist(), inspector).handle(valid_datagram(broker_end.as_fd())),
        RejectCode::PeerExited,
    );
}

#[test]
fn rejects_when_peer_pidfd_acquisition_is_unsupported() {
    let (broker_end, _attestor_end) = stream_pair();
    let unsupported = HelperService::new(
        allowlist(),
        FakePeerSource {
            result: Some(PeerPidfdError::Unsupported),
        },
        FakeUnitResolver {
            result: Ok(UNIT.to_owned()),
        },
        FakeInspector::steady(),
        FakeExecutableOpener::ok(),
    );
    expect_reject(
        &unsupported.handle(valid_datagram(broker_end.as_fd())),
        RejectCode::PeerDerivationFailed,
    );
}

#[test]
fn serves_serially_and_survives_rejections_on_one_connection() {
    let (client, server) = HelperConnection::pair().expect("pair");
    let worker = std::thread::spawn(move || {
        let service = service();
        serve_connection(&server, &service)
    });

    // First: a malformed request is answered with a typed rejection.
    client.send(b"garbage", &[]).expect("send garbage");
    let response = client
        .recv_response()
        .expect("recv")
        .expect("rejection datagram");
    match HelperResponse::decode(&response.bytes).expect("decode") {
        HelperResponse::Rejected(rejection) => {
            assert_eq!(rejection.code, RejectCode::MalformedRequest);
        }
        HelperResponse::Measured(_) => panic!("expected rejection"),
    }

    // Then: a valid request on the same connection is measured, carrying
    // exactly the pidfd and executable descriptors.
    let (broker_end, _attestor_end) = stream_pair();
    client
        .send(&request().encode().expect("encode"), &[broker_end.as_fd()])
        .expect("send request");
    let response = client
        .recv_response()
        .expect("recv")
        .expect("measured datagram");
    assert_eq!(response.descriptors.len(), 2);
    match HelperResponse::decode(&response.bytes).expect("decode") {
        HelperResponse::Measured(record) => {
            let cookie = sockopt::socket_cookie(broker_end.as_fd()).expect("cookie");
            assert_eq!(record.cookie, cookie);
        }
        HelperResponse::Rejected(rejection) => {
            panic!("expected measurement, got {:?}", rejection.code)
        }
    }

    // Outage: closing the client ends the serve loop cleanly (restart is
    // covered by the transport bind/rebind test).
    drop(client);
    worker.join().expect("join").expect("serve");
}

#[test]
fn oversized_wire_datagrams_reject_before_decoding() {
    let (client, server) = HelperConnection::pair().expect("pair");
    let worker = std::thread::spawn(move || {
        let service = service();
        serve_connection(&server, &service)
    });
    let big = vec![0x42u8; MAX_REQUEST_BYTES + 64];
    client.send(&big, &[]).expect("send oversized");
    let response = client
        .recv_response()
        .expect("recv")
        .expect("rejection datagram");
    match HelperResponse::decode(&response.bytes).expect("decode") {
        HelperResponse::Rejected(rejection) => {
            assert_eq!(rejection.code, RejectCode::MalformedRequest);
        }
        HelperResponse::Measured(_) => panic!("expected rejection"),
    }
    drop(client);
    worker.join().expect("join").expect("serve");
}
