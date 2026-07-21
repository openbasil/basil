// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Measurement-helper protocol and service (Design 0001 revision 1.2).
//!
//! One root-owned, capability-minimized measurement helper runs per host on a
//! single shared, non-generation-qualified `SOCK_SEQPACKET` endpoint. The
//! broker sends one bounded request datagram (at most
//! [`wire::MAX_REQUEST_BYTES`] bytes) carrying exactly one `SCM_RIGHTS`
//! duplicate of an already-connected attestor control stream. The request
//! never carries a PID, path, digest, unit, or UID: every expectation the
//! helper applies comes from its own root-owned installed allowlist generation
//! selected by the request-named `(realm, helper-policy generation)` pair.
//!
//! The helper derives `SO_PEERCRED` and `SO_COOKIE` from the duplicated
//! stream itself, acquires the peer pidfd, resolves the peer's systemd unit
//! (`GetUnitByPIDFD`), checks the exact expected service unit, LSM, and
//! lockdown identities, opens the peer's current executable under its sole
//! `CAP_SYS_PTRACE` authority, and answers with one bounded record (at most
//! [`wire::MAX_RESPONSE_BYTES`] bytes) bound to the stream's socket cookie
//! plus exactly two descriptors: the peer pidfd and the executable.
//!
//! The helper holds no runtime API, key, or policy-decision authority; a
//! helper outage fails only realms that need a new measurement. Host
//! integration points are dependency-injected behind traits in [`service`]
//! with production implementations in [`host`]: peer-pidfd acquisition is
//! real (`SO_PEERPIDFD` via [`peer_pidfd`], kernel 6.5+, fail-closed
//! below), while the systemd D-Bus `GetUnitByPIDFD` transport remains a
//! fail-closed placeholder pending `basil-vww7`.

pub mod allowlist;
pub mod host;
pub mod peer_pidfd;
pub mod service;
pub mod transport;
pub mod wire;

pub(crate) mod ident;

#[cfg(test)]
mod conformance;

/// Serializes tests that `fork`+`exec` a child against tests that assert a
/// closed listener refuses connections: between `fork` and `exec` the child
/// holds a copy of every parent descriptor (`CLOEXEC` closes only at
/// `exec`), so a concurrently dropped listener can appear still-bound.
#[cfg(test)]
pub(crate) static CHILD_SPAWN_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub use allowlist::{
    AllowlistError, AllowlistLoadOptions, AllowlistLookupError, InstalledAllowlist,
    RealmExpectation,
};
pub use service::{
    ConfinementFacts, ExecutableError, ExecutableOpener, HelperOutcome, HelperService,
    InspectError, PeerPidfdError, PeerPidfdSource, ProcessIdentity, ProcessInspector, ResolvedUnit,
    UnitResolveError, UnitResolver, serve_connection,
};
pub use transport::{
    HelperConnection, HelperEndpointOptions, HelperListener, ReceivedDatagram, TransportError,
};
pub use wire::{
    HELPER_PROTOCOL_VERSION, HelperResponse, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MeasuredRecord,
    MeasurementRequest, NONCE_BYTES, RejectCode, RejectionRecord, WireError,
};
