// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `basil-core` library: broker core, service adapters, and transport wiring.
//!
//! - [`core::catalog`] is the key inventory + authorization policy loaded at
//!   startup.
//! - [`core::state`] bundles the loaded policy + backend manager shared across
//!   tonic services.
//! - [`service`] contains tonic service adapters.
//! - [`transport`] owns tonic wiring, peer extraction, and authorization helpers.

// Index/slice in test code is fine (fixed test fixtures); the no-panic
// `indexing_slicing` gate has no test-allow config option, unlike unwrap/expect.
#![cfg_attr(test, allow(clippy::indexing_slicing))]

#[cfg(all(
    feature = "keystore-backend",
    not(any(feature = "db-keystore", feature = "onepassword"))
))]
compile_error!("feature `keystore-backend` requires feature `db-keystore`, `onepassword`, or both");

/// Default Unix socket path used by the daemon and local client tooling.
pub const DEFAULT_SOCKET_PATH: &str = "/tmp/basil-agent.sock";

/// Ensure a process-wide default rustls [`CryptoProvider`](rustls::crypto::CryptoProvider)
/// is installed before any `reqwest` client is built.
///
/// `reqwest` is compiled with the `rustls-no-provider` feature (its `rustls`
/// feature would pull in the `aws-lc-rs` C toolchain, which is forbidden here),
/// so building a client panics unless a default provider is already installed.
/// This daemon must never panic, so we install the pure-Rust `ring` provider
/// (the same one used for the JWKS server and gRPC transport) exactly once. A
/// prior install by an embedder is fine and left untouched (the returned `Err`
/// only signals that a provider was already set).
pub(crate) fn ensure_crypto_provider() {
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub mod agent_cli;
pub mod bundle_cli;
pub mod core;
pub mod doctor;
pub mod init;
pub mod service;
pub mod transport;
pub mod unlock;

#[cfg(feature = "tpm2")]
pub use core::identity;
pub use core::ml_dsa_sign;
pub use core::{
    actor, audit, backend, capability, catalog, decision, ed25519_sign, event, manager, minter,
    ml_kem_envelope, peer, reconcile, reload, revocation, seal, state, x25519_seal,
};
pub use service::broker as grpc;
#[cfg(feature = "http")]
pub use service::jwks;
pub use service::sds;
pub use service::spiffe;
pub use transport::grpc_server;

pub use audit::{AuditLog, ReloadActor};
#[cfg(feature = "keystore-backend")]
pub use backend::keystore::KeystoreBackend;
pub use backend::spiffe::{SpiffeConfig, SpiffeVaultBackend};
pub use backend::vault::VaultBackend;
pub use backend::{Backend, BackendError, NewKey};
pub use capability::{
    CapabilityError, CapabilityGap, CapabilityPolicy, CapabilitySummary, enforce_capabilities,
};
pub use catalog::{
    BackendKind, Capability, Catalog, Config, LoadError, LoadWarning, MissingPolicy,
    ResolvedPolicy, load,
};
pub use decision::{DecisionRecord, Outcome};
pub use event::{BrokerEvent, BrokerEventKind, EventSource};
pub use grpc_server::{DEFAULT_SOCKET_MODE, ServerConfig, run as run_grpc};
pub use manager::{BackendManager, ManagerError};
pub use peer::PeerInfo;
pub use reconcile::{CheckReport, KeyCheck, KeyStatus, ReconcileError, ReconcileSummary};
pub use reload::{ReloadError, ReloadInputs, ReloadOutcome, check_reload, reload_generation};
pub use revocation::JwtRevocationStore;
pub use seal::{
    BackendCred, CredBundle, MasterKek, MethodKind, MethodRegistry, ParsedBundle, SealError,
    SlotSpec, UnlockError, UnlockMethod,
};
pub use state::{
    BrokerLimits, BrokerState, DEFAULT_MAX_ENCRYPT_SIZE, DEFAULT_MAX_PAYLOAD_SIZE,
    DEFAULT_ROTATION_GRACE_VERSIONS, DEFAULT_SVID_TTL_SECS, Generation, INITIAL_GENERATION_ID,
};
