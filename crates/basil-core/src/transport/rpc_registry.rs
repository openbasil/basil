// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Compiled per-method RPC registry: exhaustive admission work-class
//! classification (`basil-rslz` wave, ticket `basil-k4qt`).
//!
//! Every gRPC method compiled into a Basil listener is assigned exactly one
//! admission work class in a source-code lookup table, per the admission
//! design (rev 1.1). The registry is keyed by the generated service and
//! method names decoded from [`basil_proto::FILE_DESCRIPTOR_SET`] — the same
//! descriptor input tonic generated its routing from — so no request path is
//! ever hand-typed and a classification miss provably implies a routing miss:
//! a path absent from this registry is also absent from tonic's compiled
//! routing surface and falls through to `Unimplemented` handling.
//!
//! [`RpcMethodRegistry::compiled`] fails closed when the classification table
//! and the compiled descriptor disagree in either direction (an unclassified
//! compiled method, a table entry naming no compiled method, a duplicate, or
//! a class whose streaming shape contradicts the descriptor). The exhaustive
//! test below runs that validation over every compiled service method and
//! fails whenever a new RPC lands unclassified.
//!
//! This module carries classification only. Admission mechanics (lanes,
//! queues, `OVERLOADED` emission) build on it separately (`basil-cx25`).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use prost::Message as _;
use prost_types::{FileDescriptorSet, MethodDescriptorProto};
use thiserror::Error;

/// Admission work class of one compiled RPC method (admission design §3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkClass {
    /// `U` — unary request/response bounded by the request deadline.
    Unary,
    /// `F` — server streaming that terminates on its own under a recorded
    /// generation and deadline.
    FiniteStream,
    /// `L` — long-lived stream with no self-termination contract, registered
    /// to its owning connection.
    LongLivedStream,
    /// `O` — operator/recovery reserved lane (a compiled subset of unary
    /// methods; never caller-selectable).
    Operator,
}

/// Stream-limit rejection reason for class `L` methods (admission design §5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamLimitReason {
    /// `WATCH_LIMIT` — Admin `Watch` only.
    WatchLimit,
    /// `STREAM_LIMIT` — every other long-lived stream.
    StreamLimit,
}

impl StreamLimitReason {
    /// Stable `BrokerErrorInfo` reason token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::WatchLimit => "WATCH_LIMIT",
            Self::StreamLimit => "STREAM_LIMIT",
        }
    }
}

/// Unknown-outcome replay class of one method (admission design §8.2).
///
/// Applies when a call fails with an unknown outcome (transport reset,
/// `DeadlineExceeded`, bare `Unavailable` without a typed reason).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayClass {
    /// Outcome-safe to re-run under the caller's deadline: read-only unary
    /// methods, and streams (a stream is re-established under its own
    /// contract rather than replayed).
    OutcomeSafe,
    /// Never replayed automatically: the operation may have executed. Every
    /// method without an explicit read-only contract classifies here,
    /// fail-closed.
    NoAutomaticReplay,
}

/// One compiled, classified RPC method.
#[derive(Clone, Debug)]
pub struct RpcMethod {
    path: Box<str>,
    service: Box<str>,
    method: Box<str>,
    class: WorkClass,
    overload_op: Box<str>,
    stream_limit_reason: Option<StreamLimitReason>,
    replay: ReplayClass,
}

impl RpcMethod {
    /// Full request path (`/package.Service/Method`), derived from the
    /// compiled descriptor — never hand-typed.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Fully qualified service name from the compiled descriptor.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Method name from the compiled descriptor.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Admission work class.
    #[must_use]
    pub const fn class(&self) -> WorkClass {
        self.class
    }

    /// Stable op token for pre-dispatch `OVERLOADED` statuses
    /// (`BrokerErrorInfo.op`).
    ///
    /// Derived deterministically from the frozen generated method name
    /// (`GetPublicKey` → `get_public_key`), matching the existing policy op
    /// vocabulary where the two overlap.
    #[must_use]
    pub fn overload_op(&self) -> &str {
        &self.overload_op
    }

    /// Stream-limit rejection reason; present exactly for class `L` methods.
    #[must_use]
    pub const fn stream_limit_reason(&self) -> Option<StreamLimitReason> {
        self.stream_limit_reason
    }

    /// Unknown-outcome replay class.
    #[must_use]
    pub const fn replay(&self) -> ReplayClass {
        self.replay
    }
}

/// Classification-table/descriptor reconciliation failure.
///
/// Any variant is a compile-in defect: the broker must fail startup rather
/// than serve with an admission surface that disagrees with its routing
/// surface.
#[derive(Debug, Error)]
pub enum RpcRegistryError {
    /// The embedded descriptor bytes did not decode.
    #[error("compiled file descriptor set did not decode: {0}")]
    Decode(#[from] prost::DecodeError),
    /// A compiled service method has no classification entry.
    #[error("compiled RPC method `{path}` has no work-class classification")]
    Unclassified {
        /// Descriptor-derived request path of the unclassified method.
        path: String,
    },
    /// A classification entry names no compiled service method.
    #[error("classification entry `{service}/{method}` matches no compiled RPC method")]
    UnknownEntry {
        /// Service full name as written in the table.
        service: String,
        /// Method name as written in the table.
        method: String,
    },
    /// Two classification entries name the same compiled method.
    #[error("duplicate classification for `{service}/{method}`")]
    DuplicateEntry {
        /// Service full name as written in the table.
        service: String,
        /// Method name as written in the table.
        method: String,
    },
    /// A class contradicts the descriptor's streaming shape.
    #[error("classification for `{path}` contradicts its compiled streaming shape")]
    ShapeMismatch {
        /// Descriptor-derived request path of the mismatched method.
        path: String,
    },
    /// A stream-limit reason is missing from, or present on, the wrong class.
    #[error("stream-limit reason on `{path}` does not match its work class")]
    StreamReasonMismatch {
        /// Descriptor-derived request path of the mismatched method.
        path: String,
    },
}

/// One row of the compiled classification table.
struct ClassificationEntry {
    service: &'static str,
    method: &'static str,
    class: WorkClass,
    stream_limit_reason: Option<StreamLimitReason>,
    replay: ReplayClass,
}

const fn unary(service: &'static str, method: &'static str) -> ClassificationEntry {
    ClassificationEntry {
        service,
        method,
        class: WorkClass::Unary,
        stream_limit_reason: None,
        replay: ReplayClass::NoAutomaticReplay,
    }
}

const fn unary_read(service: &'static str, method: &'static str) -> ClassificationEntry {
    ClassificationEntry {
        service,
        method,
        class: WorkClass::Unary,
        stream_limit_reason: None,
        replay: ReplayClass::OutcomeSafe,
    }
}

const fn operator(
    service: &'static str,
    method: &'static str,
    replay: ReplayClass,
) -> ClassificationEntry {
    ClassificationEntry {
        service,
        method,
        class: WorkClass::Operator,
        stream_limit_reason: None,
        replay,
    }
}

const fn finite_stream(service: &'static str, method: &'static str) -> ClassificationEntry {
    ClassificationEntry {
        service,
        method,
        class: WorkClass::FiniteStream,
        stream_limit_reason: None,
        replay: ReplayClass::OutcomeSafe,
    }
}

const fn long_lived(
    service: &'static str,
    method: &'static str,
    reason: StreamLimitReason,
) -> ClassificationEntry {
    ClassificationEntry {
        service,
        method,
        class: WorkClass::LongLivedStream,
        stream_limit_reason: Some(reason),
        replay: ReplayClass::OutcomeSafe,
    }
}

const INVOCATION: &str = "basil.broker.v1.InvocationService";
const SIGNING: &str = "basil.broker.v1.SigningService";
const AEAD: &str = "basil.broker.v1.AeadService";
const SECRET: &str = "basil.broker.v1.SecretService";
const MINTING: &str = "basil.broker.v1.MintingService";
const NATS: &str = "basil.broker.v1.NatsService";
const NIX_CACHE: &str = "basil.broker.v1.NixCacheService";
const ADMIN: &str = "basil.broker.v1.AdminService";
const SPIFFE_WORKLOAD: &str = "SpiffeWorkloadAPI";
const SDS: &str = "envoy.service.secret.v3.SecretDiscoveryService";

/// The compiled classification table (admission design §3, rev 1.1).
///
/// Service and method names must match the compiled descriptor exactly;
/// [`RpcMethodRegistry::compiled`] rejects the table when they do not, in
/// either direction. Replay classes follow the design's explicit read-only
/// list; anything unlisted is `NoAutomaticReplay`, fail-closed.
///
/// `Explain` is class `U` and class `O` membership is exactly the operator
/// recovery/observation subset (`basil-3s0o` maintainer resolution).
/// `DeltaSecrets` is compiled but unimplemented; it classifies as class `L`
/// so it can never bypass stream accounting if it ever gains a handler.
const CLASSIFICATION_TABLE: &[ClassificationEntry] = &[
    // Sealed invocation.
    unary(INVOCATION, "Invoke"),
    // Freshness-challenge issuance mints bounded broker state, so it remains
    // `NoAutomaticReplay`. The capability RPC below is the authority for the
    // connected listener's challenge and courier contract.
    unary(INVOCATION, "GetInvocationChallenge"),
    // Listener capability discovery is read-only and safe to replay.
    unary_read(INVOCATION, "GetInvocationCapabilities"),
    // Signing.
    unary(SIGNING, "NewKey"),
    unary(SIGNING, "Import"),
    unary(SIGNING, "ImportSet"),
    unary(SIGNING, "Sign"),
    unary_read(SIGNING, "Verify"),
    unary_read(SIGNING, "GetPublicKey"),
    // AEAD (in-place crypto; conservatively non-replayable).
    unary(AEAD, "Encrypt"),
    unary(AEAD, "Decrypt"),
    unary(AEAD, "WrapEnvelope"),
    unary(AEAD, "UnwrapEnvelope"),
    unary(AEAD, "UnsealCose"),
    // Secrets.
    unary_read(SECRET, "GetSecret"),
    unary(SECRET, "SetSecret"),
    unary(SECRET, "RotateSecret"),
    finite_stream(SECRET, "ListCatalog"),
    // Minting.
    unary(MINTING, "MintJwt"),
    unary(MINTING, "IssueCertificate"),
    // NATS identity.
    unary(NATS, "MintNatsUser"),
    unary(NATS, "MintNatsAccount"),
    unary(NATS, "MintNatsOperator"),
    unary(NATS, "MintNatsSigner"),
    unary(NATS, "MintNatsServer"),
    unary(NATS, "MintNatsCurve"),
    unary(NATS, "EncryptNatsCurve"),
    unary(NATS, "DecryptNatsCurve"),
    unary(NATS, "SignNatsJwt"),
    unary_read(NATS, "ValidateNatsJwt"),
    // Purpose-specific Nix binary-cache custody operations.
    unary_read(NIX_CACHE, "DescribeNixCacheKey"),
    unary(NIX_CACHE, "EnrollNixCacheKey"),
    unary(NIX_CACHE, "SignNixCacheFingerprint"),
    // Admin: the operator/recovery lane plus diagnostics.
    operator(ADMIN, "Status", ReplayClass::OutcomeSafe),
    operator(ADMIN, "Health", ReplayClass::OutcomeSafe),
    operator(ADMIN, "Readiness", ReplayClass::OutcomeSafe),
    long_lived(ADMIN, "Watch", StreamLimitReason::WatchLimit),
    operator(ADMIN, "Reload", ReplayClass::NoAutomaticReplay),
    unary_read(ADMIN, "Explain"),
    operator(ADMIN, "Revoke", ReplayClass::NoAutomaticReplay),
    operator(ADMIN, "ListConnections", ReplayClass::OutcomeSafe),
    operator(ADMIN, "DropConnections", ReplayClass::NoAutomaticReplay),
    // SPIFFE Workload API.
    long_lived(
        SPIFFE_WORKLOAD,
        "FetchX509SVID",
        StreamLimitReason::StreamLimit,
    ),
    long_lived(
        SPIFFE_WORKLOAD,
        "FetchX509Bundles",
        StreamLimitReason::StreamLimit,
    ),
    unary(SPIFFE_WORKLOAD, "FetchJWTSVID"),
    long_lived(
        SPIFFE_WORKLOAD,
        "FetchJWTBundles",
        StreamLimitReason::StreamLimit,
    ),
    unary_read(SPIFFE_WORKLOAD, "ValidateJWTSVID"),
    // Envoy SDS.
    long_lived(SDS, "DeltaSecrets", StreamLimitReason::StreamLimit),
    long_lived(SDS, "StreamSecrets", StreamLimitReason::StreamLimit),
    unary_read(SDS, "FetchSecrets"),
];

/// Compiled, descriptor-reconciled per-method registry.
#[derive(Debug)]
pub struct RpcMethodRegistry {
    by_path: BTreeMap<Box<str>, RpcMethod>,
}

static SHARED: LazyLock<Result<RpcMethodRegistry, RpcRegistryError>> =
    LazyLock::new(RpcMethodRegistry::compiled);

impl RpcMethodRegistry {
    /// Build and validate the registry from the compiled descriptor set.
    ///
    /// # Errors
    ///
    /// Returns [`RpcRegistryError`] when the classification table and the
    /// compiled descriptor disagree in any direction; callers must treat this
    /// as a startup failure, never serve without classification.
    pub fn compiled() -> Result<Self, RpcRegistryError> {
        Self::from_parts(basil_proto::FILE_DESCRIPTOR_SET, CLASSIFICATION_TABLE)
    }

    /// The process-wide validated registry.
    ///
    /// # Errors
    ///
    /// Returns the retained validation failure; callers must fail startup.
    pub fn shared() -> Result<&'static Self, &'static RpcRegistryError> {
        SHARED.as_ref()
    }

    /// Classify one request path (`:path` pseudo-header, `/Service/Method`).
    ///
    /// `None` means the path names no compiled method: it also misses tonic
    /// routing and falls through to `Unimplemented` handling.
    #[must_use]
    pub fn classify(&self, path: &str) -> Option<&RpcMethod> {
        self.by_path.get(path)
    }

    /// Every classified method, in stable path order.
    pub fn iter(&self) -> impl Iterator<Item = &RpcMethod> {
        self.by_path.values()
    }

    /// Number of classified methods.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    /// Whether the registry is empty (it never is after validation).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }

    fn from_parts(
        descriptor_bytes: &[u8],
        table: &[ClassificationEntry],
    ) -> Result<Self, RpcRegistryError> {
        let descriptor = FileDescriptorSet::decode(descriptor_bytes)?;
        let mut by_path = BTreeMap::new();
        let mut used = vec![false; table.len()];
        for file in &descriptor.file {
            let package = file.package.as_deref().unwrap_or("");
            for service in &file.service {
                let service_name = service.name.as_deref().unwrap_or("");
                let full_service = if package.is_empty() {
                    service_name.to_owned()
                } else {
                    format!("{package}.{service_name}")
                };
                for method in &service.method {
                    let entry = classified_method(&full_service, method, table, &mut used)?;
                    by_path.insert(entry.path.clone(), entry);
                }
            }
        }
        if let Some(entry) = used
            .iter()
            .position(|used| !used)
            .and_then(|index| table.get(index))
        {
            return Err(RpcRegistryError::UnknownEntry {
                service: entry.service.to_owned(),
                method: entry.method.to_owned(),
            });
        }
        Ok(Self { by_path })
    }
}

/// Reconcile one descriptor method against the classification table.
fn classified_method(
    full_service: &str,
    method: &MethodDescriptorProto,
    table: &[ClassificationEntry],
    used: &mut [bool],
) -> Result<RpcMethod, RpcRegistryError> {
    let method_name = method.name.as_deref().unwrap_or("");
    let path = format!("/{full_service}/{method_name}");
    let mut selected: Option<usize> = None;
    for (index, entry) in table.iter().enumerate() {
        if entry.service == full_service && entry.method == method_name {
            if selected.is_some() || used.get(index).copied().unwrap_or(true) {
                return Err(RpcRegistryError::DuplicateEntry {
                    service: full_service.to_owned(),
                    method: method_name.to_owned(),
                });
            }
            selected = Some(index);
        }
    }
    let Some(entry) = selected.and_then(|index| {
        if let Some(flag) = used.get_mut(index) {
            *flag = true;
        }
        table.get(index)
    }) else {
        return Err(RpcRegistryError::Unclassified { path });
    };
    let server_streaming = method.server_streaming.unwrap_or(false);
    let client_streaming = method.client_streaming.unwrap_or(false);
    let shape_ok = match entry.class {
        WorkClass::Unary | WorkClass::Operator => !server_streaming && !client_streaming,
        WorkClass::FiniteStream => server_streaming && !client_streaming,
        WorkClass::LongLivedStream => server_streaming,
    };
    if !shape_ok {
        return Err(RpcRegistryError::ShapeMismatch { path });
    }
    let reason_ok = match entry.class {
        WorkClass::LongLivedStream => entry.stream_limit_reason.is_some(),
        WorkClass::Unary | WorkClass::FiniteStream | WorkClass::Operator => {
            entry.stream_limit_reason.is_none()
        }
    };
    if !reason_ok {
        return Err(RpcRegistryError::StreamReasonMismatch { path });
    }
    Ok(RpcMethod {
        path: path.into_boxed_str(),
        service: full_service.to_owned().into_boxed_str(),
        method: method_name.to_owned().into_boxed_str(),
        class: entry.class,
        overload_op: snake_case(method_name).into_boxed_str(),
        stream_limit_reason: entry.stream_limit_reason,
        replay: entry.replay,
    })
}

/// Deterministic `CamelCase` → `snake_case` for stable op tokens.
///
/// Boundaries: before an uppercase letter following a lowercase letter or a
/// digit, and before an uppercase letter that starts a new word after an
/// acronym run (`GetPublicKey` → `get_public_key`, `FetchX509SVID` →
/// `fetch_x509_svid`). Frozen: op tokens are wire-visible and must never
/// change for an existing method.
fn snake_case(name: &str) -> String {
    let characters: Vec<char> = name.chars().collect();
    let mut out = String::with_capacity(name.len() + 4);
    for (index, character) in characters.iter().enumerate() {
        if character.is_ascii_uppercase() && index > 0 {
            let previous = characters.get(index - 1);
            let next = characters.get(index + 1);
            let after_lower_or_digit =
                previous.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
            let acronym_end = previous.is_some_and(char::is_ascii_uppercase)
                && next.is_some_and(char::is_ascii_lowercase);
            if after_lower_or_digit || acronym_end {
                out.push('_');
            }
        }
        out.push(character.to_ascii_lowercase());
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn registry() -> RpcMethodRegistry {
        RpcMethodRegistry::compiled().expect("classification table reconciles")
    }

    /// Every compiled service method is classified, and nothing else is:
    /// the registry length equals an independent descriptor enumeration.
    /// This test fails whenever a new RPC lands without a table entry
    /// (`Unclassified`), with a stale entry (`UnknownEntry`), or twice
    /// (`DuplicateEntry`).
    #[test]
    fn every_compiled_service_method_is_classified_exactly_once() {
        let registry = registry();
        let descriptor = FileDescriptorSet::decode(basil_proto::FILE_DESCRIPTOR_SET).unwrap();
        let mut compiled_methods = 0_usize;
        for file in &descriptor.file {
            let package = file.package.as_deref().unwrap_or("");
            for service in &file.service {
                for method in &service.method {
                    compiled_methods += 1;
                    let service_name = service.name.as_deref().unwrap_or("");
                    let full_service = if package.is_empty() {
                        service_name.to_owned()
                    } else {
                        format!("{package}.{service_name}")
                    };
                    let path = format!("/{full_service}/{}", method.name.as_deref().unwrap_or(""));
                    let entry = registry
                        .classify(&path)
                        .unwrap_or_else(|| panic!("`{path}` must be classified"));
                    assert_eq!(entry.path(), path);
                    assert_eq!(entry.service(), full_service);
                }
            }
        }
        assert_eq!(registry.len(), compiled_methods);
        assert_eq!(registry.len(), CLASSIFICATION_TABLE.len());
        assert!(!registry.is_empty());
    }

    /// A classification miss implies a routing miss: an unknown path is not
    /// in the registry, and every registry key came from the descriptor that
    /// tonic routing was generated from.
    #[test]
    fn unknown_paths_are_unclassified() {
        let registry = registry();
        assert!(
            registry
                .classify("/basil.broker.v1.SigningService/NotAMethod")
                .is_none()
        );
        assert!(registry.classify("/no.such.Service/Sign").is_none());
        assert!(registry.classify("").is_none());
        // Paths must match exactly; no prefix or suffix laundering.
        assert!(
            registry
                .classify("basil.broker.v1.SigningService/Sign")
                .is_none()
        );
    }

    /// Class O membership is exactly the operator recovery/observation
    /// subset, and Explain is class U (basil-3s0o maintainer resolution).
    #[test]
    fn operator_lane_membership_is_exact() {
        let registry = registry();
        let operators: Vec<&str> = registry
            .iter()
            .filter(|method| method.class() == WorkClass::Operator)
            .map(RpcMethod::method)
            .collect();
        assert_eq!(
            operators,
            [
                "DropConnections",
                "Health",
                "ListConnections",
                "Readiness",
                "Reload",
                "Revoke",
                "Status",
            ]
        );
        let explain = registry
            .classify("/basil.broker.v1.AdminService/Explain")
            .unwrap();
        assert_eq!(explain.class(), WorkClass::Unary);
        assert_eq!(explain.replay(), ReplayClass::OutcomeSafe);
    }

    /// Long-lived streams carry their exact rejection reason; Admin `Watch`
    /// is the only `WATCH_LIMIT` member. `ListCatalog` is the only finite
    /// stream today.
    #[test]
    fn stream_classes_match_the_design() {
        let registry = registry();
        let long_lived: Vec<(&str, StreamLimitReason)> = registry
            .iter()
            .filter(|method| method.class() == WorkClass::LongLivedStream)
            .map(|method| (method.path(), method.stream_limit_reason().unwrap()))
            .collect();
        assert_eq!(
            long_lived,
            [
                (
                    "/SpiffeWorkloadAPI/FetchJWTBundles",
                    StreamLimitReason::StreamLimit
                ),
                (
                    "/SpiffeWorkloadAPI/FetchX509Bundles",
                    StreamLimitReason::StreamLimit
                ),
                (
                    "/SpiffeWorkloadAPI/FetchX509SVID",
                    StreamLimitReason::StreamLimit
                ),
                (
                    "/basil.broker.v1.AdminService/Watch",
                    StreamLimitReason::WatchLimit,
                ),
                (
                    "/envoy.service.secret.v3.SecretDiscoveryService/DeltaSecrets",
                    StreamLimitReason::StreamLimit,
                ),
                (
                    "/envoy.service.secret.v3.SecretDiscoveryService/StreamSecrets",
                    StreamLimitReason::StreamLimit,
                ),
            ]
        );
        let finite: Vec<&str> = registry
            .iter()
            .filter(|method| method.class() == WorkClass::FiniteStream)
            .map(RpcMethod::path)
            .collect();
        assert_eq!(finite, ["/basil.broker.v1.SecretService/ListCatalog"]);
        // Unary/operator methods never carry a stream reason.
        assert!(registry.iter().all(|method| {
            (method.class() == WorkClass::LongLivedStream) == method.stream_limit_reason().is_some()
        }));
        assert_eq!(StreamLimitReason::WatchLimit.token(), "WATCH_LIMIT");
        assert_eq!(StreamLimitReason::StreamLimit.token(), "STREAM_LIMIT");
    }

    /// Replay classes: the design's explicit read-only list is outcome-safe;
    /// mutating and issuance methods are never auto-replayed.
    #[test]
    fn replay_classification_is_fail_closed() {
        let registry = registry();
        let safe = |path: &str| registry.classify(path).unwrap().replay();
        assert_eq!(
            safe("/basil.broker.v1.SecretService/GetSecret"),
            ReplayClass::OutcomeSafe
        );
        assert_eq!(
            safe("/basil.broker.v1.SigningService/GetPublicKey"),
            ReplayClass::OutcomeSafe
        );
        assert_eq!(
            safe("/basil.broker.v1.SigningService/Verify"),
            ReplayClass::OutcomeSafe
        );
        assert_eq!(
            safe("/SpiffeWorkloadAPI/ValidateJWTSVID"),
            ReplayClass::OutcomeSafe
        );
        for path in [
            "/basil.broker.v1.InvocationService/Invoke",
            "/basil.broker.v1.SecretService/SetSecret",
            "/basil.broker.v1.SecretService/RotateSecret",
            "/basil.broker.v1.SigningService/NewKey",
            "/basil.broker.v1.SigningService/Import",
            "/basil.broker.v1.SigningService/Sign",
            "/basil.broker.v1.MintingService/MintJwt",
            "/basil.broker.v1.NatsService/SignNatsJwt",
            "/SpiffeWorkloadAPI/FetchJWTSVID",
            "/basil.broker.v1.AdminService/Reload",
            "/basil.broker.v1.AdminService/DropConnections",
        ] {
            assert_eq!(safe(path), ReplayClass::NoAutomaticReplay, "{path}");
        }
    }

    /// Overload op tokens are deterministic snake case of the frozen
    /// generated method names.
    #[test]
    fn overload_op_tokens_are_stable_snake_case() {
        let registry = registry();
        let op = |path: &str| registry.classify(path).unwrap().overload_op().to_owned();
        assert_eq!(op("/basil.broker.v1.SigningService/Sign"), "sign");
        assert_eq!(
            op("/basil.broker.v1.SigningService/GetPublicKey"),
            "get_public_key"
        );
        assert_eq!(op("/basil.broker.v1.AdminService/Watch"), "watch");
        assert_eq!(
            op("/basil.broker.v1.AdminService/ListConnections"),
            "list_connections"
        );
        assert_eq!(op("/SpiffeWorkloadAPI/FetchX509SVID"), "fetch_x509_svid");
        assert_eq!(op("/SpiffeWorkloadAPI/ValidateJWTSVID"), "validate_jwtsvid");
        assert_eq!(
            op("/envoy.service.secret.v3.SecretDiscoveryService/StreamSecrets"),
            "stream_secrets"
        );
        // Every op token is nonempty lower-snake ASCII.
        assert!(registry.iter().all(|method| {
            !method.overload_op().is_empty()
                && method
                    .overload_op()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        }));
    }

    /// A missing table row is detected as `Unclassified`; a stale or
    /// misspelled row is detected as `UnknownEntry`; a doubled row as
    /// `DuplicateEntry`. The registry can therefore never silently drift
    /// from the compiled routing surface.
    #[test]
    fn table_descriptor_drift_fails_closed_in_both_directions() {
        let truncated: Vec<ClassificationEntry> = CLASSIFICATION_TABLE
            .iter()
            .filter(|entry| entry.method != "Sign")
            .map(|entry| ClassificationEntry { ..*entry })
            .collect();
        assert!(matches!(
            RpcMethodRegistry::from_parts(basil_proto::FILE_DESCRIPTOR_SET, &truncated),
            Err(RpcRegistryError::Unclassified { path }) if path.ends_with("/Sign")
        ));

        let mut stale: Vec<ClassificationEntry> = CLASSIFICATION_TABLE
            .iter()
            .map(|entry| ClassificationEntry { ..*entry })
            .collect();
        stale.push(unary(SIGNING, "SignTypo"));
        assert!(matches!(
            RpcMethodRegistry::from_parts(basil_proto::FILE_DESCRIPTOR_SET, &stale),
            Err(RpcRegistryError::UnknownEntry { method, .. }) if method == "SignTypo"
        ));

        let mut doubled: Vec<ClassificationEntry> = CLASSIFICATION_TABLE
            .iter()
            .map(|entry| ClassificationEntry { ..*entry })
            .collect();
        doubled.push(unary(SIGNING, "Sign"));
        assert!(matches!(
            RpcMethodRegistry::from_parts(basil_proto::FILE_DESCRIPTOR_SET, &doubled),
            Err(RpcRegistryError::DuplicateEntry { method, .. }) if method == "Sign"
        ));
    }

    /// A class whose shape contradicts the descriptor is rejected, as is a
    /// stream-limit reason on the wrong class.
    #[test]
    fn shape_and_reason_mismatches_fail_closed() {
        let reshaped: Vec<ClassificationEntry> = CLASSIFICATION_TABLE
            .iter()
            .map(|entry| {
                if entry.service == SECRET && entry.method == "ListCatalog" {
                    unary(SECRET, "ListCatalog")
                } else {
                    ClassificationEntry { ..*entry }
                }
            })
            .collect();
        assert!(matches!(
            RpcMethodRegistry::from_parts(basil_proto::FILE_DESCRIPTOR_SET, &reshaped),
            Err(RpcRegistryError::ShapeMismatch { path })
                if path == "/basil.broker.v1.SecretService/ListCatalog"
        ));

        let misreasoned: Vec<ClassificationEntry> = CLASSIFICATION_TABLE
            .iter()
            .map(|entry| {
                if entry.service == ADMIN && entry.method == "Watch" {
                    ClassificationEntry {
                        stream_limit_reason: None,
                        ..*entry
                    }
                } else {
                    ClassificationEntry { ..*entry }
                }
            })
            .collect();
        assert!(matches!(
            RpcMethodRegistry::from_parts(basil_proto::FILE_DESCRIPTOR_SET, &misreasoned),
            Err(RpcRegistryError::StreamReasonMismatch { path })
                if path == "/basil.broker.v1.AdminService/Watch"
        ));
    }

    /// The process-wide accessor validates once and returns the same registry.
    #[test]
    fn shared_registry_is_validated_and_stable() {
        let first = RpcMethodRegistry::shared().expect("shared registry validates");
        let second = RpcMethodRegistry::shared().expect("shared registry validates");
        assert!(std::ptr::eq(first, second));
        assert_eq!(first.len(), CLASSIFICATION_TABLE.len());
    }
}
