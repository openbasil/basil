// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use prost::Message;
use rustix::event::{PollFd, PollFlags};
use rustix::fs::FileType;
use rustix::net::sockopt;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, timeout_at};

use super::codec::{CodecError, FrameCodec, PeerCredentials, VerifiedPeerBinding};
use super::helper::transport::{HelperConnection, TransportError};
use super::helper::wire::{
    HELPER_PROTOCOL_VERSION, HelperResponse, MeasuredRecord, MeasurementRequest, NONCE_BYTES,
    RejectCode, WireError,
};
use super::limits::{
    ABSOLUTE_MAX_CAPABILITIES, ABSOLUTE_MAX_CAPABILITY_BYTES, ABSOLUTE_MAX_DIAGNOSTIC_BYTES,
    ABSOLUTE_MAX_ID_MAP_RANGES, ABSOLUTE_MAX_MOUNTS_PER_INSTANCE, ABSOLUTE_MAX_STRING_BYTES,
    PROTOCOL_VERSION, ProtocolLimits,
};
use super::wire;
use super::wire::envelope::Body;
use super::wire::query_instances_request::Scope;

const BINDING_BYTES: usize = 32;

/// Protocol-1 opt-in for tmpfs mount-security fields added after the original
/// schema was deployed.
pub const MOUNT_SECURITY_CAPABILITY: &str = "mount-security.v1";

macro_rules! checked_response {
    ($session:expr, $result:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => return $session.close_with(error).await,
        }
    };
}

/// Authenticated identities and broker generation bound into a new session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionAuthentication {
    /// Broker-assigned configuration generation.
    pub generation: u64,
    /// Binding produced by attestor-side authentication of the broker.
    pub broker: VerifiedPeerBinding,
    /// Binding produced by broker-side authentication of the attestor.
    pub attestor: VerifiedPeerBinding,
}

/// Closed query scope supported by protocol 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QueryScope {
    /// One exact immutable runtime instance ID.
    InstanceId(String),
    /// One exact Compose realm and project.
    Project {
        /// Configured realm name.
        realm: String,
        /// Exact Compose project.
        project: String,
    },
    /// One exact Compose realm, project, and service.
    Service {
        /// Configured realm name.
        realm: String,
        /// Exact Compose project.
        project: String,
        /// Exact Compose service.
        service: String,
    },
    /// All visible instances, available only to an explicit global doctor call.
    GlobalDoctor,
}

/// Bounded health response. Health facts are diagnostic and carry no
/// authorization evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthResult {
    /// Typed provider outcome.
    pub outcome: wire::Outcome,
    /// Diagnostic health fact, present only for a successful response.
    pub health: Option<wire::HealthFact>,
}

/// Bounded pinned-peer resolution response.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvePeerResult {
    /// Typed provider outcome.
    pub outcome: wire::Outcome,
    /// Normalized instance fact for a successful match.
    pub instance: Option<wire::InstanceFact>,
}

/// Fully verified bounded inventory response.
#[derive(Clone, Debug, PartialEq)]
pub struct InventoryResult {
    /// Typed provider outcome shared by all response chunks.
    pub outcome: wire::Outcome,
    /// Fixed normalized fact projection in wire order.
    pub instances: Vec<wire::InstanceFact>,
    /// SHA-256 digest committed by the final chunk and recomputed by the broker.
    pub digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    New,
    Ready,
    Waiting(Operation),
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Handshake,
    Health,
    ResolvePeer,
    QueryInstances,
}

/// Strict serial broker-side protocol session.
pub struct BrokerSession<S> {
    codec: FrameCodec<S>,
    authentication: SessionAuthentication,
    limits: ProtocolLimits,
    required_capabilities: Vec<String>,
    negotiated_capabilities: Vec<String>,
    session_nonce: [u8; BINDING_BYTES],
    phase: Phase,
}

impl<S> BrokerSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Construct a session over a stream whose peer was authenticated before
    /// framing was enabled.
    ///
    /// A fresh session nonce is generated here rather than accepted from the
    /// caller. No operation other than [`Self::handshake`] is available until
    /// the peer echoes every authentication binding and capability checks pass.
    pub fn new(
        codec: FrameCodec<S>,
        authentication: SessionAuthentication,
        required_capabilities: impl IntoIterator<Item = String>,
        limits: ProtocolLimits,
    ) -> Result<Self, ProtocolError> {
        if codec.peer_binding() != authentication.attestor {
            return Err(ProtocolError::PeerBindingMismatch);
        }
        if authentication.generation == 0 {
            return Err(invalid("generation", "must be non-zero"));
        }
        let required_capabilities = normalize_capabilities(required_capabilities)?;
        let mut session_nonce = [0_u8; BINDING_BYTES];
        getrandom::fill(&mut session_nonce).map_err(ProtocolError::Random)?;
        Ok(Self {
            codec,
            authentication,
            limits,
            required_capabilities,
            negotiated_capabilities: Vec::new(),
            session_nonce,
            phase: Phase::New,
        })
    }

    /// Complete the mandatory protocol-1 handshake.
    pub async fn handshake(&mut self) -> Result<(), ProtocolError> {
        if self.phase != Phase::New {
            return Err(self.phase_error(Operation::Handshake));
        }
        let binding = self.binding([0; BINDING_BYTES]);
        let request = envelope(Body::HandshakeRequest(wire::HandshakeRequest {
            binding: Some(binding.clone()),
            required_capabilities: self.required_capabilities.clone(),
            broker_peer_binding: self.authentication.broker.as_bytes().to_vec(),
        }));
        self.phase = Phase::Waiting(Operation::Handshake);
        self.write_or_close(&request).await?;
        let response = self.read_or_close(self.deadline()).await?;
        let body = checked_response!(self, take_body(response));
        let Body::HandshakeResponse(response) = body else {
            return self
                .close_with(ProtocolError::UnexpectedResponse {
                    expected: "handshake_response",
                })
                .await;
        };
        checked_response!(
            self,
            Self::validate_binding(response.binding.as_ref(), &binding)
        );
        checked_response!(self, validate_outcome(response.outcome.as_ref()));
        if checked_response!(self, outcome_code(response.outcome.as_ref())) != wire::OutcomeCode::Ok
        {
            return self
                .close_with(ProtocolError::HandshakeRejected {
                    outcome: response.outcome,
                })
                .await;
        }
        checked_response!(
            self,
            check_digest(
                "broker_peer_binding",
                &response.broker_peer_binding,
                self.authentication.broker.as_bytes(),
            )
        );
        checked_response!(
            self,
            check_digest(
                "attestor_peer_binding",
                &response.attestor_peer_binding,
                self.authentication.attestor.as_bytes(),
            )
        );
        let supported = checked_response!(
            self,
            normalize_capabilities(response.supported_capabilities)
        );
        for capability in &self.required_capabilities {
            if supported.binary_search(capability).is_err() {
                return self
                    .close_with(ProtocolError::MissingCapability(capability.clone()))
                    .await;
            }
        }
        self.negotiated_capabilities = supported;
        self.phase = Phase::Ready;
        Ok(())
    }

    /// Return the peer's bounded declared capabilities after handshake.
    #[must_use]
    pub fn negotiated_capabilities(&self) -> &[String] {
        &self.negotiated_capabilities
    }

    /// Perform one bounded diagnostic-only health probe.
    ///
    /// The caller's monotonic `budget` is clamped to the active
    /// [`ProtocolLimits::request_deadline`] and its remaining window is
    /// transmitted on the wire so the attestor-side provider stops under the
    /// caller's original deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BudgetExhausted`] without any wire traffic
    /// when `budget` has already elapsed; the session stays usable.
    pub async fn health(&mut self, budget: RequestBudget) -> Result<HealthResult, ProtocolError> {
        let (deadline, budget_millis) = self.request_window(budget)?;
        let challenge = self.begin(Operation::Health)?;
        let binding = self.binding(challenge);
        let request = envelope(Body::HealthRequest(wire::HealthRequest {
            binding: Some(binding.clone()),
            budget_millis,
        }));
        self.write_or_close(&request).await?;
        let response = self.read_or_close(deadline).await?;
        let body = checked_response!(self, take_body(response));
        let Body::HealthResponse(response) = body else {
            return self.close_unexpected("health_response").await;
        };
        checked_response!(
            self,
            Self::validate_binding(response.binding.as_ref(), &binding)
        );
        checked_response!(self, validate_outcome(response.outcome.as_ref()));
        if let Some(health) = response.health.as_ref() {
            checked_response!(self, validate_health(health));
        }
        checked_response!(
            self,
            require_success_payload(
                response.outcome.as_ref(),
                response.health.is_some(),
                "health",
            )
        );
        self.phase = Phase::Ready;
        Ok(HealthResult {
            outcome: checked_response!(self, required_outcome(response.outcome)),
            health: response.health,
        })
    }

    /// Resolve one broker-observed pinned process without accepting any
    /// runtime-instance or Compose lookup hint.
    ///
    /// The caller's monotonic `budget` is clamped to the active
    /// [`ProtocolLimits::request_deadline`] and its remaining window is
    /// transmitted on the wire so the attestor-side provider stops under the
    /// caller's original deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BudgetExhausted`] without any wire traffic
    /// when `budget` has already elapsed; the session stays usable.
    pub async fn resolve_peer(
        &mut self,
        constraints: wire::PinnedPeer,
        budget: RequestBudget,
    ) -> Result<ResolvePeerResult, ProtocolError> {
        validate_pinned_peer(&constraints)?;
        let (deadline, budget_millis) = self.request_window(budget)?;
        let challenge = self.begin(Operation::ResolvePeer)?;
        let binding = self.binding(challenge);
        let request = envelope(Body::ResolvePeerRequest(wire::ResolvePeerRequest {
            binding: Some(binding.clone()),
            budget_millis,
            constraints: Some(constraints),
        }));
        self.write_or_close(&request).await?;
        let response = self.read_or_close(deadline).await?;
        let body = checked_response!(self, take_body(response));
        let Body::ResolvePeerResponse(response) = body else {
            return self.close_unexpected("resolve_peer_response").await;
        };
        checked_response!(
            self,
            Self::validate_binding(response.binding.as_ref(), &binding)
        );
        checked_response!(self, validate_outcome(response.outcome.as_ref()));
        if let Some(instance) = response.instance.as_ref() {
            checked_response!(self, validate_instance(instance, &binding));
            checked_response!(
                self,
                validate_mount_security_negotiation(
                    instance,
                    capability_enabled(&self.required_capabilities, MOUNT_SECURITY_CAPABILITY),
                )
            );
        }
        checked_response!(
            self,
            require_success_payload(
                response.outcome.as_ref(),
                response.instance.is_some(),
                "instance",
            )
        );
        self.phase = Phase::Ready;
        Ok(ResolvePeerResult {
            outcome: checked_response!(self, required_outcome(response.outcome)),
            instance: response.instance,
        })
    }

    /// Query one closed, typed scope and verify its bounded chunk sequence,
    /// declared totals, and final digest.
    ///
    /// The caller's monotonic `budget` is clamped to the active
    /// [`ProtocolLimits::request_deadline`] and its remaining window is
    /// transmitted on the wire so the attestor-side provider stops under the
    /// caller's original deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::BudgetExhausted`] without any wire traffic
    /// when `budget` has already elapsed; the session stays usable.
    pub async fn query_instances(
        &mut self,
        scope: QueryScope,
        budget: RequestBudget,
    ) -> Result<InventoryResult, ProtocolError> {
        let scope = encode_scope(scope)?;
        let (deadline, budget_millis) = self.request_window(budget)?;
        let challenge = self.begin(Operation::QueryInstances)?;
        let binding = self.binding(challenge);
        let request = envelope(Body::QueryInstancesRequest(wire::QueryInstancesRequest {
            binding: Some(binding.clone()),
            budget_millis,
            scope: Some(scope),
        }));
        self.write_or_close(&request).await?;
        let mut accumulator = InventoryAccumulator::new(
            self.limits,
            capability_enabled(&self.required_capabilities, MOUNT_SECURITY_CAPABILITY),
        );
        loop {
            let response = self.read_or_close(deadline).await?;
            let body = checked_response!(self, take_body(response));
            let Body::QueryInstancesChunk(chunk) = body else {
                return self.close_unexpected("query_instances_chunk").await;
            };
            checked_response!(
                self,
                Self::validate_binding(chunk.binding.as_ref(), &binding)
            );
            let complete = checked_response!(self, accumulator.push(chunk, &binding));
            if let Some(result) = complete {
                self.phase = Phase::Ready;
                return Ok(result);
            }
        }
    }

    fn begin(&mut self, operation: Operation) -> Result<[u8; BINDING_BYTES], ProtocolError> {
        if self.phase != Phase::Ready {
            return Err(self.phase_error(operation));
        }
        let mut challenge = [0_u8; BINDING_BYTES];
        getrandom::fill(&mut challenge).map_err(ProtocolError::Random)?;
        self.phase = Phase::Waiting(operation);
        Ok(challenge)
    }

    fn binding(&self, challenge: [u8; BINDING_BYTES]) -> wire::SessionBinding {
        wire::SessionBinding {
            session_nonce: self.session_nonce.to_vec(),
            generation: self.authentication.generation,
            challenge: challenge.to_vec(),
        }
    }

    fn deadline(&self) -> Instant {
        Instant::now() + self.limits.request_deadline
    }

    /// Clamp a caller budget to the active limits and derive the monotonic
    /// response deadline plus the wire budget for one request.
    ///
    /// Runs before [`Self::begin`] so an exhausted budget neither advances the
    /// serial phase nor terminates the session.
    fn request_window(&self, budget: RequestBudget) -> Result<(Instant, u64), ProtocolError> {
        let remaining = budget.remaining().min(self.limits.request_deadline);
        let budget_millis = duration_millis(remaining)?;
        if budget_millis == 0 {
            return Err(ProtocolError::BudgetExhausted);
        }
        let now = Instant::now();
        let deadline = now.checked_add(remaining).unwrap_or(now);
        Ok((deadline, budget_millis))
    }

    async fn write_or_close(&mut self, envelope: &wire::Envelope) -> Result<(), ProtocolError> {
        if let Err(error) = self.codec.write_envelope(envelope).await {
            return self.close_with(error.into()).await;
        }
        Ok(())
    }

    async fn read_or_close(&mut self, deadline: Instant) -> Result<wire::Envelope, ProtocolError> {
        match timeout_at(deadline, self.codec.read_envelope()).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => self.close_with(error.into()).await,
            Err(_) => self.close_with(ProtocolError::DeadlineExceeded).await,
        }
    }

    fn validate_binding(
        actual: Option<&wire::SessionBinding>,
        expected: &wire::SessionBinding,
    ) -> Result<(), ProtocolError> {
        let actual = actual.ok_or(ProtocolError::MissingField("binding"))?;
        validate_binding_shape(actual)?;
        if actual.generation != expected.generation
            || actual.session_nonce != expected.session_nonce
        {
            return Err(ProtocolError::StaleSession);
        }
        if actual.challenge != expected.challenge {
            return Err(ProtocolError::StaleChallenge);
        }
        Ok(())
    }

    fn phase_error(&self, requested: Operation) -> ProtocolError {
        match self.phase {
            Phase::New if requested != Operation::Handshake => ProtocolError::HandshakeRequired,
            Phase::New => ProtocolError::AlreadyHandshaken,
            Phase::Ready if requested == Operation::Handshake => ProtocolError::AlreadyHandshaken,
            Phase::Ready => ProtocolError::DuplicateResponse,
            Phase::Waiting(_) => ProtocolError::RequestAlreadyPending,
            Phase::Closed => ProtocolError::Closed,
        }
    }

    async fn close_unexpected<T>(&mut self, expected: &'static str) -> Result<T, ProtocolError> {
        self.close_with(ProtocolError::UnexpectedResponse { expected })
            .await
    }

    async fn close_with<T>(&mut self, error: ProtocolError) -> Result<T, ProtocolError> {
        self.phase = Phase::Closed;
        self.codec.terminate().await;
        Err(error)
    }
}

/// One validated broker request received by the runtime attestor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttestorRequest {
    /// Bounded diagnostic-only runtime health probe.
    Health {
        /// Original request deadline, shared with response framing.
        budget: RequestBudget,
    },
    /// Pinned broker-observed process constraints.
    ResolvePeer {
        /// Broker-observed constraints.
        constraints: wire::PinnedPeer,
        /// Original request deadline, shared with response framing.
        budget: RequestBudget,
    },
    /// Closed typed inventory scope.
    QueryInstances {
        /// Closed inventory selector.
        scope: QueryScope,
        /// Original request deadline, shared with response framing.
        budget: RequestBudget,
    },
}

/// Monotonic request deadline passed unchanged from protocol validation to a
/// runtime provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBudget {
    deadline: Instant,
}

impl RequestBudget {
    /// Start a monotonic budget of `budget` from the current instant.
    ///
    /// This is the broker-side entry point of the budget seam: a caller
    /// derives one budget from its own remaining deadline and every
    /// downstream dispatch step observes the same monotonic expiry. A budget
    /// too large for the monotonic clock saturates to an empty budget, which
    /// fails closed at dispatch.
    #[must_use]
    pub fn starting_now(budget: Duration) -> Self {
        let now = Instant::now();
        Self {
            deadline: now.checked_add(budget).unwrap_or(now),
        }
    }

    /// Return the duration remaining before the original broker deadline.
    #[must_use]
    pub fn remaining(self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

enum RequestPayload {
    Health,
    ResolvePeer(wire::PinnedPeer),
    QueryInstances(QueryScope),
}

#[derive(Clone, Debug)]
struct PendingResponse {
    operation: Operation,
    binding: wire::SessionBinding,
    deadline: Instant,
}

/// Strict serial attestor-side protocol session.
///
/// This state machine reads no second request until the caller completes the
/// pending response. It validates all request constraints before returning
/// them to a provider and owns response fact binding, chunk numbering, totals,
/// and inventory digest construction.
pub struct AttestorSession<S> {
    codec: FrameCodec<S>,
    authentication: SessionAuthentication,
    limits: ProtocolLimits,
    supported_capabilities: Vec<String>,
    broker_capabilities: Vec<String>,
    session_nonce: Option<[u8; BINDING_BYTES]>,
    last_challenge: Option<[u8; BINDING_BYTES]>,
    phase: Phase,
    pending: Option<PendingResponse>,
}

impl<S> AttestorSession<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Construct an attestor session over a broker-authenticated stream.
    pub fn new(
        codec: FrameCodec<S>,
        authentication: SessionAuthentication,
        supported_capabilities: impl IntoIterator<Item = String>,
        limits: ProtocolLimits,
    ) -> Result<Self, ProtocolError> {
        if codec.peer_binding() != authentication.broker {
            return Err(ProtocolError::PeerBindingMismatch);
        }
        if authentication.generation == 0 {
            return Err(invalid("generation", "must be non-zero"));
        }
        Ok(Self {
            codec,
            authentication,
            limits,
            supported_capabilities: normalize_capabilities(supported_capabilities)?,
            broker_capabilities: Vec::new(),
            session_nonce: None,
            last_challenge: None,
            phase: Phase::New,
            pending: None,
        })
    }

    /// Receive, validate, and answer the mandatory handshake.
    pub async fn handshake(&mut self) -> Result<(), ProtocolError> {
        if self.phase != Phase::New {
            return Err(self.phase_error(Operation::Handshake));
        }
        let deadline = Instant::now() + self.limits.request_deadline;
        let incoming = self.read_until(deadline).await?;
        let body = match take_body(incoming) {
            Ok(body) => body,
            Err(error) => return self.close_with(error).await,
        };
        let Body::HandshakeRequest(request) = body else {
            return self.close_unexpected("handshake_request").await;
        };
        let Some(binding) = request.binding else {
            return self
                .close_with(ProtocolError::MissingField("binding"))
                .await;
        };
        if let Err(error) = validate_binding_shape(&binding) {
            return self.close_with(error).await;
        }
        if binding.generation != self.authentication.generation {
            return self.close_with(ProtocolError::StaleSession).await;
        }
        if binding.challenge != [0; BINDING_BYTES] {
            return self.close_with(ProtocolError::StaleChallenge).await;
        }
        if let Err(error) = check_digest(
            "broker_peer_binding",
            &request.broker_peer_binding,
            self.authentication.broker.as_bytes(),
        ) {
            return self.close_with(error).await;
        }
        let required = match normalize_capabilities(request.required_capabilities) {
            Ok(required) => required,
            Err(error) => return self.close_with(error).await,
        };
        for capability in &required {
            if self
                .supported_capabilities
                .binary_search(capability)
                .is_err()
            {
                return self
                    .close_with(ProtocolError::MissingCapability(capability.clone()))
                    .await;
            }
        }
        let nonce: [u8; BINDING_BYTES] = binding
            .session_nonce
            .as_slice()
            .try_into()
            .map_err(|_| invalid("session_nonce", "must be 32 bytes"))?;
        let response = envelope(Body::HandshakeResponse(wire::HandshakeResponse {
            outcome: Some(wire::Outcome {
                code: wire::OutcomeCode::Ok as i32,
                diagnostic: String::new(),
            }),
            binding: Some(binding),
            supported_capabilities: self.supported_capabilities.clone(),
            broker_peer_binding: self.authentication.broker.as_bytes().to_vec(),
            attestor_peer_binding: self.authentication.attestor.as_bytes().to_vec(),
        }));
        if let Err(error) = self.write_until(deadline, &response).await {
            return self.close_with(error).await;
        }
        self.broker_capabilities = required;
        self.session_nonce = Some(nonce);
        self.phase = Phase::Ready;
        Ok(())
    }

    /// Receive and validate the next request.
    ///
    /// The caller must complete it with the matching `respond_*` method before
    /// calling `receive` again.
    pub async fn receive(&mut self) -> Result<AttestorRequest, ProtocolError> {
        if self.phase != Phase::Ready || self.pending.is_some() {
            return Err(self.phase_error(Operation::Health));
        }
        let read_deadline = Instant::now() + self.limits.request_deadline;
        let incoming = self.read_until(read_deadline).await?;
        let body = match take_body(incoming) {
            Ok(body) => body,
            Err(error) => return self.close_with(error).await,
        };
        let (operation, binding, budget_millis, request) = match body {
            Body::HealthRequest(request) => (
                Operation::Health,
                request.binding,
                request.budget_millis,
                RequestPayload::Health,
            ),
            Body::ResolvePeerRequest(request) => {
                let Some(constraints) = request.constraints else {
                    return self
                        .close_with(ProtocolError::MissingField("constraints"))
                        .await;
                };
                if let Err(error) = validate_pinned_peer(&constraints) {
                    return self.close_with(error).await;
                }
                (
                    Operation::ResolvePeer,
                    request.binding,
                    request.budget_millis,
                    RequestPayload::ResolvePeer(constraints),
                )
            }
            Body::QueryInstancesRequest(request) => {
                let scope = match decode_scope(request.scope) {
                    Ok(scope) => scope,
                    Err(error) => return self.close_with(error).await,
                };
                (
                    Operation::QueryInstances,
                    request.binding,
                    request.budget_millis,
                    RequestPayload::QueryInstances(scope),
                )
            }
            _ => return self.close_unexpected("request").await,
        };
        let Some(binding) = binding else {
            return self
                .close_with(ProtocolError::MissingField("binding"))
                .await;
        };
        if let Err(error) = self.validate_request_binding(&binding) {
            return self.close_with(error).await;
        }
        let budget = match request_budget(budget_millis, self.limits.request_deadline) {
            Ok(budget) => budget,
            Err(error) => return self.close_with(error).await,
        };
        let challenge: [u8; BINDING_BYTES] = binding
            .challenge
            .as_slice()
            .try_into()
            .map_err(|_| invalid("challenge", "must be 32 bytes"))?;
        if self.last_challenge == Some(challenge) {
            return self.close_with(ProtocolError::DuplicateRequest).await;
        }
        self.last_challenge = Some(challenge);
        let deadline = Instant::now() + budget;
        let budget = RequestBudget { deadline };
        self.pending = Some(PendingResponse {
            operation,
            binding,
            deadline,
        });
        self.phase = Phase::Waiting(operation);
        Ok(match request {
            RequestPayload::Health => AttestorRequest::Health { budget },
            RequestPayload::ResolvePeer(constraints) => AttestorRequest::ResolvePeer {
                constraints,
                budget,
            },
            RequestPayload::QueryInstances(scope) => {
                AttestorRequest::QueryInstances { scope, budget }
            }
        })
    }

    /// Send the complete health response for the pending request.
    pub async fn respond_health(
        &mut self,
        outcome: wire::Outcome,
        health: Option<wire::HealthFact>,
    ) -> Result<(), ProtocolError> {
        validate_outcome(Some(&outcome))?;
        if let Some(health) = health.as_ref() {
            validate_health(health)?;
        }
        require_success_payload(Some(&outcome), health.is_some(), "health")?;
        let pending = self.take_pending(Operation::Health)?;
        let response = envelope(Body::HealthResponse(wire::HealthResponse {
            outcome: Some(outcome),
            binding: Some(pending.binding),
            health,
        }));
        self.finish_response(pending.deadline, &[response]).await
    }

    /// Send the complete pinned-peer response for the pending request.
    ///
    /// The session overwrites the fact's session binding before validation so a
    /// provider cannot choose or reuse a nonce, challenge, or generation.
    pub async fn respond_resolve_peer(
        &mut self,
        outcome: wire::Outcome,
        mut instance: Option<wire::InstanceFact>,
    ) -> Result<(), ProtocolError> {
        validate_outcome(Some(&outcome))?;
        require_success_payload(Some(&outcome), instance.is_some(), "instance")?;
        let pending = self.take_pending(Operation::ResolvePeer)?;
        if let Some(instance) = instance.as_mut() {
            project_mount_security(
                instance,
                capability_enabled(&self.broker_capabilities, MOUNT_SECURITY_CAPABILITY),
            );
            bind_instance(instance, &pending.binding)?;
            validate_instance(instance, &pending.binding)?;
        }
        let response = envelope(Body::ResolvePeerResponse(wire::ResolvePeerResponse {
            outcome: Some(outcome),
            binding: Some(pending.binding),
            instance,
        }));
        self.finish_response(pending.deadline, &[response]).await
    }

    /// Validate, bind, chunk, and send the complete inventory response.
    pub async fn respond_query_instances(
        &mut self,
        outcome: wire::Outcome,
        mut instances: Vec<wire::InstanceFact>,
    ) -> Result<(), ProtocolError> {
        validate_outcome(Some(&outcome))?;
        let success = outcome_code(Some(&outcome))? == wire::OutcomeCode::Ok;
        if !success && !instances.is_empty() {
            return Err(invalid(
                "instances",
                "must be empty for a non-success outcome",
            ));
        }
        let pending = self.take_pending(Operation::QueryInstances)?;
        for instance in &mut instances {
            project_mount_security(
                instance,
                capability_enabled(&self.broker_capabilities, MOUNT_SECURITY_CAPABILITY),
            );
            bind_instance(instance, &pending.binding)?;
            validate_instance(instance, &pending.binding)?;
        }
        let responses =
            build_inventory_responses(&outcome, &pending.binding, instances, self.limits)?;
        self.finish_response(pending.deadline, &responses).await
    }

    fn validate_request_binding(
        &self,
        binding: &wire::SessionBinding,
    ) -> Result<(), ProtocolError> {
        validate_binding_shape(binding)?;
        let nonce = self.session_nonce.ok_or(ProtocolError::HandshakeRequired)?;
        if binding.generation != self.authentication.generation || binding.session_nonce != nonce {
            return Err(ProtocolError::StaleSession);
        }
        if binding.challenge == [0; BINDING_BYTES] {
            return Err(invalid("challenge", "must be fresh and non-zero"));
        }
        Ok(())
    }

    fn take_pending(&mut self, expected: Operation) -> Result<PendingResponse, ProtocolError> {
        let pending = self
            .pending
            .take()
            .ok_or(ProtocolError::DuplicateResponse)?;
        if pending.operation != expected {
            self.pending = Some(pending);
            return Err(ProtocolError::UnexpectedResponse {
                expected: operation_name(expected),
            });
        }
        Ok(pending)
    }

    async fn finish_response(
        &mut self,
        deadline: Instant,
        responses: &[wire::Envelope],
    ) -> Result<(), ProtocolError> {
        for response in responses {
            if let Err(error) = self.write_until(deadline, response).await {
                return self.close_with(error).await;
            }
        }
        self.phase = Phase::Ready;
        Ok(())
    }

    async fn read_until(&mut self, deadline: Instant) -> Result<wire::Envelope, ProtocolError> {
        match timeout_at(deadline, self.codec.read_envelope()).await {
            Ok(Ok(request)) => Ok(request),
            Ok(Err(error)) => self.close_with(error.into()).await,
            Err(_) => self.close_with(ProtocolError::DeadlineExceeded).await,
        }
    }

    async fn write_until(
        &mut self,
        deadline: Instant,
        response: &wire::Envelope,
    ) -> Result<(), ProtocolError> {
        match timeout_at(deadline, self.codec.write_envelope(response)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(ProtocolError::DeadlineExceeded),
        }
    }

    fn phase_error(&self, requested: Operation) -> ProtocolError {
        match self.phase {
            Phase::New if requested != Operation::Handshake => ProtocolError::HandshakeRequired,
            Phase::New => ProtocolError::AlreadyHandshaken,
            Phase::Ready if requested == Operation::Handshake => ProtocolError::AlreadyHandshaken,
            Phase::Ready => ProtocolError::DuplicateResponse,
            Phase::Waiting(_) => ProtocolError::RequestAlreadyPending,
            Phase::Closed => ProtocolError::Closed,
        }
    }

    async fn close_unexpected<T>(&mut self, expected: &'static str) -> Result<T, ProtocolError> {
        self.close_with(ProtocolError::UnexpectedResponse { expected })
            .await
    }

    async fn close_with<T>(&mut self, error: ProtocolError) -> Result<T, ProtocolError> {
        self.phase = Phase::Closed;
        self.pending = None;
        self.codec.terminate().await;
        Err(error)
    }
}

fn request_budget(budget_millis: u64, maximum: Duration) -> Result<Duration, ProtocolError> {
    let budget = Duration::from_millis(budget_millis);
    if budget.is_zero() || budget > maximum {
        return Err(invalid("budget_millis", "is outside the active bound"));
    }
    Ok(budget)
}

fn decode_scope(scope: Option<Scope>) -> Result<QueryScope, ProtocolError> {
    match scope.ok_or(ProtocolError::MissingField("scope"))? {
        Scope::InstanceId(instance_id) => {
            validate_string("instance_id", &instance_id, false)?;
            Ok(QueryScope::InstanceId(instance_id))
        }
        Scope::Project(project) => {
            validate_string("realm", &project.realm, false)?;
            validate_string("project", &project.project, false)?;
            Ok(QueryScope::Project {
                realm: project.realm,
                project: project.project,
            })
        }
        Scope::Service(service) => {
            validate_string("realm", &service.realm, false)?;
            validate_string("project", &service.project, false)?;
            validate_string("service", &service.service, false)?;
            Ok(QueryScope::Service {
                realm: service.realm,
                project: service.project,
                service: service.service,
            })
        }
        Scope::GlobalDoctor(_) => Ok(QueryScope::GlobalDoctor),
    }
}

fn bind_instance(
    instance: &mut wire::InstanceFact,
    binding: &wire::SessionBinding,
) -> Result<(), ProtocolError> {
    instance
        .provenance
        .as_mut()
        .ok_or(ProtocolError::MissingField("instance.provenance"))?
        .session = Some(binding.clone());
    Ok(())
}

fn build_inventory_responses(
    outcome: &wire::Outcome,
    binding: &wire::SessionBinding,
    instances: Vec<wire::InstanceFact>,
    limits: ProtocolLimits,
) -> Result<Vec<wire::Envelope>, ProtocolError> {
    if instances.len() > limits.max_inventory_instances {
        return Err(ProtocolError::InventoryLimit);
    }
    let mut encoded_bytes = 0_usize;
    let mut hasher = Sha256::new();
    for instance in &instances {
        let encoded = instance.encode_to_vec();
        encoded_bytes = encoded_bytes
            .checked_add(encoded.len())
            .ok_or(ProtocolError::InventoryLimit)?;
        if encoded_bytes > limits.max_inventory_bytes {
            return Err(ProtocolError::InventoryLimit);
        }
        let length = u64::try_from(encoded.len()).map_err(|_| ProtocolError::InventoryLimit)?;
        hasher.update(length.to_be_bytes());
        hasher.update(encoded);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let declared_count =
        u32::try_from(instances.len()).map_err(|_| ProtocolError::InventoryLimit)?;
    let declared_bytes = u64::try_from(encoded_bytes).map_err(|_| ProtocolError::InventoryLimit)?;

    let chunk_template = wire::QueryInstancesChunk {
        outcome: Some(outcome.clone()),
        binding: Some(binding.clone()),
        chunk_index: 0,
        chunk_count: 1,
        instances: Vec::new(),
        final_chunk: true,
        declared_total_count: declared_count,
        declared_total_bytes: declared_bytes,
        final_digest: digest.to_vec(),
    };
    let chunk_base_len = chunk_template.encoded_len();
    let mut current_chunk_len = chunk_base_len;
    let mut chunks: Vec<Vec<wire::InstanceFact>> = vec![Vec::new()];
    for instance in instances {
        let instance_len = instance.encoded_len();
        let entry_len = 1_usize
            .checked_add(varint_len(instance_len))
            .and_then(|length| length.checked_add(instance_len))
            .ok_or(ProtocolError::InventoryLimit)?;
        let Some(current) = chunks.last_mut() else {
            return Err(ProtocolError::InventoryLimit);
        };
        let candidate_len = current_chunk_len
            .checked_add(entry_len)
            .ok_or(ProtocolError::InventoryLimit)?;
        if envelope_len_for_chunk(candidate_len)? > limits.max_frame_bytes {
            if current.is_empty()
                || envelope_len_for_chunk(
                    chunk_base_len
                        .checked_add(entry_len)
                        .ok_or(ProtocolError::InventoryLimit)?,
                )? > limits.max_frame_bytes
            {
                return Err(ProtocolError::InventoryLimit);
            }
            chunks.push(vec![instance]);
            current_chunk_len = chunk_base_len
                .checked_add(entry_len)
                .ok_or(ProtocolError::InventoryLimit)?;
        } else {
            current.push(instance);
            current_chunk_len = candidate_len;
        }
        if chunks.len() > limits.max_inventory_chunks {
            return Err(ProtocolError::InventoryLimit);
        }
    }
    let chunk_count = u32::try_from(chunks.len()).map_err(|_| ProtocolError::InventoryLimit)?;
    let mut responses = Vec::new();
    responses
        .try_reserve_exact(chunks.len())
        .map_err(|_| ProtocolError::InventoryLimit)?;
    for (index, chunk) in chunks.into_iter().enumerate() {
        let final_chunk = index.checked_add(1) == Some(chunk_count as usize);
        let response = envelope(Body::QueryInstancesChunk(wire::QueryInstancesChunk {
            outcome: Some(outcome.clone()),
            binding: Some(binding.clone()),
            chunk_index: u32::try_from(index).map_err(|_| ProtocolError::InventoryLimit)?,
            chunk_count,
            instances: chunk,
            final_chunk,
            declared_total_count: declared_count,
            declared_total_bytes: declared_bytes,
            final_digest: if final_chunk {
                digest.to_vec()
            } else {
                Vec::new()
            },
        }));
        if response.encoded_len() > limits.max_frame_bytes {
            return Err(ProtocolError::InventoryLimit);
        }
        responses.push(response);
    }
    Ok(responses)
}

const fn varint_len(mut value: usize) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

fn envelope_len_for_chunk(chunk_len: usize) -> Result<usize, ProtocolError> {
    // Field 1 protocol varint is two bytes at version 1; field 9's one-byte
    // length-delimited tag then prefixes the encoded chunk.
    3_usize
        .checked_add(varint_len(chunk_len))
        .and_then(|length| length.checked_add(chunk_len))
        .ok_or(ProtocolError::InventoryLimit)
}

const fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Handshake => "handshake_response",
        Operation::Health => "health_response",
        Operation::ResolvePeer => "resolve_peer_response",
        Operation::QueryInstances => "query_instances_chunk",
    }
}

const fn envelope(body: Body) -> wire::Envelope {
    wire::Envelope {
        protocol: PROTOCOL_VERSION,
        body: Some(body),
    }
}

fn take_body(envelope: wire::Envelope) -> Result<Body, ProtocolError> {
    if envelope.protocol != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch {
            received: envelope.protocol,
        });
    }
    envelope.body.ok_or(ProtocolError::MissingField("body"))
}

fn normalize_capabilities(
    capabilities: impl IntoIterator<Item = String>,
) -> Result<Vec<String>, ProtocolError> {
    let mut normalized = BTreeSet::new();
    for capability in capabilities {
        validate_capability(&capability)?;
        if !normalized.insert(capability.clone()) {
            return Err(invalid("capabilities", "contains a duplicate name"));
        }
        if normalized.len() > ABSOLUTE_MAX_CAPABILITIES {
            return Err(invalid("capabilities", "contains too many names"));
        }
    }
    Ok(normalized.into_iter().collect())
}

fn capability_enabled(capabilities: &[String], capability: &str) -> bool {
    capabilities
        .binary_search_by(|candidate| candidate.as_str().cmp(capability))
        .is_ok()
}

fn validate_capability(capability: &str) -> Result<(), ProtocolError> {
    if capability.is_empty() || capability.len() > ABSOLUTE_MAX_CAPABILITY_BYTES {
        return Err(invalid(
            "capability",
            "length is outside the compiled bound",
        ));
    }
    let mut bytes = capability.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(invalid("capability", "has an invalid stable name"));
    }
    Ok(())
}

fn duration_millis(duration: Duration) -> Result<u64, ProtocolError> {
    u64::try_from(duration.as_millis())
        .map_err(|_| invalid("budget_millis", "cannot be represented"))
}

fn encode_scope(scope: QueryScope) -> Result<Scope, ProtocolError> {
    Ok(match scope {
        QueryScope::InstanceId(instance_id) => {
            validate_string("instance_id", &instance_id, false)?;
            Scope::InstanceId(instance_id)
        }
        QueryScope::Project { realm, project } => {
            validate_string("realm", &realm, false)?;
            validate_string("project", &project, false)?;
            Scope::Project(wire::ProjectScope { realm, project })
        }
        QueryScope::Service {
            realm,
            project,
            service,
        } => {
            validate_string("realm", &realm, false)?;
            validate_string("project", &project, false)?;
            validate_string("service", &service, false)?;
            Scope::Service(wire::ServiceScope {
                realm,
                project,
                service,
            })
        }
        QueryScope::GlobalDoctor => Scope::GlobalDoctor(wire::GlobalDoctorScope {}),
    })
}

const fn validate_binding_shape(binding: &wire::SessionBinding) -> Result<(), ProtocolError> {
    if binding.session_nonce.len() != BINDING_BYTES {
        return Err(invalid("session_nonce", "must be 32 bytes"));
    }
    if binding.generation == 0 {
        return Err(invalid("generation", "must be non-zero"));
    }
    if binding.challenge.len() != BINDING_BYTES {
        return Err(invalid("challenge", "must be 32 bytes"));
    }
    Ok(())
}

fn check_digest(
    field: &'static str,
    actual: &[u8],
    expected: &[u8; 32],
) -> Result<(), ProtocolError> {
    if actual != expected {
        return Err(ProtocolError::InvalidField {
            field,
            reason: "does not match authenticated peer",
        });
    }
    Ok(())
}

fn validate_outcome(outcome: Option<&wire::Outcome>) -> Result<(), ProtocolError> {
    let outcome = outcome.ok_or(ProtocolError::MissingField("outcome"))?;
    validate_string_limit(
        "outcome.diagnostic",
        &outcome.diagnostic,
        ABSOLUTE_MAX_DIAGNOSTIC_BYTES,
        true,
    )?;
    let code = wire::OutcomeCode::try_from(outcome.code)
        .map_err(|_| invalid("outcome.code", "is unknown"))?;
    if code == wire::OutcomeCode::Unspecified {
        return Err(invalid("outcome.code", "must be specified"));
    }
    Ok(())
}

fn outcome_code(outcome: Option<&wire::Outcome>) -> Result<wire::OutcomeCode, ProtocolError> {
    let outcome = outcome.ok_or(ProtocolError::MissingField("outcome"))?;
    wire::OutcomeCode::try_from(outcome.code).map_err(|_| invalid("outcome.code", "is unknown"))
}

fn required_outcome(outcome: Option<wire::Outcome>) -> Result<wire::Outcome, ProtocolError> {
    outcome.ok_or(ProtocolError::MissingField("outcome"))
}

fn require_success_payload(
    outcome: Option<&wire::Outcome>,
    payload_present: bool,
    field: &'static str,
) -> Result<(), ProtocolError> {
    let success = outcome_code(outcome)? == wire::OutcomeCode::Ok;
    if success != payload_present {
        return Err(invalid(field, "presence does not match typed outcome"));
    }
    Ok(())
}

fn validate_health(health: &wire::HealthFact) -> Result<(), ProtocolError> {
    validate_enum::<wire::RuntimeKind>("health.runtime", health.runtime)?;
    validate_enum::<wire::RuntimeMode>("health.runtime_mode", health.runtime_mode)?;
    validate_enum::<wire::CgroupMode>("health.cgroup_mode", health.cgroup_mode)?;
    validate_string(
        "health.diagnostic_version",
        &health.diagnostic_version,
        false,
    )?;
    let missing = normalize_capabilities(health.missing_capabilities.clone())?;
    if missing != health.missing_capabilities {
        return Err(invalid(
            "health.missing_capabilities",
            "must be sorted and unique",
        ));
    }
    Ok(())
}

fn validate_pinned_peer(peer: &wire::PinnedPeer) -> Result<(), ProtocolError> {
    if peer.pid == 0 {
        return Err(invalid("pinned_peer.pid", "must be non-zero"));
    }
    if peer.start_time_ticks == 0 {
        return Err(invalid("pinned_peer.start_time_ticks", "must be non-zero"));
    }
    validate_string("pinned_peer.cgroup", &peer.cgroup, false)?;
    let namespaces = peer
        .namespaces
        .as_ref()
        .ok_or(ProtocolError::MissingField("pinned_peer.namespaces"))?;
    if [
        namespaces.user,
        namespaces.pid,
        namespaces.mount,
        namespaces.network,
        namespaces.uts,
        namespaces.ipc,
        namespaces.cgroup,
    ]
    .contains(&0)
    {
        return Err(invalid(
            "pinned_peer.namespaces",
            "all required inode constraints must be non-zero",
        ));
    }
    Ok(())
}

fn validate_instance(
    instance: &wire::InstanceFact,
    binding: &wire::SessionBinding,
) -> Result<(), ProtocolError> {
    let provenance = instance
        .provenance
        .as_ref()
        .ok_or(ProtocolError::MissingField("instance.provenance"))?;
    let session = provenance
        .session
        .as_ref()
        .ok_or(ProtocolError::MissingField("instance.provenance.session"))?;
    if session != binding {
        return Err(ProtocolError::StaleFact);
    }
    validate_string("instance.provenance.realm", &provenance.realm, false)?;
    validate_enum::<wire::RuntimeKind>("instance.provenance.provider", provenance.provider)?;
    if provenance.observed_unix_millis == 0 {
        return Err(invalid(
            "instance.provenance.observed_unix_millis",
            "must be non-zero",
        ));
    }
    validate_enum::<wire::RuntimeKind>("instance.runtime", instance.runtime)?;
    if instance.runtime != provenance.provider {
        return Err(invalid(
            "instance.runtime",
            "does not match provenance provider",
        ));
    }
    validate_string("instance.instance_id", &instance.instance_id, false)?;
    validate_pinned_peer(
        instance
            .observed_peer
            .as_ref()
            .ok_or(ProtocolError::MissingField("instance.observed_peer"))?,
    )?;
    validate_id_map("instance.uid_map", &instance.uid_map)?;
    validate_id_map("instance.gid_map", &instance.gid_map)?;
    if let Some(compose) = instance.compose.as_ref() {
        validate_string("instance.compose.project", &compose.project, false)?;
        validate_string("instance.compose.service", &compose.service, false)?;
    }
    validate_image(
        instance
            .image
            .as_ref()
            .ok_or(ProtocolError::MissingField("instance.image"))?,
    )?;
    if instance.mounts.len() > ABSOLUTE_MAX_MOUNTS_PER_INSTANCE {
        return Err(invalid("instance.mounts", "exceeds compiled count bound"));
    }
    for mount in &instance.mounts {
        validate_mount(mount)?;
    }
    validate_enum::<wire::LifecycleState>("instance.lifecycle", instance.lifecycle)?;
    validate_string(
        "instance.diagnostic_runtime_name",
        &instance.diagnostic_runtime_name,
        true,
    )
}

fn validate_id_map(field: &'static str, ranges: &[wire::IdMapRange]) -> Result<(), ProtocolError> {
    if ranges.len() > ABSOLUTE_MAX_ID_MAP_RANGES {
        return Err(invalid(field, "exceeds compiled count bound"));
    }
    if ranges.iter().any(|range| range.length == 0) {
        return Err(invalid(field, "contains a zero-length range"));
    }
    Ok(())
}

fn validate_image(image: &wire::ImageFact) -> Result<(), ProtocolError> {
    if let Some(index) = image.index_digest.as_deref() {
        validate_sha256("instance.image.index_digest", index)?;
    }
    validate_sha256("instance.image.manifest_digest", &image.manifest_digest)?;
    validate_sha256("instance.image.config_digest", &image.config_digest)?;
    validate_string("instance.image.os", &image.os, false)?;
    validate_string("instance.image.architecture", &image.architecture, false)?;
    if let Some(variant) = image.variant.as_deref() {
        validate_string("instance.image.variant", variant, false)?;
    }
    Ok(())
}

fn validate_mount(mount: &wire::MountFact) -> Result<(), ProtocolError> {
    let kind = validate_enum::<wire::MountKind>("instance.mount.kind", mount.kind)?;
    validate_enum::<wire::MountPropagation>("instance.mount.propagation", mount.propagation)?;
    validate_string(
        "instance.mount.container_destination",
        &mount.container_destination,
        false,
    )?;
    if kind != wire::MountKind::Tmpfs {
        validate_string("instance.mount.host_source", &mount.host_source, false)?;
    } else if !mount.host_source.is_empty() {
        return Err(invalid(
            "instance.mount.host_source",
            "must be empty for tmpfs",
        ));
    }
    if kind != wire::MountKind::Tmpfs
        && (mount.tmpfs_size_bytes.is_some()
            || mount.tmpfs_mode.is_some()
            || mount.tmpfs_nodev
            || mount.tmpfs_nosuid
            || mount.tmpfs_noexec
            || mount.tmpfs_noswap)
    {
        return Err(invalid(
            "instance.mount.tmpfs_options",
            "are valid only for tmpfs",
        ));
    }
    Ok(())
}

fn project_mount_security(instance: &mut wire::InstanceFact, enabled: bool) {
    if enabled {
        return;
    }
    for mount in &mut instance.mounts {
        mount.tmpfs_nodev = false;
        mount.tmpfs_nosuid = false;
        mount.tmpfs_noexec = false;
        mount.tmpfs_noswap = false;
    }
}

fn validate_mount_security_negotiation(
    instance: &wire::InstanceFact,
    enabled: bool,
) -> Result<(), ProtocolError> {
    if !enabled
        && instance.mounts.iter().any(|mount| {
            mount.tmpfs_nodev || mount.tmpfs_nosuid || mount.tmpfs_noexec || mount.tmpfs_noswap
        })
    {
        return Err(invalid(
            "instance.mount.tmpfs_security",
            "requires the mount-security capability",
        ));
    }
    Ok(())
}

fn validate_sha256(field: &'static str, digest: &str) -> Result<(), ProtocolError> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(invalid(field, "must use sha256"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid(field, "must contain 64 lowercase hex digits"));
    }
    Ok(())
}

fn validate_enum<E>(field: &'static str, value: i32) -> Result<E, ProtocolError>
where
    E: TryFrom<i32> + PartialEq + Default,
{
    let value = E::try_from(value).map_err(|_| invalid(field, "is unknown"))?;
    if value == E::default() {
        return Err(invalid(field, "must be specified"));
    }
    Ok(value)
}

fn validate_string(
    field: &'static str,
    value: &str,
    allow_empty: bool,
) -> Result<(), ProtocolError> {
    validate_string_limit(field, value, ABSOLUTE_MAX_STRING_BYTES, allow_empty)
}

fn validate_string_limit(
    field: &'static str,
    value: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), ProtocolError> {
    if (!allow_empty && value.is_empty()) || value.len() > maximum || value.contains('\0') {
        return Err(invalid(field, "is empty, overlong, or contains NUL"));
    }
    Ok(())
}

struct InventoryAccumulator {
    limits: ProtocolLimits,
    mount_security_enabled: bool,
    next_chunk: usize,
    declared_chunks: Option<usize>,
    declared_count: Option<usize>,
    declared_bytes: Option<usize>,
    encoded_bytes: usize,
    instances: Vec<wire::InstanceFact>,
    outcome: Option<wire::Outcome>,
    hasher: Sha256,
}

impl InventoryAccumulator {
    fn new(limits: ProtocolLimits, mount_security_enabled: bool) -> Self {
        Self {
            limits,
            mount_security_enabled,
            next_chunk: 0,
            declared_chunks: None,
            declared_count: None,
            declared_bytes: None,
            encoded_bytes: 0,
            instances: Vec::new(),
            outcome: None,
            hasher: Sha256::new(),
        }
    }

    // Keeping the sequence, totals, content, and commitment checks adjacent
    // makes this security boundary easier to audit.
    #[allow(clippy::too_many_lines)]
    fn push(
        &mut self,
        chunk: wire::QueryInstancesChunk,
        binding: &wire::SessionBinding,
    ) -> Result<Option<InventoryResult>, ProtocolError> {
        validate_outcome(chunk.outcome.as_ref())?;
        let chunk_index = chunk.chunk_index as usize;
        let chunk_count = chunk.chunk_count as usize;
        if chunk_index != self.next_chunk {
            return Err(if chunk_index < self.next_chunk {
                ProtocolError::DuplicateResponse
            } else {
                ProtocolError::InventoryOrder {
                    expected: self.next_chunk,
                    received: chunk_index,
                }
            });
        }
        if chunk_count == 0 || chunk_count > self.limits.max_inventory_chunks {
            return Err(invalid("chunk_count", "is outside the active bound"));
        }
        if self.declared_chunks.get_or_insert(chunk_count) != &chunk_count {
            return Err(ProtocolError::InventoryTotalsChanged);
        }
        let declared_count = chunk.declared_total_count as usize;
        let declared_bytes = usize::try_from(chunk.declared_total_bytes)
            .map_err(|_| invalid("declared_total_bytes", "cannot be represented"))?;
        if declared_count > self.limits.max_inventory_instances
            || declared_bytes > self.limits.max_inventory_bytes
        {
            return Err(ProtocolError::InventoryLimit);
        }
        if self.declared_count.get_or_insert(declared_count) != &declared_count
            || self.declared_bytes.get_or_insert(declared_bytes) != &declared_bytes
        {
            return Err(ProtocolError::InventoryTotalsChanged);
        }
        if let Some(outcome) = self.outcome.as_ref() {
            if outcome
                != chunk
                    .outcome
                    .as_ref()
                    .ok_or(ProtocolError::MissingField("outcome"))?
            {
                return Err(ProtocolError::InventoryOutcomeChanged);
            }
        } else {
            self.outcome.clone_from(&chunk.outcome);
        }
        let code = outcome_code(chunk.outcome.as_ref())?;
        if code != wire::OutcomeCode::Ok && (!chunk.instances.is_empty() || chunk_count != 1) {
            return Err(invalid(
                "query_instances_chunk",
                "non-success outcome must be one empty final chunk",
            ));
        }
        for instance in &chunk.instances {
            validate_instance(instance, binding)?;
            validate_mount_security_negotiation(instance, self.mount_security_enabled)?;
            let encoded_len = instance.encoded_len();
            self.encoded_bytes = self
                .encoded_bytes
                .checked_add(encoded_len)
                .ok_or(ProtocolError::InventoryLimit)?;
            if self.encoded_bytes > self.limits.max_inventory_bytes {
                return Err(ProtocolError::InventoryLimit);
            }
            let length = u64::try_from(encoded_len).map_err(|_| ProtocolError::InventoryLimit)?;
            self.hasher.update(length.to_be_bytes());
            let mut encoded = Vec::new();
            encoded
                .try_reserve_exact(encoded_len)
                .map_err(|_| ProtocolError::InventoryLimit)?;
            instance
                .encode(&mut encoded)
                .map_err(ProtocolError::DigestEncoding)?;
            self.hasher.update(encoded);
        }
        self.instances
            .try_reserve(chunk.instances.len())
            .map_err(|_| ProtocolError::InventoryLimit)?;
        self.instances.extend(chunk.instances);
        if self.instances.len() > self.limits.max_inventory_instances {
            return Err(ProtocolError::InventoryLimit);
        }
        let final_expected = chunk_index.checked_add(1) == Some(chunk_count);
        if chunk.final_chunk != final_expected {
            return Err(ProtocolError::InventoryFinalFlag);
        }
        if !chunk.final_chunk {
            if !chunk.final_digest.is_empty() {
                return Err(invalid(
                    "final_digest",
                    "must occur only on the final chunk",
                ));
            }
            self.next_chunk = self
                .next_chunk
                .checked_add(1)
                .ok_or(ProtocolError::InventoryLimit)?;
            return Ok(None);
        }
        if self.instances.len() != declared_count || self.encoded_bytes != declared_bytes {
            return Err(ProtocolError::InventoryTotalsMismatch);
        }
        let digest: [u8; 32] = self.hasher.clone().finalize().into();
        if chunk.final_digest != digest {
            return Err(ProtocolError::InventoryDigestMismatch);
        }
        Ok(Some(InventoryResult {
            outcome: self
                .outcome
                .take()
                .ok_or(ProtocolError::MissingField("outcome"))?,
            instances: std::mem::take(&mut self.instances),
            digest,
        }))
    }
}

const fn invalid(field: &'static str, reason: &'static str) -> ProtocolError {
    ProtocolError::InvalidField { field, reason }
}

/// Typed session, validation, or remote outcome failure.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Framing or protobuf failure; the session is terminated.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// Secure random generation failed before an operation began.
    #[error("could not generate attestor session binding: {0}")]
    Random(getrandom::Error),
    /// The mandatory handshake has not completed.
    #[error("attestor handshake is required")]
    HandshakeRequired,
    /// A handshake was attempted more than once.
    #[error("attestor handshake already completed or started")]
    AlreadyHandshaken,
    /// A second request was attempted while one was pending.
    #[error("one attestor request is already pending")]
    RequestAlreadyPending,
    /// The session was terminated and cannot be reused.
    #[error("attestor session is closed")]
    Closed,
    /// The peer used a protocol integer other than exactly 1.
    #[error("attestor protocol version mismatch: received {received}, required 1")]
    VersionMismatch {
        /// Peer-supplied exact protocol integer.
        received: u32,
    },
    /// A required protobuf field was absent.
    #[error("attestor message is missing `{0}`")]
    MissingField(&'static str),
    /// A field violated a closed type or compile-time ceiling.
    #[error("invalid attestor field `{field}`: {reason}")]
    InvalidField {
        /// Field path.
        field: &'static str,
        /// Stable diagnostic.
        reason: &'static str,
    },
    /// The response operation did not match the one serial pending request.
    #[error("unexpected attestor response; expected `{expected}`")]
    UnexpectedResponse {
        /// Expected response body.
        expected: &'static str,
    },
    /// A response or fact belongs to an old nonce or generation.
    #[error("stale attestor session binding")]
    StaleSession,
    /// A response belongs to another request on the same session.
    #[error("stale attestor request challenge")]
    StaleChallenge,
    /// A fact was not bound to the containing response.
    #[error("stale attestor fact binding")]
    StaleFact,
    /// The handshake did not echo independently authenticated peer bindings.
    #[error("attestor peer binding mismatch")]
    PeerBindingMismatch,
    /// The attestor rejected the handshake with a typed outcome.
    #[error("attestor handshake rejected")]
    HandshakeRejected {
        /// Optional malformed response outcome retained for diagnostics.
        outcome: Option<wire::Outcome>,
    },
    /// A configuration-required named capability is unsupported.
    #[error("attestor does not support required capability `{0}`")]
    MissingCapability(String),
    /// The original operation deadline expired; the session is terminated.
    #[error("attestor request deadline exceeded")]
    DeadlineExceeded,
    /// The caller's budget elapsed before the request was dispatched; the
    /// session stays open because no wire traffic occurred.
    #[error("attestor request budget exhausted before dispatch")]
    BudgetExhausted,
    /// A response was accepted after its operation had already completed.
    #[error("duplicate attestor response")]
    DuplicateResponse,
    /// The broker reused the preceding serial request challenge.
    #[error("duplicate attestor request challenge")]
    DuplicateRequest,
    /// Inventory chunks skipped or reordered an index.
    #[error("attestor inventory chunk out of order: expected {expected}, received {received}")]
    InventoryOrder {
        /// Next required zero-based chunk index.
        expected: usize,
        /// Received zero-based chunk index.
        received: usize,
    },
    /// Declared inventory totals changed between chunks.
    #[error("attestor inventory declared totals changed")]
    InventoryTotalsChanged,
    /// Typed outcomes changed between inventory chunks.
    #[error("attestor inventory outcome changed")]
    InventoryOutcomeChanged,
    /// Inventory count, aggregate bytes, or chunks exceeded active limits.
    #[error("attestor inventory exceeded an active bound")]
    InventoryLimit,
    /// Final-chunk placement disagreed with the declared chunk count.
    #[error("attestor inventory final-chunk flag is inconsistent")]
    InventoryFinalFlag,
    /// Actual inventory count or bytes disagreed with declared totals.
    #[error("attestor inventory totals do not match its contents")]
    InventoryTotalsMismatch,
    /// The final inventory digest did not match canonical facts.
    #[error("attestor inventory digest mismatch")]
    InventoryDigestMismatch,
    /// Encoding a normalized fact into the inventory digest failed.
    #[error("could not encode attestor fact digest: {0}")]
    DigestEncoding(prost::EncodeError),
}

// ---------------------------------------------------------------------------
// Broker-side measurement-helper client.
// ---------------------------------------------------------------------------

/// Absolute maximum bytes hashed from one measured executable descriptor.
pub const ABSOLUTE_MAX_MEASURED_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;

/// Bytes read per bounded hashing step.
const EXECUTABLE_HASH_CHUNK_BYTES: usize = 64 * 1024;

/// The helper-policy pin the broker's protected measurement authority binds to
/// one session's authority generation.
///
/// The request names this exact installed identity and generation, and the
/// helper's echo must match it exactly: an echo of the broker generation alone
/// never establishes helper-policy freshness. Old serving sessions and
/// candidate qualifiers each carry their own pin, so one helper endpoint
/// serves both installed generations concurrently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedHelperPolicy {
    /// Allowlisted realm name.
    pub realm: String,
    /// Exact required installed helper-policy identity.
    pub policy_identity: String,
    /// Exact required installed helper-policy generation.
    pub policy_generation: NonZeroU64,
    /// Broker configuration generation at the time of the request.
    pub broker_generation: u64,
}

/// One fully cross-checked helper measurement of a connected attestor stream.
///
/// Both descriptors were type-checked and associated with the same peer the
/// broker independently authenticated on its own stream end. The digest covers
/// the complete executable bytes read through the helper-opened descriptor.
/// Neither descriptor may be cached for a future connection: the value binds
/// to exactly one session epoch.
#[derive(Debug)]
pub struct VerifiedMeasurement {
    /// The bounded record the helper bound to the stream's socket cookie.
    pub record: MeasuredRecord,
    /// The epoch-owned peer pidfd (first response descriptor).
    pub pidfd: OwnedFd,
    /// The measured executable (second response descriptor).
    pub executable: OwnedFd,
    /// Full-file SHA-256 of the executable descriptor's bytes; feeds the exact
    /// `ArtifactRequirement` for `ReleaseAdmission::begin_preflight`.
    pub executable_sha256: [u8; 32],
}

/// Typed, fail-closed broker-side measurement failure.
#[derive(Debug, Error)]
pub enum MeasurementError {
    /// Sending the request or receiving the response failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The helper endpoint closed before answering; retry after reconnect.
    #[error("measurement helper closed before answering")]
    HelperClosed,
    /// The kernel flagged the response datagram as clipped.
    #[error("measurement helper response exceeded its bound")]
    OversizedResponse,
    /// The kernel dropped ancillary descriptors from the response.
    #[error("measurement helper response ancillary data was truncated")]
    AncillaryTruncated,
    /// The request or response record violated the fixed wire contract.
    #[error("measurement helper wire record invalid: {0}")]
    Wire(#[from] WireError),
    /// The helper rejected this request with a typed disclosure-safe code.
    #[error("measurement helper rejected the request")]
    Rejected {
        /// Typed helper rejection code.
        code: RejectCode,
    },
    /// A rejection record illegally carried descriptors.
    #[error("measurement helper rejection carried descriptors")]
    RejectionCarriedDescriptors,
    /// The response does not answer this request (replayed or foreign nonce).
    #[error("measurement helper response nonce does not answer this request")]
    StaleResponse,
    /// The response echoed another broker generation.
    #[error("measurement helper response echoed a foreign broker generation")]
    GenerationEchoMismatch,
    /// The response echoed another realm.
    #[error("measurement helper response echoed a foreign realm")]
    RealmEchoMismatch,
    /// The applied helper policy is not the pinned identity and generation.
    #[error("measurement helper applied a policy other than the pinned one")]
    PolicyPinMismatch,
    /// The record is bound to a cookie other than this stream's own cookie.
    #[error("measured record cookie does not match this stream")]
    CookieMismatch,
    /// The record names peer credentials other than the broker's own
    /// independently captured `SO_PEERCRED` for the same stream.
    #[error("measured record peer credentials do not match this stream")]
    PeerCredentialsMismatch,
    /// The measured response did not carry exactly two descriptors.
    #[error("measured response carried {received} descriptors; required 2")]
    DescriptorCount {
        /// Received descriptor count.
        received: usize,
    },
    /// The first response descriptor is not a process descriptor.
    #[error("measured response first descriptor is not a pidfd")]
    PidfdType,
    /// The pidfd names a process other than the record's peer.
    #[error("measured pidfd is not associated with the record's peer")]
    PidfdAssociation,
    /// The nonblocking pidfd exit poll itself failed.
    #[error("measured pidfd could not be polled")]
    PidfdPollFailed,
    /// The measured peer already exited.
    #[error("measured peer process exited")]
    PeerExited,
    /// The second response descriptor is not a regular file.
    #[error("measured response second descriptor is not a regular file")]
    ExecutableType,
    /// The executable descriptor's device/inode differ from the record.
    #[error("measured executable identity does not match the record")]
    ExecutableIdentityMismatch,
    /// The executable exceeds the compiled hashing ceiling.
    #[error("measured executable exceeds {ABSOLUTE_MAX_MEASURED_EXECUTABLE_BYTES} bytes")]
    ExecutableTooLarge,
    /// Reading the executable bytes for hashing failed.
    #[error("measured executable read failed: {0}")]
    ExecutableRead(std::io::Error),
    /// Secure random generation failed before the request was sent.
    #[error("could not generate a measurement nonce: {0}")]
    Random(getrandom::Error),
}

/// Request one measurement of a connected attestor control stream and
/// cross-check the complete response against broker-held facts.
///
/// One `SCM_RIGHTS` duplicate of `stream` travels with the bounded request;
/// the request carries no PID, path, digest, unit, or UID. Every check the
/// helper applies comes from its own installed allowlist generation named by
/// `pin`. The broker then independently verifies, in order: the exact nonce
/// echo, the broker-generation/realm echoes, the pinned helper-policy
/// identity and generation, the stream's own `SO_COOKIE`, its own
/// `SO_PEERCRED` capture (`expected_peer`), the exact descriptor count and
/// types, the pidfd's association with the record's peer, that the peer has
/// not already exited, the executable's device/inode identity, and finally
/// hashes the executable through the returned descriptor.
///
/// The call performs blocking I/O on `helper`; drive it from a blocking
/// context. The caller owns retry policy across helper outage and restart.
///
/// # Errors
///
/// Returns a typed [`MeasurementError`]; every failure is fail-closed and
/// leaves nothing cached.
pub fn measure_attestor_stream(
    helper: &HelperConnection,
    stream: BorrowedFd<'_>,
    expected_peer: PeerCredentials,
    pin: &PinnedHelperPolicy,
) -> Result<VerifiedMeasurement, MeasurementError> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(MeasurementError::Random)?;
    let request = MeasurementRequest {
        protocol: HELPER_PROTOCOL_VERSION,
        broker_generation: pin.broker_generation,
        policy_generation: pin.policy_generation,
        nonce,
        realm: pin.realm.clone(),
        policy_identity: pin.policy_identity.clone(),
    };
    let bytes = request.encode()?;
    helper.send(&bytes, &[stream])?;
    let datagram = helper
        .recv_response()?
        .ok_or(MeasurementError::HelperClosed)?;
    if datagram.ancillary_truncated {
        return Err(MeasurementError::AncillaryTruncated);
    }
    if datagram.oversized {
        return Err(MeasurementError::OversizedResponse);
    }
    let descriptors = datagram.descriptors;
    match HelperResponse::decode(&datagram.bytes)? {
        HelperResponse::Rejected(rejection) => {
            if !descriptors.is_empty() {
                return Err(MeasurementError::RejectionCarriedDescriptors);
            }
            check_rejection_echo(&rejection, &nonce)?;
            Err(MeasurementError::Rejected {
                code: rejection.code,
            })
        }
        HelperResponse::Measured(record) => {
            verify_record_binding(&record, stream, expected_peer, pin, &nonce)?;
            let (pidfd, executable) = bind_descriptors(descriptors, &record)?;
            let executable_sha256 = hash_executable(executable.as_fd())?;
            Ok(VerifiedMeasurement {
                record,
                pidfd,
                executable,
                executable_sha256,
            })
        }
    }
}

/// Require a rejection to answer this request.
///
/// Pre-decode rejections (a request the helper could not read) legitimately
/// echo a zeroed identity; every post-decode rejection must echo the exact
/// nonce or it answers some other request.
fn check_rejection_echo(
    rejection: &super::helper::wire::RejectionRecord,
    nonce: &[u8; NONCE_BYTES],
) -> Result<(), MeasurementError> {
    if rejection.nonce == *nonce {
        return Ok(());
    }
    let pre_decode = matches!(
        rejection.code,
        RejectCode::MalformedRequest
            | RejectCode::UnsupportedProtocol
            | RejectCode::AncillaryTruncated
    );
    if pre_decode && rejection.nonce == [0_u8; NONCE_BYTES] && rejection.broker_generation == 0 {
        return Ok(());
    }
    Err(MeasurementError::StaleResponse)
}

/// Cross-check the measured record against every broker-held fact.
fn verify_record_binding(
    record: &MeasuredRecord,
    stream: BorrowedFd<'_>,
    expected_peer: PeerCredentials,
    pin: &PinnedHelperPolicy,
    nonce: &[u8; NONCE_BYTES],
) -> Result<(), MeasurementError> {
    if record.nonce != *nonce {
        return Err(MeasurementError::StaleResponse);
    }
    if record.broker_generation != pin.broker_generation {
        return Err(MeasurementError::GenerationEchoMismatch);
    }
    if record.realm != pin.realm {
        return Err(MeasurementError::RealmEchoMismatch);
    }
    if record.policy_identity != pin.policy_identity
        || record.policy_generation != pin.policy_generation
    {
        return Err(MeasurementError::PolicyPinMismatch);
    }
    let cookie = sockopt::socket_cookie(stream).map_err(|_| MeasurementError::CookieMismatch)?;
    if record.cookie != cookie {
        return Err(MeasurementError::CookieMismatch);
    }
    let expected_pid = expected_peer
        .pid
        .ok_or(MeasurementError::PeerCredentialsMismatch)?;
    if record.peer_pid != expected_pid
        || record.peer_uid != expected_peer.uid
        || record.peer_gid != expected_peer.gid
    {
        return Err(MeasurementError::PeerCredentialsMismatch);
    }
    Ok(())
}

/// Take exactly the pidfd and executable descriptors and verify each type and
/// its association with the record's peer.
fn bind_descriptors(
    descriptors: Vec<OwnedFd>,
    record: &MeasuredRecord,
) -> Result<(OwnedFd, OwnedFd), MeasurementError> {
    let received = descriptors.len();
    let mut iterator = descriptors.into_iter();
    let (Some(pidfd), Some(executable), None) = (iterator.next(), iterator.next(), iterator.next())
    else {
        return Err(MeasurementError::DescriptorCount { received });
    };
    verify_pidfd_association(pidfd.as_fd(), record.peer_pid)?;
    if pidfd_has_exited(pidfd.as_fd()).map_err(|()| MeasurementError::PidfdPollFailed)? {
        return Err(MeasurementError::PeerExited);
    }
    verify_executable_identity(executable.as_fd(), record)?;
    Ok((pidfd, executable))
}

/// Verify the descriptor is a pidfd whose process is exactly `peer_pid`.
///
/// A pidfd's `fdinfo` carries a `Pid:` field; no other descriptor kind does.
/// A reaped process reports `-1` and a process outside this PID namespace
/// reports `0`; both fail closed.
fn verify_pidfd_association(pidfd: BorrowedFd<'_>, peer_pid: u32) -> Result<(), MeasurementError> {
    let path = format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd());
    let info = std::fs::read_to_string(path).map_err(|_| MeasurementError::PidfdType)?;
    let value = info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .ok_or(MeasurementError::PidfdType)?;
    let pid: i64 = value
        .trim()
        .parse()
        .map_err(|_| MeasurementError::PidfdType)?;
    if pid == -1 {
        return Err(MeasurementError::PeerExited);
    }
    if u32::try_from(pid).ok() != Some(peer_pid) || pid == 0 {
        return Err(MeasurementError::PidfdAssociation);
    }
    Ok(())
}

/// Nonblocking exit poll of one pidfd.
///
/// A pidfd polls readable exactly when its process has exited. The zero
/// timeout keeps this callable at the publication linearization point while
/// the registry mutex is held.
fn pidfd_has_exited(pidfd: BorrowedFd<'_>) -> Result<bool, ()> {
    let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
    let zero = rustix::event::Timespec::default();
    let ready = rustix::event::poll(&mut fds, Some(&zero)).map_err(|_| ())?;
    if ready == 0 {
        return Ok(false);
    }
    let Some(fd) = fds.first() else {
        return Err(());
    };
    let events = fd.revents();
    if events.intersects(PollFlags::NVAL | PollFlags::ERR) {
        return Err(());
    }
    Ok(events.intersects(PollFlags::IN | PollFlags::HUP))
}

/// Verify the executable descriptor is a regular file with the record's exact
/// device and inode identity, within the hashing ceiling.
fn verify_executable_identity(
    executable: BorrowedFd<'_>,
    record: &MeasuredRecord,
) -> Result<(), MeasurementError> {
    let stat = rustix::fs::fstat(executable).map_err(|_| MeasurementError::ExecutableType)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(MeasurementError::ExecutableType);
    }
    if stat_device(&stat) != record.executable_device || stat.st_ino != record.executable_inode {
        return Err(MeasurementError::ExecutableIdentityMismatch);
    }
    if u64::try_from(stat.st_size).unwrap_or(u64::MAX) > ABSOLUTE_MAX_MEASURED_EXECUTABLE_BYTES {
        return Err(MeasurementError::ExecutableTooLarge);
    }
    Ok(())
}

#[allow(clippy::useless_conversion)] // `st_dev` width is platform-dependent.
fn stat_device(stat: &rustix::fs::Stat) -> u64 {
    u64::from(stat.st_dev)
}

/// Hash the complete executable bytes through the helper-opened descriptor.
///
/// Positioned reads leave the shared file offset untouched and are bounded by
/// [`ABSOLUTE_MAX_MEASURED_EXECUTABLE_BYTES`] even if the file grows.
fn hash_executable(executable: BorrowedFd<'_>) -> Result<[u8; 32], MeasurementError> {
    let mut hasher = Sha256::new();
    let mut offset: u64 = 0;
    let mut buffer = vec![0_u8; EXECUTABLE_HASH_CHUNK_BYTES];
    loop {
        let read = rustix::io::pread(executable, buffer.as_mut_slice(), offset)
            .map_err(|errno| MeasurementError::ExecutableRead(errno.into()))?;
        if read == 0 {
            return Ok(hasher.finalize().into());
        }
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| MeasurementError::ExecutableRead(std::io::Error::other("short read")))?;
        hasher.update(chunk);
        offset = offset.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if offset > ABSOLUTE_MAX_MEASURED_EXECUTABLE_BYTES {
            return Err(MeasurementError::ExecutableTooLarge);
        }
    }
}

// ---------------------------------------------------------------------------
// Pidfd-guarded publication linearization.
// ---------------------------------------------------------------------------

/// The complete pinned token naming one authenticated session epoch.
///
/// Publication and every later fact use compare all six dimensions; any
/// mismatch is treated as another session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionPin {
    /// Accepted broker configuration generation at authentication.
    pub configuration_generation: u64,
    /// Accepted realm entry generation.
    pub entry_generation: u64,
    /// Tombstone-derived realm revision.
    pub realm_revision: u64,
    /// Session epoch owning the pidfd.
    pub session_epoch: u64,
    /// Session-handle identity.
    pub session_handle: u64,
    /// Actor version advanced by supervisor mutations.
    pub actor_version: u64,
}

/// Why a guarded session stopped accepting publication and use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidationCause {
    /// The epoch-owned pidfd reported the peer process exited.
    PeerExited,
    /// A publication attempt carried a token other than the pinned one.
    PinMismatch,
    /// Session close or drain cancelled the epoch.
    Cancelled,
}

/// Why one publication attempt was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationRejection {
    /// The session was already invalidated.
    Invalidated(InvalidationCause),
    /// A fact was already published for this epoch.
    AlreadyPublished,
    /// The nonblocking poll found the peer exited; the session is now
    /// invalidated.
    PeerExited,
    /// The complete token comparison failed; the session is now invalidated.
    PinMismatch,
}

/// A rejected publication carrying its fact back out of the lock scope.
///
/// Returning the fact lets the caller drop it (releasing, for example, an
/// active release-admission reference) outside the registry mutex.
#[derive(Debug)]
pub struct RejectedPublication<F> {
    /// Typed rejection.
    pub rejection: PublicationRejection,
    /// The fact that lost the linearization race.
    pub fact: F,
}

/// Why a published fact could not be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactUseError {
    /// The session was invalidated.
    Invalidated(InvalidationCause),
    /// The caller's token is not the pinned one.
    PinMismatch,
    /// No fact was published for this epoch.
    NotPublished,
}

struct GuardedSessionState<F> {
    pidfd: OwnedFd,
    pin: SessionPin,
    published: Option<F>,
    invalidated: Option<InvalidationCause>,
}

/// One session epoch's pidfd monitor and publication linearization point.
///
/// The single internal mutex is the registry mutex from the design: the
/// response path publishes under it, the monitor invalidates under it, and
/// every later fact use rechecks the pinned token under it. Exactly one
/// publication or invalidation wins; buffered response state that loses the
/// race never becomes authoritative. No I/O beyond the nonblocking pidfd poll,
/// no await, and no logging happens while the mutex is held; invalidation and
/// cancellation hand the fact back so its drop runs outside the lock.
///
/// A replacement epoch is a fresh value with a fresh pin: a detached monitor
/// still holding this value can never invalidate the replacement.
pub struct PidfdGuardedSession<F> {
    state: Arc<Mutex<GuardedSessionState<F>>>,
}

impl<F> Clone for PidfdGuardedSession<F> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<F> fmt::Debug for PidfdGuardedSession<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PidfdGuardedSession")
    }
}

impl<F> PidfdGuardedSession<F> {
    /// Bind one epoch-owned pidfd to its complete session pin.
    #[must_use]
    pub fn new(pidfd: OwnedFd, pin: SessionPin) -> Self {
        Self {
            state: Arc::new(Mutex::new(GuardedSessionState {
                pidfd,
                pin,
                published: None,
                invalidated: None,
            })),
        }
    }

    /// Atomically publish the completed fact for this epoch.
    ///
    /// Under the registry mutex this performs the nonblocking exit poll of the
    /// epoch-owned pidfd and the complete token comparison, then either
    /// publishes or invalidates the session. Decode and validation of response
    /// bytes must already have happened outside the lock into the
    /// non-authoritative `fact`.
    ///
    /// # Errors
    ///
    /// Returns [`RejectedPublication`] carrying `fact` back for out-of-lock
    /// disposal when the session is invalidated, already published, exited, or
    /// pinned to another token.
    pub fn publish(&self, pin: SessionPin, fact: F) -> Result<(), RejectedPublication<F>> {
        let mut state = self.lock_state();
        if let Some(cause) = state.invalidated {
            drop(state);
            return Err(RejectedPublication {
                rejection: PublicationRejection::Invalidated(cause),
                fact,
            });
        }
        if state.published.is_some() {
            drop(state);
            return Err(RejectedPublication {
                rejection: PublicationRejection::AlreadyPublished,
                fact,
            });
        }
        if pidfd_has_exited(state.pidfd.as_fd()).unwrap_or(true) {
            state.invalidated = Some(InvalidationCause::PeerExited);
            drop(state);
            return Err(RejectedPublication {
                rejection: PublicationRejection::PeerExited,
                fact,
            });
        }
        if pin != state.pin {
            state.invalidated = Some(InvalidationCause::PinMismatch);
            drop(state);
            return Err(RejectedPublication {
                rejection: PublicationRejection::PinMismatch,
                fact,
            });
        }
        state.published = Some(fact);
        drop(state);
        Ok(())
    }

    /// Record the peer's exit under the registry mutex.
    ///
    /// Exit ordered after publication is ordered after that completed fact:
    /// the fact is handed back for out-of-lock disposal and every later use
    /// rejects. Idempotent; a second observation (or one after cancellation)
    /// returns `None` and changes nothing.
    #[must_use = "drop the returned fact outside the registry mutex"]
    pub fn observe_exit(&self) -> Option<F> {
        let mut state = self.lock_state();
        if state.invalidated.is_none() {
            state.invalidated = Some(InvalidationCause::PeerExited);
        }
        let fact = state.published.take();
        drop(state);
        fact
    }

    /// Cancel this epoch at session close or drain.
    ///
    /// Cancellation is owned by the session lifecycle, not the monitor; the
    /// returned fact is dropped by the caller outside the lock.
    #[must_use = "drop the returned fact outside the registry mutex"]
    pub fn cancel(&self) -> Option<F> {
        let mut state = self.lock_state();
        if state.invalidated.is_none() {
            state.invalidated = Some(InvalidationCause::Cancelled);
        }
        let fact = state.published.take();
        drop(state);
        fact
    }

    /// Use the published fact after rechecking the complete pinned token.
    ///
    /// The closure runs under the registry mutex and must therefore be
    /// lock-cheap: no I/O, no await, no logging.
    ///
    /// # Errors
    ///
    /// Returns [`FactUseError`] when the session is invalidated, the token is
    /// not the pinned one, or nothing was published.
    pub fn with_fact<R>(
        &self,
        pin: SessionPin,
        read: impl FnOnce(&F) -> R,
    ) -> Result<R, FactUseError> {
        let state = self.lock_state();
        if let Some(cause) = state.invalidated {
            drop(state);
            return Err(FactUseError::Invalidated(cause));
        }
        if pin != state.pin {
            drop(state);
            return Err(FactUseError::PinMismatch);
        }
        let Some(fact) = state.published.as_ref() else {
            drop(state);
            return Err(FactUseError::NotPublished);
        };
        let result = read(fact);
        drop(state);
        Ok(result)
    }

    /// Duplicate the epoch-owned pidfd for an asynchronous exit monitor.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the descriptor cannot be
    /// duplicated.
    pub fn monitor_fd(&self) -> Result<OwnedFd, std::io::Error> {
        let state = self.lock_state();
        let fd = state.pidfd.try_clone();
        drop(state);
        fd
    }

    fn lock_state(&self) -> MutexGuard<'_, GuardedSessionState<F>> {
        // Poisoning is recovered: a panicked writer must not permanently
        // strand session invalidation on this long-running broker.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Await the peer's exit and invalidate the session when it happens.
///
/// The returned fact (if a publication had completed) is handed to the caller
/// for disposal outside the registry mutex — for example dropping the
/// session's `ActiveArtifact` and triggering full reconnection. Cancelling
/// this future never invalidates anything: cancellation is owned by session
/// close and drain, so no detached monitor can invalidate a replacement
/// epoch's fresh session value. A monitoring setup failure fails closed by
/// invalidating immediately.
pub async fn run_pidfd_monitor<F>(session: PidfdGuardedSession<F>) -> Option<F> {
    let Ok(fd) = session.monitor_fd() else {
        return session.observe_exit();
    };
    let Ok(async_fd) = tokio::io::unix::AsyncFd::with_interest(fd, tokio::io::Interest::READABLE)
    else {
        return session.observe_exit();
    };
    // Readable or failed both mean the epoch cannot be monitored further:
    // fail closed by observing the exit.
    let _readiness = async_fd.readable().await;
    session.observe_exit()
}

#[cfg(test)]
mod tests {
    use super::{ProtocolError, validate_mount, wire};

    fn mount(kind: wire::MountKind) -> wire::MountFact {
        wire::MountFact {
            kind: kind as i32,
            host_source: if kind == wire::MountKind::Tmpfs {
                String::new()
            } else {
                "/host".to_owned()
            },
            container_destination: "/run".to_owned(),
            read_only: false,
            propagation: wire::MountPropagation::Private as i32,
            tmpfs_size_bytes: None,
            tmpfs_mode: None,
            tmpfs_nodev: false,
            tmpfs_nosuid: false,
            tmpfs_noexec: false,
            tmpfs_noswap: false,
        }
    }

    #[test]
    fn tmpfs_security_projection_is_closed_by_mount_kind() {
        let mut tmpfs = mount(wire::MountKind::Tmpfs);
        tmpfs.tmpfs_nodev = true;
        tmpfs.tmpfs_nosuid = true;
        tmpfs.tmpfs_noexec = true;
        tmpfs.tmpfs_noswap = true;
        assert!(validate_mount(&tmpfs).is_ok());

        let mut bind = mount(wire::MountKind::Bind);
        bind.tmpfs_nodev = true;
        assert!(matches!(
            validate_mount(&bind),
            Err(ProtocolError::InvalidField {
                field: "instance.mount.tmpfs_options",
                ..
            })
        ));
    }
}

#[cfg(test)]
mod pidfd_test_support {
    //! Shared real-process pidfd fixtures for the conformance modules.

    use std::os::fd::OwnedFd;
    use std::process::{Child, Command, Stdio};

    use rustix::process::{Pid, PidfdFlags, pidfd_open};

    /// A pidfd for this (never-exiting) test process.
    pub(super) fn self_pidfd() -> OwnedFd {
        pidfd_open(rustix::process::getpid(), PidfdFlags::empty()).expect("self pidfd")
    }

    /// A child that blocks on stdin until [`exit_child`] releases it, plus its
    /// pidfd acquired while it is alive.
    pub(super) fn blocking_child() -> (Child, OwnedFd) {
        let child = Command::new("/bin/sh")
            .args(["-c", "read _line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn blocking child");
        let raw = i32::try_from(child.id()).expect("child pid fits i32");
        let pid = Pid::from_raw(raw).expect("nonzero child pid");
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).expect("child pidfd");
        (child, pidfd)
    }

    /// Release, exit, and reap a [`blocking_child`].
    pub(super) fn exit_child(mut child: Child) {
        drop(child.stdin.take());
        let _status = child.wait().expect("wait");
    }

    /// A pidfd whose process has already exited and been reaped.
    pub(super) fn exited_child_pidfd() -> OwnedFd {
        let (child, pidfd) = blocking_child();
        exit_child(child);
        pidfd
    }
}

#[cfg(test)]
mod broker_helper_conformance {
    //! Broker-side SPEC conformance test 16.
    //!
    //! Helper-side coverage (allowlist selection, unit/LSM/lockdown checks,
    //! the start-time sandwich) lives in `helper::conformance`. This module
    //! proves the broker's own cross-checks: substituted streams and cookies,
    //! replayed nonces, echo and helper-policy pin verification against the
    //! protected measurement authority, its own `SO_PEERCRED` capture,
    //! descriptor count/type/association (including PID reuse via an
    //! already-exited pidfd), executable identity and hashing into
    //! `ReleaseAdmission::begin_preflight`, generation overlap on one
    //! endpoint, typed rejection surfacing for wrong realm/UID/unit/LSM
    //! identity, and transport-level violations (oversize, ancillary
    //! truncation, outage).

    use std::collections::VecDeque;
    use std::num::NonZeroU64;
    use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};
    use std::sync::Mutex;

    use rustix::net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
        SocketType, sockopt,
    };
    use sha2::{Digest as _, Sha256};

    use super::super::codec::PeerCredentials;
    use super::super::helper::allowlist::{InstalledAllowlist, RealmExpectation};
    use super::super::helper::service::{
        ConfinementFacts, ExecutableError, ExecutableOpener, HelperOutcome, HelperService,
        InspectError, PeerPidfdError, PeerPidfdSource, ProcessIdentity, ProcessInspector,
        ResolvedUnit, UnitResolveError, UnitResolver, serve_connection,
    };
    use super::super::helper::transport::{HelperConnection, ReceivedDatagram};
    use super::super::helper::wire::{
        MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MeasuredRecord, RejectCode, RejectionRecord,
    };
    use super::pidfd_test_support::{blocking_child, exit_child, exited_child_pidfd};
    use super::{MeasurementError, PinnedHelperPolicy, measure_attestor_stream};
    use crate::core::release_admission::{
        ArtifactRequirement, ArtifactRole, CapabilityId, CapabilitySet,
        HistoricalReleaseIdentityCheck, ProductId, ProtocolVersion, ReleaseAdmission,
        ReleaseArtifact, ReleaseId, Sha256Digest, TargetTriple, VerifiedReleaseManifest,
    };

    const REALM: &str = "production-docker";
    const POLICY_G1: &str = "basil-measure-policy-g1";
    const POLICY_G2: &str = "basil-measure-policy-g2";
    const UNIT_G1: &str = "basil-attestor-production-docker-g1.service";
    const UNIT_G2: &str = "basil-attestor-production-docker-g2.service";
    const LSM: &str = "selinux:basil_attestor_g1_t";
    const LOCKDOWN: &str = "basil-attestor-lockdown-g1";
    /// A small, stable regular file measured as the "executable".
    const EXECUTABLE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");

    fn own_uid() -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn own_gid() -> u32 {
        rustix::process::getgid().as_raw()
    }

    fn self_peer() -> PeerCredentials {
        PeerCredentials {
            pid: Some(std::process::id()),
            uid: own_uid(),
            gid: own_gid(),
        }
    }

    fn expectation(generation: u64, unit: &str) -> RealmExpectation {
        RealmExpectation {
            authority_generation: NonZeroU64::new(generation).expect("nonzero"),
            service_unit: unit.to_owned(),
            attestor_uid: own_uid(),
            lsm_profile: LSM.to_owned(),
            lockdown_profile: LOCKDOWN.to_owned(),
        }
    }

    fn allowlist_g1() -> InstalledAllowlist {
        InstalledAllowlist::from_parts(vec![(
            POLICY_G1.to_owned(),
            NonZeroU64::MIN,
            vec![(REALM.to_owned(), expectation(1, UNIT_G1))],
        )])
    }

    fn overlap_allowlist() -> InstalledAllowlist {
        let two = NonZeroU64::new(2).expect("nonzero");
        InstalledAllowlist::from_parts(vec![
            (
                POLICY_G1.to_owned(),
                NonZeroU64::MIN,
                vec![(REALM.to_owned(), expectation(1, UNIT_G1))],
            ),
            (
                POLICY_G2.to_owned(),
                two,
                vec![(REALM.to_owned(), expectation(2, UNIT_G2))],
            ),
        ])
    }

    fn pin_g1() -> PinnedHelperPolicy {
        PinnedHelperPolicy {
            realm: REALM.to_owned(),
            policy_identity: POLICY_G1.to_owned(),
            policy_generation: NonZeroU64::MIN,
            broker_generation: 7,
        }
    }

    struct SelfPidfd;

    impl PeerPidfdSource for SelfPidfd {
        fn peer_pidfd(&self, _stream: BorrowedFd<'_>) -> Result<OwnedFd, PeerPidfdError> {
            rustix::process::pidfd_open(
                rustix::process::getpid(),
                rustix::process::PidfdFlags::empty(),
            )
            .map_err(|_| PeerPidfdError::Io)
        }
    }

    struct QueuedUnits(Mutex<VecDeque<String>>);

    impl QueuedUnits {
        fn of(units: &[&str]) -> Self {
            Self(Mutex::new(
                units.iter().map(|unit| (*unit).to_owned()).collect(),
            ))
        }
    }

    impl UnitResolver for QueuedUnits {
        fn unit_by_pidfd(&self, _pidfd: BorrowedFd<'_>) -> Result<ResolvedUnit, UnitResolveError> {
            self.0
                .lock()
                .expect("units lock")
                .pop_front()
                .map(|unit| ResolvedUnit { unit })
                .ok_or(UnitResolveError::Io)
        }
    }

    struct FakeInspector {
        lsm: String,
    }

    impl ProcessInspector for FakeInspector {
        fn identity(
            &self,
            _pid: u32,
            _pidfd: BorrowedFd<'_>,
        ) -> Result<ProcessIdentity, InspectError> {
            Ok(ProcessIdentity {
                uid: own_uid(),
                gid: own_gid(),
                start_time_ticks: 1000,
            })
        }

        fn confinement(
            &self,
            _pid: u32,
            _pidfd: BorrowedFd<'_>,
        ) -> Result<ConfinementFacts, InspectError> {
            Ok(ConfinementFacts {
                lsm_profile: self.lsm.clone(),
                lockdown_profile: LOCKDOWN.to_owned(),
            })
        }
    }

    struct FileOpener;

    impl ExecutableOpener for FileOpener {
        fn open_executable(
            &self,
            _pid: u32,
            _pidfd: BorrowedFd<'_>,
        ) -> Result<OwnedFd, ExecutableError> {
            rustix::fs::open(
                EXECUTABLE_PATH,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| ExecutableError::Io)
        }
    }

    type Service = HelperService<SelfPidfd, QueuedUnits, FakeInspector, FileOpener>;

    fn service_with(allowlist: InstalledAllowlist, units: &[&str], lsm: &str) -> Service {
        HelperService::new(
            allowlist,
            SelfPidfd,
            QueuedUnits::of(units),
            FakeInspector {
                lsm: lsm.to_owned(),
            },
            FileOpener,
        )
    }

    fn service() -> Service {
        service_with(allowlist_g1(), &[UNIT_G1; 8], LSM)
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

    fn serve(service: Service) -> (HelperConnection, std::thread::JoinHandle<()>) {
        let (client, server) = HelperConnection::pair().expect("pair");
        let worker = std::thread::spawn(move || {
            let _ = serve_connection(&server, &service);
        });
        (client, worker)
    }

    /// One crafted exchange: the honest service measures the request, then
    /// `craft` substitutes or mutates the response before it is sent.
    type Craft =
        Box<dyn FnOnce(MeasuredRecord, OwnedFd, OwnedFd) -> (Vec<u8>, Vec<OwnedFd>) + Send>;

    fn measure_with_crafted(craft: Craft) -> MeasurementError {
        let (client, server) = HelperConnection::pair().expect("pair");
        let worker = std::thread::spawn(move || {
            let datagram = server
                .recv(MAX_REQUEST_BYTES)
                .expect("recv")
                .expect("datagram");
            let outcome = service().handle(ReceivedDatagram {
                bytes: datagram.bytes,
                descriptors: datagram.descriptors,
                oversized: false,
                ancillary_truncated: false,
            });
            let HelperOutcome::Measured {
                record,
                pidfd,
                executable,
            } = outcome
            else {
                panic!("expected an honest measurement");
            };
            let (bytes, fds) = craft(record, pidfd, executable);
            let borrowed: Vec<_> = fds.iter().map(|fd| fd.as_fd()).collect();
            server.send(&bytes, &borrowed).expect("send crafted");
        });
        let (broker_end, _attestor_end) = stream_pair();
        let result = measure_attestor_stream(&client, broker_end.as_fd(), self_peer(), &pin_g1());
        worker.join().expect("join");
        result.expect_err("crafted response must be rejected")
    }

    fn expect_mutation(mutate: fn(&mut MeasuredRecord), check: fn(&MeasurementError) -> bool) {
        let error = measure_with_crafted(Box::new(move |mut record, pidfd, executable| {
            mutate(&mut record);
            (
                record.encode().expect("encode mutated record"),
                vec![pidfd, executable],
            )
        }));
        assert!(check(&error), "unexpected error: {error:?}");
    }

    fn admission_for(digest: [u8; 32]) -> (ReleaseAdmission, ArtifactRequirement) {
        let role = ArtifactRole::new("attestor").expect("role");
        let target = TargetTriple::new("x86_64-unknown-linux-gnu").expect("target");
        let protocol = ProtocolVersion::new(1).expect("protocol");
        let capabilities =
            CapabilitySet::try_from_iter(
                [CapabilityId::new("docker.rootful").expect("capability")],
            )
            .expect("capabilities");
        let artifact = ReleaseArtifact::new(
            role.clone(),
            target.clone(),
            Sha256Digest::from_bytes(digest),
            protocol,
            capabilities.clone(),
        );
        let manifest = VerifiedReleaseManifest::from_verified_parts(
            HistoricalReleaseIdentityCheck::completed(),
            ProductId::new("basil-attestor").expect("product"),
            ReleaseId::new("1.0.0").expect("release"),
            [artifact],
        )
        .expect("manifest");
        let requirement = ArtifactRequirement::new(
            Sha256Digest::from_bytes(digest),
            role,
            target,
            protocol,
            capabilities,
        );
        (ReleaseAdmission::new(manifest), requirement)
    }

    #[test]
    fn measures_verifies_and_admits_the_executable() {
        let (client, worker) = serve(service());
        let (broker_end, _attestor_end) = stream_pair();
        let measurement =
            measure_attestor_stream(&client, broker_end.as_fd(), self_peer(), &pin_g1())
                .expect("measurement");
        // The record is bound to this stream's own cookie and this session's
        // pinned helper policy.
        let cookie = sockopt::socket_cookie(broker_end.as_fd()).expect("cookie");
        assert_eq!(measurement.record.cookie, cookie);
        assert_eq!(measurement.record.policy_identity, POLICY_G1);
        assert_eq!(measurement.record.policy_generation, NonZeroU64::MIN);
        assert_eq!(measurement.record.service_unit, UNIT_G1);
        // The digest covers the exact bytes behind the returned descriptor.
        let expected: [u8; 32] =
            Sha256::digest(std::fs::read(EXECUTABLE_PATH).expect("read")).into();
        assert_eq!(measurement.executable_sha256, expected);
        // The exact digest feeds the artifact requirement, and admission
        // holds the release active for this preflight.
        let (admission, requirement) = admission_for(measurement.executable_sha256);
        let active = admission
            .begin_preflight(&requirement)
            .expect("begin preflight");
        assert_eq!(admission.snapshot().current.active_preflights, 1);
        drop(active);
        assert_eq!(admission.snapshot().current.active_preflights, 0);
        drop(client);
        worker.join().expect("join");
    }

    #[test]
    fn a_foreign_digest_is_never_admitted() {
        let (admission, _requirement) = admission_for([0x11; 32]);
        let (_admission_other, foreign) = admission_for([0x22; 32]);
        assert!(admission.begin_preflight(&foreign).is_err());
    }

    #[test]
    fn surfaces_typed_rejections_for_wrong_realm_generation_unit_lsm_and_uid() {
        // (allowlist, resolved units, live lsm, pin mutation, expected code)
        let wrong_realm = || {
            let mut pin = pin_g1();
            pin.realm = "other-realm".to_owned();
            pin
        };
        let stale_generation = || {
            let mut pin = pin_g1();
            pin.policy_identity = "basil-measure-policy-g9".to_owned();
            pin.policy_generation = NonZeroU64::new(9).expect("nonzero");
            pin
        };
        let cases: Vec<(Service, PinnedHelperPolicy, RejectCode)> = vec![
            (service(), wrong_realm(), RejectCode::RealmNotInstalled),
            (
                service(),
                stale_generation(),
                RejectCode::PolicyNotInstalled,
            ),
            (
                service_with(allowlist_g1(), &["basil-attestor-other-g1.service"], LSM),
                pin_g1(),
                RejectCode::UnitMismatch,
            ),
            (
                service_with(allowlist_g1(), &[UNIT_G1; 8], "selinux:unconfined_t"),
                pin_g1(),
                RejectCode::ConfinementMismatch,
            ),
        ];
        for (case, pin, code) in cases {
            let (client, worker) = serve(case);
            let (broker_end, _attestor_end) = stream_pair();
            let error = measure_attestor_stream(&client, broker_end.as_fd(), self_peer(), &pin)
                .expect_err("must reject");
            assert!(
                matches!(&error, MeasurementError::Rejected { code: got } if *got == code),
                "expected {code:?}, got {error:?}"
            );
            drop(client);
            worker.join().expect("join");
        }

        // A wrong peer UID in the installed expectation rejects.
        let mut foreign = expectation(1, UNIT_G1);
        foreign.attestor_uid = own_uid().wrapping_add(1);
        let wrong_uid = InstalledAllowlist::from_parts(vec![(
            POLICY_G1.to_owned(),
            NonZeroU64::MIN,
            vec![(REALM.to_owned(), foreign)],
        )]);
        let (client, worker) = serve(service_with(wrong_uid, &[UNIT_G1; 8], LSM));
        let (broker_end, _attestor_end) = stream_pair();
        let error = measure_attestor_stream(&client, broker_end.as_fd(), self_peer(), &pin_g1())
            .expect_err("must reject");
        assert!(matches!(
            error,
            MeasurementError::Rejected {
                code: RejectCode::PeerIdentityMismatch
            }
        ));
        drop(client);
        worker.join().expect("join");
    }

    #[test]
    fn one_endpoint_serves_old_sessions_and_candidate_qualifiers_concurrently() {
        // Both installed generations are live on one endpoint. The old
        // serving session and the candidate qualifier each name their own
        // pinned generation and are measured under their own expectations.
        let (client, worker) = serve(service_with(overlap_allowlist(), &[UNIT_G1, UNIT_G2], LSM));

        let (old_end, _old_peer) = stream_pair();
        let old = measure_attestor_stream(&client, old_end.as_fd(), self_peer(), &pin_g1())
            .expect("old-generation measurement");
        assert_eq!(old.record.policy_generation, NonZeroU64::MIN);
        assert_eq!(old.record.service_unit, UNIT_G1);

        let candidate_pin = PinnedHelperPolicy {
            realm: REALM.to_owned(),
            policy_identity: POLICY_G2.to_owned(),
            policy_generation: NonZeroU64::new(2).expect("nonzero"),
            broker_generation: 7,
        };
        let (new_end, _new_peer) = stream_pair();
        let candidate =
            measure_attestor_stream(&client, new_end.as_fd(), self_peer(), &candidate_pin)
                .expect("candidate measurement");
        assert_eq!(candidate.record.policy_generation.get(), 2);
        assert_eq!(candidate.record.service_unit, UNIT_G2);

        // A request naming a generation not installed for the realm rejects.
        let uninstalled_pin = PinnedHelperPolicy {
            policy_generation: NonZeroU64::new(3).expect("nonzero"),
            ..candidate_pin
        };
        let (third_end, _third_peer) = stream_pair();
        let error =
            measure_attestor_stream(&client, third_end.as_fd(), self_peer(), &uninstalled_pin)
                .expect_err("must reject");
        assert!(matches!(
            error,
            MeasurementError::Rejected {
                code: RejectCode::PolicyNotInstalled
            }
        ));
        drop(client);
        worker.join().expect("join");
    }

    #[test]
    fn rejects_a_substituted_stream_by_its_cookie() {
        // The helper measures a different (equally self-owned) stream than
        // the one the broker holds: peer credentials agree, so the socket
        // cookie is the discriminator.
        let (client, server) = HelperConnection::pair().expect("pair");
        let worker = std::thread::spawn(move || {
            let datagram = server
                .recv(MAX_REQUEST_BYTES)
                .expect("recv")
                .expect("datagram");
            let (substituted, _peer) = stream_pair();
            let outcome = service().handle(ReceivedDatagram {
                bytes: datagram.bytes,
                descriptors: vec![substituted],
                oversized: false,
                ancillary_truncated: false,
            });
            let HelperOutcome::Measured {
                record,
                pidfd,
                executable,
            } = outcome
            else {
                panic!("expected measurement");
            };
            server
                .send(
                    &record.encode().expect("encode"),
                    &[pidfd.as_fd(), executable.as_fd()],
                )
                .expect("send");
        });
        let (broker_end, _attestor_end) = stream_pair();
        let error = measure_attestor_stream(&client, broker_end.as_fd(), self_peer(), &pin_g1())
            .expect_err("substituted stream must be rejected");
        assert!(matches!(error, MeasurementError::CookieMismatch));
        worker.join().expect("join");
    }

    type Mutator = fn(&mut MeasuredRecord);
    type ErrorCheck = fn(&MeasurementError) -> bool;

    #[test]
    fn rejects_mutated_records_field_by_field() {
        let cases: [(Mutator, ErrorCheck); 8] = [
            (
                |record| record.nonce = [0xEE; 32],
                |error| matches!(error, MeasurementError::StaleResponse),
            ),
            (
                |record| record.broker_generation ^= 1,
                |error| matches!(error, MeasurementError::GenerationEchoMismatch),
            ),
            (
                |record| record.realm = "other-realm".to_owned(),
                |error| matches!(error, MeasurementError::RealmEchoMismatch),
            ),
            (
                |record| record.policy_identity = POLICY_G2.to_owned(),
                |error| matches!(error, MeasurementError::PolicyPinMismatch),
            ),
            (
                |record| record.policy_generation = NonZeroU64::new(2).expect("nonzero"),
                |error| matches!(error, MeasurementError::PolicyPinMismatch),
            ),
            (
                |record| record.cookie ^= 1,
                |error| matches!(error, MeasurementError::CookieMismatch),
            ),
            (
                |record| record.peer_pid ^= 1,
                |error| matches!(error, MeasurementError::PeerCredentialsMismatch),
            ),
            (
                |record| record.peer_uid ^= 1,
                |error| matches!(error, MeasurementError::PeerCredentialsMismatch),
            ),
        ];
        for (mutate, check) in cases {
            expect_mutation(mutate, check);
        }
    }

    #[test]
    fn rejects_missing_surplus_and_wrong_type_descriptors() {
        // Missing executable descriptor.
        let error = measure_with_crafted(Box::new(|record, pidfd, _executable| {
            (record.encode().expect("encode"), vec![pidfd])
        }));
        assert!(matches!(
            error,
            MeasurementError::DescriptorCount { received: 1 }
        ));

        // A surplus third descriptor.
        let error = measure_with_crafted(Box::new(|record, pidfd, executable| {
            let (extra, _peer) = stream_pair();
            (
                record.encode().expect("encode"),
                vec![pidfd, executable, extra],
            )
        }));
        assert!(matches!(
            error,
            MeasurementError::DescriptorCount { received: 3 }
        ));

        // Swapped order: a regular file is not a pidfd.
        let error = measure_with_crafted(Box::new(|record, pidfd, executable| {
            (record.encode().expect("encode"), vec![executable, pidfd])
        }));
        assert!(matches!(error, MeasurementError::PidfdType));

        // A socket is not a regular executable file.
        let error = measure_with_crafted(Box::new(|record, pidfd, _executable| {
            let (socket, _peer) = stream_pair();
            (record.encode().expect("encode"), vec![pidfd, socket])
        }));
        assert!(matches!(error, MeasurementError::ExecutableType));

        // A different regular file than the record's identity.
        let error = measure_with_crafted(Box::new(|mut record, pidfd, executable| {
            record.executable_inode ^= 1;
            (record.encode().expect("encode"), vec![pidfd, executable])
        }));
        assert!(matches!(
            error,
            MeasurementError::ExecutableIdentityMismatch
        ));
    }

    #[test]
    fn rejects_an_exited_pidfd_and_a_foreign_process_pidfd() {
        // PID reuse defense: the returned pidfd names a process that already
        // exited; any same-numbered live PID is a different process.
        let error = measure_with_crafted(Box::new(|record, _pidfd, executable| {
            (
                record.encode().expect("encode"),
                vec![exited_child_pidfd(), executable],
            )
        }));
        assert!(matches!(error, MeasurementError::PeerExited));

        // Exact association: a live pidfd for some other process is not the
        // record's peer.
        let (child, child_pidfd) = blocking_child();
        let error = measure_with_crafted(Box::new(move |record, _pidfd, executable| {
            (
                record.encode().expect("encode"),
                vec![child_pidfd, executable],
            )
        }));
        assert!(matches!(error, MeasurementError::PidfdAssociation));
        exit_child(child);
    }

    #[test]
    fn rejects_rejections_that_do_not_answer_this_request() {
        // A rejection record may never carry descriptors.
        let error = measure_with_crafted(Box::new(|record, pidfd, _executable| {
            let rejection = RejectionRecord {
                protocol: super::super::helper::wire::HELPER_PROTOCOL_VERSION,
                code: RejectCode::UnitMismatch,
                broker_generation: record.broker_generation,
                nonce: record.nonce,
            };
            (rejection.encode(), vec![pidfd])
        }));
        assert!(matches!(
            error,
            MeasurementError::RejectionCarriedDescriptors
        ));

        // A post-decode rejection must echo this request's nonce.
        let error = measure_with_crafted(Box::new(|record, _pidfd, _executable| {
            let rejection = RejectionRecord {
                protocol: super::super::helper::wire::HELPER_PROTOCOL_VERSION,
                code: RejectCode::UnitMismatch,
                broker_generation: record.broker_generation,
                nonce: [0xEE; 32],
            };
            (rejection.encode(), Vec::new())
        }));
        assert!(matches!(error, MeasurementError::StaleResponse));

        // A pre-decode rejection legitimately echoes a zeroed identity.
        let error = measure_with_crafted(Box::new(|_record, _pidfd, _executable| {
            let rejection = RejectionRecord {
                protocol: super::super::helper::wire::HELPER_PROTOCOL_VERSION,
                code: RejectCode::MalformedRequest,
                broker_generation: 0,
                nonce: [0; 32],
            };
            (rejection.encode(), Vec::new())
        }));
        assert!(matches!(
            error,
            MeasurementError::Rejected {
                code: RejectCode::MalformedRequest
            }
        ));
    }

    #[test]
    fn rejects_transport_level_violations_and_outage() {
        // Malformed response bytes.
        let error = measure_with_crafted(Box::new(|_record, _pidfd, _executable| {
            (vec![1, 2, 3], Vec::new())
        }));
        assert!(matches!(error, MeasurementError::Wire(_)));

        // Oversized response datagram.
        let error = measure_with_crafted(Box::new(|_record, _pidfd, _executable| {
            (vec![0x42; MAX_RESPONSE_BYTES + 64], Vec::new())
        }));
        assert!(matches!(error, MeasurementError::OversizedResponse));

        // Helper outage: the endpoint closes before answering. The caller
        // owns retry; a fresh connection (restart) succeeds afterwards.
        let (client, server) = HelperConnection::pair().expect("pair");
        let worker = std::thread::spawn(move || {
            let _request = server.recv(MAX_REQUEST_BYTES).expect("recv");
            drop(server);
        });
        let (broker_end, _attestor_end) = stream_pair();
        let error = measure_attestor_stream(&client, broker_end.as_fd(), self_peer(), &pin_g1())
            .expect_err("outage must reject");
        assert!(matches!(error, MeasurementError::HelperClosed));
        worker.join().expect("join");
        let (client, worker) = serve(service());
        assert!(
            measure_attestor_stream(&client, broker_end.as_fd(), self_peer(), &pin_g1()).is_ok()
        );
        drop(client);
        worker.join().expect("join");
    }

    #[test]
    fn rejects_kernel_ancillary_truncation_on_the_response() {
        let (client, server) = HelperConnection::pair().expect("pair");
        let worker = std::thread::spawn(move || {
            let datagram = server
                .recv(MAX_REQUEST_BYTES)
                .expect("recv")
                .expect("datagram");
            let outcome = service().handle(ReceivedDatagram {
                bytes: datagram.bytes,
                descriptors: datagram.descriptors,
                oversized: false,
                ancillary_truncated: false,
            });
            let HelperOutcome::Measured {
                record,
                pidfd,
                executable,
            } = outcome
            else {
                panic!("expected measurement");
            };
            // Twelve descriptors exceed the broker's reserved ancillary
            // space for four; the kernel flags CTRUNC on receive.
            let mut fds = Vec::new();
            for _ in 0..6 {
                fds.push(pidfd.try_clone().expect("dup pidfd"));
                fds.push(executable.try_clone().expect("dup executable"));
            }
            let borrowed: Vec<_> = fds.iter().map(|fd| fd.as_fd()).collect();
            let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(12))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&borrowed)));
            let bytes = record.encode().expect("encode");
            let iov = [std::io::IoSlice::new(&bytes)];
            rustix::net::sendmsg(server.as_fd(), &iov, &mut ancillary, SendFlags::NOSIGNAL)
                .expect("sendmsg");
        });
        let (broker_end, _attestor_end) = stream_pair();
        let error = measure_attestor_stream(&client, broker_end.as_fd(), self_peer(), &pin_g1())
            .expect_err("truncated ancillary must reject");
        assert!(matches!(error, MeasurementError::AncillaryTruncated));
        worker.join().expect("join");
    }
}

#[cfg(test)]
mod pidfd_publication_conformance {
    //! Pidfd state-machine SPEC conformance test 17.
    //!
    //! Response bytes are always decoded and validated outside the registry
    //! mutex into a non-authoritative fact; these tests race exit against
    //! registry-lock acquisition, the nonblocking poll, the complete-token
    //! comparison, atomic publication, later fact use, monitor cancellation,
    //! drain, and replacement. Exactly one publication or invalidation wins,
    //! every later use rechecks the pinned token, and no old monitor affects
    //! a new session.

    use std::time::Duration;

    use super::pidfd_test_support::{blocking_child, exit_child, exited_child_pidfd, self_pidfd};
    use super::{
        FactUseError, InvalidationCause, PidfdGuardedSession, PublicationRejection, SessionPin,
        run_pidfd_monitor,
    };
    use crate::core::release_admission::{
        ArtifactRequirement, ArtifactRole, CapabilityId, CapabilitySet,
        HistoricalReleaseIdentityCheck, ProductId, ProtocolVersion, ReleaseAdmission,
        ReleaseArtifact, ReleaseId, Sha256Digest, TargetTriple, VerifiedReleaseManifest,
    };

    fn pin(session_epoch: u64) -> SessionPin {
        SessionPin {
            configuration_generation: 3,
            entry_generation: 2,
            realm_revision: 5,
            session_epoch,
            session_handle: 9,
            actor_version: 4,
        }
    }

    fn admission() -> (ReleaseAdmission, ArtifactRequirement) {
        let digest = Sha256Digest::from_bytes([0x5A; 32]);
        let role = ArtifactRole::new("attestor").expect("role");
        let target = TargetTriple::new("x86_64-unknown-linux-gnu").expect("target");
        let protocol = ProtocolVersion::new(1).expect("protocol");
        let capabilities =
            CapabilitySet::try_from_iter(
                [CapabilityId::new("docker.rootful").expect("capability")],
            )
            .expect("capabilities");
        let artifact = ReleaseArtifact::new(
            role.clone(),
            target.clone(),
            digest,
            protocol,
            capabilities.clone(),
        );
        let manifest = VerifiedReleaseManifest::from_verified_parts(
            HistoricalReleaseIdentityCheck::completed(),
            ProductId::new("basil-attestor").expect("product"),
            ReleaseId::new("1.0.0").expect("release"),
            [artifact],
        )
        .expect("manifest");
        let requirement = ArtifactRequirement::new(digest, role, target, protocol, capabilities);
        (ReleaseAdmission::new(manifest), requirement)
    }

    #[test]
    fn later_use_rechecks_every_pinned_token_dimension() {
        let cell = PidfdGuardedSession::new(self_pidfd(), pin(1));
        assert!(matches!(
            cell.with_fact(pin(1), |fact: &u32| *fact),
            Err(FactUseError::NotPublished)
        ));
        cell.publish(pin(1), 7_u32).expect("publish");
        assert_eq!(cell.with_fact(pin(1), |fact| *fact).expect("use"), 7);

        let stale_pins = [
            SessionPin {
                configuration_generation: 99,
                ..pin(1)
            },
            SessionPin {
                entry_generation: 99,
                ..pin(1)
            },
            SessionPin {
                realm_revision: 99,
                ..pin(1)
            },
            SessionPin {
                session_epoch: 99,
                ..pin(1)
            },
            SessionPin {
                session_handle: 99,
                ..pin(1)
            },
            SessionPin {
                actor_version: 99,
                ..pin(1)
            },
        ];
        for stale in stale_pins {
            assert!(matches!(
                cell.with_fact(stale, |fact| *fact),
                Err(FactUseError::PinMismatch)
            ));
        }
        // A stale use does not invalidate the session for the pinned token.
        assert_eq!(cell.with_fact(pin(1), |fact| *fact).expect("use"), 7);
    }

    #[test]
    fn a_second_publication_never_wins() {
        let cell = PidfdGuardedSession::new(self_pidfd(), pin(1));
        cell.publish(pin(1), 1_u32).expect("first publication");
        let rejected = cell.publish(pin(1), 2_u32).expect_err("second must lose");
        assert_eq!(rejected.rejection, PublicationRejection::AlreadyPublished);
        assert_eq!(rejected.fact, 2);
        assert_eq!(cell.with_fact(pin(1), |fact| *fact).expect("use"), 1);
    }

    #[test]
    fn a_stale_token_at_publication_invalidates_and_rejects_the_session() {
        let cell = PidfdGuardedSession::new(self_pidfd(), pin(1));
        let rejected = cell.publish(pin(2), 7_u32).expect_err("stale token");
        assert_eq!(rejected.rejection, PublicationRejection::PinMismatch);
        assert_eq!(rejected.fact, 7);
        // The session is invalidated: even the pinned token now rejects.
        let rejected = cell.publish(pin(1), 8_u32).expect_err("invalidated");
        assert_eq!(
            rejected.rejection,
            PublicationRejection::Invalidated(InvalidationCause::PinMismatch)
        );
        assert!(matches!(
            cell.with_fact(pin(1), |fact: &u32| *fact),
            Err(FactUseError::Invalidated(InvalidationCause::PinMismatch))
        ));
    }

    #[test]
    fn an_exit_between_validation_and_publication_loses_the_race() {
        // Decode and validation completed outside the lock; the peer exits
        // before the response path reaches the linearization point. The
        // nonblocking poll under the mutex rejects and invalidates.
        let (child, pidfd) = blocking_child();
        let cell = PidfdGuardedSession::new(pidfd, pin(1));
        exit_child(child);
        let rejected = cell.publish(pin(1), 7_u32).expect_err("exited peer");
        assert_eq!(rejected.rejection, PublicationRejection::PeerExited);
        assert_eq!(rejected.fact, 7);
        assert!(matches!(
            cell.with_fact(pin(1), |fact: &u32| *fact),
            Err(FactUseError::Invalidated(InvalidationCause::PeerExited))
        ));
    }

    #[test]
    fn an_already_exited_pidfd_rejects_publication() {
        let cell = PidfdGuardedSession::new(exited_child_pidfd(), pin(1));
        let rejected = cell.publish(pin(1), 7_u32).expect_err("exited peer");
        assert_eq!(rejected.rejection, PublicationRejection::PeerExited);
    }

    #[test]
    fn exit_after_publication_is_ordered_after_the_fact_and_releases_admission() {
        let (release_admission, requirement) = admission();
        let active = release_admission
            .begin_preflight(&requirement)
            .expect("preflight");
        let cell = PidfdGuardedSession::new(self_pidfd(), pin(1));
        cell.publish(pin(1), active).expect("publish");
        assert_eq!(release_admission.snapshot().current.active_preflights, 1);

        // The monitor observes exit under the same mutex; the completed fact
        // is handed back and dropped outside the lock, releasing admission.
        let taken = cell.observe_exit();
        assert!(taken.is_some());
        drop(taken);
        assert_eq!(release_admission.snapshot().current.active_preflights, 0);

        // New work is rejected and a second observation changes nothing.
        assert!(matches!(
            cell.with_fact(pin(1), |_fact| ()),
            Err(FactUseError::Invalidated(InvalidationCause::PeerExited))
        ));
        assert!(cell.observe_exit().is_none());
    }

    #[test]
    fn exactly_one_linearization_winner_under_a_racing_monitor() {
        for _ in 0..64 {
            let cell = PidfdGuardedSession::new(self_pidfd(), pin(1));
            let publisher = {
                let cell = cell.clone();
                std::thread::spawn(move || cell.publish(pin(1), 1_u8))
            };
            let monitor = {
                let cell = cell.clone();
                std::thread::spawn(move || cell.observe_exit())
            };
            let attempt = publisher.join().expect("racing publication");
            let taken = monitor.join().expect("monitor");
            let visible = cell.with_fact(pin(1), |fact| *fact).is_ok();
            match attempt {
                // The publication won the lock first; the monitor either ran
                // later and took the fact, or the fact is still visible.
                Ok(()) => assert!(
                    taken.is_some() ^ visible,
                    "the fact must be in exactly one place"
                ),
                // The monitor won: the fact came back to the response path
                // and nothing was ever published.
                Err(rejected) => {
                    assert_eq!(
                        rejected.rejection,
                        PublicationRejection::Invalidated(InvalidationCause::PeerExited)
                    );
                    assert_eq!(rejected.fact, 1);
                    assert!(taken.is_none());
                    assert!(!visible);
                }
            }
        }
    }

    #[test]
    fn drain_cancellation_is_owned_by_close_and_never_touches_a_replacement() {
        let old = PidfdGuardedSession::new(self_pidfd(), pin(1));
        old.publish(pin(1), 1_u8).expect("publish");
        // Drain: session close cancels the epoch and disposes the fact.
        assert_eq!(old.cancel(), Some(1));
        // A detached monitor firing late observes nothing to release.
        assert!(old.observe_exit().is_none());
        assert!(matches!(
            old.with_fact(pin(1), |fact| *fact),
            Err(FactUseError::Invalidated(InvalidationCause::Cancelled))
        ));

        // The replacement epoch is a fresh cell with a fresh pin; the old
        // session's monitor and invalidation cannot reach it.
        let replacement = PidfdGuardedSession::new(self_pidfd(), pin(2));
        replacement.publish(pin(2), 2_u8).expect("publish");
        assert_eq!(replacement.with_fact(pin(2), |fact| *fact).expect("use"), 2);
        // The old pin never matches the replacement.
        assert!(matches!(
            replacement.with_fact(pin(1), |fact| *fact),
            Err(FactUseError::PinMismatch)
        ));
    }

    #[tokio::test]
    async fn the_async_monitor_observes_a_real_exit_and_invalidates() {
        let (child, pidfd) = blocking_child();
        let cell = PidfdGuardedSession::new(pidfd, pin(1));
        cell.publish(pin(1), 5_u8).expect("publish while alive");
        let monitor = tokio::spawn(run_pidfd_monitor(cell.clone()));
        exit_child(child);
        let taken = tokio::time::timeout(Duration::from_secs(30), monitor)
            .await
            .expect("monitor must observe the exit")
            .expect("monitor task");
        assert_eq!(taken, Some(5));
        assert!(matches!(
            cell.with_fact(pin(1), |fact| *fact),
            Err(FactUseError::Invalidated(InvalidationCause::PeerExited))
        ));
    }

    #[tokio::test]
    async fn cancelling_the_monitor_future_never_invalidates_the_session() {
        let (child, pidfd) = blocking_child();
        let cell = PidfdGuardedSession::new(pidfd, pin(1));
        cell.publish(pin(1), 5_u8).expect("publish");
        let monitor = tokio::spawn(run_pidfd_monitor(cell.clone()));
        // Give the monitor a chance to register before it is cancelled.
        tokio::time::sleep(Duration::from_millis(20)).await;
        monitor.abort();
        let _aborted = monitor.await;
        // Cancellation is owned by session close and drain: the session is
        // untouched and still serving its published fact.
        assert_eq!(cell.with_fact(pin(1), |fact| *fact).expect("use"), 5);
        assert_eq!(cell.cancel(), Some(5));
        exit_child(child);
    }
}
