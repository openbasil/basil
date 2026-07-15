// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::time::Duration;

use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, timeout_at};

use super::codec::{CodecError, FrameCodec, VerifiedPeerBinding};
use super::limits::{
    ABSOLUTE_MAX_CAPABILITIES, ABSOLUTE_MAX_CAPABILITY_BYTES, ABSOLUTE_MAX_DIAGNOSTIC_BYTES,
    ABSOLUTE_MAX_ID_MAP_RANGES, ABSOLUTE_MAX_MOUNTS_PER_INSTANCE, ABSOLUTE_MAX_STRING_BYTES,
    PROTOCOL_VERSION, ProtocolLimits,
};
use super::wire;
use super::wire::envelope::Body;
use super::wire::query_instances_request::Scope;

const BINDING_BYTES: usize = 32;

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
    pub async fn health(&mut self) -> Result<HealthResult, ProtocolError> {
        let challenge = self.begin(Operation::Health)?;
        let binding = self.binding(challenge);
        let request = envelope(Body::HealthRequest(wire::HealthRequest {
            binding: Some(binding.clone()),
            budget_millis: duration_millis(self.limits.request_deadline)?,
        }));
        self.write_or_close(&request).await?;
        let response = self.read_or_close(self.deadline()).await?;
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
    pub async fn resolve_peer(
        &mut self,
        constraints: wire::PinnedPeer,
    ) -> Result<ResolvePeerResult, ProtocolError> {
        validate_pinned_peer(&constraints)?;
        let challenge = self.begin(Operation::ResolvePeer)?;
        let binding = self.binding(challenge);
        let request = envelope(Body::ResolvePeerRequest(wire::ResolvePeerRequest {
            binding: Some(binding.clone()),
            budget_millis: duration_millis(self.limits.request_deadline)?,
            constraints: Some(constraints),
        }));
        self.write_or_close(&request).await?;
        let response = self.read_or_close(self.deadline()).await?;
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
    pub async fn query_instances(
        &mut self,
        scope: QueryScope,
    ) -> Result<InventoryResult, ProtocolError> {
        let scope = encode_scope(scope)?;
        let challenge = self.begin(Operation::QueryInstances)?;
        let binding = self.binding(challenge);
        let request = envelope(Body::QueryInstancesRequest(wire::QueryInstancesRequest {
            binding: Some(binding.clone()),
            budget_millis: duration_millis(self.limits.request_deadline)?,
            scope: Some(scope),
        }));
        self.write_or_close(&request).await?;
        let deadline = self.deadline();
        let mut accumulator = InventoryAccumulator::new(self.limits);
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
    Health,
    /// Pinned broker-observed process constraints.
    ResolvePeer(wire::PinnedPeer),
    /// Closed typed inventory scope.
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
                AttestorRequest::Health,
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
                    AttestorRequest::ResolvePeer(constraints),
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
                    AttestorRequest::QueryInstances(scope),
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
        self.pending = Some(PendingResponse {
            operation,
            binding,
            deadline: Instant::now() + budget,
        });
        self.phase = Phase::Waiting(operation);
        Ok(request)
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
        && (mount.tmpfs_size_bytes.is_some() || mount.tmpfs_mode.is_some())
    {
        return Err(invalid(
            "instance.mount.tmpfs_options",
            "are valid only for tmpfs",
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
    fn new(limits: ProtocolLimits) -> Self {
        Self {
            limits,
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
