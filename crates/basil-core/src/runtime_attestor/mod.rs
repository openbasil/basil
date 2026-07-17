// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Facts-only runtime-attestation providers.
//!
//! Providers own runtime-control authority, but they never receive policy,
//! secrets, backend credentials, or authorization decisions. Each operation
//! performs one bounded live read and returns only the fixed protocol-1 fact
//! projection.

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::attestor_protocol::{AttestorRequest, AttestorSession, ProtocolError, QueryScope, wire};

pub mod docker;
pub mod podman;
mod procfs;

/// One provider result with payload presence tied to the typed outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReply<T> {
    outcome: wire::Outcome,
    value: Option<T>,
}

impl<T> ProviderReply<T> {
    /// Construct a successful provider reply.
    #[must_use]
    pub fn success(value: T) -> Self {
        Self {
            outcome: outcome(wire::OutcomeCode::Ok, ""),
            value: Some(value),
        }
    }

    /// Construct a non-success provider reply with no payload.
    #[must_use]
    pub fn failure(code: wire::OutcomeCode, diagnostic: &'static str) -> Self {
        let code = if code == wire::OutcomeCode::Ok {
            wire::OutcomeCode::InvariantFailure
        } else {
            code
        };
        Self {
            outcome: outcome(code, diagnostic),
            value: None,
        }
    }

    /// Borrow the typed wire outcome.
    #[must_use]
    pub const fn outcome(&self) -> &wire::Outcome {
        &self.outcome
    }

    /// Borrow the successful payload, if present.
    #[must_use]
    pub const fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Split the reply for an [`crate::attestor_protocol::AttestorSession`]
    /// response method.
    #[must_use]
    pub fn into_parts(self) -> (wire::Outcome, Option<T>) {
        (self.outcome, self.value)
    }
}

/// Reusable facts-only provider interface implemented by Docker now and
/// rootless Podman separately.
#[async_trait]
pub trait RuntimeAttestorProvider: Send + Sync {
    /// Stable capabilities declared during protocol negotiation.
    fn capabilities(&self) -> &[String];

    /// Run one bounded diagnostic readiness probe.
    async fn health(&self, budget: std::time::Duration) -> ProviderReply<wire::HealthFact>;

    /// Independently reread and resolve one broker-pinned peer.
    async fn resolve_peer(
        &self,
        peer: &wire::PinnedPeer,
        budget: std::time::Duration,
    ) -> ProviderReply<wire::InstanceFact>;

    /// Run one bounded, non-cached inventory query.
    async fn query_instances(
        &self,
        scope: &QueryScope,
        budget: std::time::Duration,
    ) -> ProviderReply<Vec<wire::InstanceFact>>;
}

/// Dispatches one validated serial protocol request into a facts-only
/// provider under the broker's original monotonic deadline.
pub struct ProviderProtocolAdapter<P> {
    provider: P,
}

impl<P> ProviderProtocolAdapter<P>
where
    P: RuntimeAttestorProvider,
{
    /// Bind a provider to protocol-1 request dispatch.
    #[must_use]
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Capabilities to declare when constructing the attestor session.
    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        self.provider.capabilities()
    }

    /// Receive, execute, and respond to exactly one serial request.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] when request validation or response framing
    /// fails. Provider failures remain typed wire outcomes.
    pub async fn serve_next<S>(&self, session: &mut AttestorSession<S>) -> Result<(), ProtocolError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match session.receive().await? {
            AttestorRequest::Health { budget } => {
                let (outcome, health) = self.provider.health(budget.remaining()).await.into_parts();
                session.respond_health(outcome, health).await
            }
            AttestorRequest::ResolvePeer {
                constraints,
                budget,
            } => {
                let (outcome, instance) = self
                    .provider
                    .resolve_peer(&constraints, budget.remaining())
                    .await
                    .into_parts();
                session.respond_resolve_peer(outcome, instance).await
            }
            AttestorRequest::QueryInstances { scope, budget } => {
                let (outcome, instances) = self
                    .provider
                    .query_instances(&scope, budget.remaining())
                    .await
                    .into_parts();
                session
                    .respond_query_instances(outcome, instances.unwrap_or_default())
                    .await
            }
        }
    }
}

fn outcome(code: wire::OutcomeCode, diagnostic: &str) -> wire::Outcome {
    wire::Outcome {
        code: code as i32,
        diagnostic: diagnostic.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::attestor_protocol::{
        BrokerSession, FrameCodec, ProtocolLimits, RequestBudget, SessionAuthentication,
        VerifiedPeerBinding,
    };

    const BROKER_BINDING: VerifiedPeerBinding = VerifiedPeerBinding::from_authenticator([0x42; 32]);
    const ATTESTOR_BINDING: VerifiedPeerBinding =
        VerifiedPeerBinding::from_authenticator([0x24; 32]);

    struct RecordingProvider {
        observed_budget: Arc<Mutex<Option<Duration>>>,
        capabilities: Vec<String>,
    }

    #[async_trait]
    impl RuntimeAttestorProvider for RecordingProvider {
        fn capabilities(&self) -> &[String] {
            &self.capabilities
        }

        async fn health(&self, budget: Duration) -> ProviderReply<wire::HealthFact> {
            *self.observed_budget.lock().unwrap() = Some(budget);
            ProviderReply::success(wire::HealthFact {
                runtime: wire::RuntimeKind::Docker as i32,
                diagnostic_version: "test".to_string(),
                runtime_mode: wire::RuntimeMode::Rootful as i32,
                cgroup_mode: wire::CgroupMode::V2 as i32,
                ready: true,
                missing_capabilities: Vec::new(),
            })
        }

        async fn resolve_peer(
            &self,
            _peer: &wire::PinnedPeer,
            _budget: Duration,
        ) -> ProviderReply<wire::InstanceFact> {
            ProviderReply::failure(wire::OutcomeCode::NoMatch, "test")
        }

        async fn query_instances(
            &self,
            _scope: &QueryScope,
            _budget: Duration,
        ) -> ProviderReply<Vec<wire::InstanceFact>> {
            ProviderReply::success(Vec::new())
        }
    }

    fn authentication() -> SessionAuthentication {
        SessionAuthentication {
            generation: 7,
            broker: BROKER_BINDING,
            attestor: ATTESTOR_BINDING,
        }
    }

    #[tokio::test]
    async fn adapter_dispatches_protocol_request_under_original_deadline() {
        let limits =
            ProtocolLimits::lowered(4096, 16 * 1024, 10, 10, Duration::from_secs(1)).unwrap();
        let (client, server) = tokio::io::duplex(16 * 1024);
        let observed_budget = Arc::new(Mutex::new(None));
        let provider = RecordingProvider {
            observed_budget: Arc::clone(&observed_budget),
            capabilities: vec!["health".to_string()],
        };
        let adapter = ProviderProtocolAdapter::new(provider);
        let mut attestor = AttestorSession::new(
            FrameCodec::for_test(server, BROKER_BINDING, limits),
            authentication(),
            adapter.capabilities().to_vec(),
            limits,
        )
        .unwrap();
        let server_task = tokio::spawn(async move {
            attestor.handshake().await.unwrap();
            adapter.serve_next(&mut attestor).await.unwrap();
        });
        let mut broker = BrokerSession::new(
            FrameCodec::for_test(client, ATTESTOR_BINDING, limits),
            authentication(),
            ["health".to_string()],
            limits,
        )
        .unwrap();
        broker.handshake().await.unwrap();
        let caller_budget = Duration::from_millis(400);
        let health = broker
            .health(RequestBudget::starting_now(caller_budget))
            .await
            .unwrap();
        assert_eq!(health.outcome.code, wire::OutcomeCode::Ok as i32);
        server_task.await.unwrap();
        let budget = observed_budget.lock().unwrap().unwrap();
        assert!(!budget.is_zero());
        // The provider observes the caller's lowered budget, not the larger
        // configured session ceiling.
        assert!(budget <= caller_budget);
        assert!(budget <= limits.request_deadline);
    }
}
