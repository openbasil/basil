// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Internal broker event source shared by Admin Watch and future SPIFFE streams.

use std::time::SystemTime;

use tokio::sync::broadcast;

/// Broker event fanout with bounded lag semantics.
#[derive(Debug, Clone)]
pub struct EventSource {
    sender: broadcast::Sender<BrokerEvent>,
}

/// A public broker event.
#[derive(Debug, Clone)]
pub struct BrokerEvent {
    /// Event creation time.
    pub at: SystemTime,
    /// Event payload.
    pub kind: BrokerEventKind,
}

/// Event payload variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerEventKind {
    /// A catalog key rotated to a new version.
    KeyRotated {
        /// Dotted catalog key id.
        key_id: String,
        /// New latest version.
        new_version: u32,
    },
    /// A trust-domain bundle changed.
    BundleChanged {
        /// Trust domain whose bundle changed.
        trust_domain: String,
    },
    /// A credential or bundle item was revoked.
    Revoked {
        /// Trust domain containing the revoked id.
        trust_domain: String,
        /// Public revocation id, such as an X.509 serial or JWT jti.
        id: String,
    },
}

impl Default for EventSource {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSource {
    /// Build an event source with a bounded broadcast buffer.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1024);
        Self { sender }
    }

    /// Subscribe to future events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<BrokerEvent> {
        self.sender.subscribe()
    }

    /// Publish a key rotation event.
    pub fn key_rotated(&self, key_id: impl Into<String>, new_version: u32) {
        self.publish(BrokerEventKind::KeyRotated {
            key_id: key_id.into(),
            new_version,
        });
    }

    /// Publish a bundle change event.
    pub fn bundle_changed(&self, trust_domain: impl Into<String>) {
        self.publish(BrokerEventKind::BundleChanged {
            trust_domain: trust_domain.into(),
        });
    }

    /// Publish a revocation event.
    pub fn revoked(&self, trust_domain: impl Into<String>, id: impl Into<String>) {
        self.publish(BrokerEventKind::Revoked {
            trust_domain: trust_domain.into(),
            id: id.into(),
        });
    }

    fn publish(&self, kind: BrokerEventKind) {
        let _receivers = self.sender.send(BrokerEvent {
            at: SystemTime::now(),
            kind,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscribers_receive_events() {
        let source = EventSource::new();
        let mut rx = source.subscribe();
        source.key_rotated("app.key", 2);
        let event = rx.recv().await.expect("event received");
        assert_eq!(
            event.kind,
            BrokerEventKind::KeyRotated {
                key_id: "app.key".to_string(),
                new_version: 2,
            }
        );
    }
}
