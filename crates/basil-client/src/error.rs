// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Client-side error type.

use tonic::Code;

/// Errors surfaced by the [`crate::client`] / [`crate::client_sync`] clients.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// No reply arrived within the configured timeout.
    #[error("request timed out")]
    Timeout,

    /// The gRPC transport could not be created.
    #[error("transport endpoint error: {0}")]
    Endpoint(#[from] tonic::transport::Error),

    /// A caller-supplied JSON value could not be serialized.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// The agent returned a gRPC status.
    #[error("agent status [{code:?}/{reason}]: {message}")]
    Status {
        /// Canonical gRPC code.
        code: Code,
        /// Basil broker reason detail, when present.
        reason: String,
        /// Basil operation detail, when present.
        op: String,
        /// Human-readable message from the broker.
        message: String,
    },
}

pub type Result<T> = std::result::Result<T, Error>;
