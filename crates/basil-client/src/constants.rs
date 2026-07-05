// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared constants for the wire protocol and codec.

/// Default path for the agent's listening Unix domain socket.
///
/// This is a development-friendly default under `/tmp`. Production deployments
/// should override it (the agent accepts `--socket` / `BASIL_SOCKET`),
/// typically pointing at `$XDG_RUNTIME_DIR` or `/run/basil/agent.sock`.
pub const DEFAULT_SOCKET_PATH: &str = "/tmp/basil-agent.sock";

/// Default per-request timeout, in seconds, used by the clients.
pub const DEFAULT_CONN_TIMEOUT: u64 = 30;

/// Above this retained capacity, an idle decode buffer is shrunk back down.
pub const CODEC_BYTESMUT_ALLOCATION_LIMIT: usize = 16 * 1024;

/// Capacity an over-grown decode buffer is reset to once drained.
pub const CODEC_MINIMUM_BYTESMUT_ALLOCATION: usize = 2 * 1024;
