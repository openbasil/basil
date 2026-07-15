// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use thiserror::Error;

/// Protocol version implemented by this module.
pub const PROTOCOL_VERSION: u32 = 1;
/// Absolute maximum protobuf payload accepted from a peer (1 MiB).
pub const ABSOLUTE_MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Absolute maximum bytes across one inventory response (16 MiB).
pub const ABSOLUTE_MAX_INVENTORY_BYTES: usize = 16 * 1024 * 1024;
/// Absolute maximum instances across one inventory response.
pub const ABSOLUTE_MAX_INSTANCES: usize = 1_000;
/// Absolute maximum chunks across one inventory response.
pub const ABSOLUTE_MAX_CHUNKS: usize = 64;
/// Absolute maximum mounts represented for one instance.
pub const ABSOLUTE_MAX_MOUNTS_PER_INSTANCE: usize = 256;
/// Absolute maximum UID or GID map ranges represented for one instance.
pub const ABSOLUTE_MAX_ID_MAP_RANGES: usize = 64;
/// Absolute maximum UTF-8 bytes in a normalized runtime string.
pub const ABSOLUTE_MAX_STRING_BYTES: usize = 4 * 1024;
/// Absolute maximum UTF-8 bytes in a diagnostic-only message.
pub const ABSOLUTE_MAX_DIAGNOSTIC_BYTES: usize = 4 * 1024;
/// Absolute maximum named capabilities in a handshake.
pub const ABSOLUTE_MAX_CAPABILITIES: usize = 32;
/// Absolute maximum UTF-8 bytes in one capability name.
pub const ABSOLUTE_MAX_CAPABILITY_BYTES: usize = 64;
/// Absolute maximum wall budget for one serial request.
pub const ABSOLUTE_MAX_REQUEST_DEADLINE: Duration = Duration::from_secs(30);

/// Runtime protocol limits, each of which can only lower a compiled ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolLimits {
    /// Maximum protobuf payload bytes in one frame.
    pub max_frame_bytes: usize,
    /// Maximum encoded fact bytes accumulated by one inventory request.
    pub max_inventory_bytes: usize,
    /// Maximum instances accumulated by one inventory request.
    pub max_inventory_instances: usize,
    /// Maximum response chunks in one inventory request.
    pub max_inventory_chunks: usize,
    /// Maximum duration of one request, including every inventory chunk.
    pub request_deadline: Duration,
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: ABSOLUTE_MAX_FRAME_BYTES,
            max_inventory_bytes: ABSOLUTE_MAX_INVENTORY_BYTES,
            max_inventory_instances: ABSOLUTE_MAX_INSTANCES,
            max_inventory_chunks: ABSOLUTE_MAX_CHUNKS,
            request_deadline: ABSOLUTE_MAX_REQUEST_DEADLINE,
        }
    }
}

impl ProtocolLimits {
    /// Construct a lower-only limit set.
    ///
    /// # Errors
    ///
    /// Returns [`LimitsError`] when any value is zero or exceeds its compiled
    /// ceiling.
    pub fn lowered(
        max_frame_bytes: usize,
        max_inventory_bytes: usize,
        max_inventory_instances: usize,
        max_inventory_chunks: usize,
        request_deadline: Duration,
    ) -> Result<Self, LimitsError> {
        check("max_frame_bytes", max_frame_bytes, ABSOLUTE_MAX_FRAME_BYTES)?;
        check(
            "max_inventory_bytes",
            max_inventory_bytes,
            ABSOLUTE_MAX_INVENTORY_BYTES,
        )?;
        check(
            "max_inventory_instances",
            max_inventory_instances,
            ABSOLUTE_MAX_INSTANCES,
        )?;
        check(
            "max_inventory_chunks",
            max_inventory_chunks,
            ABSOLUTE_MAX_CHUNKS,
        )?;
        if request_deadline.is_zero() || request_deadline > ABSOLUTE_MAX_REQUEST_DEADLINE {
            return Err(LimitsError::OutOfRange {
                field: "request_deadline",
                value: request_deadline.as_millis(),
                maximum: ABSOLUTE_MAX_REQUEST_DEADLINE.as_millis(),
            });
        }
        Ok(Self {
            max_frame_bytes,
            max_inventory_bytes,
            max_inventory_instances,
            max_inventory_chunks,
            request_deadline,
        })
    }
}

const fn check(field: &'static str, value: usize, maximum: usize) -> Result<(), LimitsError> {
    if value == 0 || value > maximum {
        return Err(LimitsError::OutOfRange {
            field,
            value: value as u128,
            maximum: maximum as u128,
        });
    }
    Ok(())
}

/// Invalid lower-only protocol limit.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LimitsError {
    /// A value is zero or exceeds the compiled ceiling.
    #[error("`{field}` value {value} is outside 1..={maximum}")]
    OutOfRange {
        /// Invalid field.
        field: &'static str,
        /// Supplied value.
        value: u128,
        /// Compiled maximum.
        maximum: u128,
    },
}
