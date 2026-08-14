// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! gRPC service adapters.

mod admin;
mod aead;
pub mod broker;
mod invocation;
#[cfg(feature = "http")]
pub mod jwks;
mod minting;
mod nix_cache;
pub mod sds;
mod secret;
mod shared;
mod signing;
pub mod spiffe;
