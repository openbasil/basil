// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Core broker state, policy, backends, audit, and reconciliation.

pub mod actor;
pub mod audit;
pub mod backend;
pub mod capability;
pub mod catalog;
pub mod configuration;
pub mod crypto_provider;
pub mod decision;
pub mod ed25519_sign;
pub mod event;
pub mod manager;
pub mod minter;
pub mod ml_dsa_sign;
pub mod ml_kem_envelope;
pub mod peer;
pub mod reconcile;
pub mod release_admission;
pub mod reload;
pub mod revocation;
pub mod seal;
pub mod state;
pub mod x25519_seal;

#[cfg(feature = "tpm2")]
pub mod identity;

/// Whether a system TPM is present (resource-manager or raw device node).
///
/// Ungated probe shared by the `tpm2` local-identity scaffolding and the
/// `unlock-tpm` sealed-bundle slot, so neither feature needs to enable the
/// other. Mirrors `brightnexus-platform`'s `tpm_available()`.
#[must_use]
pub fn tpm_device_present() -> bool {
    std::path::Path::new("/dev/tpmrm0").exists() || std::path::Path::new("/dev/tpm0").exists()
}
