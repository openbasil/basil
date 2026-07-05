// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared sealed-bundle slot KDF/AAD helpers.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use super::super::format::Argon2Params;
use super::UnlockError;

/// Shared Argon2id slot-key derivation.
pub fn derive_slot_key(
    secret: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, UnlockError> {
    let p = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| UnlockError::Crypto(format!("argon2 params: {e}")))?;
    let kdf = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    kdf.hash_password_into(secret, salt, out.as_mut())
        .map_err(|e| UnlockError::Crypto(format!("argon2 derive: {e}")))?;
    Ok(out)
}

/// The KEK-wrap AAD: header bytes concatenated with the slot id (§2.4), so a
/// slot cannot be spliced under a different id or header.
pub fn wrap_aad(header_aad: &[u8], slot_id: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header_aad.len() + 4);
    aad.extend_from_slice(header_aad);
    aad.extend_from_slice(&slot_id.to_be_bytes());
    aad
}
