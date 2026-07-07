// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared sealed-bundle slot KDF/AAD helpers.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use super::super::format::Argon2Params;
use super::UnlockError;

/// The largest accepted Argon2 memory cost: 1 GiB (production profile is
/// 64 MiB, §8.2). The slot params come from the on-disk bundle and are consumed
/// **before** authentication, so they must be bounded or a tampered bundle can
/// OOM the daemon at startup.
const MAX_M_COST_KIB: u32 = 1_048_576;
/// The smallest accepted Argon2 memory cost (the algorithm's own floor).
const MIN_M_COST_KIB: u32 = 8;
/// The largest accepted Argon2 time cost (production profile is 3).
const MAX_T_COST: u32 = 64;
/// The largest accepted Argon2 parallelism (production profile is 1).
const MAX_P_COST: u32 = 64;

/// Shared Argon2id slot-key derivation.
///
/// The cost parameters are read from the unauthenticated bundle header, so they
/// are rejected outside a sane band before any memory is allocated: a tampered
/// `m_cost_kib` must fail closed, not OOM the daemon.
pub fn derive_slot_key(
    secret: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>, UnlockError> {
    if !(MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&params.m_cost_kib)
        || !(1..=MAX_T_COST).contains(&params.t_cost)
        || !(1..=MAX_P_COST).contains(&params.p_cost)
    {
        return Err(UnlockError::ParamsMismatch(format!(
            "argon2 costs out of accepted band (m_cost_kib {MIN_M_COST_KIB}..={MAX_M_COST_KIB}, \
             t_cost 1..={MAX_T_COST}, p_cost 1..={MAX_P_COST}): \
             m={}, t={}, p={}",
            params.m_cost_kib, params.t_cost, params.p_cost
        )));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const fn params(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Argon2Params {
        Argon2Params {
            m_cost_kib,
            t_cost,
            p_cost,
        }
    }

    #[test]
    fn production_params_are_inside_the_band() {
        let m = Argon2Params::PRODUCTION.m_cost_kib;
        let t = Argon2Params::PRODUCTION.t_cost;
        let p = Argon2Params::PRODUCTION.p_cost;
        assert!((MIN_M_COST_KIB..=MAX_M_COST_KIB).contains(&m));
        assert!((1..=MAX_T_COST).contains(&t));
        assert!((1..=MAX_P_COST).contains(&p));
    }

    #[test]
    fn oversized_costs_are_rejected_before_allocation() {
        // ~256 GiB memory request from a tampered bundle: must fail closed
        // without allocating (finding 11).
        for bad in [
            params(268_435_456, 3, 1),
            params(MIN_M_COST_KIB, MAX_T_COST + 1, 1),
            params(MIN_M_COST_KIB, 1, MAX_P_COST + 1),
            params(0, 3, 1),
            params(MIN_M_COST_KIB, 0, 1),
            params(MIN_M_COST_KIB, 1, 0),
        ] {
            let err = derive_slot_key(b"secret", b"0123456789abcdef", bad)
                .expect_err("out-of-band costs must be rejected");
            assert!(matches!(err, UnlockError::ParamsMismatch(_)), "{err}");
        }
    }

    #[test]
    fn in_band_costs_derive_a_key() {
        let key = derive_slot_key(b"secret", b"0123456789abcdef", params(8, 1, 1))
            .expect("minimal in-band costs derive");
        assert_ne!(*key, [0u8; 32]);
    }
}
