// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! KDF party identities and the ECDH-ES + HKDF-256 content-key derivation.
//!
//! The HKDF info is the RFC 9053 §5.2 `COSE_KDF_Context` (serialized by the
//! codec seam), never a bespoke label. Party identities ride in the recipient
//! protected headers (`-21`/`-24`) so any opener, including one that is not
//! the sealer, like the broker unseal RPC, can rebuild the context from the
//! message alone.

use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::ProfileError;

/// One party's identity slot in the `COSE_KDF_Context` (RFC 9053 §5.2).
///
/// v1 exposes identity only; the nonce and "other" slots are pinned nil by
/// the profile (their header parameters are rejected on decode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyIdentity(Option<Vec<u8>>);

impl PartyIdentity {
    /// The nil identity (anonymous party).
    #[must_use]
    pub const fn nil() -> Self {
        Self(None)
    }

    /// A concrete party identity (for example edgebox's `d2h`/`h2d`
    /// direction strings).
    ///
    /// # Errors
    /// [`ProfileError::EmptyPartyIdentity`] if the bytes are empty; an empty
    /// identity is indistinguishable in intent from nil, so the profile
    /// forbids it.
    pub fn from_bytes(identity: Vec<u8>) -> Result<Self, ProfileError> {
        if identity.is_empty() {
            return Err(ProfileError::EmptyPartyIdentity);
        }
        Ok(Self(Some(identity)))
    }

    /// The identity bytes, when present.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        self.0.as_deref()
    }
}

/// `PartyU` = message sender, `PartyV` = recipient, per RFC 9053 §5.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParties {
    /// The sender's identity slot.
    pub party_u: PartyIdentity,
    /// The recipient's identity slot.
    pub party_v: PartyIdentity,
}

impl KdfParties {
    /// Both slots nil (the basil invocation v1 posture).
    #[must_use]
    pub const fn anonymous() -> Self {
        Self {
            party_u: PartyIdentity::nil(),
            party_v: PartyIdentity::nil(),
        }
    }

    /// Whether both slots are nil.
    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        self.party_u.0.is_none() && self.party_v.0.is_none()
    }
}

/// Key-derivation failure marker (only reachable on an out-of-range HKDF
/// output length, never for the fixed 32-byte key; kept so the construction
/// cannot `unwrap`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfFailed;

/// Derive the 256-bit content-encryption key: HKDF-SHA-256 with no salt over
/// the X25519 shared secret, with the serialized `COSE_KDF_Context` as info.
pub fn derive_cek(
    shared_secret: &Zeroizing<[u8; 32]>,
    kdf_context: &[u8],
) -> Result<Zeroizing<[u8; 32]>, KdfFailed> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_slice());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(kdf_context, okm.as_mut_slice())
        .map_err(|_| KdfFailed)?;
    Ok(okm)
}
