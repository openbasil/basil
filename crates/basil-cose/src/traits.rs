// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The `Signer` / `Verifier` / `Recipient` traits.
//!
//! Native `async fn` in traits (AFIT), consumed through generics: no
//! `async_trait` proc-macro dependency and no `dyn` in the public API. Local
//! implementations (this crate's [`keys`](crate::keys)) complete
//! synchronously; broker-backed implementations (which live in the basil
//! client crate, not here) await an RPC.

use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::alg::SignatureAlgorithm;
use crate::claims::ProtectedHeaders;
use crate::error::{OpenError, SignError, VerifyError};
use crate::kdf::KdfParties;
use crate::types::{ExternalAad, KeyId, Signature};

/// Produces the signature over `Sig_structure` bytes.
///
/// The broker backs this with sign-in-place (Ed25519 transit accepts the
/// full arbitrary-length structure); clients use local keys.
pub trait Signer {
    /// The signing key id; becomes the outer `kid`.
    fn key_id(&self) -> &KeyId;

    /// The signature algorithm this signer produces.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Sign the exact `Sig_structure` bytes.
    async fn sign(&self, sig_structure: &[u8]) -> Result<Signature, SignError>;
}

/// Resolves a `kid` and verifies a signature.
///
/// Implementors enforce their own key/alg pinning (a broker checks the wire
/// alg against its catalog record inside its impl; a client checks against
/// its pinned broker key). Async because kid resolution may be remote (for
/// example resolving an unfamiliar peer kid over an RPC); local pinned-key
/// impls complete synchronously.
pub trait Verifier {
    /// Verify `signature` over the exact `Sig_structure` bytes, produced by
    /// the key `key_id` under `algorithm`.
    ///
    /// `protected_headers` carries the decoded critical protected headers (for
    /// example signer-certificate JWTs under `-70006`) so an implementor whose
    /// trust decision depends on them can resolve `key_id` from the message;
    /// implementors that pin keys out of band ignore it.
    async fn verify(
        &self,
        key_id: &KeyId,
        algorithm: SignatureAlgorithm,
        protected_headers: &ProtectedHeaders,
        sig_structure: &[u8],
        signature: &Signature,
    ) -> Result<(), VerifyError>;
}

/// Everything an opener needs, already strictly validated by the decode
/// entry points, plus the raw encrypt bytes so a remote (broker-backed)
/// recipient can forward them verbatim without re-encoding.
///
/// The `Enc_structure` AAD embeds the exact serialized protected-header
/// bytes, so any re-encoding of `cose_encrypt` on the way to the key would
/// break the AEAD tag.
#[derive(Debug, Clone)]
pub struct OpenRequest<'a> {
    /// Exact tagged `COSE_Encrypt` bytes, verbatim.
    pub cose_encrypt: &'a [u8],
    /// Encryption-layer external AAD.
    pub external_aad: &'a ExternalAad,
    /// Pin the KDF party identities, or `None` to accept the message values.
    pub expected_parties: Option<&'a KdfParties>,
}

/// Opens one `COSE_Encrypt` addressed to `key_id()`: ECDH-ES decapsulation +
/// HKDF-256 (`COSE_KDF_Context`) + content AEAD, returning zeroizing
/// plaintext.
///
/// A broker-backed impl forwards `OpenRequest::cose_encrypt` verbatim to the
/// broker unseal RPC; the local impl holds a `Zeroizing` X25519 private. A
/// successful open proves confidentiality, never sender identity. Sender
/// identity comes only from the outer `COSE_Sign1`.
pub trait Recipient {
    /// The recipient (static X25519) key id.
    fn key_id(&self) -> &KeyId;

    /// Open the message, returning the plaintext in a zeroizing buffer.
    async fn open(&self, request: &OpenRequest<'_>) -> Result<Zeroizing<Vec<u8>>, OpenError>;
}
