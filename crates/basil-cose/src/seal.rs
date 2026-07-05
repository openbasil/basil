// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The sealed construction: a `COSE_Sign1` over an embedded tagged
//! `COSE_Encrypt` (basil invocation requests/responses, peer messages).
//!
//! Verification and opening are two explicit stages so a verifier can run
//! replay/expiry/audience preflight on the signature-trusted claims before
//! any decryption, and so opening can be remote (broker unseal-in-place).

use alloc::vec::Vec;

use crate::claims::{Claims, MessageRole, ValidationParams};
use crate::codec::{self, ClaimsExpectation, NONCE_LEN, Sign1Layer};
use crate::encrypt::{EncryptCore, Opened, build_encrypt_core, random_array};
use crate::error::{BuildError, DecodeError, OpenError, VerifyError};
use crate::kdf::KdfParties;
use crate::keys::X25519RecipientPublic;
use crate::traits::{OpenRequest, Recipient, Signer, Verifier};
use crate::types::{ContentType, CoseBytes, ExternalAad, KeyId, SealedAad};

#[cfg(feature = "fixtures")]
use crate::encrypt::SealParts;
use zeroize::Zeroizing;

/// Parameters for [`build_sealed`].
#[derive(Debug, Clone)]
pub struct SealParams<'a> {
    /// The plaintext content type (embedded protected header 3).
    pub content_type: ContentType,
    /// The plaintext to seal.
    pub plaintext: &'a [u8],
    /// The claim set; `sender_key_id` must equal the signer key id.
    pub claims: Claims,
    /// The role shape the claims must satisfy.
    pub role: MessageRole,
    /// The recipient's static X25519 public key.
    pub recipient: X25519RecipientPublic,
    /// The content-encryption algorithm.
    pub content_algorithm: ContentAlgorithm,
    /// Per-layer external AAD.
    pub aad: SealedAad,
    /// KDF party identities.
    pub kdf_parties: KdfParties,
}

use crate::alg::ContentAlgorithm;

fn check_seal_claims<S: Signer>(params: &SealParams<'_>, signer: &S) -> Result<(), BuildError> {
    params
        .claims
        .validate_role(params.role)
        .map_err(BuildError::RoleShape)?;
    if params.claims.sender_key_id.as_ref() != Some(signer.key_id()) {
        return Err(BuildError::SenderKeyMismatch);
    }
    if let Some(k) = &params.claims.response_key_id
        && k.as_catalog_name().is_none()
    {
        return Err(BuildError::ResponseKeyNotText);
    }
    Ok(())
}

async fn build_sealed_inner<S: Signer>(
    params: &SealParams<'_>,
    signer: &S,
    ephemeral_private: &Zeroizing<[u8; 32]>,
    nonce: [u8; NONCE_LEN],
) -> Result<CoseBytes, BuildError> {
    check_seal_claims(params, signer)?;
    let encrypt_bytes = build_encrypt_core(
        &EncryptCore {
            content_algorithm: params.content_algorithm,
            content_type: &params.content_type,
            claims: Some(&params.claims),
            plaintext: params.plaintext,
            recipient: &params.recipient,
            external_aad: &params.aad.encryption,
            kdf_parties: &params.kdf_parties,
        },
        ephemeral_private,
        nonce,
    )?;
    let protected = codec::encode_sign1_protected_sealed_outer(signer.algorithm(), signer.key_id())
        .map_err(|codec::CodecError| BuildError::Codec)?;
    let sig_structure =
        codec::sig_structure(&protected, params.aad.signature.as_bytes(), &encrypt_bytes)
            .map_err(|codec::CodecError| BuildError::Codec)?;
    let signature = signer.sign(&sig_structure).await?;
    codec::assemble_sign1(&protected, &encrypt_bytes, signature.as_bytes())
        .map(CoseBytes::new)
        .map_err(|codec::CodecError| BuildError::Codec)
}

/// Build a sealed message: encrypt `plaintext` to the recipient, then sign
/// the embedded tagged `COSE_Encrypt` with `signer`.
///
/// The library generates the 12-byte content nonce and the ephemeral X25519
/// keypair internally (fresh per message, zeroized); there is no
/// caller-supplied-nonce path in the public API.
///
/// # Errors
/// [`BuildError::RoleShape`] / [`BuildError::SenderKeyMismatch`] /
/// [`BuildError::ResponseKeyNotText`] on claim-shape violations;
/// [`BuildError::Rng`] when OS randomness is unavailable;
/// [`BuildError::Sign`] when the signer fails.
pub async fn build_sealed<S: Signer>(
    params: &SealParams<'_>,
    signer: &S,
) -> Result<CoseBytes, BuildError> {
    let ephemeral = random_array::<32>()?;
    let nonce = random_array::<NONCE_LEN>()?;
    build_sealed_inner(params, signer, &ephemeral, *nonce).await
}

/// [`build_sealed`] with caller-supplied ephemeral/nonce parts, for
/// deterministic test vectors only.
///
/// # Errors
/// As [`build_sealed`], minus [`BuildError::Rng`].
#[cfg(feature = "fixtures")]
pub async fn build_sealed_with_parts<S: Signer>(
    params: &SealParams<'_>,
    signer: &S,
    parts: &SealParts,
) -> Result<CoseBytes, BuildError> {
    build_sealed_inner(params, signer, &parts.ephemeral_private, parts.nonce).await
}

/// Parameters for [`verify_sealed`].
#[derive(Debug, Clone)]
pub struct VerifySealedParams<'a> {
    /// The `Sig_structure` external AAD the protocol binds (empty for basil
    /// invocation).
    pub signature_aad: ExternalAad,
    /// Temporal/audience/role validation bounds.
    pub validation: &'a ValidationParams,
}

/// A verified (signature-checked, claims-validated) sealed message, not yet
/// opened.
#[derive(Debug, Clone)]
pub struct VerifiedSealed {
    /// The signature-trusted claims, available pre-decrypt.
    pub claims: Claims,
    /// The plaintext content type.
    pub content_type: ContentType,
    /// The outer `kid`; equals `claims.sender_key_id` (checked).
    pub signer_key_id: KeyId,
    /// The recipient static key id from the recipient structure.
    pub recipient_key_id: KeyId,
    /// The content-encryption algorithm.
    pub content_algorithm: ContentAlgorithm,
    /// The KDF party identities from the recipient protected header.
    pub parties: KdfParties,
    /// The exact embedded tagged `COSE_Encrypt` bytes for `open()`.
    encrypt_bytes: Vec<u8>,
}

/// Verify a sealed message.
///
/// In order: strict decode (the payload must be a tagged `COSE_Encrypt`),
/// signature verification via `verifier`, the `sender_key_id == outer kid`
/// cross-check, and the temporal + audience + role checks from the
/// validation params.
///
/// Replay-cache lookup stays a caller concern (`VerifiedSealed::claims`'
/// `message_id` is the input); this crate is state-free.
///
/// # Errors
/// [`VerifyError::Decode`] on any strict-decode rejection;
/// [`VerifyError::SignatureInvalid`] and friends from the verifier;
/// [`VerifyError::SenderKeyMismatch`]; [`VerifyError::Claims`].
pub async fn verify_sealed<V: Verifier>(
    bytes: &[u8],
    verifier: &V,
    params: &VerifySealedParams<'_>,
) -> Result<VerifiedSealed, VerifyError> {
    let outer = codec::decode_sign1_strict(bytes, Sign1Layer::SealedOuter)?;
    let embedded = codec::decode_encrypt_strict(&outer.payload, ClaimsExpectation::Required)
        .map_err(|e| match e {
            DecodeError::NotTagged | DecodeError::WrongTag { .. } => {
                VerifyError::Decode(DecodeError::EmbeddedNotEncrypt)
            }
            other => VerifyError::Decode(other),
        })?;

    let sig_structure = codec::sig_structure(
        &outer.protected,
        params.signature_aad.as_bytes(),
        &outer.payload,
    )
    .map_err(|codec::CodecError| VerifyError::Decode(DecodeError::Malformed))?;
    let signature = crate::types::Signature::from_bytes(outer.signature.clone())
        .map_err(|_| VerifyError::SignatureInvalid)?;
    verifier
        .verify(
            &outer.kid,
            outer.algorithm,
            &outer.protected_headers,
            &sig_structure,
            &signature,
        )
        .await?;

    let claims = embedded
        .claims
        .ok_or(VerifyError::Decode(DecodeError::MissingHeader {
            label: crate::label::HDR_CWT_CLAIMS,
        }))?;
    // The strip-and-re-sign cross-check: the claim under the AEAD-bound
    // protected header must name the outer signing key.
    if claims.sender_key_id.as_ref() != Some(&outer.kid) {
        return Err(VerifyError::SenderKeyMismatch);
    }
    claims.validate(params.validation)?;

    Ok(VerifiedSealed {
        claims,
        content_type: embedded.content_type,
        signer_key_id: outer.kid,
        recipient_key_id: embedded.recipient_kid,
        content_algorithm: embedded.content_algorithm,
        parties: embedded.parties,
        encrypt_bytes: outer.payload,
    })
}

impl VerifiedSealed {
    /// Open the embedded `COSE_Encrypt` with `recipient`, binding the
    /// encryption-layer `aad`, optionally pinning the KDF party identities.
    ///
    /// # Errors
    /// [`OpenError::RecipientKeyMismatch`] when `recipient` holds a
    /// different key than the message addresses; [`OpenError::PartyMismatch`]
    /// on pinned-party disagreement; [`OpenError::OpenFailed`] (opaque) on
    /// any authentication failure.
    pub async fn open<R: Recipient>(
        &self,
        recipient: &R,
        aad: &ExternalAad,
        expected_parties: Option<&KdfParties>,
    ) -> Result<Opened, OpenError> {
        if recipient.key_id() != &self.recipient_key_id {
            return Err(OpenError::RecipientKeyMismatch);
        }
        if let Some(expected) = expected_parties
            && *expected != self.parties
        {
            return Err(OpenError::PartyMismatch);
        }
        let request = OpenRequest {
            cose_encrypt: &self.encrypt_bytes,
            external_aad: aad,
            expected_parties,
        };
        let plaintext = recipient.open(&request).await?;
        Ok(Opened {
            plaintext,
            content_type: self.content_type.clone(),
        })
    }

    /// The exact embedded tagged `COSE_Encrypt` bytes (what a broker-backed
    /// opener forwards verbatim).
    #[must_use]
    pub fn encrypt_bytes(&self) -> &[u8] {
        &self.encrypt_bytes
    }
}
