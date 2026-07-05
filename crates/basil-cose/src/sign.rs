// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The signed construction: a bare `COSE_Sign1` (control RPC / push
//! surfaces; any sign-only basil surface).

use alloc::vec::Vec;

use crate::claims::{Claims, ProtectedHeaders, ValidationParams};
use crate::codec::{self, Sign1Layer};
use crate::error::{BuildError, VerifyError};
use crate::traits::{Signer, Verifier};
use crate::types::{ContentType, CoseBytes, ExternalAad, KeyId, Signature};

/// Parameters for [`build_signed`].
#[derive(Debug, Clone)]
pub struct SignParams<'a> {
    /// The payload content type (protected header 3).
    pub content_type: ContentType,
    /// The payload to sign (always embedded; detached payloads are not part
    /// of the v1 profile).
    pub payload: &'a [u8],
    /// Optional claims for sign-only messages.
    pub claims: Option<Claims>,
    /// The `Sig_structure` external AAD.
    pub external_aad: ExternalAad,
}

/// Build a bare signed message.
///
/// # Errors
/// [`BuildError::SenderKeyMismatch`] when a present `sender_key_id` claim
/// does not equal the signer key id; [`BuildError::ResponseKeyNotText`];
/// [`BuildError::Sign`] when the signer fails.
pub async fn build_signed<S: Signer>(
    params: &SignParams<'_>,
    signer: &S,
) -> Result<CoseBytes, BuildError> {
    build_signed_with_headers(params, &ProtectedHeaders::default(), signer).await
}

/// Build a bare signed message with additional critical protected headers.
///
/// # Errors
/// [`BuildError::SenderKeyMismatch`] when a present `sender_key_id` claim
/// does not equal the signer key id; [`BuildError::ResponseKeyNotText`];
/// [`BuildError::Sign`] when the signer fails.
pub async fn build_signed_with_headers<S: Signer>(
    params: &SignParams<'_>,
    protected_headers: &ProtectedHeaders,
    signer: &S,
) -> Result<CoseBytes, BuildError> {
    if let Some(claims) = &params.claims {
        if let Some(sender) = &claims.sender_key_id
            && sender != signer.key_id()
        {
            return Err(BuildError::SenderKeyMismatch);
        }
        if let Some(k) = &claims.response_key_id
            && k.as_catalog_name().is_none()
        {
            return Err(BuildError::ResponseKeyNotText);
        }
    }
    let protected = codec::encode_sign1_protected_bare_with_headers(
        signer.algorithm(),
        signer.key_id(),
        &params.content_type,
        params.claims.as_ref(),
        Some(protected_headers),
    )
    .map_err(|codec::CodecError| BuildError::Codec)?;
    let sig_structure =
        codec::sig_structure(&protected, params.external_aad.as_bytes(), params.payload)
            .map_err(|codec::CodecError| BuildError::Codec)?;
    let signature = signer.sign(&sig_structure).await?;
    codec::assemble_sign1(&protected, params.payload, signature.as_bytes())
        .map(CoseBytes::new)
        .map_err(|codec::CodecError| BuildError::Codec)
}

/// Parameters for [`verify_signed`].
#[derive(Debug, Clone)]
pub struct VerifySignedParams<'a> {
    /// The `Sig_structure` external AAD the protocol binds.
    pub external_aad: ExternalAad,
    /// Temporal/audience/role bounds: supply them iff claims are expected.
    /// `Some` demands claims; `None` demands their absence.
    pub validation: Option<&'a ValidationParams>,
}

/// A verified bare signed message.
#[derive(Debug, Clone)]
pub struct VerifiedSigned {
    /// The payload content type.
    pub content_type: ContentType,
    /// The signed payload.
    pub payload: Vec<u8>,
    /// Claims, when the message carried them.
    pub claims: Option<Claims>,
    /// Additional critical protected headers.
    pub protected_headers: ProtectedHeaders,
    /// The outer `kid` that signed the message.
    pub signer_key_id: KeyId,
}

/// Verify a bare signed message.
///
/// In order: strict decode, signature verification via `verifier`, claims
/// presence per `params.validation`, then temporal / audience / role checks
/// and the `sender_key_id == kid` cross-check when claims are present.
///
/// # Errors
/// [`VerifyError::Decode`], verifier failures,
/// [`VerifyError::ClaimsPresenceMismatch`],
/// [`VerifyError::SenderKeyMismatch`], [`VerifyError::Claims`].
pub async fn verify_signed<V: Verifier>(
    bytes: &[u8],
    verifier: &V,
    params: &VerifySignedParams<'_>,
) -> Result<VerifiedSigned, VerifyError> {
    let decoded = codec::decode_sign1_strict(bytes, Sign1Layer::Bare)?;

    let sig_structure = codec::sig_structure(
        &decoded.protected,
        params.external_aad.as_bytes(),
        &decoded.payload,
    )
    .map_err(|codec::CodecError| VerifyError::SignatureInvalid)?;
    let signature = Signature::from_bytes(decoded.signature.clone())
        .map_err(|_| VerifyError::SignatureInvalid)?;
    verifier
        .verify(
            &decoded.kid,
            decoded.algorithm,
            &decoded.protected_headers,
            &sig_structure,
            &signature,
        )
        .await?;

    match (params.validation, &decoded.claims) {
        (Some(validation), Some(claims)) => {
            if let Some(sender) = &claims.sender_key_id
                && sender != &decoded.kid
            {
                return Err(VerifyError::SenderKeyMismatch);
            }
            claims.validate(validation)?;
        }
        (None, None) => {}
        _ => return Err(VerifyError::ClaimsPresenceMismatch),
    }

    let Some(content_type) = decoded.content_type else {
        // Unreachable: the bare decoder requires a content type.
        return Err(VerifyError::Decode(
            crate::error::DecodeError::MissingHeader {
                label: crate::label::HDR_CONTENT_TYPE,
            },
        ));
    };
    Ok(VerifiedSigned {
        content_type,
        payload: decoded.payload,
        claims: decoded.claims,
        protected_headers: decoded.protected_headers,
        signer_key_id: decoded.kid,
    })
}
