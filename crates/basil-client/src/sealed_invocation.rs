// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Client-side COSE sealed invocation helpers.
//!
//! The broker carrier is raw tagged COSE bytes in
//! [`SealedRequest`](basil_proto::broker::v1::SealedRequest) and
//! [`SealedResponse`](basil_proto::broker::v1::SealedResponse). This module
//! owns the basil-specific request body selection, response correlation
//! checks, and client adapters for broker-backed signing and unsealing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use basil_cose::{
    BuildError, Claims, ContentAlgorithm, ContentType, Ed25519Verifier, ExternalAad,
    FreshnessChallenge, KdfParties, KeyId, MessageId, MessageRole, OpenError, OpenRequest,
    ProtectedHeaders, Recipient, RequestHash, SealParams, SealedAad, SignError, Signature,
    SignatureAlgorithm, Signer, Subject, UnixTime, ValidationParams, VerifyError,
    VerifySealedParams, X25519Recipient, X25519RecipientPublic, X25519ResponsePublicKey, Zeroizing,
    build_sealed, build_sealed_with_headers, request_hash, verify_sealed,
};
use basil_proto::broker::v1 as pb;
use basil_proto::invocation::{
    CONTENT_TYPE_SIGN_REQUEST, CONTENT_TYPE_SIGN_RESPONSE, InvocationStatusCode,
    SignInvocationRequest, SignInvocationResponse,
};
use tokio::sync::Mutex;

use crate::client::Client;

/// Local Ed25519 signer for sealed invocation requests.
///
/// This is the same broker-free implementation shipped by `basil-cose`,
/// re-exported here so client callers do not have to depend on the lower
/// layer's module layout.
pub type LocalSealedInvocationSigner = basil_cose::Ed25519Signer;

/// Local X25519 recipient for broker responses.
///
/// This is useful when the caller owns the response key locally and wants the
/// client helper to decrypt the broker's sealed response in process.
pub type LocalSealedInvocationRecipient = basil_cose::X25519Recipient;

/// Request metadata for building a COSE sealed invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedInvocationOptions {
    /// Caller-generated message id, unique inside the replay window.
    pub message_id: String,
    /// Unix timestamp when the request is issued.
    pub issued_at_unix: u32,
    /// Optional Unix timestamp when the request expires.
    pub expires_at_unix: Option<u32>,
    /// Catalog signing key id whose private key signs the request.
    pub sender_sign_id: String,
    /// Optional sender subject.
    pub sender_subject: Option<String>,
    /// Broker invocation-encryption key id.
    pub recipient_key_id: String,
    /// Optional broker recipient subject.
    pub recipient_subject: Option<String>,
    /// Caller-controlled response encryption key id.
    pub response_encryption_key_id: String,
    /// Optional server-issued single-use freshness challenge (exactly 32
    /// bytes), obtained from `InvocationService.GetInvocationChallenge` and
    /// carried as encrypted-layer claim `-70008`. Remote CI invocations must
    /// set it; local direct invocations leave it `None`.
    pub freshness_challenge: Option<[u8; 32]>,
}

/// Request metadata for a provider-proof invocation with a fresh ephemeral
/// response key.
///
/// Unlike [`SealedInvocationOptions`], this shape has no caller-selected
/// response catalog id. [`prepare_ephemeral_sealed_invocation`] generates a
/// new X25519 keypair and binds its RFC 7638 thumbprint automatically.
/// `recipient_subject` is the broker audience for the COSE claims. The OIDC
/// proof audience remains inside the provider token carried in the protected
/// headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralSealedInvocationOptions {
    /// Caller-generated message id, unique inside the freshness window.
    pub message_id: String,
    /// Unix timestamp when the request is issued.
    pub issued_at_unix: u32,
    /// Optional Unix timestamp when the request expires.
    pub expires_at_unix: Option<u32>,
    /// Request proof-signing key id.
    pub sender_sign_id: String,
    /// Optional sender subject.
    pub sender_subject: Option<String>,
    /// Broker invocation-encryption key id.
    pub recipient_key_id: String,
    /// Configured broker audience encoded as the COSE `Claims::audience`.
    ///
    /// The provider OIDC audience is carried only by the signed provider token
    /// in the protected proof headers.
    pub recipient_subject: Option<String>,
    /// Server-issued single-use freshness challenge.
    pub freshness_challenge: [u8; 32],
}

/// A prepared raw COSE invocation request plus the client-side correlation
/// state needed to verify its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSealedInvocation {
    /// Complete tagged request `COSE_Sign1` bytes.
    pub message: Vec<u8>,
    /// Request message id (`cti`), used by response claim `-70001`.
    pub message_id: Vec<u8>,
    /// Caller-requested response encryption key id, used to reject responses
    /// sealed to any other key.
    pub response_encryption_key_id: String,
    /// SHA3-256 of [`message`](Self::message), used by response claim
    /// `-70002`.
    pub request_hash: [u8; 32],
}

impl PreparedSealedInvocation {
    /// Return the wire request carrier.
    #[must_use]
    pub fn into_sealed_request(self) -> pb::SealedRequest {
        pb::SealedRequest {
            message: self.message,
        }
    }

    /// Borrow this prepared request as the wire carrier.
    #[must_use]
    pub fn to_sealed_request(&self) -> pb::SealedRequest {
        pb::SealedRequest {
            message: self.message.clone(),
        }
    }
}

/// A prepared provider-proof invocation and its private response recipient.
///
/// This type intentionally implements neither `Clone` nor `Debug`: it owns
/// the per-request X25519 private half, held by a zeroizing recipient. Use
/// [`Self::to_sealed_request`] to send the request, then
/// [`Self::verify_and_decrypt_sign_response`] to authenticate and open the
/// broker response against pinned signing keys.
///
/// The private-owning handle cannot be cloned or debug-formatted:
///
/// ```compile_fail
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<basil::PreparedEphemeralSealedInvocation>();
/// ```
///
/// ```compile_fail
/// fn requires_debug<T: core::fmt::Debug>() {}
/// requires_debug::<basil::PreparedEphemeralSealedInvocation>();
/// ```
pub struct PreparedEphemeralSealedInvocation {
    prepared: PreparedSealedInvocation,
    response_recipient: X25519Recipient,
}

impl PreparedEphemeralSealedInvocation {
    /// Borrow the prepared correlation metadata and exact request bytes.
    #[must_use]
    pub const fn prepared(&self) -> &PreparedSealedInvocation {
        &self.prepared
    }

    /// Borrow this prepared request as the wire carrier.
    #[must_use]
    pub fn to_sealed_request(&self) -> pb::SealedRequest {
        self.prepared.to_sealed_request()
    }

    /// Verify a broker-protected response with pinned Ed25519 keys and open
    /// it with this request's private ephemeral recipient.
    ///
    /// # Errors
    /// Returns [`SealedInvocationResponseError`] if signature verification,
    /// correlation, response recipient selection, authenticated opening,
    /// content type, or body decoding fails.
    pub async fn verify_and_decrypt_sign_response(
        &self,
        response: &pb::SealedResponse,
        broker_signing_keys: &BTreeMap<String, Vec<u8>>,
        validation: &ValidationParams,
    ) -> Result<SignInvocationResponse, SealedInvocationResponseError> {
        let verifier = pinned_broker_verifier(broker_signing_keys)?;
        verify_and_open_sign_response(
            &self.prepared,
            response,
            &self.response_recipient,
            &verifier,
            validation,
        )
        .await
    }
}

/// A signer backed by the broker `SigningService.Sign` RPC.
///
/// This signs the exact COSE `Sig_structure` bytes in place through an
/// already-connected agent socket client.
#[derive(Clone)]
pub struct BrokerSigner {
    client: Arc<Mutex<Client>>,
    key_id: KeyId,
}

impl BrokerSigner {
    /// Build a broker-backed signer for `key_id`.
    ///
    /// # Errors
    /// Returns [`SealedInvocationError::Profile`] if `key_id` is outside the
    /// COSE `kid` bounds.
    pub fn new(client: Arc<Mutex<Client>>, key_id: &str) -> Result<Self, SealedInvocationError> {
        Ok(Self {
            client,
            key_id: KeyId::from_text(key_id)?,
        })
    }
}

impl Signer for BrokerSigner {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EdDsa
    }

    async fn sign(&self, sig_structure: &[u8]) -> Result<Signature, SignError> {
        let key_id = self
            .key_id
            .as_catalog_name()
            .ok_or(SignError::AlgorithmUnsupported)?;
        let mut client = self.client.lock().await;
        let signature =
            client
                .sign(key_id, sig_structure)
                .await
                .map_err(|e| SignError::Provider {
                    message: e.to_string(),
                })?;
        drop(client);
        Signature::from_bytes(signature).map_err(|e| SignError::Provider {
            message: e.to_string(),
        })
    }
}

/// A recipient backed by the broker `AeadService.UnsealCose` RPC.
///
/// The adapter forwards the exact embedded tagged `COSE_Encrypt` bytes from
/// [`OpenRequest::cose_encrypt`] to the broker. It never parses and re-encodes
/// the message, preserving the protected-header bytes bound by COSE AAD.
#[derive(Clone)]
pub struct BrokerRecipient {
    client: Arc<Mutex<Client>>,
    key_id: KeyId,
}

impl BrokerRecipient {
    /// Build a broker-backed recipient for `key_id`.
    ///
    /// # Errors
    /// Returns [`SealedInvocationError::Profile`] if `key_id` is outside the
    /// COSE `kid` bounds.
    pub fn new(client: Arc<Mutex<Client>>, key_id: &str) -> Result<Self, SealedInvocationError> {
        Ok(Self {
            client,
            key_id: KeyId::from_text(key_id)?,
        })
    }

    /// Build the exact `UnsealCose` request this recipient would send.
    ///
    /// This is primarily useful for tests and for callers that need to inspect
    /// broker request construction without performing the RPC.
    ///
    /// # Errors
    /// Returns [`OpenError::RecipientKeyMismatch`] if this recipient's key id
    /// is not a UTF-8 catalog name.
    pub fn unseal_cose_request(
        &self,
        request: &OpenRequest<'_>,
    ) -> Result<pb::UnsealCoseRequest, OpenError> {
        Self::unseal_cose_request_for(&self.key_id, request)
    }

    /// Build an `UnsealCose` request for `key_id` without requiring a client.
    ///
    /// This is the pure request-construction half of the broker-backed
    /// recipient and is useful in tests for checking that exact COSE bytes are
    /// forwarded.
    ///
    /// # Errors
    /// Returns [`OpenError::RecipientKeyMismatch`] if `key_id` is not a UTF-8
    /// catalog name.
    pub fn unseal_cose_request_for(
        key_id: &KeyId,
        request: &OpenRequest<'_>,
    ) -> Result<pb::UnsealCoseRequest, OpenError> {
        let key_id = key_id
            .as_catalog_name()
            .ok_or(OpenError::RecipientKeyMismatch)?;
        Ok(pb::UnsealCoseRequest {
            key_id: key_id.to_string(),
            cose_encrypt: request.cose_encrypt.to_vec(),
            external_aad: Some(request.external_aad.as_bytes().to_vec()),
        })
    }
}

impl Recipient for BrokerRecipient {
    fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    async fn open(&self, request: &OpenRequest<'_>) -> Result<Zeroizing<Vec<u8>>, OpenError> {
        let rpc = self.unseal_cose_request(request)?;
        let mut client = self.client.lock().await;
        let plaintext = client
            .unseal_cose(&rpc.key_id, &rpc.cose_encrypt, rpc.external_aad.as_deref())
            .await
            .map_err(|e| OpenError::Provider {
                message: e.to_string(),
            })?;
        drop(client);
        Ok(Zeroizing::new(plaintext))
    }
}

/// Errors returned while preparing a sealed invocation request.
#[derive(Debug, thiserror::Error)]
pub enum SealedInvocationError {
    /// A COSE profile identifier or typed value was invalid.
    #[error("invalid COSE profile value: {0}")]
    Profile(#[from] basil_cose::ProfileError),
    /// The recipient public key was not exactly 32 bytes.
    #[error("X25519 recipient public key must be 32 bytes, got {actual}")]
    RecipientPublicKeyLength {
        /// The length actually supplied.
        actual: usize,
    },
    /// The `basil-cose` sealed builder rejected the request.
    #[error("failed to build sealed invocation request: {0}")]
    Build(#[from] BuildError),
    /// Provider-proof headers required by ephemeral response-key mode were
    /// absent or empty.
    #[error("ephemeral response-key requests require provider proof headers")]
    MissingProviderProofHeaders,
}

/// Errors returned while verifying and decrypting a protected broker response.
#[derive(Debug, thiserror::Error)]
pub enum SealedInvocationResponseError {
    /// A COSE profile identifier or typed value was invalid.
    #[error("invalid COSE profile value: {0}")]
    Profile(#[from] basil_cose::ProfileError),
    /// A pinned broker public key was not exactly 32 bytes.
    #[error("broker Ed25519 public key must be 32 bytes, got {actual}")]
    BrokerPublicKeyLength {
        /// The length actually supplied.
        actual: usize,
    },
    /// The response X25519 private key was not exactly 32 bytes.
    #[error("response X25519 private key must be 32 bytes, got {actual}")]
    ResponsePrivateKeyLength {
        /// The length actually supplied.
        actual: usize,
    },
    /// `basil-cose` verification rejected the response.
    #[error("failed to verify sealed response: {0}")]
    Verify(#[from] VerifyError),
    /// `basil-cose` opening rejected the response.
    #[error("failed to open sealed response: {0}")]
    Open(#[from] OpenError),
    /// The response did not answer the prepared request.
    #[error("sealed response in-reply-to claim did not match the request")]
    InReplyToMismatch,
    /// The response request hash did not match the exact request bytes.
    #[error("sealed response request hash did not match the request")]
    RequestHashMismatch,
    /// The response plaintext content type was not a sign response.
    #[error("sealed response content type was {actual}, expected {expected}")]
    UnexpectedContentType {
        /// The content type that was opened.
        actual: String,
        /// The required content type.
        expected: &'static str,
    },
    /// The decrypted sign response body did not match the basil CBOR schema.
    #[error("invalid sign response body: {0}")]
    SignResponseBody(#[from] basil_proto::invocation::InvocationError),
}

/// Prepare a sealed `Sign` invocation request.
///
/// `Sign` is the only invocation the broker executes; the minting body
/// schemas registered in `basil_proto::invocation` have no response decoder
/// and are rejected by the broker, so they cannot be prepared here.
///
/// The client chooses no nonce or ephemeral key material itself:
/// [`build_sealed`] generates the COSE content nonce and ephemeral X25519 key
/// internally. `recipient_public_key` is the broker invocation-encryption
/// public key.
///
/// # Errors
/// Returns [`SealedInvocationError`] when an option is outside the COSE
/// profile bounds, the recipient public key is not 32 bytes, or the signer /
/// sealed builder fails.
#[allow(
    clippy::future_not_send,
    reason = "generic over basil-cose AFIT Signer; Send is a caller-side bound"
)]
pub async fn prepare_sealed_invocation<S: Signer>(
    options: SealedInvocationOptions,
    recipient_public_key: &[u8],
    body: &SignInvocationRequest,
    signer: &S,
) -> Result<PreparedSealedInvocation, SealedInvocationError> {
    prepare_sealed_invocation_inner(options, recipient_public_key, body, signer, None, None).await
}

/// Prepare a provider-proof sealed `Sign` invocation with a fresh X25519
/// response key.
///
/// The response keypair is generated from the system CSPRNG for this request
/// only. The encrypted protected header receives critical label `-70009` and
/// the matching RFC 7638 thumbprint in `response_key_id`. The supplied
/// `proof_headers` are placed on the outer signature, which is produced only
/// after both response-key fields are fixed. The broker audience comes from
/// `options.recipient_subject`; provider-token audiences are left unchanged in
/// `proof_headers`. Critical header `-70010` binds `body.key_id` as the sole
/// provider operation target before the body is encrypted.
///
/// # Errors
/// Returns [`SealedInvocationError`] for invalid profile values, malformed
/// broker encryption public keys, unavailable randomness, or build/signing
/// failures.
#[allow(
    clippy::future_not_send,
    reason = "generic over basil-cose AFIT Signer; Send is a caller-side bound"
)]
pub async fn prepare_ephemeral_sealed_invocation<S: Signer>(
    options: EphemeralSealedInvocationOptions,
    recipient_public_key: &[u8],
    body: &SignInvocationRequest,
    proof_headers: &ProtectedHeaders,
    signer: &S,
) -> Result<PreparedEphemeralSealedInvocation, SealedInvocationError> {
    if proof_headers.signer_certificates_jwt.is_empty()
        || proof_headers
            .signer_public_key_cose
            .as_ref()
            .is_none_or(Vec::is_empty)
    {
        return Err(SealedInvocationError::MissingProviderProofHeaders);
    }
    let (response_recipient, response_public_key) = X25519Recipient::generate_ephemeral_response()?;
    let response_encryption_key_id = response_public_key.thumbprint();
    let options = SealedInvocationOptions {
        message_id: options.message_id,
        issued_at_unix: options.issued_at_unix,
        expires_at_unix: options.expires_at_unix,
        sender_sign_id: options.sender_sign_id,
        sender_subject: options.sender_subject,
        recipient_key_id: options.recipient_key_id,
        recipient_subject: options.recipient_subject,
        response_encryption_key_id,
        freshness_challenge: Some(options.freshness_challenge),
    };
    let prepared = prepare_sealed_invocation_inner(
        options,
        recipient_public_key,
        body,
        signer,
        Some(response_public_key),
        Some(proof_headers),
    )
    .await?;
    Ok(PreparedEphemeralSealedInvocation {
        prepared,
        response_recipient,
    })
}

#[allow(
    clippy::future_not_send,
    reason = "generic over basil-cose AFIT Signer; Send is a caller-side bound"
)]
async fn prepare_sealed_invocation_inner<S: Signer>(
    options: SealedInvocationOptions,
    recipient_public_key: &[u8],
    body: &SignInvocationRequest,
    signer: &S,
    response_public_key_cose: Option<X25519ResponsePublicKey>,
    protected_headers: Option<&ProtectedHeaders>,
) -> Result<PreparedSealedInvocation, SealedInvocationError> {
    let sender_key_id = KeyId::from_text(&options.sender_sign_id)?;
    let response_key_id = KeyId::from_text(&options.response_encryption_key_id)?;
    let recipient_key_id = KeyId::from_text(&options.recipient_key_id)?;
    let protected_headers = protected_headers.cloned().map(|mut headers| {
        headers.operation_target_key_id = Some(KeyId::from_text(&body.key_id)?);
        Ok::<_, SealedInvocationError>(headers)
    });
    let protected_headers = protected_headers.transpose()?;
    let public: [u8; 32] = recipient_public_key.try_into().map_err(|_| {
        SealedInvocationError::RecipientPublicKeyLength {
            actual: recipient_public_key.len(),
        }
    })?;

    let claims = Claims {
        issuer: optional_subject(options.sender_subject)?,
        audience: optional_subject(options.recipient_subject)?,
        expires_at: options.expires_at_unix.map(|t| UnixTime(i64::from(t))),
        issued_at: UnixTime(i64::from(options.issued_at_unix)),
        message_id: MessageId::from_bytes(options.message_id.into_bytes())?,
        sender_key_id: Some(sender_key_id),
        response_key_id: Some(response_key_id),
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
        freshness_challenge: options.freshness_challenge.map(FreshnessChallenge::new),
        response_public_key_cose,
    };
    let message_id = claims.message_id.as_bytes().to_vec();

    let params = SealParams {
        content_type: ContentType::new(CONTENT_TYPE_SIGN_REQUEST.to_string())?,
        plaintext: &body.to_cbor_bytes(),
        claims,
        role: MessageRole::Request,
        recipient: X25519RecipientPublic {
            key_id: recipient_key_id,
            public,
        },
        content_algorithm: ContentAlgorithm::A256Gcm,
        aad: SealedAad::empty(),
        kdf_parties: KdfParties::anonymous(),
    };
    let cose = match protected_headers.as_ref() {
        Some(headers) => build_sealed_with_headers(&params, headers, signer).await?,
        None => build_sealed(&params, signer).await?,
    };
    let message = cose.into_vec();
    let RequestHash(hash) = request_hash(&message);

    Ok(PreparedSealedInvocation {
        message,
        message_id,
        response_encryption_key_id: options.response_encryption_key_id,
        request_hash: hash,
    })
}

/// Verify a broker-protected `Sign` response and decrypt its CBOR body.
///
/// `broker_signing_keys` is pinned trust: keys are catalog ids mapped to raw
/// Ed25519 public keys. `response_private_key` is the caller-controlled
/// X25519 response key requested in the prepared invocation.
///
/// # Errors
/// Returns [`SealedInvocationResponseError`] if the broker signature, response
/// claims, response recipient key, request hash, COSE open, content type, or
/// plaintext body schema fails validation.
pub async fn verify_and_decrypt_sign_response(
    request: &PreparedSealedInvocation,
    response: &pb::SealedResponse,
    response_private_key: &[u8],
    broker_signing_keys: &BTreeMap<String, Vec<u8>>,
    validation: &ValidationParams,
) -> Result<SignInvocationResponse, SealedInvocationResponseError> {
    let verifier = pinned_broker_verifier(broker_signing_keys)?;
    let recipient = X25519Recipient::from_private_slice(
        KeyId::from_text(&request.response_encryption_key_id)?,
        response_private_key,
    )
    .map_err(|e| SealedInvocationResponseError::ResponsePrivateKeyLength { actual: e.actual })?;
    verify_and_open_sign_response(request, response, &recipient, &verifier, validation).await
}

/// Verify and open a sealed sign response using caller-supplied COSE traits.
///
/// This lower-level helper is useful for tests and for callers that already
/// have a custom verifier or recipient implementation.
///
/// # Errors
/// Returns [`SealedInvocationResponseError`] for the same validation failures
/// as [`verify_and_decrypt_sign_response`].
#[allow(
    clippy::future_not_send,
    reason = "generic over basil-cose AFIT Verifier/Recipient; Send is a caller-side bound"
)]
pub async fn verify_and_open_sign_response<V: basil_cose::Verifier, R: Recipient>(
    request: &PreparedSealedInvocation,
    response: &pb::SealedResponse,
    recipient: &R,
    broker_verifier: &V,
    validation: &ValidationParams,
) -> Result<SignInvocationResponse, SealedInvocationResponseError> {
    let sealed = verify_sealed(
        &response.message,
        broker_verifier,
        &VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation,
        },
    )
    .await?;

    if sealed.claims.in_reply_to.as_ref().map(MessageId::as_bytes)
        != Some(request.message_id.as_slice())
    {
        return Err(SealedInvocationResponseError::InReplyToMismatch);
    }
    if sealed.claims.request_hash != Some(RequestHash(request.request_hash)) {
        return Err(SealedInvocationResponseError::RequestHashMismatch);
    }

    let opened = sealed
        .open(
            recipient,
            &ExternalAad::empty(),
            Some(&KdfParties::anonymous()),
        )
        .await?;
    if opened.content_type.as_str() != CONTENT_TYPE_SIGN_RESPONSE {
        return Err(SealedInvocationResponseError::UnexpectedContentType {
            actual: opened.content_type.as_str().to_string(),
            expected: CONTENT_TYPE_SIGN_RESPONSE,
        });
    }
    SignInvocationResponse::from_cbor_bytes(&opened.plaintext)
        .map_err(SealedInvocationResponseError::SignResponseBody)
}

fn optional_subject(value: Option<String>) -> Result<Option<Subject>, SealedInvocationError> {
    value.map(Subject::new).transpose().map_err(Into::into)
}

#[cfg(test)]
fn optional_response_subject(
    value: Option<String>,
) -> Result<Option<basil_cose::ResponseSubject>, SealedInvocationError> {
    value
        .map(basil_cose::ResponseSubject::new)
        .transpose()
        .map_err(Into::into)
}

fn pinned_broker_verifier(
    keys: &BTreeMap<String, Vec<u8>>,
) -> Result<Ed25519Verifier, SealedInvocationResponseError> {
    let mut entries = keys.iter();
    let (first_id, first_key) = entries
        .next()
        .ok_or(SealedInvocationResponseError::BrokerPublicKeyLength { actual: 0 })?;
    let first: [u8; 32] = first_key.as_slice().try_into().map_err(|_| {
        SealedInvocationResponseError::BrokerPublicKeyLength {
            actual: first_key.len(),
        }
    })?;
    let mut verifier = Ed25519Verifier::from_key(KeyId::from_text(first_id)?, &first)
        .map_err(|_| SealedInvocationResponseError::BrokerPublicKeyLength { actual: 32 })?;
    for (key_id, public) in entries {
        let public: [u8; 32] = public.as_slice().try_into().map_err(|_| {
            SealedInvocationResponseError::BrokerPublicKeyLength {
                actual: public.len(),
            }
        })?;
        verifier
            .add_key(KeyId::from_text(key_id)?, &public)
            .map_err(|_| SealedInvocationResponseError::BrokerPublicKeyLength { actual: 32 })?;
    }
    Ok(verifier)
}

/// A transport that carries a prepared sealed invocation to the broker and
/// returns the broker's raw response bytes.
///
/// `basil` depends on no carrier itself (NATS, a direct socket, ...);
/// callers supply the transport. The bytes in and out are exact tagged COSE:
/// the request is a `COSE_Sign1` over an embedded `COSE_Encrypt`, and the
/// response is the broker's protected `COSE_Sign1`. Implementors forward the
/// request bytes verbatim and return the response bytes verbatim; re-encoding
/// either side breaks the COSE `AAD` binding.
#[allow(
    async_fn_in_trait,
    reason = "carrier round trips are consumed through generics; `Send` is a caller-side bound"
)]
pub trait SealedInvocationCarrier {
    /// Carrier-specific transport failure.
    type Error: core::fmt::Display;

    /// Deliver the tagged COSE `request` bytes and return the tagged COSE
    /// response bytes.
    ///
    /// # Errors
    /// Returns [`Self::Error`] when the carrier cannot deliver the request or
    /// receive a response.
    async fn round_trip(&self, request: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// Shared identities and pinned material for a [`CarrierSigner`].
///
/// Every bridged round trip reuses these; only the payload and a fresh message
/// id change per signature.
#[derive(Debug, Clone)]
pub struct CarrierSignerConfig {
    /// Catalog id of the caller's own request-signing key. This identity signs
    /// each carrier request, and it must differ from the broker key being
    /// invoked, so the request is never signed by the key it asks to use.
    pub request_sign_id: String,
    /// Optional sender subject asserted in the request claims.
    pub request_subject: Option<String>,
    /// Broker invocation-encryption key id the request is sealed to.
    pub broker_request_key_id: String,
    /// Broker invocation-encryption `X25519` public key.
    pub broker_request_public: [u8; 32],
    /// Optional broker recipient subject asserted in the request claims.
    pub broker_request_subject: Option<String>,
    /// Caller-controlled response-encryption key id the broker seals its
    /// response to.
    pub response_encryption_key_id: String,
    /// How long each issued request stays valid.
    pub request_ttl: Duration,
    /// Response validation: tolerated clock skew in either direction.
    pub max_clock_skew: Duration,
    /// Response validation: cap on an explicit response `exp - iat` span.
    pub max_ttl: Duration,
    /// Response validation: effective TTL when the response omits `exp`.
    pub default_ttl: Duration,
    /// Response validation: allowed audiences (empty accepts any `aud`).
    pub allowed_audiences: BTreeSet<Subject>,
}

/// A [`Signer`] that produces signatures for a broker-custodied key by sending
/// a sealed `Sign` invocation over a [carrier](SealedInvocationCarrier) and
/// unwrapping the broker's protected response.
///
/// This is the sealed-invocation-over-carrier signer variant. Unlike
/// [`BrokerSigner`], which signs in place over a direct agent socket, a
/// `CarrierSigner` needs no socket to the broker at all: it reaches the broker
/// only through the carrier (for example the NATS request/reply bridge). Each
/// carrier request is signed with a distinct caller identity (`request_signer`,
/// named by [`CarrierSignerConfig::request_sign_id`]) to avoid the circular
/// case of signing the request with the very key it asks the broker to use. The
/// broker's sealed response is opened with `recipient` and verified against
/// pinned trust in `broker_verifier`.
///
/// From the perspective of an outer message this signer helps build, the
/// signature is attributed to the broker key [`Signer::key_id`]; the carrier
/// signer is simply how that signature is produced without holding the key
/// locally.
pub struct CarrierSigner<C, S, R, V> {
    target_key_id: KeyId,
    target_key_name: String,
    carrier: C,
    request_signer: S,
    recipient: R,
    broker_verifier: V,
    config: CarrierSignerConfig,
}

/// A [`CarrierSigner`] for the common pure-carrier deployment.
///
/// The caller holds its response key locally ([`X25519Recipient`]) and pins the
/// broker's signing key locally ([`Ed25519Verifier`]), so no direct agent
/// socket is needed.
pub type LocalCarrierSigner<C, S> = CarrierSigner<C, S, X25519Recipient, Ed25519Verifier>;

impl<C, S, R, V> CarrierSigner<C, S, R, V> {
    /// Build a carrier signer for the broker signing key `target_key_id`.
    ///
    /// `target_key_id` is the broker-custodied key whose signatures this signer
    /// produces (returned by [`Signer::key_id`]). `request_signer` signs the
    /// carrier request and must be a different key.
    ///
    /// # Errors
    /// Returns [`SealedInvocationError::Profile`] if `target_key_id` is outside
    /// the COSE `kid` bounds.
    pub fn new(
        target_key_id: &str,
        carrier: C,
        request_signer: S,
        recipient: R,
        broker_verifier: V,
        config: CarrierSignerConfig,
    ) -> Result<Self, SealedInvocationError> {
        Ok(Self {
            target_key_id: KeyId::from_text(target_key_id)?,
            target_key_name: target_key_id.to_string(),
            carrier,
            request_signer,
            recipient,
            broker_verifier,
            config,
        })
    }
}

impl<C, S, R, V> Signer for CarrierSigner<C, S, R, V>
where
    C: SealedInvocationCarrier,
    S: Signer,
    R: Recipient,
    V: basil_cose::Verifier,
{
    fn key_id(&self) -> &KeyId {
        &self.target_key_id
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EdDsa
    }

    #[allow(
        clippy::future_not_send,
        reason = "generic over basil-cose AFIT traits; `Send` is a caller-side bound"
    )]
    async fn sign(&self, sig_structure: &[u8]) -> Result<Signature, SignError> {
        let now = current_unix_secs()?;
        let ttl = u32::try_from(self.config.request_ttl.as_secs()).unwrap_or(u32::MAX);
        // A fresh 64-bit random nonce keeps the id collision-free across
        // process restarts; a per-process counter would restart at its seed
        // and could reuse an id within the same second.
        let nonce = rand::random::<u64>();

        let body = SignInvocationRequest {
            key_id: self.target_key_name.clone(),
            message: sig_structure.to_vec(),
            algorithm: pb::SigningAlgorithm::Unspecified.into(),
        };
        let options = SealedInvocationOptions {
            message_id: format!("{}-{now}-{nonce:016x}", self.config.request_sign_id),
            issued_at_unix: now,
            expires_at_unix: Some(now.saturating_add(ttl)),
            sender_sign_id: self.config.request_sign_id.clone(),
            sender_subject: self.config.request_subject.clone(),
            recipient_key_id: self.config.broker_request_key_id.clone(),
            recipient_subject: self.config.broker_request_subject.clone(),
            response_encryption_key_id: self.config.response_encryption_key_id.clone(),
            // The carrier signer is a local trusted path, not a remote CI
            // invocation; it presents no freshness challenge.
            freshness_challenge: None,
        };
        let prepared = prepare_sealed_invocation(
            options,
            &self.config.broker_request_public,
            &body,
            &self.request_signer,
        )
        .await
        .map_err(sign_provider_error)?;

        let response_bytes = self
            .carrier
            .round_trip(&prepared.message)
            .await
            .map_err(sign_provider_error)?;
        let response = pb::SealedResponse {
            message: response_bytes,
            response_subject: None,
        };

        let validation = ValidationParams {
            now: UnixTime(i64::from(now)),
            max_clock_skew: self.config.max_clock_skew,
            max_ttl: self.config.max_ttl,
            default_ttl: self.config.default_ttl,
            allowed_audiences: self.config.allowed_audiences.clone(),
            role: MessageRole::Response,
        };
        let sign_response = verify_and_open_sign_response(
            &prepared,
            &response,
            &self.recipient,
            &self.broker_verifier,
            &validation,
        )
        .await
        .map_err(sign_provider_error)?;

        if sign_response.status.code != InvocationStatusCode::Ok {
            return Err(SignError::Provider {
                message: format!(
                    "bridged sign returned {:?}: {}",
                    sign_response.status.code,
                    sign_response
                        .status
                        .message
                        .as_deref()
                        .unwrap_or(&sign_response.status.reason)
                ),
            });
        }
        let signature = sign_response.signature.ok_or_else(|| SignError::Provider {
            message: "bridged sign response carried no signature".to_string(),
        })?;
        Signature::from_bytes(signature).map_err(sign_provider_error)
    }
}

fn sign_provider_error(error: impl core::fmt::Display) -> SignError {
    SignError::Provider {
        message: error.to_string(),
    }
}

fn current_unix_secs() -> Result<u32, SignError> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(sign_provider_error)?
        .as_secs();
    u32::try_from(secs).map_err(|_| SignError::Provider {
        message: "system clock is beyond the u32 unix-seconds range".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use basil_cose::{Ed25519Signer, X25519Recipient};
    use basil_proto::invocation::{CONTENT_TYPE_MINT_JWT_RESPONSE, InvocationStatus};
    use zeroize::Zeroizing;

    use super::*;

    fn key_id(id: &str) -> KeyId {
        KeyId::from_text(id).expect("valid key id")
    }

    fn signer(id: &str, seed: u8) -> Ed25519Signer {
        Ed25519Signer::from_secret_bytes(key_id(id), &Zeroizing::new([seed; 32]))
    }

    fn recipient(id: &str, seed: u8) -> X25519Recipient {
        X25519Recipient::new(key_id(id), Zeroizing::new([seed; 32]))
    }

    fn validation(role: MessageRole) -> ValidationParams {
        ValidationParams {
            now: UnixTime(1_005),
            max_clock_skew: Duration::from_secs(5),
            max_ttl: Duration::from_mins(5),
            default_ttl: Duration::from_secs(60),
            allowed_audiences: BTreeSet::new(),
            role,
        }
    }

    fn options() -> SealedInvocationOptions {
        SealedInvocationOptions {
            message_id: "request-1".to_string(),
            issued_at_unix: 1_000,
            expires_at_unix: Some(1_060),
            sender_sign_id: "client-sign".to_string(),
            sender_subject: Some("client".to_string()),
            recipient_key_id: "broker-recipient".to_string(),
            recipient_subject: Some("broker".to_string()),
            response_encryption_key_id: "client-response".to_string(),
            freshness_challenge: None,
        }
    }

    fn ephemeral_options() -> EphemeralSealedInvocationOptions {
        EphemeralSealedInvocationOptions {
            message_id: "remote-request-1".to_string(),
            issued_at_unix: 1_000,
            expires_at_unix: Some(1_060),
            sender_sign_id: "client-sign".to_string(),
            sender_subject: Some("client".to_string()),
            recipient_key_id: "broker-recipient".to_string(),
            recipient_subject: Some("broker".to_string()),
            freshness_challenge: [0x41; 32],
        }
    }

    fn sign_body() -> SignInvocationRequest {
        SignInvocationRequest {
            key_id: "target-sign".to_string(),
            message: b"payload".to_vec(),
            algorithm: pb::SigningAlgorithm::Unspecified.into(),
        }
    }

    async fn prepared_request() -> (PreparedSealedInvocation, Ed25519Signer, X25519Recipient) {
        let client_signer = signer("client-sign", 7);
        let broker_recipient = recipient("broker-recipient", 9);
        let response_recipient = recipient("client-response", 11);
        let prepared = prepare_sealed_invocation(
            options(),
            &broker_recipient.public().public,
            &sign_body(),
            &client_signer,
        )
        .await
        .expect("request seals");
        (prepared, client_signer, response_recipient)
    }

    async fn response_for(
        prepared: &PreparedSealedInvocation,
        response_recipient: &X25519Recipient,
        broker_signer: &Ed25519Signer,
    ) -> pb::SealedResponse {
        let response_body = SignInvocationResponse {
            status: InvocationStatus::ok(),
            policy_generation: 42,
            signature: Some(vec![1, 2, 3]),
        };
        let claims = Claims {
            issuer: Some(Subject::new("broker".to_string()).expect("subject")),
            audience: Some(Subject::new("client".to_string()).expect("subject")),
            expires_at: Some(UnixTime(1_060)),
            issued_at: UnixTime(1_000),
            message_id: MessageId::from_bytes(b"response-1".to_vec()).expect("message id"),
            sender_key_id: Some(broker_signer.key_id().clone()),
            response_key_id: None,
            response_subject: optional_response_subject(None).expect("none"),
            in_reply_to: Some(
                MessageId::from_bytes(prepared.message_id.clone()).expect("message id"),
            ),
            request_hash: Some(RequestHash(prepared.request_hash)),
            freshness_challenge: None,
            response_public_key_cose: None,
        };
        let cose = build_sealed(
            &SealParams {
                content_type: ContentType::new(CONTENT_TYPE_SIGN_RESPONSE.to_string())
                    .expect("content type"),
                plaintext: &response_body.to_cbor_bytes(),
                claims,
                role: MessageRole::Response,
                recipient: response_recipient.public(),
                content_algorithm: ContentAlgorithm::A256Gcm,
                aad: SealedAad::empty(),
                kdf_parties: KdfParties::anonymous(),
            },
            broker_signer,
        )
        .await
        .expect("response seals");
        pb::SealedResponse {
            message: cose.into_vec(),
            response_subject: None,
        }
    }

    async fn response_for_public(
        prepared: &PreparedSealedInvocation,
        response_public: X25519RecipientPublic,
        broker_signer: &Ed25519Signer,
    ) -> pb::SealedResponse {
        let response_body = SignInvocationResponse {
            status: InvocationStatus::ok(),
            policy_generation: 42,
            signature: Some(vec![1, 2, 3]),
        };
        let claims = Claims {
            issuer: Some(Subject::new("broker".to_string()).expect("subject")),
            audience: Some(Subject::new("client".to_string()).expect("subject")),
            expires_at: Some(UnixTime(1_060)),
            issued_at: UnixTime(1_000),
            message_id: MessageId::from_bytes(b"response-ephemeral".to_vec()).expect("message id"),
            sender_key_id: Some(broker_signer.key_id().clone()),
            response_key_id: None,
            response_subject: None,
            in_reply_to: Some(
                MessageId::from_bytes(prepared.message_id.clone()).expect("message id"),
            ),
            request_hash: Some(RequestHash(prepared.request_hash)),
            freshness_challenge: None,
            response_public_key_cose: None,
        };
        let cose = build_sealed(
            &SealParams {
                content_type: ContentType::new(CONTENT_TYPE_SIGN_RESPONSE.to_string())
                    .expect("content type"),
                plaintext: &response_body.to_cbor_bytes(),
                claims,
                role: MessageRole::Response,
                recipient: response_public,
                content_algorithm: ContentAlgorithm::A256Gcm,
                aad: SealedAad::empty(),
                kdf_parties: KdfParties::anonymous(),
            },
            broker_signer,
        )
        .await
        .expect("response seals");
        pb::SealedResponse {
            message: cose.into_vec(),
            response_subject: None,
        }
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn ephemeral_preparation_binds_fresh_key_and_opens_with_pinned_broker_key() {
        let client_signer = signer("client-sign", 7);
        let client_verifier =
            Ed25519Verifier::from_key(key_id("client-sign"), &client_signer.public_key_bytes())
                .expect("verifier");
        let broker_recipient = recipient("broker-recipient", 9);
        let proof_headers = ProtectedHeaders {
            signer_certificates_jwt: vec!["provider.jwt.signature".to_string()],
            signer_public_key_cose: Some(vec![0xa3, 1, 1]),
            operation_target_key_id: None,
        };

        let first = prepare_ephemeral_sealed_invocation(
            ephemeral_options(),
            &broker_recipient.public().public,
            &sign_body(),
            &proof_headers,
            &client_signer,
        )
        .await
        .expect("first request");
        let mut second_options = ephemeral_options();
        second_options.message_id = "remote-request-2".to_string();
        let second = prepare_ephemeral_sealed_invocation(
            second_options,
            &broker_recipient.public().public,
            &sign_body(),
            &proof_headers,
            &client_signer,
        )
        .await
        .expect("second request");

        let verified_first = verify_sealed(
            &first.prepared().message,
            &client_verifier,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation(MessageRole::Request),
            },
        )
        .await
        .expect("request verifies");
        let verified_second = verify_sealed(
            &second.prepared().message,
            &client_verifier,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation(MessageRole::Request),
            },
        )
        .await
        .expect("request verifies");
        let mut expected_headers = proof_headers;
        expected_headers.operation_target_key_id = Some(key_id("target-sign"));
        assert_eq!(verified_first.protected_headers, expected_headers);
        let first_public = verified_first
            .claims
            .response_public_key_cose
            .expect("response public key");
        let second_public = verified_second
            .claims
            .response_public_key_cose
            .expect("response public key");
        assert_ne!(first_public, second_public);
        assert_eq!(
            verified_first
                .claims
                .response_key_id
                .as_ref()
                .map(KeyId::as_bytes),
            Some(first_public.thumbprint().as_bytes())
        );
        assert_eq!(first_public.to_cose_key_bytes().len(), 40);

        let broker_signer = signer("broker-sign", 13);
        let response = response_for_public(
            first.prepared(),
            X25519RecipientPublic {
                key_id: KeyId::from_text(&first_public.thumbprint()).expect("key id"),
                public: *first_public.as_public_bytes(),
            },
            &broker_signer,
        )
        .await;
        let pinned = BTreeMap::from([(
            "broker-sign".to_string(),
            broker_signer.public_key_bytes().to_vec(),
        )]);
        let opened = first
            .verify_and_decrypt_sign_response(
                &response,
                &pinned,
                &validation(MessageRole::Response),
            )
            .await
            .expect("pinned response opens");
        assert_eq!(opened.signature, Some(vec![1, 2, 3]));

        let wrong_broker = signer("broker-sign", 14);
        let wrong_pins = BTreeMap::from([(
            "broker-sign".to_string(),
            wrong_broker.public_key_bytes().to_vec(),
        )]);
        assert!(matches!(
            first
                .verify_and_decrypt_sign_response(
                    &response,
                    &wrong_pins,
                    &validation(MessageRole::Response),
                )
                .await,
            Err(SealedInvocationResponseError::Verify(
                VerifyError::SignatureInvalid
            ))
        ));
    }

    #[tokio::test]
    async fn ephemeral_preparation_separates_broker_audience_from_provider_proof() {
        let client_signer = signer("client-sign", 7);
        let client_verifier =
            Ed25519Verifier::from_key(key_id("client-sign"), &client_signer.public_key_bytes())
                .expect("verifier");
        let broker_recipient = recipient("broker-recipient", 9);
        let proof_headers = ProtectedHeaders {
            signer_certificates_jwt: vec!["provider.jwt.with-oidc-audience".to_string()],
            signer_public_key_cose: Some(vec![0xa3, 1, 1]),
            operation_target_key_id: None,
        };
        let mut options = ephemeral_options();
        options.recipient_subject = Some("basil://production.example/broker".to_string());

        let prepared = prepare_ephemeral_sealed_invocation(
            options,
            &broker_recipient.public().public,
            &sign_body(),
            &proof_headers,
            &client_signer,
        )
        .await
        .expect("request seals");
        let verified = verify_sealed(
            &prepared.prepared().message,
            &client_verifier,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation(MessageRole::Request),
            },
        )
        .await
        .expect("request verifies");

        assert_eq!(
            verified.claims.audience.as_ref().map(Subject::as_str),
            Some("basil://production.example/broker")
        );
        let mut expected_headers = proof_headers;
        expected_headers.operation_target_key_id = Some(key_id("target-sign"));
        assert_eq!(verified.protected_headers, expected_headers);
    }

    #[tokio::test]
    async fn ephemeral_preparation_requires_both_provider_proof_headers() {
        let client_signer = signer("client-sign", 7);
        let broker_recipient = recipient("broker-recipient", 9);
        for headers in [
            ProtectedHeaders::default(),
            ProtectedHeaders {
                signer_certificates_jwt: vec!["provider.jwt.signature".to_string()],
                signer_public_key_cose: None,
                operation_target_key_id: None,
            },
            ProtectedHeaders {
                signer_certificates_jwt: Vec::new(),
                signer_public_key_cose: Some(vec![0xa3, 1, 1]),
                operation_target_key_id: None,
            },
        ] {
            assert!(matches!(
                prepare_ephemeral_sealed_invocation(
                    ephemeral_options(),
                    &broker_recipient.public().public,
                    &sign_body(),
                    &headers,
                    &client_signer,
                )
                .await,
                Err(SealedInvocationError::MissingProviderProofHeaders)
            ));
        }
    }

    fn carrier_validation(role: MessageRole) -> ValidationParams {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        ValidationParams {
            now: UnixTime(i64::try_from(now).expect("now fits i64")),
            max_clock_skew: Duration::from_secs(120),
            max_ttl: Duration::from_secs(600),
            default_ttl: Duration::from_secs(120),
            allowed_audiences: BTreeSet::new(),
            role,
        }
    }

    /// A carrier that plays the broker: it verifies the request to recover its
    /// message id, then seals a correlated `Sign` response back to the caller.
    struct FakeBrokerCarrier {
        request_verifier: Ed25519Verifier,
        broker_signer: Ed25519Signer,
        response_public: X25519RecipientPublic,
        signature: Option<Vec<u8>>,
        status: InvocationStatus,
    }

    impl SealedInvocationCarrier for FakeBrokerCarrier {
        type Error = std::convert::Infallible;

        async fn round_trip(&self, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
            let verified = verify_sealed(
                request,
                &self.request_verifier,
                &VerifySealedParams {
                    signature_aad: ExternalAad::empty(),
                    validation: &carrier_validation(MessageRole::Request),
                },
            )
            .await
            .expect("carrier request verifies");
            let RequestHash(hash) = request_hash(request);
            let response_body = SignInvocationResponse {
                status: self.status.clone(),
                policy_generation: 1,
                signature: self.signature.clone(),
            };
            let claims = Claims {
                issuer: Some(Subject::new("broker".to_string()).expect("subject")),
                audience: None,
                expires_at: verified.claims.expires_at,
                issued_at: verified.claims.issued_at,
                message_id: MessageId::from_bytes(b"broker-response".to_vec()).expect("message id"),
                sender_key_id: Some(self.broker_signer.key_id().clone()),
                response_key_id: None,
                response_subject: None,
                in_reply_to: Some(verified.claims.message_id.clone()),
                request_hash: Some(RequestHash(hash)),
                freshness_challenge: None,
                response_public_key_cose: None,
            };
            let cose = build_sealed(
                &SealParams {
                    content_type: ContentType::new(CONTENT_TYPE_SIGN_RESPONSE.to_string())
                        .expect("content type"),
                    plaintext: &response_body.to_cbor_bytes(),
                    claims,
                    role: MessageRole::Response,
                    recipient: self.response_public.clone(),
                    content_algorithm: ContentAlgorithm::A256Gcm,
                    aad: SealedAad::empty(),
                    kdf_parties: KdfParties::anonymous(),
                },
                &self.broker_signer,
            )
            .await
            .expect("carrier response seals");
            Ok(cose.into_vec())
        }
    }

    fn carrier_config(broker_request_public: [u8; 32]) -> CarrierSignerConfig {
        CarrierSignerConfig {
            request_sign_id: "client-invoke".to_string(),
            request_subject: Some("svc.client".to_string()),
            broker_request_key_id: "broker-recipient".to_string(),
            broker_request_public,
            broker_request_subject: Some("broker".to_string()),
            response_encryption_key_id: "client-response".to_string(),
            request_ttl: Duration::from_secs(60),
            max_clock_skew: Duration::from_secs(120),
            max_ttl: Duration::from_secs(600),
            default_ttl: Duration::from_secs(120),
            allowed_audiences: BTreeSet::new(),
        }
    }

    #[tokio::test]
    async fn prepared_invocation_carries_the_freshness_challenge_claim() {
        let client_signer = signer("client-sign", 7);
        let broker_recipient = recipient("broker-recipient", 9);
        let mut challenge = [0x77_u8; 32];
        challenge[..16].copy_from_slice(&[0x10; 16]);
        let challenged_options = SealedInvocationOptions {
            freshness_challenge: Some(challenge),
            ..options()
        };
        let prepared = prepare_sealed_invocation(
            challenged_options,
            &broker_recipient.public().public,
            &sign_body(),
            &client_signer,
        )
        .await
        .expect("request seals");

        let verifier =
            Ed25519Verifier::from_key(key_id("client-sign"), &client_signer.public_key_bytes())
                .expect("verifier");
        let checked = verify_sealed(
            &prepared.message,
            &verifier,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation(MessageRole::Request),
            },
        )
        .await
        .expect("request verifies");
        assert_eq!(
            checked.claims.freshness_challenge,
            Some(FreshnessChallenge::new(challenge))
        );

        // Local requests without a challenge keep the claim absent.
        let bare = prepare_sealed_invocation(
            options(),
            &broker_recipient.public().public,
            &sign_body(),
            &client_signer,
        )
        .await
        .expect("request seals");
        let checked = verify_sealed(
            &bare.message,
            &verifier,
            &VerifySealedParams {
                signature_aad: ExternalAad::empty(),
                validation: &validation(MessageRole::Request),
            },
        )
        .await
        .expect("request verifies");
        assert_eq!(checked.claims.freshness_challenge, None);
    }

    #[tokio::test]
    async fn carrier_signer_round_trips_a_bridged_signature() {
        let request_signer = signer("client-invoke", 7);
        let broker_signer = signer("broker-sign", 5);
        let broker_recipient = recipient("broker-recipient", 9);
        let response_recipient = recipient("client-response", 11);

        let request_verifier =
            Ed25519Verifier::from_key(key_id("client-invoke"), &request_signer.public_key_bytes())
                .expect("request verifier");
        let broker_verifier =
            Ed25519Verifier::from_key(key_id("broker-sign"), &broker_signer.public_key_bytes())
                .expect("broker verifier");
        let carrier = FakeBrokerCarrier {
            request_verifier,
            broker_signer,
            response_public: response_recipient.public(),
            signature: Some(vec![7u8; 64]),
            status: InvocationStatus::ok(),
        };
        let config = carrier_config(broker_recipient.public().public);
        let carrier_signer = CarrierSigner::new(
            "alice.sign",
            carrier,
            request_signer,
            response_recipient,
            broker_verifier,
            config,
        )
        .expect("carrier signer");

        assert_eq!(carrier_signer.key_id(), &key_id("alice.sign"));
        let signature = carrier_signer
            .sign(b"payload-to-sign")
            .await
            .expect("carrier sign round trip");
        assert_eq!(signature.as_bytes(), [7u8; 64].as_slice());
    }

    #[tokio::test]
    async fn carrier_signer_surfaces_a_missing_response_signature() {
        let request_signer = signer("client-invoke", 7);
        let broker_signer = signer("broker-sign", 5);
        let broker_recipient = recipient("broker-recipient", 9);
        let response_recipient = recipient("client-response", 11);

        let request_verifier =
            Ed25519Verifier::from_key(key_id("client-invoke"), &request_signer.public_key_bytes())
                .expect("request verifier");
        let broker_verifier =
            Ed25519Verifier::from_key(key_id("broker-sign"), &broker_signer.public_key_bytes())
                .expect("broker verifier");
        let carrier = FakeBrokerCarrier {
            request_verifier,
            broker_signer,
            response_public: response_recipient.public(),
            signature: None,
            status: InvocationStatus::ok(),
        };
        let config = carrier_config(broker_recipient.public().public);
        let carrier_signer = CarrierSigner::new(
            "alice.sign",
            carrier,
            request_signer,
            response_recipient,
            broker_verifier,
            config,
        )
        .expect("carrier signer");

        let err = carrier_signer
            .sign(b"payload-to-sign")
            .await
            .expect_err("missing signature is an error");
        assert!(matches!(err, SignError::Provider { .. }));
    }

    #[tokio::test]
    async fn request_builder_rejects_malformed_options_and_recipient_key() {
        let signer = signer("client-sign", 7);
        let broker_recipient = recipient("broker-recipient", 9);
        let body = sign_body();

        let err = prepare_sealed_invocation(options(), &[0u8; 31], &body, &signer)
            .await
            .expect_err("short recipient key rejected");
        assert!(matches!(
            err,
            SealedInvocationError::RecipientPublicKeyLength { actual: 31 }
        ));

        let mut bad_sender_key = options();
        bad_sender_key.sender_sign_id.clear();
        let err = prepare_sealed_invocation(
            bad_sender_key,
            &broker_recipient.public().public,
            &body,
            &signer,
        )
        .await
        .expect_err("empty sender key rejected");
        assert!(matches!(err, SealedInvocationError::Profile(_)));

        let mut bad_subject = options();
        bad_subject.sender_subject = Some(String::new());
        let err = prepare_sealed_invocation(
            bad_subject,
            &broker_recipient.public().public,
            &body,
            &signer,
        )
        .await
        .expect_err("empty sender subject rejected");
        assert!(matches!(err, SealedInvocationError::Profile(_)));
    }

    #[tokio::test]
    async fn pinned_broker_key_map_validation_is_fail_closed() {
        let (prepared, _client_signer, response_recipient) = prepared_request().await;
        let broker_signer = signer("broker-sign", 13);
        let response = response_for(&prepared, &response_recipient, &broker_signer).await;

        let empty = BTreeMap::new();
        let err = verify_and_decrypt_sign_response(
            &prepared,
            &response,
            &[11; 32],
            &empty,
            &validation(MessageRole::Response),
        )
        .await
        .expect_err("empty broker trust map rejected");
        assert!(matches!(
            err,
            SealedInvocationResponseError::BrokerPublicKeyLength { actual: 0 }
        ));

        let mut short_key = BTreeMap::new();
        short_key.insert("broker-sign".to_string(), vec![0u8; 31]);
        let err = verify_and_decrypt_sign_response(
            &prepared,
            &response,
            &[11; 32],
            &short_key,
            &validation(MessageRole::Response),
        )
        .await
        .expect_err("short broker key rejected");
        assert!(matches!(
            err,
            SealedInvocationResponseError::BrokerPublicKeyLength { actual: 31 }
        ));
    }

    #[tokio::test]
    async fn local_round_trip_verifies_and_decrypts_sign_response() {
        let (prepared, _client_signer, response_recipient) = prepared_request().await;
        let broker_signer = signer("broker-sign", 13);
        let response = response_for(&prepared, &response_recipient, &broker_signer).await;
        let broker_verifier =
            Ed25519Verifier::from_key(key_id("broker-sign"), &broker_signer.public_key_bytes())
                .expect("verifier");

        let opened = verify_and_open_sign_response(
            &prepared,
            &response,
            &response_recipient,
            &broker_verifier,
            &validation(MessageRole::Response),
        )
        .await
        .expect("response opens");

        assert_eq!(opened.policy_generation, 42);
        assert_eq!(opened.signature, Some(vec![1, 2, 3]));
    }

    #[tokio::test]
    async fn response_correlation_failures_are_rejected() {
        let (mut prepared, _client_signer, response_recipient) = prepared_request().await;
        let broker_signer = signer("broker-sign", 13);
        let response = response_for(&prepared, &response_recipient, &broker_signer).await;
        let broker_verifier =
            Ed25519Verifier::from_key(key_id("broker-sign"), &broker_signer.public_key_bytes())
                .expect("verifier");

        prepared.message_id = b"other-request".to_vec();
        let err = verify_and_open_sign_response(
            &prepared,
            &response,
            &response_recipient,
            &broker_verifier,
            &validation(MessageRole::Response),
        )
        .await
        .expect_err("wrong in-reply-to rejected");
        assert!(matches!(
            err,
            SealedInvocationResponseError::InReplyToMismatch
        ));

        let (mut prepared, _client_signer, response_recipient) = prepared_request().await;
        let response = response_for(&prepared, &response_recipient, &broker_signer).await;
        prepared.request_hash = [0x55; 32];
        let err = verify_and_open_sign_response(
            &prepared,
            &response,
            &response_recipient,
            &broker_verifier,
            &validation(MessageRole::Response),
        )
        .await
        .expect_err("wrong request hash rejected");
        assert!(matches!(
            err,
            SealedInvocationResponseError::RequestHashMismatch
        ));
    }

    #[tokio::test]
    async fn wrong_broker_signature_is_rejected() {
        let (prepared, _client_signer, response_recipient) = prepared_request().await;
        let broker_signer = signer("broker-sign", 13);
        let response = response_for(&prepared, &response_recipient, &broker_signer).await;
        let wrong_broker = signer("broker-sign", 14);
        let broker_verifier =
            Ed25519Verifier::from_key(key_id("broker-sign"), &wrong_broker.public_key_bytes())
                .expect("verifier");

        let err = verify_and_open_sign_response(
            &prepared,
            &response,
            &response_recipient,
            &broker_verifier,
            &validation(MessageRole::Response),
        )
        .await
        .expect_err("wrong signature rejected");
        assert!(matches!(
            err,
            SealedInvocationResponseError::Verify(VerifyError::SignatureInvalid)
        ));
    }

    #[tokio::test]
    async fn wrong_response_key_is_rejected() {
        let (prepared, _client_signer, response_recipient) = prepared_request().await;
        let broker_signer = signer("broker-sign", 13);
        let response = response_for(&prepared, &response_recipient, &broker_signer).await;
        let broker_verifier =
            Ed25519Verifier::from_key(key_id("broker-sign"), &broker_signer.public_key_bytes())
                .expect("verifier");
        let wrong_recipient = recipient("other-response", 11);

        let err = verify_and_open_sign_response(
            &prepared,
            &response,
            &wrong_recipient,
            &broker_verifier,
            &validation(MessageRole::Response),
        )
        .await
        .expect_err("wrong key rejected");
        assert!(matches!(
            err,
            SealedInvocationResponseError::Open(OpenError::RecipientKeyMismatch)
        ));
    }

    #[tokio::test]
    async fn unexpected_response_content_type_is_rejected() {
        let (prepared, _client_signer, response_recipient) = prepared_request().await;
        let broker_signer = signer("broker-sign", 13);
        let claims = Claims {
            issuer: None,
            audience: None,
            expires_at: Some(UnixTime(1_060)),
            issued_at: UnixTime(1_000),
            message_id: MessageId::from_bytes(b"response-1".to_vec()).expect("message id"),
            sender_key_id: Some(broker_signer.key_id().clone()),
            response_key_id: None,
            response_subject: None,
            in_reply_to: Some(
                MessageId::from_bytes(prepared.message_id.clone()).expect("message id"),
            ),
            request_hash: Some(RequestHash(prepared.request_hash)),
            freshness_challenge: None,
            response_public_key_cose: None,
        };
        let cose = build_sealed(
            &SealParams {
                content_type: ContentType::new(CONTENT_TYPE_MINT_JWT_RESPONSE.to_string())
                    .expect("content type"),
                plaintext: b"not a sign response",
                claims,
                role: MessageRole::Response,
                recipient: response_recipient.public(),
                content_algorithm: ContentAlgorithm::A256Gcm,
                aad: SealedAad::empty(),
                kdf_parties: KdfParties::anonymous(),
            },
            &broker_signer,
        )
        .await
        .expect("response seals");
        let response = pb::SealedResponse {
            message: cose.into_vec(),
            response_subject: None,
        };
        let broker_verifier =
            Ed25519Verifier::from_key(key_id("broker-sign"), &broker_signer.public_key_bytes())
                .expect("verifier");

        let err = verify_and_open_sign_response(
            &prepared,
            &response,
            &response_recipient,
            &broker_verifier,
            &validation(MessageRole::Response),
        )
        .await
        .expect_err("wrong content type rejected");
        assert!(matches!(
            err,
            SealedInvocationResponseError::UnexpectedContentType { .. }
        ));
    }

    #[test]
    fn broker_backed_unseal_recipient_builds_verbatim_rpc_request() {
        let aad = ExternalAad::from_bytes(vec![9, 8, 7]);
        let cose = vec![0xd8, 0x60, 0x80];
        let open_request = OpenRequest {
            cose_encrypt: &cose,
            external_aad: &aad,
            expected_parties: Some(&KdfParties::anonymous()),
        };

        let rpc =
            BrokerRecipient::unseal_cose_request_for(&key_id("broker-recipient"), &open_request)
                .expect("rpc request");

        assert_eq!(rpc.key_id, "broker-recipient");
        assert_eq!(rpc.cose_encrypt, cose);
        assert_eq!(rpc.external_aad, Some(vec![9, 8, 7]));
    }

    #[tokio::test]
    async fn convenience_response_helper_uses_pinned_key_map() {
        let (prepared, _client_signer, response_recipient) = prepared_request().await;
        let broker_signer = signer("broker-sign", 13);
        let response = response_for(&prepared, &response_recipient, &broker_signer).await;
        let mut keys = BTreeMap::new();
        keys.insert(
            "broker-sign".to_string(),
            broker_signer.public_key_bytes().to_vec(),
        );

        let opened = verify_and_decrypt_sign_response(
            &prepared,
            &response,
            &[11; 32],
            &keys,
            &validation(MessageRole::Response),
        )
        .await
        .expect("response opens");

        assert_eq!(opened.policy_generation, 42);
    }
}
