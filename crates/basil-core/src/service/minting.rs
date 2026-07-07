#![allow(clippy::result_large_err)]

// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use basil_proto::broker::v1 as pb;
use basil_proto::broker::v1::minting_service_server::MintingService;
use basil_proto::broker::v1::nats_service_server::NatsService;
use serde_json::Value as JsonValue;
use tonic::{Request, Response, Status};

use crate::backend::BackendError;
use crate::catalog::policy::Op;
use crate::minter::{NatsJtiMode, NatsJwtKind, SignNatsJwtSpec};
use crate::service::broker::{BrokerGrpc, GrpcResult};
use crate::service::shared::{
    backend_status, claims_json, credential_response, invalid_request, manager_status, ttl_seconds,
};

#[tonic::async_trait]
impl MintingService for BrokerGrpc {
    async fn mint_jwt(
        &self,
        request: Request<pb::MintJwtRequest>,
    ) -> GrpcResult<pb::CredentialResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Mint, &body.key_id)?;
        let ttl_secs = ttl_seconds(body.ttl.as_ref(), "mint")?;
        let claims = claims_json(body.claims.as_ref(), "mint")?;
        let routed = self
            .state
            .manager()
            .resolve(&body.key_id)
            .map_err(|e| manager_status("mint", &e))?;
        let subject = body.subject.as_deref().ok_or_else(|| {
            invalid_request("mint", "mint_jwt generic requires subject (the JWT sub)")
        })?;
        let token = crate::minter::mint_generic(
            routed.backend,
            routed.path(),
            &body.key_id,
            subject,
            ttl_secs,
            &claims,
        )
        .await
        .map_err(|e| generic_mint_status("mint", e))?;
        Ok(Response::new(credential_response(token, ttl_secs)?))
    }

    async fn issue_certificate(
        &self,
        request: Request<pb::IssueCertificateRequest>,
    ) -> GrpcResult<pb::IssueCertificateResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Mint, &body.issuer_key_id)?;
        if body.common_name.is_empty() {
            return Err(invalid_request(
                "issue_certificate",
                "common_name is required",
            ));
        }
        let ttl_secs = ttl_seconds(body.ttl.as_ref(), "issue_certificate")?
            .ok_or_else(|| invalid_request("issue_certificate", "ttl is required"))?;
        let cert_request = crate::backend::X509CertRequest {
            common_name: body.common_name.clone(),
            dns_sans: body.dns_sans.clone(),
            ip_sans: body.ip_sans.clone(),
            ttl_seconds: ttl_secs,
        };
        let mut issued = self
            .state
            .manager()
            .issue_x509_cert(&body.issuer_key_id, &cert_request)
            .await
            .map_err(|e| manager_status("issue_certificate", &e))?;
        Ok(Response::new(pb::IssueCertificateResponse {
            cert_chain_der: std::mem::take(&mut issued.cert_chain_der),
            // Move (never copy) the leaf key out of its `Zeroizing` buffer:
            // the proto field is then the only plain copy, and the response
            // zeroizes it on drop after tonic encodes it.
            private_key_der: std::mem::take(&mut *issued.leaf_private_key_der),
            ca_chain_der: std::mem::take(&mut issued.bundle_der),
        }))
    }
}

#[tonic::async_trait]
impl NatsService for BrokerGrpc {
    async fn mint_nats_user(
        &self,
        request: Request<pb::MintNatsUserRequest>,
    ) -> GrpcResult<pb::CredentialResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Mint, &body.key_id)?;
        let ttl_secs = ttl_seconds(body.ttl.as_ref(), "mint_nats_user")?;
        let routed = self
            .state
            .manager()
            .resolve(&body.key_id)
            .map_err(|e| manager_status("mint_nats_user", &e))?;
        let issuer = issuer_role(&routed, "mint_nats_user")?;
        let token = crate::minter::mint_nats_user(
            routed.backend,
            routed.path(),
            issuer,
            &body.subject_user_nkey,
            body.issuer_account.as_deref(),
            &body.name,
            ttl_secs,
            basil_nats::UserPermissions {
                pub_allow: body.pub_allow.clone(),
                pub_deny: body.pub_deny.clone(),
                sub_allow: body.sub_allow.clone(),
                sub_deny: body.sub_deny.clone(),
            },
        )
        .await
        .map_err(|e| nats_mint_status("mint_nats_user", &e))?;
        Ok(Response::new(credential_response(token, ttl_secs)?))
    }

    async fn mint_nats_account(
        &self,
        request: Request<pb::MintNatsAccountRequest>,
    ) -> GrpcResult<pb::CredentialResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Mint, &body.key_id)?;
        let ttl_secs = ttl_seconds(body.ttl.as_ref(), "mint_nats_account")?;
        let routed = self
            .state
            .manager()
            .resolve(&body.key_id)
            .map_err(|e| manager_status("mint_nats_account", &e))?;
        let issuer = issuer_role(&routed, "mint_nats_account")?;
        let token = crate::minter::mint_nats_account(
            routed.backend,
            routed.path(),
            issuer,
            &body.subject_account_nkey,
            &body.name,
            ttl_secs,
            body.signing_keys.clone(),
        )
        .await
        .map_err(|e| nats_mint_status("mint_nats_account", &e))?;
        Ok(Response::new(credential_response(token, ttl_secs)?))
    }

    async fn mint_nats_operator(
        &self,
        request: Request<pb::MintNatsOperatorRequest>,
    ) -> GrpcResult<pb::CredentialResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Mint, &body.key_id)?;
        let ttl_secs = ttl_seconds(body.ttl.as_ref(), "mint_nats_operator")?;
        let routed = self
            .state
            .manager()
            .resolve(&body.key_id)
            .map_err(|e| manager_status("mint_nats_operator", &e))?;
        let issuer = issuer_role(&routed, "mint_nats_operator")?;
        let token = crate::minter::mint_nats_operator(
            routed.backend,
            routed.path(),
            issuer,
            body.subject_operator_nkey.as_deref(),
            &body.name,
            ttl_secs,
            body.signing_keys.clone(),
            body.account_server_url.clone().unwrap_or_default(),
            body.system_account.clone().unwrap_or_default(),
        )
        .await
        .map_err(|e| nats_mint_status("mint_nats_operator", &e))?;
        Ok(Response::new(credential_response(token, ttl_secs)?))
    }

    async fn mint_nats_signer(
        &self,
        request: Request<pb::MintNatsSignerRequest>,
    ) -> GrpcResult<pb::CredentialResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Mint, &body.key_id)?;
        let ttl_secs = ttl_seconds(body.ttl.as_ref(), "mint_nats_signer")?;
        let routed = self
            .state
            .manager()
            .resolve(&body.key_id)
            .map_err(|e| manager_status("mint_nats_signer", &e))?;
        let issuer = issuer_role(&routed, "mint_nats_signer")?;
        let token = crate::minter::mint_nats_signer(
            routed.backend,
            routed.path(),
            issuer,
            &body.subject_nkey,
            &body.name,
            ttl_secs,
        )
        .await
        .map_err(|e| nats_mint_status("mint_nats_signer", &e))?;
        Ok(Response::new(credential_response(token, ttl_secs)?))
    }

    async fn mint_nats_server(
        &self,
        request: Request<pb::MintNatsServerRequest>,
    ) -> GrpcResult<pb::CredentialResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Mint, &body.key_id)?;
        let ttl_secs = ttl_seconds(body.ttl.as_ref(), "mint_nats_server")?;
        let routed = self
            .state
            .manager()
            .resolve(&body.key_id)
            .map_err(|e| manager_status("mint_nats_server", &e))?;
        let issuer = issuer_role(&routed, "mint_nats_server")?;
        let token = crate::minter::mint_nats_server(
            routed.backend,
            routed.path(),
            issuer,
            &body.subject_server_nkey,
            &body.name,
            ttl_secs,
        )
        .await
        .map_err(|e| nats_mint_status("mint_nats_server", &e))?;
        Ok(Response::new(credential_response(token, ttl_secs)?))
    }

    async fn mint_nats_curve(
        &self,
        request: Request<pb::MintNatsCurveRequest>,
    ) -> GrpcResult<pb::CredentialResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Mint, &body.key_id)?;
        let ttl_secs = ttl_seconds(body.ttl.as_ref(), "mint_nats_curve")?;
        let routed = self
            .state
            .manager()
            .resolve(&body.key_id)
            .map_err(|e| manager_status("mint_nats_curve", &e))?;
        let issuer = issuer_role(&routed, "mint_nats_curve")?;
        let token = crate::minter::mint_nats_curve(
            routed.backend,
            routed.path(),
            issuer,
            &body.subject_curve_nkey,
            &body.name,
            ttl_secs,
        )
        .await
        .map_err(|e| nats_mint_status("mint_nats_curve", &e))?;
        Ok(Response::new(credential_response(token, ttl_secs)?))
    }

    async fn encrypt_nats_curve(
        &self,
        request: Request<pb::EncryptNatsCurveRequest>,
    ) -> GrpcResult<pb::EncryptNatsCurveResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::EncryptNatsCurve, &body.key_id)?;
        let ciphertext = self
            .state
            .manager()
            .encrypt_nats_curve(&body.key_id, &body.recipient_public_xkey, &body.plaintext)
            .await
            .map_err(|e| manager_status("encrypt_nats_curve", &e))?;
        Ok(Response::new(pb::EncryptNatsCurveResponse { ciphertext }))
    }

    async fn decrypt_nats_curve(
        &self,
        request: Request<pb::DecryptNatsCurveRequest>,
    ) -> GrpcResult<pb::DecryptNatsCurveResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::DecryptNatsCurve, &body.key_id)?;
        let plaintext = self
            .state
            .manager()
            .decrypt_nats_curve(&body.key_id, &body.sender_public_xkey, &body.ciphertext)
            .await
            .map_err(|e| manager_status("decrypt_nats_curve", &e))?;
        Ok(Response::new(pb::DecryptNatsCurveResponse {
            plaintext: plaintext.to_vec(),
        }))
    }

    async fn sign_nats_jwt(
        &self,
        request: Request<pb::SignNatsJwtRequest>,
    ) -> GrpcResult<pb::CredentialResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::SignNatsJwt, &body.key_id)?;
        let claims = claims_json_bytes(&body.claims_json, "sign_nats_jwt")?;
        let ttl_secs = ttl_seconds(body.ttl.as_ref(), "sign_nats_jwt")?;
        let requested_issued_at = body
            .issued_at
            .as_ref()
            .map(|value| timestamp_seconds(value, "sign_nats_jwt", "issued_at"))
            .transpose()?;
        let claim_issued_at = top_level_u64_claim(&claims, "iat", "sign_nats_jwt")?;
        let issued_at = requested_issued_at.or(claim_issued_at);
        let issued_at_for_signer = if ttl_secs.is_some() && issued_at.is_none() {
            Some(unix_now_seconds("sign_nats_jwt")?)
        } else {
            issued_at
        };
        let expires_at = match (ttl_secs, body.expires_at.as_ref()) {
            (Some(_), Some(_)) => {
                return Err(invalid_request(
                    "sign_nats_jwt",
                    "ttl and expires_at are mutually exclusive",
                ));
            }
            (Some(ttl), None) => Some(
                issued_at_for_signer
                    .ok_or_else(|| invalid_request("sign_nats_jwt", "missing issued_at"))?
                    .checked_add(ttl)
                    .ok_or_else(|| invalid_request("sign_nats_jwt", "expires_at overflow"))?,
            ),
            (None, Some(value)) => Some(timestamp_seconds(value, "sign_nats_jwt", "expires_at")?),
            (None, None) => None,
        };
        let routed = self
            .state
            .manager()
            .resolve(&body.key_id)
            .map_err(|e| manager_status("sign_nats_jwt", &e))?;
        let issuer = issuer_role(&routed, "sign_nats_jwt")?;
        let token = crate::minter::sign_nats_jwt(
            routed.backend,
            SignNatsJwtSpec {
                signing_key_id: routed.path(),
                issuer_role: issuer,
                claims: &claims,
                expected_kind: nats_jwt_kind(body.expected_type)?,
                issued_at: issued_at_for_signer,
                expires_at,
                jti_mode: nats_jti_mode(body.jti_mode)?,
            },
        )
        .await
        .map_err(|e| nats_mint_status("sign_nats_jwt", &e))?;
        Ok(Response::new(credential_response_at(token, expires_at)?))
    }

    async fn validate_nats_jwt(
        &self,
        request: Request<pb::ValidateNatsJwtRequest>,
    ) -> GrpcResult<pb::ValidateNatsJwtResponse> {
        let body = request.get_ref();
        let Ok(decoded) = basil_nats::decode_nats_jwt(&body.jwt) else {
            return Ok(Response::new(validate_nats_response(
                false,
                pb::NatsJwtValidationReason::Malformed,
                None,
                None,
                None,
            )));
        };
        let expected = nats_jwt_type(body.expected_type, "validate_nats_jwt")?;
        if expected != pb::NatsJwtType::Unspecified
            && nats_jwt_type_from_claim(decoded.claims().nats_type.as_deref()) != expected
        {
            return Ok(Response::new(validate_nats_response(
                false,
                pb::NatsJwtValidationReason::WrongType,
                Some(decoded.claims()),
                None,
                Some(expected),
            )));
        }

        let now = unix_now_seconds("validate_nats_jwt")?;
        let mut matched_key_id = None;
        let mut matched_candidate = None;
        for signer in &body.allowed_signers {
            match signer.signer.as_ref() {
                Some(pb::allowed_nats_signer::Signer::KeyId(key_id)) => {
                    self.authorize(&request, Op::ValidateNatsJwt, key_id)?;
                    let routed = self
                        .state
                        .manager()
                        .resolve(key_id)
                        .map_err(|e| manager_status("validate_nats_jwt", &e))?;
                    let role = issuer_role(&routed, "validate_nats_jwt")?;
                    let public_key = self
                        .state
                        .manager()
                        .get_public_key(key_id)
                        .await
                        .map_err(|e| manager_status("validate_nats_jwt", &e))?;
                    let nkey =
                        basil_nats::encode_public(role, &public_key.public_key).map_err(|e| {
                            invalid_request("validate_nats_jwt", format!("invalid signer key: {e}"))
                        })?;
                    let validation = decoded
                        .verify_with_candidates([basil_nats::CandidateSigner::Nkey(&nkey)], now)
                        .map_err(|e| invalid_request("validate_nats_jwt", e.to_string()))?;
                    if validation.matched_signer.is_some() {
                        matched_key_id = Some(key_id.clone());
                        matched_candidate = Some(OwnedCandidateSigner::Nkey(nkey));
                        break;
                    }
                }
                Some(pb::allowed_nats_signer::Signer::NatsPublicKey(nkey)) => {
                    let validation = decoded
                        .verify_with_candidates([basil_nats::CandidateSigner::Nkey(nkey)], now)
                        .map_err(|e| invalid_request("validate_nats_jwt", e.to_string()))?;
                    if validation.matched_signer.is_some() {
                        matched_candidate = Some(OwnedCandidateSigner::Nkey(nkey.clone()));
                        break;
                    }
                }
                None => return Err(invalid_request("validate_nats_jwt", "missing signer")),
            }
        }

        let Some(candidate) = matched_candidate else {
            return Ok(Response::new(validate_nats_response(
                false,
                pb::NatsJwtValidationReason::UnknownSigner,
                Some(decoded.claims()),
                None,
                None,
            )));
        };
        let validation = decoded
            .verify_with_candidates([candidate.as_candidate()], now)
            .map_err(|e| invalid_request("validate_nats_jwt", e.to_string()))?;
        let reason = proto_validation_reason(validation.reason);
        Ok(Response::new(validate_nats_response(
            reason == pb::NatsJwtValidationReason::Valid,
            reason,
            Some(decoded.claims()),
            matched_key_id,
            None,
        )))
    }
}

enum OwnedCandidateSigner {
    Nkey(String),
}

impl OwnedCandidateSigner {
    fn as_candidate(&self) -> basil_nats::CandidateSigner<'_> {
        match self {
            Self::Nkey(nkey) => basil_nats::CandidateSigner::Nkey(nkey),
        }
    }
}

fn issuer_role(
    routed: &crate::manager::Routed<'_>,
    op: &'static str,
) -> Result<basil_nats::NkeyType, Status> {
    routed.entry.labels.nats_type().ok_or_else(|| {
        invalid_request(
            op,
            "issuer key has no nats_type label for the NKey iss prefix",
        )
    })
}

fn nats_jwt_type(value: i32, op: &'static str) -> Result<pb::NatsJwtType, Status> {
    pb::NatsJwtType::try_from(value).map_err(|_| invalid_request(op, "unknown nats jwt type"))
}

fn nats_jwt_type_from_claim(kind: Option<&str>) -> pb::NatsJwtType {
    match kind {
        Some("user") => pb::NatsJwtType::User,
        Some("account") => pb::NatsJwtType::Account,
        Some("operator") => pb::NatsJwtType::Operator,
        Some("signer") => pb::NatsJwtType::Signer,
        Some("server") => pb::NatsJwtType::Server,
        Some("curve") => pb::NatsJwtType::Curve,
        _ => pb::NatsJwtType::Unspecified,
    }
}

const fn proto_validation_reason(
    reason: basil_nats::NatsJwtValidationReason,
) -> pb::NatsJwtValidationReason {
    match reason {
        basil_nats::NatsJwtValidationReason::Valid => pb::NatsJwtValidationReason::Valid,
        basil_nats::NatsJwtValidationReason::UnknownSigner => {
            pb::NatsJwtValidationReason::UnknownSigner
        }
        basil_nats::NatsJwtValidationReason::BadSignature => {
            pb::NatsJwtValidationReason::BadSignature
        }
        basil_nats::NatsJwtValidationReason::Expired => pb::NatsJwtValidationReason::Expired,
        basil_nats::NatsJwtValidationReason::NotYetValid => {
            pb::NatsJwtValidationReason::NotYetValid
        }
    }
}

fn validate_nats_response(
    valid: bool,
    reason: pb::NatsJwtValidationReason,
    claims: Option<&basil_nats::NatsJwtClaims>,
    matched_signer_key_id: Option<String>,
    override_type: Option<pb::NatsJwtType>,
) -> pb::ValidateNatsJwtResponse {
    let jwt_type = override_type
        .unwrap_or_else(|| nats_jwt_type_from_claim(claims.and_then(|c| c.nats_type.as_deref())));
    pb::ValidateNatsJwtResponse {
        valid,
        reason: reason.into(),
        subject: claims.map_or_else(String::new, |c| c.subject.clone()),
        issuer: claims.map_or_else(String::new, |c| c.issuer.clone()),
        matched_signer_key_id: matched_signer_key_id.unwrap_or_default(),
        jwt_type: jwt_type.into(),
        expires_at_unix: claims.and_then(|c| c.expires_at).unwrap_or_default(),
        issued_at_unix: claims.and_then(|c| c.issued_at).unwrap_or_default(),
    }
}

fn nats_jwt_kind(value: i32) -> Result<Option<NatsJwtKind>, Status> {
    let kind = match pb::NatsJwtType::try_from(value)
        .map_err(|_| invalid_request("sign_nats_jwt", "unknown expected_type"))?
    {
        pb::NatsJwtType::Unspecified => None,
        pb::NatsJwtType::User => Some(NatsJwtKind::User),
        pb::NatsJwtType::Account => Some(NatsJwtKind::Account),
        pb::NatsJwtType::Operator => Some(NatsJwtKind::Operator),
        pb::NatsJwtType::Signer => Some(NatsJwtKind::Signer),
        pb::NatsJwtType::Server => Some(NatsJwtKind::Server),
        pb::NatsJwtType::Curve => Some(NatsJwtKind::Curve),
    };
    Ok(kind)
}

fn nats_jti_mode(value: i32) -> Result<NatsJtiMode, Status> {
    let mode = match pb::NatsJtiMode::try_from(value)
        .map_err(|_| invalid_request("sign_nats_jwt", "unknown jti_mode"))?
    {
        pb::NatsJtiMode::RequireValid => NatsJtiMode::RequireValid,
        pb::NatsJtiMode::Rewrite => NatsJtiMode::Rewrite,
    };
    Ok(mode)
}

fn timestamp_seconds(
    timestamp: &prost_types::Timestamp,
    op: &'static str,
    field: &'static str,
) -> Result<u64, Status> {
    u64::try_from(timestamp.seconds)
        .map_err(|_| invalid_request(op, format!("{field} must be a non-negative unix timestamp")))
}

fn claims_json_bytes(claims_json: &[u8], op: &'static str) -> Result<JsonValue, Status> {
    if claims_json.is_empty() {
        return Err(invalid_request(op, "claims_json is required"));
    }
    let claims = serde_json::from_slice::<JsonValue>(claims_json)
        .map_err(|e| invalid_request(op, format!("claims_json must be valid JSON: {e}")))?;
    if !claims.is_object() {
        return Err(invalid_request(op, "claims_json must be a JSON object"));
    }
    Ok(claims)
}

fn top_level_u64_claim(
    claims: &JsonValue,
    field: &'static str,
    op: &'static str,
) -> Result<Option<u64>, Status> {
    let Some(value) = claims.get(field) else {
        return Ok(None);
    };
    value.as_u64().map(Some).ok_or_else(|| {
        invalid_request(op, format!("claims.{field} must be a non-negative integer"))
    })
}

fn credential_response_at(
    token: String,
    expires_at: Option<u64>,
) -> Result<pb::CredentialResponse, Status> {
    let expires_at = expires_at
        .map(|seconds| {
            i64::try_from(seconds)
                .map(|seconds| prost_types::Timestamp { seconds, nanos: 0 })
                .map_err(|_| invalid_request("sign_nats_jwt", "expires_at too large"))
        })
        .transpose()?;
    Ok(pb::CredentialResponse { token, expires_at })
}

fn unix_now_seconds(op: &'static str) -> Result<u64, Status> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| invalid_request(op, "system time is before unix epoch"))
}

fn generic_mint_status(op: &'static str, err: crate::minter::GenericMintError) -> Status {
    match err {
        crate::minter::GenericMintError::Reserved(err) => invalid_request(op, err.to_string()),
        crate::minter::GenericMintError::Backend(err) => nats_mint_status(op, &err),
    }
}

pub(super) fn nats_mint_status(op: &'static str, err: &BackendError) -> Status {
    match err {
        BackendError::Protocol(message)
            if message.starts_with("invalid subject ")
                || message.starts_with("invalid nats jwt ")
                || message.starts_with("invalid account signing key")
                || message.starts_with("invalid operator signing key")
                || message.starts_with("invalid system account nkey")
                || message.starts_with("unsupported issuer role") =>
        {
            invalid_request(op, message.clone())
        }
        _ => backend_status(op, err),
    }
}
