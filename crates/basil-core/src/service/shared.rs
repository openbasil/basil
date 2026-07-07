#![allow(clippy::result_large_err)]

// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::time::{SystemTime, UNIX_EPOCH};

use basil_proto::broker::v1 as pb;
use prost_types::{Duration, Struct, Timestamp, Value as ProstValue, value::Kind as ProstKind};
use serde_json::Value as JsonValue;
use tonic::{Code, Status};

use crate::actor::AuthenticatedActor;
use crate::backend::BackendError;
use crate::catalog::policy::Op;
use crate::core::crypto_provider::{KemAlgorithm, ProviderError, SignatureAlgorithm};
use crate::event::{BrokerEvent, BrokerEventKind};
use crate::manager::{ManagerError, SealingFailure, SigningFailure};
use crate::state::BrokerState;
use crate::transport::broker_status;

pub(super) fn key_type(value: i32, op: &'static str) -> Result<basil_proto::KeyType, Status> {
    match pb::KeyType::try_from(value).map_err(|_| invalid_request(op, "unknown key type"))? {
        pb::KeyType::Unspecified => Err(invalid_request(op, "missing key type")),
        pb::KeyType::Ed25519 => Ok(basil_proto::KeyType::Ed25519),
        pb::KeyType::Ed25519Nkey => Ok(basil_proto::KeyType::Ed25519Nkey),
        pb::KeyType::Rsa2048 => Ok(basil_proto::KeyType::Rsa2048),
        pb::KeyType::EcdsaP256 => Ok(basil_proto::KeyType::EcdsaP256),
        pb::KeyType::EcdsaP384 => Ok(basil_proto::KeyType::EcdsaP384),
        pb::KeyType::EcdsaP521 => Ok(basil_proto::KeyType::EcdsaP521),
        // The post-quantum families do not flow through the classical
        // backend-native key path. `new_key` routes a software-custody PQC key
        // through the crypto provider *before* this conversion (the catalog
        // declares the algorithm); reaching here means the named key is not a
        // declared software-custody PQC key, or this is an `import` (custody
        // records are broker-sealed, never BYOK-imported).
        pb::KeyType::MlDsa44 | pb::KeyType::MlDsa65 | pb::KeyType::MlDsa87 => {
            Err(unsupported_algorithm(
                op,
                "ML-DSA keys are provisioned from a software-custody catalog entry, not this path",
            ))
        }
        pb::KeyType::MlKem512 | pb::KeyType::MlKem768 | pb::KeyType::MlKem1024 => {
            Err(unsupported_algorithm(
                op,
                "ML-KEM keys are provisioned from a software-custody catalog entry, not this path",
            ))
        }
    }
}

/// Validate that the wire `key_type` names the same ML-DSA level as the catalog
/// key being provisioned. ML-DSA software-custody keys take their algorithm from
/// the catalog `keyType`; the request must name a consistent ML-DSA key type so a
/// client cannot silently provision a different level than the catalog declares.
pub(super) fn ensure_ml_dsa_key_type_matches(
    value: i32,
    algorithm: SignatureAlgorithm,
    op: &'static str,
) -> Result<(), Status> {
    let wire = pb::KeyType::try_from(value).map_err(|_| invalid_request(op, "unknown key type"))?;
    let consistent = matches!(
        (wire, algorithm),
        (pb::KeyType::MlDsa44, SignatureAlgorithm::MlDsa44)
            | (pb::KeyType::MlDsa65, SignatureAlgorithm::MlDsa65)
            | (pb::KeyType::MlDsa87, SignatureAlgorithm::MlDsa87)
    );
    if consistent {
        Ok(())
    } else {
        Err(invalid_request(
            op,
            "key type does not match the catalog ML-DSA key",
        ))
    }
}

/// Validate that the wire `key_type` names the same ML-KEM parameter set as the
/// catalog sealing key being provisioned. The algorithm comes from the catalog
/// `keyType`; the request must name a consistent ML-KEM type so a client cannot
/// silently provision a different parameter set than the catalog declares.
pub(super) fn ensure_ml_kem_key_type_matches(
    value: i32,
    kem: KemAlgorithm,
    op: &'static str,
) -> Result<(), Status> {
    let wire = pb::KeyType::try_from(value).map_err(|_| invalid_request(op, "unknown key type"))?;
    let consistent = matches!(
        (wire, kem),
        (pb::KeyType::MlKem512, KemAlgorithm::MlKem512)
            | (pb::KeyType::MlKem768, KemAlgorithm::MlKem768)
            | (pb::KeyType::MlKem1024, KemAlgorithm::MlKem1024)
    );
    if consistent {
        Ok(())
    } else {
        Err(invalid_request(
            op,
            "key type does not match the catalog ML-KEM key",
        ))
    }
}

pub(super) fn proto_key_type(value: basil_proto::KeyType) -> i32 {
    match value {
        basil_proto::KeyType::Ed25519 => pb::KeyType::Ed25519,
        basil_proto::KeyType::Ed25519Nkey => pb::KeyType::Ed25519Nkey,
        basil_proto::KeyType::Rsa2048 => pb::KeyType::Rsa2048,
        basil_proto::KeyType::EcdsaP256 => pb::KeyType::EcdsaP256,
        basil_proto::KeyType::EcdsaP384 => pb::KeyType::EcdsaP384,
        basil_proto::KeyType::EcdsaP521 => pb::KeyType::EcdsaP521,
        basil_proto::KeyType::MlDsa44 => pb::KeyType::MlDsa44,
        basil_proto::KeyType::MlDsa65 => pb::KeyType::MlDsa65,
        basil_proto::KeyType::MlDsa87 => pb::KeyType::MlDsa87,
        basil_proto::KeyType::MlKem512 => pb::KeyType::MlKem512,
        basil_proto::KeyType::MlKem768 => pb::KeyType::MlKem768,
        basil_proto::KeyType::MlKem1024 => pb::KeyType::MlKem1024,
    }
    .into()
}

pub(super) fn ensure_supported_signing_algorithm(
    value: i32,
    op: &'static str,
) -> Result<(), Status> {
    match pb::SigningAlgorithm::try_from(value)
        .map_err(|_| invalid_request(op, "unknown signing algorithm"))?
    {
        pb::SigningAlgorithm::Unspecified
        | pb::SigningAlgorithm::Ed25519
        | pb::SigningAlgorithm::Ed25519Nkey
        | pb::SigningAlgorithm::Rs256
        | pb::SigningAlgorithm::Es256
        // ML-DSA is serviceable for a software-custodied signing key: the actual
        // algorithm is taken from the key's catalog `keyType`, not this wire
        // field, and the manager dispatches it through the local-software
        // provider. A request naming ML-DSA against a classical key still signs
        // with the key's real type (the wire algorithm is advisory).
        | pb::SigningAlgorithm::MlDsa44
        | pb::SigningAlgorithm::MlDsa65
        | pb::SigningAlgorithm::MlDsa87 => Ok(()),
    }
}

/// The KEM algorithm the broker can service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SupportedKem {
    /// X25519 sealed box (ECDH + HKDF-SHA256 + AEAD).
    X25519,
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
}

pub(super) fn ensure_supported_kem_algorithm(
    value: i32,
    op: &'static str,
) -> Result<SupportedKem, Status> {
    match pb::KemAlgorithm::try_from(value)
        .map_err(|_| invalid_request(op, "unknown KEM algorithm"))?
    {
        pb::KemAlgorithm::Unspecified => Err(invalid_request(op, "missing KEM algorithm")),
        pb::KemAlgorithm::X25519 => Ok(SupportedKem::X25519),
        pb::KemAlgorithm::MlKem512 => Ok(SupportedKem::MlKem512),
        pb::KemAlgorithm::MlKem768 => Ok(SupportedKem::MlKem768),
        pb::KemAlgorithm::MlKem1024 => Ok(SupportedKem::MlKem1024),
    }
}

pub(super) fn ensure_supported_envelope_algorithm(
    value: i32,
    op: &'static str,
) -> Result<(), Status> {
    match pb::EnvelopeAlgorithm::try_from(value)
        .map_err(|_| invalid_request(op, "unknown envelope algorithm"))?
    {
        pb::EnvelopeAlgorithm::Unspecified => {
            Err(invalid_request(op, "missing envelope algorithm"))
        }
        pb::EnvelopeAlgorithm::Aes256Gcm | pb::EnvelopeAlgorithm::Chacha20Poly1305 => Ok(()),
    }
}

pub(super) fn aead_algorithm(
    value: i32,
    op: &'static str,
) -> Result<basil_proto::AeadAlgorithm, Status> {
    match pb::AeadAlgorithm::try_from(value)
        .map_err(|_| invalid_request(op, "unknown AEAD algorithm"))?
    {
        pb::AeadAlgorithm::Unspecified => Err(invalid_request(op, "missing AEAD algorithm")),
        pb::AeadAlgorithm::Chacha20Poly1305 => Ok(basil_proto::AeadAlgorithm::Chacha20Poly1305),
        pb::AeadAlgorithm::Aes256Gcm => Ok(basil_proto::AeadAlgorithm::Aes256Gcm),
    }
}

fn proto_aead_algorithm(value: basil_proto::AeadAlgorithm) -> i32 {
    match value {
        basil_proto::AeadAlgorithm::Chacha20Poly1305 => pb::AeadAlgorithm::Chacha20Poly1305,
        basil_proto::AeadAlgorithm::Aes256Gcm => pb::AeadAlgorithm::Aes256Gcm,
    }
    .into()
}

pub(super) fn key_material(
    value: &pb::KeyMaterial,
    op: &'static str,
) -> Result<basil_proto::KeyMaterial, Status> {
    match value.material.as_ref() {
        Some(pb::key_material::Material::Ed25519Seed(seed)) => {
            Ok(basil_proto::KeyMaterial::Ed25519Seed(seed.clone()))
        }
        Some(pb::key_material::Material::Pkcs8Der(der)) => {
            Ok(basil_proto::KeyMaterial::Pkcs8Der(der.clone()))
        }
        None => Err(invalid_request(op, "missing key material")),
    }
}

pub(super) const fn material_len(material: &basil_proto::KeyMaterial) -> usize {
    match material {
        basil_proto::KeyMaterial::Ed25519Seed(seed) => seed.len(),
        basil_proto::KeyMaterial::Pkcs8Der(der) => der.len(),
    }
}

pub(super) fn ciphertext_envelope(
    value: basil_proto::CiphertextEnvelope,
) -> pb::CiphertextEnvelope {
    pb::CiphertextEnvelope {
        alg: proto_aead_algorithm(value.alg),
        key_version: value.key_version,
        nonce: value.nonce,
        ciphertext: value.ciphertext,
    }
}

pub(super) fn basil_ciphertext_envelope(
    value: &pb::CiphertextEnvelope,
    op: &'static str,
) -> Result<basil_proto::CiphertextEnvelope, Status> {
    Ok(basil_proto::CiphertextEnvelope {
        alg: aead_algorithm(value.alg, op)?,
        key_version: value.key_version,
        nonce: value.nonce.clone(),
        ciphertext: value.ciphertext.clone(),
    })
}

pub(super) fn catalog_entry(value: basil_proto::CatalogEntry) -> pb::CatalogEntry {
    pb::CatalogEntry {
        name: value.name,
        kind: match value.kind {
            basil_proto::CatalogKind::Signing => pb::CatalogKind::Signing,
            basil_proto::CatalogKind::Value => pb::CatalogKind::Value,
            basil_proto::CatalogKind::Encryption => pb::CatalogKind::Encryption,
            _ => pb::CatalogKind::Unspecified,
        }
        .into(),
        key_type: value.key_type.map(proto_key_type),
        latest_version: value.latest_version,
    }
}

pub(super) fn event_allowed(
    state: &BrokerState,
    actor: &AuthenticatedActor,
    kinds: &[i32],
    event: &BrokerEvent,
) -> bool {
    if !event_kind_selected(kinds, event) {
        return false;
    }
    match &event.kind {
        BrokerEventKind::KeyRotated { key_id, .. } => {
            let generation = state.load_generation();
            let pdp = generation.pdp();
            pdp.decide(actor, Op::List, key_id).is_allow()
                || pdp.decide(actor, Op::GetPublicKey, key_id).is_allow()
                || pdp.decide(actor, Op::Get, key_id).is_allow()
        }
        BrokerEventKind::BundleChanged { .. } | BrokerEventKind::Revoked { .. } => true,
    }
}

fn event_kind_selected(kinds: &[i32], event: &BrokerEvent) -> bool {
    if kinds.is_empty() {
        return true;
    }
    let event_kind = match event.kind {
        BrokerEventKind::KeyRotated { .. } => pb::EventKind::KeyRotated,
        BrokerEventKind::BundleChanged { .. } => pb::EventKind::BundleChanged,
        BrokerEventKind::Revoked { .. } => pb::EventKind::Revoked,
    };
    kinds
        .iter()
        .filter_map(|kind| pb::EventKind::try_from(*kind).ok())
        .any(|kind| kind == event_kind)
}

pub(super) fn proto_event(event: BrokerEvent) -> pb::Event {
    let (kind, detail) = match event.kind {
        BrokerEventKind::KeyRotated {
            key_id,
            new_version,
        } => (
            pb::EventKind::KeyRotated,
            Some(pb::event::Detail::KeyRotated(pb::KeyRotated {
                key_id,
                new_version,
            })),
        ),
        BrokerEventKind::BundleChanged { trust_domain } => (
            pb::EventKind::BundleChanged,
            Some(pb::event::Detail::BundleChanged(pb::BundleChanged {
                trust_domain,
            })),
        ),
        BrokerEventKind::Revoked { trust_domain, id } => (
            pb::EventKind::Revoked,
            Some(pb::event::Detail::Revoked(pb::Revoked { trust_domain, id })),
        ),
    };
    pb::Event {
        kind: kind.into(),
        at: Some(system_time_timestamp(event.at)),
        detail,
    }
}

fn system_time_timestamp(at: SystemTime) -> Timestamp {
    let duration = at
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0));
    Timestamp {
        seconds: i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        nanos: i32::try_from(duration.subsec_nanos()).unwrap_or(0),
    }
}

pub(super) fn manager_status(op: &'static str, err: &ManagerError) -> Status {
    match err {
        // An unknown key and a pinned-context refusal (basil-2rqj) both deny
        // access: the latter is a least-privilege denial when the op:decrypt grant
        // does not cover this envelope's KDF parties / external_aad. Both are
        // permission-denied and leak nothing secret (parties are cleartext header
        // values, external_aad is caller-supplied).
        ManagerError::UnknownKey(_) | ManagerError::UnsealContextNotPermitted(_) => {
            unauthorized(op)
        }
        // A missing public_path on a materialize-to-use key is a server-side
        // catalog misconfiguration (the loader normally rejects it), not client
        // input. Surface it as an internal fault, like an unknown backend.
        ManagerError::UnknownBackend { .. } | ManagerError::MissingPublicPath(_) => {
            internal(op, err.to_string())
        }
        ManagerError::OpNotValidForClass { .. }
        | ManagerError::AlgorithmMismatch { .. }
        | ManagerError::KemAlgorithmMismatch { .. }
        | ManagerError::ValueRotateNeedsSet(_)
        // A malformed sealing key/envelope is a client input fault; the opaque
        // unseal-authentication failure is handled separately below.
        | ManagerError::Sealing(SealingFailure::Malformed)
        // A malformed materialize-to-sign seed / verify input is likewise an input
        // (config) fault, not an oracle.
        | ManagerError::Signing(SigningFailure::Malformed) => invalid_request(op, err.to_string()),
        ManagerError::UnsupportedKeyType { .. } => unsupported_algorithm(op, err.to_string()),
        ManagerError::Unsupported(_) => unsupported(op, err.to_string()),
        // An unseal authentication failure maps to the same opaque decrypt_failed
        // code as a transit AEAD failure (no oracle).
        ManagerError::Sealing(SealingFailure::OpenFailed) => decrypt_failed(op),
        ManagerError::Provider(err) => provider_status(op, err),
        ManagerError::Backend(err) => backend_status(op, err),
    }
}

/// Map a provider-dispatch ([`ProviderError`]) failure onto a canonical, opaque
/// broker status: no internal detail or decrypt oracle leaks.
pub(super) fn provider_status(op: &'static str, err: &ProviderError) -> Status {
    match err {
        // Unsupported algorithm/provider combination (e.g. `backend-required`
        // ML-DSA with no backend-native provider), fail closed as unimplemented.
        ProviderError::Unsupported { .. } => unsupported_algorithm(op, err.to_string()),
        // Policy denied the local-software provider: the caller lacks the
        // explicit `op:use_software_custody` grant. Surface as unauthorized.
        ProviderError::PolicyDenied { .. } => unauthorized(op),
        // An opaque software-custody crypto/record failure (malformed record,
        // wrong material, auth failure). Stable, secret-free invalid_request.
        ProviderError::CryptoFailed { .. } => invalid_request(op, "provider operation failed"),
        ProviderError::Backend(err) => backend_status(op, err),
    }
}

pub(super) fn backend_status(op: &'static str, err: &BackendError) -> Status {
    match err {
        BackendError::UnsupportedKeyType(_) | BackendError::UnsupportedAlgorithm(_) => {
            unsupported_algorithm(op, err.to_string())
        }
        BackendError::Unsupported(_) => unsupported(op, err.to_string()),
        BackendError::KeyNotFound(_) => internal(op, err.to_string()),
        BackendError::DecryptFailed => decrypt_failed(op),
        BackendError::Transport(_) => backend_unavailable(op, "backend unavailable"),
        BackendError::Backend(_) | BackendError::Protocol(_) => {
            backend_error(op, "backend operation failed")
        }
    }
}

pub(super) fn invalid_request(op: &'static str, message: impl Into<String>) -> Status {
    broker_status(Code::InvalidArgument, "INVALID_REQUEST", op, message)
}

pub(super) fn payload_too_large(op: &'static str, message: impl Into<String>) -> Status {
    broker_status(Code::ResourceExhausted, "PAYLOAD_TOO_LARGE", op, message)
}

fn unsupported(op: &'static str, message: impl Into<String>) -> Status {
    broker_status(Code::Unimplemented, "UNSUPPORTED", op, message)
}

pub(super) fn unsupported_algorithm(op: &'static str, message: impl Into<String>) -> Status {
    broker_status(Code::Unimplemented, "UNSUPPORTED_ALGORITHM", op, message)
}

fn unauthorized(op: &'static str) -> Status {
    broker_status(Code::PermissionDenied, "UNAUTHORIZED", op, "not authorized")
}

fn decrypt_failed(op: &'static str) -> Status {
    broker_status(
        Code::InvalidArgument,
        "DECRYPT_FAILED",
        op,
        "decrypt failed",
    )
}

fn backend_unavailable(op: &'static str, message: impl Into<String>) -> Status {
    broker_status(Code::Unavailable, "BACKEND_UNAVAILABLE", op, message)
}

fn backend_error(op: &'static str, message: impl Into<String>) -> Status {
    broker_status(Code::Internal, "BACKEND_ERROR", op, message)
}

fn internal(op: &'static str, message: impl Into<String>) -> Status {
    broker_status(Code::Internal, "INTERNAL", op, message)
}

pub(super) fn ttl_seconds(ttl: Option<&Duration>, op: &'static str) -> Result<Option<u64>, Status> {
    let Some(ttl) = ttl else {
        return Ok(None);
    };
    if ttl.seconds < 0 {
        return Err(invalid_request(op, "ttl must be non-negative"));
    }
    if !(0..1_000_000_000).contains(&ttl.nanos) {
        return Err(invalid_request(op, "ttl nanos is out of range"));
    }
    let seconds = u64::try_from(ttl.seconds).map_err(|_| invalid_request(op, "ttl too large"))?;
    let rounded = seconds
        .checked_add(u64::from(ttl.nanos > 0))
        .ok_or_else(|| invalid_request(op, "ttl too large"))?;
    Ok(Some(rounded))
}

pub(super) fn claims_json(claims: Option<&Struct>, op: &'static str) -> Result<JsonValue, Status> {
    let Some(claims) = claims else {
        return Ok(JsonValue::Object(serde_json::Map::new()));
    };
    let fields = claims
        .fields
        .iter()
        .map(|(key, value)| prost_value_to_json(value, op).map(|value| (key.clone(), value)))
        .collect::<Result<serde_json::Map<_, _>, _>>()?;
    Ok(JsonValue::Object(fields))
}

fn prost_value_to_json(value: &ProstValue, op: &'static str) -> Result<JsonValue, Status> {
    let Some(kind) = &value.kind else {
        return Ok(JsonValue::Null);
    };
    match kind {
        ProstKind::NullValue(_) => Ok(JsonValue::Null),
        ProstKind::NumberValue(number) => prost_number_to_json(*number, op),
        ProstKind::StringValue(value) => Ok(JsonValue::String(value.clone())),
        ProstKind::BoolValue(value) => Ok(JsonValue::Bool(*value)),
        ProstKind::StructValue(value) => claims_json(Some(value), op),
        ProstKind::ListValue(value) => value
            .values
            .iter()
            .map(|value| prost_value_to_json(value, op))
            .collect::<Result<Vec<_>, _>>()
            .map(JsonValue::Array),
    }
}

fn prost_number_to_json(number: f64, op: &'static str) -> Result<JsonValue, Status> {
    if !number.is_finite() {
        return Err(invalid_request(op, "claims contain a non-finite number"));
    }
    if number.fract() == 0.0 {
        let decimal = format!("{number:.0}");
        if let Ok(value) = decimal.parse::<i64>() {
            return Ok(JsonValue::Number(value.into()));
        }
        if let Ok(value) = decimal.parse::<u64>() {
            return Ok(JsonValue::Number(value.into()));
        }
    }
    serde_json::Number::from_f64(number)
        .map(JsonValue::Number)
        .ok_or_else(|| invalid_request(op, "claims contain a non-finite number"))
}

pub(super) fn credential_response(
    token: String,
    ttl_secs: Option<u64>,
) -> Result<pb::CredentialResponse, Status> {
    let expires_at = match ttl_secs {
        Some(ttl) => Some(Timestamp {
            seconds: unix_now()
                .checked_add(ttl)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or_else(|| internal("mint", "expires_at overflow"))?,
            nanos: 0,
        }),
        None => None,
    };
    Ok(pb::CredentialResponse { token, expires_at })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
