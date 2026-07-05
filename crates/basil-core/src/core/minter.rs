// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Credential minters.
//!
//! A minter assembles a format-specific credential (here, a NATS user JWT) by
//! delegating the actual signature to the [`Backend`], so the signing key
//! never leaves the vault. This is the generic "assemble in the broker, sign in
//! the backend" pattern; SPIFFE-SVID and other formats can join later.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::elliptic_curve::sec1::ToEncodedPoint as _;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use basil_nats::{NkeyType, RoleKind};

use crate::backend::{Backend, BackendError, SignOptions};

/// Standard JWT claim keys the preset owns and a caller may NOT supply in
/// `claims` (reserved-claim protection, §6). A collision is `invalid_request`.
const RESERVED_GENERIC_CLAIMS: &[&str] = &["iss", "iat", "exp", "jti", "sub", "nbf"];

/// The reserved claims for the `svid` preset: the generic set plus `aud`, which
/// the preset owns (the required SVID audience, §6). A caller `claims.aud` is the
/// *source* of the audience, but it is consumed by the preset, not merged as an
/// arbitrary extra, so it is listed here and stripped before the merge.
const RESERVED_SVID_CLAIMS: &[&str] = &["iss", "iat", "exp", "jti", "sub", "nbf", "aud"];

/// NATS JWT claim kinds Basil can validate and sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatsJwtKind {
    /// A NATS user JWT (`nats.type=user`).
    User,
    /// A NATS account JWT (`nats.type=account`).
    Account,
    /// A NATS operator JWT (`nats.type=operator`).
    Operator,
    /// A NATS signing-key JWT (`nats.type=signer`).
    Signer,
    /// A NATS server JWT (`nats.type=server`).
    Server,
    /// A NATS curve/xkey JWT (`nats.type=curve`).
    Curve,
}

impl NatsJwtKind {
    /// Parse the `nats.type` claim.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "account" => Some(Self::Account),
            "operator" => Some(Self::Operator),
            "signer" => Some(Self::Signer),
            "server" => Some(Self::Server),
            "curve" => Some(Self::Curve),
            _ => None,
        }
    }

    /// The canonical `nats.type` string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Account => "account",
            Self::Operator => "operator",
            Self::Signer => "signer",
            Self::Server => "server",
            Self::Curve => "curve",
        }
    }
}

impl std::fmt::Display for NatsJwtKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How [`sign_nats_jwt`] handles a supplied but incorrect NATS `jti`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatsJtiMode {
    /// Reject a supplied `jti` that does not match the NATS standard-claim hash.
    RequireValid,
    /// Replace a missing or mismatched `jti` with the computed value.
    Rewrite,
}

/// Inputs for [`sign_nats_jwt`].
pub struct SignNatsJwtSpec<'a> {
    /// Catalog/backend key id to sign with.
    pub signing_key_id: &'a str,
    /// NATS role of the issuer key, from the catalog `nats_type` label.
    pub issuer_role: NkeyType,
    /// Caller-supplied NATS JWT claims.
    pub claims: &'a Value,
    /// Optional assertion against `claims.nats.type`.
    pub expected_kind: Option<NatsJwtKind>,
    /// Override/insert `iat` as a Unix timestamp.
    pub issued_at: Option<u64>,
    /// Override/insert `exp` as a Unix timestamp.
    pub expires_at: Option<u64>,
    /// Handling for a supplied but stale `jti`.
    pub jti_mode: NatsJtiMode,
}

/// The JWS `alg` for a JWT-SVID, derived from the issuer key's catalog key type.
///
/// `EdDSA` is raw Ed25519 (RFC 8037); `RS256` is RSASSA-PKCS1-v1_5 over SHA-256;
/// `ES256` is ECDSA P-256 over SHA-256 and `ES384` is ECDSA P-384 over SHA-384,
/// both with raw fixed-width `r || s` signatures. In all cases the **backend**
/// signs the signing input, so the private key never leaves the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvidAlg {
    /// Ed25519 issuer (`ed25519` / `ed25519-nkey`).
    EdDsa,
    /// RSA-2048 issuer (`rsa-2048`).
    Rs256,
    /// ECDSA P-256 issuer (`ecdsa-p256`).
    Es256,
    /// ECDSA P-384 issuer (`ecdsa-p384`).
    Es384,
}

impl SvidAlg {
    /// The JWS `alg` header string.
    const fn header_alg(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
        }
    }

    /// Backend signing options required for this JWS algorithm.
    const fn sign_options(self) -> SignOptions {
        match self {
            Self::EdDsa => SignOptions::Default,
            Self::Rs256 => SignOptions::Rs256Pkcs1v15Sha256,
            Self::Es256 => SignOptions::Es256,
            Self::Es384 => SignOptions::Es384,
        }
    }
}

/// Build JWKS bytes for a JWT-SVID issuer key held by `backend`.
///
/// The returned bytes are a UTF-8 JSON Web Key Set (`{"keys":[...]}`) suitable
/// for a SPIFFE JWT bundle response. The `kid` is deterministic from
/// `(alg, public_key)`, so issuer rotation changes the published key id without
/// backend-specific metadata.
pub async fn jwt_svid_jwks(
    backend: &dyn Backend,
    signing_key_id: &str,
    alg: SvidAlg,
) -> Result<Vec<u8>, BackendError> {
    let public_key = backend.public_key(signing_key_id).await?;
    jwt_svid_jwks_from_public_key(&public_key, alg)
}

/// Build grace-window JWKS bytes for a JWT-SVID issuer held by `backend`.
///
/// Reflects the **rotation grace window**: every version's public key still
/// inside `[grace_floor ..= latest]` is published, so a verifier can validate a
/// token signed by a recently rotated-away version, while versions below the
/// floor are dropped.
///
/// Fetches the issuer's whole version→public-key map ([`Backend::public_keys`])
/// in one round-trip and the latest version ([`Backend::public_keys`] keys), then
/// applies `grace_floor` (the broker's [`crate::state::BrokerLimits::grace_floor`]
/// for the latest version). This is the **single source of truth** used by both
/// the gRPC Workload-API JWKS and the HTTP JWKS so they never diverge.
pub async fn jwt_svid_jwks_grace(
    backend: &dyn Backend,
    signing_key_id: &str,
    alg: SvidAlg,
    grace_floor: impl Fn(u32) -> u32,
) -> Result<Vec<u8>, BackendError> {
    let versions = backend.public_keys(signing_key_id).await?;
    let latest = versions.keys().copied().max().unwrap_or(1);
    jwt_svid_jwks_grace_window(&versions, latest, grace_floor(latest), alg)
}

/// Build JWKS bytes from already-fetched JWT-SVID issuer public key bytes.
///
/// A single-key set for the supplied public half. The grace-window variant
/// [`jwt_svid_jwks_grace_window`] publishes every in-window version.
pub fn jwt_svid_jwks_from_public_key(
    public_key: &[u8],
    alg: SvidAlg,
) -> Result<Vec<u8>, BackendError> {
    let key = jwk_for_public_key(public_key, alg)?;
    serde_json::to_vec(&json!({ "keys": [key] }))
        .map_err(|e| BackendError::Protocol(format!("serializing jwks: {e}")))
}

/// Build grace-window JWKS bytes from a version→public-key map.
///
/// Reflects the **rotation grace window**: one JWK per key version in
/// `[grace_floor ..= latest]` that has a published public half, so a verifier can
/// validate a token signed by a recently-rotated-away version, and versions below
/// the floor are absent.
///
/// `versions` is the backend's whole version→public-key map (e.g. transit's
/// `data.keys`, fetched via [`Backend::public_keys`]); `grace_floor` is
/// [`crate::state::BrokerLimits::grace_floor`] applied to `latest`. Each in-window
/// version becomes a JWK with a distinct content-derived `kid` (two versions with
/// identical public bytes would collide on `kid` and de-duplicate, which is
/// correct). This is the **single source of truth** the gRPC Workload-API JWKS and
/// the HTTP JWKS both use, so the two surfaces never diverge.
///
/// # Errors
///
/// Returns a [`BackendError`] if a version's public key cannot be parsed into a
/// JWK or the set cannot be serialized.
pub fn jwt_svid_jwks_grace_window(
    versions: &std::collections::BTreeMap<u32, Vec<u8>>,
    latest: u32,
    grace_floor: u32,
    alg: SvidAlg,
) -> Result<Vec<u8>, BackendError> {
    let mut keys: Vec<Value> = Vec::new();
    let mut seen_kids: Vec<String> = Vec::new();
    for (&version, public_key) in versions {
        // Only versions inside the grace window are published; older ones are
        // dropped so a token keyed to a pre-floor version no longer resolves.
        if version < grace_floor || version > latest {
            continue;
        }
        let kid = jwt_svid_jwk_kid(public_key, alg);
        if seen_kids.iter().any(|k| k == &kid) {
            continue;
        }
        seen_kids.push(kid);
        keys.push(jwk_for_public_key(public_key, alg)?);
    }
    serde_json::to_vec(&json!({ "keys": keys }))
        .map_err(|e| BackendError::Protocol(format!("serializing jwks: {e}")))
}

/// Build a single JWK [`Value`] (not a set) for one issuer public key + `alg`.
/// Shared by the single-key and grace-window generators so the JWK shape
/// (`kty`/`crv`/`n`/`e`/`use`/`alg`/`kid`) is defined in exactly one place.
fn jwk_for_public_key(public_key: &[u8], alg: SvidAlg) -> Result<Value, BackendError> {
    let kid = jwt_svid_jwk_kid(public_key, alg);
    match alg {
        SvidAlg::EdDsa => {
            if public_key.len() != 32 {
                return Err(BackendError::Protocol(format!(
                    "Ed25519 JWT issuer public key must be 32 bytes, got {}",
                    public_key.len()
                )));
            }
            Ok(json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(public_key),
                "use": "sig",
                "alg": alg.header_alg(),
                "kid": kid,
            }))
        }
        SvidAlg::Rs256 => {
            let key = decode_rsa_public_key(public_key)?;
            Ok(json!({
                "kty": "RSA",
                "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
                "use": "sig",
                "alg": alg.header_alg(),
                "kid": kid,
            }))
        }
        SvidAlg::Es256 => {
            let key = decode_p256_public_key(public_key)?;
            let encoded = key.to_encoded_point(false);
            let x = encoded.x().ok_or_else(|| {
                BackendError::Protocol("P-256 public key has no x coordinate".into())
            })?;
            let y = encoded.y().ok_or_else(|| {
                BackendError::Protocol("P-256 public key has no y coordinate".into())
            })?;
            Ok(json!({
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
                "use": "sig",
                "alg": alg.header_alg(),
                "kid": kid,
            }))
        }
        SvidAlg::Es384 => {
            let key = decode_p384_public_key(public_key)?;
            let encoded = key.to_encoded_point(false);
            let x = encoded.x().ok_or_else(|| {
                BackendError::Protocol("P-384 public key has no x coordinate".into())
            })?;
            let y = encoded.y().ok_or_else(|| {
                BackendError::Protocol("P-384 public key has no y coordinate".into())
            })?;
            Ok(json!({
                "kty": "EC",
                "crv": "P-384",
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
                "use": "sig",
                "alg": alg.header_alg(),
                "kid": kid,
            }))
        }
    }
}

/// Deterministic key id for a JWT-SVID issuer public key.
#[must_use]
pub fn jwt_svid_jwk_kid(public_key: &[u8], alg: SvidAlg) -> String {
    let mut hasher = Sha256::new();
    hasher.update(alg.header_alg().as_bytes());
    hasher.update([0]);
    hasher.update(public_key);
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn decode_rsa_public_key(public_key: &[u8]) -> Result<rsa::RsaPublicKey, BackendError> {
    if let Ok(pem) = std::str::from_utf8(public_key)
        && pem.trim_start().starts_with("-----BEGIN ")
    {
        return rsa::RsaPublicKey::from_public_key_pem(pem)
            .or_else(|_| rsa::RsaPublicKey::from_pkcs1_pem(pem))
            .map_err(|e| BackendError::Protocol(format!("RSA public key PEM is malformed: {e}")));
    }

    rsa::RsaPublicKey::from_public_key_der(public_key)
        .or_else(|_| rsa::RsaPublicKey::from_pkcs1_der(public_key))
        .map_err(|e| BackendError::Protocol(format!("RSA public key DER is malformed: {e}")))
}

fn decode_p256_public_key(public_key: &[u8]) -> Result<p256::PublicKey, BackendError> {
    if let Ok(pem) = std::str::from_utf8(public_key)
        && pem.trim_start().starts_with("-----BEGIN ")
    {
        return p256::PublicKey::from_public_key_pem(pem).map_err(|e| {
            BackendError::Protocol(format!("P-256 public key PEM is malformed: {e}"))
        });
    }

    p256::PublicKey::from_public_key_der(public_key)
        .map_err(|e| BackendError::Protocol(format!("P-256 public key DER is malformed: {e}")))
}

fn decode_p384_public_key(public_key: &[u8]) -> Result<p384::PublicKey, BackendError> {
    if let Ok(pem) = std::str::from_utf8(public_key)
        && pem.trim_start().starts_with("-----BEGIN ")
    {
        return p384::PublicKey::from_public_key_pem(pem).map_err(|e| {
            BackendError::Protocol(format!("P-384 public key PEM is malformed: {e}"))
        });
    }

    p384::PublicKey::from_public_key_der(public_key)
        .map_err(|e| BackendError::Protocol(format!("P-384 public key DER is malformed: {e}")))
}

/// A reserved-claim collision: the caller tried to set a preset-owned claim.
/// The handler maps this onto the `invalid_request` wire code.
#[derive(Debug)]
pub struct ReservedClaim(pub String);

impl std::fmt::Display for ReservedClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "claims may not override the reserved claim `{}`", self.0)
    }
}
impl std::error::Error for ReservedClaim {}

/// Current UNIX time in seconds.
fn unix_now() -> Result<u64, BackendError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| BackendError::Backend(e.to_string()))?
        .as_secs())
}

/// Mint a NATS user JWT whose issuing account key lives in the backend.
///
/// Steps: derive the issuer `NKey` (`A…`) from the signing key's Ed25519 public
/// half, build the JWT signing input, have the backend sign it, and assemble the
/// token. The seed/private key is never read out.
///
/// `issuer_account` sets the `nats.issuer_account` claim. It is **required** when
/// `signing_key_id` is an account *signing* key rather than the account identity
/// key: without it the minted user names no owning account and `nats-server`
/// rejects the connection with an authorization violation. Pass the owning
/// account's identity public `NKey` (`A…`); leave it `None` when the signing key
/// itself *is* the account identity key. Basil cannot tell the two apart from the
/// key alone, so naming the account is the caller's responsibility.
#[allow(clippy::too_many_arguments)] // distinct scalar claim inputs; bundling them
// into a struct would just move the arity to the call site without clarifying it.
pub async fn mint_nats_user(
    backend: &dyn Backend,
    signing_key_id: &str,
    issuer_role: NkeyType,
    subject_user_nkey: &str,
    issuer_account: Option<&str>,
    name: &str,
    expires_in_secs: Option<u64>,
    permissions: basil_nats::UserPermissions,
) -> Result<String, BackendError> {
    ensure_issuer_role(issuer_role, &[NkeyType::Account], "user")?;
    // The subject must be a well-formed user public NKey.
    basil_nats::require_public_prefix(subject_user_nkey, NkeyType::User)
        .map_err(|e| BackendError::Protocol(format!("invalid subject user nkey: {e}")))?;
    // A supplied issuer account must be a well-formed account public NKey.
    let issuer_account = match issuer_account {
        Some(account) => {
            basil_nats::require_public_prefix(account, NkeyType::Account)
                .map_err(|e| BackendError::Protocol(format!("invalid issuer account nkey: {e}")))?;
            Some(account.to_string())
        }
        None => None,
    };

    // Issuer (`iss`) NKey from the backend signing key's public half.
    let public = backend.public_key(signing_key_id).await?;
    let issuer = basil_nats::encode_public(issuer_role, &public)
        .map_err(|e| BackendError::Protocol(format!("deriving issuer nkey: {e}")))?;

    let now = unix_now()?;

    let jwt = basil_nats::UserJwt {
        issuer,
        issuer_account,
        subject_user: subject_user_nkey.to_string(),
        name: name.to_string(),
        issued_at: now,
        expires: expires_in_secs.map(|s| now.saturating_add(s)),
        permissions,
    };
    let signing_input = jwt
        .signing_input()
        .map_err(|e| BackendError::Protocol(format!("building nats jwt: {e}")))?;

    // The backend performs the Ed25519 signature over the signing input.
    let signature = backend
        .sign(signing_key_id, signing_input.as_bytes())
        .await?;

    Ok(basil_nats::assemble(&signing_input, &signature))
}

/// Mint a NATS **account** JWT whose issuing operator key lives in the backend.
///
/// The issuer (`O…`) `NKey` is derived from the backend key's public half via
/// the `nats_type` prefix letter (`O` for an operator issuer). The subject is
/// the account public `NKey` (`A…`) being signed. The backend signs the signing
/// input; the seed never leaves the vault.
pub async fn mint_nats_account(
    backend: &dyn Backend,
    signing_key_id: &str,
    issuer_role: NkeyType,
    subject_account_nkey: &str,
    name: &str,
    expires_in_secs: Option<u64>,
    signing_keys: Vec<String>,
) -> Result<String, BackendError> {
    ensure_issuer_role(
        issuer_role,
        &[NkeyType::Account, NkeyType::Operator],
        "account",
    )?;
    basil_nats::require_public_prefix(subject_account_nkey, NkeyType::Account)
        .map_err(|e| BackendError::Protocol(format!("invalid subject account nkey: {e}")))?;
    for key in &signing_keys {
        basil_nats::require_public_prefix(key, NkeyType::Account)
            .map_err(|e| BackendError::Protocol(format!("invalid account signing key: {e}")))?;
    }

    let public = backend.public_key(signing_key_id).await?;
    let issuer = basil_nats::encode_public(issuer_role, &public)
        .map_err(|e| BackendError::Protocol(format!("deriving issuer nkey: {e}")))?;

    let now = unix_now()?;
    let jwt = basil_nats::AccountJwt {
        issuer,
        subject_account: subject_account_nkey.to_string(),
        name: name.to_string(),
        issued_at: now,
        expires: expires_in_secs.map(|s| now.saturating_add(s)),
        signing_keys,
        // A minted account JWT must carry a limits block: nats-server treats a
        // zero connection/subscription limit as deny-all, so without this the
        // account rejects every connection. Default to the standard unlimited
        // account (JetStream stays disabled).
        claims: basil_nats::AccountClaims {
            limits: basil_nats::OperatorLimits::unlimited(),
            ..basil_nats::AccountClaims::default()
        },
    };
    let signing_input = jwt
        .signing_input()
        .map_err(|e| BackendError::Protocol(format!("building nats account jwt: {e}")))?;
    let signature = backend
        .sign(signing_key_id, signing_input.as_bytes())
        .await?;
    Ok(basil_nats::assemble(&signing_input, &signature))
}

/// Mint a NATS **operator** JWT (usually self-signed).
///
/// The issuer (`O…`) `NKey` is derived from the backend operator key's public
/// half; the subject defaults to the same operator unless an explicit
/// `subject_operator_nkey` is given. The backend signs in place.
#[allow(clippy::too_many_arguments)] // distinct scalar claim inputs; bundling them
// into a struct would just move the arity to the call site without clarifying it.
pub async fn mint_nats_operator(
    backend: &dyn Backend,
    signing_key_id: &str,
    issuer_role: NkeyType,
    subject_operator_nkey: Option<&str>,
    name: &str,
    expires_in_secs: Option<u64>,
    signing_keys: Vec<String>,
    account_server_url: String,
    system_account: String,
) -> Result<String, BackendError> {
    ensure_issuer_role(issuer_role, &[NkeyType::Operator], "operator")?;
    let public = backend.public_key(signing_key_id).await?;
    let issuer = basil_nats::encode_public(issuer_role, &public)
        .map_err(|e| BackendError::Protocol(format!("deriving issuer nkey: {e}")))?;

    // An explicit subject must be a well-formed public NKey; otherwise the
    // operator self-signs (sub == iss).
    let subject_operator = match subject_operator_nkey {
        Some(s) => {
            basil_nats::require_public_prefix(s, NkeyType::Operator).map_err(|e| {
                BackendError::Protocol(format!("invalid subject operator nkey: {e}"))
            })?;
            s.to_string()
        }
        None => issuer.clone(),
    };
    for key in &signing_keys {
        basil_nats::require_public_prefix(key, NkeyType::Operator)
            .map_err(|e| BackendError::Protocol(format!("invalid operator signing key: {e}")))?;
    }
    if !system_account.is_empty() {
        basil_nats::require_public_prefix(&system_account, NkeyType::Account)
            .map_err(|e| BackendError::Protocol(format!("invalid system account nkey: {e}")))?;
    }

    let now = unix_now()?;
    let jwt = basil_nats::OperatorJwt {
        issuer,
        subject_operator,
        name: name.to_string(),
        issued_at: now,
        expires: expires_in_secs.map(|s| now.saturating_add(s)),
        signing_keys,
        account_server_url,
        system_account,
        claims: basil_nats::OperatorClaims::default(),
    };
    let signing_input = jwt
        .signing_input()
        .map_err(|e| BackendError::Protocol(format!("building nats operator jwt: {e}")))?;
    let signature = backend
        .sign(signing_key_id, signing_input.as_bytes())
        .await?;
    Ok(basil_nats::assemble(&signing_input, &signature))
}

fn ensure_issuer_role(
    issuer: NkeyType,
    allowed: &[NkeyType],
    claim_kind: &'static str,
) -> Result<(), BackendError> {
    if allowed.contains(&issuer) {
        return Ok(());
    }
    let expected = allowed.iter().map(|role| role.letter()).collect::<String>();
    Err(BackendError::Protocol(format!(
        "unsupported issuer role {issuer} for nats {claim_kind}; expected one of {expected}"
    )))
}

async fn mint_nats_role(
    backend: &dyn Backend,
    spec: RoleMintSpec<'_>,
) -> Result<String, BackendError> {
    let RoleMintSpec {
        signing_key_id,
        issuer_role,
        subject_nkey,
        subject_role,
        name,
        expires_in_secs,
        kind,
    } = spec;
    ensure_issuer_role(issuer_role, &[subject_role], kind.as_str())?;
    basil_nats::require_public_prefix(subject_nkey, subject_role).map_err(|e| {
        BackendError::Protocol(format!("invalid subject {} nkey: {e}", kind.as_str()))
    })?;

    let public = backend.public_key(signing_key_id).await?;
    let issuer = basil_nats::encode_public(issuer_role, &public)
        .map_err(|e| BackendError::Protocol(format!("deriving issuer nkey: {e}")))?;
    let now = unix_now()?;
    let jwt = basil_nats::RoleJwt {
        issuer,
        subject: subject_nkey.to_string(),
        name: name.to_string(),
        issued_at: now,
        expires: expires_in_secs.map(|s| now.saturating_add(s)),
        kind,
    };
    let signing_input = jwt
        .signing_input()
        .map_err(|e| BackendError::Protocol(format!("building nats {} jwt: {e}", kind.as_str())))?;
    let signature = backend
        .sign(signing_key_id, signing_input.as_bytes())
        .await?;
    Ok(basil_nats::assemble(&signing_input, &signature))
}

struct RoleMintSpec<'a> {
    signing_key_id: &'a str,
    issuer_role: NkeyType,
    subject_nkey: &'a str,
    subject_role: NkeyType,
    name: &'a str,
    expires_in_secs: Option<u64>,
    kind: RoleKind,
}

pub async fn mint_nats_signer(
    backend: &dyn Backend,
    signing_key_id: &str,
    issuer_role: NkeyType,
    subject_nkey: &str,
    name: &str,
    expires_in_secs: Option<u64>,
) -> Result<String, BackendError> {
    ensure_issuer_role(
        issuer_role,
        &[NkeyType::Account, NkeyType::Operator],
        "signer",
    )?;
    // A signer's subject shares the issuer's role (an account signs an account
    // signing key; an operator signs an operator signing key).
    basil_nats::require_public_prefix(subject_nkey, issuer_role)
        .map_err(|e| BackendError::Protocol(format!("invalid subject signer nkey: {e}")))?;

    let public = backend.public_key(signing_key_id).await?;
    let issuer = basil_nats::encode_public(issuer_role, &public)
        .map_err(|e| BackendError::Protocol(format!("deriving issuer nkey: {e}")))?;
    let now = unix_now()?;
    let jwt = basil_nats::RoleJwt {
        issuer,
        subject: subject_nkey.to_string(),
        name: name.to_string(),
        issued_at: now,
        expires: expires_in_secs.map(|s| now.saturating_add(s)),
        kind: RoleKind::Signer,
    };
    let signing_input = jwt
        .signing_input()
        .map_err(|e| BackendError::Protocol(format!("building nats signer jwt: {e}")))?;
    let signature = backend
        .sign(signing_key_id, signing_input.as_bytes())
        .await?;
    Ok(basil_nats::assemble(&signing_input, &signature))
}

pub async fn mint_nats_server(
    backend: &dyn Backend,
    signing_key_id: &str,
    issuer_role: NkeyType,
    subject_server_nkey: &str,
    name: &str,
    expires_in_secs: Option<u64>,
) -> Result<String, BackendError> {
    mint_nats_role(
        backend,
        RoleMintSpec {
            signing_key_id,
            issuer_role,
            subject_nkey: subject_server_nkey,
            subject_role: NkeyType::Server,
            name,
            expires_in_secs,
            kind: RoleKind::Server,
        },
    )
    .await
}

pub async fn mint_nats_curve(
    backend: &dyn Backend,
    signing_key_id: &str,
    issuer_role: NkeyType,
    subject_curve_nkey: &str,
    name: &str,
    expires_in_secs: Option<u64>,
) -> Result<String, BackendError> {
    mint_nats_role(
        backend,
        RoleMintSpec {
            signing_key_id,
            issuer_role,
            subject_nkey: subject_curve_nkey,
            subject_role: NkeyType::Curve,
            name,
            expires_in_secs,
            kind: RoleKind::Curve,
        },
    )
    .await
}

/// Validate, normalize, and sign a caller-supplied NATS JWT claim document.
///
/// Basil derives the `iss` `NKey` from the catalog key's public half and
/// `nats_type` label. A supplied `iss` must match; an omitted `iss` is inserted.
/// `sub`, `name`, `iat`, and the `nats` block are validated before the backend
/// signs the NATS `ed25519-nkey` signing input. Missing `iat` defaults to now,
/// and `expires_at` overrides any supplied `exp`.
pub async fn sign_nats_jwt(
    backend: &dyn Backend,
    spec: SignNatsJwtSpec<'_>,
) -> Result<String, BackendError> {
    let SignNatsJwtSpec {
        signing_key_id,
        issuer_role,
        claims,
        expected_kind,
        issued_at,
        expires_at,
        jti_mode,
    } = spec;
    let mut claims = claims
        .as_object()
        .ok_or_else(|| BackendError::Protocol("invalid nats jwt claims: expected object".into()))?
        .clone();

    let public = backend.public_key(signing_key_id).await?;
    let issuer = basil_nats::encode_public(issuer_role, &public)
        .map_err(|e| BackendError::Protocol(format!("deriving issuer nkey: {e}")))?;
    set_or_validate_string(&mut claims, "iss", &issuer)?;

    let now = unix_now()?;
    let iat = match issued_at {
        Some(value) => {
            claims.insert("iat".into(), Value::Number(value.into()));
            value
        }
        None => {
            if let Some(value) = claims.get("iat") {
                claim_u64(value, "iat")?
            } else {
                claims.insert("iat".into(), Value::Number(now.into()));
                now
            }
        }
    };
    let exp = match expires_at {
        Some(value) => {
            claims.insert("exp".into(), Value::Number(value.into()));
            Some(value)
        }
        None => claims
            .get("exp")
            .map(|value| claim_u64(value, "exp"))
            .transpose()?,
    };

    let sub = required_claim_string(&claims, "sub")?.to_string();
    let name = optional_claim_string(&claims, "name")?;
    let aud = optional_claim_string(&claims, "aud")?;
    let nbf = claims
        .get("nbf")
        .map(|value| claim_u64(value, "nbf"))
        .transpose()?;
    let kind = validate_nats_claim(&claims, expected_kind)?;
    validate_nats_roles(issuer_role, kind, &sub)?;

    let computed_jti = basil_nats::jti_for_standard_claims(&issuer, &sub, name, iat, exp, aud, nbf)
        .map_err(|e| BackendError::Protocol(format!("building nats jwt jti: {e}")))?;
    match claims.get("jti") {
        Some(value) if value.as_str() == Some(computed_jti.as_str()) => {}
        Some(_) if jti_mode == NatsJtiMode::Rewrite => {
            claims.insert("jti".into(), Value::String(computed_jti));
        }
        Some(_) => {
            return Err(BackendError::Protocol(
                "invalid nats jwt jti: supplied jti does not match standard claims".into(),
            ));
        }
        None => {
            claims.insert("jti".into(), Value::String(computed_jti));
        }
    }

    let signing_input = basil_nats::signing_input_from_claims(&Value::Object(claims))
        .map_err(|e| BackendError::Protocol(format!("building nats jwt: {e}")))?;
    let signature = backend
        .sign(signing_key_id, signing_input.as_bytes())
        .await?;
    Ok(basil_nats::assemble(&signing_input, &signature))
}

fn set_or_validate_string(
    claims: &mut serde_json::Map<String, Value>,
    field: &'static str,
    expected: &str,
) -> Result<(), BackendError> {
    match claims.get(field) {
        Some(value) if value.as_str() == Some(expected) => Ok(()),
        Some(_) => Err(BackendError::Protocol(format!(
            "invalid nats jwt {field}: does not match signing key"
        ))),
        None => {
            claims.insert(field.into(), Value::String(expected.to_string()));
            Ok(())
        }
    }
}

fn required_claim_string<'a>(
    claims: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<&'a str, BackendError> {
    claims
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| BackendError::Protocol(format!("invalid nats jwt {field}: required string")))
}

fn optional_claim_string<'a>(
    claims: &'a serde_json::Map<String, Value>,
    field: &'static str,
) -> Result<Option<&'a str>, BackendError> {
    let Some(value) = claims.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(|value| (!value.is_empty()).then_some(value))
        .ok_or_else(|| BackendError::Protocol(format!("invalid nats jwt {field}: required string")))
}

fn claim_u64(value: &Value, field: &'static str) -> Result<u64, BackendError> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    Err(BackendError::Protocol(format!(
        "invalid nats jwt {field}: required u64"
    )))
}

fn validate_nats_claim(
    claims: &serde_json::Map<String, Value>,
    expected_kind: Option<NatsJwtKind>,
) -> Result<NatsJwtKind, BackendError> {
    let nats = claims
        .get("nats")
        .and_then(Value::as_object)
        .ok_or_else(|| BackendError::Protocol("invalid nats jwt nats: required object".into()))?;
    let kind = nats
        .get("type")
        .and_then(Value::as_str)
        .and_then(NatsJwtKind::parse)
        .ok_or_else(|| {
            BackendError::Protocol("invalid nats jwt nats.type: unsupported or missing".into())
        })?;
    if let Some(expected) = expected_kind
        && expected != kind
    {
        return Err(BackendError::Protocol(format!(
            "invalid nats jwt nats.type: expected {expected}, got {kind}"
        )));
    }
    let version = nats
        .get("version")
        .ok_or_else(|| BackendError::Protocol("invalid nats jwt nats.version: expected 2".into()))
        .and_then(|value| claim_u64(value, "nats.version"))?;
    if version != 2 {
        return Err(BackendError::Protocol(
            "invalid nats jwt nats.version: expected 2".into(),
        ));
    }
    Ok(kind)
}

fn validate_nats_roles(
    issuer_role: NkeyType,
    kind: NatsJwtKind,
    subject_nkey: &str,
) -> Result<(), BackendError> {
    let allowed_issuers: &[NkeyType] = match kind {
        NatsJwtKind::User => &[NkeyType::Account],
        NatsJwtKind::Account | NatsJwtKind::Signer => &[NkeyType::Account, NkeyType::Operator],
        NatsJwtKind::Operator => &[NkeyType::Operator],
        NatsJwtKind::Server => &[NkeyType::Server],
        NatsJwtKind::Curve => &[NkeyType::Curve],
    };
    ensure_issuer_role(issuer_role, allowed_issuers, kind.as_str())?;

    let subject_role = match kind {
        NatsJwtKind::User => NkeyType::User,
        NatsJwtKind::Account | NatsJwtKind::Signer => NkeyType::Account,
        NatsJwtKind::Operator => NkeyType::Operator,
        NatsJwtKind::Server => NkeyType::Server,
        NatsJwtKind::Curve => NkeyType::Curve,
    };
    let subject_role = if kind == NatsJwtKind::Signer {
        issuer_role
    } else {
        subject_role
    };
    basil_nats::require_public_prefix(subject_nkey, subject_role)
        .map_err(|e| BackendError::Protocol(format!("invalid nats jwt sub: {e}")))?;
    Ok(())
}

/// Build the **generic** JWT signing input (`base64url(header).base64url(claims)`)
/// for the issuer's key type, then have the backend sign it and assemble the
/// compact JWS.
///
/// The preset owns `iss` (the dotted issuer name), `iat`, `exp` (from `ttl`),
/// `jti` (a deterministic, RNG-free `base64url` SHA-512/256 over the standard
/// claims, a stable unique-per-token id), and `sub`. Caller `extra` claims may
/// only add **non-reserved** keys: a collision is a [`ReservedClaim`] error the
/// handler maps to `invalid_request`.
///
/// The JWS `alg` is derived from the issuer key type, matching the JWT-SVID
/// path: Ed25519 issuers produce `EdDSA` tokens; ECDSA P-256 issuers `ES256` and
/// P-384 issuers `ES384`; RSA issuers `RS256`, each with a `kid` matching the
/// JWKS entry for the same public key.
pub async fn mint_generic(
    backend: &dyn Backend,
    signing_key_id: &str,
    issuer_name: &str,
    subject: &str,
    expires_in_secs: Option<u64>,
    extra: &Value,
) -> Result<String, GenericMintError> {
    // Start from the preset-owned standard claims, then merge non-reserved extras.
    let now = unix_now()?;
    let exp = expires_in_secs.map(|s| now.saturating_add(s));

    let mut claims = serde_json::Map::new();
    claims.insert("iss".into(), Value::String(issuer_name.to_string()));
    claims.insert("sub".into(), Value::String(subject.to_string()));
    claims.insert("iat".into(), Value::Number(now.into()));
    if let Some(exp) = exp {
        claims.insert("exp".into(), Value::Number(exp.into()));
    }

    // `jti`: a deterministic, URL-safe SHA-512/256 over the standard claims so
    // far (stable, no RNG dependency, a unique-per-token identifier).
    claims.insert("jti".into(), Value::String(jti_for(&claims)?));

    let public_key = backend.public_key(signing_key_id).await?;
    let alg = jws_alg_for_public_key(&public_key)?;

    // Merge caller extras, then build the signing input and have the backend sign.
    merge_extras(&mut claims, extra, RESERVED_GENERIC_CLAIMS)?;
    sign_jwt_claims(backend, signing_key_id, alg, claims).await
}

/// Mint a SPIFFE **JWT-SVID** (§6, `svid` preset) whose issuer key lives in the
/// backend.
///
/// The seed never leaves the vault: the backend signs the signing input and the
/// raw signature is `base64url`-assembled into the compact JWS.
///
/// The preset owns `iss` (`issuer_id`), `sub` (`subject_spiffe_id`, a validated
/// `spiffe://…` id templated by the handler from the request or the attested
/// caller), `aud` (the **required** SVID audience), `iat`, `exp` (from `ttl`),
/// and `jti`. The `alg` is the issuer's SPIFFE JWT-SVID profile signing
/// algorithm (`RS256` for RSA-2048; `ES256` for ECDSA P-256).
/// `EdDSA`/Ed25519 is not a JWT-SVID profile alg and is rejected at catalog
/// load, so a JWT-SVID issuer never signs with `EdDSA`. Caller `extra` claims
/// may only add **non-reserved**
/// keys (a collision, including `aud`, which the preset consumes, is a
/// [`ReservedClaim`] the handler maps to `invalid_request`).
#[allow(clippy::too_many_arguments)] // distinct preset-owned inputs; bundling them
// into a struct would just move the arity to the call site without clarifying it.
pub async fn mint_svid(
    backend: &dyn Backend,
    signing_key_id: &str,
    issuer_id: &str,
    alg: SvidAlg,
    subject_spiffe_id: &str,
    audience: &str,
    expires_in_secs: Option<u64>,
    extra: &Value,
) -> Result<String, GenericMintError> {
    let now = unix_now()?;
    let exp = expires_in_secs.map(|s| now.saturating_add(s));

    let mut claims = serde_json::Map::new();
    claims.insert("iss".into(), Value::String(issuer_id.to_string()));
    claims.insert("sub".into(), Value::String(subject_spiffe_id.to_string()));
    claims.insert("aud".into(), Value::String(audience.to_string()));
    claims.insert("iat".into(), Value::Number(now.into()));
    if let Some(exp) = exp {
        claims.insert("exp".into(), Value::Number(exp.into()));
    }
    claims.insert("jti".into(), Value::String(jti_for(&claims)?));

    // Caller extras may add non-reserved keys only; `aud` is preset-owned (the
    // handler already lifted it out of `extra`), so a leftover `aud` is rejected.
    merge_extras(&mut claims, extra, RESERVED_SVID_CLAIMS)?;
    sign_jwt_claims(backend, signing_key_id, alg, claims).await
}

/// Merge caller `extra` claims into `claims`, rejecting any key in `reserved`.
///
/// A non-object, non-null `extra` is itself a malformed request (mapped to
/// `invalid_request`).
fn merge_extras(
    claims: &mut serde_json::Map<String, Value>,
    extra: &Value,
    reserved: &[&str],
) -> Result<(), GenericMintError> {
    if let Some(obj) = extra.as_object() {
        for (k, v) in obj {
            if reserved.contains(&k.as_str()) {
                return Err(GenericMintError::Reserved(ReservedClaim(k.clone())));
            }
            claims.insert(k.clone(), v.clone());
        }
        Ok(())
    } else if extra.is_null() {
        Ok(())
    } else {
        Err(GenericMintError::Reserved(ReservedClaim(
            "<claims must be a JSON object>".into(),
        )))
    }
}

/// A deterministic, RNG-free `jti`: `base64url(SHA-512/256(serialized claims))`.
/// Stable and unique-per-token without a random dependency (§6).
fn jti_for(claims: &serde_json::Map<String, Value>) -> Result<String, BackendError> {
    use sha2::{Digest, Sha512_256};
    let bytes = serde_json::to_vec(claims)
        .map_err(|e| BackendError::Protocol(format!("serializing claims: {e}")))?;
    let mut hasher = Sha512_256::new();
    hasher.update(&bytes);
    Ok(URL_SAFE_NO_PAD.encode(hasher.finalize()))
}

fn jws_alg_for_public_key(public_key: &[u8]) -> Result<SvidAlg, BackendError> {
    if public_key.len() == 32 {
        return Ok(SvidAlg::EdDsa);
    }
    // ECDSA curves are probed before RSA: an EC `SubjectPublicKeyInfo` carries the
    // `id-ecPublicKey` algorithm OID, so the RSA decoders reject it (and vice
    // versa). There is no ambiguous key that satisfies both.
    if decode_p256_public_key(public_key).is_ok() {
        return Ok(SvidAlg::Es256);
    }
    if decode_p384_public_key(public_key).is_ok() {
        return Ok(SvidAlg::Es384);
    }
    if decode_rsa_public_key(public_key).is_ok() {
        return Ok(SvidAlg::Rs256);
    }
    Err(BackendError::Protocol(format!(
        "JWT issuer public key must be Ed25519 raw public bytes, ECDSA P-256/P-384 PEM/DER, or RSA PEM/DER, got {} bytes",
        public_key.len()
    )))
}

/// Build the compact-JWS signing input (`base64url(header).base64url(claims)`)
/// for `alg`, have the **backend** sign it, and assemble the token. Shared by
/// [`mint_generic`] and [`mint_svid`]: the only per-preset difference is the
/// header `alg` and the (already-built) claim set.
async fn sign_jwt_claims(
    backend: &dyn Backend,
    signing_key_id: &str,
    alg: SvidAlg,
    claims: serde_json::Map<String, Value>,
) -> Result<String, GenericMintError> {
    // The `kid` header MUST match the published JWKS key id so a SPIFFE verifier
    // (and the SPIFFE JWT-SVID profile, which requires `kid`) can select the
    // signing key. It is deterministic over (alg, public key), the same value
    // `jwt_svid_jwks` publishes for the bundle.
    let public_key = backend.public_key(signing_key_id).await?;
    let kid = jwt_svid_jwk_kid(&public_key, alg);
    let header_bytes = serde_json::to_vec(&json!({
        "typ": "JWT",
        "alg": alg.header_alg(),
        "kid": kid,
    }))
    .map_err(|e| BackendError::Protocol(format!("serializing JWS header: {e}")))?;
    let claims_bytes = serde_json::to_vec(&claims)
        .map_err(|e| BackendError::Protocol(format!("serializing claims: {e}")))?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&header_bytes),
        URL_SAFE_NO_PAD.encode(&claims_bytes)
    );
    let signature = backend
        .sign_with_options(signing_key_id, signing_input.as_bytes(), alg.sign_options())
        .await?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(&signature)
    ))
}

/// The error returned by [`mint_generic`]: either a reserved-claim collision
/// (→ `invalid_request`) or an underlying backend error (mapped per [`backend`]).
///
/// [`backend`]: crate::backend
#[derive(Debug)]
pub enum GenericMintError {
    /// A caller `claims` key collided with a preset-owned reserved claim.
    Reserved(ReservedClaim),
    /// A backend/serialization failure while building or signing the token.
    Backend(BackendError),
}

impl std::fmt::Display for GenericMintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reserved(e) => write!(f, "{e}"),
            Self::Backend(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for GenericMintError {}
impl From<BackendError> for GenericMintError {
    fn from(e: BackendError) -> Self {
        Self::Backend(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use nkeys::KeyPair;

    use crate::backend::NewKey;
    use basil_proto::KeyType;

    /// A signing backend backed by a real `nkeys::KeyPair`, so the minters
    /// produce signatures that verify under the issuer `NKey` (exactly what a
    /// NATS server checks). Only the methods the minters call are implemented.
    struct KeyPairBackend(KeyPair);

    #[async_trait]
    impl Backend for KeyPairBackend {
        fn kind(&self) -> &'static str {
            "nkey-test"
        }
        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }
        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            // The raw 32-byte Ed25519 public half from the keypair's NKey.
            let (_, raw) = basil_nats::decode_public(&self.0.public_key())
                .map_err(|e| BackendError::Protocol(e.to_string()))?;
            Ok(raw.to_vec())
        }
        async fn sign(&self, _key_id: &str, message: &[u8]) -> Result<Vec<u8>, BackendError> {
            self.0
                .sign(message)
                .map_err(|e| BackendError::Backend(e.to_string()))
        }
        async fn verify(
            &self,
            _key_id: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, BackendError> {
            Ok(self.0.verify(message, signature).is_ok())
        }
    }

    /// Split a compact JWT, returning `(header_json, claims_json, signing_input,
    /// signature_bytes)`.
    fn parse_token(token: &str) -> (Value, Value, String, Vec<u8>) {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "compact JWS has 3 parts");
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        (header, claims, signing_input, sig)
    }

    /// Distinct `kid`s in a JWKS body (in published order).
    fn jwks_kids(body: &[u8]) -> Vec<String> {
        let parsed: Value = serde_json::from_slice(body).expect("jwks json");
        parsed["keys"]
            .as_array()
            .expect("keys array")
            .iter()
            .filter_map(|k| k["kid"].as_str().map(str::to_string))
            .collect()
    }

    /// A distinct 32-byte Ed25519 public key per `seed` (the JWK shape only needs
    /// 32 bytes; `EdDsa`'s JWK builder accepts any 32-byte value). Two calls with
    /// the same `seed` produce byte-identical keys (for the dedup boundary test).
    fn ed_public(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    // ---- grace-window boundary fn (direct unit coverage) --------------------

    #[test]
    fn grace_window_includes_floor_and_latest_excludes_outside() {
        // versions 1..=4 with distinct public keys; window is [2 ..= 3].
        let versions = std::collections::BTreeMap::from([
            (1u32, ed_public(1)),
            (2, ed_public(2)),
            (3, ed_public(3)),
            (4, ed_public(4)),
        ]);
        let body = jwt_svid_jwks_grace_window(&versions, 3, 2, SvidAlg::EdDsa).expect("jwks");
        let kids = jwks_kids(&body);
        // v1 (< floor) and v4 (> latest) are excluded; v2 (== floor) and v3
        // (== latest) are included.
        assert_eq!(kids.len(), 2, "only the in-window versions: {kids:?}");
        assert!(kids.contains(&jwt_svid_jwk_kid(&ed_public(2), SvidAlg::EdDsa)));
        assert!(kids.contains(&jwt_svid_jwk_kid(&ed_public(3), SvidAlg::EdDsa)));
        assert!(!kids.contains(&jwt_svid_jwk_kid(&ed_public(1), SvidAlg::EdDsa)));
        assert!(!kids.contains(&jwt_svid_jwk_kid(&ed_public(4), SvidAlg::EdDsa)));
    }

    #[test]
    fn grace_window_floor_equals_latest_yields_single_key() {
        let versions = std::collections::BTreeMap::from([
            (1u32, ed_public(1)),
            (2, ed_public(2)),
            (3, ed_public(3)),
        ]);
        // floor == latest == 3 -> only v3.
        let body = jwt_svid_jwks_grace_window(&versions, 3, 3, SvidAlg::EdDsa).expect("jwks");
        let kids = jwks_kids(&body);
        assert_eq!(kids, vec![jwt_svid_jwk_kid(&ed_public(3), SvidAlg::EdDsa)]);
    }

    #[test]
    fn grace_window_empty_version_map_yields_empty_set_no_panic() {
        let versions: std::collections::BTreeMap<u32, Vec<u8>> = std::collections::BTreeMap::new();
        let body = jwt_svid_jwks_grace_window(&versions, 1, 1, SvidAlg::EdDsa).expect("jwks");
        assert!(jwks_kids(&body).is_empty(), "no versions -> empty key set");
    }

    #[test]
    fn grace_window_floor_zero_publishes_every_version_up_to_latest() {
        // grace_floor == 0: every version is `>= 0`, so all versions up to `latest`
        // are published (the documented `[grace_floor ..= latest]` window with a
        // floor at the bottom of the range). v4 is still excluded (> latest).
        let versions = std::collections::BTreeMap::from([
            (1u32, ed_public(1)),
            (2, ed_public(2)),
            (3, ed_public(3)),
            (4, ed_public(4)),
        ]);
        let body = jwt_svid_jwks_grace_window(&versions, 3, 0, SvidAlg::EdDsa).expect("jwks");
        let kids = jwks_kids(&body);
        assert_eq!(kids.len(), 3, "floor 0 -> v1..=v3, v4 excluded: {kids:?}");
        assert!(!kids.contains(&jwt_svid_jwk_kid(&ed_public(4), SvidAlg::EdDsa)));
    }

    #[test]
    fn grace_window_dedups_identical_public_keys_by_kid() {
        // Two in-window versions with IDENTICAL public bytes collide on the
        // content-derived kid and de-duplicate to ONE JWK.
        let shared = ed_public(7);
        let versions =
            std::collections::BTreeMap::from([(1u32, shared.clone()), (2, shared.clone())]);
        let body = jwt_svid_jwks_grace_window(&versions, 2, 1, SvidAlg::EdDsa).expect("jwks");
        let kids = jwks_kids(&body);
        assert_eq!(
            kids,
            vec![jwt_svid_jwk_kid(&shared, SvidAlg::EdDsa)],
            "identical public bytes dedup to one kid"
        );
    }

    #[tokio::test]
    async fn jwt_svid_jwks_publishes_eddsa_issuer_key() {
        let kp = KeyPair::new_account();
        let backend = KeyPairBackend(KeyPair::from_seed(&kp.seed().unwrap()).unwrap());

        let bytes = jwt_svid_jwks(&backend, "issuer-key", SvidAlg::EdDsa)
            .await
            .expect("jwks");
        let jwks: Value = serde_json::from_slice(&bytes).expect("jwks json");
        let key = jwks["keys"].as_array().unwrap().first().unwrap();

        let (_, raw_public) = basil_nats::decode_public(&kp.public_key()).expect("public key");
        assert_eq!(key["kty"], "OKP");
        assert_eq!(key["crv"], "Ed25519");
        assert_eq!(key["alg"], "EdDSA");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["x"], URL_SAFE_NO_PAD.encode(raw_public.as_slice()));
        assert_eq!(key["kid"], jwt_svid_jwk_kid(&raw_public, SvidAlg::EdDsa));
    }

    #[test]
    fn jwt_svid_jwks_publishes_rs256_issuer_key() {
        use rsa::pkcs8::EncodePublicKey;

        let mut rng = rand::thread_rng();
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let public = rsa::RsaPublicKey::from(&private);
        let public_der = public.to_public_key_der().expect("public der");

        let bytes =
            jwt_svid_jwks_from_public_key(public_der.as_bytes(), SvidAlg::Rs256).expect("jwks");
        let jwks: Value = serde_json::from_slice(&bytes).expect("jwks json");
        let key = jwks["keys"].as_array().unwrap().first().unwrap();

        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["alg"], "RS256");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["n"], URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()));
        assert_eq!(key["e"], URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()));
        assert_eq!(
            key["kid"],
            jwt_svid_jwk_kid(public_der.as_bytes(), SvidAlg::Rs256)
        );
    }

    #[test]
    fn jwt_svid_jwks_publishes_es256_issuer_key() {
        use p256::pkcs8::EncodePublicKey as _;

        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let public = signing_key.verifying_key();
        let public_der = public.to_public_key_der().expect("public der");
        let encoded = public.to_encoded_point(false);
        let x = encoded.x().expect("x coordinate");
        let y = encoded.y().expect("y coordinate");

        let bytes =
            jwt_svid_jwks_from_public_key(public_der.as_bytes(), SvidAlg::Es256).expect("jwks");
        let jwks: Value = serde_json::from_slice(&bytes).expect("jwks json");
        let key = jwks["keys"].as_array().unwrap().first().unwrap();

        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-256");
        assert_eq!(key["alg"], "ES256");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["x"], URL_SAFE_NO_PAD.encode(x));
        assert_eq!(key["y"], URL_SAFE_NO_PAD.encode(y));
        assert_eq!(
            key["kid"],
            jwt_svid_jwk_kid(public_der.as_bytes(), SvidAlg::Es256)
        );
    }

    #[test]
    fn jwt_svid_jwks_publishes_es384_issuer_key() {
        use p384::pkcs8::EncodePublicKey as _;

        let signing_key = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let public = signing_key.verifying_key();
        let public_der = public.to_public_key_der().expect("public der");
        let encoded = public.to_encoded_point(false);
        let x = encoded.x().expect("x coordinate");
        let y = encoded.y().expect("y coordinate");

        let bytes =
            jwt_svid_jwks_from_public_key(public_der.as_bytes(), SvidAlg::Es384).expect("jwks");
        let jwks: Value = serde_json::from_slice(&bytes).expect("jwks json");
        let key = jwks["keys"].as_array().unwrap().first().unwrap();

        assert_eq!(key["kty"], "EC");
        assert_eq!(key["crv"], "P-384");
        assert_eq!(key["alg"], "ES384");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["x"], URL_SAFE_NO_PAD.encode(x));
        assert_eq!(key["y"], URL_SAFE_NO_PAD.encode(y));
        assert_eq!(
            key["kid"],
            jwt_svid_jwk_kid(public_der.as_bytes(), SvidAlg::Es384)
        );
    }

    #[tokio::test]
    async fn generic_mint_round_trips_and_verifies_under_issuer_key() {
        let kp = KeyPair::new_account();
        let backend = KeyPairBackend(KeyPair::from_seed(&kp.seed().unwrap()).unwrap());

        let token = mint_generic(
            &backend,
            "issuer-key",
            "spire.issuer",
            "spiffe://example/sa/web",
            Some(60),
            &serde_json::json!({ "aud": "api", "role": "reader" }),
        )
        .await
        .expect("mint");

        let (header, claims, signing_input, sig) = parse_token(&token);
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(claims["iss"], "spire.issuer");
        assert_eq!(claims["sub"], "spiffe://example/sa/web");
        assert_eq!(claims["aud"], "api");
        assert_eq!(claims["role"], "reader");
        assert!(claims["exp"].is_number());
        assert!(claims["jti"].is_string());
        // The signature verifies under the issuer's Ed25519 key.
        kp.verify(signing_input.as_bytes(), &sig)
            .expect("signature verifies");
    }

    #[tokio::test]
    async fn generic_mint_rs256_derives_alg_and_verifies_under_issuer_key() {
        let (backend, public_der, public_pem) = rsa_backend();

        let token = mint_generic(
            &backend,
            "rsa-issuer",
            "spire.issuer",
            "spiffe://example.org/api",
            Some(120),
            &serde_json::json!({ "aud": "api" }),
        )
        .await
        .expect("mint generic rs256");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let (header, claims, _signing_input, _sig) = parse_token(&token);
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], jwt_svid_jwk_kid(&public_der, SvidAlg::Rs256));
        assert_eq!(claims["iss"], "spire.issuer");
        assert_eq!(claims["sub"], "spiffe://example.org/api");
        assert_eq!(claims["aud"], "api");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let decoding_key =
            jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes()).expect("decoding key");
        let valid = jsonwebtoken::crypto::verify(
            parts[2],
            signing_input.as_bytes(),
            &decoding_key,
            jsonwebtoken::Algorithm::RS256,
        )
        .expect("verify");
        assert!(valid, "generic RS256 signature verifies under issuer key");
    }

    #[tokio::test]
    async fn generic_mint_es256_derives_alg_and_verifies_under_issuer_key() {
        let backend = p256_backend();

        let token = mint_generic(
            &backend,
            "ecdsa-issuer",
            "spire.issuer",
            "spiffe://example.org/api",
            Some(120),
            &serde_json::json!({ "aud": "api" }),
        )
        .await
        .expect("mint generic es256");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let (header, claims, _signing_input, sig) = parse_token(&token);
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(
            header["kid"],
            jwt_svid_jwk_kid(&backend.public_der, SvidAlg::Es256),
            "generic JWS kid matches the published JWKS key id"
        );
        assert_eq!(claims["iss"], "spire.issuer");
        assert_eq!(claims["sub"], "spiffe://example.org/api");
        assert_eq!(claims["aud"], "api");
        assert_eq!(sig.len(), 64, "ES256 signatures are raw fixed r||s");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let decoding_key = jsonwebtoken::DecodingKey::from_ec_pem(backend.public_pem.as_bytes())
            .expect("decoding key");
        let valid = jsonwebtoken::crypto::verify(
            parts[2],
            signing_input.as_bytes(),
            &decoding_key,
            jsonwebtoken::Algorithm::ES256,
        )
        .expect("verify");
        assert!(valid, "generic ES256 signature verifies under issuer key");
    }

    #[tokio::test]
    async fn generic_mint_es384_derives_alg_and_verifies_under_issuer_key() {
        let backend = p384_backend();

        let token = mint_generic(
            &backend,
            "ecdsa384-issuer",
            "spire.issuer",
            "spiffe://example.org/api",
            Some(120),
            &serde_json::Value::Null,
        )
        .await
        .expect("mint generic es384");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let (header, _claims, _signing_input, sig) = parse_token(&token);
        assert_eq!(header["alg"], "ES384");
        assert_eq!(
            header["kid"],
            jwt_svid_jwk_kid(&backend.public_der, SvidAlg::Es384)
        );
        assert_eq!(sig.len(), 96, "ES384 signatures are raw fixed r||s");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let decoding_key = jsonwebtoken::DecodingKey::from_ec_pem(backend.public_pem.as_bytes())
            .expect("decoding key");
        let valid = jsonwebtoken::crypto::verify(
            parts[2],
            signing_input.as_bytes(),
            &decoding_key,
            jsonwebtoken::Algorithm::ES384,
        )
        .expect("verify");
        assert!(valid, "generic ES384 signature verifies under issuer key");
    }

    #[tokio::test]
    async fn generic_mint_rejects_reserved_claim() {
        let backend = KeyPairBackend(KeyPair::new_account());
        for reserved in ["iss", "iat", "exp", "jti", "sub", "nbf"] {
            let err = mint_generic(
                &backend,
                "p",
                "issuer",
                "sub",
                None,
                &serde_json::json!({ reserved: "x" }),
            )
            .await
            .expect_err("reserved claim rejected");
            assert!(
                // ubs false positive: test
                /* ubs:ignore */
                matches!(err, GenericMintError::Reserved(ReservedClaim(k)) if k == reserved),
                "expected reserved {reserved}"
            );
        }
    }

    #[tokio::test]
    async fn generic_mint_without_ttl_omits_exp() {
        let backend = KeyPairBackend(KeyPair::new_account());
        let token = mint_generic(
            &backend,
            "p",
            "issuer",
            "sub",
            None,
            &serde_json::Value::Null,
        )
        .await
        .expect("mint");
        let (_, claims, _, _) = parse_token(&token);
        assert!(claims.get("exp").is_none(), "no ttl => no exp claim");
    }

    #[tokio::test]
    async fn account_mint_iss_is_operator_nkey_and_verifies() {
        // Issuer is an operator key; the Operator role derives an O… iss.
        let operator = KeyPair::new_operator();
        let backend = KeyPairBackend(KeyPair::from_seed(&operator.seed().unwrap()).unwrap());
        let account = KeyPair::new_account();

        let token = mint_nats_account(
            &backend,
            "operator-key",
            NkeyType::Operator,
            &account.public_key(),
            "acme",
            Some(3600),
            vec![KeyPair::new_account().public_key()],
        )
        .await
        .expect("mint");

        let (_, claims, signing_input, sig) = parse_token(&token);
        assert_eq!(claims["nats"]["type"], "account");
        assert_eq!(claims["sub"], account.public_key());
        assert!(claims["iss"].as_str().unwrap().starts_with('O'));
        operator
            .verify(signing_input.as_bytes(), &sig)
            .expect("verifies under operator key");
    }

    #[tokio::test]
    async fn user_mint_sets_issuer_account_for_signing_key() {
        // The backend key stands in for an account *signing* key: its public half
        // becomes `iss`, while the caller-supplied account identity becomes
        // `nats.issuer_account` so nats-server can bind the user to its account.
        let signing = KeyPair::new_account();
        let backend = KeyPairBackend(KeyPair::from_seed(&signing.seed().unwrap()).unwrap());
        let account_identity = KeyPair::new_account();
        let user = KeyPair::new_user();

        let token = mint_nats_user(
            &backend,
            "account-signing-key",
            NkeyType::Account,
            &user.public_key(),
            Some(&account_identity.public_key()),
            "svc-user",
            Some(3600),
            basil_nats::UserPermissions::default(),
        )
        .await
        .expect("mint user");

        let (_, claims, signing_input, sig) = parse_token(&token);
        assert_eq!(claims["nats"]["type"], "user");
        assert_eq!(
            claims["iss"],
            signing.public_key(),
            "iss is the signing key"
        );
        assert_eq!(
            claims["nats"]["issuer_account"],
            account_identity.public_key(),
            "issuer_account names the owning account identity"
        );
        signing
            .verify(signing_input.as_bytes(), &sig)
            .expect("verifies under the signing key");
    }

    #[tokio::test]
    async fn user_mint_without_issuer_account_omits_the_claim() {
        let account = KeyPair::new_account();
        let backend = KeyPairBackend(KeyPair::from_seed(&account.seed().unwrap()).unwrap());
        let user = KeyPair::new_user();

        let token = mint_nats_user(
            &backend,
            "account-key",
            NkeyType::Account,
            &user.public_key(),
            None,
            "svc-user",
            None,
            basil_nats::UserPermissions::default(),
        )
        .await
        .expect("mint user");

        let (_, claims, _, _) = parse_token(&token);
        assert_eq!(claims["iss"], account.public_key());
        assert!(
            claims["nats"].get("issuer_account").is_none(),
            "no issuer_account claim when the account identity key signs"
        );
    }

    #[tokio::test]
    async fn user_mint_rejects_malformed_issuer_account() {
        let backend = KeyPairBackend(KeyPair::new_account());
        let user = KeyPair::new_user();
        let err = mint_nats_user(
            &backend,
            "account-key",
            NkeyType::Account,
            &user.public_key(),
            Some("not-an-account-nkey"),
            "svc-user",
            None,
            basil_nats::UserPermissions::default(),
        )
        .await
        .expect_err("malformed issuer account rejected");
        assert!(matches!(err, BackendError::Protocol(_)));
    }

    #[tokio::test]
    async fn sign_nats_jwt_derives_issuer_jti_and_verifies() {
        let account = KeyPair::new_account();
        let backend = KeyPairBackend(KeyPair::from_seed(&account.seed().unwrap()).unwrap());
        let user = KeyPair::new_user();
        let token = sign_nats_jwt(
            &backend,
            SignNatsJwtSpec {
                signing_key_id: "account-key",
                issuer_role: NkeyType::Account,
                claims: &serde_json::json!({
                    "sub": user.public_key(),
                    "name": "rich-user",
                    "nats": { "type": "user", "version": 2 }
                }),
                expected_kind: Some(NatsJwtKind::User),
                issued_at: Some(1_700_000_000),
                expires_at: Some(1_700_003_600),
                jti_mode: NatsJtiMode::RequireValid,
            },
        )
        .await
        .expect("sign nats jwt");

        let (header, claims, signing_input, sig) = parse_token(&token);
        assert_eq!(header["alg"], "ed25519-nkey");
        assert_eq!(claims["iss"], account.public_key());
        assert_eq!(claims["sub"], user.public_key());
        assert_eq!(claims["iat"], 1_700_000_000);
        assert_eq!(claims["exp"], 1_700_003_600);
        assert_eq!(claims["nats"]["type"], "user");
        assert!(claims["jti"].as_str().is_some_and(|jti| !jti.is_empty()));
        account
            .verify(signing_input.as_bytes(), &sig)
            .expect("verifies under account key");
    }

    #[tokio::test]
    async fn sign_nats_jwt_allows_missing_name() {
        let account = KeyPair::new_account();
        let backend = KeyPairBackend(KeyPair::from_seed(&account.seed().unwrap()).unwrap());
        let user = KeyPair::new_user();
        let token = sign_nats_jwt(
            &backend,
            SignNatsJwtSpec {
                signing_key_id: "account-key",
                issuer_role: NkeyType::Account,
                claims: &serde_json::json!({
                    "sub": user.public_key(),
                    "nats": { "type": "user", "version": 2 }
                }),
                expected_kind: Some(NatsJwtKind::User),
                issued_at: Some(1_700_000_000),
                expires_at: None,
                jti_mode: NatsJtiMode::RequireValid,
            },
        )
        .await
        .expect("sign nats jwt without name");

        let (_, claims, _, _) = parse_token(&token);
        assert!(claims.get("name").is_none());
        assert!(claims["jti"].as_str().is_some_and(|jti| !jti.is_empty()));
    }

    #[tokio::test]
    async fn sign_nats_jwt_accepts_jti_with_aud_and_nbf() {
        let account = KeyPair::new_account();
        let backend = KeyPairBackend(KeyPair::from_seed(&account.seed().unwrap()).unwrap());
        let user = KeyPair::new_user();
        let issuer = account.public_key();
        let subject = user.public_key();
        let jti = basil_nats::jti_for_standard_claims(
            &issuer,
            &subject,
            Some("rich-user"),
            1_700_000_000,
            Some(1_700_003_600),
            Some("orders"),
            Some(1_699_999_900),
        )
        .expect("computed jti");
        let token = sign_nats_jwt(
            &backend,
            SignNatsJwtSpec {
                signing_key_id: "account-key",
                issuer_role: NkeyType::Account,
                claims: &serde_json::json!({
                    "aud": "orders",
                    "exp": 1_700_003_600_u64,
                    "iat": 1_700_000_000_u64,
                    "iss": issuer.clone(),
                    "jti": jti.clone(),
                    "name": "rich-user",
                    "nbf": 1_699_999_900_u64,
                    "sub": subject.clone(),
                    "nats": { "type": "user", "version": 2 }
                }),
                expected_kind: Some(NatsJwtKind::User),
                issued_at: None,
                expires_at: None,
                jti_mode: NatsJtiMode::RequireValid,
            },
        )
        .await
        .expect("sign nats jwt with standard claims");

        let (_, claims, _, _) = parse_token(&token);
        assert_eq!(claims["jti"], jti);
        assert_eq!(claims["aud"], "orders");
        assert_eq!(claims["nbf"], 1_699_999_900_u64);
    }

    #[tokio::test]
    async fn sign_nats_jwt_rejects_mismatched_issuer() {
        let backend = KeyPairBackend(KeyPair::new_account());
        let user = KeyPair::new_user();
        let err = sign_nats_jwt(
            &backend,
            SignNatsJwtSpec {
                signing_key_id: "account-key",
                issuer_role: NkeyType::Account,
                claims: &serde_json::json!({
                    "iss": KeyPair::new_account().public_key(),
                    "sub": user.public_key(),
                    "name": "bad-iss",
                    "nats": { "type": "user", "version": 2 }
                }),
                expected_kind: Some(NatsJwtKind::User),
                issued_at: None,
                expires_at: None,
                jti_mode: NatsJtiMode::RequireValid,
            },
        )
        .await
        .expect_err("mismatched issuer rejects");
        assert!(matches!(
            err,
            BackendError::Protocol(message)
                if message.starts_with("invalid nats jwt iss")
        ));
    }

    #[tokio::test]
    async fn account_mint_rejects_bad_subject_nkey() {
        let backend = KeyPairBackend(KeyPair::new_operator());
        let err = mint_nats_account(
            &backend,
            "p",
            NkeyType::Operator,
            "not-an-nkey",
            "n",
            None,
            vec![],
        )
        .await
        .expect_err("bad subject");
        assert!(matches!(err, BackendError::Protocol(_)));
    }

    #[tokio::test]
    async fn account_mint_rejects_disallowed_issuer_role() {
        // The role is type-safe now, but a valid role that is not allowed to
        // issue accounts (only Account/Operator may) is a clean Protocol error.
        let backend = KeyPairBackend(KeyPair::new_user());
        let subject = KeyPair::new_account().public_key();
        let err = mint_nats_account(&backend, "p", NkeyType::User, &subject, "n", None, vec![])
            .await
            .expect_err("disallowed issuer role");
        assert!(matches!(err, BackendError::Protocol(_)));
    }

    #[tokio::test]
    async fn operator_mint_self_signs_and_verifies() {
        let operator = KeyPair::new_operator();
        let backend = KeyPairBackend(KeyPair::from_seed(&operator.seed().unwrap()).unwrap());

        let token = mint_nats_operator(
            &backend,
            "operator-key",
            NkeyType::Operator,
            None, // self-signed: sub == iss
            "root-op",
            None,
            vec![],
            "nats://localhost:4222".into(),
            KeyPair::new_account().public_key(),
        )
        .await
        .expect("mint");

        let (_, claims, signing_input, sig) = parse_token(&token);
        assert_eq!(claims["nats"]["type"], "operator");
        let iss = claims["iss"].as_str().unwrap();
        assert!(iss.starts_with('O'));
        assert_eq!(claims["sub"], iss, "self-signed: sub == iss");
        assert_eq!(
            claims["nats"]["account_server_url"],
            "nats://localhost:4222"
        );
        assert!(claims.get("exp").is_none(), "no ttl => no exp");
        operator
            .verify(signing_input.as_bytes(), &sig)
            .expect("verifies under operator key");
    }

    #[tokio::test]
    async fn signer_mint_requires_matching_account_or_operator_subject() {
        let account = KeyPair::new_account();
        let backend = KeyPairBackend(KeyPair::from_seed(&account.seed().unwrap()).unwrap());
        let signing = KeyPair::new_account();

        let token = mint_nats_signer(
            &backend,
            "account-key",
            NkeyType::Account,
            &signing.public_key(),
            "account-signer",
            Some(60),
        )
        .await
        .expect("mint");

        let (_, claims, signing_input, sig) = parse_token(&token);
        assert_eq!(claims["nats"]["type"], "signer");
        assert_eq!(claims["sub"], signing.public_key());
        assert!(claims["iss"].as_str().unwrap().starts_with('A'));
        account
            .verify(signing_input.as_bytes(), &sig)
            .expect("verifies under account key");

        let err = mint_nats_signer(
            &backend,
            "account-key",
            NkeyType::Account,
            &KeyPair::new_operator().public_key(),
            "wrong-signer",
            None,
        )
        .await
        .expect_err("wrong subject role");
        assert!(matches!(err, BackendError::Protocol(_)));
    }

    #[tokio::test]
    async fn server_and_curve_mints_verify_expected_prefixes() {
        let server = KeyPair::new_server();
        let server_backend = KeyPairBackend(KeyPair::from_seed(&server.seed().unwrap()).unwrap());

        let server_token = mint_nats_server(
            &server_backend,
            "server-key",
            NkeyType::Server,
            &server.public_key(),
            "nats-server",
            None,
        )
        .await
        .expect("server mint");
        let (_, claims, signing_input, sig) = parse_token(&server_token);
        assert_eq!(claims["nats"]["type"], "server");
        assert!(claims["iss"].as_str().unwrap().starts_with('N'));
        assert!(claims["sub"].as_str().unwrap().starts_with('N'));
        server
            .verify(signing_input.as_bytes(), &sig)
            .expect("verifies under server key");

        let curve_source = KeyPair::new_account();
        let curve_backend =
            KeyPairBackend(KeyPair::from_seed(&curve_source.seed().unwrap()).unwrap());
        let (_, raw_curve) = basil_nats::decode_public(&curve_source.public_key())
            .expect("curve source public decodes");
        let curve_public =
            basil_nats::encode_public(NkeyType::Curve, &raw_curve).expect("curve nkey encodes");
        let curve_token = mint_nats_curve(
            &curve_backend,
            "curve-key",
            NkeyType::Curve,
            &curve_public,
            "curve-key",
            None,
        )
        .await
        .expect("curve mint");
        let (_, claims, signing_input, sig) = parse_token(&curve_token);
        assert_eq!(claims["nats"]["type"], "curve");
        assert!(claims["iss"].as_str().unwrap().starts_with('X'));
        assert!(claims["sub"].as_str().unwrap().starts_with('X'));
        curve_source
            .verify(signing_input.as_bytes(), &sig)
            .expect("verifies under encoded curve issuer bytes");
    }

    #[tokio::test]
    async fn unsupported_issuer_role_is_protocol_error() {
        let backend = KeyPairBackend(KeyPair::new_operator());
        let server = KeyPair::new_server();
        let err = mint_nats_server(
            &backend,
            "operator-key",
            NkeyType::Operator,
            &server.public_key(),
            "n",
            None,
        )
        .await
        .expect_err("operator cannot mint server role");
        assert!(matches!(
            err,
            BackendError::Protocol(message) if message.starts_with("unsupported issuer role")
        ));
    }

    // ---- svid preset (vault-d0z) --------------------------------------------

    #[tokio::test]
    async fn svid_eddsa_mints_a_verifiable_jwt_svid() {
        let kp = KeyPair::new_account();
        let backend = KeyPairBackend(KeyPair::from_seed(&kp.seed().unwrap()).unwrap());

        let token = mint_svid(
            &backend,
            "issuer-key",
            "spire.svid_issuer",
            SvidAlg::EdDsa,
            "spiffe://example.org/web-01",
            "vault",
            Some(300),
            &serde_json::json!({ "role": "ingest" }),
        )
        .await
        .expect("mint svid");

        let (header, claims, signing_input, sig) = parse_token(&token);
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(claims["iss"], "spire.svid_issuer");
        assert_eq!(claims["sub"], "spiffe://example.org/web-01");
        assert_eq!(claims["aud"], "vault", "aud is required + preset-owned");
        assert!(claims["iat"].is_number());
        assert!(claims["exp"].is_number());
        assert!(claims["jti"].is_string());
        assert_eq!(claims["role"], "ingest", "non-reserved extra merged");
        // The backend's Ed25519 signature verifies under the issuer key.
        kp.verify(signing_input.as_bytes(), &sig)
            .expect("svid signature verifies under issuer key");
    }

    #[tokio::test]
    async fn svid_without_ttl_omits_exp() {
        let backend = KeyPairBackend(KeyPair::new_account());
        let token = mint_svid(
            &backend,
            "k",
            "iss",
            SvidAlg::EdDsa,
            "spiffe://example.org/svc",
            "aud",
            None,
            &serde_json::Value::Null,
        )
        .await
        .expect("mint");
        let (_, claims, _, _) = parse_token(&token);
        assert!(claims.get("exp").is_none(), "no ttl => no exp");
    }

    #[tokio::test]
    async fn svid_rejects_reserved_claims_including_aud() {
        let backend = KeyPairBackend(KeyPair::new_account());
        // `aud` is preset-owned for svid (the handler lifts the real audience out
        // before merging); a residual reserved key in the extras is rejected.
        for reserved in ["iss", "iat", "exp", "jti", "sub", "nbf", "aud"] {
            let err = mint_svid(
                &backend,
                "k",
                "iss",
                SvidAlg::EdDsa,
                "spiffe://example.org/svc",
                "aud",
                None,
                &serde_json::json!({ reserved: "x" }),
            )
            .await
            .expect_err("reserved claim rejected");
            assert!(
                // ubs false positive: test
                /* ubs:ignore */
                matches!(err, GenericMintError::Reserved(ReservedClaim(k)) if k == reserved),
                "expected reserved {reserved}"
            );
        }
    }

    /// A backend whose `sign` is JWS `RS256` (RSASSA-PKCS1-v1_5 / SHA-256). It
    /// signs the signing input with `jsonwebtoken` (the same RS256 path the rest
    /// of the crate uses) and returns the raw signature bytes, so the minter's
    /// `base64url` reassembly reproduces a token verifiable under the public key.
    struct RsaBackend {
        encoding_key: jsonwebtoken::EncodingKey,
        /// SPKI DER of the RSA public half, returned by `public_key` so the
        /// minter can derive the deterministic JWS `kid` header.
        public_der: Vec<u8>,
    }

    #[async_trait]
    impl Backend for RsaBackend {
        fn kind(&self) -> &'static str {
            "rsa-test"
        }
        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }
        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            Ok(self.public_der.clone())
        }
        async fn sign(&self, _key_id: &str, input: &[u8]) -> Result<Vec<u8>, BackendError> {
            self.rs256_sign(input)
        }
        async fn sign_with_options(
            &self,
            _key_id: &str,
            input: &[u8],
            options: SignOptions,
        ) -> Result<Vec<u8>, BackendError> {
            if options != SignOptions::Rs256Pkcs1v15Sha256 {
                return Err(BackendError::Unsupported("rsa test sign options"));
            }
            self.rs256_sign(input)
        }
        async fn verify(
            &self,
            _key_id: &str,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, BackendError> {
            Err(BackendError::Unsupported("verify"))
        }
    }

    impl RsaBackend {
        fn rs256_sign(&self, input: &[u8]) -> Result<Vec<u8>, BackendError> {
            // jsonwebtoken returns a base64url signature string; decode it to raw
            // bytes so the minter re-encodes the identical 3rd JWS segment.
            let b64 = jsonwebtoken::crypto::sign(
                input,
                &self.encoding_key,
                jsonwebtoken::Algorithm::RS256,
            )
            .map_err(|e| BackendError::Backend(e.to_string()))?;
            URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| BackendError::Backend(e.to_string()))
        }
    }

    fn rsa_backend() -> (RsaBackend, Vec<u8>, String) {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::pkcs8::{EncodePublicKey, LineEnding};

        // RSA-2048 (jsonwebtoken's ring backend rejects keys below 2048 bits).
        let mut rng = rand::thread_rng();
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let public = rsa::RsaPublicKey::from(&private);
        let private_pem = private.to_pkcs1_pem(LineEnding::LF).expect("pkcs1 pem");
        let public_pem = public.to_public_key_pem(LineEnding::LF).expect("spki pem");
        let public_der = public
            .to_public_key_der()
            .expect("spki der")
            .as_bytes()
            .to_vec();
        let backend = RsaBackend {
            encoding_key: jsonwebtoken::EncodingKey::from_rsa_pem(private_pem.as_bytes())
                .expect("encoding key"),
            public_der: public_der.clone(),
        };
        (backend, public_der, public_pem)
    }

    /// A backend whose `sign_with_options` is JWS `ES256`. It mirrors the
    /// transit boundary: the backend returns raw fixed-width `r || s` signature
    /// bytes over the compact JWS signing input.
    struct P256Backend {
        encoding_key: jsonwebtoken::EncodingKey,
        public_der: Vec<u8>,
        public_pem: String,
    }

    #[async_trait]
    impl Backend for P256Backend {
        fn kind(&self) -> &'static str {
            "p256-test"
        }
        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }
        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            Ok(self.public_der.clone())
        }
        async fn sign(&self, key_id: &str, input: &[u8]) -> Result<Vec<u8>, BackendError> {
            self.sign_with_options(key_id, input, SignOptions::Es256)
                .await
        }
        async fn sign_with_options(
            &self,
            _key_id: &str,
            input: &[u8],
            options: SignOptions,
        ) -> Result<Vec<u8>, BackendError> {
            if options != SignOptions::Es256 {
                return Err(BackendError::Unsupported("p256 test sign options"));
            }
            let b64 = jsonwebtoken::crypto::sign(
                input,
                &self.encoding_key,
                jsonwebtoken::Algorithm::ES256,
            )
            .map_err(|e| BackendError::Backend(e.to_string()))?;
            URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| BackendError::Backend(e.to_string()))
        }
        async fn verify(
            &self,
            _key_id: &str,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, BackendError> {
            Err(BackendError::Unsupported("verify"))
        }
    }

    fn p256_backend() -> P256Backend {
        use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};

        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let private_der = signing_key.to_pkcs8_der().expect("pkcs8 der");
        let public = signing_key.verifying_key();
        let public_der = public
            .to_public_key_der()
            .expect("spki der")
            .as_bytes()
            .to_vec();
        let public_pem = public.to_public_key_pem(LineEnding::LF).expect("spki pem");
        P256Backend {
            encoding_key: jsonwebtoken::EncodingKey::from_ec_der(private_der.as_bytes()),
            public_der,
            public_pem,
        }
    }

    /// A backend whose `sign_with_options` is JWS `ES384`.
    struct P384Backend {
        encoding_key: jsonwebtoken::EncodingKey,
        public_der: Vec<u8>,
        public_pem: String,
    }

    #[async_trait]
    impl Backend for P384Backend {
        fn kind(&self) -> &'static str {
            "p384-test"
        }
        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }
        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            Ok(self.public_der.clone())
        }
        async fn sign(&self, key_id: &str, input: &[u8]) -> Result<Vec<u8>, BackendError> {
            self.sign_with_options(key_id, input, SignOptions::Es384)
                .await
        }
        async fn sign_with_options(
            &self,
            _key_id: &str,
            input: &[u8],
            options: SignOptions,
        ) -> Result<Vec<u8>, BackendError> {
            if options != SignOptions::Es384 {
                return Err(BackendError::Unsupported("p384 test sign options"));
            }
            let b64 = jsonwebtoken::crypto::sign(
                input,
                &self.encoding_key,
                jsonwebtoken::Algorithm::ES384,
            )
            .map_err(|e| BackendError::Backend(e.to_string()))?;
            URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| BackendError::Backend(e.to_string()))
        }
        async fn verify(
            &self,
            _key_id: &str,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, BackendError> {
            Err(BackendError::Unsupported("verify"))
        }
    }

    fn p384_backend() -> P384Backend {
        use p384::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};

        let signing_key = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let private_der = signing_key.to_pkcs8_der().expect("pkcs8 der");
        let public = signing_key.verifying_key();
        let public_der = public
            .to_public_key_der()
            .expect("spki der")
            .as_bytes()
            .to_vec();
        let public_pem = public.to_public_key_pem(LineEnding::LF).expect("spki pem");
        P384Backend {
            encoding_key: jsonwebtoken::EncodingKey::from_ec_der(private_der.as_bytes()),
            public_der,
            public_pem,
        }
    }

    #[tokio::test]
    async fn svid_rs256_mints_a_verifiable_jwt_svid() {
        let (backend, public_der, public_pem) = rsa_backend();

        let token = mint_svid(
            &backend,
            "rsa-issuer",
            "spiffe://example.org",
            SvidAlg::Rs256,
            "spiffe://example.org/db-01",
            "vault",
            Some(300),
            &serde_json::Value::Null,
        )
        .await
        .expect("mint rs256 svid");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let (header, claims, _signing_input, _sig) = parse_token(&token);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(claims["sub"], "spiffe://example.org/db-01");
        // The `kid` header is required by the SPIFFE JWT-SVID profile and MUST
        // match the JWKS key id published for the bundle (so a verifier can
        // select the key). Same deterministic id from the same public half.
        assert_eq!(
            header["kid"],
            jwt_svid_jwk_kid(&public_der, SvidAlg::Rs256),
            "JWS kid matches the published JWKS key id"
        );
        // The RS256 signature (3rd segment) verifies under the issuer's RSA key.
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let decoding_key =
            jsonwebtoken::DecodingKey::from_rsa_pem(public_pem.as_bytes()).expect("decoding key");
        let valid = jsonwebtoken::crypto::verify(
            parts[2],
            signing_input.as_bytes(),
            &decoding_key,
            jsonwebtoken::Algorithm::RS256,
        )
        .expect("verify");
        assert!(valid, "RS256 signature verifies under issuer key");
    }

    #[tokio::test]
    async fn svid_es256_mints_a_verifiable_jwt_svid() {
        let backend = p256_backend();

        let token = mint_svid(
            &backend,
            "ecdsa-issuer",
            "spiffe://example.org",
            SvidAlg::Es256,
            "spiffe://example.org/db-01",
            "vault",
            Some(300),
            &serde_json::Value::Null,
        )
        .await
        .expect("mint es256 svid");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let (header, claims, _signing_input, sig) = parse_token(&token);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(claims["sub"], "spiffe://example.org/db-01");
        assert_eq!(
            header["kid"],
            jwt_svid_jwk_kid(&backend.public_der, SvidAlg::Es256),
            "JWS kid matches the published JWKS key id"
        );
        assert_eq!(sig.len(), 64, "ES256 signatures are raw fixed r||s");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let decoding_key = jsonwebtoken::DecodingKey::from_ec_pem(backend.public_pem.as_bytes())
            .expect("decoding key");
        let valid = jsonwebtoken::crypto::verify(
            parts[2],
            signing_input.as_bytes(),
            &decoding_key,
            jsonwebtoken::Algorithm::ES256,
        )
        .expect("verify");
        assert!(valid, "ES256 signature verifies under issuer key");
    }

    #[tokio::test]
    async fn svid_es384_mints_a_verifiable_jwt_svid() {
        let backend = p384_backend();

        let token = mint_svid(
            &backend,
            "ecdsa384-issuer",
            "spiffe://example.org",
            SvidAlg::Es384,
            "spiffe://example.org/db-01",
            "vault",
            Some(300),
            &serde_json::Value::Null,
        )
        .await
        .expect("mint es384 svid");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let (header, claims, _signing_input, sig) = parse_token(&token);
        assert_eq!(header["alg"], "ES384");
        assert_eq!(claims["sub"], "spiffe://example.org/db-01");
        assert_eq!(
            header["kid"],
            jwt_svid_jwk_kid(&backend.public_der, SvidAlg::Es384),
            "JWS kid matches the published JWKS key id"
        );
        assert_eq!(sig.len(), 96, "ES384 signatures are raw fixed r||s");

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let decoding_key = jsonwebtoken::DecodingKey::from_ec_pem(backend.public_pem.as_bytes())
            .expect("decoding key");
        let valid = jsonwebtoken::crypto::verify(
            parts[2],
            signing_input.as_bytes(),
            &decoding_key,
            jsonwebtoken::Algorithm::ES384,
        )
        .expect("verify");
        assert!(valid, "ES384 signature verifies under issuer key");
    }
}
