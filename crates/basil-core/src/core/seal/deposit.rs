//! Public-key credential deposit support for sealed bundles.
//!
//! Deposits are append-only cleartext metadata records whose credential bytes
//! are X25519-sealed to an ingest key stored inside the encrypted payload. A
//! contributor signature authenticates each record; the sealed allow-list decides
//! which records become effective after a normal unlock.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::core::{ed25519_sign, x25519_seal};

use super::cred::{BackendCred, CredBundle};
use super::format::{
    B64Bytes, DepositRecord, DepositSealedCred, Header, ParsedBundle, deposit_signing_bytes,
};
use super::{MethodRegistry, SealError};

const DEPOSIT_AAD_LABEL: &[u8] = b"basil-bundle-deposit-v1";
const MAX_DEPOSITS: usize = 1024;

/// Public review state for one deposit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositReview {
    /// Record index in the bundle deposit log.
    pub index: usize,
    /// Target backend id.
    pub backend_id: String,
    /// Contributor key id.
    pub contributor_key_id: String,
    /// Target epoch.
    pub epoch: u64,
    /// Contributor/backend sequence.
    pub seq: u64,
    /// Verification/authorization status.
    pub status: DepositStatus,
    /// Whether this record would add or replace a baseline credential.
    pub action: DepositAction,
    /// Non-secret credential fingerprint when the credential was opened.
    pub fingerprint: Option<String>,
}

/// Deposit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositStatus {
    /// Authorized, signed, current, decryptable, and selected as effective.
    Effective,
    /// Authorized but superseded by a later/higher sequence record.
    Superseded,
    /// Bundle contains no ingest identity.
    MissingIngestIdentity,
    /// Contributor id is not allow-listed.
    UnauthorizedContributor,
    /// Contributor is not delegated to this backend id.
    UnauthorizedBackend,
    /// Record epoch does not match the bundle epoch.
    StaleEpoch,
    /// Signature is malformed or invalid.
    BadSignature,
    /// Sealed credential did not open.
    DecryptFailed,
    /// Opened credential did not decode as a `BackendCred`.
    DecodeFailed,
    /// Deposit log exceeds the bounded record cap.
    LogTooLarge,
}

impl DepositStatus {
    /// Stable display token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Effective => "effective",
            Self::Superseded => "superseded",
            Self::MissingIngestIdentity => "missing-ingest-identity",
            Self::UnauthorizedContributor => "unauthorized-contributor",
            Self::UnauthorizedBackend => "unauthorized-backend",
            Self::StaleEpoch => "stale-epoch",
            Self::BadSignature => "bad-signature",
            Self::DecryptFailed => "decrypt-failed",
            Self::DecodeFailed => "decode-failed",
            Self::LogTooLarge => "log-too-large",
        }
    }
}

/// Baseline effect for a valid deposit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositAction {
    /// The backend id is absent from the sealed baseline.
    New,
    /// The backend id replaces a sealed baseline credential.
    Replace,
    /// No credential was opened, so the action cannot be known.
    Unknown,
}

impl DepositAction {
    /// Stable display token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Replace => "replace",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    index: usize,
    backend_id: String,
    contributor_key_id: String,
    seq: u64,
    cred: BackendCred,
}

/// Encode a public key as the bundle CLI token format.
#[must_use]
pub fn public_key_token(public: &[u8; 32]) -> String {
    B64.encode(public)
}

/// Parse a bundle CLI public-key token.
///
/// # Errors
/// Returns [`SealError::Format`] if the token is not base64url-nopad or is not
/// exactly 32 bytes.
pub fn public_key_from_token(token: &str) -> Result<[u8; 32], SealError> {
    let bytes = B64
        .decode(token.as_bytes())
        .map_err(|e| SealError::Format(format!("deposit public key decode: {e}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| SealError::Format("deposit public key must be 32 bytes".into()))
}

/// Derive the public key token for a contributor signing seed.
#[must_use]
pub fn contributor_public_token(seed: &Zeroizing<[u8; 32]>) -> String {
    public_key_token(&ed25519_sign::public_from_seed(seed))
}

/// Create one signed deposit record.
///
/// # Errors
/// Returns [`SealError`] on credential serialization, X25519 sealing, or
/// canonical signing-byte serialization failure.
pub fn create_signed_record(
    header: &Header,
    backend_id: String,
    contributor_key_id: String,
    seq: u64,
    recipient_public: &[u8; 32],
    signing_seed: &Zeroizing<[u8; 32]>,
    cred: &BackendCred,
) -> Result<DepositRecord, SealError> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(cred).map_err(|e| SealError::Payload(e.to_string()))?);
    let aad = deposit_aad(header, &backend_id, header.epoch, seq, &contributor_key_id)?;
    let envelope = x25519_seal::seal(recipient_public, &plaintext, &aad)
        .map_err(|e| SealError::Crypto(format!("deposit seal: {e}")))?;
    let mut record = DepositRecord {
        backend_id,
        epoch: header.epoch,
        seq,
        contributor_key_id,
        sealed_cred: DepositSealedCred {
            encapsulated_key: B64Bytes(envelope.encapsulated_key.to_vec()),
            nonce: B64Bytes(envelope.nonce.to_vec()),
            ciphertext: B64Bytes(envelope.ciphertext),
        },
        signature: B64Bytes(Vec::new()),
    };
    let signing_bytes = deposit_signing_bytes(&record)?;
    record.signature = B64Bytes(ed25519_sign::sign(signing_seed, &signing_bytes).to_vec());
    Ok(record)
}

/// Apply all authorized effective deposits over an already-opened bundle.
///
/// Invalid records are reported and ignored, not fatal.
pub fn apply_authorized_deposits(
    parsed: &ParsedBundle,
    creds: &mut CredBundle,
) -> Vec<DepositReview> {
    let (mut reviews, candidates) = review_authorized(parsed, creds);
    for candidate in select_effective(candidates) {
        if let Some(review) = reviews.get_mut(candidate.index) {
            review.status = DepositStatus::Effective;
        }
        creds.set(candidate.backend_id, candidate.cred);
    }
    reviews
}

/// Review deposits without mutating the baseline.
#[must_use]
pub fn review_deposits(parsed: &ParsedBundle, creds: &CredBundle) -> Vec<DepositReview> {
    let (mut reviews, candidates) = review_authorized(parsed, creds);
    for candidate in select_effective(candidates) {
        if let Some(review) = reviews.get_mut(candidate.index) {
            review.status = DepositStatus::Effective;
        }
    }
    reviews
}

/// Promote selected effective deposits into the sealed payload and prune them.
///
/// # Errors
/// Returns [`SealError`] if the bundle cannot be opened or fully re-sealed.
pub fn promote_deposits(
    parsed: &ParsedBundle,
    methods: &MethodRegistry<'_>,
    backend_filter: &BTreeSet<String>,
    contributor_filter: &BTreeSet<String>,
) -> Result<(Vec<u8>, Vec<DepositReview>), SealError> {
    let mut creds = super::open_bundle(parsed, methods)?;
    let baseline = creds.clone();
    let (mut reviews, candidates) = review_authorized(parsed, &baseline);
    let mut promoted = BTreeSet::new();
    for candidate in select_effective(candidates) {
        let selected_backend =
            backend_filter.is_empty() || backend_filter.contains(&candidate.backend_id);
        let selected_contributor = contributor_filter.is_empty()
            || contributor_filter.contains(&candidate.contributor_key_id);
        if !selected_backend || !selected_contributor {
            if let Some(review) = reviews.get_mut(candidate.index) {
                review.status = DepositStatus::Effective;
            }
            continue;
        }
        if let Some(review) = reviews.get_mut(candidate.index) {
            review.status = DepositStatus::Effective;
        }
        creds.set(candidate.backend_id, candidate.cred);
        promoted.insert(candidate.index);
    }

    let deposits = parsed
        .body
        .deposits
        .iter()
        .enumerate()
        .filter(|(idx, _)| !promoted.contains(idx))
        .map(|(_, deposit)| deposit.clone())
        .collect();
    let file = super::reseal_payload_bump_epoch_with_deposits(parsed, methods, &creds, deposits)?;
    Ok((file, reviews))
}

fn review_authorized(
    parsed: &ParsedBundle,
    baseline: &CredBundle,
) -> (Vec<DepositReview>, Vec<Candidate>) {
    if parsed.body.deposits.len() > MAX_DEPOSITS {
        return (
            parsed
                .body
                .deposits
                .iter()
                .enumerate()
                .map(|(index, record)| {
                    review(record, index, DepositStatus::LogTooLarge, None, baseline)
                })
                .collect(),
            Vec::new(),
        );
    }

    let Some(private) = baseline.deposit.ingest_private_key.as_ref() else {
        return (
            parsed
                .body
                .deposits
                .iter()
                .enumerate()
                .map(|(index, record)| {
                    review(
                        record,
                        index,
                        DepositStatus::MissingIngestIdentity,
                        None,
                        baseline,
                    )
                })
                .collect(),
            Vec::new(),
        );
    };
    let Ok(private) = <[u8; 32]>::try_from(private.expose_secret()) else {
        return (
            parsed
                .body
                .deposits
                .iter()
                .enumerate()
                .map(|(index, record)| {
                    review(
                        record,
                        index,
                        DepositStatus::MissingIngestIdentity,
                        None,
                        baseline,
                    )
                })
                .collect(),
            Vec::new(),
        );
    };
    let private = Zeroizing::new(private);

    let mut reviews = Vec::with_capacity(parsed.body.deposits.len());
    let mut candidates = Vec::new();
    for (index, record) in parsed.body.deposits.iter().enumerate() {
        match review_one(parsed, baseline, &private, record, index) {
            Ok((candidate, deposit_review)) => {
                candidates.push(candidate);
                reviews.push(deposit_review);
            }
            Err(status) => reviews.push(review(record, index, status, None, baseline)),
        }
    }
    (reviews, candidates)
}

fn review_one(
    parsed: &ParsedBundle,
    baseline: &CredBundle,
    private: &Zeroizing<[u8; 32]>,
    record: &DepositRecord,
    index: usize,
) -> Result<(Candidate, DepositReview), DepositStatus> {
    if record.epoch != parsed.body.header.epoch {
        return Err(DepositStatus::StaleEpoch);
    }
    let contributor = baseline
        .deposit
        .contributors
        .get(&record.contributor_key_id)
        .ok_or(DepositStatus::UnauthorizedContributor)?;
    if !contributor.allowed_backend_ids.contains(&record.backend_id) {
        return Err(DepositStatus::UnauthorizedBackend);
    }
    let public =
        public_key_from_token(&contributor.public_key).map_err(|_| DepositStatus::BadSignature)?;
    let signing_bytes = deposit_signing_bytes(record).map_err(|_| DepositStatus::BadSignature)?;
    let sig_ok = ed25519_sign::verify(&public, &signing_bytes, &record.signature.0)
        .map_err(|_| DepositStatus::BadSignature)?;
    if !sig_ok {
        return Err(DepositStatus::BadSignature);
    }
    let envelope = x25519_seal::envelope_from_parts(
        &record.sealed_cred.encapsulated_key.0,
        &record.sealed_cred.nonce.0,
        &record.sealed_cred.ciphertext.0,
    )
    .map_err(|_| DepositStatus::DecryptFailed)?;
    let aad = deposit_aad(
        &parsed.body.header,
        &record.backend_id,
        record.epoch,
        record.seq,
        &record.contributor_key_id,
    )
    .map_err(|_| DepositStatus::DecryptFailed)?;
    let plaintext =
        x25519_seal::open(private, &envelope, &aad).map_err(|_| DepositStatus::DecryptFailed)?;
    let cred: BackendCred =
        serde_json::from_slice(&plaintext).map_err(|_| DepositStatus::DecodeFailed)?;
    let fingerprint = Some(credential_fingerprint(&cred));
    Ok((
        Candidate {
            index,
            backend_id: record.backend_id.clone(),
            contributor_key_id: record.contributor_key_id.clone(),
            seq: record.seq,
            cred,
        },
        review(
            record,
            index,
            DepositStatus::Superseded,
            fingerprint,
            baseline,
        ),
    ))
}

fn select_effective(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut by_pair: BTreeMap<(String, String), Candidate> = BTreeMap::new();
    for candidate in candidates {
        let key = (
            candidate.contributor_key_id.clone(),
            candidate.backend_id.clone(),
        );
        let replace = by_pair
            .get(&key)
            .is_none_or(|current| candidate.seq >= current.seq);
        if replace {
            by_pair.insert(key, candidate);
        }
    }

    let mut by_backend: BTreeMap<String, Candidate> = BTreeMap::new();
    for candidate in by_pair.into_values() {
        let replace = by_backend
            .get(&candidate.backend_id)
            .is_none_or(|current| candidate.seq >= current.seq);
        if replace {
            by_backend.insert(candidate.backend_id.clone(), candidate);
        }
    }
    by_backend.into_values().collect()
}

fn review(
    record: &DepositRecord,
    index: usize,
    status: DepositStatus,
    fingerprint: Option<String>,
    baseline: &CredBundle,
) -> DepositReview {
    let action = if fingerprint.is_none() {
        DepositAction::Unknown
    } else if baseline.backends.contains_key(&record.backend_id) {
        DepositAction::Replace
    } else {
        DepositAction::New
    };
    DepositReview {
        index,
        backend_id: record.backend_id.clone(),
        contributor_key_id: record.contributor_key_id.clone(),
        epoch: record.epoch,
        seq: record.seq,
        status,
        action,
        fingerprint,
    }
}

fn deposit_aad(
    header: &Header,
    backend_id: &str,
    epoch: u64,
    seq: u64,
    contributor_key_id: &str,
) -> Result<Vec<u8>, SealError> {
    #[derive(Serialize)]
    struct Aad<'a> {
        label: &'a str,
        bundle_id: &'a [u8; 16],
        epoch: u64,
        backend_id: &'a str,
        seq: u64,
        contributor_key_id: &'a str,
    }

    let mut out = Vec::from(DEPOSIT_AAD_LABEL);
    let json = serde_json::to_vec(&Aad {
        label: "deposit-cred",
        bundle_id: &header.bundle_id,
        epoch,
        backend_id,
        seq,
        contributor_key_id,
    })
    .map_err(|e| SealError::Format(format!("deposit aad serialize: {e}")))?;
    out.extend_from_slice(&json);
    Ok(out)
}

fn credential_fingerprint(cred: &BackendCred) -> String {
    if let BackendCred::GcpKms {
        service_account_json: Some(json),
        ..
    } = cred
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(json.expose_secret())
    {
        let project = value
            .get("project_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        let email = value
            .get("client_email")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        let key_id = value
            .get("private_key_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        return format!("gcp-sa:{project}:{email}:{key_id}");
    }

    let encoded = serde_json::to_vec(cred).unwrap_or_default();
    let digest = Sha256::digest(encoded);
    format!("sha256:{}", B64.encode(digest))
}
