// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Sealed-bundle seal / open / slot management (vault-vh1).
//!
//! Implements `designs/unlock-and-bundle.html`: a `0600` multi-slot sealed bundle
//! holding the broker's own bootstrap credentials. One 32-byte master KEK
//! AES-256-GCM-encrypts the payload (the [`CredBundle`] cred map, §4); *N*
//! independent [`Slot`]s each wrap that *same* KEK via a different
//! [`UnlockMethod`]. Adding/removing a method rewraps one slot and leaves the
//! payload untouched. The header is bound as AAD over the payload AEAD and every
//! slot wrap (anti-downgrade/splice, §2.2).
//!
//! Everything here fails **closed** and never panics on a runtime path (§1.3):
//! every fallible step returns a `Result`, the master KEK and the decrypted
//! [`CredBundle`] are `Zeroizing`, and the KEK is wiped as early as possible.

pub mod aead;
pub mod cred;
pub mod deposit;
pub mod format;
pub mod unlock;

use zeroize::Zeroizing;

pub use cred::{BackendCred, CRED_SCHEMA_VERSION, CredBundle, DepositContributor};
pub use deposit::{
    DepositAction, DepositReview, DepositStatus, apply_authorized_deposits,
    contributor_public_token, create_signed_record, promote_deposits, public_key_from_token,
    public_key_token, review_deposits,
};
pub use format::{
    Argon2Params, B64Bytes, BundleBody, DepositRecord, DepositSealedCred, FORMAT_VERSION, Header,
    KekWrap, MAGIC, MethodKind, MethodParams, ParsedBundle, SealedPayload, Slot, Suite,
};
pub use unlock::{UnlockError, UnlockMethod};

#[cfg(feature = "unlock-age-yubikey")]
pub use unlock::age_yubikey::AgeYubikeyMethod;
#[cfg(feature = "unlock-bip39")]
pub use unlock::bip39::Bip39Method;
pub use unlock::passphrase::PassphraseMethod;
pub use unlock::tpm::TpmMethod;

/// Errors from sealing/opening a bundle (§5). Distinct from [`UnlockError`],
/// which is per-method; this is the container/orchestration layer.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    /// Container framing / JSON / version problem (bad magic, unknown version).
    #[error("bundle format: {0}")]
    Format(String),

    /// AEAD authentication failed (tampered header/payload, wrong KEK).
    #[error("authentication failed (tampered or wrong key)")]
    AuthFailed,

    /// A crypto/serialization failure.
    #[error("crypto: {0}")]
    Crypto(String),

    /// No enabled+available slot could open the bundle. Fails closed.
    #[error("no unlock slot could open the bundle")]
    NoSlotOpened,

    /// Would remove the last slot (bricks the bundle).
    #[error("refusing to remove the last slot")]
    LastSlot,

    /// The referenced slot id is not present.
    #[error("slot {0} not found")]
    SlotNotFound(u32),

    /// A method-level unlock error surfaced during seal/open.
    #[error(transparent)]
    Unlock(#[from] UnlockError),

    /// A serde error during payload (de)serialization.
    #[error("payload encode/decode: {0}")]
    Payload(String),
}

/// 32-byte master KEK that zeroizes on drop (the newtype the §3 trait sketch
/// calls `KeyMaterial`; renamed to avoid colliding with `proto::KeyMaterial`).
pub struct MasterKek(Zeroizing<[u8; aead::KEY_LEN]>);

impl MasterKek {
    /// Draw a fresh master KEK from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self(aead::fresh_key())
    }

    /// Build from exactly 32 bytes, or `None` if the length is wrong.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let arr = <[u8; aead::KEY_LEN]>::try_from(bytes).ok()?;
        Some(Self(Zeroizing::new(arr)))
    }

    /// Borrow the raw key bytes (kept on the stack inside `Zeroizing`).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; aead::KEY_LEN] {
        &self.0
    }
}

/// A slot specification for `seal` / `add_slot`: the method that will back the
/// slot and its operator-facing label.
pub struct SlotSpec<'a> {
    /// The unlock method (already configured with its recipient/phrase/etc.).
    pub method: &'a dyn UnlockMethod,
    /// Operator-facing label, e.g. `"primary-yubikey"` / `"break-glass-2026"`.
    pub label: String,
}

/// Current unix time in seconds (saturating; never panics).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Seal a fresh bundle: pick a random master KEK, encrypt `payload` under it,
/// and wrap the KEK into one slot per `specs`. Returns the on-disk file bytes.
///
/// At least one slot is required (a bundle with no slots cannot be opened).
///
/// # Errors
/// [`SealError`] on serialization, AEAD, or per-method wrap failure; fails closed.
pub fn seal(payload: &CredBundle, specs: &[SlotSpec<'_>]) -> Result<Vec<u8>, SealError> {
    if specs.is_empty() {
        return Err(SealError::LastSlot);
    }
    let kek = MasterKek::generate();
    let mut bundle_id = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bundle_id);

    let header = Header {
        format_version: FORMAT_VERSION,
        suite: Suite::v1(),
        bundle_id,
        created_unix: now_unix(),
        epoch: 1,
    };
    let header_aad = header.to_aad_bytes()?;

    // Encrypt the payload once under the KEK.
    let sealed_payload = encrypt_payload(&kek, &header_aad, payload)?;

    // Wrap the KEK into each slot (ids assigned 0..N).
    let mut slots = Vec::with_capacity(specs.len());
    for (idx, spec) in specs.iter().enumerate() {
        let slot_id = u32::try_from(idx).map_err(|_| SealError::Format("too many slots".into()))?;
        let (params, wrap) = spec.method.wrap_kek(&kek, &header_aad, slot_id)?;
        slots.push(Slot {
            slot_id,
            method: spec.method.kind(),
            label: spec.label.clone(),
            created_unix: now_unix(),
            params,
            wrap,
        });
    }

    format::encode(&header, &header_aad, slots, sealed_payload)
}

/// Open a bundle and return its [`CredBundle`].
///
/// Walks the slot table, tries each slot whose method is enabled + available,
/// recovers the master KEK on first success, decrypts the payload, then
/// **zeroizes the KEK**.
///
/// `methods` maps a [`MethodKind`] to a configured [`UnlockMethod`] able to
/// recover that slot (e.g. a `Bip39Method` holding the operator's phrase). A
/// `None` entry (or absent kind) means that method is not available this boot.
///
/// # Errors
/// [`SealError::NoSlotOpened`] if nothing opens (fail closed); [`SealError::AuthFailed`]
/// if the payload AEAD fails after a slot recovered a KEK.
pub fn open_bundle(
    parsed: &ParsedBundle,
    methods: &MethodRegistry<'_>,
) -> Result<CredBundle, SealError> {
    let header_aad = parsed.header_aad();

    for slot in &parsed.body.slots {
        let Some(method) = openable_method(slot, methods, SlotLog::Open) else {
            continue;
        };
        match method.recover_kek(slot, header_aad) {
            Ok(kek) => {
                tracing::info!(
                    slot_id = slot.slot_id,
                    method = %slot.method,
                    "unlock slot opened"
                );
                let payload = decrypt_payload(&kek, header_aad, &parsed.body.payload)?;
                // KEK zeroized here as `kek` drops at end of scope (Zeroizing).
                drop(kek);
                return Ok(payload);
            }
            Err(e) => {
                tracing::warn!(
                    slot_id = slot.slot_id,
                    method = %slot.method,
                    error = %e,
                    "unlock slot failed"
                );
            }
        }
    }
    Err(SealError::NoSlotOpened)
}

/// Replace the payload of an existing bundle (the `set-cred` flow, §6.2).
///
/// Opens via `methods` to recover the master KEK, swaps in `new_payload`, and
/// re-encrypts under the **same** KEK and the **same** header AAD (so no slot
/// rewrap is needed), returning the new file bytes.
///
/// NOTE on `epoch`: §6.2 calls for `epoch += 1` on a cred change, but the header
/// (and thus its `epoch`) is the AEAD AAD for *both* the payload and every slot
/// wrap, so bumping it here would invalidate the un-rewrapped slot wraps. The
/// epoch is therefore held stable on `set-cred`; a monotonic-epoch bump belongs
/// with the deferred §6.4 sidecar / full re-seal (logged as an OFI). The payload
/// still gets a fresh AEAD nonce, so the ciphertext changes on every `set-cred`.
///
/// # Errors
/// [`SealError`] on open/encrypt failure. Fails closed.
pub fn reseal_payload(
    parsed: &ParsedBundle,
    methods: &MethodRegistry<'_>,
    new_payload: &CredBundle,
) -> Result<Vec<u8>, SealError> {
    let header = parsed.body.header.clone();
    let header_aad = parsed.header_aad().to_vec();
    let kek = recover_any(parsed, methods)?;
    let sealed_payload = encrypt_payload(&kek, &header_aad, new_payload)?;
    drop(kek);
    format::encode_with_deposits(
        &header,
        &header_aad,
        parsed.body.slots.clone(),
        sealed_payload,
        parsed.body.deposits.clone(),
    )
}

/// Replace the payload and advance the monotonic epoch.
///
/// Unlike [`reseal_payload`], this performs the full §6.4 re-seal: it bumps the
/// header epoch, re-encrypts the payload under the new header AAD, and rewraps
/// every existing slot under that same new AAD. Every slot method already present
/// in the bundle must be configured in `methods`; otherwise Basil refuses the
/// update rather than producing a partially-openable bundle.
///
/// # Errors
/// [`SealError`] on open/encrypt/rewrap failure: fail closed.
pub fn reseal_payload_bump_epoch(
    parsed: &ParsedBundle,
    methods: &MethodRegistry<'_>,
    new_payload: &CredBundle,
) -> Result<Vec<u8>, SealError> {
    reseal_payload_bump_epoch_with_deposits(
        parsed,
        methods,
        new_payload,
        parsed.body.deposits.clone(),
    )
}

/// Replace the payload, set the deposit log, and advance the monotonic epoch.
///
/// # Errors
/// [`SealError`] on open/encrypt/rewrap failure; fails closed.
pub fn reseal_payload_bump_epoch_with_deposits(
    parsed: &ParsedBundle,
    methods: &MethodRegistry<'_>,
    new_payload: &CredBundle,
    deposits: Vec<DepositRecord>,
) -> Result<Vec<u8>, SealError> {
    let mut header = parsed.body.header.clone();
    header.epoch = header
        .epoch
        .checked_add(1)
        .ok_or_else(|| SealError::Format("bundle epoch overflow".into()))?;
    let header_aad = header.to_aad_bytes()?;
    let kek = recover_any(parsed, methods)?;
    let sealed_payload = encrypt_payload(&kek, &header_aad, new_payload)?;
    let slots = rewrap_slots(parsed, methods, &kek, &header_aad)?;
    drop(kek);
    format::encode_with_deposits(&header, &header_aad, slots, sealed_payload, deposits)
}

/// Add a slot to an existing bundle (§2.7).
///
/// Opens via `methods` to recover the KEK, wraps it for `spec`'s method under
/// the **existing** header AAD, appends the slot, and returns the new file
/// bytes. The payload is untouched.
///
/// # Errors
/// [`SealError`] on open or wrap failure, failing closed.
pub fn add_slot(
    parsed: &ParsedBundle,
    methods: &MethodRegistry<'_>,
    spec: &SlotSpec<'_>,
) -> Result<Vec<u8>, SealError> {
    let header = parsed.body.header.clone();
    let header_aad = parsed.header_aad().to_vec();
    let kek = recover_any(parsed, methods)?;

    let next_id = parsed
        .body
        .slots
        .iter()
        .map(|s| s.slot_id)
        .max()
        .map_or(0, |m| m.saturating_add(1));
    let (params, wrap) = spec.method.wrap_kek(&kek, &header_aad, next_id)?;
    drop(kek);

    let mut slots = parsed.body.slots.clone();
    slots.push(Slot {
        slot_id: next_id,
        method: spec.method.kind(),
        label: spec.label.clone(),
        created_unix: now_unix(),
        params,
        wrap,
    });
    format::encode_with_deposits(
        &header,
        &header_aad,
        slots,
        parsed.body.payload.clone(),
        parsed.body.deposits.clone(),
    )
}

/// Remove a slot by id (§2.7). Refuses to remove the last remaining slot.
///
/// # Errors
/// [`SealError::SlotNotFound`] / [`SealError::LastSlot`]: fail closed.
pub fn remove_slot(parsed: &ParsedBundle, slot_id: u32) -> Result<Vec<u8>, SealError> {
    if parsed.body.slots.len() <= 1 {
        return Err(SealError::LastSlot);
    }
    if !parsed.body.slots.iter().any(|s| s.slot_id == slot_id) {
        return Err(SealError::SlotNotFound(slot_id));
    }
    let slots: Vec<Slot> = parsed
        .body
        .slots
        .iter()
        .filter(|s| s.slot_id != slot_id)
        .cloned()
        .collect();
    let header = parsed.body.header.clone();
    let header_aad = parsed.header_aad().to_vec();
    format::encode_with_deposits(
        &header,
        &header_aad,
        slots,
        parsed.body.payload.clone(),
        parsed.body.deposits.clone(),
    )
}

/// Verify the bundle epoch against a 0600 sidecar, then persist the current
/// epoch as the new last-seen value.
///
/// Missing sidecars are initialized to the bundle's current epoch. A sidecar with
/// a higher epoch than the bundle means an older bundle was swapped in and is
/// refused. A sidecar with a lower epoch is advanced.
///
/// **Not a security boundary against a local writer.** Anyone who can replace
/// the broker-owned bundle can typically also delete the sidecar, and a missing
/// sidecar is (re)initialized rather than refused: the check only catches
/// *accidental* rollback (a restored backup, a mis-synced deploy). Deliberate
/// rollback resistance requires the deferred TPM NV binding. Callers must run
/// this check on the parsed header **before** opening the bundle, so a stale
/// bundle is refused without decrypting its payload or applying its deposit log.
/// Only the plaintext header epoch is consumed here; the header is authenticated
/// later, as the payload/slot AAD, when the bundle opens.
///
/// # Errors
/// [`SealError::Format`] on stale bundles or sidecar IO/parse errors.
pub fn verify_epoch_sidecar(
    parsed: &ParsedBundle,
    sidecar_path: &std::path::Path,
) -> Result<(), SealError> {
    let current = parsed.body.header.epoch;
    match std::fs::read_to_string(sidecar_path) {
        Ok(raw) => {
            let seen = raw
                .trim()
                .parse::<u64>()
                .map_err(|e| SealError::Format(format!("epoch sidecar parse: {e}")))?;
            if current < seen {
                return Err(SealError::Format(format!(
                    "bundle epoch rollback: current {current}, last seen {seen}"
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(SealError::Format(format!("epoch sidecar read: {e}"))),
    }
    write_epoch_sidecar(sidecar_path, current)
}

/// Write the bundle epoch sidecar as owner-only text.
///
/// # Errors
/// [`SealError::Format`] on sidecar IO errors.
pub fn write_epoch_sidecar(sidecar_path: &std::path::Path, epoch: u64) -> Result<(), SealError> {
    let tmp = sidecar_path.with_extension("epoch.tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        std::io::Write::write_all(
            &mut opts
                .open(&tmp)
                .map_err(|e| SealError::Format(format!("epoch sidecar open: {e}")))?,
            format!("{epoch}\n").as_bytes(),
        )
        .map_err(|e| SealError::Format(format!("epoch sidecar write: {e}")))?;
    }
    std::fs::rename(&tmp, sidecar_path)
        .map_err(|e| SealError::Format(format!("epoch sidecar rename: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sidecar_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| SealError::Format(format!("epoch sidecar chmod: {e}")))?;
    }
    Ok(())
}

/// Recover the master KEK from any openable slot (shared by add/reseal).
fn recover_any(
    parsed: &ParsedBundle,
    methods: &MethodRegistry<'_>,
) -> Result<MasterKek, SealError> {
    let header_aad = parsed.header_aad();
    for slot in &parsed.body.slots {
        let Some(method) = openable_method(slot, methods, SlotLog::Quiet) else {
            continue;
        };
        if let Ok(kek) = recover_slot_kek(method, slot, header_aad) {
            return Ok(kek);
        }
    }
    Err(SealError::NoSlotOpened)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SlotLog {
    Open,
    Quiet,
}

fn openable_method<'a>(
    slot: &Slot,
    methods: &MethodRegistry<'a>,
    log: SlotLog,
) -> Option<&'a dyn UnlockMethod> {
    let method = methods.get(slot.method).or_else(|| {
        log_missing_method(slot, log);
        None
    })?;
    if method.available() {
        Some(method)
    } else {
        log_unavailable_method(slot, log);
        None
    }
}

fn recover_slot_kek(
    method: &dyn UnlockMethod,
    slot: &Slot,
    header_aad: &[u8],
) -> Result<MasterKek, UnlockError> {
    method.recover_kek(slot, header_aad)
}

fn log_missing_method(slot: &Slot, log: SlotLog) {
    if log != SlotLog::Open {
        return;
    }
    match slot.method {
        // Feature-off builds carry only the reserved fail-closed TPM method, so
        // a TPM slot is genuinely unimplemented on this build. With `unlock-tpm`
        // on, a missing TPM method just means none was registered for this open
        // (e.g. no device), which the generic arm reports.
        #[cfg(not(feature = "unlock-tpm"))]
        MethodKind::Tpm => tracing::warn!(
            slot_id = slot.slot_id,
            "skipping tpm slot: not implemented (fail-closed)"
        ),
        other => tracing::warn!(
            slot_id = slot.slot_id,
            method = %other,
            "skipping slot: no configured unlock method"
        ),
    }
}

fn log_unavailable_method(slot: &Slot, log: SlotLog) {
    if log == SlotLog::Open {
        tracing::debug!(
            slot_id = slot.slot_id,
            method = %slot.method,
            "slot method unavailable"
        );
    }
}

fn rewrap_slots(
    parsed: &ParsedBundle,
    methods: &MethodRegistry<'_>,
    kek: &MasterKek,
    header_aad: &[u8],
) -> Result<Vec<Slot>, SealError> {
    let mut slots = Vec::with_capacity(parsed.body.slots.len());
    for slot in &parsed.body.slots {
        let method = methods.get(slot.method).ok_or(SealError::NoSlotOpened)?;
        if !method.available() {
            return Err(SealError::NoSlotOpened);
        }
        let (params, wrap) = method.wrap_kek(kek, header_aad, slot.slot_id)?;
        slots.push(Slot {
            slot_id: slot.slot_id,
            method: slot.method,
            label: slot.label.clone(),
            created_unix: slot.created_unix,
            params,
            wrap,
        });
    }
    Ok(slots)
}

/// Encrypt the cred map under the KEK into a [`SealedPayload`].
fn encrypt_payload(
    kek: &MasterKek,
    header_aad: &[u8],
    payload: &CredBundle,
) -> Result<SealedPayload, SealError> {
    let plaintext =
        Zeroizing::new(serde_json::to_vec(payload).map_err(|e| SealError::Payload(e.to_string()))?);
    let nonce = aead::fresh_nonce();
    let ciphertext = aead::seal(kek.as_bytes(), &nonce, header_aad, &plaintext)?;
    Ok(SealedPayload {
        nonce: B64Bytes(nonce.to_vec()),
        ciphertext: B64Bytes(ciphertext),
    })
}

/// Decrypt the [`SealedPayload`] under the KEK back into a [`CredBundle`].
fn decrypt_payload(
    kek: &MasterKek,
    header_aad: &[u8],
    payload: &SealedPayload,
) -> Result<CredBundle, SealError> {
    let nonce: [u8; aead::NONCE_LEN] = payload
        .nonce
        .0
        .as_slice()
        .try_into()
        .map_err(|_| SealError::Format("bad payload nonce length".into()))?;
    let plaintext = aead::open(kek.as_bytes(), &nonce, header_aad, &payload.ciphertext.0)?;
    serde_json::from_slice(&plaintext).map_err(|e| SealError::Payload(e.to_string()))
}

/// A registry of configured unlock methods, keyed by [`MethodKind`].
///
/// The broker builds this from config at startup (which method has the phrase /
/// recipient / key file this boot). `open_bundle` consults it per slot.
#[derive(Default)]
pub struct MethodRegistry<'a> {
    age_yubikey: Option<&'a dyn UnlockMethod>,
    bip39: Option<&'a dyn UnlockMethod>,
    passphrase: Option<&'a dyn UnlockMethod>,
    tpm: Option<&'a dyn UnlockMethod>,
}

impl<'a> MethodRegistry<'a> {
    /// An empty registry (nothing available).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a method under its kind (last registration wins).
    #[must_use]
    pub fn with(mut self, method: &'a dyn UnlockMethod) -> Self {
        match method.kind() {
            MethodKind::AgeYubikey => self.age_yubikey = Some(method),
            MethodKind::Bip39 => self.bip39 = Some(method),
            MethodKind::Passphrase => self.passphrase = Some(method),
            MethodKind::Tpm => self.tpm = Some(method),
        }
        self
    }

    /// The configured method for `kind`, if any.
    #[must_use]
    pub fn get(&self, kind: MethodKind) -> Option<&'a dyn UnlockMethod> {
        match kind {
            MethodKind::AgeYubikey => self.age_yubikey,
            MethodKind::Bip39 => self.bip39,
            MethodKind::Passphrase => self.passphrase,
            MethodKind::Tpm => self.tpm,
        }
    }
}

// The bundle integration tests exercise both the bip39 and passphrase slots, so they
// build only when both method features are on (e.g. `--all-features`). The
// per-method unit tests in `unlock::{bip39,passphrase,...}` cover each slot under its
// own feature; the container/aead/cred tests are feature-independent.
#[cfg(all(test, feature = "unlock-bip39"))]
mod tests;
