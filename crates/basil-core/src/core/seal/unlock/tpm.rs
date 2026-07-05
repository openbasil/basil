// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! TPM2 sealed-bundle unlock slot (§3.1 / §9).
//!
//! Two builds, one fail-closed contract:
//!
//! * **Without** the `unlock-tpm` feature this module exposes a *reserved*
//!   [`TpmMethod`] whose `recover_kek`/`wrap_kek` both return
//!   [`UnlockError::NotImplemented`], so a `Tpm` slot can never silently open or
//!   be created on a build that lacks TPM support.
//! * **With** `unlock-tpm` it exposes the real [`TpmMethod`]: a pure-Rust TPM2
//!   orchestrator (built on the zero-dependency `tpm2-protocol` codec, talking to
//!   `/dev/tpmrm0` over a plain `std::fs::File`) that seals a 32-byte slot key
//!   into a keyed-hash object under a SHA-256 `PolicyPCR`, then `TPM2_Unseal`s it
//!   under the same PCR policy to AES-256-GCM-unwrap the master KEK.
//!
//! Either way every fallible step returns a `Result`; there is no
//! `unwrap`/`expect`/panicking index on any path (§1.3).

#[cfg(not(feature = "unlock-tpm"))]
mod reserved {
    use super::super::super::MasterKek;
    use super::super::super::format::{KekWrap, MethodKind, MethodParams, Slot};
    use super::super::{UnlockError, UnlockMethod};

    /// Reserved TPM method: always fails closed (feature `unlock-tpm` off).
    #[derive(Debug, Default, Clone, Copy)]
    pub struct TpmMethod;

    impl UnlockMethod for TpmMethod {
        fn kind(&self) -> MethodKind {
            MethodKind::Tpm
        }

        fn available(&self) -> bool {
            // Never usable on a build without TPM support.
            false
        }

        fn recover_kek(&self, _slot: &Slot, _header_aad: &[u8]) -> Result<MasterKek, UnlockError> {
            Err(UnlockError::NotImplemented(MethodKind::Tpm))
        }

        fn wrap_kek(
            &self,
            _kek: &MasterKek,
            _header_aad: &[u8],
            _slot_id: u32,
        ) -> Result<(MethodParams, KekWrap), UnlockError> {
            Err(UnlockError::NotImplemented(MethodKind::Tpm))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::core::seal::format::{B64Bytes, TpmPcrSelection};

        #[test]
        fn tpm_is_fail_closed() {
            let m = TpmMethod;
            assert!(!m.available());
            assert!(matches!(
                m.wrap_kek(&MasterKek::generate(), b"aad", 0),
                Err(UnlockError::NotImplemented(MethodKind::Tpm))
            ));
            let slot = Slot {
                slot_id: 0,
                method: MethodKind::Tpm,
                label: "tpm".into(),
                created_unix: 0,
                params: MethodParams::Tpm {
                    public: B64Bytes(Vec::new()),
                    private: B64Bytes(Vec::new()),
                    pcrs: TpmPcrSelection {
                        bank: "sha256".into(),
                        pcrs: vec![0, 2, 4, 7],
                    },
                    name_alg: "sha256".into(),
                    srk_template: "ecc-p256-srk-v1".into(),
                },
                wrap: KekWrap {
                    nonce: B64Bytes(Vec::new()),
                    ciphertext: B64Bytes(Vec::new()),
                },
            };
            assert!(matches!(
                m.recover_kek(&slot, b"aad"),
                Err(UnlockError::NotImplemented(MethodKind::Tpm))
            ));
        }
    }
}

#[cfg(not(feature = "unlock-tpm"))]
pub use reserved::TpmMethod;

#[cfg(feature = "unlock-tpm")]
mod active {
    use crate::core::seal::MasterKek;
    use crate::core::seal::aead::{self, NONCE_LEN};
    use crate::core::seal::format::{
        B64Bytes, KekWrap, MethodKind, MethodParams, Slot, TpmPcrSelection,
    };
    // The TPM slot reuses the shared KEK-wrap AAD helper (`header || slot_id`,
    // §2.4) so every slot kind binds its wrap identically.
    use crate::core::seal::unlock::kdf::wrap_aad;
    use crate::core::seal::unlock::{UnlockError, UnlockMethod};

    /// The fixed, deterministic SRK template identifier stored in every TPM slot:
    /// an ECC NIST-P256 storage primary under the owner hierarchy. Recovery
    /// rebuilds the byte-identical template so `TPM2_CreatePrimary` regenerates
    /// the same Storage Root Key and can load the sealed object.
    pub(super) const SRK_TEMPLATE_ID: &str = "ecc-p256-srk-v1";
    /// Object name / policy hash algorithm for the sealed keyed-hash object.
    pub(super) const NAME_ALG: &str = "sha256";
    /// PCR bank the seal binds to.
    const PCR_BANK: &str = "sha256";
    /// Default PCR selection bound by the `PolicyPCR` (firmware, config, boot
    /// manager, secure-boot state).
    const DEFAULT_PCRS: &[u32] = &[0, 2, 4, 7];

    /// Real TPM2 unlock method (feature `unlock-tpm`).
    ///
    /// Holds the PCR selection a *new* slot will bind to; recovery uses the
    /// selection recorded in the slot, so a default instance can recover any slot.
    #[derive(Debug, Clone)]
    pub struct TpmMethod {
        pcrs: TpmPcrSelection,
    }

    impl TpmMethod {
        /// Build with an explicit PCR selection (used by `init` / add-slot).
        #[must_use]
        pub const fn new(pcrs: TpmPcrSelection) -> Self {
            Self { pcrs }
        }

        /// Build with the default SHA-256 PCR selection (PCRs 0, 2, 4, 7).
        #[must_use]
        pub fn new_default() -> Self {
            Self {
                pcrs: TpmPcrSelection {
                    bank: PCR_BANK.to_owned(),
                    pcrs: DEFAULT_PCRS.to_vec(),
                },
            }
        }

        /// Build from an operator-supplied PCR config (bank name + index list),
        /// used by `bundle init --tpm`. Recovery reads the selection recorded in
        /// the slot, so the bank/indices here only bind a *newly created* slot.
        #[must_use]
        pub const fn from_pcr_config(bank: String, pcrs: Vec<u32>) -> Self {
            Self {
                pcrs: TpmPcrSelection { bank, pcrs },
            }
        }
    }

    impl Default for TpmMethod {
        fn default() -> Self {
            Self::new_default()
        }
    }

    impl UnlockMethod for TpmMethod {
        fn kind(&self) -> MethodKind {
            MethodKind::Tpm
        }

        fn available(&self) -> bool {
            crate::core::tpm_device_present()
        }

        fn recover_kek(&self, slot: &Slot, header_aad: &[u8]) -> Result<MasterKek, UnlockError> {
            let MethodParams::Tpm {
                public,
                private,
                pcrs,
                ..
            } = &slot.params
            else {
                return Err(UnlockError::ParamsMismatch("expected tpm params".into()));
            };
            // `unseal_slot_key` opens the TPM device first, so a host without a
            // TPM fails with `Unavailable` before any slot bytes are interpreted.
            let slot_key = device::unseal_slot_key(&public.0, &private.0, pcrs)?;
            unwrap_with_slot_key(&slot_key, &slot.wrap, header_aad, slot.slot_id)
        }

        fn wrap_kek(
            &self,
            kek: &MasterKek,
            header_aad: &[u8],
            slot_id: u32,
        ) -> Result<(MethodParams, KekWrap), UnlockError> {
            let slot_key = aead::fresh_key();
            let (public, private) = device::seal_slot_key(&slot_key, &self.pcrs)?;
            let wrap = wrap_with_slot_key(&slot_key, kek, header_aad, slot_id)?;
            let params = MethodParams::Tpm {
                public: B64Bytes(public),
                private: B64Bytes(private),
                pcrs: self.pcrs.clone(),
                name_alg: NAME_ALG.to_owned(),
                srk_template: SRK_TEMPLATE_ID.to_owned(),
            };
            Ok((params, wrap))
        }
    }

    /// AES-256-GCM-wrap the master `kek` under the TPM-sealed 32-byte `slot_key`.
    ///
    /// The testable crypto seam shared by `wrap_kek`: it mirrors the bip39 slot's
    /// wrap so the container AAD discipline (`header || slot_id`, §2.4) is byte
    /// identical across slot kinds.
    fn wrap_with_slot_key(
        slot_key: &[u8; 32],
        kek: &MasterKek,
        header_aad: &[u8],
        slot_id: u32,
    ) -> Result<KekWrap, UnlockError> {
        let nonce = aead::fresh_nonce();
        let aad = wrap_aad(header_aad, slot_id);
        let ciphertext = aead::seal(slot_key, &nonce, &aad, kek.as_bytes())
            .map_err(|e| UnlockError::Crypto(e.to_string()))?;
        Ok(KekWrap {
            nonce: B64Bytes(nonce.to_vec()),
            ciphertext: B64Bytes(ciphertext),
        })
    }

    /// AES-256-GCM-unwrap the master KEK from `wrap` using the TPM-unsealed
    /// `slot_key`. Fails closed (`AuthFailed`) on any tamper of the wrap.
    fn unwrap_with_slot_key(
        slot_key: &[u8; 32],
        wrap: &KekWrap,
        header_aad: &[u8],
        slot_id: u32,
    ) -> Result<MasterKek, UnlockError> {
        let nonce: [u8; NONCE_LEN] = wrap
            .nonce
            .0
            .as_slice()
            .try_into()
            .map_err(|_| UnlockError::ParamsMismatch("bad wrap nonce length".into()))?;
        let aad = wrap_aad(header_aad, slot_id);
        let kek_bytes = aead::open(slot_key, &nonce, &aad, &wrap.ciphertext.0)
            .map_err(|_| UnlockError::AuthFailed)?;
        MasterKek::from_slice(&kek_bytes)
            .ok_or_else(|| UnlockError::Crypto("unwrapped KEK has wrong length".into()))
    }

    // ===================================================================
    // mod device: the ONLY code that talks to the chip.
    // (Implemented by the TPM-wire pass; keep the two `pub(super)` signatures
    //  stable: the rest of this module is built against them.)
    // ===================================================================
    /// TPM2 wire orchestration over the `tpm2-protocol` codec. Transport is a
    /// single transceive on `/dev/tpmrm0` (fallback `/dev/tpm0`) via a plain
    /// `std::fs::File`. No panics: device/IO errors map to
    /// [`UnlockError::Unavailable`], codec/protocol errors to
    /// [`UnlockError::Crypto`].
    mod device {
        use super::TpmPcrSelection;
        use super::UnlockError;

        use rand::RngCore as _;
        use sha2::{Digest, Sha256};
        use std::fs::{File, OpenOptions};
        use std::io::{Read, Write};
        use zeroize::Zeroizing;

        use tpm2_protocol::basic::{Tpm2b, TpmHandle, TpmUint16, TpmUint32};
        use tpm2_protocol::constant::{MAX_DIGEST_SIZE, TPM_PCR_SELECT_MAX};
        use tpm2_protocol::data::{
            Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce, Tpm2bPrivate, Tpm2bPublic,
            Tpm2bPublicWire, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmAlgId, TpmCc,
            TpmEccCurve, TpmRc, TpmRcBase, TpmRh, TpmSe, TpmSt, TpmaObject, TpmlDigest,
            TpmlPcrSelection, TpmsAuthCommand, TpmsEccParms, TpmsEccPoint, TpmsKeyedhashParms,
            TpmsPcrSelect, TpmsPcrSelection, TpmsSensitiveCreate, TpmtEccScheme, TpmtKdfScheme,
            TpmtKeyedhashScheme, TpmtPublic, TpmtSymDef, TpmuKeyedhashScheme, TpmuPublicId,
            TpmuPublicIdView, TpmuPublicParms, TpmuPublicParmsView, TpmuSymKeyBits, TpmuSymMode,
        };
        use tpm2_protocol::frame::{
            TpmCreateCommand, TpmCreatePrimaryCommand, TpmFlushContextCommand, TpmFrame,
            TpmLoadCommand, TpmPcrReadCommand, TpmPolicyPcrCommand, TpmResponse,
            TpmStartAuthSessionCommand, TpmUnsealCommand, tpm_marshal_command,
        };
        use tpm2_protocol::{TpmField, TpmMarshal, TpmWriter};

        // A single TPM command or response frame fits comfortably in this buffer;
        // the resource manager returns one complete response per read.
        const TPM_IO_BUF: usize = 4096;
        // Minimum sizeofSelect for a PC-client PCR selection bitmap (PCR 0..23).
        const PCR_SELECT_MIN: usize = 3;

        // ---- error helpers ------------------------------------------------

        fn crypto<E: core::fmt::Display>(context: &str, err: E) -> UnlockError {
            UnlockError::Crypto(format!("{context}: {err}"))
        }

        fn crypto_msg(message: &str) -> UnlockError {
            UnlockError::Crypto(message.to_owned())
        }

        fn unavailable<E: core::fmt::Display>(context: &str, err: E) -> UnlockError {
            UnlockError::Unavailable(format!("{context}: {err}"))
        }

        // ---- transport ----------------------------------------------------

        /// A single open handle to the kernel TPM device, held for the whole
        /// duration of a seal or unseal orchestration.
        ///
        /// This is load-bearing: `/dev/tpmrm0` is the kernel TPM **resource
        /// manager**, which scopes transient object and session handles to the
        /// open file description and flushes them when it is closed. Opening a
        /// fresh handle per command would discard the SRK created by
        /// `CreatePrimary` before `Create`/`Load` could use it (the chip would
        /// reject the now-dangling handle). All commands in one orchestration
        /// therefore share this single `TpmDevice`.
        pub(super) struct TpmDevice {
            file: File,
        }

        impl TpmDevice {
            /// Open the kernel TPM device, preferring the resource-manager node.
            pub(super) fn open() -> Result<Self, UnlockError> {
                let file = ["/dev/tpmrm0", "/dev/tpm0"]
                    .into_iter()
                    .find_map(|path| OpenOptions::new().read(true).write(true).open(path).ok())
                    .ok_or_else(|| {
                        UnlockError::Unavailable(
                            "no TPM device node (/dev/tpmrm0 or /dev/tpm0)".to_owned(),
                        )
                    })?;
                Ok(Self { file })
            }

            /// Write one command frame and read the single complete response on
            /// the persistent handle.
            fn transceive(&mut self, command: &[u8]) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
                self.file
                    .write_all(command)
                    .map_err(|e| unavailable("tpm write", e))?;
                let mut buffer = Zeroizing::new([0u8; TPM_IO_BUF]);
                let read = self
                    .file
                    .read(buffer.as_mut_slice())
                    .map_err(|e| unavailable("tpm read", e))?;
                let frame = buffer
                    .get(..read)
                    .ok_or_else(|| crypto_msg("tpm response exceeds buffer"))?;
                Ok(Zeroizing::new(frame.to_vec()))
            }

            /// Marshal `command` and transceive it on the persistent handle. The
            /// marshal buffer is zeroized on drop so command parameters carrying
            /// secret material never linger.
            fn transact<C: TpmFrame>(
                &mut self,
                command: &C,
                tag: TpmSt,
                sessions: &[TpmsAuthCommand],
            ) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
                let mut buffer = Zeroizing::new([0u8; TPM_IO_BUF]);
                let written = {
                    let mut writer = TpmWriter::new(buffer.as_mut_slice());
                    tpm_marshal_command(command, tag, sessions, &mut writer)
                        .map_err(|e| crypto("tpm command marshal", e))?;
                    writer.len()
                };
                let frame = buffer
                    .get(..written)
                    .ok_or_else(|| crypto_msg("tpm command exceeds buffer"))?;
                self.transceive(frame)
            }
        }

        /// Cast a response frame, require a success response code, and validate it
        /// for command code `cc`.
        fn check_response(frame: &[u8], cc: TpmCc) -> Result<&TpmResponse, UnlockError> {
            let response = TpmResponse::cast(frame).map_err(|e| crypto("tpm response frame", e))?;
            let rc = response.rc().map_err(|e| crypto("tpm response code", e))?;
            if !matches!(rc, TpmRc::Fmt0(TpmRcBase::Success)) {
                return Err(UnlockError::Crypto(format!(
                    "tpm command {cc} failed: rc {:#010x} ({rc})",
                    rc.value()
                )));
            }
            response
                .validate(cc)
                .map_err(|e| crypto("tpm response validate", e))?;
            Ok(response)
        }

        // ---- response body parsing ----------------------------------------

        /// Read the handle at `index` from a response handle area.
        fn response_handle(response: &TpmResponse, index: usize) -> Result<u32, UnlockError> {
            let body = response.body();
            let start = index
                .checked_mul(4)
                .ok_or_else(|| crypto_msg("tpm handle index overflow"))?;
            let end = start
                .checked_add(4)
                .ok_or_else(|| crypto_msg("tpm handle index overflow"))?;
            let bytes = body
                .get(start..end)
                .ok_or_else(|| crypto_msg("tpm response handle missing"))?;
            let array: [u8; 4] = bytes
                .try_into()
                .map_err(|_| crypto_msg("tpm response handle malformed"))?;
            Ok(u32::from_be_bytes(array))
        }

        /// Return the parameter area, skipping the handle area and (for
        /// session-tagged responses) the leading `parameterSize` field and the
        /// trailing response authorization area.
        fn response_parameters(
            response: &TpmResponse,
            handle_count: usize,
        ) -> Result<&[u8], UnlockError> {
            let body = response.body();
            let handle_bytes = handle_count
                .checked_mul(4)
                .ok_or_else(|| crypto_msg("tpm handle area overflow"))?;
            let after_handles = body
                .get(handle_bytes..)
                .ok_or_else(|| crypto_msg("tpm response handle area truncated"))?;
            let tag = response.tag().map_err(|e| crypto("tpm response tag", e))?;
            if tag != TpmSt::Sessions {
                return Ok(after_handles);
            }
            let size_bytes = after_handles
                .get(..4)
                .ok_or_else(|| crypto_msg("tpm parameter size missing"))?;
            let array: [u8; 4] = size_bytes
                .try_into()
                .map_err(|_| crypto_msg("tpm parameter size malformed"))?;
            let size = usize::try_from(u32::from_be_bytes(array))
                .map_err(|_| crypto_msg("tpm parameter size too large"))?;
            let end = size
                .checked_add(4)
                .ok_or_else(|| crypto_msg("tpm parameter size overflow"))?;
            after_handles
                .get(4..end)
                .ok_or_else(|| crypto_msg("tpm parameter area truncated"))
        }

        /// Total wire length (size prefix + payload) of the leading TPM2B.
        fn tpm2b_end(buffer: &[u8]) -> Result<usize, UnlockError> {
            let length_bytes = buffer
                .get(..2)
                .ok_or_else(|| crypto_msg("tpm2b length missing"))?;
            let array: [u8; 2] = length_bytes
                .try_into()
                .map_err(|_| crypto_msg("tpm2b length malformed"))?;
            usize::from(u16::from_be_bytes(array))
                .checked_add(2)
                .ok_or_else(|| crypto_msg("tpm2b length overflow"))
        }

        /// Split off the leading TPM2B (including its size prefix) and the rest.
        fn split_tpm2b(buffer: &[u8]) -> Result<(&[u8], &[u8]), UnlockError> {
            let end = tpm2b_end(buffer)?;
            let whole = buffer
                .get(..end)
                .ok_or_else(|| crypto_msg("tpm2b truncated"))?;
            let rest = buffer
                .get(end..)
                .ok_or_else(|| crypto_msg("tpm2b remainder truncated"))?;
            Ok((whole, rest))
        }

        /// Borrow the payload bytes of the leading TPM2B (excluding its prefix).
        fn tpm2b_payload(buffer: &[u8]) -> Result<&[u8], UnlockError> {
            let end = tpm2b_end(buffer)?;
            buffer
                .get(2..end)
                .ok_or_else(|| crypto_msg("tpm2b payload truncated"))
        }

        /// Marshal a single value standalone into a fresh buffer.
        fn marshal_value<T: TpmMarshal>(value: &T) -> Result<Vec<u8>, UnlockError> {
            let mut buffer = [0u8; TPM_IO_BUF];
            let written = {
                let mut writer = TpmWriter::new(buffer.as_mut_slice());
                value
                    .marshal(&mut writer)
                    .map_err(|e| crypto("tpm value marshal", e))?;
                writer.len()
            };
            let bytes = buffer
                .get(..written)
                .ok_or_else(|| crypto_msg("tpm value exceeds buffer"))?;
            Ok(bytes.to_vec())
        }

        // ---- PCR selection ------------------------------------------------

        /// Build a single-bank SHA-256 `TPML_PCR_SELECTION` for `pcrs`.
        fn pcr_selection_list(pcrs: &TpmPcrSelection) -> Result<TpmlPcrSelection, UnlockError> {
            if pcrs.bank != "sha256" {
                return Err(UnlockError::ParamsMismatch(format!(
                    "unsupported tpm pcr bank: {}",
                    pcrs.bank
                )));
            }
            let bitmap = pcr_bitmap(&pcrs.pcrs)?;
            let select = TpmsPcrSelect::try_from(bitmap.as_slice())
                .map_err(|e| crypto("tpm pcr select", e))?;
            let selection = TpmsPcrSelection {
                hash: TpmAlgId::Sha256,
                pcr_select: select,
            };
            let mut list = TpmlPcrSelection::new();
            list.try_push(selection)
                .map_err(|e| crypto("tpm pcr selection list", e))?;
            Ok(list)
        }

        /// Encode PCR indices as a little-endian-within-byte selection bitmap.
        fn pcr_bitmap(pcrs: &[u32]) -> Result<Vec<u8>, UnlockError> {
            let max_pcr = pcrs.iter().copied().max().unwrap_or_default();
            let span = usize::try_from(max_pcr / 8)
                .map_err(|_| crypto_msg("tpm pcr index too large"))?
                .checked_add(1)
                .ok_or_else(|| crypto_msg("tpm pcr index overflow"))?;
            let bytes = span.max(PCR_SELECT_MIN);
            if bytes > usize::from(TPM_PCR_SELECT_MAX) {
                return Err(crypto_msg("tpm pcr index out of range"));
            }
            let mut bitmap = vec![0u8; bytes];
            for &pcr in pcrs {
                let index =
                    usize::try_from(pcr / 8).map_err(|_| crypto_msg("tpm pcr index too large"))?;
                let bit = 1u8
                    .checked_shl(pcr % 8)
                    .ok_or_else(|| crypto_msg("tpm pcr bit overflow"))?;
                let slot = bitmap
                    .get_mut(index)
                    .ok_or_else(|| crypto_msg("tpm pcr index out of range"))?;
                *slot |= bit;
            }
            Ok(bitmap)
        }

        /// `TPM2_PolicyPCR` auth digest: `H(0^32 || TPM_CC_PolicyPCR || pcrs || pcrDigest)`.
        fn policy_pcr_digest(selection_bytes: &[u8], pcr_digest: &[u8; 32]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update([0u8; 32]);
            hasher.update(TpmCc::PolicyPcr.value().to_be_bytes());
            hasher.update(selection_bytes);
            hasher.update(pcr_digest);
            hasher.finalize().into()
        }

        // ---- fixed templates ----------------------------------------------

        /// One `TPM_RS_PW` password session with empty (owner) authorization.
        fn pw_auth() -> TpmsAuthCommand {
            TpmsAuthCommand {
                session_handle: TpmHandle::new(TpmRh::Pw.value()),
                ..TpmsAuthCommand::default()
            }
        }

        /// A `TPMT_SYM_DEF` selecting no symmetric algorithm.
        const fn symmetric_null() -> TpmtSymDef {
            TpmtSymDef {
                algorithm: TpmAlgId::Null,
                key_bits: TpmuSymKeyBits::Null,
                mode: TpmuSymMode::Null,
            }
        }

        /// Keyed-hash parameters for a sealed-data object (scheme = NULL).
        const fn keyedhash_parms() -> TpmuPublicParms {
            TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                scheme: TpmtKeyedhashScheme {
                    scheme: TpmAlgId::Null,
                    details: TpmuKeyedhashScheme::Null,
                },
            })
        }

        /// The fixed, deterministic ECC NIST-P256 storage-parent (SRK) template.
        fn srk_in_public() -> Tpm2bPublic {
            let symmetric = TpmtSymDef {
                algorithm: TpmAlgId::Aes,
                key_bits: TpmuSymKeyBits::Aes(TpmUint16::new(128)),
                mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
            };
            let parameters = TpmuPublicParms::Ecc(TpmsEccParms {
                symmetric,
                scheme: TpmtEccScheme::default(),
                curve_id: TpmEccCurve::NistP256,
                kdf: TpmtKdfScheme::default(),
            });
            let attributes = TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT
                | TpmaObject::SENSITIVE_DATA_ORIGIN
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::RESTRICTED
                | TpmaObject::DECRYPT;
            Tpm2bPublic::from(TpmtPublic {
                object_type: TpmAlgId::Ecc,
                name_alg: TpmAlgId::Sha256,
                object_attributes: attributes,
                auth_policy: Tpm2bDigest::new(),
                parameters,
                unique: TpmuPublicId::Ecc(TpmsEccPoint::default()),
            })
        }

        // ---- individual commands ------------------------------------------

        /// `TPM2_CreatePrimary` of the deterministic SRK under the owner hierarchy.
        fn create_primary(dev: &mut TpmDevice) -> Result<u32, UnlockError> {
            let command = TpmCreatePrimaryCommand {
                handles: [TpmHandle::new(TpmRh::Owner.value())],
                in_sensitive: Tpm2bSensitiveCreate::from(TpmsSensitiveCreate::default()),
                in_public: srk_in_public(),
                outside_info: Tpm2bData::new(),
                creation_pcr: TpmlPcrSelection::new(),
            };
            let frame = dev.transact(&command, TpmSt::Sessions, &[pw_auth()])?;
            let response = check_response(&frame, TpmCc::CreatePrimary)?;
            response_handle(response, 0)
        }

        /// `TPM2_PCR_Read` the selection and return `SHA256(concat(values))`.
        fn read_pcr_digest(
            dev: &mut TpmDevice,
            selection: &TpmlPcrSelection,
        ) -> Result<[u8; 32], UnlockError> {
            let command = TpmPcrReadCommand {
                handles: [],
                pcr_selection_in: *selection,
            };
            let frame = dev.transact(&command, TpmSt::NoSessions, &[])?;
            let response = check_response(&frame, TpmCc::PcrRead)?;
            let parameters = response_parameters(response, 0)?;
            let (_, rest) = <TpmUint32 as TpmField>::cast_prefix_field(parameters)
                .map_err(|e| crypto("tpm pcr counter", e))?;
            let (_, rest) = <TpmlPcrSelection as TpmField>::cast_prefix_field(rest)
                .map_err(|e| crypto("tpm pcr selection", e))?;
            let (values, _) = <TpmlDigest as TpmField>::cast_prefix_field(rest)
                .map_err(|e| crypto("tpm pcr values", e))?;
            let mut hasher = Sha256::new();
            for value in values.items::<Tpm2b<MAX_DIGEST_SIZE>>() {
                let digest = value.map_err(|e| crypto("tpm pcr value", e))?;
                hasher.update(digest.data());
            }
            Ok(hasher.finalize().into())
        }

        /// `TPM2_Create` a keyed-hash sealed-data object holding `slot_key` under
        /// the `PolicyPCR` digest. Returns `(public, private)` blob bytes.
        fn create_sealed(
            dev: &mut TpmDevice,
            parent: u32,
            slot_key: &[u8; 32],
            policy: &[u8; 32],
        ) -> Result<(Vec<u8>, Vec<u8>), UnlockError> {
            let sensitive = TpmsSensitiveCreate {
                data: Tpm2bSensitiveData::try_from(slot_key.as_slice())
                    .map_err(|e| crypto("tpm seal sensitive", e))?,
                ..TpmsSensitiveCreate::default()
            };
            let auth_policy = Tpm2bDigest::try_from(policy.as_slice())
                .map_err(|e| crypto("tpm policy digest", e))?;
            let public = TpmtPublic {
                object_type: TpmAlgId::KeyedHash,
                name_alg: TpmAlgId::Sha256,
                object_attributes: TpmaObject::FIXED_TPM
                    | TpmaObject::FIXED_PARENT
                    | TpmaObject::ADMIN_WITH_POLICY,
                auth_policy,
                parameters: keyedhash_parms(),
                unique: TpmuPublicId::KeyedHash(Tpm2bDigest::new()),
            };
            let command = TpmCreateCommand {
                handles: [TpmHandle::new(parent)],
                in_sensitive: Tpm2bSensitiveCreate::from(sensitive),
                in_public: Tpm2bPublic::from(public),
                outside_info: Tpm2bData::new(),
                creation_pcr: TpmlPcrSelection::new(),
            };
            let frame = dev.transact(&command, TpmSt::Sessions, &[pw_auth()])?;
            let response = check_response(&frame, TpmCc::Create)?;
            let parameters = response_parameters(response, 0)?;
            let (private, rest) = split_tpm2b(parameters)?;
            let (public_blob, _) = split_tpm2b(rest)?;
            Ok((public_blob.to_vec(), private.to_vec()))
        }

        /// Rebuild the owned `TPM2B_PUBLIC` for a sealed object from stored bytes,
        /// verifying it re-marshals byte-identically (so `Load` recomputes the
        /// same object name).
        fn reconstruct_public(public: &[u8]) -> Result<Tpm2bPublic, UnlockError> {
            let wire = Tpm2bPublicWire::cast(public).map_err(|e| crypto("tpm public area", e))?;
            let view = wire.inner().map_err(|e| crypto("tpm public inner", e))?;
            if view.object_type != TpmAlgId::KeyedHash {
                return Err(crypto_msg("tpm sealed object is not a keyed-hash object"));
            }
            if !matches!(view.parameters, TpmuPublicParmsView::KeyedHash(_)) {
                return Err(crypto_msg(
                    "tpm sealed object parameters are not keyed-hash",
                ));
            }
            let unique = match view.unique {
                TpmuPublicIdView::KeyedHash(digest) => Tpm2bDigest::try_from(digest.data())
                    .map_err(|e| crypto("tpm public unique", e))?,
                _ => return Err(crypto_msg("tpm sealed object unique is not keyed-hash")),
            };
            let auth_policy = Tpm2bDigest::try_from(view.auth_policy.data())
                .map_err(|e| crypto("tpm public auth policy", e))?;
            let rebuilt = Tpm2bPublic::from(TpmtPublic {
                object_type: TpmAlgId::KeyedHash,
                name_alg: view.name_alg,
                object_attributes: view.object_attributes,
                auth_policy,
                parameters: keyedhash_parms(),
                unique: TpmuPublicId::KeyedHash(unique),
            });
            if marshal_value(&rebuilt)?.as_slice() != public {
                return Err(crypto_msg("tpm public area did not round-trip"));
            }
            Ok(rebuilt)
        }

        /// Rebuild the owned `TPM2B_PRIVATE` from stored bytes.
        fn reconstruct_private(private: &[u8]) -> Result<Tpm2bPrivate, UnlockError> {
            Tpm2bPrivate::try_from(tpm2b_payload(private)?)
                .map_err(|e| crypto("tpm private blob", e))
        }

        /// `TPM2_Load` the sealed object under `parent`; returns its handle.
        fn load_object(
            dev: &mut TpmDevice,
            parent: u32,
            in_public: &Tpm2bPublic,
            in_private: &Tpm2bPrivate,
        ) -> Result<u32, UnlockError> {
            let command = TpmLoadCommand {
                handles: [TpmHandle::new(parent)],
                in_private: *in_private,
                in_public: in_public.clone(),
            };
            let frame = dev.transact(&command, TpmSt::Sessions, &[pw_auth()])?;
            let response = check_response(&frame, TpmCc::Load)?;
            response_handle(response, 0)
        }

        /// `TPM2_StartAuthSession` for a SHA-256 policy session; returns its handle.
        fn start_policy_session(dev: &mut TpmDevice) -> Result<u32, UnlockError> {
            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let command = TpmStartAuthSessionCommand {
                handles: [
                    TpmHandle::new(TpmRh::Null.value()),
                    TpmHandle::new(TpmRh::Null.value()),
                ],
                nonce_caller: Tpm2bNonce::try_from(nonce.as_slice())
                    .map_err(|e| crypto("tpm session nonce", e))?,
                encrypted_salt: Tpm2bEncryptedSecret::new(),
                session_type: TpmSe::Policy,
                symmetric: symmetric_null(),
                auth_hash: TpmAlgId::Sha256,
            };
            let frame = dev.transact(&command, TpmSt::NoSessions, &[])?;
            let response = check_response(&frame, TpmCc::StartAuthSession)?;
            response_handle(response, 0)
        }

        /// `TPM2_PolicyPCR` over `selection` with an empty digest (current PCRs).
        fn policy_pcr(
            dev: &mut TpmDevice,
            session: u32,
            selection: &TpmlPcrSelection,
        ) -> Result<(), UnlockError> {
            let command = TpmPolicyPcrCommand {
                handles: [TpmHandle::new(session)],
                pcr_digest: Tpm2bDigest::new(),
                pcrs: *selection,
            };
            let frame = dev.transact(&command, TpmSt::NoSessions, &[])?;
            check_response(&frame, TpmCc::PolicyPcr)?;
            Ok(())
        }

        /// `TPM2_Unseal` the object under the policy session; returns 32 bytes.
        fn unseal_object(
            dev: &mut TpmDevice,
            object: u32,
            session: u32,
        ) -> Result<Zeroizing<[u8; 32]>, UnlockError> {
            let command = TpmUnsealCommand {
                handles: [TpmHandle::new(object)],
            };
            let auth = TpmsAuthCommand {
                session_handle: TpmHandle::new(session),
                ..TpmsAuthCommand::default()
            };
            let frame = dev.transact(&command, TpmSt::Sessions, &[auth])?;
            let response = check_response(&frame, TpmCc::Unseal)?;
            let parameters = response_parameters(response, 0)?;
            let payload = tpm2b_payload(parameters)?;
            if payload.len() != 32 {
                return Err(UnlockError::Crypto(format!(
                    "tpm unsealed secret has wrong length: {}",
                    payload.len()
                )));
            }
            let mut secret = Zeroizing::new([0u8; 32]);
            secret.copy_from_slice(payload);
            Ok(secret)
        }

        /// `TPM2_FlushContext` for `handle` (best-effort; callers ignore errors).
        fn flush_context(dev: &mut TpmDevice, handle: u32) -> Result<(), UnlockError> {
            let command = TpmFlushContextCommand {
                handles: [],
                flush_handle: TpmHandle::new(handle),
            };
            let frame = dev.transact(&command, TpmSt::NoSessions, &[])?;
            check_response(&frame, TpmCc::FlushContext)?;
            Ok(())
        }

        // ---- orchestration ------------------------------------------------

        /// Seal `slot_key` into a TPM keyed-hash object under a SHA-256 `PolicyPCR`
        /// over `pcrs`, returning the object's marshalled
        /// `(TPM2B_PUBLIC, TPM2B_PRIVATE)` bytes.
        ///
        /// Sequence: `CreatePrimary` (deterministic ECC-P256 SRK, owner hierarchy)
        /// → `PCR_Read` the selected PCRs → compute the `PolicyPCR` auth digest →
        /// `Create` a keyed-hash object with empty `userAuth`, `adminWithPolicy`
        /// set, and `authPolicy` = that digest, sealing `slot_key` as its sensitive
        /// data → return its public/private blobs → `FlushContext` the SRK.
        pub(super) fn seal_slot_key(
            slot_key: &[u8; 32],
            pcrs: &TpmPcrSelection,
        ) -> Result<(Vec<u8>, Vec<u8>), UnlockError> {
            let selection = pcr_selection_list(pcrs)?;
            let selection_bytes = marshal_value(&selection)?;
            // One handle for the whole orchestration: the resource manager keeps
            // the SRK alive only while this device stays open (see `TpmDevice`).
            let mut dev = TpmDevice::open()?;
            let srk = create_primary(&mut dev)?;
            let result = seal_under_parent(&mut dev, srk, slot_key, &selection, &selection_bytes);
            let _ = flush_context(&mut dev, srk);
            result
        }

        fn seal_under_parent(
            dev: &mut TpmDevice,
            parent: u32,
            slot_key: &[u8; 32],
            selection: &TpmlPcrSelection,
            selection_bytes: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), UnlockError> {
            let pcr_digest = read_pcr_digest(dev, selection)?;
            let policy = policy_pcr_digest(selection_bytes, &pcr_digest);
            create_sealed(dev, parent, slot_key, &policy)
        }

        /// Recover the 32-byte slot key via `TPM2_Unseal` under the recorded
        /// `PolicyPCR`. Opens the TPM device **first**, so a host without a TPM
        /// fails with [`UnlockError::Unavailable`] before any slot bytes are
        /// interpreted.
        ///
        /// Sequence: open device → `CreatePrimary` (same deterministic SRK) →
        /// `Load` the `(public, private)` sealed object → `StartAuthSession`
        /// (POLICY, SHA-256) → `PolicyPCR` over `pcrs` → `Unseal` → the 32-byte
        /// secret → `FlushContext` the loaded object, SRK, and session.
        pub(super) fn unseal_slot_key(
            public: &[u8],
            private: &[u8],
            pcrs: &TpmPcrSelection,
        ) -> Result<Zeroizing<[u8; 32]>, UnlockError> {
            let selection = pcr_selection_list(pcrs)?;
            // Open the device (and create the SRK) before interpreting any slot
            // bytes: a host with no TPM fails `Unavailable` here, before `public`
            // and `private` are parsed. The single handle keeps the SRK, the
            // loaded object, and the policy session alive across the unseal.
            let mut dev = TpmDevice::open()?;
            let srk = create_primary(&mut dev)?;
            let result = unseal_under_parent(&mut dev, srk, public, private, &selection);
            let _ = flush_context(&mut dev, srk);
            result
        }

        fn unseal_under_parent(
            dev: &mut TpmDevice,
            parent: u32,
            public: &[u8],
            private: &[u8],
            selection: &TpmlPcrSelection,
        ) -> Result<Zeroizing<[u8; 32]>, UnlockError> {
            let in_public = reconstruct_public(public)?;
            let in_private = reconstruct_private(private)?;
            let object = load_object(dev, parent, &in_public, &in_private)?;
            let result = unseal_with_policy(dev, object, selection);
            let _ = flush_context(dev, object);
            result
        }

        fn unseal_with_policy(
            dev: &mut TpmDevice,
            object: u32,
            selection: &TpmlPcrSelection,
        ) -> Result<Zeroizing<[u8; 32]>, UnlockError> {
            let session = start_policy_session(dev)?;
            let result = run_policy_session(dev, object, session, selection);
            let _ = flush_context(dev, session);
            result
        }

        fn run_policy_session(
            dev: &mut TpmDevice,
            object: u32,
            session: u32,
            selection: &TpmlPcrSelection,
        ) -> Result<Zeroizing<[u8; 32]>, UnlockError> {
            policy_pcr(dev, session, selection)?;
            unseal_object(dev, object, session)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn fixed_aad() -> Vec<u8> {
            b"basil-tpm-test-header".to_vec()
        }

        /// The crypto seam round-trips a KEK through a known slot key without any
        /// TPM: wrap then unwrap recovers the same master KEK.
        #[test]
        fn slot_key_seam_round_trip() {
            let slot_key = [7u8; 32];
            let kek = MasterKek::generate();
            let aad = fixed_aad();
            let wrap = wrap_with_slot_key(&slot_key, &kek, &aad, 3).unwrap();
            let recovered = unwrap_with_slot_key(&slot_key, &wrap, &aad, 3).unwrap();
            assert_eq!(recovered.as_bytes(), kek.as_bytes());
        }

        /// A flipped ciphertext byte fails closed with `AuthFailed`.
        #[test]
        fn tampered_wrap_fails_closed() {
            let slot_key = [7u8; 32];
            let kek = MasterKek::generate();
            let aad = fixed_aad();
            let mut wrap = wrap_with_slot_key(&slot_key, &kek, &aad, 3).unwrap();
            wrap.ciphertext.0[0] ^= 0x01;
            assert!(matches!(
                unwrap_with_slot_key(&slot_key, &wrap, &aad, 3),
                Err(UnlockError::AuthFailed)
            ));
        }

        /// Splicing the wrap under a different slot id fails closed (the id is
        /// bound into the AAD).
        #[test]
        fn wrong_slot_id_fails_closed() {
            let slot_key = [9u8; 32];
            let kek = MasterKek::generate();
            let aad = fixed_aad();
            let wrap = wrap_with_slot_key(&slot_key, &kek, &aad, 1).unwrap();
            assert!(matches!(
                unwrap_with_slot_key(&slot_key, &wrap, &aad, 2),
                Err(UnlockError::AuthFailed)
            ));
        }

        /// On a host without a TPM device, the method reports unavailable and
        /// recovery fails closed with `Unavailable`, never panics. Skipped when
        /// a real TPM happens to be present (e.g. a developer box).
        #[test]
        fn no_tpm_is_unavailable_and_recover_fails_closed() {
            if crate::core::tpm_device_present() {
                return;
            }
            let m = TpmMethod::new_default();
            assert!(!m.available());
            let slot = Slot {
                slot_id: 0,
                method: MethodKind::Tpm,
                label: "tpm".into(),
                created_unix: 0,
                params: MethodParams::Tpm {
                    public: B64Bytes(vec![0u8; 8]),
                    private: B64Bytes(vec![0u8; 8]),
                    pcrs: TpmPcrSelection {
                        bank: "sha256".into(),
                        pcrs: vec![0, 2, 4, 7],
                    },
                    name_alg: "sha256".into(),
                    srk_template: "ecc-p256-srk-v1".into(),
                },
                wrap: KekWrap {
                    nonce: B64Bytes(vec![0u8; NONCE_LEN]),
                    ciphertext: B64Bytes(vec![0u8; 32]),
                },
            };
            assert!(matches!(
                m.recover_kek(&slot, b"hdr"),
                Err(UnlockError::Unavailable(_))
            ));
        }
    }
}

#[cfg(feature = "unlock-tpm")]
pub use active::TpmMethod;
