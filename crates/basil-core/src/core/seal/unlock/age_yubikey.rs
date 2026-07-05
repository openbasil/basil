// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! age + age-plugin-yubikey unlock slot (§3.1, feature `unlock-age-yubikey`).
//!
//! The master KEK is wrapped *to an age recipient* and recovered by *age
//! decryption*. The recipient may be:
//!
//! - a plugin recipient (`age1yubikey1…`) backed by `age-plugin-yubikey`, which
//!   drives PIN/touch on the hardware token (the production path), or
//! - a native X25519 recipient (`age1…`), used by the software tests here.
//!
//! `wrap.ciphertext` holds the binary age file; `wrap.nonce` is unused (age
//! manages its own framing). The header AAD cannot be bound *inside* the age
//! stanza, so the age ciphertext is itself bound to the bundle by being stored
//! in a slot whose presence is covered by the payload AEAD's header AAD.
//!
//! The regular unit tests cover the age round-trip with a software X25519
//! identity. The ignored hardware test
//! `age_yubikey_hardware_pin_touch_round_trip` exercises the real
//! `age-plugin-yubikey` PIN/touch path when run manually with a physical token.

use std::str::FromStr;

use age::{Decryptor, Encryptor, Identity, NoCallbacks, Recipient};

use super::super::MasterKek;
use super::super::format::{B64Bytes, KekWrap, MethodKind, MethodParams, Slot};
use super::{UnlockError, UnlockMethod};

/// An age-recipient unlock method.
///
/// Holds the recipient string (public, for wrap + availability) and zero or more
/// identities to attempt at recover time. In production the identity is a plugin
/// identity that talks to `age-plugin-yubikey`; in tests it is an X25519 secret.
pub struct AgeYubikeyMethod {
    recipient: String,
    identities: Vec<Box<dyn Identity + Send + Sync>>,
}

impl AgeYubikeyMethod {
    /// Build a wrap-only method from a recipient string (no identities). Suitable
    /// for `init` / add-slot where only the public recipient is known.
    #[must_use]
    pub fn for_recipient(recipient: impl Into<String>) -> Self {
        Self {
            recipient: recipient.into(),
            identities: Vec::new(),
        }
    }

    /// Build a method that can also *recover*, using the default plugin identity
    /// for `age-plugin-yubikey` (the production path: needs the hardware token).
    ///
    /// # Errors
    /// Returns [`UnlockError::Unavailable`] if the plugin binary is not on PATH.
    pub fn with_plugin(
        recipient: impl Into<String>,
        plugin_name: &str,
    ) -> Result<Self, UnlockError> {
        let identity = age::plugin::Identity::default_for_plugin(plugin_name);
        let plugin = age::plugin::IdentityPluginV1::new(plugin_name, &[identity], NoCallbacks)
            .map_err(|e| UnlockError::Unavailable(format!("age plugin {plugin_name}: {e}")))?;
        Ok(Self {
            recipient: recipient.into(),
            identities: vec![Box::new(plugin)],
        })
    }

    /// Attach an explicit identity (used by the software tests).
    #[must_use]
    pub fn with_identity(mut self, identity: Box<dyn Identity + Send + Sync>) -> Self {
        self.identities.push(identity);
        self
    }

    /// Parse the recipient string into an age recipient (native or plugin).
    fn parse_recipient(&self) -> Result<Box<dyn Recipient + Send>, UnlockError> {
        if let Ok(r) = age::x25519::Recipient::from_str(&self.recipient) {
            return Ok(Box::new(r));
        }
        let plugin_r = age::plugin::Recipient::from_str(&self.recipient)
            .map_err(|e| UnlockError::ParamsMismatch(format!("invalid age recipient: {e}")))?;
        let plugin_name = plugin_r.plugin().to_string();
        let recip =
            age::plugin::RecipientPluginV1::new(&plugin_name, &[plugin_r], &[], NoCallbacks)
                .map_err(|e| UnlockError::Unavailable(format!("age plugin {plugin_name}: {e}")))?;
        Ok(Box::new(recip))
    }
}

impl UnlockMethod for AgeYubikeyMethod {
    fn kind(&self) -> MethodKind {
        MethodKind::AgeYubikey
    }

    fn available(&self) -> bool {
        // We can wrap whenever the recipient parses; we can recover only with an
        // identity. Report available when an identity is present (recover-capable)
        // or, conservatively, when the recipient is parseable for wrap-only use.
        !self.identities.is_empty() || self.parse_recipient().is_ok()
    }

    fn recover_kek(&self, slot: &Slot, _header_aad: &[u8]) -> Result<MasterKek, UnlockError> {
        let MethodParams::AgeYubikey { .. } = &slot.params else {
            return Err(UnlockError::ParamsMismatch(
                "expected age-yubikey params".into(),
            ));
        };
        if self.identities.is_empty() {
            return Err(UnlockError::Unavailable(
                "no age identity configured for this slot".into(),
            ));
        }
        let ciphertext = &slot.wrap.ciphertext.0;
        let decryptor = Decryptor::new_buffered(ciphertext.as_slice())
            .map_err(|e| UnlockError::Crypto(format!("age header: {e}")))?;
        let identities = self.identities.iter().map(|i| i.as_ref() as &dyn Identity);
        let mut reader = decryptor
            .decrypt(identities)
            .map_err(|_| UnlockError::AuthFailed)?;
        let mut kek_bytes = zeroize::Zeroizing::new(Vec::new());
        std::io::Read::read_to_end(&mut reader, &mut kek_bytes)
            .map_err(|e| UnlockError::Crypto(format!("age read: {e}")))?;
        MasterKek::from_slice(&kek_bytes)
            .ok_or_else(|| UnlockError::Crypto("decrypted KEK has wrong length".into()))
    }

    fn wrap_kek(
        &self,
        kek: &MasterKek,
        _header_aad: &[u8],
        _slot_id: u32,
    ) -> Result<(MethodParams, KekWrap), UnlockError> {
        let recipient = self.parse_recipient()?;
        let encryptor =
            Encryptor::with_recipients(std::iter::once(recipient.as_ref() as &dyn Recipient))
                .map_err(|e| UnlockError::Crypto(format!("age encryptor: {e}")))?;
        let mut ciphertext = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|e| UnlockError::Crypto(format!("age wrap: {e}")))?;
        std::io::Write::write_all(&mut writer, kek.as_bytes())
            .map_err(|e| UnlockError::Crypto(format!("age write: {e}")))?;
        writer
            .finish()
            .map_err(|e| UnlockError::Crypto(format!("age finish: {e}")))?;

        let params = MethodParams::AgeYubikey {
            recipient: self.recipient.clone(),
        };
        let wrap = KekWrap {
            nonce: B64Bytes(Vec::new()),
            ciphertext: B64Bytes(ciphertext),
        };
        Ok((params, wrap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::format::Header;

    fn header() -> Header {
        Header {
            format_version: 1,
            suite: crate::seal::format::Suite::v1(),
            bundle_id: [3u8; 16],
            created_unix: 0,
            epoch: 1,
        }
    }

    #[test]
    fn age_software_round_trip() {
        // Software X25519 identity stands in for the YubiKey plugin path so the
        // age wrap/recover logic is exercised without hardware. (Real hardware
        // verification is logged as an OFI.)
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let aad = header().to_aad_bytes().unwrap();

        let wrap_method = AgeYubikeyMethod::for_recipient(recipient.to_string());
        let kek = MasterKek::generate();
        let (params, wrap) = wrap_method.wrap_kek(&kek, &aad, 0).unwrap();

        let slot = Slot {
            slot_id: 0,
            method: MethodKind::AgeYubikey,
            label: "primary-yubikey".into(),
            created_unix: 0,
            params,
            wrap,
        };

        let recover_method = AgeYubikeyMethod::for_recipient(recipient.to_string())
            .with_identity(Box::new(identity));
        let recovered = recover_method.recover_kek(&slot, &aad).unwrap();
        assert_eq!(recovered.as_bytes(), kek.as_bytes());
    }

    #[test]
    fn wrong_identity_fails_closed() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();
        let aad = header().to_aad_bytes().unwrap();
        let kek = MasterKek::generate();
        let (params, wrap) = AgeYubikeyMethod::for_recipient(recipient.to_string())
            .wrap_kek(&kek, &aad, 0)
            .unwrap();
        let slot = Slot {
            slot_id: 0,
            method: MethodKind::AgeYubikey,
            label: "x".into(),
            created_unix: 0,
            params,
            wrap,
        };
        // A *different* identity cannot decrypt -> fail closed.
        let wrong = age::x25519::Identity::generate();
        let method =
            AgeYubikeyMethod::for_recipient(recipient.to_string()).with_identity(Box::new(wrong));
        assert!(matches!(
            method.recover_kek(&slot, &aad),
            Err(UnlockError::AuthFailed)
        ));
    }

    #[test]
    #[ignore = "requires age-plugin-yubikey, a physical YubiKey, PIN entry, and touch"]
    fn age_yubikey_hardware_pin_touch_round_trip() {
        let recipient = std::env::var("BASIL_TEST_AGE_YUBIKEY_RECIPIENT")
            .expect("set BASIL_TEST_AGE_YUBIKEY_RECIPIENT=age1yubikey...");
        assert!(
            recipient.starts_with("age1yubikey1"),
            "BASIL_TEST_AGE_YUBIKEY_RECIPIENT must be an age-plugin-yubikey recipient"
        );

        let aad = header().to_aad_bytes().unwrap();
        let kek = MasterKek::generate();
        let wrap_method = AgeYubikeyMethod::for_recipient(recipient.clone());
        let (params, wrap) = wrap_method.wrap_kek(&kek, &aad, 0).unwrap();
        let slot = Slot {
            slot_id: 0,
            method: MethodKind::AgeYubikey,
            label: "hardware-yubikey".into(),
            created_unix: 0,
            params,
            wrap,
        };

        eprintln!("Touch the YubiKey and enter its PIN when prompted by age-plugin-yubikey.");
        let recover_method = AgeYubikeyMethod::with_plugin(recipient, "yubikey")
            .expect("age-plugin-yubikey on PATH");
        let recovered = recover_method.recover_kek(&slot, &aad).unwrap();
        assert_eq!(recovered.as_bytes(), kek.as_bytes());
    }
}
