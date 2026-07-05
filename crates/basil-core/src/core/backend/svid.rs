// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Self-minted JWT-SVIDs.
//!
//! The broker acts as its own SPIFFE issuer: it holds an RSA signing key and
//! mints short-lived JWT-SVIDs with the SPIFFE JWT-SVID claim shape: `sub`
//! (the SPIFFE ID), `aud`, `iat`, `exp`, all signed RS256.
//!
//! In a real SPIFFE deployment these would be issued by SPIRE and fetched over
//! the Workload API; minting them here keeps the flow self-contained. Vault's
//! `jwt` auth method validates the token against the broker's public key
//! (`jwt_validation_pubkeys`) and binds the SPIFFE ID to a role/policy.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::BackendError;

const RSA_BITS: usize = 2048;

/// The JWT-SVID claim set (SPIFFE JWT-SVID profile, single audience).
#[derive(Serialize)]
struct SvidClaims {
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
}

/// Mints JWT-SVIDs from a freshly generated RSA issuer key.
pub struct SvidMinter {
    encoding_key: EncodingKey,
    /// SPKI PEM of the public key, for Vault's `jwt_validation_pubkeys`.
    public_key_pem: String,
    header: Header,
    spiffe_id: String,
    audience: String,
    ttl: Duration,
}

impl SvidMinter {
    /// Generate a new issuer key and bind it to a SPIFFE id + audience.
    pub fn generate(
        spiffe_id: impl Into<String>,
        audience: impl Into<String>,
        ttl: Duration,
    ) -> Result<Self, BackendError> {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, RSA_BITS)
            .map_err(|e| BackendError::Backend(format!("rsa keygen: {e}")))?;
        Self::from_rsa_private(&private, spiffe_id, audience, ttl)
    }

    /// Bind an **existing** RSA issuer key (decoded from a sealed-bundle PEM) to
    /// a SPIFFE id + audience. Accepts either a `PKCS#1` or `PKCS#8` private PEM;
    /// the derived SPKI public PEM is what Vault's jwt auth validates against.
    pub fn from_pem(
        key_pem: &str,
        spiffe_id: impl Into<String>,
        audience: impl Into<String>,
        ttl: Duration,
    ) -> Result<Self, BackendError> {
        // The bundled key may be in either common encoding; try PKCS#8 (the
        // modern default) first, then fall back to PKCS#1 (RSA-specific).
        let private = RsaPrivateKey::from_pkcs8_pem(key_pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(key_pem))
            .map_err(|e| BackendError::Backend(format!("decode signer private key: {e}")))?;
        Self::from_rsa_private(&private, spiffe_id, audience, ttl)
    }

    /// Shared construction from a concrete [`RsaPrivateKey`]: derive both PEMs
    /// `jsonwebtoken` and Vault require, then assemble the minter.
    fn from_rsa_private(
        private: &RsaPrivateKey,
        spiffe_id: impl Into<String>,
        audience: impl Into<String>,
        ttl: Duration,
    ) -> Result<Self, BackendError> {
        let public = RsaPublicKey::from(private);

        // jsonwebtoken's RSA signer wants a PKCS#1 private PEM; Vault's jwt
        // auth wants an SPKI public PEM. The private PEM is the broker's own
        // JWT-SVID signing key in plaintext, so it is held in a `Zeroizing`
        // buffer that wipes its heap bytes on drop rather than lingering
        // un-scrubbed (consistent with the `BackendCred` zeroization discipline).
        // `to_pkcs1_pem` already yields `Zeroizing<String>` for a private key;
        // the explicit binding makes that guarantee load-bearing and prevents a
        // silent regression to a plain `String` from leaving the secret un-wiped.
        let private_pem: Zeroizing<String> = private
            .to_pkcs1_pem(LineEnding::LF)
            .map_err(|e| BackendError::Backend(format!("encode private key: {e}")))?;
        let public_key_pem = public
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| BackendError::Backend(format!("encode public key: {e}")))?;
        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|e| BackendError::Backend(format!("load signing key: {e}")))?;
        drop(private_pem); // wipe the plaintext private PEM as soon as it is loaded.

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(Uuid::new_v4().simple().to_string());

        Ok(Self {
            encoding_key,
            public_key_pem,
            header,
            spiffe_id: spiffe_id.into(),
            audience: audience.into(),
            ttl,
        })
    }

    /// The public key (SPKI PEM) to register with Vault's jwt auth.
    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    /// The SPIFFE id this minter stamps into `sub`.
    pub fn spiffe_id(&self) -> &str {
        &self.spiffe_id
    }

    /// Mint a fresh, short-lived JWT-SVID.
    pub fn mint(&self) -> Result<String, BackendError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| BackendError::Backend(e.to_string()))?
            .as_secs();
        let claims = SvidClaims {
            sub: self.spiffe_id.clone(),
            aud: self.audience.clone(),
            iat: now,
            exp: now + self.ttl.as_secs(),
        };
        jsonwebtoken::encode(&self.header, &claims, &self.encoding_key)
            .map_err(|e| BackendError::Backend(format!("mint svid: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::{Duration, RsaPrivateKey, SvidMinter};
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};

    /// 2048-bit RSA key: `jsonwebtoken` rejects sub-2048 keys for RS256 minting,
    /// so the `mint()` assertion needs at least this size.
    fn test_key() -> RsaPrivateKey {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen")
    }

    #[test]
    fn from_pem_loads_pkcs8_and_mints() {
        let key = test_key();
        let pem = key.to_pkcs8_pem(LineEnding::LF).expect("pkcs8 pem");
        let minter = SvidMinter::from_pem(
            &pem,
            "spiffe://example.test/basil",
            "openbao",
            Duration::from_mins(1),
        )
        .expect("from_pem pkcs8");
        assert_eq!(minter.spiffe_id(), "spiffe://example.test/basil");
        assert!(minter.public_key_pem().contains("BEGIN PUBLIC KEY"));
        // The loaded key actually signs a token.
        assert!(!minter.mint().expect("mint").is_empty());
    }

    #[test]
    fn from_pem_loads_pkcs1() {
        let key = test_key();
        let pem = key.to_pkcs1_pem(LineEnding::LF).expect("pkcs1 pem");
        let minter = SvidMinter::from_pem(
            &pem,
            "spiffe://example.test/basil",
            "openbao",
            Duration::from_mins(1),
        )
        .expect("from_pem pkcs1");
        assert_eq!(minter.spiffe_id(), "spiffe://example.test/basil");
    }

    /// The derived private PEM intermediate is held in a `Zeroizing` buffer so
    /// the broker's plaintext signing key is wiped on drop. This is a
    /// compile-time guarantee on the binding's type; the assertion here just
    /// pins that `to_pkcs1_pem` keeps yielding a `Zeroizing<String>` for a
    /// private key (a plain-`String` regression would fail to compile).
    #[test]
    fn private_pem_intermediate_is_zeroizing() {
        use zeroize::Zeroizing;
        let key = test_key();
        let private_pem: Zeroizing<String> = key.to_pkcs1_pem(LineEnding::LF).expect("pkcs1 pem");
        assert!(private_pem.contains("PRIVATE KEY"));
        // Construction through the minter must still succeed end-to-end after
        // the explicit-drop of the scrubbed private PEM.
        let minter = SvidMinter::from_pem(
            &private_pem,
            "spiffe://example.test/basil",
            "openbao",
            Duration::from_mins(1),
        )
        .expect("from_pem after zeroizing-pem round-trip");
        assert!(!minter.mint().expect("mint").is_empty());
    }

    #[test]
    fn from_pem_rejects_garbage() {
        // `SvidMinter` is intentionally not `Debug` (it wraps key material), so
        // match on the error rather than `expect_err`.
        match SvidMinter::from_pem(
            "not a pem",
            "spiffe://example.test/basil",
            "openbao",
            Duration::from_mins(1),
        ) {
            Err(e) => assert!(e.to_string().contains("decode signer private key")),
            Ok(_) => panic!("garbage pem must be rejected"),
        }
    }
}
