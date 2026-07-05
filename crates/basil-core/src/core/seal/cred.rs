// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Per-backend credential payload (§4 of `designs/unlock-and-bundle.html`).
//!
//! The decrypted sealed-bundle payload is a [`CredBundle`]: a map of opaque
//! backend id → [`BackendCred`]. Every secret field is wrapped in
//! [`Zeroizing`] so the *whole* decrypted payload (not just the master KEK)
//! is wiped on drop. The broker hands `creds[backend_id]` to the matching
//! backend constructor at startup, then drops (zeroizes) the bundle.

use std::collections::{BTreeMap, BTreeSet};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zero_secrets::{SecretArray, SecretBytes, SecretString};

/// Schema version of the cred payload, independent of the container
/// `format_version`. Bump when [`BackendCred`] gains/changes a variant.
pub const CRED_SCHEMA_VERSION: u16 = 2;

/// The decrypted per-backend credential map.
///
/// This is the AEAD plaintext of the sealed payload (§2.3). It holds the
/// broker's *own* bootstrap credentials, the secrets it needs to authenticate
/// *to* each backend, and nothing else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredBundle {
    /// Payload schema version (see [`CRED_SCHEMA_VERSION`]).
    pub schema_version: u16,
    /// Opaque backend id → credential. The id is the same string the catalog
    /// routes keys to.
    pub backends: BTreeMap<String, BackendCred>,
    /// Sealed credential-deposit material. The ingest private key and
    /// contributor allow-list live inside the encrypted payload; append-only
    /// deposit records outside the payload are useless without this material.
    #[serde(default)]
    pub deposit: DepositMaterial,
}

impl CredBundle {
    /// An empty bundle at the current schema version.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            schema_version: CRED_SCHEMA_VERSION,
            backends: BTreeMap::new(),
            deposit: DepositMaterial::empty(),
        }
    }

    /// Insert or replace the credential for `backend_id`.
    pub fn set(&mut self, backend_id: impl Into<String>, cred: BackendCred) {
        self.backends.insert(backend_id.into(), cred);
    }

    /// Ensure this bundle has an ingest identity for public credential deposits.
    pub fn ensure_deposit_identity(&mut self) {
        if self.deposit.ingest_private_key.is_some() {
            return;
        }
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        self.deposit.ingest_private_key = Some(SecretArray::new(seed));
    }

    /// Return the public deposit recipient when an ingest identity exists.
    #[must_use]
    pub fn deposit_recipient(&self) -> Option<[u8; 32]> {
        let private = self.deposit.ingest_private_key.as_ref()?;
        let private = zeroize::Zeroizing::new(private.expose_secret().try_into().ok()?);
        Some(crate::core::x25519_seal::public_from_private(&private))
    }
}

impl Default for CredBundle {
    fn default() -> Self {
        Self::empty()
    }
}

/// Sealed configuration that authorizes public-key credential deposits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositMaterial {
    /// Private X25519 ingest identity. Its public half is safe to publish; this
    /// private half stays in the sealed payload and is recovered only after a
    /// normal bundle unlock.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "secret_array_32_opt"
    )]
    pub ingest_private_key: Option<SecretArray<32>>,
    /// Contributor id → signing public key and delegated backend ids.
    #[serde(default)]
    pub contributors: BTreeMap<String, DepositContributor>,
}

impl DepositMaterial {
    /// Empty deposit material.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            ingest_private_key: None,
            contributors: BTreeMap::new(),
        }
    }
}

impl Default for DepositMaterial {
    fn default() -> Self {
        Self::empty()
    }
}

/// One allow-listed credential depositor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositContributor {
    /// Base64url-nopad Ed25519 verifying key.
    pub public_key: String,
    /// Backend ids this contributor may replace via the deposit log.
    #[serde(default)]
    pub allowed_backend_ids: BTreeSet<String>,
}

/// A single backend's bootstrap credential. Secret fields are `Zeroizing`.
///
/// Serialized with serde's external tagging (a `{ "<variant>": { … } }`
/// object), the same style the wire protocol uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackendCred {
    /// Vault static token (the `bundle create --backend …,token-file=` cred).
    /// Dev / simple setups.
    VaultToken {
        /// The bearer token sent as `X-Vault-Token`.
        #[serde(with = "secret_string")]
        token: SecretString,
        /// Optional per-cred address override; otherwise the broker's
        /// `--vault-addr` applies.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        addr: Option<String>,
    },

    /// Vault `AppRole`: `secret_id` (+ `role_id`) exchanged for a short-lived
    /// token at startup. Recommended production default (§4).
    VaultAppRole {
        /// Non-secret `role_id`.
        role_id: String,
        /// Secret `secret_id` (zeroized on drop).
        #[serde(with = "secret_string")]
        secret_id: SecretString,
        /// Optional per-cred address override.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        addr: Option<String>,
    },

    /// SPIFFE/JWT-SVID signing key for the `spiffe` backend path: a private key
    /// the broker uses to self-issue an SVID, exchanged via bao `jwt` auth.
    SpiffeSigner {
        /// PEM-encoded private signing key (zeroized on drop).
        #[serde(with = "secret_string")]
        key_pem: SecretString,
        /// SPIFFE id stamped into the SVID `sub`.
        spiffe_id: String,
    },

    /// Future value-store backend (db-keystore): the DEK that opens the local DB.
    DbKeystoreDek {
        /// 32-byte data-encryption key (zeroized on drop).
        #[serde(with = "secret_dek")]
        dek: SecretArray<32>,
    },

    /// `1Password` provider configuration.
    OnePassword {
        /// Provider URI, for example `onepassword://vault` or
        /// `onepassword+token://token@vault`.
        provider_uri: String,
        /// Item-title project namespace.
        project: String,
        /// Item-title profile.
        profile: String,
    },

    /// AWS KMS transit backend addressing. Auth is the ambient AWS credential
    /// chain (env / profile / IAM role / IMDS), so **no secret is sealed here**:
    /// this variant carries only non-secret addressing.
    AwsKms {
        /// AWS region, for example `us-east-1`. Empty ⇒ SDK default resolution.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        region: String,
        /// Optional named profile from `~/.aws/config`. Empty ⇒ default chain.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        profile: String,
    },

    /// GCP Cloud KMS transit backend addressing. Auth defaults to Application
    /// Default Credentials; when `service_account_json` is present, the whole
    /// service-account key file is sealed as one opaque secret. Crypto-key names
    /// route under
    /// `projects/{project}/locations/{location}/keyRings/{key_ring}`.
    GcpKms {
        /// GCP project id.
        project: String,
        /// KMS location, for example `global` or `us-west1`.
        location: String,
        /// Key ring name that holds the crypto keys.
        key_ring: String,
        /// Optional service-account JSON key. `None` uses ambient ADC.
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "secret_string_opt"
        )]
        service_account_json: Option<SecretString>,
    },

    /// Escape hatch for a backend kind not yet modelled: opaque labelled bytes.
    Opaque {
        /// Operator-facing kind label.
        kind: String,
        /// Opaque secret bytes (zeroized on drop).
        #[serde(with = "secret_bytes")]
        secret: SecretBytes,
    },
}

/// serde for `SecretString` (passes through as a JSON string).
mod secret_string {
    use serde::{Deserialize, Deserializer, Serializer};
    use zero_secrets::SecretString;

    pub fn serialize<S: Serializer>(v: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v.expose_secret())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
        Ok(SecretString::new(String::deserialize(d)?))
    }
}

/// serde for optional `SecretString` fields.
mod secret_string_opt {
    use serde::{Deserialize, Deserializer, Serializer};
    use zero_secrets::SecretString;

    #[allow(clippy::ref_option)] // serde `with` requires `&Option<T>` here.
    pub fn serialize<S: Serializer>(v: &Option<SecretString>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(secret) => s.serialize_some(secret.expose_secret()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SecretString>, D::Error> {
        Ok(Option::<String>::deserialize(d)?.map(SecretString::new))
    }
}

/// serde for `SecretBytes` (base64-nopad string, matching the container).
mod secret_bytes {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use serde::{Deserialize, Deserializer, Serializer};
    use zero_secrets::SecretBytes;

    pub fn serialize<S: Serializer>(v: &SecretBytes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v.expose_secret()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretBytes, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes())
            .map(SecretBytes::new)
            .map_err(serde::de::Error::custom)
    }
}

/// serde for `SecretArray<32>` (base64-nopad, exactly 32 bytes).
mod secret_dek {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use serde::{Deserialize, Deserializer, Serializer};
    use zero_secrets::SecretArray;

    pub fn serialize<S: Serializer>(v: &SecretArray<32>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v.expose_secret()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretArray<32>, D::Error> {
        let s = String::deserialize(d)?;
        let v = B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        let arr = <[u8; 32]>::try_from(v.as_slice())
            .map_err(|_| serde::de::Error::custom("dek must be 32 bytes"))?;
        Ok(SecretArray::new(arr))
    }
}

/// serde for optional `SecretArray<32>` fields.
mod secret_array_32_opt {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use serde::{Deserialize, Deserializer, Serializer};
    use zero_secrets::SecretArray;

    #[allow(clippy::ref_option)] // serde `with` requires `&Option<T>` here.
    pub fn serialize<S: Serializer>(v: &Option<SecretArray<32>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(secret) => s.serialize_some(&B64.encode(secret.expose_secret())),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<SecretArray<32>>, D::Error> {
        let Some(s) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        let bytes = B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)?;
        let arr = <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| serde::de::Error::custom("secret array must be 32 bytes"))?;
        Ok(Some(SecretArray::new(arr)))
    }
}

impl BackendCred {
    /// Short, stable name for the variant (for audit/logging, never the bytes).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::VaultToken { .. } => "vault-token",
            Self::VaultAppRole { .. } => "vault-approle",
            Self::SpiffeSigner { .. } => "spiffe-signer",
            Self::DbKeystoreDek { .. } => "db-keystore-dek",
            Self::OnePassword { .. } => "onepassword",
            Self::AwsKms { .. } => "aws-kms",
            Self::GcpKms { .. } => "gcp-kms",
            Self::Opaque { .. } => "opaque",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_secrets::{SecretArray, SecretBytes, SecretString};

    #[test]
    fn round_trip_json() {
        let mut bundle = CredBundle::empty();
        bundle.set(
            "vault-transit",
            BackendCred::VaultToken {
                token: SecretString::new("s.deadbeef".to_string()),
                addr: Some("http://127.0.0.1:8200".to_string()),
            },
        );
        bundle.set(
            "vault-approle",
            BackendCred::VaultAppRole {
                role_id: "role-123".to_string(),
                secret_id: SecretString::new("secret-456".to_string()),
                addr: None,
            },
        );
        let json = serde_json::to_vec(&bundle).unwrap();
        let back: CredBundle = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.schema_version, CRED_SCHEMA_VERSION);
        assert_eq!(back.backends.len(), 2);
        match back.backends.get("vault-transit") {
            Some(BackendCred::VaultToken { token, addr }) => {
                assert_eq!(token.expose_secret(), "s.deadbeef");
                assert_eq!(addr.as_deref(), Some("http://127.0.0.1:8200"));
            }
            other => panic!("wrong variant: {:?}", other.map(BackendCred::kind)),
        }
        match back.backends.get("vault-approle") {
            Some(BackendCred::VaultAppRole {
                role_id,
                secret_id,
                addr,
            }) => {
                assert_eq!(role_id, "role-123");
                assert_eq!(secret_id.expose_secret(), "secret-456");
                assert!(addr.is_none());
            }
            other => panic!("wrong variant: {:?}", other.map(BackendCred::kind)),
        }
    }

    #[test]
    fn approle_omits_absent_addr() {
        let cred = BackendCred::VaultAppRole {
            role_id: "r".to_string(),
            secret_id: SecretString::new("s".to_string()),
            addr: None,
        };
        let v = serde_json::to_value(&cred).unwrap();
        // `addr: None` is skipped, not serialized as null.
        assert!(v["VaultAppRole"].get("addr").is_none());
    }

    #[test]
    fn debug_redacts_secret_fields() {
        let cases = [
            format!(
                "{:?}",
                BackendCred::VaultToken {
                    token: SecretString::new("s.debug-token".to_string()),
                    addr: None,
                }
            ),
            format!(
                "{:?}",
                BackendCred::VaultAppRole {
                    role_id: "role".to_string(),
                    secret_id: SecretString::new("debug-secret-id".to_string()),
                    addr: None,
                }
            ),
            format!(
                "{:?}",
                BackendCred::SpiffeSigner {
                    key_pem: SecretString::new("-----BEGIN PRIVATE KEY-----".to_string()),
                    spiffe_id: "spiffe://example.test/basil".to_string(),
                }
            ),
            format!(
                "{:?}",
                BackendCred::DbKeystoreDek {
                    dek: SecretArray::new([0xabu8; 32]),
                }
            ),
            format!(
                "{:?}",
                BackendCred::GcpKms {
                    project: "p".to_string(),
                    location: "global".to_string(),
                    key_ring: "ring".to_string(),
                    service_account_json: Some(SecretString::new(
                        "{\"private_key\":\"debug-private-key\"}".to_string(),
                    )),
                }
            ),
            format!(
                "{:?}",
                BackendCred::Opaque {
                    kind: "test".to_string(),
                    secret: SecretBytes::new(vec![0xde, 0xad, 0xbe, 0xef]),
                }
            ),
        ];

        for rendered in cases {
            assert!(rendered.contains("REDACTED"));
            assert!(!rendered.contains("debug-token"));
            assert!(!rendered.contains("debug-secret-id"));
            assert!(!rendered.contains("PRIVATE KEY"));
            assert!(!rendered.contains("debug-private-key"));
            assert!(!rendered.contains("171"));
            assert!(!rendered.contains("222"));
        }
    }
}
