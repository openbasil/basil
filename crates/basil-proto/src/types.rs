// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Shared Basil domain types used by the client and agent internals.

use serde::{Deserialize, Serialize};

/// Asymmetric key type used by key creation, import, signing, and minting.
///
/// Mirrors the wire `basil.broker.v1.KeyType` enum one-for-one, including the
/// post-quantum families. The classical types (`ed25519`..`ecdsa-p256`) are
/// produced/imported in place by the backend; the post-quantum types
/// (`ml-dsa-*` signing, `ml-kem-*` sealing) are provisioned through the
/// local-software crypto provider against an operator-declared software-custody
/// catalog entry: a client names the type but never the custody/storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyType {
    /// Raw Ed25519 signing key.
    #[serde(rename = "ed25519")]
    Ed25519,
    /// Ed25519 in the NATS `NKey` envelope.
    #[serde(rename = "ed25519-nkey")]
    Ed25519Nkey,
    /// RSA-2048.
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    /// ECDSA P-256.
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256,
    /// ECDSA P-384.
    #[serde(rename = "ecdsa-p384")]
    EcdsaP384,
    /// ECDSA P-521.
    #[serde(rename = "ecdsa-p521")]
    EcdsaP521,
    /// ML-DSA (FIPS 204) post-quantum signatures, parameter set 44.
    #[serde(rename = "ml-dsa-44")]
    MlDsa44,
    /// ML-DSA parameter set 65.
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
    /// ML-DSA parameter set 87.
    #[serde(rename = "ml-dsa-87")]
    MlDsa87,
    /// ML-KEM (FIPS 203) post-quantum key encapsulation, parameter set 512.
    #[serde(rename = "ml-kem-512")]
    MlKem512,
    /// ML-KEM parameter set 768.
    #[serde(rename = "ml-kem-768")]
    MlKem768,
    /// ML-KEM parameter set 1024.
    #[serde(rename = "ml-kem-1024")]
    MlKem1024,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ed25519 => "ed25519",
            Self::Ed25519Nkey => "ed25519-nkey",
            Self::Rsa2048 => "rsa-2048",
            Self::EcdsaP256 => "ecdsa-p256",
            Self::EcdsaP384 => "ecdsa-p384",
            Self::EcdsaP521 => "ecdsa-p521",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
            Self::MlKem512 => "ml-kem-512",
            Self::MlKem768 => "ml-kem-768",
            Self::MlKem1024 => "ml-kem-1024",
        })
    }
}

/// AEAD suite used for Basil-owned nonce encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AeadAlgorithm {
    /// `ChaCha20-Poly1305`: 12-byte nonce, 16-byte tag.
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
    /// AES-256-GCM: 12-byte nonce, 16-byte tag.
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

impl std::fmt::Display for AeadAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Chacha20Poly1305 => "chacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
        })
    }
}

/// The kind of a catalog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogKind {
    /// A signing/asymmetric key.
    Signing,
    /// An opaque value key.
    Value,
    /// A symmetric AEAD key.
    Encryption,
}

/// BYOK key material for import. Write-only; never returned to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyMaterial {
    /// 32-byte raw Ed25519 seed.
    Ed25519Seed(#[serde(with = "serde_bytes")] Vec<u8>),
    /// Generic PKCS#8 DER.
    Pkcs8Der(#[serde(with = "serde_bytes")] Vec<u8>),
}

/// Self-describing AEAD ciphertext produced by `encrypt` and consumed by
/// `decrypt`. The broker owns the nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextEnvelope {
    /// AEAD suite.
    pub alg: AeadAlgorithm,
    /// Key version used.
    pub key_version: u32,
    /// Broker-generated nonce.
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
    /// AEAD ciphertext, including tag.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
}

/// Metadata for one visible catalog entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// Dotted catalog name.
    pub name: String,
    /// Catalog entry class.
    pub kind: CatalogKind,
    /// Present for signing/encryption keys; omitted for opaque values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_type: Option<KeyType>,
    /// Latest visible version.
    pub latest_version: u32,
}

#[cfg(test)]
mod tests {
    use super::{AeadAlgorithm, KeyMaterial, KeyType};
    use serde_json::json;

    #[test]
    fn key_type_and_algorithm_wire_spellings() {
        assert_eq!(
            serde_json::to_value(KeyType::Ed25519).unwrap(),
            json!("ed25519")
        );
        assert_eq!(
            serde_json::to_value(KeyType::Ed25519Nkey).unwrap(),
            json!("ed25519-nkey")
        );
        assert_eq!(
            serde_json::to_value(KeyType::Rsa2048).unwrap(),
            json!("rsa-2048")
        );
        assert_eq!(
            serde_json::to_value(KeyType::EcdsaP256).unwrap(),
            json!("ecdsa-p256")
        );
        assert_eq!(
            serde_json::to_value(KeyType::EcdsaP384).unwrap(),
            json!("ecdsa-p384")
        );
        assert_eq!(
            serde_json::to_value(KeyType::EcdsaP521).unwrap(),
            json!("ecdsa-p521")
        );
        assert_eq!(
            serde_json::to_value(KeyType::MlDsa65).unwrap(),
            json!("ml-dsa-65")
        );
        assert_eq!(
            serde_json::to_value(KeyType::MlKem768).unwrap(),
            json!("ml-kem-768")
        );
        assert_eq!(
            serde_json::from_value::<KeyType>(json!("ml-dsa-44")).unwrap(),
            KeyType::MlDsa44
        );
        assert_eq!(
            serde_json::from_value::<KeyType>(json!("ml-kem-1024")).unwrap(),
            KeyType::MlKem1024
        );
        assert_eq!(
            serde_json::to_value(AeadAlgorithm::Aes256Gcm).unwrap(),
            json!("aes-256-gcm")
        );
        assert_eq!(
            serde_json::to_value(AeadAlgorithm::Chacha20Poly1305).unwrap(),
            json!("chacha20-poly1305")
        );
    }

    #[test]
    fn key_material_is_tagged_union() {
        let v = serde_json::to_value(KeyMaterial::Ed25519Seed(vec![1, 2, 3])).unwrap();
        assert_eq!(v, json!({"ed25519_seed":[1,2,3]}));
        let back: KeyMaterial = serde_json::from_value(v).unwrap();
        assert_eq!(back, KeyMaterial::Ed25519Seed(vec![1, 2, 3]));
    }
}
