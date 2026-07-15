#![allow(clippy::result_large_err)]

// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use basil_proto::broker::v1 as pb;
use basil_proto::broker::v1::aead_service_server::AeadService;
use tonic::{Request, Response};

use crate::catalog::policy::Op;
use crate::core::crypto_provider::{
    Envelope as ProviderEnvelope, EnvelopeAlgorithm as ProviderEnvelopeAlgorithm,
    KemAlgorithm as ProviderKemAlgorithm,
};
use crate::manager::MlKemEnvelopeParts;
use crate::service::broker::{BrokerGrpc, GrpcResult};
use crate::service::shared::{
    SupportedKem, aead_algorithm, basil_ciphertext_envelope, ciphertext_envelope,
    ensure_supported_envelope_algorithm, ensure_supported_kem_algorithm, invalid_request,
    manager_status, payload_too_large,
};
use crate::x25519_seal::SealedEnvelope;

#[tonic::async_trait]
impl AeadService for BrokerGrpc {
    async fn encrypt(
        &self,
        request: Request<pb::EncryptRequest>,
    ) -> GrpcResult<pb::EncryptResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Encrypt, &body.key_id)?;
        if body.plaintext.len() > self.state.limits().max_encrypt_size {
            return Err(payload_too_large(
                "encrypt",
                "encrypt payload exceeds configured cap",
            ));
        }
        let envelope = self
            .state
            .manager()
            .encrypt(
                &body.key_id,
                aead_algorithm(body.algorithm, "encrypt")?,
                &body.plaintext,
                body.aad.as_deref(),
            )
            .await
            .map_err(|e| manager_status("encrypt", &e))?;
        Ok(Response::new(pb::EncryptResponse {
            envelope: Some(ciphertext_envelope(envelope)),
        }))
    }

    async fn decrypt(
        &self,
        request: Request<pb::DecryptRequest>,
    ) -> GrpcResult<pb::DecryptResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Decrypt, &body.key_id)?;
        let envelope = body
            .envelope
            .as_ref()
            .ok_or_else(|| invalid_request("decrypt", "missing ciphertext envelope"))
            .and_then(|envelope| basil_ciphertext_envelope(envelope, "decrypt"))?;
        if envelope.ciphertext.len() > self.state.limits().max_encrypt_size {
            return Err(payload_too_large(
                "decrypt",
                "decrypt payload exceeds configured cap",
            ));
        }
        let plaintext = self
            .state
            .manager()
            .decrypt(&body.key_id, &envelope, body.aad.as_deref())
            .await
            .map_err(|e| manager_status("decrypt", &e))?;
        Ok(Response::new(pb::DecryptResponse { plaintext }))
    }

    async fn wrap_envelope(
        &self,
        request: Request<pb::WrapEnvelopeRequest>,
    ) -> GrpcResult<pb::WrapEnvelopeResponse> {
        let body = request.get_ref();
        let actor = self.authorize(&request, Op::Encrypt, &body.key_id)?;
        let uid = Self::require_unix_uid(&actor, "encrypt")?;
        if body.plaintext.len() > self.state.limits().max_encrypt_size {
            return Err(payload_too_large(
                "wrap_envelope",
                "envelope payload exceeds configured cap",
            ));
        }
        let kem = ensure_supported_kem_algorithm(body.kem_algorithm, "wrap_envelope")?;
        ensure_supported_envelope_algorithm(body.envelope_algorithm, "wrap_envelope")?;
        // X25519 wraps through the classical sealing path (public-only); ML-KEM
        // dispatches through the software-custody crypto provider, which self-seals
        // to the custodied seed's encapsulation key under the op:use_software_custody
        // grant.
        let Some(provider_kem) = ml_kem_provider_algorithm(kem) else {
            let sealed = self
                .state
                .manager()
                .wrap_envelope(
                    &body.key_id,
                    &body.plaintext,
                    body.aad.as_deref().unwrap_or_default(),
                )
                .await
                .map_err(|e| manager_status("wrap_envelope", &e))?;
            return Ok(Response::new(pb::WrapEnvelopeResponse {
                envelope: Some(kem_envelope(
                    body.kem_algorithm,
                    body.envelope_algorithm,
                    &sealed,
                )),
            }));
        };
        let envelope_algorithm =
            provider_envelope_algorithm(body.envelope_algorithm, "wrap_envelope")?;
        let gate = self.provider_gate(&actor, &body.key_id);
        let (envelope, dispatch) = self
            .state
            .manager()
            .provider_wrap_envelope(
                &body.key_id,
                provider_kem,
                envelope_algorithm,
                &body.plaintext,
                body.aad.as_deref().unwrap_or_default(),
                gate,
            )
            .await
            .inspect_err(|e| {
                self.audit_provider_failure(
                    uid,
                    "wrap_envelope",
                    &body.key_id,
                    provider_kem.token(),
                    e,
                );
            })
            .map_err(|e| manager_status("wrap_envelope", &e))?;
        self.audit_provider_success(uid, "wrap_envelope", &body.key_id, dispatch);
        Ok(Response::new(pb::WrapEnvelopeResponse {
            envelope: Some(ml_kem_wire_envelope(
                body.kem_algorithm,
                body.envelope_algorithm,
                &envelope,
            )),
        }))
    }

    /// Open a sealed envelope (`unwrap`) addressed to a sealing key: an X25519
    /// sealed box or ML-KEM software-custody envelope, selected by the wire
    /// `kem_algorithm`.
    ///
    /// **Confidentiality only, NOT sender authentication.** A sealed envelope is
    /// anonymous: a successful unseal proves only that the payload was sealed to
    /// this recipient's public key, never *who* sealed it (anyone with the public
    /// can produce a valid envelope). Callers MUST NOT treat a successful unwrap as
    /// proof of sender identity. Bind sender authenticity at a higher layer if
    /// needed.
    async fn unwrap_envelope(
        &self,
        request: Request<pb::UnwrapEnvelopeRequest>,
    ) -> GrpcResult<pb::UnwrapEnvelopeResponse> {
        let body = request.get_ref();
        let actor = self.authorize(&request, Op::Decrypt, &body.key_id)?;
        let uid = Self::require_unix_uid(&actor, "decrypt")?;
        let envelope = body
            .envelope
            .as_ref()
            .ok_or_else(|| invalid_request("unwrap_envelope", "missing KEM envelope"))?;
        let kem = ensure_supported_kem_algorithm(envelope.kem_algorithm, "unwrap_envelope")?;
        ensure_supported_envelope_algorithm(envelope.envelope_algorithm, "unwrap_envelope")?;
        if envelope.ciphertext.len() > self.state.limits().max_encrypt_size {
            return Err(payload_too_large(
                "unwrap_envelope",
                "envelope payload exceeds configured cap",
            ));
        }
        // X25519 opens through the classical sealing path; ML-KEM dispatches through
        // the software-custody crypto provider (gated by op:use_software_custody).
        let Some(provider_kem) = ml_kem_provider_algorithm(kem) else {
            // Validate the fixed-length wire fields (never index attacker bytes).
            let sealed = seal_envelope_from_wire(envelope)?;
            let plaintext = self
                .state
                .manager()
                .unwrap_envelope(
                    &body.key_id,
                    &sealed,
                    body.aad.as_deref().unwrap_or_default(),
                )
                .await
                .map_err(|e| manager_status("unwrap_envelope", &e))?;
            return Ok(Response::new(pb::UnwrapEnvelopeResponse {
                plaintext: plaintext.to_vec(),
            }));
        };
        let envelope_algorithm =
            provider_envelope_algorithm(envelope.envelope_algorithm, "unwrap_envelope")?;
        let gate = self.provider_gate(&actor, &body.key_id);
        let (plaintext, dispatch) = self
            .state
            .manager()
            .provider_unwrap_envelope(
                &body.key_id,
                provider_kem,
                envelope_algorithm,
                MlKemEnvelopeParts {
                    encapsulated_key: &envelope.encapsulated_key,
                    nonce: &envelope.nonce,
                    ciphertext: &envelope.ciphertext,
                },
                body.aad.as_deref().unwrap_or_default(),
                gate,
            )
            .await
            .inspect_err(|e| {
                self.audit_provider_failure(
                    uid,
                    "unwrap_envelope",
                    &body.key_id,
                    provider_kem.token(),
                    e,
                );
            })
            .map_err(|e| manager_status("unwrap_envelope", &e))?;
        self.audit_provider_success(uid, "unwrap_envelope", &body.key_id, dispatch);
        Ok(Response::new(pb::UnwrapEnvelopeResponse { plaintext }))
    }

    async fn unseal_cose(
        &self,
        request: Request<pb::UnsealCoseRequest>,
    ) -> GrpcResult<pb::UnsealCoseResponse> {
        let body = request.get_ref();
        self.authorize(&request, Op::Decrypt, &body.key_id)?;
        if body.cose_encrypt.len() > self.state.limits().max_encrypt_size {
            return Err(payload_too_large(
                "unseal_cose",
                "COSE payload exceeds configured cap",
            ));
        }
        let plaintext = self
            .state
            .manager()
            .unseal_cose(
                &body.key_id,
                &body.cose_encrypt,
                body.external_aad.as_deref().unwrap_or_default(),
            )
            .await
            .map_err(|e| manager_status("unseal_cose", &e))?;
        Ok(Response::new(pb::UnsealCoseResponse {
            plaintext: plaintext.to_vec(),
        }))
    }
}

/// Build the wire [`pb::KemEnvelope`] response from a sealed X25519 envelope. The
/// key version field is unused for a software-custodied sealing key (the private
/// is materialized from KV, not transit-versioned), so it is reported as 0.
fn kem_envelope(
    kem_algorithm: i32,
    envelope_algorithm: i32,
    sealed: &SealedEnvelope,
) -> pb::KemEnvelope {
    pb::KemEnvelope {
        kem_algorithm,
        envelope_algorithm,
        key_version: 0,
        encapsulated_key: sealed.encapsulated_key.to_vec(),
        nonce: sealed.nonce.to_vec(),
        ciphertext: sealed.ciphertext.clone(),
    }
}

/// Parse a wire [`pb::KemEnvelope`] into the crypto-core [`SealedEnvelope`],
/// validating the fixed-length `encapsulated_key` / `nonce` fields. A wrong length
/// is a client error, mapped through the manager `Malformed` surface.
fn seal_envelope_from_wire(envelope: &pb::KemEnvelope) -> Result<SealedEnvelope, tonic::Status> {
    crate::x25519_seal::envelope_from_parts(
        &envelope.encapsulated_key,
        &envelope.nonce,
        &envelope.ciphertext,
    )
    .map_err(|_| {
        invalid_request(
            "unwrap_envelope",
            "malformed KEM envelope (bad encapsulated_key or nonce length)",
        )
    })
}

/// Map a broker-supported KEM to the provider-dispatch ML-KEM algorithm. Returns
/// `None` for X25519, which is not provider-dispatched (it uses the classical
/// sealing path).
const fn ml_kem_provider_algorithm(kem: SupportedKem) -> Option<ProviderKemAlgorithm> {
    match kem {
        SupportedKem::MlKem512 => Some(ProviderKemAlgorithm::MlKem512),
        SupportedKem::MlKem768 => Some(ProviderKemAlgorithm::MlKem768),
        SupportedKem::MlKem1024 => Some(ProviderKemAlgorithm::MlKem1024),
        SupportedKem::X25519 => None,
    }
}

/// Map the wire envelope-AEAD enum to the provider-dispatch algorithm.
fn provider_envelope_algorithm(
    value: i32,
    op: &'static str,
) -> Result<ProviderEnvelopeAlgorithm, tonic::Status> {
    match pb::EnvelopeAlgorithm::try_from(value)
        .map_err(|_| invalid_request(op, "unknown envelope algorithm"))?
    {
        pb::EnvelopeAlgorithm::Unspecified => {
            Err(invalid_request(op, "missing envelope algorithm"))
        }
        pb::EnvelopeAlgorithm::Aes256Gcm => Ok(ProviderEnvelopeAlgorithm::Aes256Gcm),
        pb::EnvelopeAlgorithm::Chacha20Poly1305 => Ok(ProviderEnvelopeAlgorithm::ChaCha20Poly1305),
    }
}

/// Build the wire [`pb::KemEnvelope`] from a provider-dispatched ML-KEM
/// [`ProviderEnvelope`]. Self-describing: it echoes the requested KEM/envelope
/// algorithm and carries the custody record's `key_version`, so `unwrap` routes to
/// the right parameter set, AEAD algorithm, and key version without leaking secrets.
fn ml_kem_wire_envelope(
    kem_algorithm: i32,
    envelope_algorithm: i32,
    envelope: &ProviderEnvelope,
) -> pb::KemEnvelope {
    pb::KemEnvelope {
        kem_algorithm,
        envelope_algorithm,
        key_version: envelope.key_version,
        encapsulated_key: envelope.encapsulated_key.clone(),
        nonce: envelope.nonce.clone(),
        ciphertext: envelope.ciphertext.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::Arc;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use basil_cose::{
        ContentAlgorithm, ContentType, EncryptParams, ExternalAad, KdfParties, KeyId, PartyIdentity,
    };
    use basil_proto::broker::v1 as pb;
    use basil_proto::broker::v1::aead_service_server::AeadService;
    use basil_proto::{AeadAlgorithm, CiphertextEnvelope, KeyType};
    use tonic::{Code, Request};
    use zeroize::Zeroizing;

    use super::BrokerGrpc;
    use crate::backend::{Backend, BackendError, KvValue, NewKey};
    use crate::catalog::load;
    use crate::manager::BackendManager;
    use crate::peer::PeerInfo;
    use crate::state::BrokerState;

    /// In-memory backend that serves a pre-provisioned ML-KEM software-custody
    /// record from `kv_get` and unseals the seed from `decrypt`. `encrypt`
    /// length-prefixes the AAD so `decrypt` authenticates it (identity envelope;
    /// the test exercises the broker/provider wiring, not the storage AEAD).
    #[derive(Default)]
    struct SealingBackend {
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl SealingBackend {
        fn seeded(path: &str, record: Vec<u8>) -> Self {
            let backend = Self::default();
            if let Ok(mut store) = backend.store.lock() {
                store.insert(path.to_string(), record);
            }
            backend
        }
    }

    #[async_trait]
    impl Backend for SealingBackend {
        fn kind(&self) -> &'static str {
            "ml-kem-sealing-test"
        }

        async fn new_key(&self, _key_type: KeyType) -> Result<NewKey, BackendError> {
            Err(BackendError::Unsupported("new_key"))
        }

        async fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("public_key"))
        }

        async fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, BackendError> {
            Err(BackendError::Unsupported("sign"))
        }

        async fn verify(
            &self,
            _key_id: &str,
            _message: &[u8],
            _signature: &[u8],
        ) -> Result<bool, BackendError> {
            Err(BackendError::Unsupported("verify"))
        }

        async fn encrypt(
            &self,
            _key_id: &str,
            algorithm: AeadAlgorithm,
            plaintext: &[u8],
            aad: Option<&[u8]>,
        ) -> Result<CiphertextEnvelope, BackendError> {
            let aad = aad.unwrap_or(&[]);
            let mut ciphertext = vec![u8::try_from(aad.len()).unwrap_or(u8::MAX)];
            ciphertext.extend_from_slice(aad);
            ciphertext.extend_from_slice(plaintext);
            Ok(CiphertextEnvelope {
                alg: algorithm,
                key_version: 1,
                nonce: Vec::new(),
                ciphertext,
            })
        }

        async fn decrypt(
            &self,
            _key_id: &str,
            envelope: &CiphertextEnvelope,
            aad: Option<&[u8]>,
        ) -> Result<Vec<u8>, BackendError> {
            let aad = aad.unwrap_or(&[]);
            let ct = &envelope.ciphertext;
            let aad_len = *ct.first().ok_or(BackendError::DecryptFailed)? as usize;
            let bound = ct.get(1..1 + aad_len).ok_or(BackendError::DecryptFailed)?;
            if bound != aad {
                return Err(BackendError::DecryptFailed);
            }
            Ok(ct
                .get(1 + aad_len..)
                .ok_or(BackendError::DecryptFailed)?
                .to_vec())
        }

        async fn kv_put(&self, key_id: &str, value: &[u8]) -> Result<u32, BackendError> {
            self.store
                .lock()
                .map_err(|_| BackendError::Unsupported("kv_put"))?
                .insert(key_id.to_string(), value.to_vec());
            Ok(1)
        }

        async fn kv_get(
            &self,
            key_id: &str,
            _version: Option<u32>,
        ) -> Result<KvValue, BackendError> {
            let value = self
                .store
                .lock()
                .map_err(|_| BackendError::Unsupported("kv_get"))?
                .get(key_id)
                .cloned();
            value
                .map(|value| KvValue { value, version: 1 })
                .ok_or(BackendError::Unsupported("kv_get"))
        }

        async fn kv_get_secret(
            &self,
            key_id: &str,
            _version: Option<u32>,
        ) -> Result<crate::backend::KvSecret, BackendError> {
            let value = self
                .store
                .lock()
                .map_err(|_| BackendError::Unsupported("kv_get_secret"))?
                .get(key_id)
                .cloned();
            value
                .map(|value| crate::backend::KvSecret {
                    value: Zeroizing::new(value),
                    version: 1,
                })
                .ok_or(BackendError::Unsupported("kv_get_secret"))
        }
    }

    const CATALOG: &str = r#"{
      "schema": "catalog",
      "backends": { "bao": { "kind": "vault", "addr": "https://127.0.0.1:8200" } },
      "keys": {
        "cose.sealing": {
          "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2",
          "path": "secret/data/cose/sealing",
          "publicPath": "secret/data/cose/sealing-public",
          "writable": true, "missing": "error",
          "description": "x25519 COSE recipient key"
        },
        "cose.wrong": {
          "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2",
          "path": "secret/data/cose/wrong",
          "publicPath": "secret/data/cose/wrong-public",
          "writable": true, "missing": "error",
          "description": "wrong x25519 COSE recipient key"
        },
        "cose.pinparties": {
          "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2",
          "path": "secret/data/cose/pin-parties",
          "publicPath": "secret/data/cose/pin-parties-public",
          "writable": true, "missing": "error",
          "sealingPin": { "parties": { "partyU": "alice", "partyV": "bob" } },
          "description": "x25519 COSE recipient key pinned to alice/bob KDF parties"
        },
        "cose.pinaad": {
          "class": "sealing", "keyType": "x25519", "backend": "bao", "engine": "kv2",
          "path": "secret/data/cose/pin-aad",
          "publicPath": "secret/data/cose/pin-aad-public",
          "writable": true, "missing": "error",
          "sealingPin": { "externalAad": ["ctx"] },
          "description": "x25519 COSE recipient key pinned to the ctx external_aad"
        },
        "pqc.sealing": {
          "class": "sealing", "keyType": "ml-kem-768", "backend": "bao", "engine": "kv2",
          "path": "secret/data/pqc/sealing",
          "publicPath": "secret/data/pqc/sealing-public",
          "writable": true, "missing": "error",
          "labels": ["crypto_provider=local-software", "crypto_provider_policy=local-software",
                     "pqc_custody=software-encrypted", "pqc_storage_key=pqc/aead",
                     "pqc_algorithm=ml-kem-768", "crypto_provider_version=1"],
          "description": "ml-kem-768 software-custodied sealing key"
        }
      }
    }"#;

    // uid 42 holds the local-software grant; uid 43 holds encrypt/decrypt but NOT
    // op:use_software_custody, so it cannot drive the local-software provider.
    const POLICY: &str = r#"{
      "schema": "policy",
      "subjects": {
        "svc.granted": { "domain": "host-process", "match": { "all": [ { "process.uid": 42 } ] } },
        "svc.ungranted": { "domain": "host-process", "match": { "all": [ { "process.uid": 43 } ] } }
      },
      "roles": {},
      "rules": [
        { "id": "granted", "subjects": ["svc.granted"],
          "action": ["op:encrypt", "op:decrypt", "op:use_software_custody"],
          "target": ["pqc.*", "cose.*"] },
        { "id": "ungranted", "subjects": ["svc.ungranted"],
          "action": ["op:encrypt", "op:decrypt"],
          "target": ["pqc.*", "cose.*"] }
      ],
      "config": {
        "names": { "users": { "42": "svc-granted", "43": "svc-ungranted" }, "groups": {} },
        "memberships": { "42": [42], "43": [43] }
      }
    }"#;

    // The seed and its custody path are consumed only by the unwrap test and
    // `ml_kem_record`.
    const SEED: [u8; 64] = [0x42; 64];
    const SEALING_PATH: &str = "secret/data/pqc/sealing";
    const COSE_KEY_ID: &str = "cose.sealing";
    const COSE_WRONG_KEY_ID: &str = "cose.wrong";
    const COSE_PIN_PARTIES_KEY_ID: &str = "cose.pinparties";
    const COSE_PIN_AAD_KEY_ID: &str = "cose.pinaad";
    const COSE_PATH: &str = "secret/data/cose/sealing";
    const COSE_WRONG_PATH: &str = "secret/data/cose/wrong";
    const COSE_PIN_PARTIES_PATH: &str = "secret/data/cose/pin-parties";
    const COSE_PIN_AAD_PATH: &str = "secret/data/cose/pin-aad";
    const COSE_PRIVATE: [u8; 32] = [0x37; 32];
    const COSE_WRONG_PRIVATE: [u8; 32] = [0xA5; 32];

    fn service(backend: SealingBackend) -> BrokerGrpc {
        let (catalog, policy, config, warnings) = load(CATALOG, POLICY).expect("fixture loads");
        assert!(warnings.is_empty());
        let mut backends: BTreeMap<String, Box<dyn Backend>> = BTreeMap::new();
        backends.insert("bao".to_string(), Box::new(backend));
        let manager = BackendManager::new(catalog.clone(), backends).expect("manager builds");
        BrokerGrpc::new(Arc::new(BrokerState::new(
            catalog,
            policy,
            config,
            manager,
            "pqc-aead-test",
        )))
    }

    fn request<T>(uid: u32, body: T) -> Request<T> {
        let mut request = Request::new(body);
        request.extensions_mut().insert(PeerInfo {
            uid: Some(uid),
            ..PeerInfo::default()
        });
        request
    }

    fn cose_backend() -> SealingBackend {
        let backend = SealingBackend::seeded(COSE_PATH, COSE_PRIVATE.to_vec());
        if let Ok(mut store) = backend.store.lock() {
            store.insert(COSE_WRONG_PATH.to_string(), COSE_WRONG_PRIVATE.to_vec());
            // The pinned keys share the same private so a matching-context envelope
            // still opens; only the pin cross-check differs.
            store.insert(COSE_PIN_PARTIES_PATH.to_string(), COSE_PRIVATE.to_vec());
            store.insert(COSE_PIN_AAD_PATH.to_string(), COSE_PRIVATE.to_vec());
        }
        backend
    }

    fn cose_parties() -> KdfParties {
        KdfParties {
            party_u: PartyIdentity::from_bytes(b"alice".to_vec()).expect("valid PartyU"),
            party_v: PartyIdentity::from_bytes(b"bob".to_vec()).expect("valid PartyV"),
        }
    }

    fn cose_parties_other() -> KdfParties {
        KdfParties {
            party_u: PartyIdentity::from_bytes(b"alice".to_vec()).expect("valid PartyU"),
            party_v: PartyIdentity::from_bytes(b"carol".to_vec()).expect("valid PartyV"),
        }
    }

    fn cose_message(key_id: &str, private: [u8; 32], aad: &[u8], parties: KdfParties) -> Vec<u8> {
        let key_id = KeyId::from_text(key_id).expect("valid key id");
        let recipient = basil_cose::X25519Recipient::new(key_id, Zeroizing::new(private)).public();
        basil_cose::build_encrypted(&EncryptParams {
            content_type: ContentType::new("application/basil.peer".to_string())
                .expect("valid content type"),
            plaintext: b"peer message",
            recipient,
            content_algorithm: ContentAlgorithm::A256Gcm,
            external_aad: ExternalAad::from_bytes(aad.to_vec()),
            kdf_parties: parties,
        })
        .expect("COSE seal succeeds")
        .into_vec()
    }

    /// Build a valid ML-KEM software-custody record JSON sealing `SEED` under the
    /// `SealingBackend` identity envelope, with the AAD the provider reconstructs.
    fn ml_kem_record() -> Vec<u8> {
        use crate::core::crypto_provider::{SoftwareCustodyCatalog, encode_record_bytes};

        let meta = SoftwareCustodyCatalog {
            key_id: "pqc.sealing",
            algorithm: "ml-kem-768",
            provider: "local-software",
            provider_version: "1",
            custody: "software-encrypted",
            storage_key: "pqc/aead",
        };
        let aad = meta.aad(1);
        let mut ciphertext = vec![u8::try_from(aad.len()).expect("aad fits")];
        ciphertext.extend_from_slice(&aad);
        ciphertext.extend_from_slice(&SEED);
        serde_json::json!({
            "schemaVersion": 1,
            "keyId": "pqc.sealing",
            "keyVersion": 1,
            "publicKey": encode_record_bytes(&[0x7A; 1184]),
            "algorithm": "ml-kem-768",
            "provider": "local-software",
            "providerVersion": "1",
            "custody": "software-encrypted",
            "encryptedPrivateKey": {
                "wrappingKey": "pqc/aead",
                "algorithm": "aes-256-gcm",
                "keyVersion": 1,
                "nonce": encode_record_bytes(&[]),
                "ciphertext": encode_record_bytes(&ciphertext),
            }
        })
        .to_string()
        .into_bytes()
    }

    // The wire round trip wraps then unwraps through the gRPC contract; the deny
    // test below fails closed before the provider runs.
    #[tokio::test]
    async fn ml_kem_wrap_unwrap_through_grpc_with_grant() {
        let svc = service(SealingBackend::seeded(SEALING_PATH, ml_kem_record()));
        let wrapped = svc
            .wrap_envelope(request(
                42,
                pb::WrapEnvelopeRequest {
                    key_id: "pqc.sealing".to_string(),
                    plaintext: b"enrollment payload".to_vec(),
                    kem_algorithm: pb::KemAlgorithm::MlKem768.into(),
                    envelope_algorithm: pb::EnvelopeAlgorithm::Aes256Gcm.into(),
                    aad: Some(b"ctx".to_vec()),
                },
            ))
            .await
            .expect("wrap succeeds with grant")
            .into_inner()
            .envelope
            .expect("wrap returns an envelope");
        // Self-describing: the wire envelope echoes the requested algorithms.
        assert_eq!(wrapped.kem_algorithm, i32::from(pb::KemAlgorithm::MlKem768));
        assert_eq!(
            wrapped.envelope_algorithm,
            i32::from(pb::EnvelopeAlgorithm::Aes256Gcm)
        );

        let plaintext = svc
            .unwrap_envelope(request(
                42,
                pb::UnwrapEnvelopeRequest {
                    key_id: "pqc.sealing".to_string(),
                    envelope: Some(wrapped),
                    aad: Some(b"ctx".to_vec()),
                },
            ))
            .await
            .expect("unwrap succeeds with grant")
            .into_inner()
            .plaintext;
        assert_eq!(plaintext, b"enrollment payload");
    }

    // An envelope naming no AEAD suite is an implicit attacker-suppliable
    // algorithm choice; decrypt must reject it, not fall back to a default.
    #[tokio::test]
    async fn decrypt_rejects_an_unspecified_aead_algorithm() {
        let svc = service(cose_backend());
        let status = svc
            .decrypt(request(
                42,
                pb::DecryptRequest {
                    key_id: COSE_KEY_ID.to_string(),
                    envelope: Some(pb::CiphertextEnvelope {
                        alg: pb::AeadAlgorithm::Unspecified.into(),
                        key_version: 1,
                        nonce: vec![0u8; 12],
                        ciphertext: vec![0u8; 32],
                    }),
                    aad: None,
                },
            ))
            .await
            .expect_err("unspecified AEAD algorithm is rejected on decrypt");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(
            status.message().contains("missing AEAD algorithm"),
            "unexpected message: {}",
            status.message()
        );
    }

    #[tokio::test]
    async fn unseal_cose_through_grpc_with_x25519_key() {
        let svc = service(cose_backend());
        let cose_encrypt = cose_message(COSE_KEY_ID, COSE_PRIVATE, b"ctx", cose_parties());

        let plaintext = svc
            .unseal_cose(request(
                42,
                pb::UnsealCoseRequest {
                    key_id: COSE_KEY_ID.to_string(),
                    cose_encrypt,
                    external_aad: Some(b"ctx".to_vec()),
                },
            ))
            .await
            .expect("unseal succeeds")
            .into_inner()
            .plaintext;
        assert_eq!(plaintext, b"peer message");
    }

    #[tokio::test]
    async fn unseal_cose_wrong_key_fails_closed() {
        let svc = service(cose_backend());
        let cose_encrypt = cose_message(COSE_KEY_ID, COSE_PRIVATE, b"ctx", cose_parties());

        let status = svc
            .unseal_cose(request(
                42,
                pb::UnsealCoseRequest {
                    key_id: COSE_WRONG_KEY_ID.to_string(),
                    cose_encrypt,
                    external_aad: Some(b"ctx".to_vec()),
                },
            ))
            .await
            .expect_err("wrong recipient key is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn unseal_cose_wrong_aad_fails_closed() {
        let svc = service(cose_backend());
        let cose_encrypt = cose_message(COSE_KEY_ID, COSE_PRIVATE, b"right", cose_parties());

        let status = svc
            .unseal_cose(request(
                42,
                pb::UnsealCoseRequest {
                    key_id: COSE_KEY_ID.to_string(),
                    cose_encrypt,
                    external_aad: Some(b"wrong".to_vec()),
                },
            ))
            .await
            .expect_err("wrong AAD is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    fn tamper_party_identity(mut cose_encrypt: Vec<u8>) -> Vec<u8> {
        let offset = cose_encrypt
            .windows(b"alice".len())
            .position(|w| w == b"alice")
            .expect("party identity is encoded");
        let end = offset + b"alica".len();
        cose_encrypt[offset..end].copy_from_slice(b"alica");
        cose_encrypt
    }

    #[tokio::test]
    async fn unseal_cose_tampered_party_info_fails_closed() {
        let svc = service(cose_backend());
        let cose_encrypt = tamper_party_identity(cose_message(
            COSE_KEY_ID,
            COSE_PRIVATE,
            b"ctx",
            cose_parties(),
        ));
        let status = svc
            .unseal_cose(request(
                42,
                pb::UnsealCoseRequest {
                    key_id: COSE_KEY_ID.to_string(),
                    cose_encrypt,
                    external_aad: Some(b"ctx".to_vec()),
                },
            ))
            .await
            .expect_err("unexpected party info is not accepted");
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    // ---- Catalog pinning of the UnsealCose decrypt oracle (basil-2rqj) --------

    #[tokio::test]
    async fn unseal_cose_pinned_parties_match_succeeds() {
        // The key pins partyU=alice/partyV=bob; an envelope carrying exactly those
        // parties opens under the op:decrypt grant.
        let svc = service(cose_backend());
        let cose_encrypt = cose_message(
            COSE_PIN_PARTIES_KEY_ID,
            COSE_PRIVATE,
            b"ctx",
            cose_parties(),
        );
        let plaintext = svc
            .unseal_cose(request(
                42,
                pb::UnsealCoseRequest {
                    key_id: COSE_PIN_PARTIES_KEY_ID.to_string(),
                    cose_encrypt,
                    external_aad: Some(b"ctx".to_vec()),
                },
            ))
            .await
            .expect("matching pinned parties open")
            .into_inner()
            .plaintext;
        assert_eq!(plaintext, b"peer message");
    }

    #[tokio::test]
    async fn unseal_cose_pinned_wrong_party_fails_closed() {
        // Same key/grant, but the envelope names partyV=carol, outside the pin.
        // A least-privilege refusal: PermissionDenied, not a decrypt oracle.
        let svc = service(cose_backend());
        let cose_encrypt = cose_message(
            COSE_PIN_PARTIES_KEY_ID,
            COSE_PRIVATE,
            b"ctx",
            cose_parties_other(),
        );
        let status = svc
            .unseal_cose(request(
                42,
                pb::UnsealCoseRequest {
                    key_id: COSE_PIN_PARTIES_KEY_ID.to_string(),
                    cose_encrypt,
                    external_aad: Some(b"ctx".to_vec()),
                },
            ))
            .await
            .expect_err("a party outside the pin is refused");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn unseal_cose_pinned_absent_party_fails_closed() {
        // The pin requires named parties; an anonymous (nil) envelope is refused.
        let svc = service(cose_backend());
        let cose_encrypt = cose_message(
            COSE_PIN_PARTIES_KEY_ID,
            COSE_PRIVATE,
            b"ctx",
            KdfParties::anonymous(),
        );
        let status = svc
            .unseal_cose(request(
                42,
                pb::UnsealCoseRequest {
                    key_id: COSE_PIN_PARTIES_KEY_ID.to_string(),
                    cose_encrypt,
                    external_aad: Some(b"ctx".to_vec()),
                },
            ))
            .await
            .expect_err("absent parties when pinned is refused");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn unseal_cose_pinned_aad_match_succeeds() {
        // The key pins external_aad=["ctx"] but not parties; a ctx-bound envelope
        // with any parties opens.
        let svc = service(cose_backend());
        let cose_encrypt = cose_message(
            COSE_PIN_AAD_KEY_ID,
            COSE_PRIVATE,
            b"ctx",
            KdfParties::anonymous(),
        );
        let plaintext = svc
            .unseal_cose(request(
                42,
                pb::UnsealCoseRequest {
                    key_id: COSE_PIN_AAD_KEY_ID.to_string(),
                    cose_encrypt,
                    external_aad: Some(b"ctx".to_vec()),
                },
            ))
            .await
            .expect("matching pinned external_aad open")
            .into_inner()
            .plaintext;
        assert_eq!(plaintext, b"peer message");
    }

    #[tokio::test]
    async fn unseal_cose_pinned_wrong_aad_fails_closed() {
        // A caller-supplied external_aad outside the pinned set is refused before
        // the private is ever materialized: PermissionDenied.
        let svc = service(cose_backend());
        let cose_encrypt = cose_message(
            COSE_PIN_AAD_KEY_ID,
            COSE_PRIVATE,
            b"other",
            KdfParties::anonymous(),
        );
        let status = svc
            .unseal_cose(request(
                42,
                pb::UnsealCoseRequest {
                    key_id: COSE_PIN_AAD_KEY_ID.to_string(),
                    cose_encrypt,
                    external_aad: Some(b"other".to_vec()),
                },
            ))
            .await
            .expect_err("an external_aad outside the pin is refused");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn unseal_cose_pinned_aad_absent_fails_closed() {
        // The pin requires a ctx binding; an absent (empty) external_aad is refused.
        let svc = service(cose_backend());
        let cose_encrypt = cose_message(
            COSE_PIN_AAD_KEY_ID,
            COSE_PRIVATE,
            b"ctx",
            KdfParties::anonymous(),
        );
        let status = svc
            .unseal_cose(request(
                42,
                pb::UnsealCoseRequest {
                    key_id: COSE_PIN_AAD_KEY_ID.to_string(),
                    cose_encrypt,
                    external_aad: None,
                },
            ))
            .await
            .expect_err("absent external_aad when pinned is refused");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn ml_kem_wrap_without_software_custody_grant_is_denied() {
        // uid 43 may Encrypt (authorize passes) but lacks op:use_software_custody,
        // so the local-software provider is denied: fail closed as PermissionDenied
        // before any backend access.
        let svc = service(SealingBackend::default());
        let status = svc
            .wrap_envelope(request(
                43,
                pb::WrapEnvelopeRequest {
                    key_id: "pqc.sealing".to_string(),
                    plaintext: b"payload".to_vec(),
                    kem_algorithm: pb::KemAlgorithm::MlKem768.into(),
                    envelope_algorithm: pb::EnvelopeAlgorithm::Aes256Gcm.into(),
                    aad: None,
                },
            ))
            .await
            .expect_err("ml-kem wrap denied without local-software grant");
        assert_eq!(status.code(), Code::PermissionDenied);
    }
}
