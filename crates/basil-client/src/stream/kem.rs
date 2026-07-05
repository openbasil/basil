//! ML-KEM key-establishment for streaming encryption.
//!
//! For an ML-KEM stream the 256-bit content-encryption key (CEK) is generated
//! once, wrapped into an ML-KEM + AES-256-GCM envelope against the recipient's
//! public encapsulation key, and written into the container header exactly once.
//! Decryption recovers the CEK from that envelope through a [`CekRecovery`] seam:
//!
//! * [`BrokerCekRecovery`] recovers it through the broker's `UnwrapEnvelope` RPC,
//!   so the ML-KEM decapsulation key (seed) stays custodied. Encryption needs
//!   only the public key, so it never touches the broker.
//! * [`LocalSeedCekRecovery`] decapsulates locally with a raw seed; it exists so
//!   the container format is fully testable without a live broker.
//!
//! The envelope bytes are byte-compatible with `basil-core`'s ML-KEM envelope
//! (`HKDF-SHA256` label `basil-ml-kem-envelope-v1`), so a CEK wrapped here is
//! openable by the broker.

use std::future::Future;

use basil_proto::broker::v1 as pb;
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, FromSeed, KeyExport, TryKeyInit};
use ml_kem::{MlKem512, MlKem768, MlKem1024};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::format::{
    CEK_LEN, ChunkAead, NONCE_LEN, StreamError, StreamResult, aead_open, aead_seal,
};
use super::{MlKemSuite, fill_random};
use crate::client::Client;

/// HKDF info label for the CEK-wrap envelope. Must match `basil-core`'s
/// `ml_kem_envelope` so a broker can open a CEK wrapped by this client.
const KEM_ENVELOPE_LABEL: &[u8] = b"basil-ml-kem-envelope-v1";
/// Envelope AEAD token bound into the KEM HKDF info. The CEK wrap always uses
/// AES-256-GCM.
const ENV_TOKEN_AES256GCM: &[u8] = b"aes-256-gcm";

/// The KEM-wrapped content-encryption key carried once in an ML-KEM stream
/// header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamKemEnvelope {
    /// ML-KEM ciphertext (the encapsulated key).
    pub encapsulated_key: Vec<u8>,
    /// AEAD nonce used to seal the CEK.
    pub nonce: [u8; NONCE_LEN],
    /// AEAD ciphertext (the wrapped CEK plus authentication tag).
    pub ciphertext: Vec<u8>,
}

/// Recovers the content-encryption key from a stream's ML-KEM envelope.
///
/// Implementations recover the CEK exactly once per stream and must fail closed
/// on any error.
pub trait CekRecovery {
    /// Recover the wrapped CEK from `envelope`, authenticating `aad`.
    ///
    /// # Errors
    ///
    /// Returns a [`StreamError`] for a wrong recipient key, a tampered envelope,
    /// or a broker/transport failure.
    fn recover_cek(
        &self,
        envelope: &StreamKemEnvelope,
        aad: &[u8],
    ) -> impl Future<Output = StreamResult<Zeroizing<Vec<u8>>>> + Send;
}

/// Recovers the CEK through the broker's `UnwrapEnvelope` RPC. The decapsulation
/// key stays custodied; only the broker can recover the shared secret.
#[derive(Clone)]
pub struct BrokerCekRecovery {
    client: Client,
    key_id: String,
    suite: MlKemSuite,
}

impl BrokerCekRecovery {
    /// Build a broker-backed recovery seam for the sealing key `key_id`.
    #[must_use]
    pub fn new(client: Client, key_id: impl Into<String>, suite: MlKemSuite) -> Self {
        Self {
            client,
            key_id: key_id.into(),
            suite,
        }
    }
}

impl CekRecovery for BrokerCekRecovery {
    fn recover_cek(
        &self,
        envelope: &StreamKemEnvelope,
        aad: &[u8],
    ) -> impl Future<Output = StreamResult<Zeroizing<Vec<u8>>>> + Send {
        let mut client = self.client.clone();
        let key_id = self.key_id.clone();
        let pb_env = pb::KemEnvelope {
            kem_algorithm: i32::from(self.suite.proto_kem_algorithm()),
            envelope_algorithm: i32::from(pb::EnvelopeAlgorithm::Aes256Gcm),
            key_version: 0,
            encapsulated_key: envelope.encapsulated_key.clone(),
            nonce: envelope.nonce.to_vec(),
            ciphertext: envelope.ciphertext.clone(),
        };
        let aad = aad.to_vec();
        async move {
            let cek = client.unwrap_envelope(&key_id, pb_env, Some(&aad)).await?;
            if cek.len() != CEK_LEN {
                return Err(StreamError::BadCekLength);
            }
            Ok(Zeroizing::new(cek))
        }
    }
}

/// Recovers the CEK by decapsulating locally with a raw 64-byte seed.
///
/// This bypasses the broker and is intended for tests and tools that legitimately
/// hold the seed; production decryptors should prefer [`BrokerCekRecovery`].
pub struct LocalSeedCekRecovery {
    seed: Zeroizing<Vec<u8>>,
    suite: MlKemSuite,
}

impl LocalSeedCekRecovery {
    /// Build a local recovery seam from a raw ML-KEM seed.
    #[must_use]
    pub fn new(seed: impl Into<Vec<u8>>, suite: MlKemSuite) -> Self {
        Self {
            seed: Zeroizing::new(seed.into()),
            suite,
        }
    }
}

impl CekRecovery for LocalSeedCekRecovery {
    fn recover_cek(
        &self,
        envelope: &StreamKemEnvelope,
        aad: &[u8],
    ) -> impl Future<Output = StreamResult<Zeroizing<Vec<u8>>>> + Send {
        let recovered = open_cek_local(&self.seed, self.suite, envelope, aad);
        async move { recovered }
    }
}

/// Wrap a content-encryption key into an ML-KEM envelope against `public_key`.
///
/// # Errors
///
/// Returns [`StreamError::BadPublicKey`] for a malformed encapsulation key and
/// [`StreamError::SealFailed`]/[`StreamError::KdfFailed`] for crypto failures.
pub fn wrap_cek(
    public_key: &[u8],
    suite: MlKemSuite,
    cek: &[u8],
    aad: &[u8],
) -> StreamResult<StreamKemEnvelope> {
    let (encapsulated_key, shared_secret, derived_public) = match suite {
        MlKemSuite::MlKem512 => encapsulate_to::<MlKem512>(public_key)?,
        MlKemSuite::MlKem768 => encapsulate_to::<MlKem768>(public_key)?,
        MlKemSuite::MlKem1024 => encapsulate_to::<MlKem1024>(public_key)?,
    };
    let aead_key = derive_kem_aead_key(suite, &shared_secret, &encapsulated_key, &derived_public)?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce);
    let ciphertext = aead_seal(ChunkAead::Aes256Gcm, &aead_key, &nonce, cek, aad)?;
    Ok(StreamKemEnvelope {
        encapsulated_key,
        nonce,
        ciphertext,
    })
}

/// Recover a CEK from an ML-KEM envelope using a raw 64-byte seed.
///
/// # Errors
///
/// Returns [`StreamError::BadKemCiphertext`] for malformed key material and
/// [`StreamError::AuthFailed`] for a wrong key or tampered envelope.
pub fn open_cek_local(
    seed: &[u8],
    suite: MlKemSuite,
    envelope: &StreamKemEnvelope,
    aad: &[u8],
) -> StreamResult<Zeroizing<Vec<u8>>> {
    let seed = seed_from_slice(seed)?;
    let (shared_secret, derived_public) = match suite {
        MlKemSuite::MlKem512 => {
            decapsulate_with_seed::<MlKem512>(&seed, &envelope.encapsulated_key)?
        }
        MlKemSuite::MlKem768 => {
            decapsulate_with_seed::<MlKem768>(&seed, &envelope.encapsulated_key)?
        }
        MlKemSuite::MlKem1024 => {
            decapsulate_with_seed::<MlKem1024>(&seed, &envelope.encapsulated_key)?
        }
    };
    let aead_key = derive_kem_aead_key(
        suite,
        &shared_secret,
        &envelope.encapsulated_key,
        &derived_public,
    )?;
    aead_open(
        ChunkAead::Aes256Gcm,
        &aead_key,
        &envelope.nonce,
        &envelope.ciphertext,
        aad,
    )
}

/// Serialize the KEM header that follows the fixed header for an ML-KEM stream.
///
/// Layout (big-endian lengths): `kem_ct_len[4] | encapsulated_key |
/// cek_nonce[12] | wrapped_cek_len[4] | wrapped_cek`.
///
/// # Errors
///
/// Returns [`StreamError::SealFailed`] if a field length exceeds `u32`.
pub fn serialize_kem_header(env: &StreamKemEnvelope) -> StreamResult<Vec<u8>> {
    let kem_ct_len =
        u32::try_from(env.encapsulated_key.len()).map_err(|_| StreamError::SealFailed)?;
    let wrapped_len = u32::try_from(env.ciphertext.len()).map_err(|_| StreamError::SealFailed)?;
    let mut out =
        Vec::with_capacity(8 + env.encapsulated_key.len() + NONCE_LEN + env.ciphertext.len());
    out.extend_from_slice(&kem_ct_len.to_be_bytes());
    out.extend_from_slice(&env.encapsulated_key);
    out.extend_from_slice(&env.nonce);
    out.extend_from_slice(&wrapped_len.to_be_bytes());
    out.extend_from_slice(&env.ciphertext);
    Ok(out)
}

fn derive_kem_aead_key(
    suite: MlKemSuite,
    shared_secret: &[u8],
    encapsulated_key: &[u8],
    public_key: &[u8],
) -> StreamResult<Zeroizing<[u8; CEK_LEN]>> {
    let kem_token = suite.kem_token().as_bytes();
    let mut info = Vec::with_capacity(
        KEM_ENVELOPE_LABEL.len()
            + kem_token.len()
            + ENV_TOKEN_AES256GCM.len()
            + encapsulated_key.len()
            + public_key.len(),
    );
    info.extend_from_slice(KEM_ENVELOPE_LABEL);
    info.extend_from_slice(kem_token);
    info.extend_from_slice(ENV_TOKEN_AES256GCM);
    info.extend_from_slice(encapsulated_key);
    info.extend_from_slice(public_key);

    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = Zeroizing::new([0u8; CEK_LEN]);
    hk.expand(&info, okm.as_mut_slice())
        .map_err(|_| StreamError::KdfFailed)?;
    Ok(okm)
}

fn to_vec_bytes(value: &impl AsRef<[u8]>) -> Vec<u8> {
    value.as_ref().to_vec()
}

/// `(encapsulated_key, shared_secret, derived_public_key)` from a KEM encapsulation.
type Encapsulation = (Vec<u8>, Zeroizing<Vec<u8>>, Vec<u8>);

fn encapsulate_to<K>(public_key: &[u8]) -> StreamResult<Encapsulation>
where
    K: ml_kem::kem::Kem,
    K::EncapsulationKey: Encapsulate<Kem = K>,
{
    let ek = <K::EncapsulationKey as TryKeyInit>::new_from_slice(public_key)
        .map_err(|_| StreamError::BadPublicKey)?;
    let derived_public = <K::EncapsulationKey as KeyExport>::to_bytes(&ek);
    let (encapsulated_key, shared_secret) = ek.encapsulate();
    Ok((
        to_vec_bytes(&encapsulated_key),
        Zeroizing::new(to_vec_bytes(&shared_secret)),
        to_vec_bytes(&derived_public),
    ))
}

fn decapsulate_with_seed<K>(
    seed: &ml_kem::Seed,
    encapsulated_key: &[u8],
) -> StreamResult<(Zeroizing<Vec<u8>>, Vec<u8>)>
where
    K: ml_kem::kem::Kem + FromSeed<SeedSize = ml_kem::array::sizes::U64>,
    K::DecapsulationKey: Decapsulate<Kem = K>,
    K::EncapsulationKey: KeyExport,
{
    let (decapsulation_key, encapsulation_key) = K::from_seed(seed);
    let shared_secret = decapsulation_key
        .decapsulate_slice(encapsulated_key)
        .map_err(|_| StreamError::BadKemCiphertext)?;
    let derived_public = encapsulation_key.to_bytes();
    Ok((
        Zeroizing::new(to_vec_bytes(&shared_secret)),
        to_vec_bytes(&derived_public),
    ))
}

fn seed_from_slice(seed: &[u8]) -> StreamResult<Zeroizing<ml_kem::Seed>> {
    let seed = seed.try_into().map_err(|_| StreamError::BadKemCiphertext)?;
    Ok(Zeroizing::new(seed))
}

/// Derive the public encapsulation key from a raw seed. Test-only helper that
/// stands in for the broker's published public encapsulation key.
#[cfg(test)]
pub fn public_from_seed(seed: &[u8], suite: MlKemSuite) -> StreamResult<Vec<u8>> {
    let seed = seed_from_slice(seed)?;
    let public = match suite {
        MlKemSuite::MlKem512 => public_from_seed_for::<MlKem512>(&seed),
        MlKemSuite::MlKem768 => public_from_seed_for::<MlKem768>(&seed),
        MlKemSuite::MlKem1024 => public_from_seed_for::<MlKem1024>(&seed),
    };
    Ok(public)
}

#[cfg(test)]
fn public_from_seed_for<K>(seed: &ml_kem::Seed) -> Vec<u8>
where
    K: ml_kem::kem::Kem + FromSeed<SeedSize = ml_kem::array::sizes::U64>,
    K::EncapsulationKey: KeyExport,
{
    let (_decapsulation_key, encapsulation_key) = K::from_seed(seed);
    to_vec_bytes(&encapsulation_key.to_bytes())
}
