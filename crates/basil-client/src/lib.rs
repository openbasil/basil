//! `basil`: client library for the basil agent.
//!
//! The public client talks to Basil's broker over gRPC.

// Index/slice in test code is fine (fixed test vectors); the no-panic
// `indexing_slicing` gate has no test-allow config option, unlike unwrap/expect.
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod constants;
pub mod error;
pub mod proto;

pub mod client;
pub mod client_sync;
pub mod sealed_invocation;
pub mod stream;

pub use basil_proto::broker::v1::{
    AeadAlgorithm as GrpcAeadAlgorithm, CatalogEntry as GrpcCatalogEntry,
    CatalogKind as GrpcCatalogKind, CiphertextEnvelope as GrpcCiphertextEnvelope,
    EnvelopeAlgorithm, Event, EventKind, KemAlgorithm, KemEnvelope, KeyMaterial as GrpcKeyMaterial,
    NatsJtiMode, NatsJwtType, NatsJwtValidationReason as GrpcNatsJwtValidationReason,
    SigningAlgorithm,
};
pub use client::{
    AgentExplanation, AgentHealth, AgentReadiness, AgentReload, AgentRevocation, AgentStatus,
    AllowedNatsSigner, Client, ImportEntry, IssuedCertificate, KeyHandle, MatchedRule, MintedJwt,
    NatsJwtValidation, NatsJwtValidationReason, NatsUserPermissions, ReadinessReason,
    ReloadRejection, SecretValue, SignNatsJwtOptions,
};
pub use client_sync::BlockingClient;
pub use error::{Error, Result};
pub use proto::{
    AeadAlgorithm, CatalogEntry, CatalogKind, CiphertextEnvelope, KeyMaterial, KeyType,
};
pub use sealed_invocation::{
    BrokerRecipient, BrokerSigner, CarrierSigner, CarrierSignerConfig, LocalCarrierSigner,
    LocalSealedInvocationRecipient, LocalSealedInvocationSigner, PreparedSealedInvocation,
    SealedInvocationBody, SealedInvocationCarrier, SealedInvocationError, SealedInvocationOptions,
    SealedInvocationResponseError, prepare_sealed_invocation, verify_and_decrypt_sign_response,
    verify_and_open_sign_response,
};
pub use stream::{
    AeadSuite, BrokerCekRecovery, CekRecovery, CekSource, DEFAULT_CHUNK_SIZE, LocalSeedCekRecovery,
    MAX_CHUNK_SIZE, MlKemSuite, StreamError, StreamKemEnvelope, StreamResult, decrypt_aead,
    decrypt_ml_kem, encrypt_aead, encrypt_ml_kem,
};
