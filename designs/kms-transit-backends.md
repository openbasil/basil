# AWS/GCP KMS transit backends (design + SDK notes)

Status: **Phase 2, not yet implemented.** Phase 1 (1Password → keystore-backend,
secretspec removed) is done.

## Decision (settled with user)

- **1Password** is a materialize-to-use key/value store → lives in
  `basil-keystore-backend` behind `SecretStore` (done in Phase 1).
- **AWS KMS + GCP Cloud KMS** are *transit* services: the private key never
  leaves the KMS and **cannot be exported**, so materialize-to-use is impossible.
  They are implemented as in-place `Backend`s (like `VaultBackend`), **not** as
  keystore adapters. They live in `basil-core/src/core/backend/` behind features
  `aws-kms` / `gcp-kms`.
- Scope: **KMS transit only**; no AWS Secrets Manager / GCP Secret Manager KV
  port.

## Placement / wiring plan

- New `core/backend/aws_kms.rs`, `core/backend/gcp_kms.rs`, each `impl Backend`
  (async_trait), gated `#[cfg(feature = "aws-kms")]` / `"gcp-kms"`.
- Implement only the transit-shaped methods; everything else keeps the trait's
  `Unsupported` default: `kind`, `new_key`/`create_named_key`, `public_key`
  (+`_with_meta`), `sign`(+options for ES256/384/512), `verify`, `encrypt`,
  `decrypt`. `rotate`/`kv_*`/PKI stay `Unsupported` (KMS has no KV/PKI here).

## Status of the first cut (implemented) and tracked follow-ups

The operational surface is **implemented and gated**: `sign`/`verify`/`public_key`
(+`_with_meta`)/`encrypt`/`decrypt` over pre-provisioned keys, Ed25519 signing +
symmetric AES-256-GCM, for both AWS KMS and GCP Cloud KMS. Everything else fails
closed as `Unsupported`. Tracked follow-ups (`br`, label `kms`):

- **`basil-ayty`** (done): `new_key`/`create_named_key`/`create_named_aead`
  key provisioning. AWS creates customer managed keys and deterministic aliases;
  GCP creates `CryptoKey`s under the configured key ring and returns version-1
  handles for asymmetric keys.
- **`basil-4s0s`** (done): `GcpKms` optional **sealed service-account JSON**:
  `BackendCred::GcpKms` can now carry the whole key-file JSON as a sealed secret,
  and the backend uses it instead of ADC when present. Corrects the "`GcpKms` is
  non-secret" assumption below. See `designs/bundle-credential-deposit.md`.
- **`basil-ujic`** (done) adds ECDSA / JWS signing. AWS KMS supports
  `ES256`/`ES384`/`ES512`; GCP Cloud KMS supports `ES256`/`ES384` and
  provider-rejects `ES512` because Cloud KMS exposes no P-521 signing key.
  Basil converts provider DER signatures to/from JWS raw `r‖s`.
- **`basil-y3g8`** (done): `bundle set-cred` support for `AwsKms`/`GcpKms`
  creds. `AwsKms` accepts `--aws-kms-region` plus optional
  `--aws-kms-profile`; `GcpKms` accepts project/location/key-ring plus optional
  sealed service-account JSON.
- **`basil-0tk7`** (done): GCP explicit `cryptoKeyVersion` selection:
  asymmetric catalog paths now carry `cryptoKeyVersions/<N>`, and
  sign/public-key/JWKS paths use and report that exact version.
- **`basil-ey2u`** (P2): bundle credential **deposit** (public-key contribution
  without full unlock), so a GCP admin can add a KMS cred without read access to
  the rest of the bundle. Design: `designs/bundle-credential-deposit.md`.

> **Note (auth):** the sealed-cred section below models `GcpKms` as non-secret
> (ADC). That holds only for ambient auth (GKE workload identity / metadata
> server). Explicit service-account key JSON is a secret and is tracked in
> `basil-4s0s`.
- Catalog: KMS backends *provide* `Engine::Transit`. Add `BackendKind::AwsKms` /
  `GcpKms` (schema.rs) + doctor CLI/feature checks. Routing reuses the transit
  path.
- Sealed cred: add `BackendCred::AwsKms { region, key_prefix?, ... }` and
  `GcpKms { project, location, key_ring, service_account_json? }`. AWS auth is
  the ambient cloud chain. GCP defaults to ADC but can seal a whole
  service-account JSON key as an opaque secret for cross-cloud / CI / non-GKE
  deployments. Wire into `agent_cli::backend_from_cred` + `bundle_cli`.
- Deps (optional, behind features): `aws-sdk-kms`, `aws-config`; GCP crate TBD
  (see open decision). Both need a tokio runtime (already present).
- **Build-cost caveat:** these SDKs are heavy; `--all-features` gates (mandated)
  will compile them every run. Flag/confirm with user.
- ES256/384/512: both clouds return **ASN.1 DER** ECDSA sigs; JWS needs raw
  `r‖s`, so implement DER→raw (and inverse for verify) in both backends.

## Open decisions before coding Phase 2

1. **GCP crate**: `google-cloud-kms` 0.6.0 (yoshidan community; fetchable now;
   *no* server-side asymmetric verify → verify locally via public key; *no*
   set-primary-version) **vs** Google-official `google-cloud-kms-v1` (+
   `google-cloud-gax` 1.x, generated, larger surface).
2. **Build-cost management** for the heavy SDKs in `--all-features`.
3. `BackendKind`/cred/config-key naming (defaults proposed above; low-risk).

---

## SDK cheat-sheet (verified against fetched crate sources)

### AWS: `aws-sdk-kms` 1.111.0 + `aws-config` 1.8.18

Fluent builder: `client.<op>().<field>(..).send().await`. Blobs =
`aws_smithy_types::Blob`. Enums under `aws_sdk_kms::types::*`.

- **Client/auth**:
  `aws_config::defaults(BehaviorVersion::latest()).region(Region::new(..)).profile_name(..).load().await`
  → `SdkConfig`; `aws_sdk_kms::Client::new(&cfg)`. Default cred chain
  (env/profile/SSO/IMDS).
- **Create signing key**: `create_key().key_spec(KeySpec::EccNistP256)
  .key_usage(KeyUsageType::SignVerify).send()`; out `.key_metadata().key_id()`.
  `create_alias().alias_name("alias/..").target_key_id(id)`.
  KeySpec incl. `EccNistP256/384/521`, `EccNistEdwards25519` (Ed25519!),
  `Rsa2048/3072/4096`, `MlDsa44/65/87`, `SymmetricDefault`.
- **Sign**: `sign().key_id(id).message(Blob).message_type(MessageType::Raw|Digest)
  .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256).send()` →
  `.signature()` = **DER ECDSA**. `Raw` for ≤4 KiB (KMS hashes), else `Digest`
  (32-byte SHA-256). Ed25519 spec: `Ed25519Sha512`.
- **Verify**: `verify()...` → `.signature_valid()` (invalid sig → Err
  `KmsInvalidSignatureException`, not `false`).
- **Get public key**: `get_public_key().key_id(id)` → `.public_key()` = **DER
  SPKI**, `.key_spec()`, `.signing_algorithms()`.
- **Encrypt/decrypt** (symmetric): `encrypt().key_id(id).plaintext(Blob)
  [.encryption_context(k,v)]` → `.ciphertext_blob()` (opaque, self-describing;
  KMS owns nonce; ≤4 KiB). `decrypt().ciphertext_blob(Blob)[.key_id][.enc_ctx]`
  → `.plaintext()`.
- **Errors**: `.send()` → `Result<_, SdkError<OpError, _>>`;
  `e.into_service_error().is_not_found_exception()` etc.
- **Rotation**: no transit-style versions; `rotate_key_on_demand` /
  `enable_key_rotation` (symmetric only). Asymmetric rotation = new key + alias
  swap.

### GCP: `google-cloud-kms` 0.6.0 (yoshidan)

gRPC/tonic; `Client` derefs to `KmsGrpcClient`. Methods:
`async fn <op>(&self, req: <Req>, retry: Option<RetrySetting>) -> Result<<Resp>, Status>`.
Build raw prost structs from `google_cloud_kms::grpc::kms::v1::*`. Resource names
are strings you assemble. **Requires tokio.**

- **Client/auth**: `ClientConfig::default().with_auth().await?` (ADC:
  `GOOGLE_APPLICATION_CREDENTIALS[_JSON]` or metadata server); `Client::new(cfg).await?`.
- **Create signing key**: `create_crypto_key(CreateCryptoKeyRequest{ parent:
  "projects/P/locations/L/keyRings/KR", crypto_key_id, crypto_key: Some(CryptoKey{
  purpose: CryptoKeyPurpose::AsymmetricSign as i32, version_template:
  Some(CryptoKeyVersionTemplate{ protection_level, algorithm:
  CryptoKeyVersionAlgorithm::EcSignP256Sha256 as i32 }), ..}), .. }, None)`.
  Key ring must exist (`create_key_ring`). Enums are prost i32 (`Variant as i32`).
  Algorithms incl. `EcSignP256Sha256`, `EcSignEd25519`, `RsaSign*`,
  `GoogleSymmetricEncryption`.
- **Sign**: `asymmetric_sign(AsymmetricSignRequest{ name:
  ".../cryptoKeyVersions/<N>", digest: Some(Digest{ digest:
  Some(digest::Digest::Sha256(sha256.to_vec())) }), .. }, None)` →
  `.signature` = **DER ECDSA** (Ed25519 → set `data` not `digest`, returns raw
  64-byte).
- **Verify**: **none server-side** → fetch public key + verify locally.
- **Get public key**: `get_public_key(GetPublicKeyRequest{ name: version_name })`
  where `version_name` is the explicit `cryptoKeyVersions/<N>` catalog target
  → `.pem` (**PEM** SPKI), `.algorithm` (i32).
- **Encrypt/decrypt** (purpose EncryptDecrypt, `GoogleSymmetricEncryption`):
  `encrypt(EncryptRequest{ name: crypto_key, plaintext, additional_authenticated_data,
  .. })` → `.ciphertext`; `decrypt(DecryptRequest{ name, ciphertext, aad, .. })`
  → `.plaintext`. AAD supported; ≤64 KiB.
- **Errors**: `Result<_, google_cloud_gax::grpc::Status>`;
  `status.code() == Code::NotFound`.
- **Limits (0.6.0)**: no `UpdateCryptoKeyPrimaryVersion`, no `asymmetric_decrypt`,
  no raw encrypt/decrypt/import. Sign and public-key reads require an explicit
  version name.

### Ed25519 / minimal sets
- AWS Ed25519: `KeySpec::EccNistEdwards25519` + `Ed25519Sha512` (recent; confirm
  region availability). GCP Ed25519: `EcSignEd25519` (send `data`).
- Minimal to cover ES256 sign + symmetric encrypt:
  - AWS: `EccNistP256`+`SignVerify`+`EcdsaSha256`; `SymmetricDefault`+`EncryptDecrypt`.
  - GCP: `AsymmetricSign`/`EcSignP256Sha256`; `EncryptDecrypt`/`GoogleSymmetricEncryption`.
