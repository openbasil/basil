//! `basil`: command-line client for the basil agent.

// Index into fixed `serde_json::Value` shapes in test assertions is fine (the
// keys are constants we just rendered); the no-panic `indexing_slicing` gate has
// no test-allow config option, unlike unwrap/expect. Matches `basil/src/lib.rs`.
#![cfg_attr(test, allow(clippy::indexing_slicing))]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use basil::{
    AeadAlgorithm, CiphertextEnvelope, Client, ImportEntry, KeyMaterial, KeyType, NatsJwtType,
    NatsUserPermissions, SignNatsJwtOptions,
};
use clap::{Subcommand, ValueEnum};

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AeadAlg {
    Aes256Gcm,
    Chacha20Poly1305,
}

impl From<AeadAlg> for AeadAlgorithm {
    fn from(value: AeadAlg) -> Self {
        match value {
            AeadAlg::Aes256Gcm => Self::Aes256Gcm,
            AeadAlg::Chacha20Poly1305 => Self::Chacha20Poly1305,
        }
    }
}

/// Asymmetric key type accepted by `new-key` / `import` / `import-set`.
///
/// The serde
/// and value names match the wire `KeyType` so a manifest or flag spells
/// `key_type` the same way the rest of Basil does. The post-quantum types
/// (`ml-dsa-*` signing, `ml-kem-*` sealing) are provisionable only via `new-key`
/// against an operator-declared software-custody catalog entry; `import` of a
/// post-quantum key is rejected by the broker (custody records are broker-sealed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, serde::Deserialize)]
pub enum KeyTypeArg {
    #[serde(rename = "ed25519")]
    Ed25519,
    #[serde(rename = "ed25519-nkey")]
    Ed25519Nkey,
    #[serde(rename = "rsa-2048")]
    #[value(name = "rsa-2048")]
    Rsa2048,
    #[serde(rename = "ecdsa-p256")]
    #[value(name = "ecdsa-p256")]
    EcdsaP256,
    #[serde(rename = "ecdsa-p384")]
    #[value(name = "ecdsa-p384")]
    EcdsaP384,
    #[serde(rename = "ecdsa-p521")]
    #[value(name = "ecdsa-p521")]
    EcdsaP521,
    #[serde(rename = "ml-dsa-44")]
    #[value(name = "ml-dsa-44")]
    MlDsa44,
    #[serde(rename = "ml-dsa-65")]
    #[value(name = "ml-dsa-65")]
    MlDsa65,
    #[serde(rename = "ml-dsa-87")]
    #[value(name = "ml-dsa-87")]
    MlDsa87,
    #[serde(rename = "ml-kem-512")]
    #[value(name = "ml-kem-512")]
    MlKem512,
    #[serde(rename = "ml-kem-768")]
    #[value(name = "ml-kem-768")]
    MlKem768,
    #[serde(rename = "ml-kem-1024")]
    #[value(name = "ml-kem-1024")]
    MlKem1024,
}

impl From<KeyTypeArg> for KeyType {
    fn from(value: KeyTypeArg) -> Self {
        match value {
            KeyTypeArg::Ed25519 => Self::Ed25519,
            KeyTypeArg::Ed25519Nkey => Self::Ed25519Nkey,
            KeyTypeArg::Rsa2048 => Self::Rsa2048,
            KeyTypeArg::EcdsaP256 => Self::EcdsaP256,
            KeyTypeArg::EcdsaP384 => Self::EcdsaP384,
            KeyTypeArg::EcdsaP521 => Self::EcdsaP521,
            KeyTypeArg::MlDsa44 => Self::MlDsa44,
            KeyTypeArg::MlDsa65 => Self::MlDsa65,
            KeyTypeArg::MlDsa87 => Self::MlDsa87,
            KeyTypeArg::MlKem512 => Self::MlKem512,
            KeyTypeArg::MlKem768 => Self::MlKem768,
            KeyTypeArg::MlKem1024 => Self::MlKem1024,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum NatsJwtTypeArg {
    User,
    Account,
    Operator,
    Signer,
    Server,
    Curve,
}

impl From<NatsJwtTypeArg> for NatsJwtType {
    fn from(value: NatsJwtTypeArg) -> Self {
        match value {
            NatsJwtTypeArg::User => Self::User,
            NatsJwtTypeArg::Account => Self::Account,
            NatsJwtTypeArg::Operator => Self::Operator,
            NatsJwtTypeArg::Signer => Self::Signer,
            NatsJwtTypeArg::Server => Self::Server,
            NatsJwtTypeArg::Curve => Self::Curve,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum GetOutputFormatArg {
    Raw,
    Hex,
    Base64,
    #[value(name = "base64-url-no-pad")]
    Base64UrlNoPad,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SecretFileModeArg {
    #[value(name = "0600")]
    OwnerReadWrite,
    #[value(name = "0660")]
    OwnerGroupReadWrite,
}

impl SecretFileModeArg {
    const fn mode(self) -> u32 {
        match self {
            Self::OwnerReadWrite => 0o600,
            Self::OwnerGroupReadWrite => 0o660,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new asymmetric key.
    NewKey {
        /// Dotted catalog name for the new key.
        #[arg(long, default_value = "example.signing_key")]
        key_id: String,
        /// Key type to create.
        #[arg(long, value_enum, default_value_t = KeyTypeArg::Ed25519)]
        key_type: KeyTypeArg,
    },

    /// Import caller-provided (BYOK) key material into a catalog key. The broker
    /// fetches the backend transit `wrapping_key`, wraps the material with
    /// RSA-OAEP + AES-KWP in place, and POSTs it to `keys/<k>/import`; the raw
    /// material never lands on the backend unwrapped. Supply exactly one material
    /// source: `--seed-hex` (64 hex chars = a 32-byte Ed25519 seed; Ed25519-only)
    /// or `--pkcs8-file` (a PKCS#8 DER private key for Ed25519/RSA/P-256).
    /// Prints the `key_id` + `public_key` hex.
    Import {
        /// Dotted catalog name to import the key under.
        #[arg(long)]
        key_id: String,
        /// Key type of the imported material.
        #[arg(long, value_enum, default_value_t = KeyTypeArg::Ed25519)]
        key_type: KeyTypeArg,
        /// 32-byte raw Ed25519 seed as 64 hex chars.
        #[arg(long, conflicts_with = "pkcs8_file")]
        seed_hex: Option<String>,
        /// Path to a PKCS#8 DER private key file.
        #[arg(long)]
        pkcs8_file: Option<PathBuf>,
        /// Validate local inputs without contacting the agent or importing.
        #[arg(long)]
        check: bool,
    },

    /// Import several keys from a JSON manifest in one all-or-nothing call. The
    /// broker authorizes `import` on EVERY entry before importing ANY, so an
    /// unauthorized entry rejects the whole batch and creates no keys. The
    /// manifest is a JSON array of objects: `{"key_id": "...", "key_type":
    /// "ed25519", "seed_hex": "<64 hex>"}` or with `"pkcs8_file": "<path>"`
    /// instead of `"seed_hex"`. Raw seeds are Ed25519-only; RSA/P-256 use
    /// PKCS#8 DER. `key_type` defaults to `ed25519` when omitted.
    /// Prints one `key_id`/`public_key` pair per imported key.
    ImportSet {
        /// Path to the JSON manifest of keys to import.
        #[arg(long)]
        file: PathBuf,
        /// Validate the manifest without contacting the agent or importing.
        #[arg(long)]
        check: bool,
    },

    /// Sign a payload and print the signature as hex.
    Sign {
        #[arg(long)]
        key_id: String,
        payload: String,
    },

    /// Verify a payload signature.
    Verify {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        signature: String,
        payload: String,
    },

    /// Encrypt a payload and print envelope fields.
    Encrypt {
        #[arg(long)]
        key_id: String,
        #[arg(long, value_enum, default_value_t = AeadAlg::Aes256Gcm)]
        algorithm: AeadAlg,
        #[arg(long)]
        aad_hex: Option<String>,
        plaintext: String,
    },

    /// Decrypt an envelope and print plaintext as hex.
    Decrypt {
        #[arg(long)]
        key_id: String,
        #[arg(long, value_enum)]
        algorithm: AeadAlg,
        #[arg(long)]
        version: u32,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        ciphertext: String,
        #[arg(long)]
        aad_hex: Option<String>,
    },

    /// Fetch a value key. Prints `version` + hex `value` by default; `--raw` writes
    /// the bytes to stdout and `--out-file` writes them to a 0600 file. Use
    /// `--format base64` when materializing secrets for consumers that require
    /// standard padded Base64.
    ///
    /// Basil attests the caller by its kernel `SO_PEERCRED` uid/gid, so to fetch a
    /// secret as a particular service, run this CLI under that service's identity
    /// (systemd `User=`/`Group=`, or `runuser -u <svc>`); the CLI cannot impersonate.
    Get {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        version: Option<u32>,
        /// Write the raw secret bytes to stdout (no hex, no `version:` line).
        #[arg(long, conflicts_with = "out_file")]
        raw: bool,
        /// Encode the value as `raw`, `hex`, standard padded `base64`, or
        /// URL-safe unpadded Base64. When set, stdout prints only the value and
        /// `--out-file` writes the encoded value instead of raw bytes.
        #[arg(long, value_enum)]
        format: Option<GetOutputFormatArg>,
        /// Write the raw secret bytes to this file, created/truncated mode 0600.
        #[arg(long)]
        out_file: Option<PathBuf>,
    },

    /// Assemble a local `NATS` user `.creds` file from a signed user JWT and
    /// user `NKey` seed. This is local file plumbing: mint/sign the JWT first,
    /// then call this command to render the canonical credentials document.
    IssueNatsCreds {
        /// Signed compact `NATS` user JWT. Prefer `--jwt-file` for automation so
        /// secrets do not appear in argv.
        #[arg(long, conflicts_with = "jwt_file")]
        jwt: Option<String>,
        /// File containing the signed compact `NATS` user JWT.
        #[arg(long, conflicts_with = "jwt")]
        jwt_file: Option<PathBuf>,
        /// User `NKey` seed. Prefer `--seed-file` so the seed does not appear in
        /// argv.
        #[arg(long, conflicts_with = "seed_file")]
        seed: Option<String>,
        /// File containing the user `NKey` seed.
        #[arg(long, conflicts_with = "seed")]
        seed_file: Option<PathBuf>,
        /// Destination `.creds` path.
        #[arg(long)]
        out_file: PathBuf,
        /// Destination file mode.
        #[arg(long, value_enum, default_value_t = SecretFileModeArg::OwnerReadWrite)]
        mode: SecretFileModeArg,
    },

    /// Store a value key from text or hex.
    Set {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        hex: bool,
        value: String,
    },

    /// Rotate a key and print the new version.
    Rotate {
        #[arg(long)]
        key_id: String,
    },

    /// List visible catalog keys.
    List {
        #[arg(long)]
        prefix: Option<String>,
    },

    /// Mint a generic JWT.
    MintJwt {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        sub: String,
        #[arg(long)]
        ttl_secs: Option<u64>,
        #[arg(long, default_value = "{}")]
        claims_json: String,
    },

    /// Mint a NATS user JWT signed by an account key held by Basil.
    ///
    /// When `--key-id` is an account *signing* key (not the account identity
    /// key), pass `--issuer-account` with the owning account's identity public
    /// `NKey` (`A…`); otherwise the minted user carries no `issuer_account` and
    /// nats-server rejects the connection with an authorization violation. Omit
    /// `--issuer-account` when `--key-id` is the account identity key itself.
    MintNatsUser {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        user_nkey: String,
        /// Owning account identity public `NKey` (`A…`); required when `--key-id`
        /// is an account signing key.
        #[arg(long = "issuer-account")]
        issuer_account: Option<String>,
        #[arg(long, default_value = "basil-user")]
        name: String,
        #[arg(long)]
        ttl_secs: Option<u64>,
        #[arg(long = "pub-allow")]
        pub_allow: Vec<String>,
        #[arg(long = "pub-deny")]
        pub_deny: Vec<String>,
        #[arg(long = "sub-allow")]
        sub_allow: Vec<String>,
        #[arg(long = "sub-deny")]
        sub_deny: Vec<String>,
    },

    /// Validate and sign a caller-supplied NATS JWT claim document.
    SignNatsJwt {
        #[arg(long)]
        key_id: String,
        #[arg(long, conflicts_with = "claims_file")]
        claims_json: Option<String>,
        #[arg(long, conflicts_with = "claims_json")]
        claims_file: Option<PathBuf>,
        #[arg(long, value_enum)]
        expect_type: Option<NatsJwtTypeArg>,
        #[arg(long, conflicts_with = "expires_at_unix")]
        ttl_secs: Option<u64>,
        #[arg(long)]
        expires_at_unix: Option<u64>,
        #[arg(long)]
        issued_at_unix: Option<u64>,
        #[arg(long)]
        rewrite_jti: bool,
    },

    /// Issue a DNS/IP-SAN X.509 leaf (TLS cert) from a backend PKI engine, signed
    /// by the issuer CA the broker holds in place. Prints the leaf+chain and the
    /// issuing-CA chain as `CERTIFICATE` PEM blocks and the leaf key as a
    /// `PRIVATE KEY` PEM block, so the output pipes into `openssl x509`/`openssl
    /// pkey`. The issuing CA key never leaves the backend.
    IssueCert {
        /// Catalog key of the issuer (a `pki/issue/<role>` engine key).
        #[arg(long)]
        key_id: String,
        /// Subject common name for the leaf certificate.
        #[arg(long)]
        common_name: String,
        /// DNS SAN to bind (repeatable).
        #[arg(long = "dns-san")]
        dns_san: Vec<String>,
        /// IP SAN to bind (repeatable).
        #[arg(long = "ip-san")]
        ip_san: Vec<String>,
        /// Requested certificate lifetime in seconds.
        #[arg(long)]
        ttl_secs: u64,
    },

    /// Print the agent backend, version, and protocol.
    Status,

    /// Liveness probe: is the agent process up and serving the socket? Cheap; the
    /// agent does no backend I/O. Exits 0 when alive, nonzero on a connect/RPC
    /// failure. With `--json`, prints a stable one-line JSON object for automation
    /// (systemd `WatchdogSec` companion, container liveness check).
    Health {
        /// Emit a machine-readable JSON object instead of human lines.
        #[arg(long)]
        json: bool,
    },

    /// Readiness probe: can the agent actually serve data-plane ops? The agent
    /// probes every backend and catalog key and returns a non-secret summary.
    /// Exits 0 when ready, 1 when not ready (and nonzero on a connect/RPC
    /// failure). With `--json`, prints a stable one-line JSON object for
    /// automation (systemd `ExecStartPost`, container `HEALTHCHECK`, k8s readiness
    /// probe). Never prints key names or secret material.
    Ready {
        /// Emit a machine-readable JSON object instead of human lines.
        #[arg(long)]
        json: bool,
    },

    /// Hot-reload the agent's catalog/policy generation FROM DISK. The agent
    /// re-reads the catalog/policy from the paths it was started with (the request
    /// carries NO config: config can never be supplied over the wire), validates
    /// the candidate, and atomically swaps in a new generation on success. Prints
    /// the old->new generation id + key/grant counts. Requires the dedicated
    /// `reload` permission (not implied by any data-plane grant); a caller lacking
    /// it is denied. Exits 0 on success, nonzero on rejection or permission-denied.
    /// With `--check`, validates the candidate WITHOUT swapping (dry-run).
    Reload {
        /// Dry-run: validate the on-disk candidate without swapping the serving
        /// generation. Exits nonzero if the candidate would be rejected.
        #[arg(long)]
        check: bool,
        /// Emit a machine-readable JSON object instead of human lines.
        #[arg(long)]
        json: bool,
    },

    /// Ask the running agent why a subject would be allowed or denied for a
    /// given operation and key. Requires the dedicated `explain` admin permission.
    Explain {
        /// Subject name to evaluate.
        #[arg(long)]
        subject: String,
        /// Policy op token to evaluate (`get`, `sign`, `set`, ...).
        #[arg(long)]
        op: String,
        /// Catalog key/target to evaluate.
        #[arg(long)]
        key: String,
        /// Emit a machine-readable JSON object instead of human lines.
        #[arg(long)]
        json: bool,
    },

    /// Revoke a JWT-SVID by trust-domain and jti. Requires the dedicated
    /// `revoke` admin permission over `broker.revoke` and a configured
    /// persistent `revocation_store=jwt-svid` value key.
    Revoke {
        /// SPIFFE trust domain for the token issuer, without `spiffe://`.
        #[arg(long)]
        trust_domain: String,
        /// JWT ID (`jti`) to deny.
        #[arg(long)]
        jti: String,
        /// Unix expiry of the credential; the deny-list entry expires then.
        #[arg(long)]
        expires_at_unix: u64,
        /// Emit a machine-readable JSON object instead of human lines.
        #[arg(long)]
        json: bool,
    },
}

pub async fn run(socket: Option<String>, command: Command) -> Result<()> {
    if let Command::IssueNatsCreds {
        jwt,
        jwt_file,
        seed,
        seed_file,
        out_file,
        mode,
    } = command
    {
        return issue_nats_creds(
            jwt,
            jwt_file.as_deref(),
            seed,
            seed_file.as_deref(),
            &out_file,
            mode,
        );
    }

    match &command {
        Command::Import {
            key_type,
            seed_hex,
            pkcs8_file,
            check: true,
            ..
        } => return check_import(*key_type, seed_hex.as_deref(), pkcs8_file.as_deref()),
        Command::ImportSet { file, check: true } => return check_import_set(file),
        _ => {}
    }

    let socket = socket.unwrap_or_else(|| basil::constants::DEFAULT_SOCKET_PATH.to_string());
    let mut client = Client::connect(&socket)
        .await
        .with_context(|| format!("connecting to agent at {socket}"))?;

    dispatch(&mut client, command).await?;

    drop(client);
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn dispatch(client: &mut Client, command: Command) -> Result<()> {
    match command {
        Command::NewKey { key_id, key_type } => new_key(client, &key_id, key_type).await,
        Command::Import {
            key_id,
            key_type,
            seed_hex,
            pkcs8_file,
            check,
        } => {
            import(
                client,
                &key_id,
                key_type,
                seed_hex,
                pkcs8_file.as_deref(),
                check,
            )
            .await
        }
        Command::ImportSet { file, check } => import_set(client, &file, check).await,
        Command::Sign { key_id, payload } => sign(client, &key_id, &payload).await,
        Command::Verify {
            key_id,
            signature,
            payload,
        } => verify(client, &key_id, &signature, &payload).await,
        Command::Encrypt {
            key_id,
            algorithm,
            aad_hex,
            plaintext,
        } => encrypt(client, &key_id, algorithm, aad_hex, &plaintext).await,
        Command::Decrypt {
            key_id,
            algorithm,
            version,
            nonce,
            ciphertext,
            aad_hex,
        } => {
            decrypt(
                client,
                &key_id,
                algorithm,
                version,
                &nonce,
                &ciphertext,
                aad_hex,
            )
            .await
        }
        Command::Get {
            key_id,
            version,
            raw,
            format,
            out_file,
        } => get(client, &key_id, version, raw, format, out_file.as_deref()).await,
        Command::IssueNatsCreds {
            jwt,
            jwt_file,
            seed,
            seed_file,
            out_file,
            mode,
        } => issue_nats_creds(
            jwt,
            jwt_file.as_deref(),
            seed,
            seed_file.as_deref(),
            &out_file,
            mode,
        ),
        Command::Set { key_id, hex, value } => set(client, &key_id, hex, value).await,
        Command::Rotate { key_id } => rotate(client, &key_id).await,
        Command::List { prefix } => list(client, prefix.as_deref()).await,
        Command::MintJwt {
            key_id,
            sub,
            ttl_secs,
            claims_json,
        } => mint_jwt(client, &key_id, &sub, ttl_secs, &claims_json).await,
        Command::MintNatsUser {
            key_id,
            user_nkey,
            issuer_account,
            name,
            ttl_secs,
            pub_allow,
            pub_deny,
            sub_allow,
            sub_deny,
        } => {
            mint_nats_user(
                client,
                &key_id,
                &user_nkey,
                issuer_account.as_deref(),
                &name,
                ttl_secs,
                NatsUserPermissions {
                    pub_allow,
                    pub_deny,
                    sub_allow,
                    sub_deny,
                },
            )
            .await
        }
        Command::SignNatsJwt {
            key_id,
            claims_json,
            claims_file,
            expect_type,
            ttl_secs,
            expires_at_unix,
            issued_at_unix,
            rewrite_jti,
        } => {
            sign_nats_jwt(
                client,
                &key_id,
                claims_json.as_deref(),
                claims_file.as_deref(),
                expect_type.map(Into::into),
                ttl_secs,
                expires_at_unix,
                issued_at_unix,
                rewrite_jti,
            )
            .await
        }
        Command::IssueCert {
            key_id,
            common_name,
            dns_san,
            ip_san,
            ttl_secs,
        } => issue_cert(client, &key_id, &common_name, &dns_san, &ip_san, ttl_secs).await,
        Command::Status => status(client).await,
        Command::Health { json } => health(client, json).await,
        Command::Ready { json } => ready(client, json).await,
        Command::Reload { check, json } => reload(client, check, json).await,
        Command::Explain {
            subject,
            op,
            key,
            json,
        } => explain(client, &subject, &op, &key, json).await,
        Command::Revoke {
            trust_domain,
            jti,
            expires_at_unix,
            json,
        } => revoke(client, &trust_domain, &jti, expires_at_unix, json).await,
    }
}

async fn new_key(client: &mut Client, key_id: &str, key_type: KeyTypeArg) -> Result<()> {
    let key = client.new_key(key_id, key_type.into()).await?;
    println!("key_id: {}", key.key_id);
    println!("public_key: {}", hex::encode(key.public_key));
    Ok(())
}

/// One entry in an `import-set` JSON manifest. Carries exactly one material
/// source (`seed_hex` xor `pkcs8_file`); `key_type` defaults to `ed25519`.
#[derive(Debug, serde::Deserialize)]
struct ManifestEntry {
    key_id: String,
    #[serde(default = "default_manifest_key_type")]
    key_type: KeyTypeArg,
    #[serde(default)]
    seed_hex: Option<String>,
    #[serde(default)]
    pkcs8_file: Option<PathBuf>,
}

const fn default_manifest_key_type() -> KeyTypeArg {
    KeyTypeArg::Ed25519
}

/// Build a [`KeyMaterial`] from the two mutually-exclusive material sources. The
/// caller must supply exactly one; zero or both is an error.
fn key_material(seed_hex: Option<&str>, pkcs8_file: Option<&Path>) -> Result<KeyMaterial> {
    match (seed_hex, pkcs8_file) {
        (Some(seed), None) => {
            let seed = decode_hex(seed, "seed-hex")?;
            if seed.len() != 32 {
                bail!("seed-hex must decode to 32 bytes (got {})", seed.len());
            }
            Ok(KeyMaterial::Ed25519Seed(seed))
        }
        (None, Some(path)) => {
            let der = std::fs::read(path)
                .with_context(|| format!("reading PKCS#8 DER from {}", path.display()))?;
            if der.is_empty() {
                bail!("pkcs8-file {} is empty", path.display());
            }
            Ok(KeyMaterial::Pkcs8Der(der))
        }
        (None, None) => bail!("supply key material: --seed-hex or --pkcs8-file"),
        (Some(_), Some(_)) => bail!("supply only one of --seed-hex or --pkcs8-file"),
    }
}

async fn import(
    client: &mut Client,
    key_id: &str,
    key_type: KeyTypeArg,
    seed_hex: Option<String>,
    pkcs8_file: Option<&Path>,
    check: bool,
) -> Result<()> {
    let material = key_material(seed_hex.as_deref(), pkcs8_file)?;
    if check {
        return Ok(());
    }
    let key = client.import(key_id, key_type.into(), material).await?;
    println!("key_id: {}", key.key_id);
    println!("public_key: {}", hex::encode(key.public_key));
    Ok(())
}

fn check_import(
    key_type: KeyTypeArg,
    seed_hex: Option<&str>,
    pkcs8_file: Option<&Path>,
) -> Result<()> {
    let _material = key_material(seed_hex, pkcs8_file)?;
    let _key_type = KeyType::from(key_type);
    Ok(())
}

fn import_set_entries(file: &Path) -> Result<Vec<ImportEntry>> {
    let raw = std::fs::read_to_string(file)
        .with_context(|| format!("reading import manifest {}", file.display()))?;
    let manifest: Vec<ManifestEntry> =
        serde_json::from_str(&raw).context("import manifest is not a JSON array of key entries")?;
    if manifest.is_empty() {
        bail!("import manifest {} has no entries", file.display());
    }
    let mut entries = Vec::with_capacity(manifest.len());
    for entry in manifest {
        let material = key_material(entry.seed_hex.as_deref(), entry.pkcs8_file.as_deref())
            .with_context(|| format!("manifest entry {}", entry.key_id))?;
        entries.push(ImportEntry {
            key_id: entry.key_id,
            key_type: entry.key_type.into(),
            material,
        });
    }
    Ok(entries)
}

fn check_import_set(file: &Path) -> Result<()> {
    let _entries = import_set_entries(file)?;
    Ok(())
}

async fn import_set(client: &mut Client, file: &Path, check: bool) -> Result<()> {
    let entries = import_set_entries(file)?;
    if check {
        return Ok(());
    }
    for key in client.import_set(entries).await? {
        println!("key_id: {}", key.key_id);
        println!("public_key: {}", hex::encode(key.public_key));
    }
    Ok(())
}

async fn sign(client: &mut Client, key_id: &str, payload: &str) -> Result<()> {
    let sig = client.sign(key_id, payload.as_bytes()).await?;
    println!("{}", hex::encode(sig));
    Ok(())
}

async fn verify(client: &mut Client, key_id: &str, signature: &str, payload: &str) -> Result<()> {
    let sig = decode_hex(signature, "signature")?;
    let valid = client.verify(key_id, payload.as_bytes(), &sig).await?;
    println!("{valid}");
    if !valid {
        std::process::exit(1);
    }
    Ok(())
}

async fn encrypt(
    client: &mut Client,
    key_id: &str,
    algorithm: AeadAlg,
    aad_hex: Option<String>,
    plaintext: &str,
) -> Result<()> {
    let aad = optional_hex(aad_hex, "aad")?;
    let envelope = client
        .encrypt(
            key_id,
            algorithm.into(),
            plaintext.as_bytes(),
            aad.as_deref(),
        )
        .await?;
    println!("algorithm: {}", aead_name(envelope.alg));
    println!("version: {}", envelope.key_version);
    println!("nonce: {}", hex::encode(envelope.nonce));
    println!("ciphertext: {}", hex::encode(envelope.ciphertext));
    Ok(())
}

async fn decrypt(
    client: &mut Client,
    key_id: &str,
    algorithm: AeadAlg,
    version: u32,
    nonce: &str,
    ciphertext: &str,
    aad_hex: Option<String>,
) -> Result<()> {
    let aad = optional_hex(aad_hex, "aad")?;
    // Vault/OpenBao transit embeds the nonce inside its ciphertext blob, so a
    // transit-AEAD envelope carries an EMPTY nonce (documented broker invariant,
    // see `TransitClient::decrypt`). Permit it; a provider that genuinely needs a
    // discrete nonce fails the decrypt at the broker, not at this arg guard.
    let nonce_bytes = if nonce.trim().is_empty() {
        Vec::new()
    } else {
        decode_hex(nonce, "nonce")?
    };
    let envelope = CiphertextEnvelope {
        alg: algorithm.into(),
        key_version: version,
        nonce: nonce_bytes,
        ciphertext: decode_hex(ciphertext, "ciphertext")?,
    };
    let plaintext = client
        .decrypt(key_id, envelope, aad.as_deref())
        .await
        .context("decrypt failed")?;
    println!("{}", hex::encode(plaintext));
    Ok(())
}

async fn get(
    client: &mut Client,
    key_id: &str,
    version: Option<u32>,
    raw: bool,
    format: Option<GetOutputFormatArg>,
    out_file: Option<&Path>,
) -> Result<()> {
    if raw && format.is_some_and(|format| format != GetOutputFormatArg::Raw) {
        bail!("--raw cannot be combined with a non-raw --format");
    }
    let format = format.or_else(|| raw.then_some(GetOutputFormatArg::Raw));
    let secret = client.get_secret(key_id, version).await?;
    let (value, version) = (secret.value, secret.version);
    if let Some(path) = out_file {
        let encoded = format.map_or_else(|| value.clone(), |format| encode_secret(&value, format));
        return write_secret_file(path, &encoded)
            .with_context(|| format!("writing secret to {}", path.display()));
    }
    if let Some(format) = format {
        use std::io::Write as _;

        let encoded = encode_secret(&value, format);
        return std::io::stdout()
            .write_all(&encoded)
            .and_then(|()| {
                if format == GetOutputFormatArg::Raw {
                    Ok(())
                } else {
                    std::io::stdout().write_all(b"\n")
                }
            })
            .context("writing formatted secret to stdout");
    }
    println!("version: {version}");
    println!("value: {}", hex::encode(value));
    Ok(())
}

fn encode_secret(value: &[u8], format: GetOutputFormatArg) -> Vec<u8> {
    match format {
        GetOutputFormatArg::Raw => value.to_vec(),
        GetOutputFormatArg::Hex => hex::encode(value).into_bytes(),
        GetOutputFormatArg::Base64 => base64::engine::general_purpose::STANDARD
            .encode(value)
            .into_bytes(),
        GetOutputFormatArg::Base64UrlNoPad => base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(value)
            .into_bytes(),
    }
}

/// Write secret bytes to `path`, creating/truncating it mode 0600. Enforces 0600
/// even if the file pre-existed with broader permissions.
fn write_secret_file(path: &Path, value: &[u8]) -> Result<()> {
    write_secret_file_with_mode(path, value, 0o600)
}

/// Atomically write secret bytes to `path`, enforcing `mode` even if the file
/// pre-existed with broader permissions.
fn write_secret_file_with_mode(path: &Path, value: &[u8], mode: u32) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .context("secret output path must name a file")?;
    let mut temporary_name = OsString::from(".");
    temporary_name.push(file_name);
    temporary_name.push(format!(".{}.tmp", std::process::id()));
    let temporary_path = parent.join(temporary_name);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temporary_path)?;
    let result = (|| -> Result<()> {
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(value)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary_path, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

fn issue_nats_creds(
    jwt: Option<String>,
    jwt_file: Option<&Path>,
    seed: Option<String>,
    seed_file: Option<&Path>,
    out_file: &Path,
    mode: SecretFileModeArg,
) -> Result<()> {
    let jwt = read_exactly_one_secret_arg(jwt, jwt_file, "jwt")?;
    let seed = read_exactly_one_secret_arg(seed, seed_file, "seed")?;
    let creds =
        basil_nats::format_user_creds(&jwt, &seed).context("formatting NATS credentials")?;
    write_secret_file_with_mode(out_file, creds.as_bytes(), mode.mode())
        .with_context(|| format!("writing NATS credentials to {}", out_file.display()))?;
    Ok(())
}

fn read_exactly_one_secret_arg(
    inline: Option<String>,
    file: Option<&Path>,
    field: &'static str,
) -> Result<String> {
    match (inline, file) {
        (Some(value), None) => Ok(value),
        (None, Some(path)) => std::fs::read_to_string(path)
            .with_context(|| format!("reading {field} file {}", path.display())),
        (None, None) => bail!("supply --{field} or --{field}-file"),
        (Some(_), Some(_)) => bail!("supply only one of --{field} or --{field}-file"),
    }
}

async fn set(client: &mut Client, key_id: &str, hex: bool, value: String) -> Result<()> {
    let value = if hex {
        decode_hex(&value, "value")?
    } else {
        value.into_bytes()
    };
    let version = client.set_secret(key_id, &value).await?;
    println!("version: {version}");
    Ok(())
}

async fn rotate(client: &mut Client, key_id: &str) -> Result<()> {
    let version = client.rotate_secret(key_id).await?;
    println!("version: {version}");
    Ok(())
}

async fn list(client: &mut Client, prefix: Option<&str>) -> Result<()> {
    for key in client.list_catalog(prefix).await? {
        println!(
            "{}\t{}\t{}\t{}",
            key.name,
            key.kind,
            key.key_type.unwrap_or_default(),
            key.latest_version
        );
    }
    Ok(())
}

async fn mint_jwt(
    client: &mut Client,
    key_id: &str,
    sub: &str,
    ttl_secs: Option<u64>,
    claims_json: &str,
) -> Result<()> {
    let claims: serde_json::Value =
        serde_json::from_str(claims_json).context("claims-json is not valid JSON")?;
    let jwt = client.mint_jwt(key_id, sub, ttl_secs, claims).await?;
    println!("{}", jwt.token);
    if let Some(expires_at) = jwt.expires_at {
        println!("expires_at: {expires_at}");
    }
    Ok(())
}

async fn mint_nats_user(
    client: &mut Client,
    key_id: &str,
    user_nkey: &str,
    issuer_account: Option<&str>,
    name: &str,
    ttl_secs: Option<u64>,
    permissions: NatsUserPermissions,
) -> Result<()> {
    let token = client
        .mint_nats_user(
            key_id,
            user_nkey,
            issuer_account,
            name,
            ttl_secs,
            permissions,
        )
        .await?;
    println!("{token}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn sign_nats_jwt(
    client: &mut Client,
    key_id: &str,
    claims_json: Option<&str>,
    claims_file: Option<&Path>,
    expected_type: Option<NatsJwtType>,
    ttl_secs: Option<u64>,
    expires_at: Option<u64>,
    issued_at: Option<u64>,
    rewrite_jti: bool,
) -> Result<()> {
    let claims_text = match (claims_json, claims_file) {
        (Some(value), None) => value.to_string(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .with_context(|| format!("reading claims file `{}`", path.display()))?,
        (None, None) | (Some(_), Some(_)) => {
            bail!("supply exactly one of --claims-json or --claims-file")
        }
    };
    let _: serde_json::Value =
        serde_json::from_str(&claims_text).context("NATS JWT claims are not valid JSON")?;
    let jwt = client
        .sign_nats_jwt_json(
            key_id,
            claims_text.into_bytes(),
            SignNatsJwtOptions {
                expected_type,
                ttl_secs,
                expires_at,
                issued_at,
                rewrite_jti,
            },
        )
        .await?;
    println!("{}", jwt.token);
    if let Some(expires_at) = jwt.expires_at {
        println!("expires_at: {expires_at}");
    }
    Ok(())
}

async fn issue_cert(
    client: &mut Client,
    key_id: &str,
    common_name: &str,
    dns_sans: &[String],
    ip_sans: &[String],
    ttl_secs: u64,
) -> Result<()> {
    let issued = client
        .issue_certificate(key_id, common_name, dns_sans, ip_sans, ttl_secs)
        .await?;
    // Leaf + any intermediate issuers (DER), re-framed as CERTIFICATE PEM. The
    // first block is the leaf; the broker hands back its DER already decoded.
    print!("{}", pem_blocks("CERTIFICATE", &issued.cert_chain_der));
    // The issuing-CA / trust-bundle chain (DER), labelled distinctly so the e2e
    // can tell the leaf chain from the CA chain. On a single internal root with
    // no intermediates this is the root cert; OpenBao and Vault both populate it
    // from the issue response's `issuing_ca` field.
    print!("{}", pem_blocks("CERTIFICATE", &issued.ca_chain_der));
    // The PKCS#8 leaf private key (DER): released to the caller for a TLS server.
    print!("{}", pem_block("PRIVATE KEY", &issued.private_key_der));
    Ok(())
}

/// Frame a sequence of DER blobs as concatenated PEM blocks under `label`.
fn pem_blocks(label: &str, ders: &[Vec<u8>]) -> String {
    ders.iter().map(|der| pem_block(label, der)).collect()
}

/// Frame a single DER blob as one PEM block (`-----BEGIN <label>-----` … with
/// the base64 body wrapped at 64 columns, per RFC 7468).
fn pem_block(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    use std::fmt::Write as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    // `write!` to a String is infallible; ignore the formatter Result.
    let _ = writeln!(out, "-----BEGIN {label}-----");
    for chunk in body.as_bytes().chunks(64) {
        // chunk is ASCII base64; from_utf8 cannot fail here.
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    let _ = writeln!(out, "-----END {label}-----");
    out
}

async fn status(client: &mut Client) -> Result<()> {
    let status = client.status().await?;
    println!("backend: {}", status.backend);
    println!("version: {}", status.version);
    println!("protocol: {}", status.protocol);
    Ok(())
}

/// Liveness probe. A returned health response means the agent is alive; we exit
/// 0. A connect/RPC failure propagates as an `Err` (the `?`), which `main`
/// reports and turns into a nonzero exit, so a dead agent reads as not-alive to
/// the caller's probe.
async fn health(client: &mut Client, json: bool) -> Result<()> {
    let health = client.health().await?;
    if json {
        // A stable, single-line object for `systemd`/container probes to parse.
        println!("{}", health_json(&health));
    } else {
        println!("alive: {}", health.alive);
        println!("version: {}", health.version);
    }
    Ok(())
}

/// The stable one-line `--json` object for `basil health` (the scriptable
/// liveness contract: `systemd`/container/k8s probes parse this). Pure: lifted
/// out of [`health`] so the field set is unit-testable without a live broker.
fn health_json(health: &basil::AgentHealth) -> serde_json::Value {
    serde_json::json!({ "alive": health.alive, "version": health.version })
}

/// Readiness probe. Prints the non-secret summary and maps readiness to the
/// process exit code: 0 when ready, 1 when not ready (a connect/RPC failure is a
/// separate nonzero exit via `main`). The JSON shape is stable for automation
/// (systemd `ExecStartPost`, container `HEALTHCHECK`, k8s `exec` readiness).
async fn ready(client: &mut Client, json: bool) -> Result<()> {
    let r = client.readiness().await?;
    if json {
        println!("{}", ready_json(&r));
    } else {
        println!("ready: {}", r.ready);
        println!("reason: {}", r.reason);
        println!("generation: {}", r.generation);
        println!("keys_total: {}", r.keys_total);
        println!("keys_present: {}", r.keys_present);
        println!("keys_required_missing: {}", r.keys_required_missing);
        println!("keys_optional_missing: {}", r.keys_optional_missing);
    }
    if ready_exit_code(&r) != 0 {
        // Exit 1 = "not ready" so a probe can gate on the code, distinct from a
        // connect/RPC failure (which `main` surfaces as its own nonzero exit).
        std::process::exit(1);
    }
    Ok(())
}

/// The stable one-line `--json` object for `basil ready` (the scriptable
/// readiness contract). Pure: lifted out of [`ready`] so the field set + the
/// coarse `reason` token are unit-testable without a live broker.
fn ready_json(r: &basil::AgentReadiness) -> serde_json::Value {
    serde_json::json!({
        "ready": r.ready,
        "reason": r.reason.to_string(),
        "generation": r.generation,
        "keys_total": r.keys_total,
        "keys_present": r.keys_present,
        "keys_required_missing": r.keys_required_missing,
        "keys_optional_missing": r.keys_optional_missing,
    })
}

/// Map a readiness outcome to the process exit code orchestrators gate on:
/// `0` when ready, `1` when not ready (a connect/RPC failure is a separate
/// nonzero exit `main` surfaces). Pure, so the not-ready→nonzero contract is
/// unit-testable without a live server.
const fn ready_exit_code(r: &basil::AgentReadiness) -> i32 {
    if r.ready { 0 } else { 1 }
}

/// Hot-reload the agent's catalog/policy generation from disk (`basil-atq`).
///
/// The agent re-reads config from its on-disk paths only; this call sends no
/// config (the trust boundary is enforced by construction). Prints the old->new
/// generation id + counts. A permission-denied surfaces as an `Err` (the `?`),
/// which `main` turns into a nonzero exit. A *rejection* (validation/routing,
/// the previous generation keeps serving) exits 1, distinct from a connect/RPC
/// failure, so automation can gate on the code. `--check` validates without
/// swapping.
async fn reload(client: &mut Client, check: bool, json: bool) -> Result<()> {
    let r = client.reload(check).await?;
    if json {
        println!("{}", reload_json(&r));
    } else if let Some(rej) = &r.rejection {
        println!("reload rejected: {} ({})", rej.reason, rej.message);
        println!(
            "previous_generation: {} (still serving)",
            r.previous_generation
        );
    } else if check {
        println!("checked: ok (no swap)");
        println!("previous_generation: {}", r.previous_generation);
        println!("would_be_generation: {}", r.new_generation);
        println!("key_count: {}", r.key_count);
        println!("grant_count: {}", r.grant_count);
    } else {
        println!("applied: {}", r.applied);
        println!("previous_generation: {}", r.previous_generation);
        println!("new_generation: {}", r.new_generation);
        println!("key_count: {}", r.key_count);
        println!("grant_count: {}", r.grant_count);
    }
    if reload_exit_code(&r) != 0 {
        // Exit 1 = "rejected" (the candidate did not validate / changed a
        // restart-only dimension). Distinct from a permission-denied or
        // connect/RPC failure, which `main` reports as its own nonzero exit.
        std::process::exit(1);
    }
    Ok(())
}

/// The stable one-line `--json` object for `basil reload [--check]` (the
/// scriptable reload contract). Pure: lifted out of [`reload`] so the field set,
/// including the nested `rejection` object (present only on a rejected
/// candidate), is unit-testable without a live broker.
fn reload_json(r: &basil::AgentReload) -> serde_json::Value {
    serde_json::json!({
        "applied": r.applied,
        "checked": r.checked,
        "previous_generation": r.previous_generation,
        "new_generation": r.new_generation,
        "key_count": r.key_count,
        "grant_count": r.grant_count,
        "rejection": r.rejection.as_ref().map(|rej| serde_json::json!({
            "reason": rej.reason,
            "message": rej.message,
        })),
    })
}

/// Map a reload outcome to the process exit code automation gates on: `0` when
/// the candidate was accepted (applied, or a dry-run that validated), `1` on a
/// rejection (the previous generation keeps serving). A permission-denied /
/// connect failure never reaches here. It surfaces as its own nonzero exit via
/// `main`. Pure, so the reject→nonzero mapping is unit-testable without a live
/// server (`basil-a84j`).
const fn reload_exit_code(r: &basil::AgentReload) -> i32 {
    if r.succeeded() { 0 } else { 1 }
}

/// Live policy explanation against the running broker's serving generation.
async fn explain(
    client: &mut Client,
    subject: &str,
    op: &str,
    key: &str,
    json: bool,
) -> Result<()> {
    let explanation = client.explain(subject, op, key).await?;
    if json {
        println!("{}", explain_json(&explanation));
        return Ok(());
    }

    println!(
        "{} {} {} for subject {}",
        explanation.decision.to_uppercase(),
        explanation.op,
        explanation.key,
        explanation.subject
    );
    if explanation.decision == "allow" {
        println!("via: {}", explanation.via);
        if let Some(rule) = &explanation.matched_rule {
            println!("matched_rule: {}", rule.rule);
            println!("action: {}", rule.action);
            println!("target: {}", rule.target);
        }
    } else {
        println!("reason: {}", explanation.reason);
    }
    Ok(())
}

/// Stable JSON shape for `basil explain --json`, mirroring
/// `basil config explain --json` for the single-tuple path.
fn explain_json(explanation: &basil::AgentExplanation) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("subject".into(), explanation.subject.clone().into());
    obj.insert("op".into(), explanation.op.clone().into());
    obj.insert("key".into(), explanation.key.clone().into());
    obj.insert("decision".into(), explanation.decision.clone().into());
    if explanation.decision == "allow" {
        obj.insert("via".into(), explanation.via.clone().into());
        let matched = explanation
            .matched_rule
            .as_ref()
            .map_or(serde_json::Value::Null, |m| {
                serde_json::json!({
                    "rule": m.rule,
                    "via": m.via,
                    "action": m.action,
                    "target": m.target,
                })
            });
        obj.insert("matched_rule".into(), matched);
    } else {
        obj.insert("reason".into(), explanation.reason.clone().into());
    }
    serde_json::Value::Object(obj)
}

/// Live JWT-SVID revocation against the running broker's deny-list.
async fn revoke(
    client: &mut Client,
    trust_domain: &str,
    jti: &str,
    expires_at_unix: u64,
    json: bool,
) -> Result<()> {
    let revocation = client.revoke(trust_domain, jti, expires_at_unix).await?;
    if json {
        println!("{}", revoke_json(&revocation));
        return Ok(());
    }
    println!("revoked: {}", revocation.jti);
    println!("trust_domain: {}", revocation.trust_domain);
    println!("expires_at_unix: {}", revocation.expires_at_unix);
    println!("persisted: {}", revocation.persisted);
    Ok(())
}

/// Stable JSON shape for `basil revoke --json`.
fn revoke_json(revocation: &basil::AgentRevocation) -> serde_json::Value {
    serde_json::json!({
        "trust_domain": revocation.trust_domain,
        "jti": revocation.jti,
        "expires_at_unix": revocation.expires_at_unix,
        "persisted": revocation.persisted,
    })
}

fn optional_hex(value: Option<String>, field: &'static str) -> Result<Option<Vec<u8>>> {
    value.map(|value| decode_hex(&value, field)).transpose()
}

fn decode_hex(value: &str, field: &'static str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{field} hex must not be empty");
    }
    hex::decode(trimmed).with_context(|| format!("{field} is not valid hex"))
}

const fn aead_name(value: AeadAlgorithm) -> &'static str {
    match value {
        AeadAlgorithm::Aes256Gcm => "aes256-gcm",
        AeadAlgorithm::Chacha20Poly1305 => "chacha20-poly1305",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Command as ClientCommand, KeyMaterial, ManifestEntry, check_import_set, explain_json,
        health_json, key_material, ready_exit_code, ready_json, reload_exit_code, reload_json,
        revoke_json,
    };
    use crate::Cli;
    use basil::{
        AgentExplanation, AgentHealth, AgentReadiness, AgentReload, AgentRevocation, MatchedRule,
        ReadinessReason, ReloadRejection,
    };
    use clap::Parser;
    use std::path::Path;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn parses_grpc_command_surface() {
        Cli::parse_from(["basil", "status"]);
        Cli::parse_from(["basil", "health"]);
        Cli::parse_from(["basil", "health", "--json"]);
        Cli::parse_from(["basil", "ready"]);
        Cli::parse_from(["basil", "ready", "--json"]);
        Cli::parse_from(["basil", "reload"]);
        Cli::parse_from(["basil", "reload", "--check"]);
        Cli::parse_from(["basil", "reload", "--check", "--json"]);
        Cli::parse_from([
            "basil",
            "new-key",
            "--key-id",
            "asym.rsa",
            "--key-type",
            "rsa-2048",
        ]);
        Cli::parse_from([
            "basil",
            "revoke",
            "--trust-domain",
            "example.test",
            "--jti",
            "token-1",
            "--expires-at-unix",
            "2000000000",
            "--json",
        ]);
        Cli::parse_from([
            "basil",
            "explain",
            "--subject",
            "svc.orders",
            "--op",
            "sign",
            "--key",
            "app.signing",
            "--json",
        ]);
        Cli::parse_from([
            "basil",
            "import",
            "--key-id",
            "byok.signer",
            "--seed-hex",
            &"00".repeat(32),
            "--check",
        ]);
        Cli::parse_from([
            "basil",
            "import",
            "--key-id",
            "byok.signer",
            "--key-type",
            "ed25519",
            "--pkcs8-file",
            "/tmp/key.der",
        ]);
        Cli::parse_from([
            "basil",
            "import-set",
            "--file",
            "/tmp/manifest.json",
            "--check",
        ]);
        Cli::parse_from(["basil", "get", "--key-id", "app.secret"]);
        Cli::parse_from(["basil", "get", "--key-id", "app.secret", "--raw"]);
        Cli::parse_from([
            "basil",
            "get",
            "--key-id",
            "app.secret",
            "--format",
            "base64",
        ]);
        Cli::parse_from([
            "basil",
            "get",
            "--key-id",
            "app.secret",
            "--format",
            "base64-url-no-pad",
        ]);
        Cli::parse_from([
            "basil",
            "get",
            "--key-id",
            "app.secret",
            "--format",
            "hex",
            "--out-file",
            "/run/secrets/app.hex",
        ]);
        Cli::parse_from([
            "basil",
            "get",
            "--key-id",
            "app.secret",
            "--out-file",
            "/run/secrets/app",
        ]);
        Cli::parse_from([
            "basil",
            "issue-nats-creds",
            "--jwt-file",
            "/run/secrets/user.jwt",
            "--seed-file",
            "/run/secrets/user.seed",
            "--out-file",
            "/run/secrets/user.creds",
            "--mode",
            "0660",
        ]);
        Cli::parse_from(["basil", "set", "--key-id", "app.secret", "hunter2"]);
        Cli::parse_from(["basil", "rotate", "--key-id", "app.secret"]);
        Cli::parse_from(["basil", "list", "--prefix", "app."]);
        Cli::parse_from([
            "basil",
            "mint-jwt",
            "--key-id",
            "jwt.issuer",
            "--sub",
            "subject",
        ]);
        Cli::parse_from([
            "basil",
            "mint-nats-user",
            "--key-id",
            "nats.account",
            "--user-nkey",
            "UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--pub-allow",
            "orders.>",
            "--sub-deny",
            "_INBOX.>",
        ]);
        Cli::parse_from([
            "basil",
            "sign-nats-jwt",
            "--key-id",
            "nats.account",
            "--claims-json",
            r#"{"sub":"UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","name":"svc","nats":{"type":"user","version":2}}"#,
            "--expect-type",
            "user",
            "--ttl-secs",
            "3600",
            "--rewrite-jti",
        ]);
        Cli::parse_from([
            "basil",
            "issue-cert",
            "--key-id",
            "spire.x509",
            "--common-name",
            "svc.example.org",
            "--dns-san",
            "svc.example.org",
            "--ip-san",
            "127.0.0.1",
            "--ttl-secs",
            "3600",
        ]);
        Cli::parse_from([
            "basil",
            "encrypt",
            "--key-id",
            "app.aead",
            "--algorithm",
            "aes256-gcm",
            "secret",
        ]);
        Cli::parse_from([
            "basil",
            "decrypt",
            "--key-id",
            "app.aead",
            "--algorithm",
            "aes256-gcm",
            "--version",
            "1",
            "--nonce",
            "000000000000000000000000",
            "--ciphertext",
            "00",
        ]);
    }

    #[test]
    fn explain_parses_subject_op_key_and_json() {
        let cli = Cli::parse_from([
            "basil",
            "explain",
            "--subject",
            "svc.orders",
            "--op",
            "sign",
            "--key",
            "app.signing",
            "--json",
        ]);
        match cli.command {
            crate::Command::Client(ClientCommand::Explain {
                subject,
                op,
                key,
                json,
            }) => {
                assert_eq!(subject, "svc.orders");
                assert_eq!(op, "sign");
                assert_eq!(key, "app.signing");
                assert!(json, "--json flag parsed");
            }
            other => panic!("unexpected command: {other:?}"),
        }

        // `--json` defaults off when omitted.
        let cli = Cli::parse_from([
            "basil",
            "explain",
            "--subject",
            "s",
            "--op",
            "get",
            "--key",
            "k",
        ]);
        match cli.command {
            crate::Command::Client(ClientCommand::Explain { json, .. }) => {
                assert!(!json, "--json defaults off");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn explain_json_allow_carries_matched_rule_provenance() {
        let explanation = AgentExplanation {
            subject: "svc.orders".into(),
            op: "sign".into(),
            key: "app.signing".into(),
            decision: "allow".into(),
            via: "user".into(),
            reason: String::new(),
            matched_rule: Some(MatchedRule {
                rule: "rule-7".into(),
                via: "user".into(),
                action: "sign".into(),
                target: "app.*".into(),
                subject: "svc.orders".into(),
            }),
        };
        let json = explain_json(&explanation);
        assert_eq!(json["decision"], "allow");
        assert_eq!(json["subject"], "svc.orders");
        assert_eq!(json["op"], "sign");
        assert_eq!(json["key"], "app.signing");
        assert_eq!(json["via"], "user");
        assert_eq!(json["matched_rule"]["rule"], "rule-7");
        assert_eq!(json["matched_rule"]["via"], "user");
        assert_eq!(json["matched_rule"]["action"], "sign");
        assert_eq!(json["matched_rule"]["target"], "app.*");
        // An allow object never carries a deny `reason` field.
        assert!(json.get("reason").is_none(), "allow omits reason");
    }

    #[test]
    fn explain_json_deny_carries_reason_not_rule() {
        let explanation = AgentExplanation {
            subject: "svc.orders".into(),
            op: "sign".into(),
            key: "app.signing".into(),
            decision: "deny".into(),
            via: String::new(),
            reason: "no_matching_rule".into(),
            matched_rule: None,
        };
        let json = explain_json(&explanation);
        assert_eq!(json["decision"], "deny");
        assert_eq!(json["subject"], "svc.orders");
        assert_eq!(json["reason"], "no_matching_rule");
        // A deny object carries neither the allow `via` scope nor a matched rule.
        assert!(json.get("via").is_none(), "deny omits via");
        assert!(
            json.get("matched_rule").is_none(),
            "deny omits matched_rule"
        );
    }

    #[test]
    fn new_key_parses_default_and_explicit_key_type() {
        let cli = Cli::parse_from(["basil", "new-key", "--key-id", "asym.default"]);
        match cli.command {
            crate::Command::Client(ClientCommand::NewKey { key_id, key_type }) => {
                assert_eq!(key_id, "asym.default");
                assert_eq!(key_type, super::KeyTypeArg::Ed25519);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let cli = Cli::parse_from([
            "basil",
            "new-key",
            "--key-id",
            "asym.nkey",
            "--key-type",
            "ed25519-nkey",
        ]);
        match cli.command {
            crate::Command::Client(ClientCommand::NewKey { key_id, key_type }) => {
                assert_eq!(key_id, "asym.nkey");
                assert_eq!(key_type, super::KeyTypeArg::Ed25519Nkey);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn import_check_flags_parse() {
        let cli = Cli::parse_from([
            "basil",
            "import",
            "--key-id",
            "byok.signer",
            "--seed-hex",
            &"00".repeat(32),
            "--check",
        ]);
        match cli.command {
            crate::Command::Client(ClientCommand::Import { check, .. }) => {
                assert!(check, "--check flag parsed for import");
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let cli = Cli::parse_from([
            "basil",
            "import-set",
            "--file",
            "/tmp/manifest.json",
            "--check",
        ]);
        match cli.command {
            crate::Command::Client(ClientCommand::ImportSet { check, .. }) => {
                assert!(check, "--check flag parsed for import-set");
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn get_format_parses_as_materialization_override() {
        let cli = Cli::parse_from([
            "basil",
            "get",
            "--key-id",
            "netbird.datastore",
            "--format",
            "base64",
            "--out-file",
            "/run/secrets/netbird-datastore-key",
        ]);
        match cli.command {
            crate::Command::Client(ClientCommand::Get {
                key_id,
                format,
                out_file,
                ..
            }) => {
                assert_eq!(key_id, "netbird.datastore");
                assert_eq!(format, Some(super::GetOutputFormatArg::Base64));
                assert_eq!(
                    out_file.as_deref(),
                    Some(Path::new("/run/secrets/netbird-datastore-key"))
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn issue_nats_creds_parses_local_file_inputs() {
        let cli = Cli::parse_from([
            "basil",
            "issue-nats-creds",
            "--jwt-file",
            "/run/secrets/user.jwt",
            "--seed-file",
            "/run/secrets/user.seed",
            "--out-file",
            "/run/secrets/user.creds",
            "--mode",
            "0660",
        ]);
        match cli.command {
            crate::Command::Client(ClientCommand::IssueNatsCreds {
                jwt_file,
                seed_file,
                out_file,
                mode,
                ..
            }) => {
                assert_eq!(
                    jwt_file.as_deref(),
                    Some(Path::new("/run/secrets/user.jwt"))
                );
                assert_eq!(
                    seed_file.as_deref(),
                    Some(Path::new("/run/secrets/user.seed"))
                );
                assert_eq!(out_file, Path::new("/run/secrets/user.creds"));
                assert_eq!(mode.mode(), 0o660);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn secret_encoding_formats_match_external_consumers() {
        let value = [251, 255, 0, 1];
        assert_eq!(
            super::encode_secret(&value, super::GetOutputFormatArg::Raw),
            value
        );
        assert_eq!(
            super::encode_secret(&value, super::GetOutputFormatArg::Hex),
            b"fbff0001"
        );
        assert_eq!(
            super::encode_secret(&value, super::GetOutputFormatArg::Base64),
            b"+/8AAQ=="
        );
        assert_eq!(
            super::encode_secret(&value, super::GetOutputFormatArg::Base64UrlNoPad),
            b"-_8AAQ"
        );
    }

    #[test]
    fn pem_block_frames_der_at_64_columns() {
        // 48 bytes of DER -> 64 base64 chars on a single body line.
        let der = vec![0xABu8; 48];
        let pem = super::pem_block("CERTIFICATE", &der);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        let body: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert_eq!(body.len(), 1);
        assert_eq!(body.first().map(|l| l.len()), Some(64));
    }

    #[test]
    fn pem_blocks_emits_one_block_per_der() {
        let ders = vec![vec![1u8; 10], vec![2u8; 10]];
        let pem = super::pem_blocks("CERTIFICATE", &ders);
        assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 2);
        assert_eq!(pem.matches("-----END CERTIFICATE-----").count(), 2);
    }

    #[test]
    fn seed_hex_decodes_to_a_32_byte_ed25519_seed() {
        let seed = "01".repeat(32);
        let material = key_material(Some(&seed), None).expect("32-byte seed must decode");
        assert_eq!(material, KeyMaterial::Ed25519Seed(vec![1u8; 32]));
    }

    #[test]
    fn seed_hex_of_wrong_length_is_rejected() {
        // 31 bytes: one short of an Ed25519 seed.
        let short = "01".repeat(31);
        assert!(key_material(Some(&short), None).is_err());
    }

    #[test]
    fn material_requires_exactly_one_source() {
        // Neither source.
        assert!(key_material(None, None).is_err());
        // Both sources at once.
        let seed = "01".repeat(32);
        assert!(key_material(Some(&seed), Some(Path::new("/tmp/key.der"))).is_err());
    }

    #[test]
    fn manifest_entry_parses_seed_hex_and_defaults_key_type() {
        let json = r#"{"key_id": "byok.a", "seed_hex": "00ff00ff"}"#;
        let entry: ManifestEntry = serde_json::from_str(json).expect("manifest entry must parse");
        assert_eq!(entry.key_id, "byok.a");
        assert_eq!(entry.key_type, super::KeyTypeArg::Ed25519);
        assert_eq!(entry.seed_hex.as_deref(), Some("00ff00ff"));
        assert!(entry.pkcs8_file.is_none());
    }

    #[test]
    fn manifest_entry_parses_explicit_key_type() {
        let json = r#"{"key_id": "byok.b", "key_type": "rsa-2048", "pkcs8_file": "/tmp/b.der"}"#;
        let entry: ManifestEntry = serde_json::from_str(json).expect("manifest entry must parse");
        assert_eq!(entry.key_type, super::KeyTypeArg::Rsa2048);
        assert_eq!(entry.pkcs8_file.as_deref(), Some(Path::new("/tmp/b.der")));

        let json =
            r#"{"key_id": "byok.ecdsa", "key_type": "ecdsa-p256", "pkcs8_file": "/tmp/e.der"}"#;
        let entry: ManifestEntry = serde_json::from_str(json).expect("manifest entry must parse");
        assert_eq!(entry.key_type, super::KeyTypeArg::EcdsaP256);
        assert_eq!(entry.pkcs8_file.as_deref(), Some(Path::new("/tmp/e.der")));
    }

    #[test]
    fn import_set_check_validates_manifest_and_local_material() {
        let base =
            std::env::temp_dir().join(format!("basil-import-set-check-{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("test temp directory must be created");
        let der = base.join("key.der");
        std::fs::write(&der, [0x30, 0x03, 0x02, 0x01, 0x00]).expect("DER fixture must be written");
        let manifest = base.join("manifest.json");
        std::fs::write(
            &manifest,
            format!(
                r#"[
                    {{"key_id":"byok.seed","seed_hex":"{}"}},
                    {{"key_id":"byok.pkcs8","key_type":"rsa-2048","pkcs8_file":"{}"}}
                ]"#,
                "11".repeat(32),
                der.display()
            ),
        )
        .expect("manifest fixture must be written");

        check_import_set(&manifest).expect("valid manifest must pass check mode validation");
    }

    #[test]
    fn import_set_check_rejects_empty_pkcs8_file() {
        let base = std::env::temp_dir().join(format!(
            "basil-import-set-check-empty-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).expect("test temp directory must be created");
        let der = base.join("empty.der");
        std::fs::write(&der, []).expect("empty DER fixture must be written");
        let manifest = base.join("manifest.json");
        std::fs::write(
            &manifest,
            format!(
                r#"[{{"key_id":"byok.pkcs8","key_type":"rsa-2048","pkcs8_file":"{}"}}]"#,
                der.display()
            ),
        )
        .expect("manifest fixture must be written");

        assert!(
            check_import_set(&manifest).is_err(),
            "empty PKCS#8 files are rejected in check mode"
        );
    }

    #[tokio::test]
    async fn import_checks_do_not_connect_to_agent() {
        super::run(
            Some("/tmp/basil-check-mode-no-agent.sock".to_string()),
            ClientCommand::Import {
                key_id: "byok.signer".to_string(),
                key_type: super::KeyTypeArg::Ed25519,
                seed_hex: Some("22".repeat(32)),
                pkcs8_file: None,
                check: true,
            },
        )
        .await
        .expect("import --check must not require a live agent");

        let base = std::env::temp_dir().join(format!(
            "basil-import-set-no-connect-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).expect("test temp directory must be created");
        let manifest = base.join("manifest.json");
        std::fs::write(
            &manifest,
            format!(
                r#"[{{"key_id":"byok.seed","seed_hex":"{}"}}]"#,
                "33".repeat(32)
            ),
        )
        .expect("manifest fixture must be written");

        super::run(
            Some("/tmp/basil-check-mode-no-agent.sock".to_string()),
            ClientCommand::ImportSet {
                file: manifest,
                check: true,
            },
        )
        .await
        .expect("import-set --check must not require a live agent");
    }

    // -----------------------------------------------------------------------
    // CLI shape coverage: the scriptable `--json` field set + the exit-code
    // mapping for `health` / `ready` / `reload` (`basil-mil0.6`, `basil-a84j`).
    // These pin the contract orchestrators gate on WITHOUT a live server: the
    // live not-ready→nonzero / reject→nonzero legs are the e2e's job.
    // -----------------------------------------------------------------------

    #[test]
    fn health_json_shape_is_alive_and_version() {
        let h = AgentHealth {
            alive: true,
            version: "0.1.0".to_string(),
        };
        let v = health_json(&h);
        // Exactly two keys, both scriptable: a probe parses `alive`.
        assert_eq!(v["alive"], serde_json::json!(true));
        assert_eq!(v["version"], serde_json::json!("0.1.0"));
        let obj = v.as_object().expect("health --json is a JSON object");
        assert_eq!(
            obj.len(),
            2,
            "health --json carries exactly alive + version"
        );
    }

    /// Build an [`AgentReadiness`] with a coarse reason + counts for the shape tests.
    fn readiness(ready: bool, reason: ReadinessReason, present: u32, total: u32) -> AgentReadiness {
        AgentReadiness {
            ready,
            reason,
            generation: 7,
            keys_total: total,
            keys_present: present,
            keys_required_missing: total - present,
            keys_optional_missing: 0,
        }
    }

    #[test]
    fn ready_json_shape_and_reason_tokens() {
        // READY: present == total, the active generation is surfaced.
        let r = readiness(true, ReadinessReason::Ready, 4, 4);
        let v = ready_json(&r);
        assert_eq!(v["ready"], serde_json::json!(true));
        assert_eq!(v["reason"], serde_json::json!("ready"));
        assert_eq!(v["generation"], serde_json::json!(7));
        assert_eq!(v["keys_total"], serde_json::json!(4));
        assert_eq!(v["keys_present"], serde_json::json!(4));
        assert_eq!(v["keys_required_missing"], serde_json::json!(0));
        assert_eq!(v["keys_optional_missing"], serde_json::json!(0));
        let obj = v.as_object().expect("ready --json is a JSON object");
        assert_eq!(
            obj.len(),
            7,
            "ready --json carries the full 7-field summary"
        );

        // The coarse reason tokens automation matches on are stable.
        assert_eq!(
            ready_json(&readiness(false, ReadinessReason::BackendUnreachable, 0, 4))["reason"],
            serde_json::json!("backend_unreachable")
        );
        assert_eq!(
            ready_json(&readiness(false, ReadinessReason::RequiredKeyMissing, 3, 4))["reason"],
            serde_json::json!("required_key_missing")
        );
    }

    #[test]
    fn ready_exit_code_maps_ready_to_zero_and_not_ready_to_one() {
        assert_eq!(
            ready_exit_code(&readiness(true, ReadinessReason::Ready, 4, 4)),
            0,
            "a ready broker exits 0"
        );
        assert_eq!(
            ready_exit_code(&readiness(false, ReadinessReason::BackendUnreachable, 0, 4)),
            1,
            "a backend-unreachable broker exits 1 (not ready)"
        );
        assert_eq!(
            ready_exit_code(&readiness(false, ReadinessReason::RequiredKeyMissing, 3, 4)),
            1,
            "a required-key-missing broker exits 1 (not ready)"
        );
    }

    /// Build an applied [`AgentReload`] (a real swap) for the shape tests.
    fn reload_applied() -> AgentReload {
        AgentReload {
            applied: true,
            checked: false,
            previous_generation: 4,
            new_generation: 5,
            key_count: 12,
            grant_count: 9,
            rejection: None,
        }
    }

    /// Build a rejected [`AgentReload`] (the previous generation keeps serving).
    fn reload_rejected() -> AgentReload {
        AgentReload {
            applied: false,
            checked: false,
            previous_generation: 4,
            new_generation: 4,
            key_count: 12,
            grant_count: 9,
            rejection: Some(ReloadRejection {
                reason: "routing_shape_changed".to_string(),
                message: "a key's backend locator changed (restart-only)".to_string(),
            }),
        }
    }

    #[test]
    fn reload_json_shape_applied_has_null_rejection() {
        let v = reload_json(&reload_applied());
        assert_eq!(v["applied"], serde_json::json!(true));
        assert_eq!(v["checked"], serde_json::json!(false));
        assert_eq!(v["previous_generation"], serde_json::json!(4));
        assert_eq!(v["new_generation"], serde_json::json!(5));
        assert_eq!(v["key_count"], serde_json::json!(12));
        assert_eq!(v["grant_count"], serde_json::json!(9));
        // An applied reload carries an explicit `null` rejection (the key is
        // always present so automation can test for it unconditionally).
        assert_eq!(v["rejection"], serde_json::Value::Null);
        let obj = v.as_object().expect("reload --json is a JSON object");
        assert_eq!(obj.len(), 7, "reload --json carries 7 keys incl. rejection");
    }

    #[test]
    fn reload_json_shape_rejected_nests_reason_and_message() {
        let v = reload_json(&reload_rejected());
        assert_eq!(v["applied"], serde_json::json!(false));
        // The previous generation keeps serving: prev == new on a rejection.
        assert_eq!(v["previous_generation"], v["new_generation"]);
        let rej = v["rejection"]
            .as_object()
            .expect("a rejected reload nests a rejection object");
        assert_eq!(rej["reason"], serde_json::json!("routing_shape_changed"));
        assert_eq!(
            rej["message"],
            serde_json::json!("a key's backend locator changed (restart-only)")
        );
    }

    #[test]
    fn reload_exit_code_maps_accepted_to_zero_and_rejected_to_one() {
        assert_eq!(
            reload_exit_code(&reload_applied()),
            0,
            "an applied reload exits 0"
        );
        assert_eq!(
            reload_exit_code(&reload_rejected()),
            1,
            "a rejected reload exits 1 (never a silent 0)"
        );
        // A clean dry-run (`--check`) also exits 0: validated, no swap, no rejection.
        let mut dry = reload_applied();
        dry.applied = false;
        dry.checked = true;
        assert_eq!(reload_exit_code(&dry), 0, "a clean --check dry-run exits 0");
    }

    #[test]
    fn revoke_json_shape_is_stable() {
        let v = revoke_json(&AgentRevocation {
            trust_domain: "example.test".into(),
            jti: "token-1".into(),
            expires_at_unix: 2_000_000_000,
            persisted: true,
        });
        assert_eq!(v["trust_domain"], serde_json::json!("example.test"));
        assert_eq!(v["jti"], serde_json::json!("token-1"));
        assert_eq!(v["expires_at_unix"], serde_json::json!(2_000_000_000_u64));
        assert_eq!(v["persisted"], serde_json::json!(true));
        let obj = v.as_object().expect("revoke --json is a JSON object");
        assert_eq!(obj.len(), 4, "revoke --json carries exactly four fields");
    }
}
