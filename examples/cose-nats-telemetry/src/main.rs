//! Two services exchange COSE-signed telemetry over NATS using nothing but
//! Basil-minted **leases** and **in-place signatures**. No long-lived secrets
//! anywhere.
//!
//! This is deliberately different from `examples/cose-nats-demo`, which carries
//! *sealed invocations* over the `basil-nats-bridge`. Here two NATS clients
//! connect **directly** and exchange **bare `COSE_Sign1`** application messages:
//!
//! - Basil mints the operator → account → user NATS credential chain. The
//!   operator/account/user NKey seeds stay custodied in the vault.
//! - Each service authenticates to `nats-server` (operator mode, memory
//!   resolver) with a Basil-minted **user JWT** and a signature callback that
//!   routes the server nonce through `SignWithAlgorithm` (`ED25519_NKEY`): the
//!   NKey seed never leaves the vault.
//! - The publisher signs a telemetry payload as a bare `COSE_Sign1`
//!   (`basil_cose::build_signed`) with a broker-backed signer over a transit
//!   Ed25519 key. The subscriber verifies with the public key fetched from the
//!   broker (`verify_signed`), checks the claims, and asserts payload equality.
//! - A tampered message is rejected.
//!
//! Two subcommands: `write-nats-config` (mint the operator/account chain and
//! render an operator-mode `nats-server` config) and `run` (mint user leases,
//! connect both services, and exchange telemetry).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use async_nats::{AuthError, ConnectOptions};
use basil::{Client, NatsJwtType, NatsUserPermissions, SignNatsJwtOptions, SigningAlgorithm};
use basil_cose::{
    Claims, ContentType, Ed25519Verifier, ExternalAad, KeyId, MessageId, MessageRole, SignParams,
    Subject, UnixTime, ValidationParams, VerifySignedParams, build_signed, verify_signed,
};
use basil_nats::NkeyType;
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use tokio::sync::{Mutex, mpsc, oneshot};

/// Catalog key that signs the COSE telemetry (transit Ed25519).
const SIGN_KEY: &str = "telemetry.sign";
/// Catalog key custodying the operator identity NKey.
const OPERATOR_KEY: &str = "nats.operator";
/// Catalog key custodying the account identity NKey.
const ACCOUNT_KEY: &str = "nats.account";
/// Catalog key custodying the publisher user NKey.
const PUBLISHER_KEY: &str = "nats.pub";
/// Catalog key custodying the subscriber user NKey.
const SUBSCRIBER_KEY: &str = "nats.sub";
/// The subject telemetry is published on.
const SUBJECT: &str = "telemetry.ingest";
/// The COSE content type for the telemetry payload.
const CONTENT_TYPE: &str = "application/vnd.basil.example.telemetry+json";
/// The telemetry payload the publisher signs.
const TELEMETRY: &str =
    r#"{"sensor":"turbine-7","metric":"rpm","value":3600,"ts":"2026-07-03T00:00:00Z"}"#;

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Mint the operator + account chain and render an operator-mode
    /// `nats-server` config (memory resolver, account preloaded).
    WriteNatsConfig {
        #[arg(long)]
        socket: String,
        /// Where to write the `nats-server` config file.
        #[arg(long)]
        out: PathBuf,
        /// Where to write the operator JWT (referenced by the config).
        #[arg(long)]
        operator_jwt: PathBuf,
        /// The port the config makes `nats-server` listen on.
        #[arg(long, default_value_t = 4240)]
        nats_port: u16,
    },
    /// Mint the user leases, connect both services, and exchange telemetry.
    Run {
        #[arg(long)]
        socket: String,
        #[arg(long)]
        nats_url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::WriteNatsConfig {
            socket,
            out,
            operator_jwt,
            nats_port,
        } => write_nats_config(&socket, &out, &operator_jwt, nats_port).await,
        Command::Run { socket, nats_url } => run(&socket, &nats_url).await,
    }
}

/// Mint the operator (self-signed) and account (operator-signed) JWTs, then
/// render an operator-mode `nats-server` config with the account preloaded in
/// the memory resolver.
async fn write_nats_config(
    socket: &str,
    out: &std::path::Path,
    operator_jwt_path: &std::path::Path,
    nats_port: u16,
) -> Result<()> {
    let mut client = Client::connect(socket)
        .await
        .with_context(|| format!("connect basil agent at {socket}"))?;

    let account_nkey = public_nkey(&mut client, ACCOUNT_KEY, NkeyType::Account).await?;

    // The operator self-signs (subject == issuer).
    let operator_jwt = client
        .mint_nats_operator(
            OPERATOR_KEY,
            None,
            "basil-telemetry-operator",
            &[],
            None,
            None,
            None,
        )
        .await
        .context("mint operator JWT")?;

    // The account JWT is signed by the operator key. This example uses the
    // caller-supplied-claims path (`sign_nats_jwt`) so it can pin an explicit
    // limits block; `mint_nats_account` now defaults to unlimited limits.
    let account_claims = serde_json::json!({
        "sub": account_nkey,
        "name": "APP",
        "nats": {
            "type": "account",
            "version": 2,
            "limits": {
                "subs": -1, "data": -1, "payload": -1,
                "conn": -1, "leaf": -1, "imports": -1, "exports": -1,
                "wildcards": true
            }
        }
    });
    let account_jwt = client
        .sign_nats_jwt(
            OPERATOR_KEY,
            account_claims,
            SignNatsJwtOptions {
                expected_type: Some(NatsJwtType::Account),
                ..Default::default()
            },
        )
        .await
        .context("sign account JWT")?
        .token;

    tokio::fs::write(operator_jwt_path, operator_jwt.as_bytes())
        .await
        .with_context(|| format!("write operator JWT to {}", operator_jwt_path.display()))?;

    let config = format!(
        "port: {nats_port}\n\
         operator: {operator}\n\
         resolver: MEMORY\n\
         resolver_preload: {{\n\
         \x20 {account_nkey}: {account_jwt}\n\
         }}\n",
        operator = operator_jwt_path.display(),
        account_jwt = account_jwt,
    );
    tokio::fs::write(out, config.as_bytes())
        .await
        .with_context(|| format!("write nats-server config to {}", out.display()))?;

    println!("account nkey: {account_nkey}");
    println!(
        "wrote operator-mode nats-server config to {}",
        out.display()
    );
    Ok(())
}

/// Mint two short-lived user leases, connect a publisher and a subscriber, and
/// exchange COSE-signed telemetry with a tamper check.
async fn run(socket: &str, nats_url: &str) -> Result<()> {
    let mut client = Client::connect(socket)
        .await
        .with_context(|| format!("connect basil agent at {socket}"))?;

    // The public NKeys are the subjects of the user JWTs.
    let publisher_nkey = public_nkey(&mut client, PUBLISHER_KEY, NkeyType::User).await?;
    let subscriber_nkey = public_nkey(&mut client, SUBSCRIBER_KEY, NkeyType::User).await?;

    // Short-lived, narrowly-scoped user leases (the account key signs them).
    let publisher_jwt = client
        .mint_nats_user(
            ACCOUNT_KEY,
            &publisher_nkey,
            None,
            "telemetry-publisher",
            Some(300),
            NatsUserPermissions {
                pub_allow: vec![format!("{SUBJECT}")],
                sub_allow: vec!["_INBOX.>".to_string()],
                ..Default::default()
            },
        )
        .await
        .context("mint publisher user JWT")?;
    let subscriber_jwt = client
        .mint_nats_user(
            ACCOUNT_KEY,
            &subscriber_nkey,
            None,
            "telemetry-subscriber",
            Some(300),
            NatsUserPermissions {
                sub_allow: vec![format!("{SUBJECT}")],
                pub_allow: vec!["_INBOX.>".to_string()],
                ..Default::default()
            },
        )
        .await
        .context("mint subscriber user JWT")?;

    // The verifier pins the publisher's COSE signing public key (fetched from
    // the broker). Verification is pure: it needs no broker round-trip.
    let sign_public = fetch_public_key(&mut client, SIGN_KEY).await?;

    // A background task signs NATS server nonces in place. Routing through a
    // channel keeps the async-nats auth callback's future `Send + Sync` (the
    // gRPC call future itself is not) while never releasing the NKey seed.
    let (sign_tx, mut sign_rx) = mpsc::unbounded_channel::<NonceSign>();
    let mut signer_client = client.clone();
    let signer = tokio::spawn(async move {
        while let Some(req) = sign_rx.recv().await {
            let result = signer_client
                .sign_with_algorithm(&req.key_id, &req.nonce, SigningAlgorithm::Ed25519Nkey)
                .await
                .map_err(|e| e.to_string());
            let _ = req.reply.send(result);
        }
    });

    // Subscriber: authenticate, subscribe, verify each message, reply.
    let (ready_tx, ready_rx) = oneshot::channel();
    let sub_options = nats_options(subscriber_jwt, SUBSCRIBER_KEY.to_string(), sign_tx.clone());
    let sub_url = nats_url.to_string();
    let subscriber = tokio::spawn(subscriber_loop(sub_options, sub_url, sign_public, ready_tx));
    if ready_rx.await.is_err() {
        // The subscriber task ended before signaling ready; surface its real error.
        let outcome = subscriber.await.context("join subscriber")?;
        outcome.context("subscriber failed before it was ready")?;
        bail!("subscriber ended before signaling ready");
    }
    println!("subscriber: authenticated to NATS with minted user JWT");

    // Publisher: authenticate, then sign + publish telemetry.
    let pub_options = nats_options(publisher_jwt, PUBLISHER_KEY.to_string(), sign_tx.clone());
    let publisher_nats = pub_options
        .connect(nats_url)
        .await
        .context("publisher connect to NATS")?;
    println!("publisher: authenticated to NATS with minted user JWT");

    let cose_signer = basil::BrokerSigner::new(Arc::new(Mutex::new(client.clone())), SIGN_KEY)
        .context("build broker-backed COSE signer")?;
    let cose = build_telemetry(&cose_signer).await?;

    // Good message: the subscriber must verify it and echo the payload.
    let reply = publisher_nats
        .request(SUBJECT.to_string(), cose.clone().into())
        .await
        .context("publish telemetry over NATS")?;
    let reply = String::from_utf8_lossy(&reply.payload).into_owned();
    let Some(payload) = reply.strip_prefix("verified:") else {
        bail!("subscriber did not verify the telemetry: {reply}");
    };
    ensure!(
        payload == TELEMETRY,
        "subscriber payload mismatch: {payload:?}"
    );
    println!("subscriber: COSE verify true (payload matched)");

    // Tampered message: one flipped byte in the signature must be rejected.
    let mut tampered = cose.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let reply = publisher_nats
        .request(SUBJECT.to_string(), tampered.into())
        .await
        .context("publish tampered telemetry over NATS")?;
    let reply = String::from_utf8_lossy(&reply.payload).into_owned();
    ensure!(
        reply.starts_with("rejected:"),
        "subscriber accepted a tampered message: {reply}"
    );
    println!("subscriber: tampered message rejected ({reply})");

    drop(publisher_nats);
    drop(sign_tx);
    subscriber.await.context("join subscriber")??;
    signer.await.context("join signer task")?;
    println!("cose-nats-telemetry: all assertions passed");
    Ok(())
}

/// One in-place NKey nonce-signing request.
struct NonceSign {
    key_id: String,
    nonce: Vec<u8>,
    reply: oneshot::Sender<Result<Vec<u8>, String>>,
}

/// Build async-nats connect options that present `jwt` and sign the server nonce
/// in place through the background signer task (the seed never leaves the vault).
fn nats_options(
    jwt: String,
    key_id: String,
    sign_tx: mpsc::UnboundedSender<NonceSign>,
) -> ConnectOptions {
    ConnectOptions::with_jwt(jwt, move |nonce: Vec<u8>| {
        let sign_tx = sign_tx.clone();
        let key_id = key_id.clone();
        async move {
            let (reply, rx) = oneshot::channel();
            sign_tx
                .send(NonceSign {
                    key_id,
                    nonce,
                    reply,
                })
                .map_err(|_| AuthError::new("basil signer task is gone"))?;
            let signature = rx
                .await
                .map_err(|_| AuthError::new("basil signer task dropped the request"))?
                .map_err(AuthError::new)?;
            Ok(signature)
        }
    })
}

/// Connect, subscribe, and verify each COSE message, replying with the outcome.
async fn subscriber_loop(
    options: ConnectOptions,
    url: String,
    sign_public: [u8; 32],
    ready_tx: oneshot::Sender<()>,
) -> Result<()> {
    let nats = options.connect(&url).await.context("subscriber connect")?;
    let mut subscription = nats
        .subscribe(SUBJECT.to_string())
        .await
        .context("subscribe telemetry")?;
    ready_tx
        .send(())
        .map_err(|()| anyhow::anyhow!("publisher stopped waiting"))?;

    let verifier = Ed25519Verifier::from_key(KeyId::from_text(SIGN_KEY)?, &sign_public)
        .context("pin COSE verifier key")?;

    let mut handled = 0u8;
    while let Some(message) = subscription.next().await {
        let Some(reply_subject) = message.reply.clone() else {
            bail!("telemetry request carried no reply subject");
        };
        let response = match verify_telemetry(&verifier, &message.payload).await {
            Ok(payload) => format!("verified:{payload}"),
            Err(err) => format!("rejected:{err}"),
        };
        nats.publish(reply_subject, response.into_bytes().into())
            .await
            .context("reply to publisher")?;
        nats.flush().await.context("flush reply")?;
        handled += 1;
        if handled == 2 {
            break;
        }
    }
    Ok(())
}

/// Verify a bare `COSE_Sign1` telemetry message and return its payload as text.
async fn verify_telemetry(verifier: &Ed25519Verifier, bytes: &[u8]) -> Result<String> {
    let validation = ValidationParams {
        now: UnixTime(i64::from(now_unix()?)),
        max_clock_skew: Duration::from_secs(30),
        max_ttl: Duration::from_secs(120),
        default_ttl: Duration::from_secs(60),
        allowed_audiences: BTreeSet::new(),
        role: MessageRole::Peer,
    };
    let verified = verify_signed(
        bytes,
        verifier,
        &VerifySignedParams {
            external_aad: ExternalAad::empty(),
            validation: Some(&validation),
        },
    )
    .await?;
    ensure!(
        verified.content_type.as_str() == CONTENT_TYPE,
        "unexpected content type {}",
        verified.content_type.as_str()
    );
    String::from_utf8(verified.payload).context("telemetry payload was not UTF-8")
}

/// Build a bare `COSE_Sign1` over the telemetry payload with a broker-backed signer.
async fn build_telemetry(signer: &basil::BrokerSigner) -> Result<Vec<u8>> {
    let now = now_unix()?;
    let claims = Claims {
        issuer: Some(Subject::new("telemetry-publisher".to_string())?),
        audience: Some(Subject::new("telemetry-subscriber".to_string())?),
        expires_at: Some(UnixTime(i64::from(now + 60))),
        issued_at: UnixTime(i64::from(now)),
        message_id: MessageId::from_bytes(format!("telemetry-{now}").into())?,
        sender_key_id: Some(KeyId::from_text(SIGN_KEY)?),
        response_key_id: None,
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
    };
    let cose = build_signed(
        &SignParams {
            content_type: ContentType::new(CONTENT_TYPE.to_string())?,
            payload: TELEMETRY.as_bytes(),
            claims: Some(claims),
            external_aad: ExternalAad::empty(),
        },
        signer,
    )
    .await?;
    Ok(cose.into_vec())
}

/// Fetch a key's public half and return the NKey-encoded public string.
async fn public_nkey(client: &mut Client, key_id: &str, role: NkeyType) -> Result<String> {
    let raw = fetch_public_key(client, key_id).await?;
    basil_nats::encode_public(role, &raw).with_context(|| format!("encode {key_id} public NKey"))
}

/// Fetch a key's 32-byte public half.
async fn fetch_public_key(client: &mut Client, key_id: &str) -> Result<[u8; 32]> {
    let public = client
        .get_public_key(key_id, None)
        .await
        .with_context(|| format!("fetch public key {key_id}"))?
        .public_key;
    public.as_slice().try_into().with_context(|| {
        format!(
            "{key_id} public key was {} bytes, expected 32",
            public.len()
        )
    })
}

/// Current Unix time in seconds as a `u32`.
fn now_unix() -> Result<u32> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    u32::try_from(seconds).context("unix time does not fit u32")
}
