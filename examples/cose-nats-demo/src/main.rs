// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use async_nats::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use basil::{
    BrokerRecipient, BrokerSigner, CarrierSigner, CarrierSignerConfig, Client,
    SealedInvocationCarrier,
};
use basil_cose::{
    Claims, ContentAlgorithm, ContentType, Ed25519Signer, Ed25519Verifier, ExternalAad, KdfParties,
    KeyId, MessageId, MessageRole, SealParams, SealedAad, Signer, Subject, UnixTime,
    ValidationParams, X25519RecipientPublic, build_sealed, verify_sealed,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const ALICE_INVOKE_SEED: [u8; 32] = [0x11; 32];
const BOB_INVOKE_SEED: [u8; 32] = [0x22; 32];
const ALICE_SEAL_PRIVATE: [u8; 32] = [0x33; 32];
const BOB_SEAL_PRIVATE: [u8; 32] = [0x44; 32];
const BROKER_REQUEST_PRIVATE: [u8; 32] = [0x55; 32];
const ALICE_RESPONSE_PRIVATE: [u8; 32] = [0x66; 32];
const PEER_CONTENT_TYPE: &str = "application/vnd.basil.example.peer-message";

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print deterministic fixture material as shell assignments.
    PrintFixtures,
    /// Run the Alice/Bob COSE-over-NATS exchange.
    Run {
        #[arg(long)]
        socket: String,
        #[arg(long)]
        nats_url: String,
        #[arg(long, default_value = "basil.invoke")]
        bridge_subject: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Args::parse().command {
        Command::PrintFixtures => {
            print_fixtures();
            Ok(())
        }
        Command::Run {
            socket,
            nats_url,
            bridge_subject,
        } => run_demo(&socket, &nats_url, &bridge_subject).await,
    }
}

fn print_fixtures() {
    let alice_invoke_public = SigningKey::from_bytes(&ALICE_INVOKE_SEED)
        .verifying_key()
        .to_bytes();
    let bob_invoke_public = SigningKey::from_bytes(&BOB_INVOKE_SEED)
        .verifying_key()
        .to_bytes();

    print_assignment(
        "ALICE_INVOKE_PUBLIC",
        &URL_SAFE_NO_PAD.encode(alice_invoke_public),
    );
    print_assignment(
        "BOB_INVOKE_PUBLIC",
        &URL_SAFE_NO_PAD.encode(bob_invoke_public),
    );
    print_assignment("ALICE_SEAL_PRIVATE", &STANDARD.encode(ALICE_SEAL_PRIVATE));
    print_assignment(
        "ALICE_SEAL_PUBLIC",
        &STANDARD.encode(x25519_public(ALICE_SEAL_PRIVATE)),
    );
    print_assignment("BOB_SEAL_PRIVATE", &STANDARD.encode(BOB_SEAL_PRIVATE));
    print_assignment(
        "BOB_SEAL_PUBLIC",
        &STANDARD.encode(x25519_public(BOB_SEAL_PRIVATE)),
    );
    print_assignment(
        "BROKER_REQUEST_PRIVATE",
        &STANDARD.encode(BROKER_REQUEST_PRIVATE),
    );
    print_assignment(
        "BROKER_REQUEST_PUBLIC",
        &STANDARD.encode(x25519_public(BROKER_REQUEST_PRIVATE)),
    );
    print_assignment(
        "ALICE_RESPONSE_PRIVATE",
        &STANDARD.encode(ALICE_RESPONSE_PRIVATE),
    );
    print_assignment(
        "ALICE_RESPONSE_PUBLIC",
        &STANDARD.encode(x25519_public(ALICE_RESPONSE_PRIVATE)),
    );
}

fn print_assignment(name: &str, value: &str) {
    println!("{name}='{value}'");
}

fn x25519_public(private: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(private)).to_bytes()
}

async fn run_demo(socket: &str, nats_url: &str, bridge_subject: &str) -> anyhow::Result<()> {
    let client = Arc::new(Mutex::new(
        Client::connect(socket)
            .await
            .with_context(|| format!("connect basil agent at {socket}"))?,
    ));
    let nats = async_nats::connect(nats_url)
        .await
        .with_context(|| format!("connect NATS at {nats_url}"))?;

    let alice_sign_public = public_key(&client, "alice.sign").await?;
    let bob_sign_public = public_key(&client, "bob.sign").await?;
    let broker_response_public = public_key(&client, "broker.response").await?;
    let broker_request_public = x25519_public(BROKER_REQUEST_PRIVATE);
    let alice_seal_public = x25519_public(ALICE_SEAL_PRIVATE);
    let bob_seal_public = x25519_public(BOB_SEAL_PRIVATE);

    let peer_verifier = verifier([
        ("alice.sign", alice_sign_public.as_slice()),
        ("bob.sign", bob_sign_public.as_slice()),
    ])?;
    let broker_verifier = verifier([("broker.response", broker_response_public.as_slice())])?;

    let bob_client = Arc::clone(&client);
    let bob_nats = nats.clone();
    let (bob_ready_tx, bob_ready_rx) = oneshot::channel();
    let bob = tokio::spawn(async move {
        bob_loop(
            bob_client,
            bob_nats,
            peer_verifier,
            X25519RecipientPublic {
                key_id: KeyId::from_text("alice.seal")?,
                public: alice_seal_public,
            },
            bob_ready_tx,
        )
        .await
    });

    bob_ready_rx.await.context("wait for Bob subscription")?;

    let alice_bridge_signer = CarrierSigner::new(
        "alice.sign",
        NatsCarrier {
            nats: nats.clone(),
            subject: bridge_subject.to_string(),
        },
        Ed25519Signer::from_secret_bytes(
            KeyId::from_text("alice.invoke")?,
            &Zeroizing::new(ALICE_INVOKE_SEED),
        ),
        BrokerRecipient::new(Arc::clone(&client), "alice.response")?,
        broker_verifier,
        CarrierSignerConfig {
            request_sign_id: "alice.invoke".to_string(),
            request_subject: Some("svc.alice".to_string()),
            broker_request_key_id: "broker.request".to_string(),
            broker_request_public: to_array(&broker_request_public, "broker.request public")?,
            broker_request_subject: Some("basil://example/cose-nats-demo".to_string()),
            response_encryption_key_id: "alice.response".to_string(),
            request_ttl: Duration::from_secs(45),
            max_clock_skew: Duration::from_secs(30),
            max_ttl: Duration::from_secs(120),
            default_ttl: Duration::from_secs(60),
            allowed_audiences: BTreeSet::new(),
        },
    )?;
    let request = peer_message(
        "alice.sign",
        "svc.alice",
        "svc.bob",
        "alice-to-bob",
        "hello Bob - signed through the NATS bridge",
        X25519RecipientPublic {
            key_id: KeyId::from_text("bob.seal")?,
            public: bob_seal_public,
        },
        &alice_bridge_signer,
    )
    .await?;

    let reply = nats
        .request("demo.bob".to_string(), request.into())
        .await
        .context("request Bob over NATS")?;
    ensure_no_bridge_error(reply.headers.as_ref())?;

    let alice_verifier = verifier([("bob.sign", bob_sign_public.as_slice())])?;
    let opened = open_peer_message(
        Arc::clone(&client),
        "alice.seal",
        &reply.payload,
        &alice_verifier,
    )
    .await?;
    if opened != b"hello Alice - Bob verified your message" {
        bail!("unexpected Bob reply: {}", String::from_utf8_lossy(&opened));
    }
    println!(
        "alice verified Bob reply: {}",
        String::from_utf8_lossy(&opened)
    );

    drop(nats);
    bob.await.context("join Bob task")??;
    println!("demo completed");
    Ok(())
}

async fn bob_loop(
    client: Arc<Mutex<Client>>,
    nats: async_nats::Client,
    verifier: Ed25519Verifier,
    alice_recipient: X25519RecipientPublic,
    ready: oneshot::Sender<()>,
) -> anyhow::Result<()> {
    let mut sub = nats.subscribe("demo.bob".to_string()).await?;
    nats.flush().await?;
    let _ = ready.send(());
    let message = sub
        .next()
        .await
        .context("waiting for Alice message on demo.bob")?;
    let opened =
        open_peer_message(Arc::clone(&client), "bob.seal", &message.payload, &verifier).await?;
    if opened != b"hello Bob - signed through the NATS bridge" {
        bail!(
            "unexpected Alice message: {}",
            String::from_utf8_lossy(&opened)
        );
    }
    println!(
        "bob verified Alice message: {}",
        String::from_utf8_lossy(&opened)
    );

    let signer = BrokerSigner::new(Arc::clone(&client), "bob.sign")?;
    let response = peer_message(
        "bob.sign",
        "svc.bob",
        "svc.alice",
        "bob-to-alice",
        "hello Alice - Bob verified your message",
        alice_recipient,
        &signer,
    )
    .await?;
    let Some(reply) = message.reply else {
        bail!("Alice request had no reply subject");
    };
    nats.publish(reply, response.into()).await?;
    Ok(())
}

async fn peer_message<S: Signer>(
    sender_key_id: &str,
    issuer: &str,
    audience: &str,
    message_tag: &str,
    text: &str,
    recipient: X25519RecipientPublic,
    signer: &S,
) -> anyhow::Result<Vec<u8>> {
    let now = now_unix()?;
    let claims = Claims {
        issuer: Some(Subject::new(issuer.to_string())?),
        audience: Some(Subject::new(audience.to_string())?),
        expires_at: Some(UnixTime(i64::from(now + 60))),
        issued_at: UnixTime(i64::from(now)),
        message_id: MessageId::from_bytes(format!("{message_tag}-{}", Uuid::new_v4()).into())?,
        sender_key_id: Some(KeyId::from_text(sender_key_id)?),
        response_key_id: None,
        response_subject: None,
        in_reply_to: None,
        request_hash: None,
    };
    let message = build_sealed(
        &SealParams {
            content_type: ContentType::new(PEER_CONTENT_TYPE.to_string())?,
            plaintext: text.as_bytes(),
            claims,
            role: MessageRole::Peer,
            recipient,
            content_algorithm: ContentAlgorithm::A256Gcm,
            aad: SealedAad::empty(),
            kdf_parties: KdfParties::anonymous(),
        },
        signer,
    )
    .await?;
    Ok(message.into_vec())
}

async fn open_peer_message(
    client: Arc<Mutex<Client>>,
    recipient_key_id: &str,
    message: &[u8],
    verifier: &Ed25519Verifier,
) -> anyhow::Result<Vec<u8>> {
    let validation = ValidationParams {
        now: UnixTime(i64::from(now_unix()?)),
        max_clock_skew: Duration::from_secs(30),
        max_ttl: Duration::from_secs(120),
        default_ttl: Duration::from_secs(60),
        allowed_audiences: BTreeSet::new(),
        role: MessageRole::Peer,
    };
    let verified = verify_sealed(
        message,
        verifier,
        &basil_cose::VerifySealedParams {
            signature_aad: ExternalAad::empty(),
            validation: &validation,
        },
    )
    .await?;
    if verified.content_type.as_str() != PEER_CONTENT_TYPE {
        bail!(
            "unexpected peer content type {}",
            verified.content_type.as_str()
        );
    }
    let recipient = BrokerRecipient::new(client, recipient_key_id)?;
    let opened = verified
        .open(
            &recipient,
            &ExternalAad::empty(),
            Some(&KdfParties::anonymous()),
        )
        .await?;
    Ok(opened.plaintext.to_vec())
}

/// A [`SealedInvocationCarrier`] over the NATS request/reply bridge.
///
/// This is all the demo needs to reach the broker over NATS; the sealed `Sign`
/// invocation, the distinct request signer, and the response verification are
/// handled generically by [`CarrierSigner`].
struct NatsCarrier {
    nats: async_nats::Client,
    subject: String,
}

impl SealedInvocationCarrier for NatsCarrier {
    type Error = anyhow::Error;

    async fn round_trip(&self, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let reply = self
            .nats
            .request(self.subject.clone(), request.to_vec().into())
            .await
            .context("bridge round trip over NATS")?;
        ensure_no_bridge_error(reply.headers.as_ref())?;
        Ok(reply.payload.to_vec())
    }
}

async fn public_key(client: &Arc<Mutex<Client>>, key_id: &str) -> anyhow::Result<Vec<u8>> {
    let mut client = client.lock().await;
    let response = client.get_public_key(key_id, None).await?;
    drop(client);
    if response.public_key.len() != 32 {
        bail!(
            "key {key_id} returned {} public-key bytes, expected 32",
            response.public_key.len()
        );
    }
    Ok(response.public_key)
}

fn verifier<'a>(
    keys: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> anyhow::Result<Ed25519Verifier> {
    let mut keys = keys.into_iter();
    let (first_id, first_public) = keys.next().context("at least one verifier key")?;
    let mut verifier = Ed25519Verifier::from_key(
        KeyId::from_text(first_id)?,
        &to_array(first_public, first_id)?,
    )
    .with_context(|| format!("pin verifier key {first_id}"))?;
    for (key_id, public) in keys {
        verifier
            .add_key(KeyId::from_text(key_id)?, &to_array(public, key_id)?)
            .with_context(|| format!("pin verifier key {key_id}"))?;
    }
    Ok(verifier)
}

fn to_array(bytes: &[u8], label: &str) -> anyhow::Result<[u8; 32]> {
    bytes
        .try_into()
        .with_context(|| format!("{label} was {} bytes, expected 32", bytes.len()))
}

fn now_unix() -> anyhow::Result<u32> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    u32::try_from(seconds).context("unix time does not fit u32")
}

fn ensure_no_bridge_error(headers: Option<&HeaderMap>) -> anyhow::Result<()> {
    let Some(headers) = headers else {
        return Ok(());
    };
    let Some(error) = headers.get("Basil-Bridge-Error") else {
        return Ok(());
    };
    let detail = headers
        .get("Basil-Bridge-Message")
        .map_or("", |value| value.as_str());
    bail!("bridge returned {}: {detail}", error.as_str());
}
