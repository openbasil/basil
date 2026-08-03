// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Job-scoped CI identity and typed local-adapter runtime.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use clap::{Args, Subcommand};
use ed25519_dalek::SigningKey;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore, watch};
use tokio::task::JoinSet;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

const TOKEN_REQUEST_URL_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
const TOKEN_REQUEST_TOKEN_ENV: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_TOKEN_BYTES: usize = 32 * 1024;
const MAX_CONTROL_BYTES: usize = 1_024;
const MAX_ADAPTER_BYTES: usize = 1024 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const RANDOM_NAME_ATTEMPTS: usize = 16;
const MAX_SESSION_CONNECTIONS: usize = 32;
const SESSION_OPERATION_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenResponse<'a> {
    value: &'a str,
}

#[derive(Deserialize)]
struct TimeClaims {
    iat: u64,
    exp: u64,
}

/// CI-specific commands.
#[derive(Debug, Subcommand)]
pub enum CiCommand {
    /// Run one job-scoped identity session.
    Session(SessionArgs),
}

/// Arguments for `basil ci session`.
#[derive(Clone, Debug, Args)]
pub struct SessionArgs {
    /// Absolute path to the reviewed Basil executable.
    #[arg(long)]
    pub basil_executable: PathBuf,
    /// Exact lowercase SHA-256 digest of the reviewed executable.
    #[arg(long)]
    pub basil_executable_sha256: String,
    /// Maximum token age configured on the matching federation rule.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=900))]
    pub rule_max_token_age_seconds: u64,
    /// Absolute directory in which to create the unique private session directory.
    #[arg(long)]
    pub runtime_parent: Option<PathBuf>,
}

/// Immutable configuration for one CI session.
#[derive(Clone, Debug)]
struct SessionConfig {
    /// Absolute path to the executable whose bytes the wrapper approved.
    pub basil_executable: PathBuf,
    /// Exact lowercase hexadecimal SHA-256 of the approved executable.
    pub basil_executable_sha256: String,
    /// Rule-bound maximum provider-token age.
    pub rule_max_token_age: Duration,
    /// Parent for the unique owner-only runtime directory.
    pub runtime_parent: PathBuf,
}

impl TryFrom<SessionArgs> for SessionConfig {
    type Error = anyhow::Error;

    fn try_from(args: SessionArgs) -> Result<Self> {
        let rule_max_token_age = Duration::from_secs(args.rule_max_token_age_seconds);
        if !(1..=900).contains(&rule_max_token_age.as_secs()) {
            bail!("rule maximum token age must be in 1..=900 seconds");
        }
        Ok(Self {
            basil_executable: args.basil_executable,
            basil_executable_sha256: args.basil_executable_sha256,
            rule_max_token_age,
            runtime_parent: args.runtime_parent.unwrap_or_else(std::env::temp_dir),
        })
    }
}

/// The four provider-neutral, non-secret outputs of a CI session.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
struct SessionOutputs {
    /// Absolute owner-only lifecycle socket path.
    pub session_control_socket: PathBuf,
    /// Registered typed-adapter names and their absolute socket paths.
    pub adapter_sockets: BTreeMap<String, PathBuf>,
    /// Unpadded base64url proof-key thumbprint.
    pub proof_jkt: String,
    /// Provider-token audience bound to `proof_jkt`.
    pub proof_audience: String,
}

/// Provider identity held only for the lifetime of one session.
struct SessionIdentity {
    _token: Zeroizing<String>,
    valid_until_unix: u64,
    proof: Arc<ProofIdentity>,
}

impl SessionIdentity {
    #[cfg(test)]
    fn proof_jkt(&self) -> &str {
        &self.proof.jkt
    }

    /// Return the exact key-bound provider audience.
    #[must_use]
    #[cfg(test)]
    fn proof_audience(&self) -> &str {
        &self.proof.audience
    }

    /// Return the effective token-validity boundary as Unix seconds.
    #[must_use]
    const fn valid_until_unix(&self) -> u64 {
        self.valid_until_unix
    }
}

/// A fresh response recipient consumed by one typed invocation.
struct EphemeralResponseKey {
    _secret: StaticSecret,
    #[cfg_attr(not(test), allow(dead_code))]
    public: X25519PublicKey,
}

impl EphemeralResponseKey {
    fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *bytes)
            .map_err(|error| anyhow!("generating invocation response key: {error}"))?;
        let secret = StaticSecret::from(*bytes);
        let public = X25519PublicKey::from(&secret);
        Ok(Self {
            _secret: secret,
            public,
        })
    }

    #[cfg(test)]
    fn public_bytes(&self) -> &[u8; 32] {
        self.public.as_bytes()
    }
}

/// Compile-time registration and dispatch contract for one typed adapter.
///
/// The session runtime deserializes only `Request` on the socket named by
/// `ADAPTER_NAME`; there is no runtime-selected operation or generic remote
/// invocation carrier.
trait TypedInvocationTransport: Send + Sync + 'static {
    /// Closed adapter name published in [`SessionOutputs::adapter_sockets`].
    const ADAPTER_NAME: &'static str;
    /// Whether this build registers the adapter socket.
    const REGISTERED: bool = true;
    /// Purpose-specific local request accepted by this adapter.
    type Request: Send + 'static;
    /// Purpose-specific local response returned by this adapter.
    type Response: Serialize + Send + Sync;

    /// Decode only this registered adapter's closed local protocol.
    fn decode_request(bytes: &[u8]) -> Result<Self::Request, ()>;

    /// Perform one invocation with the current identity and a fresh response key.
    fn invoke(
        &self,
        identity: Arc<SessionIdentity>,
        response_key: EphemeralResponseKey,
        request: Self::Request,
    ) -> impl Future<Output = Result<Self::Response>> + Send;
}

/// Fetches provider tokens for one stable proof audience.
trait IdentityTokenSource: Send + Sync + 'static {
    /// Fetch one provider JWT whose requested audience is `proof_audience`.
    fn fetch(&self, proof_audience: &str)
    -> impl Future<Output = Result<Zeroizing<String>>> + Send;
}

/// OIDC token source backed by the provider-injected Actions environment.
struct ActionsOidcTokenSource {
    request_url: Zeroizing<String>,
    request_token: Zeroizing<String>,
    client: reqwest::Client,
}

impl ActionsOidcTokenSource {
    /// Consume the provider request URL and bearer value from the process environment.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, non-Unicode, malformed, or unbounded inputs.
    fn from_environment() -> Result<Self> {
        let request_url = zeroizing_environment_value(TOKEN_REQUEST_URL_ENV)?;
        let request_token = zeroizing_environment_value(TOKEN_REQUEST_TOKEN_ENV)?;
        Self::new(request_url, request_token)
    }

    fn new(request_url: Zeroizing<String>, request_token: Zeroizing<String>) -> Result<Self> {
        if request_token.is_empty() || request_token.len() > MAX_TOKEN_BYTES {
            bail!("provider token-request bearer has an invalid length");
        }
        validate_token_request_url(&request_url)?;
        install_rustls_provider();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()
            .context("building provider token-request client")?;
        Ok(Self {
            request_url,
            request_token,
            client,
        })
    }

    async fn fetch_from_url(
        &self,
        base: &reqwest::Url,
        proof_audience: &str,
    ) -> Result<Zeroizing<String>> {
        let url = token_request_url(base, proof_audience)?;
        let response = self
            .client
            .get(url.clone())
            .bearer_auth(&*self.request_token)
            .send()
            .await
            .map_err(|_| anyhow!("provider identity request failed"))?;
        if response.url() != &url || !response.status().is_success() {
            bail!("provider identity request rejected");
        }
        let body = read_bounded_body(response, MAX_TOKEN_RESPONSE_BYTES).await?;
        let decoded: TokenResponse<'_> =
            serde_json::from_slice(&body).context("parsing provider identity response")?;
        if decoded.value.is_empty() || decoded.value.len() > MAX_TOKEN_BYTES {
            bail!("provider identity has an invalid length");
        }
        Ok(Zeroizing::new(decoded.value.to_owned()))
    }
}

impl IdentityTokenSource for ActionsOidcTokenSource {
    async fn fetch(&self, proof_audience: &str) -> Result<Zeroizing<String>> {
        let base = validate_token_request_url(&self.request_url)?;
        self.fetch_from_url(&base, proof_audience).await
    }
}

/// A prepared session whose outputs may be published before serving begins.
struct PreparedSession<T, S> {
    transport: Arc<T>,
    token_source: Arc<S>,
    identity: Arc<RwLock<Arc<SessionIdentity>>>,
    outputs: SessionOutputs,
    control_listener: SecureListener,
    adapter_listener: Option<SecureListener>,
    _executable_copy: PinnedFile,
    _runtime_directory: RuntimeDirectory,
    rule_max_token_age: Duration,
    connection_slots: Arc<Semaphore>,
    #[cfg(test)]
    task_set_high_water: Arc<TaskSetHighWater>,
}

#[cfg(test)]
#[derive(Default)]
struct TaskSetHighWater {
    maximum: AtomicUsize,
}

#[cfg(test)]
impl TaskSetHighWater {
    fn observe(&self, current: usize) {
        self.maximum
            .fetch_max(current, std::sync::atomic::Ordering::SeqCst);
    }

    fn load(&self) -> usize {
        self.maximum.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl<T, S> PreparedSession<T, S>
where
    T: TypedInvocationTransport,
    S: IdentityTokenSource,
{
    /// Return the four non-secret values safe for a workflow output channel.
    #[must_use]
    const fn outputs(&self) -> &SessionOutputs {
        &self.outputs
    }

    /// Serve lifecycle and registered typed-adapter sockets until shutdown or expiry.
    ///
    /// # Errors
    ///
    /// Returns an error when signal handling, token refresh, or a listener fails.
    async fn serve(self, mut signals: SessionSignals) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let mut tasks = JoinSet::new();
        let mut next_refresh = refresh_at(self.identity.read().await.valid_until_unix());
        let result = 'serving: loop {
            while let Some(completed) = tasks.try_join_next() {
                if let Err(error) = reclaim_session_task(completed) {
                    break 'serving Err(error);
                }
            }
            let expiry = self.identity.read().await.valid_until_unix();
            let refresh_sleep = tokio::time::sleep_until(unix_to_instant(next_refresh));
            let expiry_sleep = tokio::time::sleep_until(unix_to_instant(expiry));
            tokio::pin!(refresh_sleep, expiry_sleep);
            tokio::select! {
                accepted = self.control_listener.accept(), if tasks.len() < MAX_SESSION_CONNECTIONS => {
                    match accepted {
                        Ok(stream) => {
                            let deadline = tokio::time::Instant::now() + SESSION_OPERATION_DEADLINE;
                            if let Ok(permit) = Arc::clone(&self.connection_slots).try_acquire_owned() {
                                let shutdown = shutdown_tx.clone();
                                tasks.spawn(handle_control_bounded(stream, shutdown, permit, deadline));
                                #[cfg(test)]
                                self.task_set_high_water.observe(tasks.len());
                            }
                        }
                        Err(error) => break Err(error).context("accepting CI control connection"),
                    }
                }
                accepted = accept_adapter(self.adapter_listener.as_ref()), if tasks.len() < MAX_SESSION_CONNECTIONS => {
                    match accepted {
                        Ok(stream) => {
                            let deadline = tokio::time::Instant::now() + SESSION_OPERATION_DEADLINE;
                            if let Ok(permit) = Arc::clone(&self.connection_slots).try_acquire_owned() {
                                let transport = Arc::clone(&self.transport);
                                let identity = Arc::clone(&self.identity);
                                tasks.spawn(handle_adapter_bounded(
                                    stream,
                                    transport,
                                    identity,
                                    permit,
                                    deadline,
                                ));
                                #[cfg(test)]
                                self.task_set_high_water.observe(tasks.len());
                            }
                        }
                        Err(error) => break Err(error).context("accepting CI adapter connection"),
                    }
                }
                changed = shutdown_rx.changed() => {
                    match changed {
                        Ok(()) if *shutdown_rx.borrow() => break Ok(()),
                        Ok(()) => {}
                        Err(_) => break Ok(()),
                    }
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    match completed {
                        Some(completed) => {
                            if let Err(error) = reclaim_session_task(completed) {
                                break Err(error);
                            }
                        }
                        None => break Err(anyhow!("CI session task set closed unexpectedly")),
                    }
                }
                result = signals.wait() => break result,
                () = refresh_sleep => {
                    let refreshed = refresh_identity(
                        self.token_source.as_ref(),
                        &self.identity,
                        self.rule_max_token_age,
                    ).await;
                    if let Ok(valid_until) = refreshed {
                        next_refresh = refresh_at(valid_until);
                    } else {
                        let current_expiry = self.identity.read().await.valid_until_unix();
                        if unix_now()? >= current_expiry {
                            break Err(anyhow!("provider identity expired during refresh"));
                        }
                        next_refresh = unix_now()?.saturating_add(1).min(current_expiry);
                    }
                }
                () = expiry_sleep => {
                    if unix_now()? >= self.identity.read().await.valid_until_unix() {
                        break Err(anyhow!("provider identity expired"));
                    }
                }
            }
        };
        let _ = shutdown_tx.send(true);
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        drop(tasks);
        result
    }
}

/// Prepare a session with one statically registered typed adapter.
///
/// # Errors
///
/// Returns an error unless executable provenance, token acquisition, private
/// runtime creation, and socket publication all succeed.
async fn prepare_session<T, S>(
    config: SessionConfig,
    token_source: S,
    transport: T,
) -> Result<PreparedSession<T, S>>
where
    T: TypedInvocationTransport,
    S: IdentityTokenSource,
{
    validate_adapter::<T>()?;
    let runtime_directory = RuntimeDirectory::create(&config.runtime_parent)?;
    let executable_copy = verify_and_copy_executable(
        &config.basil_executable,
        &config.basil_executable_sha256,
        runtime_directory.path(),
    )?;
    let proof = Arc::new(ProofIdentity::generate()?);
    let token = token_source.fetch(&proof.audience).await?;
    let identity = Arc::new(SessionIdentity::new(
        token,
        config.rule_max_token_age,
        Arc::clone(&proof),
    )?);
    let control_path = runtime_directory.path().join("control.sock");
    let control_listener = SecureListener::bind(&control_path)?;
    let (adapter_listener, adapter_sockets) = if T::REGISTERED {
        let path = runtime_directory
            .path()
            .join(format!("{}.sock", T::ADAPTER_NAME));
        let listener = SecureListener::bind(&path)?;
        let mut adapters = BTreeMap::new();
        adapters.insert(T::ADAPTER_NAME.to_owned(), path);
        (Some(listener), adapters)
    } else {
        (None, BTreeMap::new())
    };
    let outputs = SessionOutputs {
        session_control_socket: control_path,
        adapter_sockets,
        proof_jkt: proof.jkt.clone(),
        proof_audience: proof.audience.clone(),
    };
    Ok(PreparedSession {
        transport: Arc::new(transport),
        token_source: Arc::new(token_source),
        identity: Arc::new(RwLock::new(identity)),
        outputs,
        control_listener,
        adapter_listener,
        _executable_copy: executable_copy,
        _runtime_directory: runtime_directory,
        rule_max_token_age: config.rule_max_token_age,
        connection_slots: Arc::new(Semaphore::new(MAX_SESSION_CONNECTIONS)),
        #[cfg(test)]
        task_set_high_water: Arc::new(TaskSetHighWater::default()),
    })
}

/// Run the production command with no authority-bearing adapter registered.
///
/// Consumer revisions bind a concrete [`TypedInvocationTransport`] in the
/// binary before advertising an adapter socket.
pub async fn run(args: SessionArgs) -> Result<()> {
    let mut signals = SessionSignals::register()?;
    let mut preparation = tokio::spawn(async move {
        let token_source = ActionsOidcTokenSource::from_environment()?;
        prepare_session(args.try_into()?, token_source, NoAdapter).await
    });
    let session = tokio::select! {
        biased;
        result = signals.wait() => {
            preparation.abort();
            let _ = preparation.await;
            return result;
        },
        result = &mut preparation => result.context("joining CI session preparation")??,
    };
    serde_json::to_writer(std::io::stdout().lock(), session.outputs())?;
    writeln!(std::io::stdout().lock())?;
    session.serve(signals).await
}

struct SessionSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl SessionSignals {
    fn register() -> Result<Self> {
        Ok(Self {
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .context("registering SIGINT handler")?,
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("registering SIGTERM handler")?,
        })
    }

    async fn wait(&mut self) -> Result<()> {
        tokio::select! {
            signal = self.interrupt.recv() => signal.map_or_else(
                || Err(anyhow!("SIGINT handler closed")),
                |()| Ok(()),
            ),
            signal = self.terminate.recv() => signal.map_or_else(
                || Err(anyhow!("SIGTERM handler closed")),
                |()| Ok(()),
            ),
        }
    }
}

struct NoAdapter;

enum NoAdapterRequest {}

impl TypedInvocationTransport for NoAdapter {
    const ADAPTER_NAME: &'static str = "none";
    const REGISTERED: bool = false;
    type Request = NoAdapterRequest;
    type Response = ();

    fn decode_request(_bytes: &[u8]) -> Result<Self::Request, ()> {
        Err(())
    }

    async fn invoke(
        &self,
        _identity: Arc<SessionIdentity>,
        _response_key: EphemeralResponseKey,
        request: Self::Request,
    ) -> Result<Self::Response> {
        match request {}
    }
}

struct ProofIdentity {
    _signing_key: SigningKey,
    jkt: String,
    audience: String,
}

impl ProofIdentity {
    fn generate() -> Result<Self> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *secret)
            .map_err(|error| anyhow!("generating CI proof key: {error}"))?;
        let signing_key = SigningKey::from_bytes(&secret);
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(signing_key.verifying_key().as_bytes());
        let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
        let digest = Sha256::digest(canonical.as_bytes());
        let jkt = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        let audience = format!("urn:basil:ci:jkt:{jkt}");
        Ok(Self {
            _signing_key: signing_key,
            jkt,
            audience,
        })
    }
}

impl SessionIdentity {
    fn new(
        token: Zeroizing<String>,
        maximum_age: Duration,
        proof: Arc<ProofIdentity>,
    ) -> Result<Self> {
        let valid_until_unix = effective_valid_until(&token, maximum_age)?;
        if valid_until_unix <= unix_now()? {
            bail!("provider identity is already outside its effective validity");
        }
        Ok(Self {
            _token: token,
            valid_until_unix,
            proof,
        })
    }
}

async fn refresh_identity<S: IdentityTokenSource>(
    source: &S,
    identity: &RwLock<Arc<SessionIdentity>>,
    maximum_age: Duration,
) -> Result<u64> {
    let proof = Arc::clone(&identity.read().await.proof);
    let token = source.fetch(&proof.audience).await?;
    let replacement = Arc::new(SessionIdentity::new(token, maximum_age, proof)?);
    let valid_until = replacement.valid_until_unix;
    *identity.write().await = replacement;
    Ok(valid_until)
}

fn effective_valid_until(token: &str, maximum_age: Duration) -> Result<u64> {
    let mut parts = token.split('.');
    let _header = parts
        .next()
        .ok_or_else(|| anyhow!("provider JWT is malformed"))?;
    let payload = parts
        .next()
        .ok_or_else(|| anyhow!("provider JWT is malformed"))?;
    let _signature = parts
        .next()
        .ok_or_else(|| anyhow!("provider JWT is malformed"))?;
    if parts.next().is_some() || payload.len() > MAX_TOKEN_BYTES {
        bail!("provider JWT is malformed");
    }
    let decoded = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| anyhow!("provider JWT payload is malformed"))?,
    );
    let claims: TimeClaims =
        serde_json::from_slice(&decoded).context("parsing provider JWT time claims")?;
    if claims.exp <= claims.iat {
        bail!("provider JWT has a non-positive validity span");
    }
    let age_bound = claims
        .iat
        .checked_add(maximum_age.as_secs())
        .ok_or_else(|| anyhow!("provider JWT time bound overflows"))?;
    Ok(claims.exp.min(age_bound))
}

fn validate_token_request_url(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).context("parsing provider token-request URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query_pairs().any(|(name, _)| name == "audience")
    {
        bail!("provider token-request URL violates the HTTPS audience contract");
    }
    Ok(url)
}

fn token_request_url(base: &reqwest::Url, proof_audience: &str) -> Result<reqwest::Url> {
    if proof_audience.is_empty() || !proof_audience.starts_with("urn:basil:ci:jkt:") {
        bail!("proof audience has an invalid shape");
    }
    let mut url = base.clone();
    url.query_pairs_mut()
        .append_pair("audience", proof_audience);
    let count = url
        .query_pairs()
        .filter(|(name, _)| name == "audience")
        .count();
    if count != 1 {
        bail!("provider token-request URL has an ambiguous audience");
    }
    Ok(url)
}

async fn read_bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("provider identity response is too large");
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .context("reading provider identity response")?
    {
        if chunk.len() > limit.saturating_sub(body.len()) {
            bail!("provider identity response is too large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn install_rustls_provider() {
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn validate_adapter<T: TypedInvocationTransport>() -> Result<()> {
    if !T::REGISTERED {
        return Ok(());
    }
    let valid = !T::ADAPTER_NAME.is_empty()
        && T::ADAPTER_NAME != "control"
        && T::ADAPTER_NAME
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid {
        bail!("typed CI adapter name is invalid");
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum ControlRequest {
    Status,
    Shutdown,
}

#[derive(Serialize)]
struct ControlResponse {
    status: &'static str,
}

async fn handle_control_bounded(
    mut stream: UnixStream,
    shutdown: watch::Sender<bool>,
    permit: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
) -> OwnedSemaphorePermit {
    if tokio::time::timeout_at(deadline, handle_control_inner(&mut stream, shutdown))
        .await
        .is_err()
    {
        let _ = stream.shutdown().await;
    }
    permit
}

async fn handle_control_inner(stream: &mut UnixStream, shutdown: watch::Sender<bool>) {
    if !same_uid(stream) {
        return;
    }
    let (response, should_shutdown) = match read_control_frame(stream).await {
        Ok(ControlRequest::Status) => (ControlResponse { status: "running" }, false),
        Ok(ControlRequest::Shutdown) => (
            ControlResponse {
                status: "shutting-down",
            },
            true,
        ),
        Err(()) => (ControlResponse { status: "rejected" }, false),
    };
    let _ = write_frame(stream, &response, MAX_CONTROL_BYTES).await;
    if should_shutdown {
        let _ = shutdown.send(true);
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
enum AdapterResponse<T> {
    Ok { value: T },
    Rejected,
}

async fn handle_adapter_bounded<T: TypedInvocationTransport>(
    mut stream: UnixStream,
    transport: Arc<T>,
    identity: Arc<RwLock<Arc<SessionIdentity>>>,
    permit: OwnedSemaphorePermit,
    deadline: tokio::time::Instant,
) -> OwnedSemaphorePermit {
    if tokio::time::timeout_at(
        deadline,
        handle_adapter_inner(&mut stream, transport, identity, deadline),
    )
    .await
    .is_err()
    {
        let _ = stream.shutdown().await;
    }
    permit
}

fn reclaim_session_task(
    completed: std::result::Result<OwnedSemaphorePermit, tokio::task::JoinError>,
) -> Result<()> {
    let permit = completed.context("joining CI session connection task")?;
    drop(permit);
    Ok(())
}

async fn handle_adapter_inner<T: TypedInvocationTransport>(
    stream: &mut UnixStream,
    transport: Arc<T>,
    identity: Arc<RwLock<Arc<SessionIdentity>>>,
    connection_deadline: tokio::time::Instant,
) {
    if !same_uid(stream) {
        return;
    }
    let Ok(body) = read_frame_bytes(stream, MAX_ADAPTER_BYTES).await else {
        let _ = write_frame(stream, &AdapterResponse::<()>::Rejected, MAX_ADAPTER_BYTES).await;
        return;
    };
    let Ok(request) = T::decode_request(&body) else {
        let _ = write_frame(stream, &AdapterResponse::<()>::Rejected, MAX_ADAPTER_BYTES).await;
        return;
    };
    let current = {
        let guard = identity.read().await;
        Arc::clone(&guard)
    };
    let valid_until = current.valid_until_unix();
    let response = match EphemeralResponseKey::generate() {
        Ok(response_key) => {
            match enforce_invocation_deadline(
                connection_deadline,
                valid_until,
                transport.invoke(current, response_key, request),
            )
            .await
            {
                Ok(value) => AdapterResponse::Ok { value },
                Err(()) => AdapterResponse::Rejected,
            }
        }
        Err(_) => AdapterResponse::Rejected,
    };
    let _ = write_frame(stream, &response, MAX_ADAPTER_BYTES).await;
}

async fn enforce_invocation_deadline<F, R>(
    connection_deadline: tokio::time::Instant,
    valid_until: u64,
    invocation: F,
) -> Result<R, ()>
where
    F: Future<Output = Result<R>>,
{
    if !identity_is_valid(valid_until) {
        return Err(());
    }
    let identity_deadline = unix_deadline(valid_until).map_err(|_| ())?;
    let deadline = connection_deadline.min(identity_deadline);
    match tokio::time::timeout_at(deadline, invocation).await {
        Ok(Ok(value)) if identity_is_valid(valid_until) => Ok(value),
        Ok(Ok(_) | Err(_)) | Err(_) => Err(()),
    }
}

async fn read_frame_bytes(stream: &mut UnixStream, limit: usize) -> Result<Zeroizing<Vec<u8>>, ()> {
    let length = stream.read_u32().await.map_err(|_| ())? as usize;
    if length == 0 || length > limit {
        return Err(());
    }
    let mut body = Zeroizing::new(vec![0_u8; length]);
    stream.read_exact(&mut body).await.map_err(|_| ())?;
    Ok(body)
}

async fn read_control_frame(stream: &mut UnixStream) -> Result<ControlRequest, ()> {
    let body = read_frame_bytes(stream, MAX_CONTROL_BYTES).await?;
    serde_json::from_slice(&body).map_err(|_| ())
}

async fn write_frame<T: Serialize + Sync>(
    stream: &mut UnixStream,
    value: &T,
    limit: usize,
) -> Result<(), ()> {
    let body = Zeroizing::new(serde_json::to_vec(value).map_err(|_| ())?);
    if body.is_empty() || body.len() > limit || body.len() > u32::MAX as usize {
        return Err(());
    }
    stream
        .write_u32(u32::try_from(body.len()).map_err(|_| ())?)
        .await
        .map_err(|_| ())?;
    stream.write_all(&body).await.map_err(|_| ())?;
    stream.shutdown().await.map_err(|_| ())
}

async fn accept_adapter(listener: Option<&SecureListener>) -> std::io::Result<UnixStream> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

fn same_uid(stream: &UnixStream) -> bool {
    stream.peer_cred().is_ok_and(|credentials| {
        peer_uid_is_authorized(credentials.uid(), rustix::process::geteuid().as_raw())
    })
}

const fn peer_uid_is_authorized(peer_uid: u32, effective_uid: u32) -> bool {
    peer_uid == effective_uid
}

fn identity_is_valid(valid_until: u64) -> bool {
    unix_now().is_ok_and(|now| now < valid_until)
}

fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .context("system clock is before the Unix epoch")
}

fn refresh_at(valid_until: u64) -> u64 {
    let now = unix_now().unwrap_or(valid_until);
    let remaining = valid_until.saturating_sub(now);
    valid_until
        .saturating_sub((remaining / 5).clamp(1, 30))
        .max(now.saturating_add(1).min(valid_until))
}

fn zeroizing_environment_value(name: &str) -> Result<Zeroizing<String>> {
    let value =
        std::env::var_os(name).ok_or_else(|| anyhow!("environment value {name} is absent"))?;
    let bytes = Zeroizing::new(value.into_vec());
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow!("environment value {name} is not UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn unix_to_instant(unix: u64) -> tokio::time::Instant {
    let now_unix = unix_now().unwrap_or(unix);
    tokio::time::Instant::now() + Duration::from_secs(unix.saturating_sub(now_unix))
}

fn unix_deadline(unix: u64) -> Result<tokio::time::Instant> {
    let target = UNIX_EPOCH
        .checked_add(Duration::from_secs(unix))
        .ok_or_else(|| anyhow!("provider identity deadline overflows"))?;
    let remaining = target
        .duration_since(SystemTime::now())
        .context("provider identity is expired")?;
    Ok(tokio::time::Instant::now() + remaining)
}

#[derive(Debug)]
struct RuntimeDirectory {
    path: PathBuf,
    parent: OwnedFd,
    name: OsString,
    binding: OwnedFd,
}

impl RuntimeDirectory {
    fn create(parent: &Path) -> Result<Self> {
        if !parent.is_absolute() {
            bail!("CI runtime parent must be absolute");
        }
        let parent_fd = open_directory_without_symlinks(parent)?;
        for _ in 0..RANDOM_NAME_ATTEMPTS {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random)
                .map_err(|error| anyhow!("generating CI runtime directory name: {error}"))?;
            let name = OsString::from(format!("basil-ci-{}", hex::encode(random)));
            let path = parent.join(&name);
            match rustix::fs::mkdirat(&parent_fd, &name, Mode::from_bits_truncate(0o700)) {
                Ok(()) => {
                    let binding = rustix::fs::openat(
                        &parent_fd,
                        &name,
                        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
                        Mode::empty(),
                    )?;
                    let candidate = Self {
                        path,
                        parent: parent_fd,
                        name,
                        binding,
                    };
                    rustix::fs::fchmod(&candidate.binding, Mode::from_bits_truncate(0o700))?;
                    let stat = rustix::fs::fstat(&candidate.binding)?;
                    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
                        || stat.st_uid != rustix::process::geteuid().as_raw()
                        || stat.st_mode & 0o7777 != 0o700
                    {
                        bail!("CI runtime directory is not owner-only");
                    }
                    return Ok(candidate);
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error).context("creating CI runtime directory"),
            }
        }
        bail!("could not allocate a unique CI runtime directory")
    }

    const fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        let Ok(bound) = rustix::fs::fstat(&self.binding) else {
            return;
        };
        let Ok(current) = rustix::fs::statat(&self.parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)
        else {
            return;
        };
        if FileType::from_raw_mode(bound.st_mode) == FileType::Directory
            && FileType::from_raw_mode(current.st_mode) == FileType::Directory
            && bound.st_dev == current.st_dev
            && bound.st_ino == current.st_ino
            && current.st_uid == rustix::process::geteuid().as_raw()
        {
            let _ = rustix::fs::unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR);
        }
    }
}

#[derive(Debug)]
struct PinnedFile {
    parent: OwnedFd,
    name: OsString,
    binding: OwnedFd,
}

impl Drop for PinnedFile {
    fn drop(&mut self) {
        remove_pinned_path(
            &self.parent,
            &self.name,
            &self.binding,
            FileType::RegularFile,
        );
    }
}

fn verify_and_copy_executable(source: &Path, expected: &str, runtime: &Path) -> Result<PinnedFile> {
    if !source.is_absolute()
        || expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("Basil executable provenance requires an absolute path and lowercase SHA-256");
    }
    let source_fd = rustix::fs::open(
        source,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .context("opening reviewed Basil executable")?;
    let source_stat = rustix::fs::fstat(&source_fd)?;
    if FileType::from_raw_mode(source_stat.st_mode) != FileType::RegularFile
        || source_stat.st_mode & 0o111 == 0
        || source_stat.st_mode & 0o022 != 0
    {
        bail!("reviewed Basil path is not a non-writable regular executable");
    }
    let mut source_file = std::fs::File::from(source_fd);
    let actual = hash_reader(&mut source_file)?;
    if actual != expected {
        bail!("reviewed Basil executable digest does not match");
    }
    source_file.seek(SeekFrom::Start(0))?;
    let parent = open_directory_without_symlinks(runtime)?;
    let name = OsString::from("basil");
    let binding = rustix::fs::openat(
        &parent,
        &name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o500),
    )
    .context("creating verified Basil executable copy")?;
    let mut pinned = PinnedFile {
        parent,
        name,
        binding,
    };
    let mut destination_file = std::fs::File::from(pinned.binding.try_clone()?);
    std::io::copy(&mut source_file, &mut destination_file)
        .context("copying reviewed Basil executable")?;
    destination_file.sync_all()?;
    drop(destination_file);
    rustix::fs::fchmod(&pinned.binding, Mode::from_bits_truncate(0o500))?;
    let copied = rustix::fs::fstat(&pinned.binding)?;
    if FileType::from_raw_mode(copied.st_mode) != FileType::RegularFile
        || copied.st_uid != rustix::process::geteuid().as_raw()
        || copied.st_mode & 0o7777 != 0o500
    {
        bail!("verified Basil executable copy has unsafe metadata");
    }
    let read_only = rustix::fs::openat(
        &pinned.parent,
        &pinned.name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let reopened = rustix::fs::fstat(&read_only)?;
    if copied.st_dev != reopened.st_dev || copied.st_ino != reopened.st_ino {
        bail!("verified Basil executable copy was replaced");
    }
    pinned.binding = read_only;
    let mut verify = std::fs::File::from(pinned.binding.try_clone()?);
    verify.seek(SeekFrom::Start(0))?;
    if hash_reader(&mut verify)? != expected {
        bail!("verified Basil executable copy digest does not match");
    }
    Ok(pinned)
}

fn hash_reader(reader: &mut std::fs::File) -> Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = Zeroizing::new([0_u8; 8 * 1024]);
    loop {
        let read = reader.read(&mut *buffer)?;
        if read == 0 {
            break;
        }
        hash.update(
            buffer
                .get(..read)
                .ok_or_else(|| anyhow!("invalid read length"))?,
        );
    }
    Ok(hex::encode(hash.finalize()))
}

#[derive(Debug)]
struct SecureListener {
    inner: UnixListener,
    parent: OwnedFd,
    name: OsString,
    binding: OwnedFd,
}

impl SecureListener {
    fn bind(path: &Path) -> Result<Self> {
        let parent_path = path
            .parent()
            .ok_or_else(|| anyhow!("CI socket path has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("CI socket path has no file name"))?;
        let parent = open_directory_without_symlinks(parent_path)?;
        let parent_stat = rustix::fs::fstat(&parent)?;
        if parent_stat.st_uid != rustix::process::geteuid().as_raw()
            || parent_stat.st_mode & 0o7777 != 0o700
        {
            bail!("CI socket parent is not owner-only");
        }
        let fd = rustix::net::socket_with(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
            None,
        )?;
        rustix::net::bind(&fd, &rustix::net::SocketAddrUnix::new(path)?)?;
        // Without a descriptor there is no race-free way to prove that a
        // pathname still names the socket just bound. Leave it in the
        // private runtime directory instead of unlinking a replacement.
        let binding = rustix::fs::openat(
            &parent,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        if let Err(error) = rustix::fs::chmodat(
            &parent,
            name,
            Mode::from_bits_truncate(0o600),
            AtFlags::empty(),
        ) {
            remove_pinned_path(&parent, name, &binding, FileType::Socket);
            return Err(error.into());
        }
        let stat = match rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(error) => {
                remove_pinned_path(&parent, name, &binding, FileType::Socket);
                return Err(error.into());
            }
        };
        let pinned = rustix::fs::fstat(&binding)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_dev != pinned.st_dev
            || stat.st_ino != pinned.st_ino
        {
            remove_pinned_path(&parent, name, &binding, FileType::Socket);
            bail!("CI socket publication was replaced");
        }
        if let Err(error) = rustix::net::listen(&fd, 32) {
            remove_pinned_path(&parent, name, &binding, FileType::Socket);
            return Err(error.into());
        }
        let listener = StdUnixListener::from(fd);
        let inner = match UnixListener::from_std(listener) {
            Ok(inner) => inner,
            Err(error) => {
                remove_pinned_path(&parent, name, &binding, FileType::Socket);
                return Err(error.into());
            }
        };
        Ok(Self {
            inner,
            parent,
            name: name.to_os_string(),
            binding,
        })
    }

    async fn accept(&self) -> std::io::Result<UnixStream> {
        self.inner.accept().await.map(|(stream, _)| stream)
    }
}

impl Drop for SecureListener {
    fn drop(&mut self) {
        remove_pinned_path(&self.parent, &self.name, &self.binding, FileType::Socket);
    }
}

fn remove_pinned_path(parent: &OwnedFd, name: &OsStr, binding: &OwnedFd, expected_type: FileType) {
    let Ok(bound) = rustix::fs::fstat(binding) else {
        return;
    };
    let Ok(current) = rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return;
    };
    if FileType::from_raw_mode(bound.st_mode) == expected_type
        && FileType::from_raw_mode(current.st_mode) == expected_type
        && current.st_dev == bound.st_dev
        && current.st_ino == bound.st_ino
        && current.st_uid == rustix::process::geteuid().as_raw()
    {
        let _ = rustix::fs::unlinkat(parent, name, AtFlags::empty());
    }
}

fn open_directory_without_symlinks(path: &Path) -> Result<OwnedFd> {
    if !path.is_absolute() {
        bail!("path must be absolute");
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        bail!("path must begin at the filesystem root");
    }
    let mut directory = rustix::fs::open(
        "/",
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
        Mode::empty(),
    )?;
    for component in components {
        let Component::Normal(name) = component else {
            bail!("path contains an unsupported component");
        };
        directory = rustix::fs::openat(
            &directory,
            name,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::RDONLY,
            Mode::empty(),
        )?;
    }
    Ok(directory)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, mpsc};

    use serde_json::json;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;

    fn jwt(iat: u64, exp: u64, marker: &str) -> Zeroizing<String> {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"iat": iat, "exp": exp, "m": marker})).unwrap());
        Zeroizing::new(format!("e30.{payload}.signature"))
    }

    async fn read_test_frame(
        stream: &mut UnixStream,
        limit: usize,
    ) -> Result<serde_json::Value, ()> {
        let body = read_frame_bytes(stream, limit).await?;
        serde_json::from_slice(&body).map_err(|_| ())
    }

    async fn connect_during_flood(path: &Path) -> UnixStream {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match UnixStream::connect(path).await {
                    Ok(stream) => return stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("connecting flood client: {error}"),
                }
            }
        })
        .await
        .unwrap()
    }

    async fn raw_http_server(
        response: Vec<u8>,
    ) -> (
        reqwest::Url,
        oneshot::Receiver<Zeroizing<Vec<u8>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (request_tx, request_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Zeroizing::new(Vec::new());
            let mut buffer = Zeroizing::new([0_u8; 1_024]);
            loop {
                let read = stream.read(&mut *buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() <= 16 * 1_024);
            }
            let _ = request_tx.send(request);
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        (
            reqwest::Url::parse(&format!("http://{address}/token?job=1")).unwrap(),
            request_rx,
            task,
        )
    }

    fn http_response(status: &str, body: &[u8]) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect()
    }

    fn chunked_http_response(chunks: &[Vec<u8>]) -> Vec<u8> {
        let mut response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for chunk in chunks {
            response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            response.extend_from_slice(chunk);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        response
    }

    fn test_oidc_source(secret: &str) -> ActionsOidcTokenSource {
        ActionsOidcTokenSource::new(
            Zeroizing::new("https://issuer.example/token".to_owned()),
            Zeroizing::new(secret.to_owned()),
        )
        .unwrap()
    }

    #[test]
    fn audience_query_is_exact_and_encoded_once() {
        let base = validate_token_request_url("https://issuer.example/token?job=1").unwrap();
        let url = token_request_url(&base, "urn:basil:ci:jkt:a/b+").unwrap();
        assert_eq!(
            url.as_str(),
            "https://issuer.example/token?job=1&audience=urn%3Abasil%3Aci%3Ajkt%3Aa%2Fb%2B"
        );
        for rejected in [
            "http://issuer.example/token",
            "https://issuer.example/token?audience=old",
            "https://issuer.example/token?aud%69ence=old",
            "https://user@issuer.example/token",
            "https://issuer.example/token#fragment",
        ] {
            assert!(validate_token_request_url(rejected).is_err(), "{rejected}");
        }
    }

    #[tokio::test]
    async fn provider_http_is_bounded_strict_non_redirecting_and_secret_safe() {
        let bearer = "request-bearer-secret";
        let source = test_oidc_source(bearer);
        let provider_token = "provider-token-secret";
        let body = serde_json::to_vec(&json!({"value": provider_token})).unwrap();
        let (url, request, server) = raw_http_server(http_response("200 OK", &body)).await;
        let fetched = source
            .fetch_from_url(&url, "urn:basil:ci:jkt:test")
            .await
            .unwrap();
        assert_eq!(&*fetched, provider_token);
        let request = request.await.unwrap();
        assert!(
            request
                .windows(bearer.len())
                .any(|part| part == bearer.as_bytes())
        );
        assert!(
            request
                .windows(b"audience=urn%3Abasil%3Aci%3Ajkt%3Atest".len())
                .any(|part| part == b"audience=urn%3Abasil%3Aci%3Ajkt%3Atest")
        );
        server.await.unwrap();

        let redirect_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = redirect_target.local_addr().unwrap();
        let redirect = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/stolen\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let (url, _request, server) = raw_http_server(redirect).await;
        let error = source
            .fetch_from_url(&url, "urn:basil:ci:jkt:test")
            .await
            .unwrap_err();
        assert!(!format!("{error:#}").contains(bearer));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), redirect_target.accept())
                .await
                .is_err()
        );
        server.await.unwrap();

        for response in [
            http_response(
                "200 OK",
                br#"{"value":"provider-token-secret","unexpected":true}"#,
            ),
            b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n{".to_vec(),
        ] {
            let (url, _request, server) = raw_http_server(response).await;
            let error = source
                .fetch_from_url(&url, "urn:basil:ci:jkt:test")
                .await
                .unwrap_err();
            let message = format!("{error:#}");
            assert!(!message.contains(bearer));
            assert!(!message.contains(provider_token));
            server.await.unwrap();
        }

        let response =
            chunked_http_response(&[vec![b'a'; MAX_TOKEN_RESPONSE_BYTES], vec![b'b'; 1]]);
        let (url, _request, server) = raw_http_server(response).await;
        let error = source
            .fetch_from_url(&url, "urn:basil:ci:jkt:test")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("too large"));
        server.await.unwrap();

        let mut response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        response.extend(std::iter::repeat_n(b'x', MAX_TOKEN_RESPONSE_BYTES + 1));
        let (url, _request, server) = raw_http_server(response).await;
        let error = source
            .fetch_from_url(&url, "urn:basil:ci:jkt:test")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("too large"));
        server.await.unwrap();
    }

    #[test]
    fn effective_validity_is_minimum_of_expiry_and_rule_age() {
        assert_eq!(
            effective_valid_until(&jwt(100, 1_000, "a"), Duration::from_secs(90)).unwrap(),
            190
        );
        assert_eq!(
            effective_valid_until(&jwt(100, 150, "b"), Duration::from_secs(90)).unwrap(),
            150
        );
        assert!(effective_valid_until(&jwt(100, 100, "c"), Duration::from_secs(90)).is_err());
    }

    #[test]
    fn proof_is_stable_while_response_keys_are_fresh() {
        let proof = Arc::new(ProofIdentity::generate().unwrap());
        let now = unix_now().unwrap();
        let first = SessionIdentity::new(
            jwt(now, now + 100, "first"),
            Duration::from_secs(90),
            Arc::clone(&proof),
        )
        .unwrap();
        let second = SessionIdentity::new(
            jwt(now + 1, now + 101, "second"),
            Duration::from_secs(90),
            Arc::clone(&proof),
        )
        .unwrap();
        assert_eq!(first.proof_jkt(), second.proof_jkt());
        assert_eq!(first.proof_audience(), second.proof_audience());
        let mut publics = std::collections::BTreeSet::new();
        for _ in 0..64 {
            assert!(publics.insert(*EphemeralResponseKey::generate().unwrap().public_bytes()));
        }
    }

    enum FetchResult {
        Token(Zeroizing<String>),
        Failure,
    }

    struct SequenceSource {
        results: Mutex<VecDeque<FetchResult>>,
    }

    impl IdentityTokenSource for SequenceSource {
        async fn fetch(&self, _proof_audience: &str) -> Result<Zeroizing<String>> {
            let result = self.results.lock().unwrap().pop_front().unwrap();
            match result {
                FetchResult::Token(token) => Ok(token),
                FetchResult::Failure => bail!("synthetic provider failure"),
            }
        }
    }

    #[tokio::test]
    async fn refresh_keeps_proof_and_retains_current_identity_on_failure() {
        let proof = Arc::new(ProofIdentity::generate().unwrap());
        let now = unix_now().unwrap();
        let initial = Arc::new(
            SessionIdentity::new(
                jwt(now, now + 120, "initial"),
                Duration::from_secs(90),
                Arc::clone(&proof),
            )
            .unwrap(),
        );
        let identity = RwLock::new(Arc::clone(&initial));
        let source = SequenceSource {
            results: Mutex::new(VecDeque::from([
                FetchResult::Token(jwt(now + 1, now + 121, "replacement")),
                FetchResult::Failure,
            ])),
        };
        refresh_identity(&source, &identity, Duration::from_secs(90))
            .await
            .unwrap();
        let refreshed = Arc::clone(&*identity.read().await);
        assert!(Arc::ptr_eq(&refreshed.proof, &proof));
        assert!(!Arc::ptr_eq(&refreshed, &initial));
        assert!(
            refresh_identity(&source, &identity, Duration::from_secs(90))
                .await
                .is_err()
        );
        assert!(Arc::ptr_eq(&*identity.read().await, &refreshed));
    }

    struct InitialThenFailureSource {
        initial: Mutex<Option<Zeroizing<String>>>,
        attempts: Arc<AtomicUsize>,
    }

    impl IdentityTokenSource for InitialThenFailureSource {
        async fn fetch(&self, _proof_audience: &str) -> Result<Zeroizing<String>> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let token = self.initial.lock().unwrap().take();
            token.ok_or_else(|| anyhow!("synthetic provider refresh failure"))
        }
    }

    #[tokio::test]
    async fn serving_retries_failed_refresh_and_cleans_up_at_expiry() {
        let root = test_directory("refresh-expiry");
        let source = root.join("source");
        std::fs::write(&source, b"binary").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500)).unwrap();
        let now = unix_now().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let session = prepare_session(
            SessionConfig {
                basil_executable: source.clone(),
                basil_executable_sha256: hex::encode(Sha256::digest(b"binary")),
                rule_max_token_age: Duration::from_secs(4),
                runtime_parent: root.clone(),
            },
            InitialThenFailureSource {
                initial: Mutex::new(Some(jwt(now, now + 4, "refresh-expiry"))),
                attempts: Arc::clone(&attempts),
            },
            NoAdapter,
        )
        .await
        .unwrap();
        let runtime_path = session
            .outputs()
            .session_control_socket
            .parent()
            .unwrap()
            .to_path_buf();
        let task = tokio::spawn(session.serve(SessionSignals::register().unwrap()));
        tokio::time::timeout(Duration::from_secs(5), async {
            while attempts.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!task.is_finished());
        let error = tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("expired"));
        assert!(!runtime_path.exists());
        std::fs::remove_file(source).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[tokio::test]
    async fn invocation_is_cancelled_at_captured_identity_expiry() {
        let valid_until = unix_now().unwrap() + 1;
        let completed = Arc::new(AtomicBool::new(false));
        let completed_in_future = Arc::clone(&completed);
        let result = enforce_invocation_deadline(
            tokio::time::Instant::now() + Duration::from_secs(3),
            valid_until,
            async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                completed_in_future.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err());
        assert!(!completed.load(Ordering::SeqCst));
        assert!(!identity_is_valid(valid_until));
    }

    #[test]
    fn peer_uid_policy_accepts_only_the_effective_uid() {
        let effective = rustix::process::geteuid().as_raw();
        assert!(peer_uid_is_authorized(effective, effective));
        assert!(!peer_uid_is_authorized(
            effective.wrapping_add(1),
            effective
        ));
    }

    #[test]
    fn executable_copy_is_exact_and_cleanup_is_replacement_safe() {
        let root = test_directory("copy");
        let source = root.join("source");
        std::fs::write(&source, b"reviewed executable bytes").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500)).unwrap();
        let digest = hex::encode(Sha256::digest(b"reviewed executable bytes"));
        let runtime = RuntimeDirectory::create(&root).unwrap();
        let copy = verify_and_copy_executable(&source, &digest, runtime.path()).unwrap();
        let copied_path = runtime.path().join("basil");
        assert_eq!(
            std::fs::read(&copied_path).unwrap(),
            b"reviewed executable bytes"
        );
        assert_eq!(
            std::fs::metadata(&copied_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o500
        );
        std::fs::remove_file(&copied_path).unwrap();
        std::fs::write(&copied_path, b"replacement").unwrap();
        drop(copy);
        assert_eq!(std::fs::read(&copied_path).unwrap(), b"replacement");
        std::fs::remove_file(&copied_path).unwrap();
        let runtime_path = runtime.path().clone();
        drop(runtime);
        assert!(!runtime_path.exists());
        std::fs::remove_file(source).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[tokio::test]
    async fn socket_and_runtime_cleanup_preserve_path_replacements() {
        let root = test_directory("replacement");
        let runtime = RuntimeDirectory::create(&root).unwrap();
        let runtime_path = runtime.path().clone();
        let socket_path = runtime_path.join("control.sock");
        let listener = SecureListener::bind(&socket_path).unwrap();
        std::fs::remove_file(&socket_path).unwrap();
        std::fs::write(&socket_path, b"replacement socket path").unwrap();
        drop(listener);
        assert_eq!(
            std::fs::read(&socket_path).unwrap(),
            b"replacement socket path"
        );
        std::fs::remove_file(&socket_path).unwrap();

        let original_path = root.join("original-runtime");
        std::fs::rename(&runtime_path, &original_path).unwrap();
        std::fs::create_dir(&runtime_path).unwrap();
        std::fs::set_permissions(&runtime_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(runtime);
        assert!(runtime_path.is_dir());
        std::fs::remove_dir(runtime_path).unwrap();
        std::fs::remove_dir(original_path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn executable_provenance_rejects_mutable_and_wrong_bytes() {
        let root = test_directory("provenance");
        let source = root.join("source");
        std::fs::write(&source, b"bytes").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o720)).unwrap();
        let runtime = RuntimeDirectory::create(&root).unwrap();
        let digest = hex::encode(Sha256::digest(b"bytes"));
        assert!(verify_and_copy_executable(&source, &digest, runtime.path()).is_err());
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(verify_and_copy_executable(&source, &"0".repeat(64), runtime.path()).is_err());
        drop(runtime);
        std::fs::remove_file(source).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[derive(Clone)]
    struct StaticSource {
        token: Arc<Mutex<Zeroizing<String>>>,
    }

    impl IdentityTokenSource for StaticSource {
        async fn fetch(&self, _proof_audience: &str) -> Result<Zeroizing<String>> {
            Ok(Zeroizing::new(self.token.lock().unwrap().to_string()))
        }
    }

    #[tokio::test]
    async fn control_shutdown_cleans_all_session_paths_and_outputs_have_no_secrets() {
        let root = test_directory("process");
        let source = root.join("source");
        std::fs::write(&source, b"binary").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500)).unwrap();
        let digest = hex::encode(Sha256::digest(b"binary"));
        let now = unix_now().unwrap();
        let secret_marker = "secret-provider-token";
        let provider_token = jwt(now, now + 100, secret_marker);
        let provider_token_text = provider_token.to_string();
        let session = prepare_session(
            SessionConfig {
                basil_executable: source.clone(),
                basil_executable_sha256: digest,
                rule_max_token_age: Duration::from_secs(90),
                runtime_parent: root.clone(),
            },
            StaticSource {
                token: Arc::new(Mutex::new(provider_token)),
            },
            NoAdapter,
        )
        .await
        .unwrap();
        let outputs = session.outputs().clone();
        let encoded = serde_json::to_string(&outputs).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded)
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            4
        );
        assert!(!encoded.contains(secret_marker));
        assert!(!encoded.contains(&provider_token_text));
        assert!(outputs.adapter_sockets.is_empty());
        let runtime = outputs
            .session_control_socket
            .parent()
            .unwrap()
            .to_path_buf();
        let task = tokio::spawn(session.serve(SessionSignals::register().unwrap()));
        let mut rejected = UnixStream::connect(&outputs.session_control_socket)
            .await
            .unwrap();
        write_frame(
            &mut rejected,
            &json!({"operation": "invoke", "request": {"operation": "sign"}}),
            MAX_CONTROL_BYTES,
        )
        .await
        .unwrap();
        let response: serde_json::Value = read_test_frame(&mut rejected, MAX_CONTROL_BYTES)
            .await
            .unwrap();
        assert_eq!(response["status"], "rejected");

        let mut status = UnixStream::connect(&outputs.session_control_socket)
            .await
            .unwrap();
        write_frame(
            &mut status,
            &json!({"operation": "status"}),
            MAX_CONTROL_BYTES,
        )
        .await
        .unwrap();
        let response: serde_json::Value = read_test_frame(&mut status, MAX_CONTROL_BYTES)
            .await
            .unwrap();
        assert_eq!(response["status"], "running");

        let mut control = UnixStream::connect(&outputs.session_control_socket)
            .await
            .unwrap();
        write_frame(
            &mut control,
            &json!({"operation": "shutdown"}),
            MAX_CONTROL_BYTES,
        )
        .await
        .unwrap();
        let response: serde_json::Value = read_test_frame(&mut control, MAX_CONTROL_BYTES)
            .await
            .unwrap();
        assert_eq!(response["status"], "shutting-down");
        task.await.unwrap().unwrap();
        assert!(!runtime.exists());
        std::fs::remove_file(source).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[tokio::test]
    async fn stalled_and_flooded_connections_are_bounded_and_reclaimed() {
        let root = test_directory("admission");
        let source = root.join("source");
        std::fs::write(&source, b"binary").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o500)).unwrap();
        let now = unix_now().unwrap();
        let session = prepare_session(
            SessionConfig {
                basil_executable: source.clone(),
                basil_executable_sha256: hex::encode(Sha256::digest(b"binary")),
                rule_max_token_age: Duration::from_secs(90),
                runtime_parent: root.clone(),
            },
            StaticSource {
                token: Arc::new(Mutex::new(jwt(now, now + 100, "admission"))),
            },
            NoAdapter,
        )
        .await
        .unwrap();
        let control_path = session.outputs().session_control_socket.clone();
        let high_water = Arc::clone(&session.task_set_high_water);
        let task = tokio::spawn(session.serve(SessionSignals::register().unwrap()));

        let mut stalled = Vec::new();
        for _ in 0..MAX_SESSION_CONNECTIONS {
            stalled.push(UnixStream::connect(&control_path).await.unwrap());
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while high_water.load() < MAX_SESSION_CONNECTIONS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(high_water.load(), MAX_SESSION_CONNECTIONS);
        drop(stalled);

        let flooders = MAX_SESSION_CONNECTIONS * 2;
        let start = Arc::new(tokio::sync::Barrier::new(flooders + 1));
        let mut clients = Vec::new();
        for _ in 0..flooders {
            let path = control_path.clone();
            let start = Arc::clone(&start);
            clients.push(tokio::spawn(async move {
                start.wait().await;
                for _ in 0..8 {
                    let mut stream = connect_during_flood(&path).await;
                    write_frame(
                        &mut stream,
                        &json!({"operation": "status"}),
                        MAX_CONTROL_BYTES,
                    )
                    .await
                    .unwrap();
                    let response = read_test_frame(&mut stream, MAX_CONTROL_BYTES)
                        .await
                        .unwrap();
                    assert_eq!(response["status"], "running");
                }
            }));
        }
        start.wait().await;
        for client in clients {
            client.await.unwrap();
        }
        assert!(high_water.load() <= MAX_SESSION_CONNECTIONS);

        let mut shutdown = UnixStream::connect(&control_path).await.unwrap();
        write_frame(
            &mut shutdown,
            &json!({"operation": "shutdown"}),
            MAX_CONTROL_BYTES,
        )
        .await
        .unwrap();
        let _: serde_json::Value = read_test_frame(&mut shutdown, MAX_CONTROL_BYTES)
            .await
            .unwrap();
        task.await.unwrap().unwrap();
        std::fs::remove_file(source).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[tokio::test]
    async fn partial_frame_is_closed_at_operation_deadline() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let (shutdown, _receiver) = watch::channel(false);
        let task = tokio::spawn(handle_control_bounded(
            server,
            shutdown,
            Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap(),
            tokio::time::Instant::now() + Duration::from_millis(25),
        ));
        client.write_u32(100).await.unwrap();
        let read = tokio::time::timeout(Duration::from_secs(1), client.read_u8())
            .await
            .unwrap();
        assert!(matches!(read, Ok(0) | Err(_)));
        drop(task.await.unwrap());
    }

    struct StalledSource;

    impl IdentityTokenSource for StalledSource {
        async fn fetch(&self, _proof_audience: &str) -> Result<Zeroizing<String>> {
            println!("BASIL_CI_PREPARATION_STALLED");
            std::io::stdout().flush().unwrap();
            std::future::pending().await
        }
    }

    #[test]
    fn signal_during_preparation_child() {
        let Some(root) = std::env::var_os("BASIL_CI_SIGNAL_CHILD_ROOT") else {
            return;
        };
        let source = PathBuf::from(std::env::var_os("BASIL_CI_SIGNAL_CHILD_SOURCE").unwrap());
        let digest = std::env::var("BASIL_CI_SIGNAL_CHILD_DIGEST").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut signals = SessionSignals::register().unwrap();
            let mut preparation = tokio::spawn(prepare_session(
                SessionConfig {
                    basil_executable: source,
                    basil_executable_sha256: digest,
                    rule_max_token_age: Duration::from_secs(90),
                    runtime_parent: PathBuf::from(root),
                },
                StalledSource,
                NoAdapter,
            ));
            let signalled = tokio::select! {
                biased;
                result = signals.wait() => {
                    result.unwrap();
                    true
                },
                _ = &mut preparation => false,
            };
            assert!(signalled);
            preparation.abort();
            let _ = preparation.await;
        });
    }

    #[test]
    fn signal_after_output_child() {
        let Some(root) = std::env::var_os("BASIL_CI_POST_OUTPUT_CHILD_ROOT") else {
            return;
        };
        let source = PathBuf::from(std::env::var_os("BASIL_CI_SIGNAL_CHILD_SOURCE").unwrap());
        let digest = std::env::var("BASIL_CI_SIGNAL_CHILD_DIGEST").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let signals = SessionSignals::register().unwrap();
            let now = unix_now().unwrap();
            let session = prepare_session(
                SessionConfig {
                    basil_executable: source,
                    basil_executable_sha256: digest,
                    rule_max_token_age: Duration::from_secs(30),
                    runtime_parent: PathBuf::from(root),
                },
                StaticSource {
                    token: Arc::new(Mutex::new(jwt(now, now + 30, "post-output"))),
                },
                NoAdapter,
            )
            .await
            .unwrap();
            serde_json::to_writer(std::io::stdout().lock(), session.outputs()).unwrap();
            writeln!(std::io::stdout().lock()).unwrap();
            println!("BASIL_CI_OUTPUT_READY");
            std::io::stdout().flush().unwrap();
            session.serve(signals).await.unwrap();
        });
    }

    fn assert_signal_child_cleanup(test_name: &str, marker: &str, root_environment: &str) {
        let root = test_directory("signal-child");
        let child_executable = std::env::current_exe().unwrap();
        let reviewed_executable = root.join("reviewed-basil");
        std::fs::write(&reviewed_executable, b"reviewed executable").unwrap();
        std::fs::set_permissions(&reviewed_executable, std::fs::Permissions::from_mode(0o500))
            .unwrap();
        let digest = hex::encode(Sha256::digest(b"reviewed executable"));
        let mut child = Command::new(&child_executable)
            .arg(test_name)
            .arg("--exact")
            .arg("--nocapture")
            .env(root_environment, &root)
            .env("BASIL_CI_SIGNAL_CHILD_SOURCE", &reviewed_executable)
            .env("BASIL_CI_SIGNAL_CHILD_DIGEST", digest)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let marker = marker.to_owned();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let _reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout)
                .lines()
                .map_while(Result::ok)
            {
                if line.contains(&marker) {
                    let _ = ready_tx.send(());
                }
            }
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let raw_pid = i32::try_from(child.id()).unwrap();
        let pid = rustix::process::Pid::from_raw(raw_pid).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        let (status_tx, status_rx) = mpsc::sync_channel(1);
        let _waiter = std::thread::spawn(move || {
            let _ = status_tx.send(child.wait());
        });
        let status = status_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap();
        assert!(status.success());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        std::fs::remove_file(reviewed_executable).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn signal_cancels_preparation_and_removes_partial_runtime() {
        assert_signal_child_cleanup(
            "ci_session::tests::signal_during_preparation_child",
            "BASIL_CI_PREPARATION_STALLED",
            "BASIL_CI_SIGNAL_CHILD_ROOT",
        );
    }

    #[test]
    fn signal_after_output_removes_all_session_paths() {
        assert_signal_child_cleanup(
            "ci_session::tests::signal_after_output_child",
            "BASIL_CI_OUTPUT_READY",
            "BASIL_CI_POST_OUTPUT_CHILD_ROOT",
        );
    }

    fn test_directory(label: &str) -> PathBuf {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "basil-ci-session-test-{label}-{}-{attempt}",
                std::process::id()
            ));
            if std::fs::create_dir(&path).is_ok() {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
                return path;
            }
        }
        panic!("could not allocate test directory")
    }
}
