// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Public-only Nix binary-cache key commands.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow, bail};
use base64::Engine as _;
use basil::{Client, NixCacheEnrollment, NixCacheEnrollmentDisposition, NixCacheKey};
use clap::Subcommand;
use serde::Serialize;

use crate::nix_cache_cli::{NixCacheCommand, run as run_cache};
use crate::nix_provider::{ProviderServeArgs, serve as serve_provider};

const CORRELATION_ID_LEN: usize = 16;
const RANDOM_ID_ATTEMPTS: usize = 8;
const PENDING_REASON: &str = "NIX_CACHE_KEY_PENDING";
const CUSTODY_GUIDANCE: &str = concat!(
    "Basil keeps Nix cache private keys in backend custody; pass a catalog key ID with ",
    "`--key-id ID`. Secret input and private-key files are unsupported"
);

/// Nix integration commands.
#[derive(Debug, Subcommand)]
pub enum NixCommand {
    /// Add, replace, or remove signatures in a local Nix binary cache.
    #[command(subcommand)]
    Cache(NixCacheCommand),
    /// Manage backend-custodied Nix binary-cache keys.
    #[command(subcommand)]
    Key(NixKeyCommand),
    /// Serve the purpose-specific local external-signer protocol.
    #[command(subcommand, visible_alias = "provider")]
    Signer(NixSignerCommand),
}

/// Nix external-signer provider commands.
#[derive(Debug, Subcommand)]
pub enum NixSignerCommand {
    /// Serve one enrolled catalog key on one owner-only Unix socket.
    Serve(ProviderServeArgs),
}

/// Nix binary-cache key commands.
#[derive(Debug, Subcommand)]
pub enum NixKeyCommand {
    /// Ensure a predeclared Nix cache key and print its public identity.
    GenerateCacheKey {
        /// Catalog key ID whose typed `nixCache` identity is pending enrollment.
        #[arg(long, required_unless_present_any = ["key_file", "legacy_input"])]
        key_id: Option<String>,
        /// Emit a stable machine-readable JSON object.
        #[arg(long)]
        json: bool,
        /// Rejected compatibility input. Nix cache private keys stay in the backend.
        #[arg(long, hide = true)]
        key_file: Option<PathBuf>,
        /// Rejected compatibility input. Secret bytes are never accepted.
        #[arg(hide = true, allow_hyphen_values = true)]
        legacy_input: Option<OsString>,
    },
    /// Print the public identity of an enrolled Nix cache key.
    #[command(visible_alias = "convert-secret-to-public")]
    Public {
        /// Catalog key ID whose enrolled public identity should be returned.
        #[arg(long, required_unless_present_any = ["key_file", "legacy_input"])]
        key_id: Option<String>,
        /// Emit a stable machine-readable JSON object.
        #[arg(long)]
        json: bool,
        /// Rejected compatibility input. Nix cache private keys stay in the backend.
        #[arg(long, hide = true)]
        key_file: Option<PathBuf>,
        /// Rejected compatibility input. Secret bytes are never accepted.
        #[arg(hide = true, allow_hyphen_values = true)]
        legacy_input: Option<OsString>,
    },
    /// Rejected legacy generator. Basil provisions keys directly in the backend.
    #[command(hide = true)]
    GenerateSecret {
        /// Legacy arguments are accepted only to return custody-specific guidance.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
}

#[derive(Serialize)]
struct PublicOutput<'a> {
    key_id: &'a str,
    key_name: &'a str,
    backend_version: u32,
    public_key: String,
}

#[derive(Serialize)]
struct EnrollmentOutput<'a> {
    disposition: &'static str,
    key_id: &'a str,
    key_name: &'a str,
    backend_version: u32,
    public_key: String,
}

trait NixCacheRpc {
    fn describe_nix_cache_key(
        &mut self,
        key_id: &str,
        batch_id: [u8; CORRELATION_ID_LEN],
        request_id: [u8; CORRELATION_ID_LEN],
    ) -> impl std::future::Future<Output = basil::Result<NixCacheKey>>;

    fn enroll_nix_cache_key(
        &mut self,
        key_id: &str,
        batch_id: [u8; CORRELATION_ID_LEN],
        request_id: [u8; CORRELATION_ID_LEN],
    ) -> impl std::future::Future<Output = basil::Result<NixCacheEnrollment>>;
}

impl NixCacheRpc for Client {
    async fn describe_nix_cache_key(
        &mut self,
        key_id: &str,
        batch_id: [u8; CORRELATION_ID_LEN],
        request_id: [u8; CORRELATION_ID_LEN],
    ) -> basil::Result<NixCacheKey> {
        Self::describe_nix_cache_key(self, key_id, batch_id, request_id).await
    }

    async fn enroll_nix_cache_key(
        &mut self,
        key_id: &str,
        batch_id: [u8; CORRELATION_ID_LEN],
        request_id: [u8; CORRELATION_ID_LEN],
    ) -> basil::Result<NixCacheEnrollment> {
        Self::enroll_nix_cache_key(self, key_id, batch_id, request_id).await
    }
}

trait CorrelationIds {
    fn next_pair(&mut self) -> Result<([u8; CORRELATION_ID_LEN], [u8; CORRELATION_ID_LEN])>;
}

struct SystemCorrelationIds;

impl CorrelationIds for SystemCorrelationIds {
    fn next_pair(&mut self) -> Result<([u8; CORRELATION_ID_LEN], [u8; CORRELATION_ID_LEN])> {
        let batch_id = random_correlation_id(None)?;
        let request_id = random_correlation_id(Some(&batch_id))?;
        Ok((batch_id, request_id))
    }
}

fn random_correlation_id(
    excluded: Option<&[u8; CORRELATION_ID_LEN]>,
) -> Result<[u8; CORRELATION_ID_LEN]> {
    for _ in 0..RANDOM_ID_ATTEMPTS {
        let mut id = [0_u8; CORRELATION_ID_LEN];
        getrandom::fill(&mut id)
            .map_err(|error| anyhow!("generating Nix RPC correlation ID: {error}"))?;
        if id != [0; CORRELATION_ID_LEN] && excluded != Some(&id) {
            return Ok(id);
        }
    }
    bail!("operating-system randomness did not produce a fresh nonzero Nix RPC correlation ID")
}

/// Run a Nix command over the selected Basil Unix socket.
///
/// # Errors
///
/// Returns an error for forbidden legacy secret input, entropy or connection
/// failures, broker rejection, malformed broker replies, and output failures.
pub async fn run(socket: Option<String>, command: NixCommand) -> Result<()> {
    reject_legacy_input(&command)?;
    let socket = socket.unwrap_or_else(|| basil::constants::DEFAULT_SOCKET_PATH.to_string());
    match command {
        NixCommand::Signer(NixSignerCommand::Serve(args)) => {
            return serve_provider(&socket, args).await;
        }
        NixCommand::Cache(command) => return run_cache(&socket, command).await,
        NixCommand::Key(command) => {
            return run_key(&socket, command).await;
        }
    }
}

async fn run_key(socket: &str, command: NixKeyCommand) -> Result<()> {
    let mut client = Client::connect(socket)
        .await
        .with_context(|| format!("connecting to agent at {socket}"))?;
    let mut ids = SystemCorrelationIds;
    let mut output = Vec::new();
    dispatch(&mut client, NixCommand::Key(command), &mut ids, &mut output).await?;
    drop(client);
    std::io::stdout()
        .lock()
        .write_all(&output)
        .context("writing Nix cache key output")
}

fn reject_legacy_input(command: &NixCommand) -> Result<()> {
    let NixCommand::Key(command) = command else {
        return Ok(());
    };
    match command {
        NixKeyCommand::GenerateSecret { arguments } => {
            let _ = arguments;
            bail!("{CUSTODY_GUIDANCE}; use `basil nix key generate-cache-key --key-id ID`");
        }
        NixKeyCommand::GenerateCacheKey {
            key_file,
            legacy_input,
            ..
        }
        | NixKeyCommand::Public {
            key_file,
            legacy_input,
            ..
        } if key_file.is_some() || legacy_input.is_some() => {
            bail!("{CUSTODY_GUIDANCE}");
        }
        _ => Ok(()),
    }
}

async fn dispatch<C, I, W>(
    client: &mut C,
    command: NixCommand,
    ids: &mut I,
    output: &mut W,
) -> Result<()>
where
    C: NixCacheRpc,
    I: CorrelationIds,
    W: std::io::Write,
{
    reject_legacy_input(&command)?;
    let NixCommand::Key(command) = command else {
        bail!("provider commands use the provider runtime dispatcher");
    };
    match command {
        NixKeyCommand::GenerateCacheKey {
            key_id: Some(key_id),
            json,
            key_file: None,
            legacy_input: None,
        } => enroll(client, ids, output, &key_id, json).await,
        NixKeyCommand::Public {
            key_id: Some(key_id),
            json,
            key_file: None,
            legacy_input: None,
        } => public(client, ids, output, &key_id, json).await,
        NixKeyCommand::GenerateCacheKey { .. } | NixKeyCommand::Public { .. } => {
            bail!("a catalog key ID is required; pass `--key-id ID`");
        }
        NixKeyCommand::GenerateSecret { .. } => {
            bail!("{CUSTODY_GUIDANCE}; use `basil nix key generate-cache-key --key-id ID`");
        }
    }
}

async fn enroll<C: NixCacheRpc, I: CorrelationIds, W: std::io::Write>(
    client: &mut C,
    ids: &mut I,
    output: &mut W,
    key_id: &str,
    json: bool,
) -> Result<()> {
    let (batch_id, request_id) = ids.next_pair()?;
    let enrollment = client
        .enroll_nix_cache_key(key_id, batch_id, request_id)
        .await
        .context("enrolling backend-custodied Nix cache key")?;
    let disposition = disposition_token(enrollment.disposition)?;
    let public_key = encode_public_key(&enrollment.key);
    if json {
        serde_json::to_writer(
            &mut *output,
            &EnrollmentOutput {
                disposition,
                key_id,
                key_name: &enrollment.key.key_name,
                backend_version: enrollment.key.backend_version,
                public_key,
            },
        )?;
        writeln!(output)?;
        return Ok(());
    }
    writeln!(output, "disposition: {disposition}")?;
    write_public_fields(output, key_id, &enrollment.key, &public_key)
}

async fn public<C: NixCacheRpc, I: CorrelationIds, W: std::io::Write>(
    client: &mut C,
    ids: &mut I,
    output: &mut W,
    key_id: &str,
    json: bool,
) -> Result<()> {
    let (batch_id, request_id) = ids.next_pair()?;
    let key = client
        .describe_nix_cache_key(key_id, batch_id, request_id)
        .await
        .map_err(map_public_error)?;
    let public_key = encode_public_key(&key);
    if json {
        serde_json::to_writer(
            &mut *output,
            &PublicOutput {
                key_id,
                key_name: &key.key_name,
                backend_version: key.backend_version,
                public_key,
            },
        )?;
        writeln!(output)?;
        return Ok(());
    }
    write_public_fields(output, key_id, &key, &public_key)
}

fn map_public_error(error: basil::Error) -> anyhow::Error {
    if let basil::Error::Status { reason, .. } = &error
        && reason == PENDING_REASON
    {
        return anyhow!(
            "Nix cache key is pending enrollment; run `basil nix key generate-cache-key --key-id ID`, record its public identity in the catalog, and reload Basil: {error}"
        );
    }
    anyhow!(error).context("reading enrolled Nix cache public identity")
}

fn disposition_token(disposition: NixCacheEnrollmentDisposition) -> Result<&'static str> {
    match disposition {
        NixCacheEnrollmentDisposition::Created => Ok("CREATED"),
        NixCacheEnrollmentDisposition::Existing => Ok("EXISTING"),
        NixCacheEnrollmentDisposition::Unspecified => {
            bail!("broker returned an unspecified Nix cache enrollment disposition")
        }
    }
}

fn encode_public_key(key: &NixCacheKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.public_key)
}

fn write_public_fields<W: std::io::Write>(
    output: &mut W,
    key_id: &str,
    key: &NixCacheKey,
    public_key: &str,
) -> Result<()> {
    writeln!(output, "key_id: {key_id}")?;
    writeln!(output, "key_name: {}", key.key_name)?;
    writeln!(output, "backend_version: {}", key.backend_version)?;
    writeln!(output, "public_key: {public_key}")?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use basil_proto::broker::v1 as pb;
    use basil_proto::broker::v1::nix_cache_service_server::{
        NixCacheService, NixCacheServiceServer,
    };
    use clap::Parser as _;
    use tokio::net::UnixListener;
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};

    use super::*;
    use crate::{Cli, Command};

    const BATCH_ID: [u8; CORRELATION_ID_LEN] = [0x41; CORRELATION_ID_LEN];
    const REQUEST_ID: [u8; CORRELATION_ID_LEN] = [0x52; CORRELATION_ID_LEN];
    const KEY_ID: &str = "cache.signing";
    const KEY_NAME: &str = "cache.example-1";
    static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy)]
    enum Behavior {
        Created,
        Existing,
        Pending,
        WrongEcho,
        Incompatible,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ObservedRequest {
        operation: &'static str,
        key_id: String,
        batch_id: Vec<u8>,
        request_id: Vec<u8>,
    }

    #[derive(Clone)]
    struct MockNixCacheService {
        behavior: Behavior,
        requests: Arc<Mutex<Vec<ObservedRequest>>>,
    }

    impl MockNixCacheService {
        fn record(
            &self,
            operation: &'static str,
            key_id: String,
            batch_id: Vec<u8>,
            request_id: Vec<u8>,
        ) {
            self.requests.lock().unwrap().push(ObservedRequest {
                operation,
                key_id,
                batch_id,
                request_id,
            });
        }
    }

    #[tonic::async_trait]
    impl NixCacheService for MockNixCacheService {
        async fn describe_nix_cache_key(
            &self,
            request: Request<pb::DescribeNixCacheKeyRequest>,
        ) -> Result<Response<pb::DescribeNixCacheKeyResponse>, Status> {
            let body = request.into_inner();
            self.record(
                "describe",
                body.key_id.clone(),
                body.batch_id.clone(),
                body.request_id.clone(),
            );
            if matches!(self.behavior, Behavior::Pending) {
                return Err(basil_core::transport::broker_status(
                    tonic::Code::FailedPrecondition,
                    PENDING_REASON,
                    "describe_nix_cache_key",
                    "Nix cache key is pending enrollment",
                ));
            }
            let request_id = if matches!(self.behavior, Behavior::WrongEcho) {
                vec![0x7f; CORRELATION_ID_LEN]
            } else {
                body.request_id
            };
            Ok(Response::new(pb::DescribeNixCacheKeyResponse {
                key_name: KEY_NAME.to_string(),
                public_key: vec![0x11; 32],
                backend_version: if matches!(self.behavior, Behavior::Incompatible) {
                    2
                } else {
                    1
                },
                batch_id: body.batch_id,
                request_id,
            }))
        }

        async fn enroll_nix_cache_key(
            &self,
            request: Request<pb::EnrollNixCacheKeyRequest>,
        ) -> Result<Response<pb::EnrollNixCacheKeyResponse>, Status> {
            let body = request.into_inner();
            self.record(
                "enroll",
                body.key_id.clone(),
                body.batch_id.clone(),
                body.request_id.clone(),
            );
            let disposition = if matches!(self.behavior, Behavior::Existing) {
                pb::NixCacheEnrollmentDisposition::Existing
            } else {
                pb::NixCacheEnrollmentDisposition::Created
            };
            Ok(Response::new(pb::EnrollNixCacheKeyResponse {
                key_name: KEY_NAME.to_string(),
                public_key: vec![0x11; 32],
                backend_version: 1,
                disposition: disposition.into(),
                batch_id: body.batch_id,
                request_id: body.request_id,
            }))
        }

        async fn sign_nix_cache_fingerprint(
            &self,
            _request: Request<pb::SignNixCacheFingerprintRequest>,
        ) -> Result<Response<pb::SignNixCacheFingerprintResponse>, Status> {
            Err(Status::unimplemented("not used by key CLI tests"))
        }
    }

    struct TestServer {
        path: PathBuf,
        requests: Arc<Mutex<Vec<ObservedRequest>>>,
        shutdown: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    }

    impl TestServer {
        async fn stop(mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            self.task.await.unwrap().unwrap();
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn start_server(behavior: Behavior) -> TestServer {
        let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "basil-nix-cli-{}-{sequence}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let service = MockNixCacheService {
            behavior,
            requests: Arc::clone(&requests),
        };
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(NixCacheServiceServer::new(service))
                .serve_with_incoming_shutdown(UnixListenerStream::new(listener), async {
                    let _ = receiver.await;
                })
                .await
        });
        TestServer {
            path,
            requests,
            shutdown: Some(shutdown),
            task,
        }
    }

    struct FixedIds {
        pairs: VecDeque<([u8; CORRELATION_ID_LEN], [u8; CORRELATION_ID_LEN])>,
    }

    impl FixedIds {
        fn one() -> Self {
            Self {
                pairs: VecDeque::from([(BATCH_ID, REQUEST_ID)]),
            }
        }
    }

    impl CorrelationIds for FixedIds {
        fn next_pair(&mut self) -> Result<([u8; CORRELATION_ID_LEN], [u8; CORRELATION_ID_LEN])> {
            self.pairs
                .pop_front()
                .context("test exhausted fixed correlation IDs")
        }
    }

    fn generate_command(json: bool) -> NixCommand {
        NixCommand::Key(NixKeyCommand::GenerateCacheKey {
            key_id: Some(KEY_ID.to_string()),
            json,
            key_file: None,
            legacy_input: None,
        })
    }

    fn public_command(json: bool) -> NixCommand {
        NixCommand::Key(NixKeyCommand::Public {
            key_id: Some(KEY_ID.to_string()),
            json,
            key_file: None,
            legacy_input: None,
        })
    }

    async fn connect(server: &TestServer) -> Client {
        Client::connect(server.path.to_str().unwrap())
            .await
            .unwrap()
    }

    #[test]
    fn parses_nix_key_commands_and_public_alias() {
        let generate = Cli::try_parse_from([
            "basil",
            "nix",
            "key",
            "generate-cache-key",
            "--key-id",
            KEY_ID,
            "--json",
        ])
        .unwrap();
        assert!(matches!(generate.command, Command::Nix(_)));

        let alias = Cli::try_parse_from([
            "basil",
            "nix",
            "key",
            "convert-secret-to-public",
            "--key-id",
            KEY_ID,
        ])
        .unwrap();
        assert!(matches!(alias.command, Command::Nix(_)));
    }

    #[test]
    fn parses_canonical_nix_signer_serve_and_provider_alias() {
        for spelling in ["signer", "provider"] {
            let parsed = Cli::try_parse_from([
                "basil",
                "nix",
                spelling,
                "serve",
                "--key-id",
                KEY_ID,
                "--listen",
                "/run/nix-cache/signer.sock",
            ])
            .unwrap();
            let Command::Nix(NixCommand::Signer(NixSignerCommand::Serve(args))) = parsed.command
            else {
                panic!("Nix signer serve command expected");
            };
            assert_eq!(args.key_id, KEY_ID);
            assert_eq!(args.listen, PathBuf::from("/run/nix-cache/signer.sock"));
        }
    }

    #[test]
    fn legacy_secret_inputs_are_rejected_with_custody_guidance() {
        for arguments in [
            vec!["basil", "nix", "key", "generate-secret", "legacy.key"],
            vec![
                "basil",
                "nix",
                "key",
                "generate-cache-key",
                "--key-file",
                "/tmp/private",
            ],
            vec!["basil", "nix", "key", "convert-secret-to-public", "-"],
        ] {
            let parsed = Cli::try_parse_from(arguments).unwrap();
            let Command::Nix(command) = parsed.command else {
                panic!("Nix command expected");
            };
            let error = reject_legacy_input(&command).unwrap_err();
            let message = error.to_string();
            assert!(message.contains("backend custody"), "{message}");
            assert!(message.contains("--key-id ID"), "{message}");
        }
    }

    #[test]
    fn system_ids_are_nonzero_and_distinct() {
        let mut source = SystemCorrelationIds;
        let mut observed = Vec::new();
        for _ in 0..32 {
            let (batch, request) = source.next_pair().unwrap();
            assert_ne!(batch, [0; CORRELATION_ID_LEN]);
            assert_ne!(request, [0; CORRELATION_ID_LEN]);
            assert_ne!(batch, request);
            observed.push(batch);
            observed.push(request);
        }
        observed.sort_unstable();
        observed.dedup();
        assert_eq!(observed.len(), 64);
    }

    #[tokio::test]
    async fn enrollment_outputs_created_json_and_preserves_request_ids() {
        let server = start_server(Behavior::Created);
        let mut client = connect(&server).await;
        let mut output = Vec::new();
        dispatch(
            &mut client,
            generate_command(true),
            &mut FixedIds::one(),
            &mut output,
        )
        .await
        .unwrap();
        let public_key = base64::engine::general_purpose::STANDARD.encode([0x11; 32]);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!(
                "{{\"disposition\":\"CREATED\",\"key_id\":\"{KEY_ID}\",\"key_name\":\"{KEY_NAME}\",\"backend_version\":1,\"public_key\":\"{public_key}\"}}\n"
            )
        );
        drop(client);
        assert_eq!(
            *server.requests.lock().unwrap(),
            [ObservedRequest {
                operation: "enroll",
                key_id: KEY_ID.to_string(),
                batch_id: BATCH_ID.to_vec(),
                request_id: REQUEST_ID.to_vec(),
            }]
        );
        server.stop().await;
    }

    #[tokio::test]
    async fn enrollment_outputs_existing_without_private_material() {
        let server = start_server(Behavior::Existing);
        let mut client = connect(&server).await;
        let mut output = Vec::new();
        dispatch(
            &mut client,
            generate_command(false),
            &mut FixedIds::one(),
            &mut output,
        )
        .await
        .unwrap();
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.starts_with("disposition: EXISTING\n"));
        assert!(rendered.contains(&format!("key_id: {KEY_ID}\n")));
        assert!(rendered.contains(&format!("key_name: {KEY_NAME}\n")));
        assert!(rendered.contains("backend_version: 1\n"));
        assert!(!rendered.to_ascii_lowercase().contains("private"));
        assert!(!rendered.contains(&hex::encode(BATCH_ID)));
        assert!(!rendered.contains(&hex::encode(REQUEST_ID)));
        drop(client);
        server.stop().await;
    }

    #[tokio::test]
    async fn public_outputs_only_enrolled_public_identity() {
        let server = start_server(Behavior::Created);
        let mut client = connect(&server).await;
        let mut output = Vec::new();
        dispatch(
            &mut client,
            public_command(true),
            &mut FixedIds::one(),
            &mut output,
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["key_id"], KEY_ID);
        assert_eq!(value["key_name"], KEY_NAME);
        assert_eq!(value["backend_version"], 1);
        assert_eq!(value.as_object().unwrap().len(), 4);
        drop(client);
        assert_eq!(server.requests.lock().unwrap()[0].operation, "describe");
        server.stop().await;
    }

    #[tokio::test]
    async fn pending_public_denial_has_enrollment_guidance_and_no_output() {
        let server = start_server(Behavior::Pending);
        let mut client = connect(&server).await;
        let mut output = Vec::new();
        let error = dispatch(
            &mut client,
            public_command(false),
            &mut FixedIds::one(),
            &mut output,
        )
        .await
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("pending enrollment"), "{message}");
        assert!(message.contains("generate-cache-key"), "{message}");
        assert!(output.is_empty());
        drop(client);
        server.stop().await;
    }

    #[tokio::test]
    async fn correlation_echo_mismatch_fails_without_output() {
        let server = start_server(Behavior::WrongEcho);
        let mut client = connect(&server).await;
        let mut output = Vec::new();
        let error = dispatch(
            &mut client,
            public_command(false),
            &mut FixedIds::one(),
            &mut output,
        )
        .await
        .unwrap_err();
        let client_error = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<basil::Error>())
            .expect("client error remains in the error chain");
        assert!(
            matches!(
                client_error,
                basil::Error::Protocol(message)
                    if message == "Nix cache response changed the request ID"
            ),
            "{error:#}"
        );
        assert!(output.is_empty());
        drop(client);
        server.stop().await;
    }

    #[tokio::test]
    async fn incompatible_backend_identity_fails_without_output() {
        let server = start_server(Behavior::Incompatible);
        let mut client = connect(&server).await;
        let mut output = Vec::new();
        let error = dispatch(
            &mut client,
            public_command(false),
            &mut FixedIds::one(),
            &mut output,
        )
        .await
        .unwrap_err();
        let client_error = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<basil::Error>())
            .expect("client error remains in the error chain");
        assert!(
            matches!(
                client_error,
                basil::Error::Status {
                    code: tonic::Code::DataLoss,
                    reason,
                    op,
                    message,
                } if reason.is_empty()
                    && op.is_empty()
                    && message == "field 3 must equal 1"
            ),
            "{error:#}"
        );
        assert!(output.is_empty());
        drop(client);
        server.stop().await;
    }
}
