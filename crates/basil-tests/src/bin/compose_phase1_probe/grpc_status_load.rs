// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use basil_proto::broker::v1::StatusRequest;
use basil_proto::broker::v1::admin_service_client::AdminServiceClient;
use hyper_util::rt::TokioIo;
use rustix::io::Errno;
use serde::Serialize;
use tokio::net::UnixStream;
use tokio::runtime::Builder;
use tokio::sync::{Barrier, Mutex};
use tokio::task::JoinHandle;
use tonic::Code;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use super::{MAX_PATH_BYTES, ProbeError, ProbeResult, bounded_text, required_arg};

const MAX_CONNECTIONS: usize = 4_096;
const MAX_IN_FLIGHT: usize = 4_096;
const MAX_REQUESTS: usize = 1_000_000;
const MAX_HOLD: Duration = Duration::from_mins(1);
const CONNECT_CONCURRENCY: usize = 128;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RPC_TIMEOUT: Duration = Duration::from_secs(10);
const OVERALL_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_CONNECTION_FAILURE_CAUSES: usize = 10;
const MAX_CONNECTION_CAUSE_BYTES: usize = 192;
const MAX_STATUS_RESPONSE_BYTES: usize = 64 * 1024;
const MILLI_RATE_SCALE: u64 = 1_000_000_000;
const HISTOGRAM_BUCKETS_US: [u64; 17] = [
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000,
    1_000_000, 2_500_000, 5_000_000, 10_000_000,
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoadConfig {
    socket_path: PathBuf,
    connections: usize,
    in_flight: usize,
    requests: usize,
    hold: Duration,
}

#[derive(Debug, Serialize)]
pub struct GrpcStatusLoadReport {
    socket_path: String,
    connection_setup: ConnectionSetupReport,
    retained_channel_handles: usize,
    warmup_concurrency: usize,
    workload_bearing_channels: usize,
    load_executed: bool,
    load_skipped_reason: Option<&'static str>,
    in_flight: usize,
    requests: usize,
    hold_ms: u64,
    limits: LoadLimits,
    connect_elapsed_us: u64,
    warmup_elapsed_us: u64,
    workload_elapsed_us: u64,
    hold_elapsed_us: u64,
    overall_elapsed_us: u64,
    attempted_milli_requests_per_second: u64,
    successful_milli_requests_per_second: u64,
    warmup: RpcCounts,
    workload: RpcCounts,
    latency_us: LatencySummary,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct LoadLimits {
    max_connections: usize,
    max_in_flight: usize,
    max_requests: usize,
    max_hold_ms: u64,
    connect_concurrency: usize,
    connect_timeout_ms: u64,
    rpc_timeout_ms: u64,
    overall_timeout_ms: u64,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ConnectionSetupReport {
    requested: u64,
    attempted: u64,
    established: u64,
    failed: u64,
    complete: bool,
    failure_causes: Vec<ConnectionFailureCause>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct ConnectionFailureCause {
    cause: &'static str,
    count: u64,
    example: String,
    raw_os_error: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ConnectionFailureKind {
    FileDescriptorExhausted,
    ConnectionRefused,
    SocketNotFound,
    PermissionDenied,
    TimedOut,
    Unavailable,
    InvalidSocket,
    Transport,
    TaskFailed,
    EndpointFailed,
}

#[derive(Clone, Debug)]
struct ConnectionFailure {
    kind: ConnectionFailureKind,
    example: String,
    raw_os_error: Option<i32>,
}

#[derive(Debug)]
enum ConnectionAttempt {
    Established(Channel),
    Failed(ConnectionFailure),
}

#[derive(Debug)]
struct ConnectionSetup {
    channels: Vec<Channel>,
    report: ConnectionSetupReport,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
struct RpcCounts {
    attempted: u64,
    succeeded: u64,
    client_timeouts: u64,
    grpc_failures: GrpcCodeCounts,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
struct GrpcCodeCounts {
    ok: u64,
    cancelled: u64,
    unknown: u64,
    invalid_argument: u64,
    deadline_exceeded: u64,
    not_found: u64,
    already_exists: u64,
    permission_denied: u64,
    resource_exhausted: u64,
    failed_precondition: u64,
    aborted: u64,
    out_of_range: u64,
    unimplemented: u64,
    internal: u64,
    unavailable: u64,
    data_loss: u64,
    unauthenticated: u64,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct LatencySummary {
    sample_method: &'static str,
    samples: u64,
    min: Option<u64>,
    p50: Option<u64>,
    p95: Option<u64>,
    p99: Option<u64>,
    max: Option<u64>,
    mean: Option<u64>,
    cumulative_histogram: Vec<LatencyBucket>,
    above_highest_bucket: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct LatencyBucket {
    less_than_or_equal: u64,
    count: u64,
}

#[derive(Debug)]
enum RpcObservation {
    Success { latency_us: u64 },
    ClientTimeout,
    GrpcFailure(Code),
}

#[derive(Debug)]
struct WorkerReport {
    counts: RpcCounts,
    successful_latencies_us: Vec<u64>,
}

struct AbortOnDrop<T> {
    handle: JoinHandle<T>,
}

impl<T> AbortOnDrop<T> {
    const fn new(handle: JoinHandle<T>) -> Self {
        Self { handle }
    }

    async fn join(mut self, code: &'static str, context: &'static str) -> ProbeResult<T> {
        (&mut self.handle).await.map_err(|error| {
            ProbeError::new(code, format!("{context} task did not complete: {error}"))
        })
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub fn run(args: &[OsString]) -> ProbeResult<GrpcStatusLoadReport> {
    let config = parse_config(args)?;
    let runtime = Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| {
            ProbeError::io("GRPC_RUNTIME_FAILED", "build gRPC load runtime", &error)
        })?;
    runtime.block_on(async {
        tokio::time::timeout(OVERALL_TIMEOUT, execute(config))
            .await
            .map_err(|_elapsed| {
                ProbeError::new(
                    "GRPC_OVERALL_TIMEOUT",
                    "gRPC status load exceeded the five-minute overall deadline",
                )
            })?
    })
}

fn parse_config(args: &[OsString]) -> ProbeResult<LoadConfig> {
    if !(5..=6).contains(&args.len()) {
        return Err(ProbeError::new("USAGE", super::usage()));
    }
    let socket_path = PathBuf::from(required_arg(args, 1, "SOCKET")?);
    super::validate_socket_path(&socket_path)?;
    let connections = parse_positive_count(
        required_arg(args, 2, "CONNECTIONS")?,
        "CONNECTIONS",
        MAX_CONNECTIONS,
    )?;
    let in_flight = parse_positive_count(
        required_arg(args, 3, "IN_FLIGHT")?,
        "IN_FLIGHT",
        MAX_IN_FLIGHT,
    )?;
    let requests =
        parse_positive_count(required_arg(args, 4, "REQUESTS")?, "REQUESTS", MAX_REQUESTS)?;
    if in_flight > requests {
        return Err(ProbeError::new(
            "INVALID_GRPC_LOAD_ARGUMENT",
            "IN_FLIGHT must not exceed REQUESTS",
        ));
    }
    let hold = args
        .get(5)
        .map_or(Ok(Duration::ZERO), |value| parse_hold(value.as_os_str()))?;
    Ok(LoadConfig {
        socket_path,
        connections,
        in_flight,
        requests,
        hold,
    })
}

fn parse_positive_count(value: &OsStr, name: &str, maximum: usize) -> ProbeResult<usize> {
    let text = value.to_str().ok_or_else(|| {
        ProbeError::new(
            "INVALID_GRPC_LOAD_ARGUMENT",
            format!("{name} must be valid UTF-8 decimal text"),
        )
    })?;
    let parsed = text.parse::<u64>().map_err(|error| {
        ProbeError::new(
            "INVALID_GRPC_LOAD_ARGUMENT",
            format!("invalid {name}: {error}"),
        )
    })?;
    if parsed == 0 {
        return Err(ProbeError::new(
            "INVALID_GRPC_LOAD_ARGUMENT",
            format!("{name} must be greater than zero"),
        ));
    }
    let maximum_u64 = u64::try_from(maximum).map_err(|error| {
        ProbeError::new(
            "ARITHMETIC_OVERFLOW",
            format!("convert {name} limit: {error}"),
        )
    })?;
    if parsed > maximum_u64 {
        return Err(ProbeError::new(
            "GRPC_LOAD_LIMIT",
            format!("{name} must not exceed {maximum}"),
        ));
    }
    usize::try_from(parsed)
        .map_err(|error| ProbeError::new("ARITHMETIC_OVERFLOW", format!("convert {name}: {error}")))
}

fn parse_hold(value: &OsStr) -> ProbeResult<Duration> {
    let text = value.to_str().ok_or_else(|| {
        ProbeError::new(
            "INVALID_GRPC_LOAD_ARGUMENT",
            "HOLD_MS must be valid UTF-8 decimal text",
        )
    })?;
    let milliseconds = text.parse::<u64>().map_err(|error| {
        ProbeError::new(
            "INVALID_GRPC_LOAD_ARGUMENT",
            format!("invalid HOLD_MS: {error}"),
        )
    })?;
    let hold = Duration::from_millis(milliseconds);
    if hold > MAX_HOLD {
        return Err(ProbeError::new(
            "GRPC_LOAD_LIMIT",
            "HOLD_MS must not exceed 60000",
        ));
    }
    Ok(hold)
}

async fn execute(config: LoadConfig) -> ProbeResult<GrpcStatusLoadReport> {
    let overall_started = Instant::now();
    let socket_path = bounded_text(&config.socket_path.to_string_lossy(), MAX_PATH_BYTES);
    let path = Arc::new(config.socket_path);

    let connect_started = Instant::now();
    let setup = connect_channels(Arc::clone(&path), config.connections).await?;
    let connect_elapsed_us = elapsed_us(connect_started, "connection elapsed time")?;
    let channels = setup.channels;
    let retained_channel_handles = channels.len();
    let warmup_concurrency = config
        .in_flight
        .min(CONNECT_CONCURRENCY)
        .min(retained_channel_handles);

    let mut warmup = RpcCounts::default();
    let mut workload = RpcCounts::default();
    let mut successful_latencies_us = Vec::new();
    let mut warmup_elapsed_us = 0;
    let mut workload_elapsed_us = 0;
    let mut hold_elapsed_us = 0;
    let load_executed = !channels.is_empty();
    let load_skipped_reason = if load_executed {
        None
    } else {
        Some("no_connections_established")
    };

    if load_executed {
        let warmup_started = Instant::now();
        warmup = warm_channels(&channels, warmup_concurrency).await?;
        warmup_elapsed_us = elapsed_us(warmup_started, "warmup elapsed time")?;

        (workload, successful_latencies_us, workload_elapsed_us) =
            run_workers(&channels, config.in_flight, config.requests).await?;

        let hold_started = Instant::now();
        tokio::time::sleep(config.hold).await;
        hold_elapsed_us = elapsed_us(hold_started, "hold elapsed time")?;
    }

    let latency_us = LatencySummary::from_samples(&mut successful_latencies_us)?;
    let attempted_milli_requests_per_second =
        milli_requests_per_second(workload.attempted, workload_elapsed_us)?;
    let successful_milli_requests_per_second =
        milli_requests_per_second(workload.succeeded, workload_elapsed_us)?;
    let workload_bearing_channels = if load_executed {
        retained_channel_handles.min(config.requests)
    } else {
        0
    };
    let overall_elapsed_us = elapsed_us(overall_started, "overall elapsed time")?;
    drop(channels);

    Ok(GrpcStatusLoadReport {
        socket_path,
        connection_setup: setup.report,
        retained_channel_handles,
        warmup_concurrency,
        workload_bearing_channels,
        load_executed,
        load_skipped_reason,
        in_flight: config.in_flight,
        requests: config.requests,
        hold_ms: duration_millis(config.hold, "hold duration")?,
        limits: load_limits()?,
        connect_elapsed_us,
        warmup_elapsed_us,
        workload_elapsed_us,
        hold_elapsed_us,
        overall_elapsed_us,
        attempted_milli_requests_per_second,
        successful_milli_requests_per_second,
        warmup,
        workload,
        latency_us,
    })
}

async fn connect_channels(path: Arc<PathBuf>, count: usize) -> ProbeResult<ConnectionSetup> {
    let mut channels = Vec::new();
    reserve_exact(&mut channels, count, "gRPC channel vector")?;
    let mut failures = Vec::new();
    reserve_exact(&mut failures, count, "gRPC connection failure vector")?;
    let mut attempted = 0_u64;

    while usize::try_from(attempted).map_err(|error| {
        ProbeError::new(
            "ARITHMETIC_OVERFLOW",
            format!("convert attempted connection count: {error}"),
        )
    })? < count
    {
        let attempted_usize = usize::try_from(attempted).map_err(|error| {
            ProbeError::new(
                "ARITHMETIC_OVERFLOW",
                format!("convert attempted connection count: {error}"),
            )
        })?;
        let remaining = count.checked_sub(attempted_usize).ok_or_else(|| {
            ProbeError::new(
                "ARITHMETIC_OVERFLOW",
                "gRPC connection remainder underflowed",
            )
        })?;
        let batch_size = remaining.min(CONNECT_CONCURRENCY);
        let mut tasks = Vec::new();
        reserve_exact(&mut tasks, batch_size, "gRPC connection task vector")?;
        for _ in 0..batch_size {
            let path = Arc::clone(&path);
            tasks.push(AbortOnDrop::new(tokio::spawn(async move {
                connect_channel(path).await
            })));
        }
        for task in tasks {
            attempted = checked_increment(attempted, "attempted connection count")?;
            match task
                .join("GRPC_CONNECT_TASK_FAILED", "gRPC connection")
                .await
            {
                Ok(ConnectionAttempt::Established(channel)) => channels.push(channel),
                Ok(ConnectionAttempt::Failed(failure)) => failures.push(failure),
                Err(error) => failures.push(ConnectionFailure {
                    kind: ConnectionFailureKind::TaskFailed,
                    example: bounded_text(&error.message, MAX_CONNECTION_CAUSE_BYTES),
                    raw_os_error: None,
                }),
            }
        }
    }

    let requested = usize_to_u64(count, "requested connection count")?;
    let established = usize_to_u64(channels.len(), "established connection count")?;
    let failed = attempted.checked_sub(established).ok_or_else(|| {
        ProbeError::new("ARITHMETIC_OVERFLOW", "failed connection count underflowed")
    })?;
    let failure_causes = summarize_connection_failures(failures)?;
    Ok(ConnectionSetup {
        channels,
        report: ConnectionSetupReport {
            requested,
            attempted,
            established,
            failed,
            complete: established == requested && failed == 0,
            failure_causes,
        },
    })
}

async fn connect_channel(path: Arc<PathBuf>) -> ConnectionAttempt {
    let stream =
        match tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(path.as_path())).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return ConnectionAttempt::Failed(connection_io_failure(&error)),
            Err(_elapsed) => {
                return ConnectionAttempt::Failed(ConnectionFailure {
                    kind: ConnectionFailureKind::TimedOut,
                    example: "timed out opening the Unix socket".to_owned(),
                    raw_os_error: None,
                });
            }
        };
    let endpoint = match Endpoint::try_from("http://[::]:50051") {
        Ok(endpoint) => endpoint.connect_timeout(CONNECT_TIMEOUT),
        Err(error) => {
            return ConnectionAttempt::Failed(ConnectionFailure {
                kind: ConnectionFailureKind::EndpointFailed,
                example: bounded_text(
                    &format!("construct local gRPC endpoint: {error}"),
                    MAX_CONNECTION_CAUSE_BYTES,
                ),
                raw_os_error: None,
            });
        }
    };
    let initial_stream = Arc::new(Mutex::new(Some(stream)));
    let connect = endpoint.connect_with_connector(service_fn(move |_uri: Uri| {
        let path = Arc::clone(&path);
        let initial_stream = Arc::clone(&initial_stream);
        async move {
            let stream = initial_stream.lock().await.take();
            if let Some(stream) = stream {
                return Ok(TokioIo::new(stream));
            }
            UnixStream::connect(path.as_path()).await.map(TokioIo::new)
        }
    }));
    match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(channel)) => ConnectionAttempt::Established(channel),
        Ok(Err(error)) => ConnectionAttempt::Failed(ConnectionFailure {
            kind: ConnectionFailureKind::Transport,
            example: bounded_text(
                &format!("establish gRPC transport: {error}"),
                MAX_CONNECTION_CAUSE_BYTES,
            ),
            raw_os_error: None,
        }),
        Err(_elapsed) => ConnectionAttempt::Failed(ConnectionFailure {
            kind: ConnectionFailureKind::TimedOut,
            example: "timed out establishing the gRPC transport".to_owned(),
            raw_os_error: None,
        }),
    }
}

fn connection_io_failure(error: &io::Error) -> ConnectionFailure {
    let raw_os_error = error.raw_os_error();
    let kind = if raw_os_error.is_some_and(|error_number| {
        error_number == Errno::MFILE.raw_os_error() || error_number == Errno::NFILE.raw_os_error()
    }) {
        ConnectionFailureKind::FileDescriptorExhausted
    } else {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => ConnectionFailureKind::ConnectionRefused,
            io::ErrorKind::NotFound => ConnectionFailureKind::SocketNotFound,
            io::ErrorKind::PermissionDenied => ConnectionFailureKind::PermissionDenied,
            io::ErrorKind::TimedOut => ConnectionFailureKind::TimedOut,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => {
                ConnectionFailureKind::InvalidSocket
            }
            _ => ConnectionFailureKind::Unavailable,
        }
    };
    ConnectionFailure {
        kind,
        example: bounded_text(&error.to_string(), MAX_CONNECTION_CAUSE_BYTES),
        raw_os_error,
    }
}

fn summarize_connection_failures(
    mut failures: Vec<ConnectionFailure>,
) -> ProbeResult<Vec<ConnectionFailureCause>> {
    failures.sort_by_key(|failure| failure.kind);
    let mut causes = Vec::new();
    reserve_exact(
        &mut causes,
        failures.len().min(MAX_CONNECTION_FAILURE_CAUSES),
        "connection failure cause vector",
    )?;
    for failure in failures {
        if let Some(existing) = causes
            .iter_mut()
            .find(|cause: &&mut ConnectionFailureCause| {
                cause.cause == failure_kind_token(failure.kind)
            })
        {
            existing.count = checked_increment(existing.count, "connection failure cause count")?;
            continue;
        }
        if causes.len() >= MAX_CONNECTION_FAILURE_CAUSES {
            continue;
        }
        causes.push(ConnectionFailureCause {
            cause: failure_kind_token(failure.kind),
            count: 1,
            example: failure.example,
            raw_os_error: failure.raw_os_error,
        });
    }
    Ok(causes)
}

const fn failure_kind_token(kind: ConnectionFailureKind) -> &'static str {
    match kind {
        ConnectionFailureKind::FileDescriptorExhausted => "file_descriptor_exhausted",
        ConnectionFailureKind::ConnectionRefused => "connection_refused",
        ConnectionFailureKind::SocketNotFound => "socket_not_found",
        ConnectionFailureKind::PermissionDenied => "permission_denied",
        ConnectionFailureKind::TimedOut => "timed_out",
        ConnectionFailureKind::Unavailable => "unavailable",
        ConnectionFailureKind::InvalidSocket => "invalid_socket",
        ConnectionFailureKind::Transport => "transport",
        ConnectionFailureKind::TaskFailed => "task_failed",
        ConnectionFailureKind::EndpointFailed => "endpoint_failed",
    }
}

fn admin_client(channel: Channel) -> AdminServiceClient<Channel> {
    AdminServiceClient::new(channel).max_decoding_message_size(MAX_STATUS_RESPONSE_BYTES)
}

async fn warm_channels(channels: &[Channel], concurrency: usize) -> ProbeResult<RpcCounts> {
    let mut total = RpcCounts::default();
    let batch_size = concurrency.max(1);
    for batch in channels.chunks(batch_size) {
        let mut tasks = Vec::new();
        reserve_exact(&mut tasks, batch.len(), "gRPC warmup task vector")?;
        for channel in batch {
            let channel = channel.clone();
            tasks.push(AbortOnDrop::new(tokio::spawn(async move {
                let mut client = admin_client(channel);
                status_observation(&mut client).await
            })));
        }
        for task in tasks {
            let observation = task
                .join("GRPC_WARMUP_TASK_FAILED", "gRPC warmup")
                .await??;
            total.record(&observation)?;
        }
    }
    Ok(total)
}

async fn run_workers(
    channels: &[Channel],
    in_flight: usize,
    requests: usize,
) -> ProbeResult<(RpcCounts, Vec<u64>, u64)> {
    if channels.is_empty() {
        return Err(ProbeError::new(
            "GRPC_INTERNAL_ERROR",
            "gRPC worker pool had no connected channels",
        ));
    }
    let mut successful_latencies_us = Vec::new();
    reserve_exact(
        &mut successful_latencies_us,
        requests,
        "successful latency sample vector",
    )?;
    let barrier_parties = in_flight.checked_add(1).ok_or_else(|| {
        ProbeError::new("ARITHMETIC_OVERFLOW", "gRPC worker barrier size overflowed")
    })?;
    let barrier = Arc::new(Barrier::new(barrier_parties));
    let channels = Arc::new(channels.to_vec());
    let mut tasks = Vec::new();
    reserve_exact(&mut tasks, in_flight, "gRPC worker task vector")?;
    for worker_id in 0..in_flight {
        let expected_requests = worker_request_count(worker_id, in_flight, requests)?;
        let mut worker_latencies = Vec::new();
        reserve_exact(
            &mut worker_latencies,
            expected_requests,
            "worker latency sample vector",
        )?;
        let barrier = Arc::clone(&barrier);
        let channels = Arc::clone(&channels);
        tasks.push(AbortOnDrop::new(tokio::spawn(async move {
            worker_loop(
                worker_id,
                in_flight,
                requests,
                expected_requests,
                worker_latencies,
                channels,
                barrier,
            )
            .await
        })));
    }

    let workload_started = Instant::now();
    barrier.wait().await;
    let mut total = RpcCounts::default();
    for task in tasks {
        let worker = task
            .join("GRPC_WORKER_TASK_FAILED", "gRPC worker")
            .await??;
        total.merge(&worker.counts)?;
        successful_latencies_us.extend(worker.successful_latencies_us);
    }
    let expected_attempted = usize_to_u64(requests, "requested RPC count")?;
    if total.attempted != expected_attempted {
        return Err(ProbeError::new(
            "GRPC_INTERNAL_ERROR",
            format!(
                "gRPC workers attempted {} requests, expected {expected_attempted}",
                total.attempted
            ),
        ));
    }
    let workload_elapsed_us = elapsed_us(workload_started, "workload elapsed time")?;
    Ok((total, successful_latencies_us, workload_elapsed_us))
}

async fn worker_loop(
    worker_id: usize,
    stride: usize,
    requests: usize,
    expected_requests: usize,
    mut successful_latencies_us: Vec<u64>,
    channels: Arc<Vec<Channel>>,
    barrier: Arc<Barrier>,
) -> ProbeResult<WorkerReport> {
    barrier.wait().await;
    let mut counts = RpcCounts::default();
    let mut request_index = worker_id;
    while request_index < requests {
        let channel_index = request_index % channels.len();
        let channel = channels.get(channel_index).cloned().ok_or_else(|| {
            ProbeError::new(
                "GRPC_INTERNAL_ERROR",
                "gRPC request channel selection was out of bounds",
            )
        })?;
        let mut client = admin_client(channel);
        let observation = status_observation(&mut client).await?;
        counts.record(&observation)?;
        if let RpcObservation::Success { latency_us } = observation {
            successful_latencies_us.push(latency_us);
        }
        request_index = request_index.checked_add(stride).ok_or_else(|| {
            ProbeError::new(
                "ARITHMETIC_OVERFLOW",
                "gRPC worker request index overflowed",
            )
        })?;
    }
    if counts.attempted != usize_to_u64(expected_requests, "worker request count")? {
        return Err(ProbeError::new(
            "GRPC_INTERNAL_ERROR",
            "gRPC worker request distribution was inconsistent",
        ));
    }
    Ok(WorkerReport {
        counts,
        successful_latencies_us,
    })
}

async fn status_observation(
    client: &mut AdminServiceClient<Channel>,
) -> ProbeResult<RpcObservation> {
    status_observation_with_timeout(client, RPC_TIMEOUT).await
}

async fn status_observation_with_timeout(
    client: &mut AdminServiceClient<Channel>,
    timeout: Duration,
) -> ProbeResult<RpcObservation> {
    let started = Instant::now();
    let request = tonic::Request::new(StatusRequest {
        include_realms: false,
    });
    let result = tokio::time::timeout(timeout, client.status(request)).await;
    match result {
        Ok(Ok(_response)) => Ok(RpcObservation::Success {
            latency_us: elapsed_us(started, "successful RPC latency")?,
        }),
        Ok(Err(status)) => Ok(RpcObservation::GrpcFailure(status.code())),
        Err(_elapsed) => Ok(RpcObservation::ClientTimeout),
    }
}

impl RpcCounts {
    fn record(&mut self, observation: &RpcObservation) -> ProbeResult<()> {
        self.attempted = checked_increment(self.attempted, "RPC attempted count")?;
        match observation {
            RpcObservation::Success { .. } => {
                self.succeeded = checked_increment(self.succeeded, "RPC success count")?;
            }
            RpcObservation::ClientTimeout => {
                self.client_timeouts =
                    checked_increment(self.client_timeouts, "RPC client timeout count")?;
            }
            RpcObservation::GrpcFailure(code) => self.grpc_failures.increment(*code)?,
        }
        Ok(())
    }

    fn merge(&mut self, other: &Self) -> ProbeResult<()> {
        self.attempted = checked_add(self.attempted, other.attempted, "RPC attempted count")?;
        self.succeeded = checked_add(self.succeeded, other.succeeded, "RPC success count")?;
        self.client_timeouts = checked_add(
            self.client_timeouts,
            other.client_timeouts,
            "RPC client timeout count",
        )?;
        self.grpc_failures.merge(&other.grpc_failures)
    }
}

impl GrpcCodeCounts {
    fn increment(&mut self, code: Code) -> ProbeResult<()> {
        let (counter, name) = match code {
            Code::Ok => (&mut self.ok, "ok"),
            Code::Cancelled => (&mut self.cancelled, "cancelled"),
            Code::Unknown => (&mut self.unknown, "unknown"),
            Code::InvalidArgument => (&mut self.invalid_argument, "invalid_argument"),
            Code::DeadlineExceeded => (&mut self.deadline_exceeded, "deadline_exceeded"),
            Code::NotFound => (&mut self.not_found, "not_found"),
            Code::AlreadyExists => (&mut self.already_exists, "already_exists"),
            Code::PermissionDenied => (&mut self.permission_denied, "permission_denied"),
            Code::ResourceExhausted => (&mut self.resource_exhausted, "resource_exhausted"),
            Code::FailedPrecondition => (&mut self.failed_precondition, "failed_precondition"),
            Code::Aborted => (&mut self.aborted, "aborted"),
            Code::OutOfRange => (&mut self.out_of_range, "out_of_range"),
            Code::Unimplemented => (&mut self.unimplemented, "unimplemented"),
            Code::Internal => (&mut self.internal, "internal"),
            Code::Unavailable => (&mut self.unavailable, "unavailable"),
            Code::DataLoss => (&mut self.data_loss, "data_loss"),
            Code::Unauthenticated => (&mut self.unauthenticated, "unauthenticated"),
        };
        *counter = checked_increment(*counter, name)?;
        Ok(())
    }

    fn merge(&mut self, other: &Self) -> ProbeResult<()> {
        self.ok = checked_add(self.ok, other.ok, "gRPC ok status count")?;
        self.cancelled = checked_add(
            self.cancelled,
            other.cancelled,
            "gRPC cancelled status count",
        )?;
        self.unknown = checked_add(self.unknown, other.unknown, "gRPC unknown status count")?;
        self.invalid_argument = checked_add(
            self.invalid_argument,
            other.invalid_argument,
            "gRPC invalid-argument status count",
        )?;
        self.deadline_exceeded = checked_add(
            self.deadline_exceeded,
            other.deadline_exceeded,
            "gRPC deadline-exceeded status count",
        )?;
        self.not_found = checked_add(
            self.not_found,
            other.not_found,
            "gRPC not-found status count",
        )?;
        self.already_exists = checked_add(
            self.already_exists,
            other.already_exists,
            "gRPC already-exists status count",
        )?;
        self.permission_denied = checked_add(
            self.permission_denied,
            other.permission_denied,
            "gRPC permission-denied status count",
        )?;
        self.resource_exhausted = checked_add(
            self.resource_exhausted,
            other.resource_exhausted,
            "gRPC resource-exhausted status count",
        )?;
        self.failed_precondition = checked_add(
            self.failed_precondition,
            other.failed_precondition,
            "gRPC failed-precondition status count",
        )?;
        self.aborted = checked_add(self.aborted, other.aborted, "gRPC aborted status count")?;
        self.out_of_range = checked_add(
            self.out_of_range,
            other.out_of_range,
            "gRPC out-of-range status count",
        )?;
        self.unimplemented = checked_add(
            self.unimplemented,
            other.unimplemented,
            "gRPC unimplemented status count",
        )?;
        self.internal = checked_add(self.internal, other.internal, "gRPC internal status count")?;
        self.unavailable = checked_add(
            self.unavailable,
            other.unavailable,
            "gRPC unavailable status count",
        )?;
        self.data_loss = checked_add(
            self.data_loss,
            other.data_loss,
            "gRPC data-loss status count",
        )?;
        self.unauthenticated = checked_add(
            self.unauthenticated,
            other.unauthenticated,
            "gRPC unauthenticated status count",
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn total(&self) -> ProbeResult<u64> {
        let values = [
            self.ok,
            self.cancelled,
            self.unknown,
            self.invalid_argument,
            self.deadline_exceeded,
            self.not_found,
            self.already_exists,
            self.permission_denied,
            self.resource_exhausted,
            self.failed_precondition,
            self.aborted,
            self.out_of_range,
            self.unimplemented,
            self.internal,
            self.unavailable,
            self.data_loss,
            self.unauthenticated,
        ];
        values.into_iter().try_fold(0_u64, |total, value| {
            checked_add(total, value, "gRPC failure status total")
        })
    }
}

impl LatencySummary {
    fn from_samples(samples: &mut [u64]) -> ProbeResult<Self> {
        samples.sort_unstable();
        let sample_count = usize_to_u64(samples.len(), "latency sample count")?;
        let mut cumulative_histogram = Vec::new();
        reserve_exact(
            &mut cumulative_histogram,
            HISTOGRAM_BUCKETS_US.len(),
            "latency histogram vector",
        )?;
        let mut last_count = 0_u64;
        for upper_bound in HISTOGRAM_BUCKETS_US {
            let count = usize_to_u64(
                samples.partition_point(|sample| *sample <= upper_bound),
                "latency histogram bucket count",
            )?;
            cumulative_histogram.push(LatencyBucket {
                less_than_or_equal: upper_bound,
                count,
            });
            last_count = count;
        }
        let above_highest_bucket = sample_count.checked_sub(last_count).ok_or_else(|| {
            ProbeError::new(
                "ARITHMETIC_OVERFLOW",
                "latency histogram overflow count underflowed",
            )
        })?;
        let total = samples.iter().try_fold(0_u128, |sum, sample| {
            sum.checked_add(u128::from(*sample)).ok_or_else(|| {
                ProbeError::new("ARITHMETIC_OVERFLOW", "latency sample sum overflowed")
            })
        })?;
        let mean = if samples.is_empty() {
            None
        } else {
            let divisor = u128::try_from(samples.len()).map_err(|error| {
                ProbeError::new(
                    "ARITHMETIC_OVERFLOW",
                    format!("convert latency sample divisor: {error}"),
                )
            })?;
            Some(u64::try_from(total / divisor).map_err(|error| {
                ProbeError::new(
                    "ARITHMETIC_OVERFLOW",
                    format!("convert mean latency: {error}"),
                )
            })?)
        };
        Ok(Self {
            sample_method: "all_successful_requests",
            samples: sample_count,
            min: samples.first().copied(),
            p50: percentile(samples, 50)?,
            p95: percentile(samples, 95)?,
            p99: percentile(samples, 99)?,
            max: samples.last().copied(),
            mean,
            cumulative_histogram,
            above_highest_bucket,
        })
    }
}

fn percentile(sorted_samples: &[u64], percent: usize) -> ProbeResult<Option<u64>> {
    if percent > 100 {
        return Err(ProbeError::new(
            "GRPC_INTERNAL_ERROR",
            "latency percentile must not exceed 100",
        ));
    }
    let Some(last_index) = sorted_samples.len().checked_sub(1) else {
        return Ok(None);
    };
    let numerator = last_index
        .checked_mul(percent)
        .ok_or_else(|| ProbeError::new("ARITHMETIC_OVERFLOW", "latency percentile overflowed"))?;
    // Match the evidence shell's `int(p * (n - 1) / 100 + 0.5)` convention.
    let rounded = numerator.checked_add(50).ok_or_else(|| {
        ProbeError::new(
            "ARITHMETIC_OVERFLOW",
            "latency percentile rounding overflowed",
        )
    })? / 100;
    sorted_samples.get(rounded).copied().map_or_else(
        || {
            Err(ProbeError::new(
                "GRPC_INTERNAL_ERROR",
                "latency percentile index was out of bounds",
            ))
        },
        |sample| Ok(Some(sample)),
    )
}

fn worker_request_count(worker_id: usize, workers: usize, requests: usize) -> ProbeResult<usize> {
    if workers == 0 {
        return Err(ProbeError::new(
            "GRPC_INTERNAL_ERROR",
            "gRPC worker count was zero",
        ));
    }
    if worker_id >= requests {
        return Ok(0);
    }
    let after_first = requests
        .checked_sub(worker_id)
        .and_then(|remaining| remaining.checked_sub(1))
        .ok_or_else(|| {
            ProbeError::new(
                "ARITHMETIC_OVERFLOW",
                "gRPC worker request count underflowed",
            )
        })?;
    after_first
        .checked_div(workers)
        .and_then(|additional| additional.checked_add(1))
        .ok_or_else(|| {
            ProbeError::new(
                "ARITHMETIC_OVERFLOW",
                "gRPC worker request count overflowed",
            )
        })
}

fn milli_requests_per_second(count: u64, elapsed_microseconds: u64) -> ProbeResult<u64> {
    let denominator = elapsed_microseconds.max(1);
    count
        .checked_mul(MILLI_RATE_SCALE)
        .and_then(|scaled| scaled.checked_div(denominator))
        .ok_or_else(|| {
            ProbeError::new(
                "ARITHMETIC_OVERFLOW",
                "gRPC throughput calculation overflowed",
            )
        })
}

fn elapsed_us(started: Instant, field: &str) -> ProbeResult<u64> {
    duration_micros(started.elapsed(), field)
}

fn duration_micros(duration: Duration, field: &str) -> ProbeResult<u64> {
    u64::try_from(duration.as_micros()).map_err(|error| {
        ProbeError::new("ARITHMETIC_OVERFLOW", format!("convert {field}: {error}"))
    })
}

fn duration_millis(duration: Duration, field: &str) -> ProbeResult<u64> {
    u64::try_from(duration.as_millis()).map_err(|error| {
        ProbeError::new("ARITHMETIC_OVERFLOW", format!("convert {field}: {error}"))
    })
}

fn usize_to_u64(value: usize, field: &str) -> ProbeResult<u64> {
    u64::try_from(value).map_err(|error| {
        ProbeError::new("ARITHMETIC_OVERFLOW", format!("convert {field}: {error}"))
    })
}

fn checked_add(left: u64, right: u64, field: &str) -> ProbeResult<u64> {
    left.checked_add(right)
        .ok_or_else(|| ProbeError::new("ARITHMETIC_OVERFLOW", format!("{field} overflowed")))
}

fn checked_increment(value: u64, field: &str) -> ProbeResult<u64> {
    checked_add(value, 1, field)
}

fn reserve_exact<T>(values: &mut Vec<T>, additional: usize, field: &str) -> ProbeResult<()> {
    values
        .try_reserve_exact(additional)
        .map_err(|error| ProbeError::new("ALLOCATION_FAILED", format!("reserve {field}: {error}")))
}

fn load_limits() -> ProbeResult<LoadLimits> {
    Ok(LoadLimits {
        max_connections: MAX_CONNECTIONS,
        max_in_flight: MAX_IN_FLIGHT,
        max_requests: MAX_REQUESTS,
        max_hold_ms: duration_millis(MAX_HOLD, "maximum hold duration")?,
        connect_concurrency: CONNECT_CONCURRENCY,
        connect_timeout_ms: duration_millis(CONNECT_TIMEOUT, "connection timeout")?,
        rpc_timeout_ms: duration_millis(RPC_TIMEOUT, "RPC timeout")?,
        overall_timeout_ms: duration_millis(OVERALL_TIMEOUT, "overall timeout")?,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]

    use std::io;
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::{SystemTime, UNIX_EPOCH};

    use basil_proto::broker::v1 as pb;
    use basil_proto::broker::v1::admin_service_server::{AdminService, AdminServiceServer};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::oneshot;
    use tokio_stream::StreamExt;
    use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};

    use super::*;

    static NEXT_SOCKET_ID: AtomicUsize = AtomicUsize::new(0);

    #[derive(Default)]
    struct ConnectionState {
        accepted: AtomicUsize,
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    struct TrackedStream {
        inner: UnixStream,
        connections: Arc<ConnectionState>,
    }

    impl TrackedStream {
        fn new(inner: UnixStream, connections: Arc<ConnectionState>) -> Self {
            connections.accepted.fetch_add(1, Ordering::SeqCst);
            let active = connections
                .active
                .fetch_add(1, Ordering::SeqCst)
                .saturating_add(1);
            connections.max_active.fetch_max(active, Ordering::SeqCst);
            Self { inner, connections }
        }
    }

    impl Drop for TrackedStream {
        fn drop(&mut self) {
            self.connections.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl AsyncRead for TrackedStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(context, buffer)
        }
    }

    impl AsyncWrite for TrackedStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(context, buffer)
        }

        fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(context)
        }
    }

    impl tonic::transport::server::Connected for TrackedStream {
        type ConnectInfo = ();

        fn connect_info(&self) -> Self::ConnectInfo {}
    }

    struct MockState {
        calls: AtomicUsize,
        current_in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        warmup_calls: usize,
        warmup_delay: Duration,
        workload_delay: Duration,
        fail_every: Option<usize>,
        failure_code: Code,
    }

    impl MockState {
        fn new(
            warmup_calls: usize,
            warmup_delay: Duration,
            workload_delay: Duration,
            fail_every: Option<usize>,
            failure_code: Code,
        ) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                current_in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                warmup_calls,
                warmup_delay,
                workload_delay,
                fail_every,
                failure_code,
            }
        }

        fn begin_request(self: &Arc<Self>) -> InFlightGuard {
            let current = self
                .current_in_flight
                .fetch_add(1, Ordering::SeqCst)
                .saturating_add(1);
            self.max_in_flight.fetch_max(current, Ordering::SeqCst);
            InFlightGuard {
                state: Arc::clone(self),
            }
        }
    }

    struct InFlightGuard {
        state: Arc<MockState>,
    }

    impl Drop for InFlightGuard {
        fn drop(&mut self) {
            self.state.current_in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Clone)]
    struct MockAdminService {
        state: Arc<MockState>,
    }

    #[tonic::async_trait]
    impl AdminService for MockAdminService {
        type WatchStream = ReceiverStream<Result<pb::Event, Status>>;

        async fn status(
            &self,
            _request: Request<pb::StatusRequest>,
        ) -> Result<Response<pb::StatusResponse>, Status> {
            let ordinal = self.state.calls.fetch_add(1, Ordering::SeqCst);
            let _guard = self.state.begin_request();
            if ordinal < self.state.warmup_calls {
                tokio::time::sleep(self.state.warmup_delay).await;
            } else {
                tokio::time::sleep(self.state.workload_delay).await;
                let workload_ordinal = ordinal.saturating_sub(self.state.warmup_calls);
                if self
                    .state
                    .fail_every
                    .is_some_and(|every| workload_ordinal.is_multiple_of(every))
                {
                    return Err(Status::new(self.state.failure_code, "planned failure"));
                }
            }
            Ok(Response::new(pb::StatusResponse {
                backend: "mock".to_owned(),
                version: "test".to_owned(),
                protocol: 1,
                realms: Vec::new(),
            }))
        }

        async fn health(
            &self,
            _request: Request<pb::HealthRequest>,
        ) -> Result<Response<pb::HealthResponse>, Status> {
            Err(Status::unimplemented("health"))
        }

        async fn readiness(
            &self,
            _request: Request<pb::ReadinessRequest>,
        ) -> Result<Response<pb::ReadinessResponse>, Status> {
            Err(Status::unimplemented("readiness"))
        }

        async fn watch(
            &self,
            _request: Request<pb::WatchRequest>,
        ) -> Result<Response<Self::WatchStream>, Status> {
            Err(Status::unimplemented("watch"))
        }

        async fn reload(
            &self,
            _request: Request<pb::ReloadRequest>,
        ) -> Result<Response<pb::ReloadResponse>, Status> {
            Err(Status::unimplemented("reload"))
        }

        async fn explain(
            &self,
            _request: Request<pb::ExplainRequest>,
        ) -> Result<Response<pb::ExplainResponse>, Status> {
            Err(Status::unimplemented("explain"))
        }

        async fn revoke(
            &self,
            _request: Request<pb::RevokeRequest>,
        ) -> Result<Response<pb::RevokeResponse>, Status> {
            Err(Status::unimplemented("revoke"))
        }
    }

    struct MockServer {
        path: PathBuf,
        shutdown: Option<oneshot::Sender<()>>,
        task: JoinHandle<Result<(), tonic::transport::Error>>,
        connections: Arc<ConnectionState>,
        state: Arc<MockState>,
    }

    impl MockServer {
        async fn shutdown(mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            self.task.await.unwrap().unwrap();
            std::fs::remove_file(&self.path).unwrap();
        }
    }

    fn spawn_mock_server(
        connections: usize,
        delay: Duration,
        fail_every: Option<usize>,
        failure_code: Code,
    ) -> MockServer {
        spawn_mock_server_with_warmup(connections, Duration::ZERO, delay, fail_every, failure_code)
    }

    fn spawn_mock_server_with_warmup(
        connections: usize,
        warmup_delay: Duration,
        workload_delay: Duration,
        fail_every: Option<usize>,
        failure_code: Code,
    ) -> MockServer {
        let path = unique_socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let connection_state = Arc::new(ConnectionState::default());
        let incoming_connections = Arc::clone(&connection_state);
        let incoming = UnixListenerStream::new(listener).map(move |result| {
            let connections = Arc::clone(&incoming_connections);
            result.map(|stream| TrackedStream::new(stream, connections))
        });
        let state = Arc::new(MockState::new(
            connections,
            warmup_delay,
            workload_delay,
            fail_every,
            failure_code,
        ));
        let service = MockAdminService {
            state: Arc::clone(&state),
        };
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(AdminServiceServer::new(service))
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
        });
        MockServer {
            path,
            shutdown: Some(shutdown),
            task,
            connections: connection_state,
            state,
        }
    }

    fn unique_socket_path() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_SOCKET_ID.fetch_add(1, Ordering::SeqCst);
        PathBuf::from(format!(
            "/tmp/basil-grpc-load-{}-{unique}-{sequence}.sock",
            std::process::id()
        ))
    }

    fn config(
        path: &Path,
        connections: usize,
        in_flight: usize,
        requests: usize,
        hold: Duration,
    ) -> LoadConfig {
        LoadConfig {
            socket_path: path.to_owned(),
            connections,
            in_flight,
            requests,
            hold,
        }
    }

    #[test]
    fn parses_bounded_load_arguments_and_default_hold() {
        let args = [
            OsString::from("grpc-status-load"),
            OsString::from("/tmp/basil.sock"),
            OsString::from(MAX_CONNECTIONS.to_string()),
            OsString::from(MAX_IN_FLIGHT.to_string()),
            OsString::from(MAX_REQUESTS.to_string()),
        ];
        let parsed = parse_config(&args).unwrap();
        assert_eq!(parsed.connections, MAX_CONNECTIONS);
        assert_eq!(parsed.in_flight, MAX_IN_FLIGHT);
        assert_eq!(parsed.requests, MAX_REQUESTS);
        assert_eq!(parsed.hold, Duration::ZERO);
    }

    #[test]
    fn rejects_invalid_load_counts_and_hold() {
        let mut args = [
            OsString::from("grpc-status-load"),
            OsString::from("/tmp/basil.sock"),
            OsString::from("1"),
            OsString::from("1"),
            OsString::from("1"),
            OsString::from("0"),
        ];
        args[2] = OsString::from("0");
        assert_eq!(
            parse_config(&args).unwrap_err().code,
            "INVALID_GRPC_LOAD_ARGUMENT"
        );
        args[2] = OsString::from("1");
        args[3] = OsString::from("2");
        assert_eq!(
            parse_config(&args).unwrap_err().code,
            "INVALID_GRPC_LOAD_ARGUMENT"
        );
        args[3] = OsString::from("1");
        args[5] = OsString::from("60001");
        assert_eq!(parse_config(&args).unwrap_err().code, "GRPC_LOAD_LIMIT");
    }

    #[test]
    fn percentiles_match_shell_rounding_and_histogram_is_exact() {
        let mut samples = vec![11_000_000, 1_001, 50, 1_000, 101, 100];
        let summary = LatencySummary::from_samples(&mut samples).unwrap();
        assert_eq!(samples, [50, 100, 101, 1_000, 1_001, 11_000_000]);
        assert_eq!(summary.min, Some(50));
        assert_eq!(summary.p50, Some(1_000));
        assert_eq!(summary.p95, Some(11_000_000));
        assert_eq!(summary.p99, Some(11_000_000));
        assert_eq!(summary.max, Some(11_000_000));
        assert_eq!(summary.cumulative_histogram[0].count, 1);
        assert_eq!(summary.cumulative_histogram[1].count, 2);
        assert_eq!(summary.cumulative_histogram[4].count, 4);
        assert_eq!(summary.cumulative_histogram[5].count, 5);
        assert_eq!(summary.cumulative_histogram[16].count, 5);
        assert_eq!(summary.above_highest_bucket, 1);
    }

    #[test]
    fn worker_distribution_is_deterministic_and_exact() {
        let counts = (0..7)
            .map(|worker| worker_request_count(worker, 7, 25).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(counts, [4, 4, 4, 4, 3, 3, 3]);
        assert_eq!(counts.into_iter().sum::<usize>(), 25);
    }

    #[test]
    fn grpc_failure_codes_remain_separate() {
        let mut counts = RpcCounts::default();
        counts
            .record(&RpcObservation::GrpcFailure(Code::Unavailable))
            .unwrap();
        counts
            .record(&RpcObservation::GrpcFailure(Code::ResourceExhausted))
            .unwrap();
        counts.record(&RpcObservation::ClientTimeout).unwrap();
        assert_eq!(counts.grpc_failures.unavailable, 1);
        assert_eq!(counts.grpc_failures.resource_exhausted, 1);
        assert_eq!(counts.grpc_failures.total().unwrap(), 2);
        assert_eq!(counts.client_timeouts, 1);
        assert_eq!(counts.attempted, 3);
    }

    #[test]
    fn process_and_system_file_descriptor_exhaustion_share_one_cause() {
        for errno in [Errno::MFILE, Errno::NFILE] {
            let error = io::Error::from_raw_os_error(errno.raw_os_error());
            let failure = connection_io_failure(&error);
            assert_eq!(failure.kind, ConnectionFailureKind::FileDescriptorExhausted);
            assert_eq!(failure.raw_os_error, Some(errno.raw_os_error()));
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn uds_load_uses_distinct_connections_and_real_concurrency() {
        let server = spawn_mock_server(2, Duration::from_millis(20), None, Code::Ok);
        let report = execute(config(&server.path, 2, 6, 24, Duration::ZERO))
            .await
            .unwrap();

        assert_eq!(report.connection_setup.requested, 2);
        assert_eq!(report.connection_setup.established, 2);
        assert_eq!(report.connection_setup.failed, 0);
        assert!(report.connection_setup.complete);
        assert_eq!(report.retained_channel_handles, 2);
        assert_eq!(report.warmup_concurrency, 2);
        assert_eq!(report.workload_bearing_channels, 2);
        assert!(report.load_executed);
        assert_eq!(report.load_skipped_reason, None);
        assert_eq!(server.connections.accepted.load(Ordering::SeqCst), 2);
        assert_eq!(server.connections.max_active.load(Ordering::SeqCst), 2);
        assert_eq!(server.state.calls.load(Ordering::SeqCst), 26);
        assert_eq!(server.state.max_in_flight.load(Ordering::SeqCst), 6);
        assert_eq!(report.warmup.attempted, 2);
        assert_eq!(report.warmup.succeeded, 2);
        assert_eq!(report.workload.attempted, 24);
        assert_eq!(report.workload.succeeded, 24);
        assert_eq!(report.latency_us.samples, 24);
        assert!(report.latency_us.min <= report.latency_us.p50);
        assert!(report.latency_us.p50 <= report.latency_us.p95);
        assert!(report.latency_us.p95 <= report.latency_us.p99);
        assert!(report.latency_us.p99 <= report.latency_us.max);
        for pair in report.latency_us.cumulative_histogram.windows(2) {
            assert!(pair[0].less_than_or_equal < pair[1].less_than_or_equal);
            assert!(pair[0].count <= pair[1].count);
        }
        let final_bucket = report.latency_us.cumulative_histogram.last().unwrap().count;
        assert_eq!(
            final_bucket + report.latency_us.above_highest_bucket,
            report.latency_us.samples
        );
        server.shutdown().await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn uds_load_reports_grpc_failures_without_aborting() {
        let server = spawn_mock_server(
            3,
            Duration::from_millis(2),
            Some(2),
            Code::ResourceExhausted,
        );
        let report = execute(config(&server.path, 3, 4, 12, Duration::ZERO))
            .await
            .unwrap();

        assert_eq!(server.connections.accepted.load(Ordering::SeqCst), 3);
        assert_eq!(server.state.calls.load(Ordering::SeqCst), 15);
        assert_eq!(report.workload.attempted, 12);
        assert_eq!(report.workload.succeeded, 6);
        assert_eq!(report.workload.client_timeouts, 0);
        assert_eq!(report.workload.grpc_failures.resource_exhausted, 6);
        assert_eq!(report.workload.grpc_failures.total().unwrap(), 6);
        assert_eq!(report.latency_us.samples, 6);
        server.shutdown().await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn warmup_respects_the_requested_in_flight_cap() {
        let server = spawn_mock_server_with_warmup(
            8,
            Duration::from_millis(20),
            Duration::ZERO,
            None,
            Code::Ok,
        );
        let setup = connect_channels(Arc::new(server.path.clone()), 8)
            .await
            .unwrap();
        let warmup = warm_channels(&setup.channels, 2).await.unwrap();

        assert_eq!(warmup.attempted, 8);
        assert_eq!(warmup.succeeded, 8);
        assert_eq!(server.state.max_in_flight.load(Ordering::SeqCst), 2);
        drop(setup);
        server.shutdown().await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timed_out_rpc_is_cancelled_and_the_channel_remains_reusable() {
        let server = spawn_mock_server(0, Duration::from_millis(100), None, Code::Ok);
        let setup = connect_channels(Arc::new(server.path.clone()), 1)
            .await
            .unwrap();
        let channel = setup.channels.first().cloned().unwrap();
        let mut client = admin_client(channel);

        let timed_out = status_observation_with_timeout(&mut client, Duration::from_millis(10))
            .await
            .unwrap();
        assert!(matches!(timed_out, RpcObservation::ClientTimeout));
        tokio::time::timeout(Duration::from_secs(1), async {
            while server.state.current_in_flight.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();

        let reused = status_observation_with_timeout(&mut client, Duration::from_millis(500))
            .await
            .unwrap();
        assert!(matches!(reused, RpcObservation::Success { .. }));
        drop(client);
        drop(setup);
        server.shutdown().await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unavailable_socket_reports_partial_connection_evidence() {
        let path = unique_socket_path();
        let report = execute(config(&path, 3, 2, 4, Duration::ZERO))
            .await
            .unwrap();

        assert_eq!(report.connection_setup.requested, 3);
        assert_eq!(report.connection_setup.attempted, 3);
        assert_eq!(report.connection_setup.established, 0);
        assert_eq!(report.connection_setup.failed, 3);
        assert!(!report.connection_setup.complete);
        assert_eq!(report.connection_setup.failure_causes.len(), 1);
        assert_eq!(
            report.connection_setup.failure_causes[0].cause,
            "socket_not_found"
        );
        assert_eq!(report.connection_setup.failure_causes[0].count, 3);
        assert_eq!(report.retained_channel_handles, 0);
        assert_eq!(report.warmup_concurrency, 0);
        assert_eq!(report.workload_bearing_channels, 0);
        assert!(!report.load_executed);
        assert_eq!(
            report.load_skipped_reason,
            Some("no_connections_established")
        );
        assert_eq!(report.warmup.attempted, 0);
        assert_eq!(report.workload.attempted, 0);
        assert_eq!(report.latency_us.samples, 0);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn uds_load_keeps_all_channels_alive_during_hold() {
        let server = spawn_mock_server(4, Duration::from_millis(2), None, Code::Ok);
        let state = Arc::clone(&server.state);
        let connections = Arc::clone(&server.connections);
        let task = tokio::spawn(execute(config(
            &server.path,
            4,
            2,
            2,
            Duration::from_millis(200),
        )));

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.calls.load(Ordering::SeqCst) == 6
                    && state.current_in_flight.load(Ordering::SeqCst) == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(!task.is_finished());
        assert_eq!(connections.active.load(Ordering::SeqCst), 4);

        let report = task.await.unwrap().unwrap();
        assert!(report.hold_elapsed_us >= 150_000);
        server.shutdown().await;
    }
}
