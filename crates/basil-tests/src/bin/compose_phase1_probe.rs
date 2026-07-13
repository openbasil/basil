// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::Builder;

const SCHEMA: &str = "basil.compose.phase1.probe/v1";
const MAX_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_TEXT_FILE_BYTES: usize = 256 * 1024;
const MAX_ERROR_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_CGROUP_ENTRIES: usize = 64;
const MAX_MAP_RANGES: usize = 64;
const MAX_CONTROLLERS: usize = 64;
const MAX_PROJECTION_DEPTH: usize = 64;
const MAX_PROJECTION_NODES: usize = 1_000_000;
const DEFAULT_PEER_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PEER_TIMEOUT: Duration = Duration::from_secs(60);
const TARGET_CONTAINERS: u64 = 1_000;
const SCALE_LADDER: [u64; 8] = [1, 10, 50, 100, 250, 500, 750, 1_000];

#[derive(Debug)]
struct ProbeError {
    code: &'static str,
    message: String,
}

impl ProbeError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: bounded_text(&message.into(), MAX_ERROR_BYTES),
        }
    }

    fn io(code: &'static str, context: &str, error: &io::Error) -> Self {
        Self::new(code, format!("{context}: {error}"))
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ProbeError {}

type ProbeResult<T> = Result<T, ProbeError>;

#[derive(Serialize)]
struct SuccessEnvelope<'a, T> {
    schema: &'static str,
    ok: bool,
    kind: &'a str,
    data: T,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    schema: &'static str,
    ok: bool,
    kind: &'a str,
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct IdMapRange {
    inside_id: u64,
    outside_id: u64,
    length: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CgroupEntry {
    hierarchy_id: u64,
    controllers: String,
    path: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct NamespaceFact {
    name: String,
    inode: Option<u64>,
    target: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct LivenessFact {
    alive_after_snapshot: bool,
    start_time_unchanged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProcessFacts {
    pid: u32,
    state: String,
    start_time_ticks: u64,
    cgroups: Vec<CgroupEntry>,
    namespaces: Vec<NamespaceFact>,
    uid_map: Vec<IdMapRange>,
    gid_map: Vec<IdMapRange>,
    uids: Option<[u64; 4]>,
    gids: Option<[u64; 4]>,
    no_new_privs: Option<u64>,
    seccomp_mode: Option<u64>,
    liveness: LivenessFact,
}

#[derive(Debug, Serialize)]
struct HostProcessSnapshot {
    captured_unix_ms: u128,
    os: &'static str,
    architecture: &'static str,
    logical_cpus: Option<usize>,
    cgroup_v2: bool,
    cgroup_controllers: Vec<String>,
    memory: BTreeMap<String, u64>,
    kernel_limits: BTreeMap<String, u64>,
    process: ProcessFacts,
}

#[derive(Debug, Serialize)]
struct PeerCredentials {
    pid: i32,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Serialize)]
struct PeerObservation {
    role: &'static str,
    socket_path: String,
    peer: PeerCredentials,
}

#[derive(Clone, Copy, Debug)]
struct ProjectionLimits {
    max_depth: usize,
    max_nodes: usize,
}

#[derive(Debug, Serialize)]
struct ProjectionMetrics {
    input_bytes: usize,
    nodes: usize,
    max_depth: usize,
    object_entries: usize,
    array_items: usize,
    string_values: usize,
    string_bytes: usize,
    max_string_bytes: usize,
    numbers: usize,
    booleans: usize,
    nulls: usize,
    probe_input_limit_bytes: usize,
    probe_depth_limit: usize,
    probe_node_limit: usize,
    final_protocol_ceiling_evidence: bool,
}

#[derive(Debug, Serialize)]
struct CapacityMetadata {
    purpose: &'static str,
    target_containers: u64,
    scale_ladder: &'static [u64],
    required_runtime_lanes: [&'static str; 2],
    creates_containers: bool,
    final_protocol_ceiling_evidence: bool,
    probe_bounds: ProbeBounds,
    stop_condition_categories: [&'static str; 7],
}

#[derive(Debug, Serialize)]
struct ProbeBounds {
    output_bytes: usize,
    input_bytes: usize,
    projection_depth: usize,
    projection_nodes: usize,
    cgroup_entries: usize,
    id_map_ranges: usize,
    peer_timeout_ms: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FactMatch {
    Match,
    Mismatch,
}

impl FactMatch {
    const fn from_bool(value: bool) -> Self {
        if value { Self::Match } else { Self::Mismatch }
    }

    const fn is_match(self) -> bool {
        matches!(self, Self::Match)
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct ProcessFactComparison {
    pid: FactMatch,
    start_time: FactMatch,
    cgroups: FactMatch,
    namespaces: FactMatch,
    uid_map: FactMatch,
    gid_map: FactMatch,
    credentials: FactMatch,
    binding_unchanged: bool,
}

#[derive(Debug, Serialize)]
struct ProcessComparisonSnapshot {
    interval_ms: u128,
    before: ProcessFacts,
    after: ProcessFacts,
    comparison: ProcessFactComparison,
}

#[derive(Debug)]
struct ProcStat {
    state: String,
    start_time_ticks: u64,
}

struct SocketPathGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketPathGuard {
    fn new(path: &Path) -> ProbeResult<Self> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            ProbeError::io(
                "PEER_SOCKET_METADATA_FAILED",
                "inspect bound Unix socket",
                &error,
            )
        })?;
        if !metadata.file_type().is_socket() {
            return Err(ProbeError::new(
                "PEER_SOCKET_TYPE_INVALID",
                "bound Unix socket path did not identify a socket",
            ));
        }
        Ok(Self {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _result = fs::remove_file(&self.path);
        }
    }
}

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let args: Vec<OsString> = args.take(5).collect();
    let command = args
        .first()
        .and_then(|value| value.to_str())
        .unwrap_or("usage");

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            emit_error(command, &error);
            ExitCode::from(2)
        }
    }
}

fn run(args: &[OsString]) -> ProbeResult<()> {
    let Some(command) = args.first().and_then(|value| value.to_str()) else {
        return Err(ProbeError::new("USAGE", usage()));
    };

    match command {
        "host-process-snapshot" if args.len() == 1 => {
            emit_success(command, host_process_snapshot()?)
        }
        "process-facts" if args.len() <= 2 => {
            let pid = args
                .get(1)
                .map_or_else(|| Ok(std::process::id()), |value| parse_pid(value))?;
            emit_success(command, snapshot_process(pid)?)
        }
        "process-compare" if (2..=3).contains(&args.len()) => {
            let pid = parse_pid(required_arg(args, 1, "PID")?)?;
            let interval = parse_interval(args.get(2))?;
            emit_success(command, compare_process(pid, interval)?)
        }
        "peer-listen" if (2..=3).contains(&args.len()) => {
            let timeout = parse_timeout(args.get(2))?;
            emit_success(
                command,
                peer_listen(Path::new(required_arg(args, 1, "socket path")?), timeout)?,
            )
        }
        "peer-connect" if (2..=3).contains(&args.len()) => {
            let timeout = parse_timeout(args.get(2))?;
            emit_success(
                command,
                peer_connect(Path::new(required_arg(args, 1, "socket path")?), timeout)?,
            )
        }
        "projection-size" if args.len() <= 2 => {
            let source = args
                .get(1)
                .map_or_else(|| OsStr::new("-"), OsString::as_os_str);
            emit_success(command, projection_size(source)?)
        }
        "capacity-metadata" if args.len() == 1 => emit_success(command, capacity_metadata()),
        _ => Err(ProbeError::new("USAGE", usage())),
    }
}

const fn usage() -> &'static str {
    "usage: compose_phase1_probe <host-process-snapshot|process-facts [PID]|process-compare PID [INTERVAL_MS]|peer-listen SOCKET [TIMEOUT_MS]|peer-connect SOCKET [TIMEOUT_MS]|projection-size [FILE|-]|capacity-metadata>"
}

fn required_arg<'a>(args: &'a [OsString], index: usize, name: &str) -> ProbeResult<&'a OsStr> {
    args.get(index)
        .map(OsString::as_os_str)
        .ok_or_else(|| ProbeError::new("USAGE", format!("missing required argument: {name}")))
}

fn parse_pid(value: &OsStr) -> ProbeResult<u32> {
    let text = value
        .to_str()
        .ok_or_else(|| ProbeError::new("INVALID_PID", "PID must be valid UTF-8 decimal text"))?;
    let pid = text
        .parse::<u32>()
        .map_err(|error| ProbeError::new("INVALID_PID", format!("invalid PID: {error}")))?;
    if pid == 0 {
        return Err(ProbeError::new(
            "INVALID_PID",
            "PID must be greater than zero",
        ));
    }
    Ok(pid)
}

fn parse_timeout(value: Option<&OsString>) -> ProbeResult<Duration> {
    let Some(value) = value else {
        return Ok(DEFAULT_PEER_TIMEOUT);
    };
    let text = value.to_str().ok_or_else(|| {
        ProbeError::new(
            "INVALID_TIMEOUT",
            "timeout must be valid UTF-8 decimal text",
        )
    })?;
    let milliseconds = text
        .parse::<u64>()
        .map_err(|error| ProbeError::new("INVALID_TIMEOUT", format!("invalid timeout: {error}")))?;
    let timeout = Duration::from_millis(milliseconds);
    if timeout.is_zero() || timeout > MAX_PEER_TIMEOUT {
        return Err(ProbeError::new(
            "INVALID_TIMEOUT",
            "timeout must be between 1 and 60000 milliseconds",
        ));
    }
    Ok(timeout)
}

fn parse_interval(value: Option<&OsString>) -> ProbeResult<Duration> {
    let Some(value) = value else {
        return Ok(Duration::ZERO);
    };
    let text = value.to_str().ok_or_else(|| {
        ProbeError::new(
            "INVALID_INTERVAL",
            "interval must be valid UTF-8 decimal text",
        )
    })?;
    let milliseconds = text.parse::<u64>().map_err(|error| {
        ProbeError::new("INVALID_INTERVAL", format!("invalid interval: {error}"))
    })?;
    let interval = Duration::from_millis(milliseconds);
    if interval > Duration::from_secs(10) {
        return Err(ProbeError::new(
            "INVALID_INTERVAL",
            "interval must not exceed 10000 milliseconds",
        ));
    }
    Ok(interval)
}

fn emit_success<T: Serialize>(kind: &str, data: T) -> ProbeResult<()> {
    let envelope = SuccessEnvelope {
        schema: SCHEMA,
        ok: true,
        kind,
        data,
    };
    let mut encoded = serde_json::to_vec(&envelope).map_err(|error| {
        ProbeError::new("JSON_ENCODE_FAILED", format!("encode output: {error}"))
    })?;
    if encoded.len() >= MAX_OUTPUT_BYTES {
        return Err(ProbeError::new(
            "OUTPUT_LIMIT",
            "probe output exceeded its fixed byte limit",
        ));
    }
    encoded.push(b'\n');
    io::stdout()
        .lock()
        .write_all(&encoded)
        .map_err(|error| ProbeError::io("OUTPUT_WRITE_FAILED", "write stdout", &error))
}

fn emit_error(kind: &str, error: &ProbeError) {
    let envelope = ErrorEnvelope {
        schema: SCHEMA,
        ok: false,
        kind: &bounded_text(kind, 64),
        error: ErrorBody {
            code: error.code,
            message: &error.message,
        },
    };
    let mut stderr = io::stderr().lock();
    let encoded = serde_json::to_writer(&mut stderr, &envelope).is_ok();
    if !encoded || stderr.write_all(b"\n").is_err() {
        let _result = writeln!(io::stderr(), "probe error: {}", error.code);
    }
}

fn bounded_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value[..end].to_owned()
}

fn host_process_snapshot() -> ProbeResult<HostProcessSnapshot> {
    let captured_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ProbeError::new("CLOCK_ERROR", format!("system clock: {error}")))?
        .as_millis();
    let logical_cpus = thread::available_parallelism().ok().map(Into::into);
    let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").is_file();
    let cgroup_controllers = read_words(Path::new("/sys/fs/cgroup/cgroup.controllers"))
        .unwrap_or_default()
        .into_iter()
        .take(MAX_CONTROLLERS)
        .collect();
    let memory = selected_meminfo()?;
    let kernel_limits = selected_kernel_limits();
    let process = snapshot_process(std::process::id())?;

    Ok(HostProcessSnapshot {
        captured_unix_ms,
        os: env::consts::OS,
        architecture: env::consts::ARCH,
        logical_cpus,
        cgroup_v2,
        cgroup_controllers,
        memory,
        kernel_limits,
        process,
    })
}

fn selected_meminfo() -> ProbeResult<BTreeMap<String, u64>> {
    let text = read_bounded_text(Path::new("/proc/meminfo"), MAX_TEXT_FILE_BYTES)
        .map_err(|error| ProbeError::io("MEMINFO_READ_FAILED", "read /proc/meminfo", &error))?;
    let selected = ["MemTotal", "MemAvailable", "SwapTotal", "SwapFree"];
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if !selected.contains(&name) {
            continue;
        }
        let Some(number) = rest.split_whitespace().next() else {
            continue;
        };
        if let Ok(value) = number.parse::<u64>() {
            result.insert(format!("{}_kib", name.to_ascii_lowercase()), value);
        }
    }
    Ok(result)
}

fn selected_kernel_limits() -> BTreeMap<String, u64> {
    let paths = [
        ("pid_max", "/proc/sys/kernel/pid_max"),
        ("threads_max", "/proc/sys/kernel/threads-max"),
        ("file_max", "/proc/sys/fs/file-max"),
        ("max_user_namespaces", "/proc/sys/user/max_user_namespaces"),
        ("max_pid_namespaces", "/proc/sys/user/max_pid_namespaces"),
        ("max_mnt_namespaces", "/proc/sys/user/max_mnt_namespaces"),
        ("max_net_namespaces", "/proc/sys/user/max_net_namespaces"),
    ];
    paths
        .into_iter()
        .filter_map(|(name, path)| read_u64(Path::new(path)).ok().map(|value| (name, value)))
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
}

fn snapshot_process(pid: u32) -> ProbeResult<ProcessFacts> {
    let stat = process_stat(pid)?;
    let base = PathBuf::from(format!("/proc/{pid}"));
    let cgroups = parse_cgroups(&read_process_file(&base, "cgroup")?)?;
    let namespaces = snapshot_namespaces(&base);
    let uid_map = parse_id_map(&read_process_file(&base, "uid_map")?)?;
    let gid_map = parse_id_map(&read_process_file(&base, "gid_map")?)?;
    let status = read_process_file(&base, "status")?;
    let uids = parse_status_quad(&status, "Uid:");
    let gids = parse_status_quad(&status, "Gid:");
    let no_new_privs = parse_status_scalar(&status, "NoNewPrivs:");
    let seccomp_mode = parse_status_scalar(&status, "Seccomp:");
    let final_stat = process_stat(pid).ok();
    let liveness = LivenessFact {
        alive_after_snapshot: final_stat.is_some(),
        start_time_unchanged: final_stat
            .as_ref()
            .is_some_and(|value| value.start_time_ticks == stat.start_time_ticks),
    };

    Ok(ProcessFacts {
        pid,
        state: stat.state,
        start_time_ticks: stat.start_time_ticks,
        cgroups,
        namespaces,
        uid_map,
        gid_map,
        uids,
        gids,
        no_new_privs,
        seccomp_mode,
        liveness,
    })
}

fn read_process_file(base: &Path, name: &str) -> ProbeResult<String> {
    read_bounded_text(&base.join(name), MAX_TEXT_FILE_BYTES).map_err(|error| {
        ProbeError::io(
            "PROCESS_FACT_READ_FAILED",
            &format!("read process {name}"),
            &error,
        )
    })
}

fn process_stat(pid: u32) -> ProbeResult<ProcStat> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let text = read_bounded_text(&path, 64 * 1024)
        .map_err(|error| ProbeError::io("PROCESS_STAT_READ_FAILED", "read process stat", &error))?;
    parse_proc_stat(pid, &text)
}

fn parse_proc_stat(expected_pid: u32, text: &str) -> ProbeResult<ProcStat> {
    let open = text
        .find('(')
        .ok_or_else(|| ProbeError::new("PROCESS_STAT_INVALID", "process stat has no command"))?;
    let close = text
        .rfind(')')
        .filter(|close| *close > open)
        .ok_or_else(|| {
            ProbeError::new("PROCESS_STAT_INVALID", "process stat command is incomplete")
        })?;
    let parsed_pid = text[..open].trim().parse::<u32>().map_err(|error| {
        ProbeError::new("PROCESS_STAT_INVALID", format!("invalid stat PID: {error}"))
    })?;
    if parsed_pid != expected_pid {
        return Err(ProbeError::new(
            "PROCESS_STAT_MISMATCH",
            "process stat PID did not match the requested PID",
        ));
    }
    let fields: Vec<&str> = text[close.saturating_add(1)..]
        .split_whitespace()
        .take(20)
        .collect();
    if fields.len() < 20 {
        return Err(ProbeError::new(
            "PROCESS_STAT_INVALID",
            "process stat did not contain a start-time field",
        ));
    }
    let state = fields
        .first()
        .and_then(|field| field.chars().next())
        .ok_or_else(|| ProbeError::new("PROCESS_STAT_INVALID", "process stat state was empty"))?;
    let start_time = fields.get(19).ok_or_else(|| {
        ProbeError::new(
            "PROCESS_STAT_INVALID",
            "process stat did not contain a start-time field",
        )
    })?;
    let start_time_ticks = start_time.parse::<u64>().map_err(|error| {
        ProbeError::new(
            "PROCESS_STAT_INVALID",
            format!("invalid process start time: {error}"),
        )
    })?;
    Ok(ProcStat {
        state: state.to_string(),
        start_time_ticks,
    })
}

fn parse_cgroups(text: &str) -> ProbeResult<Vec<CgroupEntry>> {
    let mut entries = Vec::new();
    for line in text.lines() {
        if entries.len() >= MAX_CGROUP_ENTRIES {
            return Err(ProbeError::new(
                "CGROUP_LIMIT",
                "process cgroup entry count exceeded the probe limit",
            ));
        }
        let mut parts = line.splitn(3, ':');
        let hierarchy_id = parts
            .next()
            .ok_or_else(|| ProbeError::new("CGROUP_INVALID", "missing cgroup hierarchy"))?
            .parse::<u64>()
            .map_err(|error| {
                ProbeError::new("CGROUP_INVALID", format!("invalid hierarchy: {error}"))
            })?;
        let controllers = parts
            .next()
            .ok_or_else(|| ProbeError::new("CGROUP_INVALID", "missing cgroup controllers"))?;
        let path = parts
            .next()
            .ok_or_else(|| ProbeError::new("CGROUP_INVALID", "missing cgroup path"))?;
        entries.push(CgroupEntry {
            hierarchy_id,
            controllers: bounded_text(controllers, 1_024),
            path: bounded_text(path, MAX_PATH_BYTES),
        });
    }
    Ok(entries)
}

fn snapshot_namespaces(base: &Path) -> Vec<NamespaceFact> {
    const NAMES: [&str; 8] = [
        "cgroup",
        "ipc",
        "mnt",
        "net",
        "pid",
        "pid_for_children",
        "user",
        "uts",
    ];
    NAMES
        .into_iter()
        .map(|name| {
            let target = fs::read_link(base.join("ns").join(name)).ok();
            let target_text = target
                .as_ref()
                .map(|path| bounded_text(&path.to_string_lossy(), 128));
            let inode = target_text.as_deref().and_then(parse_namespace_inode);
            NamespaceFact {
                name: name.to_owned(),
                inode,
                target: target_text,
            }
        })
        .collect()
}

fn parse_namespace_inode(target: &str) -> Option<u64> {
    let (_, suffix) = target.split_once('[')?;
    suffix.strip_suffix(']')?.parse::<u64>().ok()
}

fn parse_id_map(text: &str) -> ProbeResult<Vec<IdMapRange>> {
    let mut ranges = Vec::new();
    for line in text.lines() {
        if ranges.len() >= MAX_MAP_RANGES {
            return Err(ProbeError::new(
                "ID_MAP_LIMIT",
                "identity-map range count exceeded the probe limit",
            ));
        }
        let values: Vec<&str> = line.split_whitespace().take(4).collect();
        let [inside, outside, length] = values.as_slice() else {
            return Err(ProbeError::new(
                "ID_MAP_INVALID",
                "identity-map row must contain exactly three integers",
            ));
        };
        let parse = |value: &str| {
            value.parse::<u64>().map_err(|error| {
                ProbeError::new(
                    "ID_MAP_INVALID",
                    format!("invalid identity-map value: {error}"),
                )
            })
        };
        ranges.push(IdMapRange {
            inside_id: parse(inside)?,
            outside_id: parse(outside)?,
            length: parse(length)?,
        });
    }
    Ok(ranges)
}

fn parse_status_quad(text: &str, prefix: &str) -> Option<[u64; 4]> {
    let line = text.lines().find(|line| line.starts_with(prefix))?;
    let values: Vec<u64> = line[prefix.len()..]
        .split_whitespace()
        .take(5)
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    values.try_into().ok()
}

fn parse_status_scalar(text: &str, prefix: &str) -> Option<u64> {
    text.lines()
        .find(|line| line.starts_with(prefix))?
        .get(prefix.len()..)?
        .trim()
        .parse::<u64>()
        .ok()
}

fn compare_process(pid: u32, interval: Duration) -> ProbeResult<ProcessComparisonSnapshot> {
    let before = snapshot_process(pid)?;
    if !interval.is_zero() {
        thread::sleep(interval);
    }
    let after = snapshot_process(pid)?;
    let comparison = compare_process_facts(&before, &after);
    Ok(ProcessComparisonSnapshot {
        interval_ms: interval.as_millis(),
        before,
        after,
        comparison,
    })
}

fn compare_process_facts(left: &ProcessFacts, right: &ProcessFacts) -> ProcessFactComparison {
    let pid = FactMatch::from_bool(left.pid == right.pid);
    let start_time = FactMatch::from_bool(left.start_time_ticks == right.start_time_ticks);
    let cgroups = FactMatch::from_bool(left.cgroups == right.cgroups);
    let namespaces = FactMatch::from_bool(left.namespaces == right.namespaces);
    let uid_map = FactMatch::from_bool(left.uid_map == right.uid_map);
    let gid_map = FactMatch::from_bool(left.gid_map == right.gid_map);
    let credentials = FactMatch::from_bool(left.uids == right.uids && left.gids == right.gids);
    let binding_unchanged = [
        pid,
        start_time,
        cgroups,
        namespaces,
        uid_map,
        gid_map,
        credentials,
    ]
    .into_iter()
    .all(FactMatch::is_match);
    ProcessFactComparison {
        pid,
        start_time,
        cgroups,
        namespaces,
        uid_map,
        gid_map,
        credentials,
        binding_unchanged,
    }
}

fn peer_listen(path: &Path, timeout: Duration) -> ProbeResult<PeerObservation> {
    validate_socket_path(path)?;
    let listener = UnixListener::bind(path)
        .map_err(|error| ProbeError::io("PEER_BIND_FAILED", "bind Unix listener", &error))?;
    let _guard = SocketPathGuard::new(path)?;
    listener
        .set_nonblocking(true)
        .map_err(|error| ProbeError::io("PEER_LISTENER_FAILED", "set nonblocking", &error))?;
    let started = Instant::now();
    let stream = loop {
        match listener.accept() {
            Ok((stream, _address)) => break stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && started.elapsed() < timeout =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(ProbeError::new(
                    "PEER_TIMEOUT",
                    "timed out waiting for a Unix peer",
                ));
            }
            Err(error) => {
                return Err(ProbeError::io(
                    "PEER_ACCEPT_FAILED",
                    "accept Unix peer",
                    &error,
                ));
            }
        }
    };
    peer_observation("listener", path, &stream)
}

fn peer_connect(path: &Path, timeout: Duration) -> ProbeResult<PeerObservation> {
    validate_socket_path(path)?;
    let started = Instant::now();
    let stream = loop {
        match UnixStream::connect(path) {
            Ok(stream) => break stream,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::WouldBlock
                ) && started.elapsed() < timeout =>
            {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) if started.elapsed() >= timeout => {
                return Err(ProbeError::io(
                    "PEER_TIMEOUT",
                    "timed out connecting to Unix listener",
                    &error,
                ));
            }
            Err(error) => {
                return Err(ProbeError::io(
                    "PEER_CONNECT_FAILED",
                    "connect to Unix listener",
                    &error,
                ));
            }
        }
    };
    peer_observation("connector", path, &stream)
}

fn validate_socket_path(path: &Path) -> ProbeResult<()> {
    if path.as_os_str().as_bytes().is_empty() {
        return Err(ProbeError::new(
            "INVALID_SOCKET_PATH",
            "socket path is empty",
        ));
    }
    if path.as_os_str().as_bytes().len() > MAX_PATH_BYTES {
        return Err(ProbeError::new(
            "INVALID_SOCKET_PATH",
            "socket path exceeded the probe path limit",
        ));
    }
    Ok(())
}

fn peer_observation(
    role: &'static str,
    path: &Path,
    stream: &UnixStream,
) -> ProbeResult<PeerObservation> {
    Ok(PeerObservation {
        role,
        socket_path: bounded_text(&path.to_string_lossy(), MAX_PATH_BYTES),
        peer: peer_credentials(stream)?,
    })
}

fn peer_credentials(stream: &UnixStream) -> ProbeResult<PeerCredentials> {
    let cloned = stream.try_clone().map_err(|error| {
        ProbeError::io(
            "PEER_CREDENTIALS_FAILED",
            "clone Unix stream for credential capture",
            &error,
        )
    })?;
    cloned.set_nonblocking(true).map_err(|error| {
        ProbeError::io(
            "PEER_CREDENTIALS_FAILED",
            "set credential stream nonblocking",
            &error,
        )
    })?;
    let runtime = Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|error| {
            ProbeError::io(
                "PEER_CREDENTIALS_FAILED",
                "build credential capture runtime",
                &error,
            )
        })?;
    let _runtime_guard = runtime.enter();
    let stream = tokio::net::UnixStream::from_std(cloned).map_err(|error| {
        ProbeError::io(
            "PEER_CREDENTIALS_FAILED",
            "adopt Unix stream for credential capture",
            &error,
        )
    })?;
    let credentials = stream
        .peer_cred()
        .map_err(|error| ProbeError::io("PEER_CREDENTIALS_FAILED", "read SO_PEERCRED", &error))?;
    let pid = credentials.pid().ok_or_else(|| {
        ProbeError::new(
            "PEER_PID_UNAVAILABLE",
            "SO_PEERCRED did not include a peer process ID",
        )
    })?;
    Ok(PeerCredentials {
        pid,
        uid: credentials.uid(),
        gid: credentials.gid(),
    })
}

fn projection_size(source: &OsStr) -> ProbeResult<ProjectionMetrics> {
    let bytes = if source == OsStr::new("-") {
        read_limited(io::stdin().lock(), MAX_INPUT_BYTES)
            .map_err(|error| ProbeError::io("PROJECTION_READ_FAILED", "read stdin", &error))?
    } else {
        let file = File::open(Path::new(source)).map_err(|error| {
            ProbeError::io("PROJECTION_OPEN_FAILED", "open projection input", &error)
        })?;
        read_limited(file, MAX_INPUT_BYTES).map_err(|error| {
            ProbeError::io("PROJECTION_READ_FAILED", "read projection input", &error)
        })?
    };
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ProbeError::new(
            "PROJECTION_INPUT_LIMIT",
            "projection input exceeded the probe byte limit",
        ));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        ProbeError::new(
            "PROJECTION_JSON_INVALID",
            format!("parse projection JSON: {error}"),
        )
    })?;
    analyze_projection(
        &value,
        bytes.len(),
        ProjectionLimits {
            max_depth: MAX_PROJECTION_DEPTH,
            max_nodes: MAX_PROJECTION_NODES,
        },
    )
}

fn analyze_projection(
    root: &Value,
    input_bytes: usize,
    limits: ProjectionLimits,
) -> ProbeResult<ProjectionMetrics> {
    let mut metrics = ProjectionMetrics {
        input_bytes,
        nodes: 0,
        max_depth: 0,
        object_entries: 0,
        array_items: 0,
        string_values: 0,
        string_bytes: 0,
        max_string_bytes: 0,
        numbers: 0,
        booleans: 0,
        nulls: 0,
        probe_input_limit_bytes: MAX_INPUT_BYTES,
        probe_depth_limit: limits.max_depth,
        probe_node_limit: limits.max_nodes,
        final_protocol_ceiling_evidence: false,
    };
    let mut pending = vec![(root, 1_usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > limits.max_depth {
            return Err(ProbeError::new(
                "PROJECTION_DEPTH_LIMIT",
                "projection nesting exceeded the probe limit",
            ));
        }
        metrics.nodes = checked_increment(metrics.nodes, "projection node count")?;
        if metrics.nodes > limits.max_nodes {
            return Err(ProbeError::new(
                "PROJECTION_NODE_LIMIT",
                "projection node count exceeded the probe limit",
            ));
        }
        metrics.max_depth = metrics.max_depth.max(depth);
        match value {
            Value::Object(map) => {
                metrics.object_entries = checked_add(
                    metrics.object_entries,
                    map.len(),
                    "projection object entry count",
                )?;
                for (key, child) in map {
                    metrics.string_bytes = checked_add(
                        metrics.string_bytes,
                        key.len(),
                        "projection string byte count",
                    )?;
                    metrics.max_string_bytes = metrics.max_string_bytes.max(key.len());
                    pending.push((child, checked_increment(depth, "projection depth")?));
                }
            }
            Value::Array(array) => {
                metrics.array_items = checked_add(
                    metrics.array_items,
                    array.len(),
                    "projection array item count",
                )?;
                let child_depth = checked_increment(depth, "projection depth")?;
                pending.extend(array.iter().map(|child| (child, child_depth)));
            }
            Value::String(text) => {
                metrics.string_values =
                    checked_increment(metrics.string_values, "projection string value count")?;
                metrics.string_bytes = checked_add(
                    metrics.string_bytes,
                    text.len(),
                    "projection string byte count",
                )?;
                metrics.max_string_bytes = metrics.max_string_bytes.max(text.len());
            }
            Value::Number(_) => {
                metrics.numbers = checked_increment(metrics.numbers, "projection number count")?;
            }
            Value::Bool(_) => {
                metrics.booleans = checked_increment(metrics.booleans, "projection boolean count")?;
            }
            Value::Null => {
                metrics.nulls = checked_increment(metrics.nulls, "projection null count")?;
            }
        }
    }
    Ok(metrics)
}

fn checked_add(left: usize, right: usize, field: &str) -> ProbeResult<usize> {
    left.checked_add(right)
        .ok_or_else(|| ProbeError::new("ARITHMETIC_OVERFLOW", format!("{field} overflowed")))
}

fn checked_increment(value: usize, field: &str) -> ProbeResult<usize> {
    checked_add(value, 1, field)
}

const fn capacity_metadata() -> CapacityMetadata {
    CapacityMetadata {
        purpose: "environment readiness only; not final broker, attestor, or protocol ceiling evidence",
        target_containers: TARGET_CONTAINERS,
        scale_ladder: &SCALE_LADDER,
        required_runtime_lanes: ["rootful-docker", "rootless-podman"],
        creates_containers: false,
        final_protocol_ceiling_evidence: false,
        probe_bounds: ProbeBounds {
            output_bytes: MAX_OUTPUT_BYTES,
            input_bytes: MAX_INPUT_BYTES,
            projection_depth: MAX_PROJECTION_DEPTH,
            projection_nodes: MAX_PROJECTION_NODES,
            cgroup_entries: MAX_CGROUP_ENTRIES,
            id_map_ranges: MAX_MAP_RANGES,
            peer_timeout_ms: DEFAULT_PEER_TIMEOUT.as_millis(),
        },
        stop_condition_categories: [
            "runtime-errors",
            "memory-pressure",
            "disk-or-inode-pressure",
            "file-descriptor-pressure",
            "pid-or-cgroup-pressure",
            "latency-or-timeout-regression",
            "evidence-retention-overflow",
        ],
    }
}

fn read_words(path: &Path) -> io::Result<Vec<String>> {
    Ok(read_bounded_text(path, MAX_TEXT_FILE_BYTES)?
        .split_whitespace()
        .take(MAX_CONTROLLERS.saturating_add(1))
        .map(|word| bounded_text(word, 128))
        .collect())
}

fn read_u64(path: &Path) -> io::Result<u64> {
    let text = read_bounded_text(path, 1_024)?;
    text.trim()
        .parse::<u64>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_bounded_text(path: &Path, limit: usize) -> io::Result<String> {
    let bytes = read_limited(File::open(path)?, limit)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeded probe read limit",
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_limited<R: Read>(reader: R, limit: usize) -> io::Result<Vec<u8>> {
    let max = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    reader.take(max).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;
    use std::io::Cursor;

    fn sample_process() -> ProcessFacts {
        ProcessFacts {
            pid: 10,
            state: "S".to_owned(),
            start_time_ticks: 20,
            cgroups: vec![CgroupEntry {
                hierarchy_id: 0,
                controllers: String::new(),
                path: "/user.slice".to_owned(),
            }],
            namespaces: vec![NamespaceFact {
                name: "pid".to_owned(),
                inode: Some(30),
                target: Some("pid:[30]".to_owned()),
            }],
            uid_map: vec![IdMapRange {
                inside_id: 0,
                outside_id: 1_000,
                length: 65_536,
            }],
            gid_map: vec![IdMapRange {
                inside_id: 0,
                outside_id: 1_000,
                length: 65_536,
            }],
            uids: Some([1_000; 4]),
            gids: Some([1_000; 4]),
            no_new_privs: Some(1),
            seccomp_mode: Some(2),
            liveness: LivenessFact {
                alive_after_snapshot: true,
                start_time_unchanged: true,
            },
        }
    }

    #[test]
    fn parses_proc_stat_with_parentheses_in_command() {
        let mut fields = vec!["S".to_owned()];
        fields.extend((1..19).map(|value| value.to_string()));
        fields.push("424242".to_owned());
        let text = format!("123 (worker ) name) {}", fields.join(" "));
        let stat = parse_proc_stat(123, &text).unwrap();
        assert_eq!(stat.state, "S");
        assert_eq!(stat.start_time_ticks, 424_242);
    }

    #[test]
    fn rejects_excess_identity_map_columns() {
        let error = parse_id_map("0 1000 65536 9\n").unwrap_err();
        assert_eq!(error.code, "ID_MAP_INVALID");
    }

    #[test]
    fn projection_metrics_count_keys_values_and_depth() {
        let value: Value = serde_json::from_str(r#"{"items":["abc",true,null],"n":7}"#).unwrap();
        let metrics = analyze_projection(
            &value,
            35,
            ProjectionLimits {
                max_depth: 8,
                max_nodes: 16,
            },
        )
        .unwrap();
        assert_eq!(metrics.nodes, 6);
        assert_eq!(metrics.max_depth, 3);
        assert_eq!(metrics.object_entries, 2);
        assert_eq!(metrics.array_items, 3);
        assert_eq!(metrics.string_values, 1);
        assert_eq!(metrics.string_bytes, 9);
        assert_eq!(metrics.booleans, 1);
        assert_eq!(metrics.nulls, 1);
        assert_eq!(metrics.numbers, 1);
    }

    #[test]
    fn projection_metrics_enforce_node_bound() {
        let value: Value = serde_json::from_str("[1,2,3]").unwrap();
        let error = analyze_projection(
            &value,
            7,
            ProjectionLimits {
                max_depth: 8,
                max_nodes: 3,
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "PROJECTION_NODE_LIMIT");
    }

    #[test]
    fn limited_reader_stops_after_limit_plus_one() {
        let bytes = read_limited(Cursor::new(vec![0_u8; 100]), 32).unwrap();
        assert_eq!(bytes.len(), 33);
    }

    #[test]
    fn fact_comparison_detects_start_time_reuse() {
        let first = sample_process();
        let mut second = first.clone();
        second.start_time_ticks = second.start_time_ticks.saturating_add(1);
        let comparison = compare_process_facts(&first, &second);
        assert_eq!(comparison.pid, FactMatch::Match);
        assert_eq!(comparison.start_time, FactMatch::Mismatch);
        assert!(!comparison.binding_unchanged);
    }

    #[test]
    fn fact_comparison_accepts_identical_binding() {
        let first = sample_process();
        let comparison = compare_process_facts(&first, &first);
        assert!(comparison.binding_unchanged);
    }

    #[test]
    fn peer_credentials_are_observed_without_unsafe_code() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "basil-compose-probe-{}-{unique}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let guard = SocketPathGuard::new(&path).unwrap();
        let connector = thread::spawn(move || UnixStream::connect(path).unwrap());
        let (accepted, _address) = listener.accept().unwrap();
        let connected = connector.join().unwrap();
        let accepted_peer = peer_credentials(&accepted).unwrap();
        let connected_peer = peer_credentials(&connected).unwrap();
        let expected_pid = i32::try_from(std::process::id()).unwrap();
        assert_eq!(accepted_peer.pid, expected_pid);
        assert_eq!(connected_peer.pid, expected_pid);
        drop(guard);
    }
}
