// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! The JSONL audit sink (`vault-vq5`): persist every authorization decision.
//!
//! [`crate::decision::DecisionRecord`] is the single place a gated op's
//! `(subject, op, key) -> Allow|Deny` decision is materialized, and it is already
//! logged structurally via `tracing`. This module adds a *second*, durable side
//! channel: when the broker is started with config key `audit-log`, each recorded
//! decision is also appended as exactly **one JSON object per line** (JSONL) to
//! an open append-only file.
//!
//! # Discipline
//!
//! - **No secret bytes.** A [`DecisionRecord`] carries only the actor subject,
//!   presenter context, op, key name, outcome, and reason token, never payloads,
//!   key bytes, or signatures. The audit line is built from exactly those fields
//!   plus a timestamp.
//! - **Best-effort at request time.** The kernel-trustworthy decision has already
//!   happened and is in `tracing`; queue or IO trouble must **not** panic and
//!   must **not** block or deny the op. A failed enqueue/write logs an error and
//!   the data plane carries on. (Audit-disk trouble must not take down the broker;
//!   see `vault-vq5` close note.)
//! - **Dedicated writer.** Request handlers only enqueue a serialized line into a
//!   bounded channel. One audit writer thread owns the file handle, writes one
//!   complete JSONL record at a time, and flushes each line so a crash does not
//!   lose recent entries.
//! - **Fail-closed startup.** Opening the file (`O_APPEND | O_CREATE`, mode
//!   `0600`) happens once at startup via [`AuditLog::open`]; a failure there is a
//!   clean startup error (the binary aborts), never a panic.

use std::fs::OpenOptions;
use std::io::BufWriter;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::SystemTime;

use serde_json::json;

use crate::configuration::OverrideProvenance;
use tracing::{error, info};

use crate::decision::{DecisionRecord, Outcome, op_token};

const DEFAULT_QUEUE_CAPACITY: usize = 1024;
const REOPEN_POLL: Duration = Duration::from_secs(1);

/// An open, append-only JSONL audit file backed by a dedicated writer thread.
///
/// Request handlers serialize the record and try to enqueue it into a bounded
/// channel. They never perform audit file IO. The writer thread owns the
/// `BufWriter<File>`, writes whole lines, flushes per line, and handles
/// logrotate-friendly reopen requests.
#[derive(Debug)]
pub struct AuditLog {
    sender: Mutex<Option<SyncSender<AuditCommand>>>,
    reopen_requested: Arc<AtomicBool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl AuditLog {
    /// Open (or create) the audit file at `path` in append-only mode, `0600`.
    ///
    /// The file is opened **once at startup**; the handle is then held for the
    /// broker's lifetime. `O_APPEND` makes each write atomic w.r.t. other
    /// appenders, and mode `0600` keeps the audit trail owner-only.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] if the file cannot be opened or
    /// created (a fail-closed startup error: the binary aborts cleanly, no
    /// panic).
    pub fn open(path: &Path) -> std::io::Result<Self> {
        Self::open_with_capacity(path, DEFAULT_QUEUE_CAPACITY)
    }

    fn open_with_capacity(path: &Path, capacity: usize) -> std::io::Result<Self> {
        let file = open_append(path)?;
        let (sender, receiver) = sync_channel(capacity);
        let reopen_requested = Arc::new(AtomicBool::new(false));
        let worker_reopen_requested = Arc::clone(&reopen_requested);
        let worker_path = path.to_path_buf();
        let worker = std::thread::Builder::new()
            .name("basil-audit-writer".to_string())
            .spawn(move || {
                run_writer(
                    &worker_path,
                    BufWriter::new(file),
                    &receiver,
                    &worker_reopen_requested,
                );
            })?;
        Ok(Self {
            sender: Mutex::new(Some(sender)),
            reopen_requested,
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Append one audit record as a single JSONL line (best-effort).
    ///
    /// Builds the line from the [`DecisionRecord`] plus a timestamp and tries to
    /// enqueue it. A full or closed queue is logged and swallowed: appending the
    /// audit line must never block or fail the op. This method therefore returns
    /// nothing and never panics.
    pub fn append(&self, record: &DecisionRecord) {
        let line = serialize_line(record);
        self.try_send(AuditCommand::Line(line));
    }

    /// Append one pre-rendered structured JSON value as a single JSONL line
    /// (best-effort). Used by events that build their own audit JSON, e.g. a
    /// provider operation
    /// ([`ProviderAuditEvent`](crate::core::crypto_provider::ProviderAuditEvent)),
    /// which carries its own `occurred_at` timestamp. Like [`Self::append`], a
    /// full or closed queue is logged and swallowed: this never blocks, fails the
    /// op, or panics.
    pub fn append_value(&self, value: &serde_json::Value) {
        self.try_send(AuditCommand::Line(value.to_string()));
    }

    /// Append one **reload** audit line (`basil-y3e.2`, `basil-atq`): a
    /// `basil.audit.reload` JSONL event recording a generation reload, allow or
    /// reject.
    ///
    /// `actor` attributes the trigger: a [`ReloadActor::Sighup`] for the operator
    /// `SIGHUP` signal path, or a [`ReloadActor::Caller`] carrying the peer-cred
    /// attested uid for the gated admin `Reload` RPC. The two paths are otherwise
    /// byte-identical (same gen ids + outcome + reason shape), so a SIGHUP and an
    /// RPC reload of the same candidate differ in the audit trail ONLY in this
    /// actor field. `outcome` is `"applied"`/`"checked"`/`"rejected"`;
    /// `new_generation` is the id now serving (== `previous_generation` on a
    /// reject/check, since no swap happened); `reason` is a short, stable,
    /// non-secret token (`signal`/`admin_rpc` on success, or the
    /// [`ReloadError`](crate::reload::ReloadError) audit reason on a reject).
    /// Best-effort and non-blocking, exactly like [`Self::append`].
    pub fn append_reload(
        &self,
        previous_generation: u64,
        new_generation: u64,
        outcome: &str,
        reason: &str,
        actor: ReloadActor,
    ) {
        self.append_reload_with_overrides(
            previous_generation,
            new_generation,
            outcome,
            reason,
            actor,
            &[],
        );
    }

    /// Append one reload audit line including non-secret override provenance.
    pub fn append_reload_with_overrides(
        &self,
        previous_generation: u64,
        new_generation: u64,
        outcome: &str,
        reason: &str,
        actor: ReloadActor,
        overrides: &[OverrideProvenance],
    ) {
        let line = serialize_reload_line_with_overrides(
            previous_generation,
            new_generation,
            outcome,
            reason,
            actor,
            overrides,
        );
        self.try_send(AuditCommand::Line(line));
    }

    /// Request a logrotate-friendly close/reopen of the configured audit path.
    ///
    /// This is best-effort and non-blocking for the caller. The writer thread
    /// observes the request before the next write, or within a short idle poll.
    pub fn request_reopen(&self) {
        self.reopen_requested.store(true, Ordering::Release);
        self.try_send(AuditCommand::Wake);
    }

    fn try_send(&self, cmd: AuditCommand) {
        let sender = {
            let guard = match self.sender.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.as_ref().cloned()
        };
        let Some(sender) = sender else {
            error!("audit writer is stopped; dropping audit command");
            return;
        };
        let result = sender.try_send(cmd);
        match result {
            Ok(()) => {}
            Err(TrySendError::Full(AuditCommand::Line(_))) => {
                error!("audit log queue full; dropping audit line (decision is in tracing)");
            }
            Err(TrySendError::Full(_cmd)) => {
                error!("audit log queue full; writer will observe pending reopen later");
            }
            Err(TrySendError::Disconnected(_cmd)) => {
                error!("audit writer is stopped; dropping audit command");
            }
        }
    }

    #[cfg(test)]
    fn reopen_for_test(&self) {
        let (sender, receiver) = sync_channel(0);
        self.reopen_requested.store(true, Ordering::Release);
        self.try_send(AuditCommand::ReopenAck(sender));
        receiver
            .recv()
            .expect("audit writer should acknowledge reopen");
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
        if let Ok(mut worker) = self.worker.lock()
            && let Some(handle) = worker.take()
            && handle.join().is_err()
        {
            error!("audit writer thread panicked during shutdown");
        }
    }
}

#[derive(Debug)]
enum AuditCommand {
    Line(String),
    Wake,
    #[cfg(test)]
    ReopenAck(SyncSender<()>),
}

fn run_writer(
    path: &Path,
    mut writer: BufWriter<std::fs::File>,
    receiver: &Receiver<AuditCommand>,
    reopen_requested: &AtomicBool,
) {
    loop {
        maybe_reopen(path, &mut writer, reopen_requested);
        let cmd = match receiver.recv_timeout(REOPEN_POLL) {
            Ok(cmd) => cmd,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        };
        match cmd {
            AuditCommand::Line(line) => {
                maybe_reopen(path, &mut writer, reopen_requested);
                if let Err(e) = write_line(&mut writer, &line) {
                    error!(error = %e, "failed to append audit log line; continuing (decision is in tracing)");
                }
            }
            AuditCommand::Wake => {}
            #[cfg(test)]
            AuditCommand::ReopenAck(sender) => {
                maybe_reopen(path, &mut writer, reopen_requested);
                let _ = sender.send(());
            }
        }
    }
    if let Err(e) = writer.flush() {
        error!(error = %e, "failed to flush audit log during shutdown");
    }
}

fn maybe_reopen(path: &Path, writer: &mut BufWriter<std::fs::File>, reopen_requested: &AtomicBool) {
    if !reopen_requested.swap(false, Ordering::AcqRel) {
        return;
    }
    if let Err(e) = writer.flush() {
        error!(error = %e, "failed to flush audit log before reopen; continuing");
    }
    match open_append(path) {
        Ok(file) => {
            *writer = BufWriter::new(file);
            info!(path = %path.display(), "audit log reopened");
        }
        Err(e) => {
            reopen_requested.store(true, Ordering::Release);
            error!(error = %e, path = %path.display(), "failed to reopen audit log; keeping existing handle");
        }
    }
}

fn open_append(path: &Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

/// Write one already-serialized line plus a newline, then flush.
///
/// Split out so the IO can be unit-tested against an arbitrary `io::Write`
/// (including a deliberately-failing one) without touching the filesystem.
fn write_line<W: std::io::Write>(w: &mut W, line: &str) -> std::io::Result<()> {
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    // Flush per line so a crash does not lose recent entries.
    w.flush()
}

/// Serialize one [`DecisionRecord`] to a compact JSON object string (no newline).
///
/// The shape is stable and secret-free: `occurred_at` (RFC3339-ish UTC, or the
/// unix epoch seconds on the astronomically-unlikely clock-before-epoch case),
/// `generation` (the policy generation id the decision was made against), `op`,
/// `target`, subject actor, presenter context, `outcome`, and `reason`.
/// `serde_json::to_string` of a `Value` is infallible, so this cannot
/// fail; on the impossible error we fall back to a minimal hand-rolled object so
/// the audit line is never silently lost.
fn serialize_line(record: &DecisionRecord) -> String {
    let obj = json!({
        "event_kind": "basil.audit.authz",
        "event_version": 2,
        "occurred_at": timestamp(),
        "generation": record.generation,
        "op": op_token(record.op),
        "target_kind": "catalog_key",
        "target_id": record.key,
        "actor_kind": record.actor_kind,
        "actor_id": record.actor_id,
        "authenticated_by": record.authenticated_by,
        "presenter_kind": record.presenter_kind,
        "presenter_id": record.presenter_id,
        "decision": outcome_token(record.outcome),
        "outcome": outcome_token(record.outcome),
        "reason": record.reason,
    });
    serde_json::to_string(&obj).unwrap_or_else(|_| {
        // Infallible in practice (a plain object of strings); keep a non-panic
        // floor so an audit line is emitted even on the impossible error.
        format!(
            "{{\"event_kind\":\"basil.audit.authz\",\"event_version\":2,\"op\":\"{}\",\"target_kind\":\"catalog_key\",\"target_id\":\"{}\",\"actor_kind\":\"{}\",\"actor_id\":\"{}\",\"outcome\":\"{}\"}}",
            op_token(record.op),
            record.key,
            record.actor_kind,
            record.actor_id,
            outcome_token(record.outcome),
        )
    })
}

/// Who triggered a generation reload, for the `actor` field of a
/// `basil.audit.reload` line (`basil-atq`, `basil-mil0.5`/`basil-ftmc`).
///
/// The two reload triggers, the operator `SIGHUP` signal and the gated admin
/// `Reload` RPC, drive the SAME `reload_generation` engine and emit the SAME
/// audit shape, so they are distinguishable in the trail only by this actor: a
/// signal carries no uid, while the RPC path carries the peer-cred attested
/// caller uid (mirroring the `unix_uid` actor of the authz line).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReloadActor {
    /// The operator `SIGHUP` signal path (`actor: {kind:"signal", id:"SIGHUP"}`).
    Sighup,
    /// The gated admin `Reload` RPC, attributed to the attested caller `uid`
    /// (`actor: {kind:"unix_uid", id:"<uid>"}`).
    Caller(u32),
}

impl ReloadActor {
    /// The `(kind, id)` pair this actor renders as in the audit `actor` object.
    /// The id is a string for both arms so the field's JSON type is stable
    /// regardless of trigger.
    fn kind_and_id(self) -> (&'static str, String) {
        match self {
            Self::Sighup => ("signal", "SIGHUP".to_string()),
            Self::Caller(uid) => ("unix_uid", uid.to_string()),
        }
    }
}

/// Serialize one reload audit event (`basil-y3e.2`, `basil-atq`) as a single
/// JSONL line.
///
/// Mirrors [`serialize_line`]'s shape (`event`/`occurred_at`/`actor`/`outcome`/
/// `reason`) but with `kind: basil.audit.reload` and the old → new generation
/// ids, so a reload (applied, checked, or rejected) is greppable in the same
/// audit trail. The `actor` distinguishes the trigger (`SIGHUP` signal vs the
/// attested RPC caller uid) while every other field is byte-identical across the
/// two paths. The hand-rolled fallback keeps a non-panic floor on the
/// (impossible) serde error.
#[cfg(test)]
fn serialize_reload_line(
    previous_generation: u64,
    new_generation: u64,
    outcome: &str,
    reason: &str,
    actor: ReloadActor,
) -> String {
    serialize_reload_line_with_overrides(
        previous_generation,
        new_generation,
        outcome,
        reason,
        actor,
        &[],
    )
}

fn serialize_reload_line_with_overrides(
    previous_generation: u64,
    new_generation: u64,
    outcome: &str,
    reason: &str,
    actor: ReloadActor,
    overrides: &[OverrideProvenance],
) -> String {
    let (actor_kind, actor_id) = actor.kind_and_id();
    let obj = json!({
        "event": {
            "kind": "basil.audit.reload",
            "version": 1,
        },
        "occurred_at": timestamp(),
        "actor": {
            "kind": actor_kind,
            "id": actor_id,
        },
        "previous_generation": previous_generation,
        "generation": new_generation,
        "outcome": outcome,
        "reason": reason,
        "overrides": overrides,
    });
    serde_json::to_string(&obj).unwrap_or_else(|_| {
        format!(
            "{{\"event\":{{\"kind\":\"basil.audit.reload\",\"version\":1}},\"previous_generation\":{previous_generation},\"generation\":{new_generation},\"outcome\":\"{outcome}\"}}"
        )
    })
}

/// A best-effort, dependency-free timestamp for an audit line.
///
/// Renders the current UTC instant as `YYYY-MM-DDThh:mm:ssZ` (RFC3339, seconds
/// precision) from a single [`SystemTime`] reading: no date crate needed. On the
/// astronomically-unlikely case of a clock set before the unix epoch, falls back
/// to the signed epoch-seconds string so the line still carries a timestamp.
pub(crate) fn timestamp() -> String {
    let now = SystemTime::now();
    match now.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(dur) => format_rfc3339(dur.as_secs()),
        Err(e) => {
            // Clock is before the epoch; emit the (negative) offset in seconds.
            let secs = e.duration().as_secs();
            format!("-{secs}")
        }
    }
}

/// Format unix epoch `secs` as `YYYY-MM-DDThh:mm:ssZ` (UTC, civil calendar).
///
/// A small, panic-free Howard-Hinnant `days_from_civil`-inverse so the audit
/// line carries a human-readable RFC3339 timestamp without pulling in a date
/// crate. Pure integer arithmetic; valid for the full lifetime of any process.
fn format_rfc3339(secs: u64) -> String {
    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let (hour, min, sec) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );

    // Howard Hinnant's civil_from_days (epoch shifted to 0000-03-01).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// The stable lowercase token for `outcome` (`allow` / `deny`).
const fn outcome_token(outcome: Outcome) -> &'static str {
    outcome.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::policy::Op;
    use std::io;

    /// A record with no secret material. The audit sink only ever sees these.
    fn allow_record() -> DecisionRecord {
        DecisionRecord {
            generation: 1,
            op: Op::Sign,
            key: "nats.account".to_string(),
            actor_kind: "subject".to_string(),
            actor_id: "svc.nats".to_string(),
            authenticated_by: vec!["unix_peercred:svc.nats".to_string()],
            presenter_kind: "unix_peercred".to_string(),
            presenter_id: "svc-nats(9002)".to_string(),
            outcome: Outcome::Allow,
            reason: "subject:svc.nats".to_string(),
        }
    }

    fn deny_record() -> DecisionRecord {
        DecisionRecord {
            generation: 1,
            op: Op::Decrypt,
            key: "secret.payload".to_string(),
            actor_kind: "subject".to_string(),
            actor_id: "svc.api".to_string(),
            authenticated_by: vec!["unix_peercred:svc.api".to_string()],
            presenter_kind: "unix_peercred".to_string(),
            presenter_id: "svc-api(7777)".to_string(),
            outcome: Outcome::Deny,
            reason: "not_permitted".to_string(),
        }
    }

    #[test]
    fn serialized_line_is_valid_json_with_expected_fields() {
        let line = serialize_line(&allow_record());
        assert!(!line.contains('\n'), "a line must be single-line JSONL");
        let v: serde_json::Value = serde_json::from_str(&line).expect("audit line must be JSON");
        assert_eq!(v["event_kind"], "basil.audit.authz");
        assert_eq!(v["event_version"], 2);
        assert_eq!(v["generation"], 1);
        assert_eq!(v["op"], "sign");
        assert_eq!(v["target_kind"], "catalog_key");
        assert_eq!(v["target_id"], "nats.account");
        assert_eq!(v["actor_kind"], "subject");
        assert_eq!(v["actor_id"], "svc.nats");
        assert_eq!(v["authenticated_by"][0], "unix_peercred:svc.nats");
        assert_eq!(v["presenter_kind"], "unix_peercred");
        assert_eq!(v["presenter_id"], "svc-nats(9002)");
        assert_eq!(v["decision"], "allow");
        assert_eq!(v["outcome"], "allow");
        assert_eq!(v["reason"], "subject:svc.nats");
        // A timestamp is always present and RFC3339-Z shaped.
        let ts = v["occurred_at"]
            .as_str()
            .expect("timestamp must be a string");
        assert!(ts.ends_with('Z'), "ts is RFC3339 UTC: {ts}");
        assert!(ts.contains('T'), "ts is RFC3339 datetime: {ts}");
    }

    #[test]
    fn reload_line_is_valid_json_with_expected_fields() {
        let applied = serialize_reload_line(1, 2, "applied", "signal", ReloadActor::Sighup);
        assert!(!applied.contains('\n'), "a line must be single-line JSONL");
        let v: serde_json::Value =
            serde_json::from_str(&applied).expect("reload line must be JSON");
        assert_eq!(v["event"]["kind"], "basil.audit.reload");
        assert_eq!(v["event"]["version"], 1);
        assert_eq!(v["actor"]["kind"], "signal");
        assert_eq!(v["actor"]["id"], "SIGHUP");
        assert_eq!(v["previous_generation"], 1);
        assert_eq!(v["generation"], 2);
        assert_eq!(v["outcome"], "applied");
        assert_eq!(v["reason"], "signal");

        // A rejection records the same gen on both sides (no swap) + the reason.
        let rejected =
            serialize_reload_line(5, 5, "rejected", "validation_failed", ReloadActor::Sighup);
        let r: serde_json::Value =
            serde_json::from_str(&rejected).expect("reject line must be JSON");
        assert_eq!(r["previous_generation"], 5);
        assert_eq!(r["generation"], 5);
        assert_eq!(r["outcome"], "rejected");
        assert_eq!(r["reason"], "validation_failed");
    }

    #[test]
    fn reload_line_reports_override_provenance_without_values() {
        let overrides = [OverrideProvenance {
            path: "catalog.keys.web.signer.writable".to_string(),
            masked_source: "/etc/basil/catalog.json".into(),
        }];
        let line = serialize_reload_line_with_overrides(
            1,
            2,
            "applied",
            "signal",
            ReloadActor::Sighup,
            &overrides,
        );
        let value: serde_json::Value = serde_json::from_str(&line).expect("audit JSON");
        assert_eq!(value["overrides"][0]["path"], overrides[0].path);
        assert_eq!(
            value["overrides"][0]["masked_source"],
            "/etc/basil/catalog.json"
        );
        assert!(!line.contains("=true"));
    }

    /// The RPC reload path attributes the line to the attested caller uid
    /// (`unix_uid`), while a SIGHUP carries the `signal`/`SIGHUP` actor: the SAME
    /// shape otherwise. This is the SIGHUP-vs-RPC parity discriminator the live
    /// `reload_e2e` asserts (`basil-ftmc`).
    #[test]
    fn reload_actor_distinguishes_signal_from_rpc_caller() {
        let rpc = serialize_reload_line(1, 2, "applied", "admin_rpc", ReloadActor::Caller(4242));
        let v: serde_json::Value =
            serde_json::from_str(&rpc).expect("rpc reload line must be JSON");
        assert_eq!(v["actor"]["kind"], "unix_uid");
        assert_eq!(v["actor"]["id"], "4242");
        // Every non-actor field matches a SIGHUP reload of the same gen swap.
        let sig = serialize_reload_line(1, 2, "applied", "admin_rpc", ReloadActor::Sighup);
        let s: serde_json::Value = serde_json::from_str(&sig).expect("sighup line must be JSON");
        assert_eq!(v["event"], s["event"]);
        assert_eq!(v["previous_generation"], s["previous_generation"]);
        assert_eq!(v["generation"], s["generation"]);
        assert_eq!(v["outcome"], s["outcome"]);
        assert_eq!(v["reason"], s["reason"]);
        assert_ne!(v["actor"], s["actor"], "only the actor differs");
    }

    #[test]
    fn deny_line_is_shaped_and_carries_reason() {
        let line = serialize_line(&deny_record());
        let v: serde_json::Value = serde_json::from_str(&line).expect("audit line must be JSON");
        assert_eq!(v["op"], "decrypt");
        assert_eq!(v["outcome"], "deny");
        assert_eq!(v["reason"], "not_permitted");
        assert_eq!(v["actor_kind"], "subject");
        assert_eq!(v["actor_id"], "svc.api");
        assert_eq!(v["presenter_id"], "svc-api(7777)");
    }

    #[test]
    fn appended_file_has_one_parseable_jsonl_line_per_record() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "vault-yul-async-audit-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let log = AuditLog::open(&path).expect("open temp audit log");
        log.append(&allow_record());
        log.append(&deny_record());
        drop(log); // flush + close

        let body = std::fs::read_to_string(&path).expect("read back audit file");
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "one JSONL line per appended record");

        let recs: Vec<serde_json::Value> = lines
            .iter()
            .map(|l| serde_json::from_str(l).expect("each line is JSON"))
            .collect();
        assert_eq!(recs[0]["event_kind"], "basil.audit.authz");
        assert_eq!(recs[0]["op"], "sign");
        assert_eq!(recs[0]["outcome"], "allow");
        assert_eq!(recs[1]["op"], "decrypt");
        assert_eq!(recs[1]["outcome"], "deny");

        // No secret material can have leaked: the file is exactly the
        // value-free record fields. Assert the presenter labels are present and
        // nothing resembling key bytes / a payload is.
        assert!(body.contains("svc-nats(9002)"));
        assert!(!body.contains("BEGIN"), "no PEM/key material in audit log");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reopen_writes_new_records_to_new_path_inode() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "vault-xrk-reopen-audit-{}.jsonl",
            std::process::id()
        ));
        let rotated = dir.join(format!(
            "vault-xrk-reopen-audit-{}.jsonl.1",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&rotated);

        let log = AuditLog::open(&path).expect("open temp audit log");
        log.append(&allow_record());
        log.reopen_for_test();

        std::fs::rename(&path, &rotated).expect("simulate logrotate rename");
        log.reopen_for_test();
        log.append(&deny_record());
        drop(log);

        let old_body = std::fs::read_to_string(&rotated).expect("read rotated audit file");
        let new_body = std::fs::read_to_string(&path).expect("read reopened audit file");
        assert_eq!(old_body.lines().count(), 1);
        assert!(old_body.contains("\"outcome\":\"allow\""));
        assert_eq!(new_body.lines().count(), 1);
        assert!(new_body.contains("\"outcome\":\"deny\""));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&rotated);
    }

    #[test]
    fn bounded_queue_drops_instead_of_blocking_request_path() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "vault-yul-bounded-audit-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        let log = AuditLog::open_with_capacity(&path, 1).expect("open temp audit log");
        for _ in 0..128 {
            log.append(&allow_record());
        }
        drop(log);

        let body = std::fs::read_to_string(&path).expect("read back audit file");
        assert!(
            !body.is_empty(),
            "bounded writer should persist the lines it accepted"
        );
        for line in body.lines() {
            let value: serde_json::Value =
                serde_json::from_str(line).expect("accepted audit line remains JSON");
            assert_eq!(value["op"], "sign");
            assert_eq!(value["target_id"], "nats.account");
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vault-vq5-mode-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let log = AuditLog::open(&path).expect("open temp audit log");
        log.append(&allow_record());
        drop(log);

        let mode = std::fs::metadata(&path)
            .expect("stat audit file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "audit file is owner-only");

        let _ = std::fs::remove_file(&path);
    }

    /// An `io::Write` whose `write_all` always fails, standing in for a full or
    /// unwritable audit disk at request time.
    struct FailingWriter;

    impl io::Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk go boom"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("disk go boom"))
        }
    }

    #[test]
    fn a_failing_sink_returns_error_not_panic() {
        // `write_line` surfaces the IO error (it does NOT panic); the public
        // `append` swallows it after logging. Here we assert the lower layer
        // reports the error so `append`'s log-and-continue is exercised by the
        // type system, and that building the line itself never panics.
        let line = serialize_line(&allow_record());
        let mut bad = FailingWriter;
        let err = write_line(&mut bad, &line);
        assert!(err.is_err(), "a bad sink yields an error, not a panic");
    }

    #[test]
    fn rfc3339_formats_known_epochs() {
        // Unix epoch.
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2021-01-01T00:00:00Z = 1_609_459_200.
        assert_eq!(format_rfc3339(1_609_459_200), "2021-01-01T00:00:00Z");
        // A leap-day instant: 2020-02-29T12:34:56Z = 1_582_979_696.
        assert_eq!(format_rfc3339(1_582_979_696), "2020-02-29T12:34:56Z");
    }
}
