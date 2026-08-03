// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use basil_core::core::nix_cache_file::{CACHE_LOCK_FILE, LockedCacheRoot};
use serde_json::Value;

const PROCESS_DEADLINE: Duration = Duration::from_secs(10);
const NARINFO_NAME: &str = "09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5.narinfo";
const NARINFO: &[u8] = b"StorePath: /nix/store/09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5-example\n\
URL: nar/example.nar\n\
Compression: none\n\
FileHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n\
FileSize: 1\n\
NarHash: sha256:09ymwqf5i9q7d4dm7x4pjjcqqj0qrcp5lnznbh42gfsci5hcbqqm\n\
NarSize: 1\n\
References: \n\
Sig: old:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\n";

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "basil-nix-cache-signals-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&path).expect("create cache fixture");
        std::fs::write(path.join(NARINFO_NAME), NARINFO).expect("write narinfo fixture");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    const fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    const fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child already reaped")
    }

    fn signal_and_wait(&mut self, signal: rustix::process::Signal) -> ExitStatus {
        let mut child = self.child.take().expect("child already reaped");
        let raw_pid = i32::try_from(child.id()).expect("child pid fits i32");
        let pid = rustix::process::Pid::from_raw(raw_pid).expect("child pid is nonzero");
        rustix::process::kill_process(pid, signal).expect("signal basil child");

        let (sender, receiver) = mpsc::sync_channel(1);
        let _waiter = std::thread::spawn(move || {
            let _ = sender.send(child.wait());
        });
        match receiver.recv_timeout(PROCESS_DEADLINE) {
            Ok(result) => result.expect("wait for basil child"),
            Err(error) => {
                let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                match receiver.recv_timeout(PROCESS_DEADLINE) {
                    Ok(_) => panic!("basil child exceeded exit deadline: {error}"),
                    Err(reap_error) => panic!(
                        "basil child could not be reaped after SIGKILL: {error}; {reap_error}"
                    ),
                }
            }
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let (sender, receiver) = mpsc::sync_channel(1);
            let _waiter = std::thread::spawn(move || {
                let _ = sender.send(child.wait());
            });
            let _ = receiver.recv_timeout(PROCESS_DEADLINE);
        }
    }
}

enum ReaderEvent {
    Line(std::io::Result<String>),
    Done,
}

struct RunningCommand {
    process: ChildGuard,
    lines: mpsc::Receiver<ReaderEvent>,
    captured: Vec<String>,
}

impl RunningCommand {
    fn spawn(cache: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_basil"))
            .args(["nix", "cache", "remove", "--key-name", "old", "--cache"])
            .arg(cache)
            .args(["--all", "--yes", "--lock-timeout", "30"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn basil cache remove");
        let mut process = ChildGuard::new(child);
        let stderr = process.child_mut().stderr.take().expect("piped stderr");
        let (sender, lines) = mpsc::channel();
        let _reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if sender.send(ReaderEvent::Line(line)).is_err() {
                    return;
                }
            }
            let _ = sender.send(ReaderEvent::Done);
        });
        Self {
            process,
            lines,
            captured: Vec::new(),
        }
    }

    fn wait_for_phase(&mut self, expected: &str) {
        let deadline = Instant::now()
            .checked_add(PROCESS_DEADLINE)
            .expect("process deadline");
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "audit phase {expected} timed out");
            let line = match self
                .lines
                .recv_timeout(remaining)
                .expect("basil stderr closed before expected audit phase")
            {
                ReaderEvent::Line(line) => line.expect("read basil stderr"),
                ReaderEvent::Done => panic!("basil stderr ended before audit phase {expected}"),
            };
            let found = has_event_phase(&line, expected);
            self.captured.push(line);
            if found {
                break;
            }
        }
    }

    fn signal_and_collect(mut self, signal: rustix::process::Signal) -> (ExitStatus, Vec<String>) {
        let status = self.process.signal_and_wait(signal);
        let deadline = Instant::now()
            .checked_add(PROCESS_DEADLINE)
            .expect("stderr deadline");
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "basil stderr reader timed out");
            match self
                .lines
                .recv_timeout(remaining)
                .expect("basil stderr reader disconnected")
            {
                ReaderEvent::Line(line) => {
                    self.captured
                        .push(line.expect("read trailing basil stderr"));
                }
                ReaderEvent::Done => break,
            }
        }
        (status, self.captured)
    }
}

fn has_event_phase(line: &str, expected: &str) -> bool {
    serde_json::from_str::<Value>(line)
        .ok()
        .is_some_and(|value| value.get("phase").and_then(Value::as_str) == Some(expected))
}

fn audit_events(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value.get("phase").is_some())
        .collect()
}

fn assert_graceful_signal(signal: rustix::process::Signal, signal_name: &str) {
    let fixture = Fixture::new();
    let target = fixture.path().join(NARINFO_NAME);
    let before = std::fs::read(&target).expect("read original narinfo");
    let holder = LockedCacheRoot::try_acquire(fixture.path()).expect("hold cache lock");
    let lock_before =
        std::fs::metadata(fixture.path().join(CACHE_LOCK_FILE)).expect("read held lock metadata");

    let mut command = RunningCommand::spawn(fixture.path());
    command.wait_for_phase("batch_start");
    assert!(holder.holds_lock());
    assert!(
        command
            .process
            .child_mut()
            .try_wait()
            .expect("probe child")
            .is_none()
    );
    assert_eq!(
        std::fs::read(&target).expect("read target at barrier"),
        before
    );

    let (status, lines) = command.signal_and_collect(signal);
    assert_eq!(status.signal(), None);
    assert_eq!(status.code(), Some(1));
    assert_eq!(
        std::fs::read(&target).expect("read target after signal"),
        before
    );

    let events = audit_events(&lines);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["phase"] == "batch_start")
            .count(),
        1
    );
    let cancellations = events
        .iter()
        .filter(|event| event["phase"] == "batch_cancellation")
        .collect::<Vec<_>>();
    assert_eq!(cancellations.len(), 1);
    assert_eq!(cancellations[0]["signal"], signal_name);
    assert_eq!(cancellations[0]["counts"]["durable_commits"], 0);
    assert!(events.iter().all(|event| {
        !matches!(
            event["phase"].as_str(),
            Some("path_commit" | "batch_failure" | "batch_completion")
        )
    }));

    drop(holder);
    let recovered = LockedCacheRoot::try_acquire(fixture.path()).expect("lock after child exit");
    let lock_after = std::fs::metadata(fixture.path().join(CACHE_LOCK_FILE))
        .expect("read recovered lock metadata");
    assert_eq!(lock_before.dev(), lock_after.dev());
    assert_eq!(lock_before.ino(), lock_after.ino());
    drop(recovered);
}

#[test]
fn production_mutation_signals_cancel_lock_wait_once_without_mutation() {
    assert_graceful_signal(rustix::process::Signal::INT, "SIGINT");
    assert_graceful_signal(rustix::process::Signal::TERM, "SIGTERM");
}
