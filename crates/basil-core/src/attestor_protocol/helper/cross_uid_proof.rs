// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Cross-UID executable-pinning capability proof (`basil-nfko`).
//!
//! Empirically answers the `basil-k9oe` question: does the helper's
//! `/proc/<pid>/exe` open path ([`super::host::ProcExecutableOpener`])
//! still pin a cross-UID peer's executable when the process holds **only**
//! `CAP_SYS_PTRACE` — no `CAP_DAC_READ_SEARCH`, no generic filesystem read?
//! The hard case is a rootless-realm executable of mode `0700` inside a
//! mode-`0700` directory owned by another UID.
//!
//! Measured answer (kernel 6.18): **no**. Following the `/proc/<pid>/exe`
//! magic link is gated by the ptrace access mode and succeeds under
//! `CAP_SYS_PTRACE` alone (`readlink` and `O_PATH` opens work), but the
//! final `O_RDONLY` open performs the ordinary DAC permission check against
//! the target file's own mode via `capable_wrt_inode_uidgid`, and there is
//! no bypass without `CAP_DAC_READ_SEARCH`: the open fails `EACCES`
//! (reopening an `O_PATH` descriptor through `/proc/self/fd` re-runs the
//! same check and fails identically). Adding `CAP_DAC_READ_SEARCH` makes
//! the same open succeed, so the helper's capability trio must keep
//! `CAP_DAC_READ_SEARCH`; dropping it silently breaks measurement of every
//! owner-0700 rootless executable. Recorded on `basil-k9oe`; the
//! `basil-b0p4` policy tightening must not remove the DAC capability.
//!
//! The proof runs unprivileged inside a rootless user namespace
//! (`podman unshare`, subordinate-UID mapping): kernel capability checks
//! against files owned by mapped UIDs are namespace-relative, so ns-root
//! with a reduced bounding set faithfully models a root helper holding only
//! the listed capabilities. The orchestrator test skips (passes with a
//! notice) when the tooling is unavailable.

use std::os::fd::AsFd as _;
use std::path::PathBuf;

use rustix::fs::{Mode, OFlags};

use super::host::ProcExecutableOpener;
use super::service::{ExecutableError, ExecutableOpener as _};

/// Probe role, executed by the orchestrator inside the user namespace under
/// a `setpriv`-reduced bounding set. Ignored so it never runs in a normal
/// suite invocation; the orchestrator selects it with `--exact --ignored`.
#[test]
#[ignore = "probe role: run by cross_uid_exe_pinning_requires_dac_read_search under setpriv"]
#[allow(clippy::unwrap_used)]
fn probe_role() {
    let Ok(pid) = std::env::var("BASIL_CROSS_UID_TARGET_PID") else {
        panic!("probe role requires BASIL_CROSS_UID_TARGET_PID");
    };
    let expect = std::env::var("BASIL_CROSS_UID_EXPECT").unwrap();
    let pid: u32 = pid.parse().unwrap();
    let raw_pid = i32::try_from(pid).unwrap();
    let kernel_pid = rustix::process::Pid::from_raw(raw_pid).unwrap();
    let pidfd =
        rustix::process::pidfd_open(kernel_pid, rustix::process::PidfdFlags::empty()).unwrap();

    // The ptrace-mode gate on the magic link itself passes under
    // CAP_SYS_PTRACE alone: the link target is readable in both probes.
    let target = std::fs::read_link(format!("/proc/{pid}/exe"))
        .expect("readlink of /proc/<pid>/exe must pass the ptrace-mode gate");
    eprintln!("probe: readlink ok -> {}", target.display());

    let opened = ProcExecutableOpener.open_executable(pid, pidfd.as_fd());
    match expect.as_str() {
        // CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH: the open pins the binary.
        "ok" => {
            let fd = opened.expect("open must succeed with CAP_DAC_READ_SEARCH");
            let mut buffer = [0_u8; 4];
            let read = rustix::io::pread(&fd, &mut buffer, 0).unwrap();
            assert_eq!(read, 4, "pinned executable must be readable");
            assert_eq!(&buffer, b"\x7fELF");
        }
        // CAP_SYS_PTRACE only: the final open is denied by the ordinary
        // DAC check on the 0700 cross-UID file; there is no bypass.
        "eacces" => {
            assert!(
                matches!(opened, Err(ExecutableError::Io)),
                "open must fail without CAP_DAC_READ_SEARCH, got {opened:?}"
            );
            let errno = rustix::fs::open(
                format!("/proc/{pid}/exe"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .expect_err("direct open must be denied");
            assert_eq!(errno, rustix::io::Errno::ACCESS);
        }
        other => panic!("unknown BASIL_CROSS_UID_EXPECT value {other}"),
    }
}

/// Locate a tool on `PATH`.
fn which_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Orchestrator: sets up the cross-UID fixture in a rootless user namespace
/// and runs [`probe_role`] twice — once under `CAP_SYS_PTRACE` only
/// (expecting the documented `EACCES` failure) and once with
/// `CAP_DAC_READ_SEARCH` added (expecting success). Skips with a notice
/// when the rootless-namespace tooling is unavailable.
#[test]
#[allow(clippy::unwrap_used)]
fn cross_uid_exe_pinning_requires_dac_read_search() {
    for tool in ["podman", "setpriv", "timeout"] {
        if which_on_path(tool).is_none() {
            eprintln!("skipping cross-UID pinning proof: {tool} not on PATH");
            return;
        }
    }
    let exe = std::env::current_exe().unwrap();
    let exe = exe.to_str().unwrap();
    let probe = "attestor_protocol::helper::cross_uid_proof::probe_role";
    let script = format!(
        r#"
set -eu
work=$(mktemp -d)
trap 'echo done > "$work/gate" 2>/dev/null || true' EXIT
cp /bin/sh "$work/target-bin"
chown 1:1 "$work" "$work/target-bin"
chmod 0700 "$work" "$work/target-bin"
mkfifo "$work/gate"
setpriv --reuid 1 --regid 1 --clear-groups "$work/target-bin" -c \
    "echo \$\$ > '$work_pid'; read _line < '$work_gate'" &
i=0
while [ ! -s "$work/pid" ]; do
  i=$((i+1))
  [ "$i" -gt 100 ] && echo "target never started" >&2 && exit 70
  sleep 0.05
done
pid=$(cat "$work/pid")
BASIL_CROSS_UID_TARGET_PID=$pid BASIL_CROSS_UID_EXPECT=eacces \
    setpriv --bounding-set -all,+sys_ptrace \
    '{exe}' --exact {probe} --ignored
BASIL_CROSS_UID_TARGET_PID=$pid BASIL_CROSS_UID_EXPECT=ok \
    setpriv --bounding-set -all,+sys_ptrace,+dac_read_search \
    '{exe}' --exact {probe} --ignored
"#
    );
    // The inner single-quoted heredoc-style shell cannot interpolate
    // `$work` inside the double-quoted child command line directly; splice
    // the two placeholders now.
    let script = script
        .replace("$work_pid", "$work/pid")
        .replace("$work_gate", "$work/gate");

    // Serialize with listener-drop tests: the namespace setup forks
    // children that briefly hold copies of every open descriptor.
    let output = {
        let _spawn_guard = super::CHILD_SPAWN_TEST_LOCK.lock().unwrap();
        let probe_run = std::process::Command::new("timeout")
            .args(["120", "podman", "unshare", "sh", "-c", &script])
            .output();
        match probe_run {
            Ok(output) => output,
            Err(error) => {
                eprintln!("skipping cross-UID pinning proof: podman unshare failed: {error}");
                return;
            }
        }
    };
    if !output.status.success()
        && String::from_utf8_lossy(&output.stderr).contains("cannot find UID/GID")
    {
        // No subordinate-UID range for this account: the namespace cannot
        // map a second UID, so the cross-UID case is not constructible.
        eprintln!("skipping cross-UID pinning proof: no subordinate UID range");
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "cross-UID pinning proof failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    // Guard against vacuous success: a probe filter matching zero tests
    // would exit 0 without proving anything. Both probe invocations must
    // have run exactly one test each.
    assert_eq!(
        stdout.matches("test result: ok. 1 passed").count(),
        2,
        "expected both probe invocations to run\nstdout:\n{stdout}"
    );
}
