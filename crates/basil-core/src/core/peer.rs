//! Peer attestation for accepted connections.
//!
//! Adapted from `brightnexus-platform`'s `attestation.rs` and the `PeerInfo`
//! shape in `brightnexus-core`'s `handler.rs`. We derive the connecting peer's
//! `(uid, gid, pid)` from `SO_PEERCRED` (via Tokio's `UCred`) and enrich it from
//! `/proc`: the executable path, the process lineage, and any wrapping SSH
//! session.
//!
//! This broker only runs on NixOS, which has no `dpkg` package database, so the
//! attestation is purely credential- and `/proc`-derived (no Debian package
//! verification). It is informational for v1 (logged per connection); a future
//! policy layer can gate `SIGN` on it.

use std::collections::HashMap;
use std::fs;
use std::io::Read;

use tokio::net::UnixStream;

const LINEAGE_CAP: usize = 8;

/// Identity and attestation facts about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub executable_path: Option<String>,
    pub attestation_class: String,
    pub subject_id: Option<String>,
    pub signature_valid: bool,
    pub display_label: Option<String>,
}

impl Default for PeerInfo {
    fn default() -> Self {
        Self {
            pid: None,
            uid: None,
            gid: None,
            executable_path: None,
            // No credential resolved yet; enrichment may upgrade this.
            attestation_class: "Unknown".into(),
            subject_id: None,
            // No package signature is ever checked on NixOS (no dpkg).
            signature_valid: false,
            display_label: None,
        }
    }
}

impl PeerInfo {
    /// Attest the peer on the far end of `stream`.
    #[must_use]
    pub fn from_stream(stream: &UnixStream) -> Self {
        stream.peer_cred().map_or_else(
            |_| Self::default(),
            |cred| {
                // `mut` is consumed only by the Linux-only `enrich_linux` below;
                // on other targets (e.g. macOS) the binding is never mutated.
                #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
                let mut info = Self {
                    pid: cred.pid().map(i32::cast_unsigned),
                    uid: Some(cred.uid()),
                    gid: Some(cred.gid()),
                    ..Default::default()
                };
                #[cfg(target_os = "linux")]
                enrich_linux(&mut info);
                info
            },
        )
    }

    /// Build peer information from already-captured Unix credentials.
    ///
    /// tonic captures connection info before dispatching requests, so gRPC
    /// handlers receive the credential facts through request extensions rather
    /// than from the original [`UnixStream`].
    #[must_use]
    pub fn from_unix_cred(pid: Option<u32>, uid: u32, gid: u32) -> Self {
        // `mut` is consumed only by the Linux-only `enrich_linux` below; on
        // other targets (e.g. macOS) the binding is never mutated.
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut info = Self {
            pid,
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        };
        #[cfg(target_os = "linux")]
        enrich_linux(&mut info);
        info
    }
}

/// Fill in the executable path from `/proc`.
///
/// This broker targets NixOS, which has no `dpkg` package database, so there is
/// no Debian package verification: the attestation is the peer's credential plus
/// its `/proc` executable path. `signature_valid` is always `false` here (there
/// is no package signature to check); a `/proc` exe we can resolve sets
/// `attestation_class = "PeerCred"`, otherwise it stays the default `"Unknown"`.
#[cfg(target_os = "linux")]
fn enrich_linux(info: &mut PeerInfo) {
    if let Some(pid) = info.pid {
        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        info.executable_path.clone_from(&exe);
        info.display_label.clone_from(&exe);
        if exe.is_some() {
            info.attestation_class = "PeerCred".into();
        }
    }
}

/// Read a process's environment from `/proc/<pid>/environ`.
#[must_use]
pub fn read_proc_environ(pid: u32) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(mut f) = fs::File::open(format!("/proc/{pid}/environ")) {
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_ok() {
            for part in buf.split(|&b| b == 0) {
                if let Ok(s) = std::str::from_utf8(part)
                    && let Some((k, v)) = s.split_once('=')
                {
                    map.insert(k.to_string(), v.to_string());
                }
            }
        }
    }
    map
}

/// Walk the parent-PID chain starting at `pid` (capped at [`LINEAGE_CAP`]).
#[must_use]
pub fn lineage_pids(pid: u32) -> Vec<u32> {
    let mut out = vec![pid];
    let mut current = pid;
    for _ in 0..LINEAGE_CAP {
        let Ok(status) = fs::read_to_string(format!("/proc/{current}/status")) else {
            break;
        };
        let parent = status
            .lines()
            .find(|l| l.starts_with("PPid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if parent == 0 || out.contains(&parent) {
            break;
        }
        out.push(parent);
        current = parent;
    }
    out
}

/// If any ancestor in `lineage` is an `sshd`, return the
/// `(user, remote_host, sshd_pid)` session it established.
///
/// Advisory only: on NixOS there is no `dpkg` package database, so the `sshd`
/// process is identified by its `/proc` executable path (not a verified Debian
/// package). A `/proc/<pid>/exe` we cannot read is skipped, not fatal.
#[must_use]
pub fn detect_ssh_session(lineage: &[u32]) -> Option<(String, String, u32)> {
    for &pid in lineage {
        let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) else {
            continue;
        };
        if !exe.to_string_lossy().contains("sshd") {
            continue;
        }
        let env = read_proc_environ(pid);
        let host = remote_host_from_ssh_connection(env.get("SSH_CONNECTION").map(String::as_str));
        let user = env.get("USER").cloned().unwrap_or_default();
        return Some((user, host, pid));
    }
    None
}

/// Extract the remote (client) host from an `SSH_CONNECTION` value.
///
/// `SSH_CONNECTION` is `"<client_ip> <client_port> <server_ip> <server_port>"`;
/// the remote host the broker cares about is the **server-side** address the
/// session terminated on (field index 2). A malformed/absent value yields `""`.
fn remote_host_from_ssh_connection(conn: Option<&str>) -> String {
    conn.unwrap_or_default()
        .split_whitespace()
        .nth(2)
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_connection_host_is_the_server_side_address() {
        // "<client_ip> <client_port> <server_ip> <server_port>".
        assert_eq!(
            remote_host_from_ssh_connection(Some("10.0.0.5 51000 10.0.0.1 22")),
            "10.0.0.1"
        );
    }

    #[test]
    fn ssh_connection_missing_or_malformed_is_empty() {
        assert_eq!(remote_host_from_ssh_connection(None), "");
        assert_eq!(remote_host_from_ssh_connection(Some("")), "");
        assert_eq!(remote_host_from_ssh_connection(Some("only two")), "");
    }

    #[test]
    fn default_peer_is_unknown_and_unsigned() {
        let p = PeerInfo::default();
        assert_eq!(p.attestation_class, "Unknown");
        assert!(!p.signature_valid);
        assert!(p.subject_id.is_none());
    }
}
