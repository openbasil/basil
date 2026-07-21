// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `basil-attestor`: the per-realm, per-generation runtime-attestor process
//! (`docs/attestor-realm-contract/SPEC.md` rev 1.2; packaged at
//! `/usr/libexec/basil/basil-attestor` for the generation-qualified
//! `basil-attestor-<realm>-g<gen>.service` unit).
//!
//! Startup order is the lockdown contract (`basil-rslz`): every thread and
//! long-lived descriptor is created first, the post-init lockdown profile is
//! engaged at the marked boundary (non-dumpable, thread-synchronized seccomp
//! filter install plus verify), and only then does the process bind the realm
//! control socket ([`AttestorListener::bind`]) and advertise readiness
//! (`sd_notify` `READY=1`; there is deliberately no socket unit, so
//! `SO_PEERCRED`/`SO_PEERPIDFD` name this process, never a launcher).
//!
//! Serving state: the listener accepts broker connections and authenticates
//! each peer against the enrollment-installed `broker.toml` trust anchor
//! (SPEC.md rev 1.2): the anchor file is fd-pinned and hashed at startup,
//! and every accepted connection's kernel credentials, race-free pidfd,
//! PID/start time, and system-manager unit are verified and bound into a
//! `VerifiedPeerBinding`. Session construction on top of that binding
//! (epoch agreement, `AttestorSession`, `basil-agrz`) has not landed, so
//! every verified connection is still rejected fail-closed after
//! verification. The process never panics: startup failures exit nonzero
//! and per-connection failures reject one connection.

use std::num::NonZeroU64;
use std::os::linux::net::SocketAddrExt as _;
use std::path::PathBuf;
use std::process::ExitCode;

use basil_core::attestor_protocol::{
    AttestorListener, AttestorListenerOptions, BrokerTrustAnchor, LockdownGuard, LockdownProfile,
    LockdownProfileId, LockdownProfileKind, engage, verify_broker_peer,
};
use basil_core::core::attestor_realm::RealmName;
use clap::Parser;

/// Per-realm, per-generation Basil runtime attestor.
#[derive(Debug, Parser)]
#[command(name = "basil-attestor", version, about)]
struct Args {
    /// Canonical realm name this process serves.
    #[arg(long, value_parser = parse_realm)]
    realm: RealmName,

    /// Exact decimal authority generation this process serves.
    #[arg(long)]
    authority_generation: NonZeroU64,

    /// Generation-qualified runtime directory installed by the authority
    /// transaction.
    ///
    /// Defaults to the canonical
    /// `/run/basil/attestors/<realm>/g<authority-generation>`. An override is
    /// intended only for unprivileged development hosts and must still end
    /// with the exact `g<authority-generation>` component.
    #[arg(long)]
    runtime_directory: Option<PathBuf>,

    /// Exact octal mode the runtime directory must carry.
    #[arg(long, default_value = "0770", value_parser = parse_octal_mode)]
    directory_mode: u32,

    /// Octal mode applied to the bound control socket.
    #[arg(long, default_value = "0660", value_parser = parse_octal_mode)]
    socket_mode: u32,

    /// Exact owner UID the runtime directory must carry.
    ///
    /// Defaults to root: SPEC.md rev 1.2 installs the generation-qualified
    /// runtime directory root-owned in the authority transaction. An
    /// override is intended only for unprivileged development hosts.
    #[arg(long, default_value_t = 0)]
    directory_owner_uid: u32,

    /// Exact owner UID a stale control socket must carry before removal.
    ///
    /// Defaults to this process's effective UID (the unit runs as the
    /// declared `attestorUid` / `socketOwner`, which created any leftover
    /// socket of a previous run). Declared separately from the root
    /// directory owner.
    #[arg(long)]
    socket_owner_uid: Option<u32>,

    /// Enrollment-installed broker trust anchor (`broker.toml`).
    ///
    /// Defaults to the canonical
    /// `/etc/basil/attestors/<realm>/broker.toml`. The file must exist and
    /// validate before serving starts; there is no anchor-less mode.
    #[arg(long)]
    broker_trust_anchor: Option<PathBuf>,

    /// Exact owner UID the trust anchor and its parent must carry.
    ///
    /// Defaults to root (enrollment installs the anchor UID-0-owned below
    /// UID-0-owned non-writable parents). An override is intended only for
    /// unprivileged development hosts.
    #[arg(long, default_value_t = 0)]
    broker_trust_owner_uid: u32,

    /// Checked, generation-qualified lockdown-profile identity to engage.
    ///
    /// Defaults to the canonical `basil-attestor-lockdown-g<authority-generation>`.
    /// An override must still be canonical and embed the exact
    /// `g<authority-generation>` qualifier for the attestor body, so it can
    /// never name a stale generation or the helper body.
    #[arg(long)]
    lockdown_profile: Option<String>,
}

/// Resolve and validate the lockdown-profile identity this process engages.
fn lockdown_profile(args: &Args) -> Result<LockdownProfile, String> {
    let identity = args.lockdown_profile.clone().unwrap_or_else(|| {
        format!(
            "{}-g{}",
            LockdownProfileKind::AttestorV1.identity_base(),
            args.authority_generation
        )
    });
    let id = LockdownProfileId::new(
        &identity,
        args.authority_generation,
        LockdownProfileKind::AttestorV1,
    )
    .map_err(|error| format!("invalid lockdown profile `{identity}`: {error}"))?;
    Ok(LockdownProfile::new(id))
}

/// Validate the realm name against the closed realm grammar.
fn parse_realm(value: &str) -> Result<RealmName, String> {
    RealmName::new(value).map_err(|error| error.to_string())
}

/// Parse a 1-to-4 digit octal mode granting at most owner and group
/// permissions (no `other` bits, no set-id/sticky bits).
fn parse_octal_mode(value: &str) -> Result<u32, String> {
    if value.is_empty() || value.len() > 4 || !value.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err("expected an octal mode such as 0660".to_owned());
    }
    let mode = u32::from_str_radix(value, 8).map_err(|error| error.to_string())?;
    if mode & !0o770 != 0 {
        return Err(
            "mode must grant no `other` permissions and no set-id/sticky bits (maximum 0770)"
                .to_owned(),
        );
    }
    Ok(mode)
}

/// The checked runtime-directory location for one realm generation.
///
/// The default is canonical; an override must still end with the exact
/// generation-qualified `g<gen>` component (the checked generation binding
/// from the realm contract), so a stale or wrong-generation directory can
/// never be bound.
fn runtime_directory(args: &Args) -> Result<PathBuf, String> {
    let generation_component = format!("g{}", args.authority_generation);
    match &args.runtime_directory {
        None => Ok(PathBuf::from("/run/basil/attestors")
            .join(args.realm.as_str())
            .join(generation_component)),
        Some(directory) => {
            if directory.file_name().and_then(|name| name.to_str())
                == Some(generation_component.as_str())
            {
                Ok(directory.clone())
            } else {
                Err(format!(
                    "--runtime-directory must end with the exact generation component `{generation_component}`"
                ))
            }
        }
    }
}

/// The checked trust-anchor location for one realm.
fn trust_anchor_path(args: &Args) -> PathBuf {
    args.broker_trust_anchor.clone().unwrap_or_else(|| {
        PathBuf::from("/etc/basil/attestors")
            .join(args.realm.as_str())
            .join("broker.toml")
    })
}

/// Pause after one failed `accept` so a persistent failure cannot busy-spin.
const ACCEPT_FAILURE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Consecutive `accept` failures after which the process exits nonzero so
/// the system manager restarts it instead of wedging.
const MAX_CONSECUTIVE_ACCEPT_FAILURES: u32 = 100;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    // Never create anything wider than owner-only before the explicit chmod.
    basil_core::attestor_protocol::helper::transport::set_restrictive_umask();

    let directory = match runtime_directory(&args) {
        Ok(directory) => directory,
        Err(error) => {
            tracing::error!(%error, "invalid runtime directory");
            return ExitCode::FAILURE;
        }
    };
    let socket_path = directory.join("control.sock");
    let options = AttestorListenerOptions {
        required_directory_owner_uid: args.directory_owner_uid,
        required_directory_mode: args.directory_mode,
        required_socket_owner_uid: args
            .socket_owner_uid
            .unwrap_or_else(|| rustix::process::geteuid().as_raw()),
        socket_mode: args.socket_mode,
    };

    // The broker trust anchor must exist and validate before serving
    // (enrollment installs it before unit start); there is no anchor-less
    // serving mode.
    let anchor_path = trust_anchor_path(&args);
    let anchor = match BrokerTrustAnchor::load(
        &anchor_path,
        args.realm.as_str(),
        args.broker_trust_owner_uid,
    ) {
        Ok(anchor) => anchor,
        Err(error) => {
            tracing::error!(
                %error,
                path = %anchor_path.display(),
                "failed to load the broker trust anchor"
            );
            return ExitCode::FAILURE;
        }
    };

    // Pre-bind resource creation: the (single-threaded) runtime and every
    // long-lived descriptor exist before the lockdown boundary below, so the
    // engaged filter never has to permit thread or runtime construction.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "failed to build the async runtime");
            return ExitCode::FAILURE;
        }
    };

    // ----- basil-rslz lockdown boundary -------------------------------------
    // The post-init lockdown primitive engages here, after every thread and
    // long-lived descriptor exists (the current-thread runtime above and every
    // fd opened by `bind` inside `serve` — note `bind` opens only the realm
    // socket, which is the guarded operation itself) and before the realm
    // socket is bound: PR_SET_DUMPABLE(0), thread-synchronized (TSYNC) seccomp
    // filter install, then filter verification. The returned guard is required
    // by `AttestorListener::bind`, so binding is unreachable until lockdown is
    // engaged. The manager-applied unit baseline filter stacks additively.
    // ------------------------------------------------------------------------
    let profile = match lockdown_profile(&args) {
        Ok(profile) => profile,
        Err(error) => {
            tracing::error!(%error, "invalid lockdown profile");
            return ExitCode::FAILURE;
        }
    };
    let lockdown = match engage(&profile) {
        Ok(guard) => guard,
        Err(error) => {
            tracing::error!(%error, "failed to engage post-init lockdown before bind");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        profile = lockdown.profile().as_str(),
        "post-init lockdown engaged"
    );

    runtime.block_on(serve(&args, &socket_path, &options, &anchor, &lockdown))
}

async fn serve(
    args: &Args,
    socket_path: &std::path::Path,
    options: &AttestorListenerOptions,
    anchor: &BrokerTrustAnchor,
    lockdown: &LockdownGuard,
) -> ExitCode {
    let listener = match AttestorListener::bind(socket_path, options, lockdown) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, path = %socket_path.display(), "failed to bind the realm control socket");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        realm = args.realm.as_str(),
        generation = args.authority_generation.get(),
        path = %socket_path.display(),
        "realm control socket bound"
    );
    notify_ready();

    let mut consecutive_accept_failures: u32 = 0;
    loop {
        let accepted = match listener.accept().await {
            Ok(accepted) => {
                consecutive_accept_failures = 0;
                accepted
            }
            Err(error) => {
                consecutive_accept_failures = consecutive_accept_failures.saturating_add(1);
                if consecutive_accept_failures >= MAX_CONSECUTIVE_ACCEPT_FAILURES {
                    tracing::error!(%error, "persistent accept failure; exiting for restart");
                    return ExitCode::FAILURE;
                }
                tracing::warn!(%error, "accept failed; backing off");
                tokio::time::sleep(ACCEPT_FAILURE_BACKOFF).await;
                continue;
            }
        };
        // Full broker peer verification against the trust anchor before any
        // protocol byte: kernel credentials, race-free pidfd, PID/start
        // time, and the exact enrolled system unit.
        match verify_broker_peer(
            anchor,
            accepted.credentials,
            std::os::fd::AsFd::as_fd(&accepted.stream),
        ) {
            Ok(verified) => {
                // The mutual peer binding is derived, but session
                // construction on top of it (epoch agreement,
                // `AttestorSession`) has not landed (basil-agrz); fail
                // closed rather than speak the protocol without a session.
                drop(verified);
                tracing::warn!(
                    peer_uid = accepted.credentials.uid,
                    "verified broker connection rejected: attestor-side session construction not yet available (basil-agrz)"
                );
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    peer_uid = accepted.credentials.uid,
                    "connection rejected: broker peer verification failed"
                );
            }
        }
        drop(accepted);
    }
}

/// Advertise `Type=notify` readiness to the service manager, if present.
///
/// Best-effort by design: a missing or unwritable `NOTIFY_SOCKET` is not a
/// serving failure (development hosts run without a manager).
fn notify_ready() {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let Some(path) = socket.to_str() else {
        tracing::warn!("NOTIFY_SOCKET is not valid UTF-8; readiness not advertised");
        return;
    };
    let result = std::os::unix::net::UnixDatagram::unbound().and_then(|datagram| {
        if let Some(abstract_name) = path.strip_prefix('@') {
            let address =
                std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())?;
            datagram.send_to_addr(b"READY=1", &address)
        } else {
            datagram.send_to(b"READY=1", path)
        }
    });
    match result {
        Ok(_) => tracing::info!("readiness advertised to the service manager"),
        Err(error) => tracing::warn!(%error, "failed to advertise readiness"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("basil-attestor").chain(arguments.iter().copied()))
    }

    #[test]
    fn canonical_runtime_directory_is_generation_qualified() {
        let args = parse(&["--realm", "owner-podman", "--authority-generation", "3"]).unwrap();
        assert_eq!(
            runtime_directory(&args).unwrap(),
            PathBuf::from("/run/basil/attestors/owner-podman/g3")
        );
    }

    #[test]
    fn runtime_directory_override_must_embed_the_exact_generation() {
        let args = parse(&[
            "--realm",
            "owner-podman",
            "--authority-generation",
            "3",
            "--runtime-directory",
            "/tmp/dev/g3",
        ])
        .unwrap();
        assert_eq!(
            runtime_directory(&args).unwrap(),
            PathBuf::from("/tmp/dev/g3")
        );
        for wrong in ["/tmp/dev/g2", "/tmp/dev/g33", "/tmp/dev/gen3", "/tmp/dev"] {
            let args = parse(&[
                "--realm",
                "owner-podman",
                "--authority-generation",
                "3",
                "--runtime-directory",
                wrong,
            ])
            .unwrap();
            assert!(runtime_directory(&args).is_err(), "accepted {wrong}");
        }
    }

    #[test]
    fn generation_and_realm_reject_invalid_values() {
        assert!(parse(&["--realm", "owner-podman", "--authority-generation", "0"]).is_err());
        assert!(parse(&["--realm", "Not-Canonical", "--authority-generation", "1"]).is_err());
        assert!(parse(&["--realm", "", "--authority-generation", "1"]).is_err());
    }

    #[test]
    fn trust_anchor_defaults_to_the_canonical_realm_path() {
        let args = parse(&["--realm", "owner-podman", "--authority-generation", "3"]).unwrap();
        assert_eq!(
            trust_anchor_path(&args),
            PathBuf::from("/etc/basil/attestors/owner-podman/broker.toml")
        );
        let args = parse(&[
            "--realm",
            "owner-podman",
            "--authority-generation",
            "3",
            "--broker-trust-anchor",
            "/tmp/dev/broker.toml",
        ])
        .unwrap();
        assert_eq!(
            trust_anchor_path(&args),
            PathBuf::from("/tmp/dev/broker.toml")
        );
    }

    /// Rev 1.2 defaults: the runtime directory and the trust anchor are
    /// root-owned installed state, while the socket owner defaults to this
    /// process (the attestor account creates the socket).
    #[test]
    fn ownership_defaults_follow_the_installed_authority() {
        let args = parse(&["--realm", "owner-podman", "--authority-generation", "3"]).unwrap();
        assert_eq!(args.directory_owner_uid, 0);
        assert_eq!(args.broker_trust_owner_uid, 0);
        assert_eq!(args.socket_owner_uid, None);
    }

    #[test]
    fn octal_mode_accepts_owner_and_group_permissions_only() {
        assert_eq!(parse_octal_mode("0770").unwrap(), 0o770);
        assert_eq!(parse_octal_mode("0660").unwrap(), 0o660);
        assert!(parse_octal_mode("0666").is_err());
        assert!(parse_octal_mode("0777").is_err());
        assert!(parse_octal_mode("1770").is_err());
        assert!(parse_octal_mode("").is_err());
    }
}
