// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! `basil-measure-helper`: the root-owned, capability-minimized measurement
//! helper service (Design 0001 revision 1.2, `basil-ln84`).
//!
//! One instance runs per host on the single shared, non-generation-qualified
//! `SOCK_SEQPACKET` endpoint. It answers broker measurement requests under
//! its root-owned, generation-versioned allowlist and holds no runtime API,
//! key, or policy-decision authority. Packaging (system unit, `CAP_SYS_PTRACE`
//! bounding set, LSM confinement, syscall filter) is installed by enrollment;
//! this process only loads its allowlist, binds its endpoint, and serves
//! serially.
//!
//! The helper never panics: every failure is logged and either rejects one
//! request or exits with a nonzero status at startup.

use std::path::PathBuf;
use std::process::ExitCode;

use basil_core::attestor_protocol::helper::host::{
    AuthorityManifestOptions, DEFAULT_MANIFEST_DIRECTORY, ManifestEvidenceInspector,
};
use basil_core::attestor_protocol::helper::{
    AllowlistLoadOptions, HelperConnection, HelperEndpointOptions, HelperListener, HelperService,
    InstalledAllowlist, host, serve_connection,
};
use basil_core::attestor_protocol::{
    LockdownProfile, LockdownProfileId, LockdownProfileKind, engage,
};
use clap::Parser;

/// Root-owned measurement helper for Basil attestor realms.
#[derive(Debug, Parser)]
#[command(name = "basil-measure-helper", version, about)]
struct Args {
    /// Path of the single shared helper endpoint socket.
    #[arg(long, default_value = "/run/basil/measure/control.sock")]
    endpoint: PathBuf,

    /// Directory of installed root-owned helper policy generations.
    #[arg(long, default_value = "/etc/basil/measure/policy.d")]
    policy_dir: PathBuf,

    /// Directory of installed root-owned authority manifests.
    ///
    /// The confinement-evidence store the helper re-reads per measurement to
    /// bind each generation's LSM identity to its lockdown-profile identity.
    /// Defaults to the production store; naming an explicit directory (paired
    /// with `--required-owner-uid`) lets unprivileged development hosts and
    /// the live e2e lanes point at a store they own, mirroring `--policy-dir`.
    #[arg(long, default_value = DEFAULT_MANIFEST_DIRECTORY)]
    manifest_dir: PathBuf,

    /// Octal mode applied to the bound endpoint socket.
    #[arg(long, default_value = "0660", value_parser = parse_octal_mode)]
    socket_mode: u32,

    /// Required owner UID for the policy directory, manifest directory, and
    /// endpoint parent.
    ///
    /// Production deployments must keep the default of 0 (root). Overriding
    /// is intended only for unprivileged development hosts.
    #[arg(long, default_value_t = 0)]
    required_owner_uid: u32,

    /// Authority generation that installed this helper's unit and lockdown
    /// profile.
    ///
    /// Binds the engaged lockdown-profile identity to a generation, matching
    /// the generation-versioned helper authority (`basil-ln84`). Required: the
    /// helper fails closed rather than engage an unversioned lockdown.
    #[arg(long)]
    lockdown_generation: std::num::NonZeroU64,

    /// Checked, generation-qualified lockdown-profile identity to engage.
    ///
    /// Defaults to the canonical
    /// `basil-measure-helper-lockdown-g<lockdown-generation>`. An override must
    /// still be canonical and embed the exact `g<lockdown-generation>`
    /// qualifier for the helper body.
    #[arg(long)]
    lockdown_profile: Option<String>,
}

/// Resolve and validate the lockdown-profile identity this helper engages.
fn lockdown_profile(args: &Args) -> Result<LockdownProfile, String> {
    let identity = args.lockdown_profile.clone().unwrap_or_else(|| {
        format!(
            "{}-g{}",
            LockdownProfileKind::MeasureHelperV1.identity_base(),
            args.lockdown_generation
        )
    });
    let id = LockdownProfileId::new(
        &identity,
        args.lockdown_generation,
        LockdownProfileKind::MeasureHelperV1,
    )
    .map_err(|error| format!("invalid lockdown profile `{identity}`: {error}"))?;
    Ok(LockdownProfile::new(id))
}

/// Parse a 1-to-4 digit octal mode granting at most owner and group
/// permissions.
///
/// Any `other` permission bit and any set-id/sticky bit rejects, so an
/// operator typo (for example `0666` or `0777`) can never make the root-owned
/// measurement endpoint world-connectable.
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

/// Pause after one failed `accept` so a persistent failure (for example
/// descriptor exhaustion on a service that receives forwarded fds) cannot
/// busy-spin at warn rate.
const ACCEPT_FAILURE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

/// Consecutive `accept` failures after which the helper exits nonzero so the
/// system manager restarts it instead of wedging.
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

    let allowlist = match InstalledAllowlist::load_dir(
        &args.policy_dir,
        &AllowlistLoadOptions {
            required_owner_uid: args.required_owner_uid,
        },
    ) {
        Ok(allowlist) => allowlist,
        Err(error) => {
            tracing::error!(%error, "failed to load the installed helper allowlist");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        generations = allowlist.generation_count(),
        "loaded installed helper policy generations"
    );

    // ----- basil-rslz lockdown boundary -------------------------------------
    // Engage the post-init lockdown after the allowlist and every long-lived
    // descriptor exist, and before the endpoint is bound. The returned guard is
    // required by `HelperListener::bind`, so binding is unreachable until
    // lockdown is engaged: PR_SET_DUMPABLE(0), TSYNC seccomp install, verify.
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

    let listener = match HelperListener::bind(
        &args.endpoint,
        &HelperEndpointOptions {
            required_parent_owner_uid: args.required_owner_uid,
            socket_mode: args.socket_mode,
        },
        &lockdown,
    ) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(%error, "failed to bind the helper endpoint");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(endpoint = %args.endpoint.display(), "measurement helper serving");

    let service = HelperService::new(
        allowlist,
        host::KernelPeerPidfdSource,
        host::SystemdUnitResolver,
        ManifestEvidenceInspector::new(AuthorityManifestOptions {
            directory: args.manifest_dir,
            required_owner_uid: args.required_owner_uid,
        }),
        host::ProcExecutableOpener,
    );

    let mut consecutive_accept_failures: u32 = 0;
    loop {
        let connection: HelperConnection = match listener.accept() {
            Ok(connection) => {
                consecutive_accept_failures = 0;
                connection
            }
            Err(error) => {
                consecutive_accept_failures = consecutive_accept_failures.saturating_add(1);
                if consecutive_accept_failures >= MAX_CONSECUTIVE_ACCEPT_FAILURES {
                    tracing::error!(%error, "persistent accept failure; exiting for restart");
                    return ExitCode::FAILURE;
                }
                tracing::warn!(%error, "accept failed; backing off");
                std::thread::sleep(ACCEPT_FAILURE_BACKOFF);
                continue;
            }
        };
        if let Err(error) = serve_connection(&connection, &service) {
            tracing::warn!(%error, "connection ended with a transport error");
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::path::Path;

    use clap::Parser;

    use super::{
        Args, DEFAULT_MANIFEST_DIRECTORY, LockdownProfileKind, lockdown_profile, parse_octal_mode,
    };

    #[test]
    fn manifest_dir_defaults_to_the_production_store() {
        let args =
            Args::try_parse_from(["basil-measure-helper", "--lockdown-generation", "1"]).unwrap();
        assert_eq!(args.manifest_dir, Path::new(DEFAULT_MANIFEST_DIRECTORY));
        // The default trust anchor stays root; nothing is loosened implicitly.
        assert_eq!(args.required_owner_uid, 0);
    }

    #[test]
    fn manifest_dir_and_required_owner_uid_override_together() {
        let args = Args::try_parse_from([
            "basil-measure-helper",
            "--lockdown-generation",
            "1",
            "--manifest-dir",
            "/home/dev/manifests",
            "--required-owner-uid",
            "1000",
        ])
        .unwrap();
        assert_eq!(args.manifest_dir, Path::new("/home/dev/manifests"));
        assert_eq!(args.required_owner_uid, 1000);
    }

    #[test]
    fn lockdown_generation_is_required() {
        assert!(Args::try_parse_from(["basil-measure-helper"]).is_err());
    }

    #[test]
    fn lockdown_profile_defaults_to_the_canonical_generation_identity() {
        let args =
            Args::try_parse_from(["basil-measure-helper", "--lockdown-generation", "5"]).unwrap();
        let profile = lockdown_profile(&args).expect("canonical profile");
        assert_eq!(
            profile.identity().as_str(),
            "basil-measure-helper-lockdown-g5"
        );
        assert_eq!(profile.kind(), LockdownProfileKind::MeasureHelperV1);
    }

    #[test]
    fn lockdown_profile_rejects_wrong_generation_or_body() {
        // Override naming a different generation than declared.
        let args = Args::try_parse_from([
            "basil-measure-helper",
            "--lockdown-generation",
            "5",
            "--lockdown-profile",
            "basil-measure-helper-lockdown-g4",
        ])
        .unwrap();
        assert!(lockdown_profile(&args).is_err());
        // Override naming the attestor body.
        let args = Args::try_parse_from([
            "basil-measure-helper",
            "--lockdown-generation",
            "5",
            "--lockdown-profile",
            "basil-attestor-lockdown-g5",
        ])
        .unwrap();
        assert!(lockdown_profile(&args).is_err());
    }

    #[test]
    fn octal_mode_accepts_owner_and_group_permissions_only() {
        assert_eq!(parse_octal_mode("0660").unwrap(), 0o660);
        assert_eq!(parse_octal_mode("0600").unwrap(), 0o600);
        assert_eq!(parse_octal_mode("0770").unwrap(), 0o770);
        assert_eq!(parse_octal_mode("0").unwrap(), 0);
        assert!(parse_octal_mode("0666").is_err());
        assert!(parse_octal_mode("0777").is_err());
        assert!(parse_octal_mode("0664").is_err());
        assert!(parse_octal_mode("2660").is_err());
        assert!(parse_octal_mode("1770").is_err());
        assert!(parse_octal_mode("").is_err());
        assert!(parse_octal_mode("088").is_err());
        assert!(parse_octal_mode("06600").is_err());
    }
}
