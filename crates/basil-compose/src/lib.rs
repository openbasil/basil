// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Bounded projection of a Docker Compose v2 effective model.
//!
//! The selected frontend owns merging, interpolation, includes, extensions,
//! and profile semantics. This crate invokes its `config` operation with an
//! exact argument vector, then retains only the small allowlist represented by
//! [`EffectiveModel`]. It never parses source Compose files.

#![cfg_attr(test, allow(clippy::indexing_slicing, clippy::unwrap_used))]

use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use zeroize::Zeroizing;

mod parse;

/// Maximum accepted normalized JSON output: eight mebibytes.
pub const MAX_STDOUT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum consumed frontend diagnostics: 64 kibibytes.
pub const MAX_STDERR_BYTES: usize = 64 * 1024;
/// Maximum number of services retained from one project.
pub const MAX_SERVICES: usize = 256;
/// Maximum number of profiles retained for one service.
pub const MAX_PROFILES_PER_SERVICE: usize = 64;
/// Maximum project, service, or profile name length in bytes.
pub const MAX_NAME_BYTES: usize = 128;
/// Maximum image, platform, or build-provenance string length in bytes.
pub const MAX_VALUE_BYTES: usize = 2 * 1024;
/// Maximum decoded JSON nesting accepted from the frontend.
pub const MAX_JSON_DEPTH: usize = 64;
/// Maximum encoded size of any one JSON string token.
pub const MAX_JSON_STRING_BYTES: usize = 64 * 1024;
/// Maximum structural tokens inspected before typed projection.
pub const MAX_JSON_TOKENS: usize = 1_000_000;
/// Maximum time allowed for the frontend and projection operation.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A tested frontend for the Docker Compose v2 normalized JSON contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Frontend {
    /// Docker with its integrated Compose v2 plugin.
    Docker {
        /// Absolute path to the selected Docker executable.
        executable: PathBuf,
    },
    /// Rootless Podman with an explicitly pinned Docker Compose v2 provider.
    Podman {
        /// Absolute path to the selected Podman executable.
        executable: PathBuf,
        /// Absolute path to the tested external Docker Compose v2 provider.
        provider: PathBuf,
    },
}

/// Inputs which must match the later workload-launch invocation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Invocation {
    /// Compose files, in merge order.
    pub files: Vec<PathBuf>,
    /// Enabled profiles, in command-line order.
    pub profiles: Vec<String>,
    /// Compose environment files, in precedence order.
    pub environment_files: Vec<PathBuf>,
    /// Explicit effective project name, when selected by the operator.
    pub project_name: Option<String>,
    /// Explicit project directory used for relative path resolution.
    pub project_directory: Option<PathBuf>,
}

/// Exact process specification used to render the effective model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
}

impl CommandSpec {
    /// Selected executable path.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Exact argument vector, excluding argument zero.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// Explicit environment overrides required by the frontend.
    #[must_use]
    pub const fn environment(&self) -> &BTreeMap<OsString, OsString> {
        &self.environment
    }

    /// Render the invocation for operator review using debug-escaped arguments.
    ///
    /// This string is informational only and is never interpreted by a shell.
    #[must_use]
    #[allow(clippy::unnecessary_debug_formatting)]
    pub fn display(&self) -> String {
        // `Debug` preserves non-UTF-8 platform strings and escapes control
        // characters. A lossy `Display` rendering could show a different argv.
        let mut rendered = format!("{:?}", self.program);
        for argument in &self.arguments {
            let _ = write!(rendered, " {argument:?}");
        }
        rendered
    }
}

/// Sanitized effective Compose project.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectiveModel {
    /// Effective Compose project name.
    pub name: String,
    /// Services keyed by their effective Compose service name.
    pub services: BTreeMap<String, Service>,
}

/// Sanitized effective service facts needed by later Basil generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Service {
    /// Effective image reference, if supplied by the frontend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Effective target platform, if supplied by the frontend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Profiles associated with the service.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<String>,
    /// Non-sensitive local-build provenance, if the service has a build.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<Build>,
}

/// Non-sensitive build provenance retained for operator diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Build {
    /// Effective build context path, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Effective Dockerfile path, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
}

/// Failure to invoke or safely project an effective model.
#[derive(Debug, Error)]
pub enum ProjectionError {
    /// The selected executable or provider was not an absolute path.
    #[error("Compose frontend and provider paths must be absolute")]
    RelativeExecutable,
    /// An invocation input exceeded its documented bound.
    #[error("Compose invocation input exceeds its allowed bound")]
    InvocationLimit,
    /// The frontend process could not be launched or observed.
    #[error("Compose frontend execution failed")]
    Execution(#[source] std::io::Error),
    /// The frontend exceeded its execution deadline.
    #[error("Compose frontend execution timed out")]
    Timeout,
    /// Frontend stdout or stderr exceeded its byte bound.
    #[error("Compose frontend output exceeds its allowed bound")]
    OutputLimit,
    /// The frontend returned a non-success exit status.
    #[error("Compose frontend returned an unsuccessful status")]
    FrontendFailed,
    /// The output was not the tested normalized JSON contract.
    #[error("Compose frontend returned invalid normalized JSON")]
    InvalidModel,
    /// A retained field or collection exceeded its projection bound.
    #[error("Compose effective model exceeds its allowed bound")]
    ModelLimit,
}

/// Build the exact frontend `config` process specification.
pub fn command_spec(
    frontend: &Frontend,
    invocation: &Invocation,
) -> Result<CommandSpec, ProjectionError> {
    validate_invocation(invocation)?;
    let (program, mut arguments, environment) = match frontend {
        Frontend::Docker { executable } => {
            require_absolute(executable)?;
            (
                executable.clone(),
                vec![OsString::from("compose")],
                BTreeMap::new(),
            )
        }
        Frontend::Podman {
            executable,
            provider,
        } => {
            require_absolute(executable)?;
            require_absolute(provider)?;
            let environment = BTreeMap::from([(
                OsString::from("PODMAN_COMPOSE_PROVIDER"),
                provider.as_os_str().to_owned(),
            )]);
            (
                executable.clone(),
                vec![OsString::from("compose")],
                environment,
            )
        }
    };

    for file in &invocation.files {
        push_pair(&mut arguments, "--file", file.as_os_str());
    }
    for profile in &invocation.profiles {
        push_pair(&mut arguments, "--profile", OsStr::new(profile));
    }
    for environment_file in &invocation.environment_files {
        push_pair(&mut arguments, "--env-file", environment_file.as_os_str());
    }
    if let Some(project_name) = &invocation.project_name {
        push_pair(&mut arguments, "--project-name", OsStr::new(project_name));
    }
    if let Some(project_directory) = &invocation.project_directory {
        push_pair(
            &mut arguments,
            "--project-directory",
            project_directory.as_os_str(),
        );
    }
    arguments.extend([
        OsString::from("config"),
        OsString::from("--format"),
        OsString::from("json"),
        OsString::from("--no-env-resolution"),
    ]);

    Ok(CommandSpec {
        program,
        arguments,
        environment,
    })
}

/// Invoke the frontend and return only the bounded allowlisted projection.
pub async fn project(
    frontend: &Frontend,
    invocation: &Invocation,
) -> Result<EffectiveModel, ProjectionError> {
    project_with_timeout(frontend, invocation, DEFAULT_TIMEOUT).await
}

/// Invoke the frontend with an explicit deadline.
pub async fn project_with_timeout(
    frontend: &Frontend,
    invocation: &Invocation,
    timeout: Duration,
) -> Result<EffectiveModel, ProjectionError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ProjectionError::Timeout)?;
    let spec = command_spec(frontend, invocation)?;
    let mut command = Command::new(spec.program());
    command
        .args(spec.arguments())
        .envs(spec.environment())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(ProjectionError::Execution)?;
    let stdout = child.stdout.take().ok_or_else(|| {
        ProjectionError::Execution(std::io::Error::other("stdout pipe unavailable"))
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        ProjectionError::Execution(std::io::Error::other("stderr pipe unavailable"))
    })?;

    let execution = async move {
        let (status, stdout, _stderr) = tokio::try_join!(
            async { child.wait().await.map_err(ProjectionError::Execution) },
            read_bounded(stdout, MAX_STDOUT_BYTES),
            read_bounded(stderr, MAX_STDERR_BYTES),
        )?;
        if !status.success() {
            return Err(ProjectionError::FrontendFailed);
        }
        Ok(stdout)
    };
    let stdout = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), execution)
        .await
        .map_err(|_| ProjectionError::Timeout)??;
    parse::project_json(&stdout, deadline)
}

/// Project already-bounded Docker Compose v2 normalized JSON.
///
/// Errors never contain raw input or retained values.
pub fn project_json(json: &[u8]) -> Result<EffectiveModel, ProjectionError> {
    let deadline = Instant::now()
        .checked_add(DEFAULT_TIMEOUT)
        .ok_or(ProjectionError::Timeout)?;
    parse::project_json(json, deadline)
}

async fn read_bounded(
    reader: impl AsyncRead + Unpin,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, ProjectionError> {
    let capacity = limit.min(64 * 1024);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    let read_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    reader
        .take(read_limit)
        .read_to_end(&mut bytes)
        .await
        .map_err(ProjectionError::Execution)?;
    if bytes.len() > limit {
        return Err(ProjectionError::OutputLimit);
    }
    Ok(bytes)
}

fn validate_invocation(invocation: &Invocation) -> Result<(), ProjectionError> {
    if invocation.files.len() > 64
        || invocation.profiles.len() > 64
        || invocation.environment_files.len() > 64
    {
        return Err(ProjectionError::InvocationLimit);
    }
    if invocation
        .profiles
        .iter()
        .any(|profile| profile.is_empty() || profile.len() > MAX_NAME_BYTES)
        || invocation
            .project_name
            .as_ref()
            .is_some_and(|name| name.is_empty() || name.len() > MAX_NAME_BYTES)
    {
        return Err(ProjectionError::InvocationLimit);
    }
    Ok(())
}

fn require_absolute(path: &Path) -> Result<(), ProjectionError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(ProjectionError::RelativeExecutable)
    }
}

fn push_pair(arguments: &mut Vec<OsString>, flag: &str, value: &OsStr) {
    arguments.push(OsString::from(flag));
    arguments.push(value.to_owned());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempFrontend(PathBuf);

    impl TempFrontend {
        fn new(body: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("basil-compose-test-{}-{nonce}", std::process::id()));
            fs::write(&path, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TempFrontend {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn docker_argv_preserves_all_launch_inputs_in_order() {
        let invocation = Invocation {
            files: vec!["compose.yaml".into(), "compose.prod.yaml".into()],
            profiles: vec!["worker".into(), "metrics".into()],
            environment_files: vec!["base.env".into(), "prod.env".into()],
            project_name: Some("payments".into()),
            project_directory: Some("/srv/payments".into()),
        };
        let spec = command_spec(
            &Frontend::Docker {
                executable: "/usr/bin/docker".into(),
            },
            &invocation,
        )
        .unwrap();
        let expected: Vec<OsString> = [
            "compose",
            "--file",
            "compose.yaml",
            "--file",
            "compose.prod.yaml",
            "--profile",
            "worker",
            "--profile",
            "metrics",
            "--env-file",
            "base.env",
            "--env-file",
            "prod.env",
            "--project-name",
            "payments",
            "--project-directory",
            "/srv/payments",
            "config",
            "--format",
            "json",
            "--no-env-resolution",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert_eq!(spec.program(), Path::new("/usr/bin/docker"));
        assert_eq!(spec.arguments(), expected);
        assert!(spec.environment().is_empty());
    }

    #[test]
    fn podman_pins_the_tested_provider_for_the_same_argv() {
        let spec = command_spec(
            &Frontend::Podman {
                executable: "/usr/bin/podman".into(),
                provider: "/usr/libexec/docker-compose".into(),
            },
            &Invocation::default(),
        )
        .unwrap();
        assert_eq!(
            spec.arguments(),
            [
                "compose",
                "config",
                "--format",
                "json",
                "--no-env-resolution"
            ]
            .map(OsString::from)
        );
        assert_eq!(
            spec.environment()
                .get(OsStr::new("PODMAN_COMPOSE_PROVIDER")),
            Some(&OsString::from("/usr/libexec/docker-compose"))
        );
    }

    #[test]
    fn projection_discards_rendered_sensitive_and_operational_values() {
        let secret = "TOP-SECRET-INTERPOLATED-VALUE";
        let json = format!(
            r#"{{
              "name":"payments",
              "services":{{
                "api":{{
                  "image":"registry.example/api:stable",
                  "platform":"linux/amd64",
                  "profiles":["prod"],
                  "environment":{{"TOKEN":"{secret}"}},
                  "labels":{{"secret-label":"{secret}"}},
                  "configs":[{{"content":"{secret}"}}],
                  "secrets":[{{"environment":"{secret}"}}],
                  "command":["--token", "{secret}"]
                }}
              }},
              "x-sensitive":"{secret}"
            }}"#
        );
        let model = project_json(json.as_bytes()).unwrap();
        let sanitized = serde_json::to_string(&model).unwrap();
        assert_eq!(model.name, "payments");
        assert!(!sanitized.contains(secret));
        assert!(!sanitized.contains("environment"));
        assert!(!sanitized.contains("configs"));
        assert!(!sanitized.contains("secrets"));
        assert!(!sanitized.contains("command"));
    }

    #[test]
    fn normalized_build_and_local_image_cases_are_retained() {
        let model = project_json(
            br#"{
              "name":"local",
              "services":{
                "built":{"image":"local-api","build":{"context":".","dockerfile":"Containerfile"}},
                "context-only":{"build":"./worker"},
                "prebuilt":{"image":"registry.example/prebuilt@sha256:abc"}
              }
            }"#,
        )
        .unwrap();
        assert_eq!(model.services["built"].image.as_deref(), Some("local-api"));
        assert_eq!(
            model.services["built"]
                .build
                .as_ref()
                .unwrap()
                .dockerfile
                .as_deref(),
            Some("Containerfile")
        );
        assert_eq!(
            model.services["context-only"]
                .build
                .as_ref()
                .unwrap()
                .context
                .as_deref(),
            Some("./worker")
        );
        assert!(model.services["prebuilt"].build.is_none());
    }

    #[test]
    fn malicious_output_and_retained_collections_are_bounded() {
        let oversized = vec![b' '; MAX_STDOUT_BYTES + 1];
        assert!(matches!(
            project_json(&oversized),
            Err(ProjectionError::OutputLimit)
        ));

        let services = (0..=MAX_SERVICES)
            .map(|index| format!(r#""service-{index}":{{}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(r#"{{"name":"bounded","services":{{{services}}}}}"#);
        assert!(matches!(
            project_json(json.as_bytes()),
            Err(ProjectionError::ModelLimit)
        ));
    }

    #[test]
    fn malicious_strings_nesting_and_build_shapes_reject_before_projection() {
        let oversized_name = "x".repeat(MAX_NAME_BYTES + 1);
        let json = format!(r#"{{"name":"p","services":{{"{oversized_name}":{{}}}}}}"#);
        assert!(matches!(
            project_json(json.as_bytes()),
            Err(ProjectionError::ModelLimit)
        ));

        let escaped_name = "\\u0061".repeat(MAX_NAME_BYTES + 1);
        let json = format!(r#"{{"name":"p","services":{{"{escaped_name}":{{}}}}}}"#);
        assert!(matches!(
            project_json(json.as_bytes()),
            Err(ProjectionError::ModelLimit)
        ));

        let profiles = (0..=MAX_PROFILES_PER_SERVICE)
            .map(|index| format!(r#""profile-{index}""#))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(r#"{{"name":"p","services":{{"api":{{"profiles":[{profiles}]}}}}}}"#);
        assert!(matches!(
            project_json(json.as_bytes()),
            Err(ProjectionError::ModelLimit)
        ));

        let oversized_unknown = "x".repeat(MAX_JSON_STRING_BYTES + 1);
        let json = format!(r#"{{"name":"p","services":{{}},"unknown":"{oversized_unknown}"}}"#);
        assert!(matches!(
            project_json(json.as_bytes()),
            Err(ProjectionError::ModelLimit)
        ));

        let nested = format!(
            r#"{{"name":"p","services":{{}},"unknown":{}{}}}"#,
            "[".repeat(MAX_JSON_DEPTH),
            "]".repeat(MAX_JSON_DEPTH)
        );
        assert!(matches!(
            project_json(nested.as_bytes()),
            Err(ProjectionError::ModelLimit)
        ));

        assert!(matches!(
            project_json(br#"{"name":"p","services":{"api":{"build":["."]}}}"#),
            Err(ProjectionError::InvalidModel)
        ));
    }

    #[test]
    fn unknown_build_fields_are_skipped_without_entering_the_projection() {
        let secret = "SENSITIVE-BUILD-ARG";
        let json = format!(
            r#"{{"name":"p","services":{{"api":{{"build":{{"context":".","dockerfile":"Containerfile","args":{{"TOKEN":"{secret}"}},"cache_from":[{{"type":"local","src":"{secret}"}}]}}}}}}}}"#
        );
        let model = project_json(json.as_bytes()).unwrap();
        let sanitized = serde_json::to_string(&model).unwrap();
        assert_eq!(
            model.services["api"]
                .build
                .as_ref()
                .and_then(|build| build.context.as_deref()),
            Some(".")
        );
        assert!(!sanitized.contains(secret));
        assert!(!sanitized.contains("cache_from"));
    }

    #[test]
    fn errors_do_not_repeat_sensitive_input() {
        let secret = "DO-NOT-DIAGNOSE-THIS";
        let error = project_json(format!(r#"{{"name":"{secret}""#).as_bytes()).unwrap_err();
        assert!(!error.to_string().contains(secret));
    }

    #[tokio::test]
    async fn execution_discards_success_diagnostics_before_returning_model() {
        let frontend = TempFrontend::new(
            r#"printf '%s' '{"name":"executed","services":{"api":{"image":"example/api"}}}'
printf '%s' 'SENSITIVE-FRONTEND-DIAGNOSTIC' >&2"#,
        );
        let model = project(
            &Frontend::Docker {
                executable: frontend.0.clone(),
            },
            &Invocation::default(),
        )
        .await
        .unwrap();
        assert_eq!(model.name, "executed");
        assert_eq!(model.services["api"].image.as_deref(), Some("example/api"));
    }

    #[tokio::test]
    async fn failed_frontend_does_not_repeat_its_sensitive_diagnostics() {
        let secret = "SENSITIVE-FAILURE-DIAGNOSTIC";
        let frontend = TempFrontend::new(&format!("printf '%s' '{secret}' >&2\nexit 9"));
        let error = project(
            &Frontend::Docker {
                executable: frontend.0.clone(),
            },
            &Invocation::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(error, ProjectionError::FrontendFailed),
            "unexpected frontend failure: {error:?}"
        );
        assert!(!error.to_string().contains(secret));
    }

    #[tokio::test]
    async fn stdout_and_stderr_overflow_map_to_output_limit() {
        for body in [
            format!("printf '%*s' {} ''", MAX_STDOUT_BYTES + 1),
            format!("printf '%*s' {} '' >&2", MAX_STDERR_BYTES + 1),
        ] {
            let frontend = TempFrontend::new(&body);
            let error = project(
                &Frontend::Docker {
                    executable: frontend.0.clone(),
                },
                &Invocation::default(),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(error, ProjectionError::OutputLimit),
                "unexpected overflow error: {error:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn timeout_terminates_the_frontend_process() {
        let pid_file =
            std::env::temp_dir().join(format!("basil-compose-timeout-pid-{}", std::process::id()));
        let frontend = TempFrontend::new(&format!(
            "printf '%s' $$ > {}\nexec sleep 30",
            pid_file.display()
        ));
        let error = project_with_timeout(
            &Frontend::Docker {
                executable: frontend.0.clone(),
            },
            &Invocation::default(),
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ProjectionError::Timeout));
        assert_process_terminated(&pid_file).await;
        let _ = fs::remove_file(pid_file);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancellation_terminates_the_frontend_process() {
        let pid_file =
            std::env::temp_dir().join(format!("basil-compose-cancel-pid-{}", std::process::id()));
        let frontend = TempFrontend::new(&format!(
            "printf '%s' $$ > {}\nexec sleep 30",
            pid_file.display()
        ));
        let path = frontend.0.clone();
        let task = tokio::spawn(async move {
            project(
                &Frontend::Docker { executable: path },
                &Invocation::default(),
            )
            .await
        });
        for _ in 0..50 {
            if pid_file.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(pid_file.exists());
        task.abort();
        let _ = task.await;
        assert_process_terminated(&pid_file).await;
        let _ = fs::remove_file(pid_file);
    }

    #[cfg(target_os = "linux")]
    async fn assert_process_terminated(pid_file: &Path) {
        let pid = fs::read_to_string(pid_file).unwrap();
        let process_path = PathBuf::from(format!("/proc/{}", pid.trim()));
        for _ in 0..50 {
            if !process_path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("frontend process remained alive after cancellation");
    }

    #[test]
    fn executable_and_input_bounds_fail_before_spawn() {
        let relative = Frontend::Docker {
            executable: "docker".into(),
        };
        assert!(matches!(
            command_spec(&relative, &Invocation::default()),
            Err(ProjectionError::RelativeExecutable)
        ));

        let invocation = Invocation {
            profiles: vec!["x".repeat(MAX_NAME_BYTES + 1)],
            ..Invocation::default()
        };
        assert!(matches!(
            command_spec(
                &Frontend::Docker {
                    executable: "/usr/bin/docker".into()
                },
                &invocation
            ),
            Err(ProjectionError::InvocationLimit)
        ));
    }
}
