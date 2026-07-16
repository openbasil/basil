// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Validated named Unix-listener configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

use super::grpc_server::{DEFAULT_SOCKET_MODE, ListenerType, MAX_LISTENERS};

/// Maximum listener-name length.
pub const MAX_LISTENER_NAME_BYTES: usize = 63;

/// Portable maximum pathname bytes for a filesystem Unix socket.
pub const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;

/// Unvalidated values from one named listener table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerConfigInput {
    /// Closed compiled listener type.
    pub listener_type: ListenerType,
    /// Filesystem path for the Unix socket.
    pub path: PathBuf,
    /// Optional socket mode; owner-only when omitted.
    pub mode: Option<u32>,
    /// Optional socket group name or numeric identifier.
    pub group: Option<String>,
}

/// Legacy top-level single-listener fields.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LegacyListenerConfig {
    /// Legacy `socket` value.
    pub path: Option<PathBuf>,
    /// Legacy `socket-mode` value.
    pub mode: Option<u32>,
    /// Legacy `socket-group` value.
    pub group: Option<String>,
}

impl LegacyListenerConfig {
    const fn is_explicit(&self) -> bool {
        self.path.is_some() || self.mode.is_some() || self.group.is_some()
    }
}

/// One fully validated named listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerConfig {
    name: String,
    listener_type: ListenerType,
    path: PathBuf,
    mode: u32,
    group: Option<String>,
}

impl ListenerConfig {
    pub(crate) fn validated(
        name: String,
        listener_type: ListenerType,
        path: PathBuf,
        mode: u32,
        group: Option<String>,
    ) -> Result<Self, ListenerConfigError> {
        validate_name(&name)?;
        validate_path(&path)?;
        validate_mode(mode)?;
        validate_group(group.as_deref())?;
        Ok(Self {
            name,
            listener_type,
            path,
            mode,
            group,
        })
    }

    /// Stable local listener name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Closed compiled listener type.
    #[must_use]
    pub const fn listener_type(&self) -> ListenerType {
        self.listener_type
    }

    /// Absolute normalized Unix-socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Socket filesystem mode.
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    /// Optional socket group name or numeric identifier.
    #[must_use]
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }
}

/// Complete validated listener set for one broker generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenerConfigSet(BTreeMap<String, ListenerConfig>);

impl ListenerConfigSet {
    /// Validate named listeners or project the legacy top-level socket fields.
    ///
    /// Named listeners and explicitly configured legacy fields are mutually
    /// exclusive. When no named listener exists, this creates one `host`
    /// listener named `host`, preserving the existing defaults.
    ///
    /// # Errors
    ///
    /// Returns [`ListenerConfigError`] for ambiguous, unbounded, malformed, or
    /// duplicate configuration.
    pub fn resolve(
        named: BTreeMap<String, ListenerConfigInput>,
        legacy: LegacyListenerConfig,
    ) -> Result<Self, ListenerConfigError> {
        let inputs = if named.is_empty() {
            let input = ListenerConfigInput {
                listener_type: ListenerType::Host,
                path: legacy
                    .path
                    .unwrap_or_else(|| PathBuf::from(crate::DEFAULT_SOCKET_PATH)),
                mode: legacy.mode,
                group: legacy.group,
            };
            BTreeMap::from([("host".to_string(), input)])
        } else {
            if legacy.is_explicit() {
                return Err(ListenerConfigError::LegacyNamedConflict);
            }
            named
        };

        if inputs.len() > MAX_LISTENERS {
            return Err(ListenerConfigError::TooMany {
                actual: inputs.len(),
                maximum: MAX_LISTENERS,
            });
        }

        let mut paths = BTreeSet::new();
        let mut listeners = BTreeMap::new();
        let mut has_host = false;
        for (name, input) in inputs {
            if !paths.insert(input.path.clone()) {
                return Err(ListenerConfigError::DuplicatePath(input.path));
            }
            has_host |= input.listener_type == ListenerType::Host;
            let config = ListenerConfig::validated(
                name.clone(),
                input.listener_type,
                input.path,
                input.mode.unwrap_or(DEFAULT_SOCKET_MODE),
                input.group,
            )?;
            listeners.insert(name, config);
        }
        if !has_host {
            return Err(ListenerConfigError::MissingHost);
        }
        Ok(Self(listeners))
    }

    /// Number of configured listeners.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether no listeners are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Look up one listener by its stable name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ListenerConfig> {
        self.0.get(name)
    }

    /// Iterate in stable name order.
    pub fn iter(&self) -> impl Iterator<Item = &ListenerConfig> {
        self.0.values()
    }
}

/// Named-listener configuration validation failure.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ListenerConfigError {
    /// Named and legacy listener forms were both configured.
    #[error("named listeners cannot be combined with legacy socket fields")]
    LegacyNamedConflict,
    /// The configured listener count exceeds the safety ceiling.
    #[error("listener count {actual} exceeds maximum {maximum}")]
    TooMany {
        /// Configured listener count.
        actual: usize,
        /// Compiled safety ceiling.
        maximum: usize,
    },
    /// No host/operator listener was configured.
    #[error("named listeners must include at least one `host` listener")]
    MissingHost,
    /// A listener name is empty, overlong, or contains unsupported bytes.
    #[error("invalid listener name `{0}`")]
    InvalidName(String),
    /// A socket path is not absolute, normalized, bounded, and filesystem based.
    #[error("invalid listener Unix-socket path `{0}`")]
    InvalidPath(PathBuf),
    /// Two listener names resolve to the same socket path.
    #[error("duplicate listener Unix-socket path `{0}`")]
    DuplicatePath(PathBuf),
    /// A socket mode contains bits outside the Unix permission mask.
    #[error("invalid listener socket mode `{0:o}`")]
    InvalidMode(u32),
    /// A socket group is empty, overlong, or contains a NUL byte.
    #[error("invalid listener socket group")]
    InvalidGroup,
}

fn validate_name(name: &str) -> Result<(), ListenerConfigError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_LISTENER_NAME_BYTES
        && name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        });
    if valid {
        Ok(())
    } else {
        Err(ListenerConfigError::InvalidName(name.to_string()))
    }
}

fn validate_path(path: &Path) -> Result<(), ListenerConfigError> {
    let bytes = path.as_os_str().as_bytes();
    let components_are_normal = path.components().enumerate().all(|(index, component)| {
        matches!(
            (index, component),
            (0, Component::RootDir) | (_, Component::Normal(_))
        )
    });
    let text_is_normal = path
        .to_str()
        .is_some_and(|value| !value.contains("//") && !value.ends_with('/'));
    if path.is_absolute()
        && components_are_normal
        && text_is_normal
        && bytes.len() <= MAX_UNIX_SOCKET_PATH_BYTES
        && path.file_name().is_some()
    {
        Ok(())
    } else {
        Err(ListenerConfigError::InvalidPath(path.to_path_buf()))
    }
}

const fn validate_mode(mode: u32) -> Result<(), ListenerConfigError> {
    if mode <= 0o7777 {
        Ok(())
    } else {
        Err(ListenerConfigError::InvalidMode(mode))
    }
}

fn validate_group(group: Option<&str>) -> Result<(), ListenerConfigError> {
    if group.is_some_and(|value| value.is_empty() || value.len() > 255 || value.contains('\0')) {
        Err(ListenerConfigError::InvalidGroup)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(listener_type: ListenerType, path: &str) -> ListenerConfigInput {
        ListenerConfigInput {
            listener_type,
            path: PathBuf::from(path),
            mode: None,
            group: None,
        }
    }

    #[test]
    fn legacy_fields_project_to_one_host_listener() {
        let listeners = ListenerConfigSet::resolve(
            BTreeMap::new(),
            LegacyListenerConfig {
                path: Some(PathBuf::from("/run/basil/control.sock")),
                mode: Some(0o660),
                group: Some("basil".to_string()),
            },
        )
        .expect("legacy listener projects");
        let host = listeners.get("host").expect("host listener");
        assert_eq!(listeners.len(), 1);
        assert_eq!(host.listener_type(), ListenerType::Host);
        assert_eq!(host.path(), Path::new("/run/basil/control.sock"));
        assert_eq!(host.mode(), 0o660);
        assert_eq!(host.group(), Some("basil"));
    }

    #[test]
    fn named_listener_set_is_typed_bounded_and_ordered() {
        let listeners = ListenerConfigSet::resolve(
            BTreeMap::from([
                (
                    "workloads".to_string(),
                    input(ListenerType::Container, "/run/basil/workloads/agent.sock"),
                ),
                (
                    "control".to_string(),
                    input(ListenerType::Host, "/run/basil/control/agent.sock"),
                ),
            ]),
            LegacyListenerConfig::default(),
        )
        .expect("named listeners validate");
        assert_eq!(
            listeners
                .iter()
                .map(ListenerConfig::name)
                .collect::<Vec<_>>(),
            ["control", "workloads"]
        );
        assert_eq!(
            listeners
                .get("workloads")
                .map(ListenerConfig::listener_type),
            Some(ListenerType::Container)
        );
    }

    #[test]
    fn named_and_legacy_forms_are_mutually_exclusive() {
        let error = ListenerConfigSet::resolve(
            BTreeMap::from([(
                "control".to_string(),
                input(ListenerType::Host, "/run/basil/control.sock"),
            )]),
            LegacyListenerConfig {
                path: Some(PathBuf::from("/run/basil/legacy.sock")),
                ..LegacyListenerConfig::default()
            },
        )
        .expect_err("ambiguous forms fail");
        assert_eq!(error, ListenerConfigError::LegacyNamedConflict);
    }

    #[test]
    fn invalid_names_paths_duplicates_modes_and_missing_host_fail() {
        for name in ["", "Host", "-host", "host/socket"] {
            let error = ListenerConfigSet::resolve(
                BTreeMap::from([(
                    name.to_string(),
                    input(ListenerType::Host, "/run/basil/agent.sock"),
                )]),
                LegacyListenerConfig::default(),
            )
            .expect_err("invalid name fails");
            assert!(matches!(error, ListenerConfigError::InvalidName(_)));
        }

        for path in [
            "relative.sock",
            "/run/../agent.sock",
            "/run//agent.sock",
            "/",
        ] {
            let error = ListenerConfigSet::resolve(
                BTreeMap::from([("host".to_string(), input(ListenerType::Host, path))]),
                LegacyListenerConfig::default(),
            )
            .expect_err("invalid path fails");
            assert!(matches!(error, ListenerConfigError::InvalidPath(_)));
        }

        let duplicate = ListenerConfigSet::resolve(
            BTreeMap::from([
                (
                    "host".to_string(),
                    input(ListenerType::Host, "/run/basil/agent.sock"),
                ),
                (
                    "container".to_string(),
                    input(ListenerType::Container, "/run/basil/agent.sock"),
                ),
            ]),
            LegacyListenerConfig::default(),
        )
        .expect_err("duplicate path fails");
        assert!(matches!(duplicate, ListenerConfigError::DuplicatePath(_)));

        let mut bad_mode = input(ListenerType::Host, "/run/basil/agent.sock");
        bad_mode.mode = Some(0o10_000);
        assert!(matches!(
            ListenerConfigSet::resolve(
                BTreeMap::from([("host".to_string(), bad_mode)]),
                LegacyListenerConfig::default(),
            ),
            Err(ListenerConfigError::InvalidMode(_))
        ));

        assert_eq!(
            ListenerConfigSet::resolve(
                BTreeMap::from([(
                    "container".to_string(),
                    input(ListenerType::Container, "/run/basil/container.sock"),
                )]),
                LegacyListenerConfig::default(),
            ),
            Err(ListenerConfigError::MissingHost)
        );
    }

    #[test]
    fn listener_count_has_a_hard_safety_ceiling() {
        let named = (0..=MAX_LISTENERS)
            .map(|index| {
                let listener_type = if index == 0 {
                    ListenerType::Host
                } else {
                    ListenerType::Container
                };
                (
                    format!("listener-{index}"),
                    input(listener_type, &format!("/run/basil/listener-{index}.sock")),
                )
            })
            .collect();
        assert_eq!(
            ListenerConfigSet::resolve(named, LegacyListenerConfig::default()),
            Err(ListenerConfigError::TooMany {
                actual: MAX_LISTENERS + 1,
                maximum: MAX_LISTENERS,
            })
        );
    }
}
