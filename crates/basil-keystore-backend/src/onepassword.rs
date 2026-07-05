//! `1Password` materialize-to-use backend for [`SecretStore`](crate::SecretStore).
//!
//! Secrets are stored as Secure Note items through the `1Password` CLI (`op`),
//! addressed by a `secretspec`-style item title. `1Password` items are
//! string-valued, so this backend is **string-only**: [`put`](OnePasswordProvider::set)
//! of non-UTF-8 bytes fails closed with [`StoreError::NonUtf8Value`]. This is a
//! limitation of the `1Password` backend, not of `SecretStore` in general.
//!
//! Ported from the `secretspec` `onepassword` provider, adapted to Basil's
//! byte-oriented store interface: values move as bytes (a UTF-8 string round
//! trip through `op`), never a `SecretString`, and every error is reduced to a
//! stable, leak-safe summary before it leaves this module.

use std::process::Command;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroizing;

use crate::store::StoreError;

/// The default item-title template. `{project}`, `{profile}`, and `{key}` are
/// substituted per read/write.
const DEFAULT_FOLDER_PREFIX: &str = "basil/{project}/{profile}/{key}";

/// A single field within a `1Password` item, as `op ... --format json` reports it.
#[derive(Debug, Deserialize)]
struct OnePasswordField {
    /// Field identifier (e.g. `"password"`).
    id: String,
    /// Field type (e.g. `"STRING"`, `"CONCEALED"`).
    #[serde(rename = "type")]
    field_type: String,
    /// Human-readable label used to locate the `"value"` field.
    label: Option<String>,
    /// The stored value, absent for some field types.
    value: Option<String>,
}

/// A `1Password` item with its fields, as `op item get --format json` reports it.
#[derive(Debug, Deserialize)]
struct OnePasswordItem {
    /// The item's fields.
    fields: Vec<OnePasswordField>,
}

/// A row of `op item list --format json`, used to resolve a title to an id.
#[derive(Debug, Deserialize)]
struct OnePasswordListItem {
    /// The item id.
    id: String,
    /// The item title (matched against the formatted item name).
    title: String,
}

/// One field of a new-item creation template (`op item create`).
#[derive(Debug, Serialize)]
struct OnePasswordFieldTemplate {
    /// Field label (`"project"`, `"key"`, `"value"`).
    label: String,
    /// Field type, always `"STRING"` here.
    #[serde(rename = "type")]
    field_type: String,
    /// The value to store.
    value: String,
}

/// A new-item creation template serialized to JSON on `op item create` stdin.
#[derive(Debug, Serialize)]
struct OnePasswordItemTemplate {
    /// Item title (the formatted item name).
    title: String,
    /// Item category: always `"SECURE_NOTE"`.
    category: String,
    /// The item's fields.
    fields: Vec<OnePasswordFieldTemplate>,
    /// Organizing tags.
    tags: Vec<String>,
}

/// Resolved `1Password` addressing/auth configuration, parsed from a provider URI.
#[derive(Debug, Clone, Default)]
pub struct OnePasswordConfig {
    /// Optional account shorthand (`--account`), for multi-account setups.
    pub account: Option<String>,
    /// Default vault; `"Private"` when unset.
    pub default_vault: Option<String>,
    /// Service-account token (`OP_SERVICE_ACCOUNT_TOKEN`) for non-interactive auth.
    pub service_account_token: Option<String>,
    /// Item-title template override; [`DEFAULT_FOLDER_PREFIX`] when unset.
    pub folder_prefix: Option<String>,
}

impl OnePasswordConfig {
    /// Parse a `1Password` provider URI.
    ///
    /// Accepts `onepassword://[account@]vault` and
    /// `onepassword+token://[token@]vault` (or `user:token@vault`). A dummy
    /// `localhost` host is ignored, leaving the vault unset (falls back to
    /// `"Private"`).
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] with a stable summary when the URI does not parse
    /// or does not carry a `1Password` scheme.
    pub fn from_uri(uri: &str) -> Result<Self, StoreError> {
        let url =
            Url::parse(uri).map_err(|_| StoreError::Backend("onepassword-bad-uri".to_owned()))?;
        let scheme = url.scheme();
        if scheme != "onepassword" && scheme != "onepassword+token" {
            return Err(StoreError::Backend("onepassword-bad-scheme".to_owned()));
        }

        let mut config = Self::default();

        // A non-`localhost` host is the vault; an empty host leaves it unset.
        if let Some(host) = url.host_str().map(decode)
            && host != "localhost"
        {
            let username = decode(url.username());
            if !username.is_empty() {
                if scheme == "onepassword+token" {
                    config.service_account_token = Some(url.password().map_or(username, decode));
                } else {
                    config.account = Some(username);
                }
            }
            config.default_vault = Some(host);
        }

        Ok(config)
    }
}

/// Percent-decode a URI component with lossy UTF-8 handling.
fn decode(raw: &str) -> String {
    percent_decode_str(raw).decode_utf8_lossy().into_owned()
}

/// Detects Windows Subsystem for Linux 2 (`op.exe` is used there).
#[cfg(target_os = "linux")]
fn is_wsl2() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .is_some_and(|content| content.trim().ends_with("-microsoft-standard-WSL2"))
}

#[cfg(not(target_os = "linux"))]
const fn is_wsl2() -> bool {
    false
}

/// Strips any `OP_SESSION_*` env vars so an expired manual-signin session does
/// not shadow the desktop-app integration `op` would otherwise fall back to.
fn strip_op_session_env(cmd: &mut Command) {
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("OP_SESSION_") {
            cmd.env_remove(&key);
        }
    }
}

/// The outcome of an `op` invocation that is not a hard error: either the
/// captured stdout, or a recognized "absent"/"ambiguous" signal the caller acts
/// on. Hard failures are surfaced as [`StoreError`] and never carry `op` stderr
/// verbatim (which could echo a secret value).
enum OpErr {
    /// The addressed item does not exist.
    NotFound,
    /// More than one item shares the title; retry the read by id.
    Ambiguous,
    /// A hard failure already reduced to a leak-safe store error.
    Store(StoreError),
}

impl From<OpErr> for StoreError {
    fn from(err: OpErr) -> Self {
        match err {
            OpErr::NotFound | OpErr::Ambiguous => Self::Backend("onepassword-op-failed".to_owned()),
            OpErr::Store(store) => store,
        }
    }
}

/// A materialize-to-use `1Password` store backend.
pub struct OnePasswordProvider {
    /// Resolved addressing/auth config.
    config: OnePasswordConfig,
    /// The `op` CLI command (`op`, `op.exe` on WSL2, or `BASIL_OP_CLI_PATH`).
    op_command: String,
}

impl OnePasswordProvider {
    /// Build a provider from resolved config.
    #[must_use]
    pub fn new(config: OnePasswordConfig) -> Self {
        let op_command = std::env::var("BASIL_OP_CLI_PATH").unwrap_or_else(|_| {
            if is_wsl2() {
                "op.exe".to_owned()
            } else {
                "op".to_owned()
            }
        });
        Self { config, op_command }
    }

    /// The vault to address; `"Private"` when none is configured.
    fn vault(&self) -> String {
        self.config
            .default_vault
            .clone()
            .unwrap_or_else(|| "Private".to_owned())
    }

    /// Format the `1Password` item title from the configured template.
    // `{project}`/`{profile}`/`{key}` are literal template placeholders passed to
    // `str::replace`, not format-macro arguments.
    #[allow(clippy::literal_string_with_formatting_args)]
    fn item_name(&self, project: &str, key: &str, profile: &str) -> String {
        self.config
            .folder_prefix
            .as_deref()
            .unwrap_or(DEFAULT_FOLDER_PREFIX)
            .replace("{project}", project)
            .replace("{profile}", profile)
            .replace("{key}", key)
    }

    /// Run an `op` command, optionally writing `stdin_data`, and return stdout.
    ///
    /// Errors are classified into [`OpErr`] without ever echoing `op` stderr
    /// (which can contain a secret value).
    fn run(&self, args: &[&str], stdin_data: Option<&str>) -> Result<String, OpErr> {
        use std::io::Write as _;
        use std::process::Stdio;

        let mut cmd = Command::new(&self.op_command);
        strip_op_session_env(&mut cmd);
        if let Some(token) = &self.config.service_account_token {
            cmd.env("OP_SERVICE_ACCOUNT_TOKEN", token);
        }
        if let Some(account) = &self.config.account {
            cmd.arg("--account").arg(account);
        }
        cmd.args(args);

        let output = if let Some(data) = stdin_data {
            cmd.stdin(Stdio::piped());
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
            let mut child = cmd.spawn().map_err(|e| spawn_err(&e))?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(data.as_bytes()).map_err(|_| {
                    OpErr::Store(StoreError::Backend("onepassword-stdin".to_owned()))
                })?;
                drop(stdin);
            }
            child.wait_with_output().map_err(|_| {
                OpErr::Store(StoreError::Backend("onepassword-op-failed".to_owned()))
            })?
        } else {
            cmd.output().map_err(|e| spawn_err(&e))?
        };

        if output.status.success() {
            return String::from_utf8(output.stdout).map_err(|_| {
                OpErr::Store(StoreError::Backend(
                    "onepassword-non-utf8-output".to_owned(),
                ))
            });
        }

        // Classify by known stderr markers, but never propagate the raw text.
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("isn't an item") {
            Err(OpErr::NotFound)
        } else if stderr.contains("More than one item") {
            Err(OpErr::Ambiguous)
        } else if stderr.contains("not currently signed in")
            || stderr.contains("no active session")
            || stderr.contains("could not find session token")
            || stderr.contains("account is not signed in")
            || stderr.contains("authentication required")
        {
            Err(OpErr::Store(StoreError::Backend(
                "onepassword-auth-required".to_owned(),
            )))
        } else {
            Err(OpErr::Store(StoreError::Backend(
                "onepassword-op-failed".to_owned(),
            )))
        }
    }

    /// Find an item id by title (more reliable than `op item get` for existence).
    fn find_item_id(&self, item_name: &str, vault: &str) -> Result<Option<String>, StoreError> {
        let out = self.run(
            &["item", "list", "--vault", vault, "--format", "json"],
            None,
        )?;
        let items: Vec<OnePasswordListItem> = serde_json::from_str(&out).unwrap_or_default();
        Ok(items
            .into_iter()
            .find(|item| item.title == item_name)
            .map(|item| item.id))
    }

    /// Extract the secret value bytes from an `op item get --format json` output.
    fn extract_value(output: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        let item: OnePasswordItem = serde_json::from_str(output)
            .map_err(|_| StoreError::Backend("onepassword-parse-item".to_owned()))?;

        // Prefer the labelled `value` field, then any concealed/password field.
        for field in &item.fields {
            if field.label.as_deref() == Some("value") {
                return Ok(field.value.as_deref().map(as_secret_bytes));
            }
        }
        for field in &item.fields {
            if field.field_type == "CONCEALED" || field.id == "password" {
                return Ok(field.value.as_deref().map(as_secret_bytes));
            }
        }
        Ok(None)
    }

    /// Read the secret at `key`, returning `None` when the item is absent.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] for `op`/auth failures.
    pub fn get(
        &self,
        project: &str,
        key: &str,
        profile: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        let vault = self.vault();
        let item_name = self.item_name(project, key, profile);
        let args = [
            "item", "get", &item_name, "--vault", &vault, "--format", "json",
        ];
        match self.run(&args, None) {
            Ok(out) => Self::extract_value(&out),
            Err(OpErr::NotFound) => Ok(None),
            Err(OpErr::Ambiguous) => {
                // Duplicate titles: disambiguate by id.
                let Some(id) = self.find_item_id(&item_name, &vault)? else {
                    return Ok(None);
                };
                let args = ["item", "get", &id, "--vault", &vault, "--format", "json"];
                match self.run(&args, None) {
                    Ok(out) => Self::extract_value(&out),
                    Err(OpErr::NotFound) => Ok(None),
                    Err(other) => Err(other.into()),
                }
            }
            Err(other) => Err(other.into()),
        }
    }

    /// Store `value` at `key`, creating or updating the item.
    ///
    /// # Errors
    ///
    /// [`StoreError::NonUtf8Value`] when `value` is not UTF-8 (a `1Password`
    /// limitation), or [`StoreError::Backend`] for `op`/auth failures.
    pub fn set(
        &self,
        project: &str,
        key: &str,
        value: &[u8],
        profile: &str,
    ) -> Result<(), StoreError> {
        let text = std::str::from_utf8(value).map_err(|_| StoreError::NonUtf8Value)?;
        let vault = self.vault();
        let item_name = self.item_name(project, key, profile);

        if let Some(id) = self.find_item_id(&item_name, &vault)? {
            // Update the existing item's `value` field by id.
            let assignment = format!("value={text}");
            let args = ["item", "edit", &id, "--vault", &vault, &assignment];
            self.run(&args, None)?;
        } else {
            // Create a fresh Secure Note; the template (incl. the value) is piped
            // on stdin, never placed on the command line.
            let template = OnePasswordItemTemplate {
                title: item_name,
                category: "SECURE_NOTE".to_owned(),
                fields: vec![
                    OnePasswordFieldTemplate {
                        label: "project".to_owned(),
                        field_type: "STRING".to_owned(),
                        value: project.to_owned(),
                    },
                    OnePasswordFieldTemplate {
                        label: "key".to_owned(),
                        field_type: "STRING".to_owned(),
                        value: key.to_owned(),
                    },
                    OnePasswordFieldTemplate {
                        label: "value".to_owned(),
                        field_type: "STRING".to_owned(),
                        value: text.to_owned(),
                    },
                ],
                tags: vec!["automated".to_owned(), project.to_owned()],
            };
            let json = serde_json::to_string(&template)
                .map_err(|_| StoreError::Backend("onepassword-template-encode".to_owned()))?;
            let args = ["item", "create", "--vault", &vault, "-"];
            self.run(&args, Some(&json))?;
        }
        Ok(())
    }
}

/// Wrap a string value's bytes in a zeroizing owner.
fn as_secret_bytes(value: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(value.to_owned().into_bytes())
}

/// Map a spawn failure to a leak-safe store error, distinguishing a missing CLI.
fn spawn_err(err: &std::io::Error) -> OpErr {
    if err.kind() == std::io::ErrorKind::NotFound {
        OpErr::Store(StoreError::Backend(
            "onepassword-cli-not-installed".to_owned(),
        ))
    } else {
        OpErr::Store(StoreError::Backend("onepassword-op-failed".to_owned()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{DEFAULT_FOLDER_PREFIX, OnePasswordConfig, OnePasswordProvider};

    fn provider_from(uri: &str) -> OnePasswordProvider {
        OnePasswordProvider::new(OnePasswordConfig::from_uri(uri).expect("valid uri"))
    }

    #[test]
    fn uri_parses_account_and_vault() {
        let c = OnePasswordConfig::from_uri("onepassword://work@Production").unwrap();
        assert_eq!(c.account.as_deref(), Some("work"));
        assert_eq!(c.default_vault.as_deref(), Some("Production"));
        assert!(c.service_account_token.is_none());
    }

    #[test]
    fn uri_parses_vault_only() {
        let c = OnePasswordConfig::from_uri("onepassword://Production").unwrap();
        assert!(c.account.is_none());
        assert_eq!(c.default_vault.as_deref(), Some("Production"));
    }

    #[test]
    fn uri_percent_decodes_vault_name() {
        let c = OnePasswordConfig::from_uri("onepassword://Home%20Lab").unwrap();
        assert_eq!(c.default_vault.as_deref(), Some("Home Lab"));
    }

    #[test]
    fn uri_token_scheme_captures_token_from_username() {
        let c = OnePasswordConfig::from_uri("onepassword+token://ops_tok@Private").unwrap();
        assert_eq!(c.service_account_token.as_deref(), Some("ops_tok"));
        assert_eq!(c.default_vault.as_deref(), Some("Private"));
        assert!(c.account.is_none());
    }

    #[test]
    fn uri_token_scheme_captures_token_from_password() {
        let c = OnePasswordConfig::from_uri("onepassword+token://acct:ops_tok@Private").unwrap();
        assert_eq!(c.service_account_token.as_deref(), Some("ops_tok"));
    }

    #[test]
    fn uri_ignores_localhost_host() {
        let c = OnePasswordConfig::from_uri("onepassword://localhost").unwrap();
        assert!(c.default_vault.is_none());
        assert!(c.account.is_none());
    }

    #[test]
    fn uri_rejects_unknown_scheme() {
        let err = OnePasswordConfig::from_uri("keyring://vault").unwrap_err();
        assert!(matches!(err, super::StoreError::Backend(_)));
    }

    #[test]
    fn uri_rejects_garbage() {
        assert!(OnePasswordConfig::from_uri("not a uri at all").is_err());
    }

    #[test]
    fn vault_defaults_to_private() {
        assert_eq!(provider_from("onepassword://localhost").vault(), "Private");
        assert_eq!(
            provider_from("onepassword://Production").vault(),
            "Production"
        );
    }

    #[test]
    fn item_name_default_and_custom() {
        let default = provider_from("onepassword://Production");
        assert_eq!(
            default.item_name("proj", "KEY", "prod"),
            "basil/proj/prod/KEY"
        );
        assert_eq!(DEFAULT_FOLDER_PREFIX, "basil/{project}/{profile}/{key}");

        let mut cfg = OnePasswordConfig::from_uri("onepassword://Production").unwrap();
        cfg.folder_prefix = Some("{project}-{key}".to_owned());
        let custom = OnePasswordProvider::new(cfg);
        assert_eq!(custom.item_name("proj", "KEY", "prod"), "proj-KEY");
    }
}
