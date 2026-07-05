//! Backend **capability enforcement**: does each backend *provide* what the
//! catalog *requires*?
//!
//! Two declarations, two roles:
//!
//! - **Provides**: `BackendRef::engines` + `BackendRef::capabilities` +
//!   `BackendRef::mint_key_types`: what the server instance supports. In nix this
//!   comes from a version preset (`VAULT_2_0`, `OPENBAO_2_5`); a hand-written
//!   catalog supplies the same JSON (so a non-nix adapter works too). It is the
//!   version→capability table, in config rather than hardcoded in the binary.
//! - **Requires**: what *this* deployment needs. Mostly **derived** (and so it
//!   can't drift): each key's effective [`Engine`] and its [`KeyAlgorithm`]'s
//!   [`required_capability`](crate::catalog::KeyAlgorithm::required_capability).
//!   For the few non-key-derivable needs there is the explicit
//!   `BackendRef::requires` list, unioned with the derived set.
//!
//! Enforcement is `required ⊆ provided`. It is a **pure** catalog check: no
//! backend I/O and no extra Vault privilege, so it runs both at startup and in
//! the offline `check` lint, and needs no reachable server. The live cross-check
//! against a server's real version is a separate (future) concern.
//!
//! # Policy
//!
//! [`CapabilityPolicy`] is the operator's stance, a **ceiling** over each key's
//! [`MissingPolicy`]:
//!
//! - `strict` (default, secure): any unmet requirement aborts startup; every
//!   gap is reported together.
//! - `degraded`, which defers to per-key `missing`: a gap on a `missing="error"` key is
//!   still fatal; on any other key it is logged and the broker serves the rest
//!   (the runtime `Unsupported` backstop catches the op if it is ever made).
//! - `off` skips the check entirely.
//!
//! # Undeclared backends
//!
//! A backend that declares **no** provides (`engines`, `capabilities`, and
//! `mint_key_types` all empty) is *capability-unknown*: the check is skipped
//! with a warning, even under `strict`. The agent can't manufacture the data, and
//! failing closed on absence would punish every minimal catalog. Real enforcement
//! is opt-in by declaring the provides set (which the nix presets make trivial).

use std::collections::BTreeSet;
use std::str::FromStr;

use crate::catalog::{Capability, Catalog, Engine, KeyAlgorithm, MissingPolicy};

/// How startup handles a backend that cannot satisfy a required capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapabilityPolicy {
    /// Any unmet requirement aborts startup (fail closed). The default.
    #[default]
    Strict,
    /// Defer to each key's [`MissingPolicy`]: a gap on a `missing="error"` key is
    /// fatal; otherwise it is logged and the broker serves the rest.
    Degraded,
    /// Skip the capability check entirely.
    Off,
}

impl FromStr for CapabilityPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "strict" => Ok(Self::Strict),
            "degraded" => Ok(Self::Degraded),
            "off" => Ok(Self::Off),
            other => Err(format!(
                "invalid capability-policy `{other}` (want one of: strict, degraded, off)"
            )),
        }
    }
}

impl std::fmt::Display for CapabilityPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Strict => "strict",
            Self::Degraded => "degraded",
            Self::Off => "off",
        })
    }
}

/// One unmet capability requirement, for a single key, or (when `key` is
/// `None`) a backend-level explicit `requires` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityGap {
    /// The catalog backend name whose provides fell short.
    pub backend: String,
    /// The catalog key whose needs aren't met, or `None` for a backend-level
    /// `requires` gap (which is not tied to any one key).
    pub key: Option<String>,
    /// Required engines the backend does not provide.
    pub missing_engines: Vec<Engine>,
    /// Required capabilities the backend does not provide.
    pub missing_capabilities: Vec<Capability>,
    /// Required native mint/import key algorithms the backend does not provide.
    pub missing_mint_key_types: Vec<KeyAlgorithm>,
}

impl std::fmt::Display for CapabilityGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.key {
            Some(k) => write!(f, "key `{k}` (backend `{}`)", self.backend)?,
            None => write!(f, "backend `{}` requires", self.backend)?,
        }
        if !self.missing_engines.is_empty() {
            let engines: Vec<&str> = self.missing_engines.iter().map(|e| e.token()).collect();
            write!(f, " needs engine(s) [{}]", engines.join(", "))?;
        }
        if !self.missing_capabilities.is_empty() {
            let caps: Vec<&str> = self
                .missing_capabilities
                .iter()
                .map(Capability::token)
                .collect();
            write!(f, " needs capabilit(ies) [{}]", caps.join(", "))?;
        }
        if !self.missing_mint_key_types.is_empty() {
            let types: Vec<&str> = self
                .missing_mint_key_types
                .iter()
                .map(|alg| alg.token())
                .collect();
            write!(f, " needs mint key type(s) [{}]", types.join(", "))?;
        }
        Ok(())
    }
}

/// A fatal capability-enforcement failure (fail closed). Carries **every** gap,
/// not just the first, so one startup attempt surfaces all the misfits.
#[derive(Debug, thiserror::Error)]
#[error(
    "backend capability check failed ({} unmet requirement(s)):\n  - {}",
    .0.len(),
    format_gaps(&.0)
)]
pub struct CapabilityError(pub Vec<CapabilityGap>);

fn format_gaps(gaps: &[CapabilityGap]) -> String {
    gaps.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n  - ")
}

/// Summary of a non-fatal capability pass, for the startup log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapabilitySummary {
    /// Backends whose declared provides were checked.
    pub enforced: usize,
    /// Backends skipped because they declared no provides (capability-unknown).
    pub skipped_undeclared: usize,
    /// Gaps logged but not made fatal (degraded mode).
    pub warnings: usize,
}

/// Validate every backend's declared provides against what its keys (and its
/// explicit `requires`) need, applying `policy`.
///
/// Pure and offline: it reads only the catalog, makes no backend calls, and
/// needs no Vault privilege. Suitable for both startup and the `check` lint.
///
/// # Errors
///
/// [`CapabilityError`] (carrying every gap) when `policy` makes one or more
/// unmet requirements fatal: always under `strict`, and under `degraded` for a
/// gap on a `missing="error"` key.
pub fn enforce_capabilities(
    catalog: &Catalog,
    policy: CapabilityPolicy,
) -> Result<CapabilitySummary, CapabilityError> {
    let mut summary = CapabilitySummary::default();
    // ubs false positive - not secret comparison
    /* ubs:ignore */
    if policy == CapabilityPolicy::Off {
        return Ok(summary);
    }

    let mut fatal: Vec<CapabilityGap> = Vec::new();

    for (bname, backend) in &catalog.backends {
        // Undeclared provides → capability-unknown → skip (even under strict).
        if backend.engines.is_empty()
            && backend.capabilities.is_empty()
            && backend.mint_key_types.is_empty()
        {
            summary.skipped_undeclared += 1;
            tracing::warn!(
                backend = %bname,
                "backend declares no engines/capabilities/mint key types; capability enforcement skipped \
                 (declare a provides set, or set capability-policy=\"off\" to silence)"
            );
            continue;
        }
        summary.enforced += 1;

        let provided_engines: BTreeSet<Engine> = backend.engines.iter().copied().collect();
        let provided_caps: BTreeSet<Capability> = backend.capabilities.iter().cloned().collect();
        let provided_mint_key_types: BTreeSet<KeyAlgorithm> =
            backend.mint_key_types.iter().copied().collect();

        // Surface (non-fatally) any capability token this build doesn't know:
        // a likely typo, but carried opaque so newer-engine names still work.
        for cap in backend.capabilities.iter().chain(&backend.requires) {
            if !cap.is_known() {
                tracing::warn!(
                    backend = %bname, capability = %cap,
                    "unrecognized capability token; treated as opaque for enforcement"
                );
            }
        }

        // Backend-level explicit `requires` (no key to attach a policy to).
        let missing_req: Vec<Capability> = backend
            .requires
            .iter()
            .filter(|c| !provided_caps.contains(c))
            .cloned()
            .collect();
        if !missing_req.is_empty() {
            let gap = CapabilityGap {
                backend: bname.clone(),
                key: None,
                missing_engines: Vec::new(),
                missing_capabilities: missing_req,
                missing_mint_key_types: Vec::new(),
            };
            match policy {
                CapabilityPolicy::Strict => fatal.push(gap),
                CapabilityPolicy::Degraded => {
                    tracing::warn!(gap = %gap, "capability gap (degraded; backend-level requires)");
                    summary.warnings += 1;
                }
                CapabilityPolicy::Off => {}
            }
        }

        for (gap, missing) in key_capability_gaps(
            catalog,
            bname,
            &provided_engines,
            &provided_caps,
            &provided_mint_key_types,
        ) {
            match policy {
                CapabilityPolicy::Strict => fatal.push(gap),
                CapabilityPolicy::Degraded => {
                    if missing == MissingPolicy::Error {
                        fatal.push(gap);
                    } else {
                        tracing::warn!(gap = %gap, "capability gap (degraded; non-required key)");
                        summary.warnings += 1;
                    }
                }
                CapabilityPolicy::Off => {}
            }
        }
    }

    if fatal.is_empty() {
        Ok(summary)
    } else {
        fatal.sort_by(|a, b| (&a.backend, &a.key).cmp(&(&b.backend, &b.key)));
        Err(CapabilityError(fatal))
    }
}

fn key_capability_gaps(
    catalog: &Catalog,
    backend: &str,
    provided_engines: &BTreeSet<Engine>,
    provided_caps: &BTreeSet<Capability>,
    provided_mint_key_types: &BTreeSet<KeyAlgorithm>,
) -> Vec<(CapabilityGap, MissingPolicy)> {
    let mut gaps = Vec::new();

    for (kname, entry) in &catalog.keys {
        // ubs false positive: not a secret comparison
        /* ubs:ignore */
        if entry.backend != backend {
            continue;
        }
        let engine = entry.effective_engine();
        let missing_engines = if provided_engines.contains(&engine) {
            Vec::new()
        } else {
            vec![engine]
        };
        let missing_capabilities: Vec<Capability> = entry
            .key_type
            .and_then(KeyAlgorithm::required_capability)
            .filter(|c| !provided_caps.contains(c))
            .into_iter()
            .collect();
        let missing_mint_key_types: Vec<KeyAlgorithm> = required_mint_key_type(entry)
            .filter(|alg| !provided_mint_key_types.contains(alg))
            .into_iter()
            .collect();

        if missing_engines.is_empty()
            && missing_capabilities.is_empty()
            && missing_mint_key_types.is_empty()
        {
            continue;
        }
        gaps.push((
            CapabilityGap {
                backend: backend.to_owned(),
                key: Some(kname.clone()),
                missing_engines,
                missing_capabilities,
                missing_mint_key_types,
            },
            entry.missing,
        ));
    }

    gaps
}

fn required_mint_key_type(entry: &crate::catalog::KeyEntry) -> Option<KeyAlgorithm> {
    if entry.class == crate::catalog::Class::Asymmetric
        && entry.effective_engine() == Engine::Transit
        && entry.missing == MissingPolicy::Generate
    {
        entry.key_type
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A catalog with one `vault` backend (given provides) and the listed keys.
    /// Each key is `(name, engine_json, key_type_json, missing_json)` fragments.
    fn catalog_json(provides: &str, keys: &str) -> String {
        format!(
            r#"{{
              "schemaVersion": 1,
              "backends": {{ "bao": {{ "kind": "vault", "addr": "http://127.0.0.1:8200"{provides} }} }},
              "keys": {{ {keys} }}
            }}"#
        )
    }

    fn parse(json: &str) -> Catalog {
        serde_json::from_str(json).expect("catalog parses")
    }

    const SIGNER: &str = r#""web.sig": { "class": "asymmetric", "keyType": "ed25519", "backend": "bao", "engine": "transit", "path": "web", "writable": true, "description": "d" }"#;
    const GENERATED_RSA_SIGNER: &str = r#""web.sig": { "class": "asymmetric", "keyType": "rsa-2048", "backend": "bao", "engine": "transit", "path": "web", "writable": true, "missing": "generate", "description": "d" }"#;

    #[test]
    fn capability_token_round_trips_known_and_unknown() {
        for tok in [
            "byok-import",
            "prehash-sign",
            "pqc-transit",
            "pki-crl",
            "jwt-auth",
            "approle-auth",
        ] {
            let cap = Capability::from(tok.to_string());
            assert!(cap.is_known(), "{tok} should be known");
            assert_eq!(cap.token(), tok);
        }
        let unknown = Capability::from("ml-kem-1024-transit".to_string());
        assert!(!unknown.is_known());
        assert_eq!(unknown.token(), "ml-kem-1024-transit");
        assert_eq!(
            unknown,
            Capability::Other("ml-kem-1024-transit".to_string())
        );
    }

    #[test]
    fn unknown_capability_deserializes_without_error() {
        // An engine release adds a capability our enum doesn't know: a
        // hand-written catalog must still load (open type, no rebuild needed).
        let cat = parse(&catalog_json(
            r#", "engines": ["transit"], "capabilities": ["some-2027-feature"]"#,
            SIGNER,
        ));
        let caps = &cat.backends["bao"].capabilities;
        assert_eq!(caps, &[Capability::Other("some-2027-feature".to_string())]);
    }

    #[test]
    fn undeclared_backend_is_skipped_even_under_strict() {
        // No engines/capabilities declared -> capability-unknown -> skipped.
        let cat = parse(&catalog_json("", SIGNER));
        let summary =
            enforce_capabilities(&cat, CapabilityPolicy::Strict).expect("skipped, not fatal");
        assert_eq!(summary.skipped_undeclared, 1);
        assert_eq!(summary.enforced, 0);
    }

    #[test]
    fn declared_backend_satisfying_requirements_passes() {
        let cat = parse(&catalog_json(
            r#", "engines": ["transit", "kv2"], "capabilities": []"#,
            SIGNER,
        ));
        let summary =
            enforce_capabilities(&cat, CapabilityPolicy::Strict).expect("requirements met");
        assert_eq!(summary.enforced, 1);
        assert_eq!(summary.skipped_undeclared, 0);
    }

    #[test]
    fn missing_engine_is_fatal_under_strict() {
        // Key needs transit; backend declares only kv2.
        let cat = parse(&catalog_json(
            r#", "engines": ["kv2"], "capabilities": []"#,
            SIGNER,
        ));
        let err = enforce_capabilities(&cat, CapabilityPolicy::Strict).expect_err("should fail");
        assert_eq!(err.0.len(), 1);
        assert_eq!(err.0[0].key.as_deref(), Some("web.sig"));
        assert_eq!(err.0[0].missing_engines, vec![Engine::Transit]);
    }

    #[test]
    fn missing_engine_on_error_key_is_fatal_in_degraded_too() {
        // Default missing policy is `error`, so a degraded run still fails it.
        let cat = parse(&catalog_json(
            r#", "engines": ["kv2"], "capabilities": []"#,
            SIGNER,
        ));
        let err = enforce_capabilities(&cat, CapabilityPolicy::Degraded)
            .expect_err("error-key gap is fatal");
        assert_eq!(err.0.len(), 1);
    }

    #[test]
    fn missing_engine_on_warn_key_is_tolerated_in_degraded() {
        let warn_key = r#""web.sig": { "class": "asymmetric", "keyType": "ed25519", "backend": "bao", "engine": "transit", "path": "web", "writable": true, "missing": "warn", "description": "d" }"#;
        let cat = parse(&catalog_json(
            r#", "engines": ["kv2"], "capabilities": []"#,
            warn_key,
        ));
        let summary =
            enforce_capabilities(&cat, CapabilityPolicy::Degraded).expect("warn key tolerated");
        assert_eq!(summary.warnings, 1);
    }

    #[test]
    fn explicit_requires_gap_is_fatal_under_strict() {
        // Backend provides transit but the deployment requires byok-import.
        let cat = parse(&catalog_json(
            r#", "engines": ["transit"], "capabilities": [], "requires": ["byok-import"]"#,
            SIGNER,
        ));
        let err = enforce_capabilities(&cat, CapabilityPolicy::Strict).expect_err("requires unmet");
        let gap = err
            .0
            .iter()
            .find(|g| g.key.is_none())
            .expect("backend-level gap");
        assert_eq!(gap.missing_capabilities, vec![Capability::ByokImport]);
    }

    #[test]
    fn generate_key_type_must_be_in_static_backend_preset() {
        let cat = parse(&catalog_json(
            r#", "engines": ["transit"], "capabilities": [], "mintKeyTypes": ["ed25519"]"#,
            GENERATED_RSA_SIGNER,
        ));
        let err = enforce_capabilities(&cat, CapabilityPolicy::Strict)
            .expect_err("rsa generate must require preset support");
        assert_eq!(err.0.len(), 1);
        let gap = &err.0[0];
        assert_eq!(gap.key.as_deref(), Some("web.sig"));
        assert_eq!(gap.missing_mint_key_types, vec![KeyAlgorithm::Rsa2048]);
    }

    #[test]
    fn generate_key_type_declared_in_static_backend_preset_passes() {
        let cat = parse(&catalog_json(
            r#", "engines": ["transit"], "capabilities": [], "mintKeyTypes": ["rsa-2048"]"#,
            GENERATED_RSA_SIGNER,
        ));
        enforce_capabilities(&cat, CapabilityPolicy::Strict).expect("rsa generate supported");
    }

    #[test]
    fn explicit_requires_met_passes() {
        let cat = parse(&catalog_json(
            r#", "engines": ["transit"], "capabilities": ["byok-import"], "requires": ["byok-import"]"#,
            SIGNER,
        ));
        enforce_capabilities(&cat, CapabilityPolicy::Strict).expect("requires satisfied");
    }

    #[test]
    fn off_policy_skips_everything() {
        let cat = parse(&catalog_json(
            r#", "engines": ["kv2"], "capabilities": []"#,
            SIGNER,
        ));
        let summary = enforce_capabilities(&cat, CapabilityPolicy::Off).expect("off never fails");
        assert_eq!(summary, CapabilitySummary::default());
    }

    #[test]
    fn policy_parses_and_displays() {
        for (s, p) in [
            ("strict", CapabilityPolicy::Strict),
            ("degraded", CapabilityPolicy::Degraded),
            ("off", CapabilityPolicy::Off),
        ] {
            assert_eq!(s.parse::<CapabilityPolicy>().unwrap(), p);
            assert_eq!(p.to_string(), s);
        }
        assert!("bogus".parse::<CapabilityPolicy>().is_err());
    }
}
