// SPDX-FileCopyrightText: 2026 OpenBasil Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! Best-effort, secret-free audit events for local Nix cache mutations.

use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

pub const ID_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationOp {
    Sign,
    Replace,
    Remove,
}

impl MutationOp {
    const fn token(self) -> &'static str {
        match self {
            Self::Sign => "sign",
            Self::Replace => "replace",
            Self::Remove => "remove",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureSource {
    NotApplicable,
    Produced,
    Reused,
}

impl SignatureSource {
    const fn token(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Produced => "produced",
            Self::Reused => "reused",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BatchCounts {
    pub selected: usize,
    pub durable_commits: usize,
    pub unchanged: usize,
    pub preview_changes: usize,
    pub signatures_produced: usize,
    pub signatures_reused: usize,
    pub signatures_installed: usize,
}

pub trait AuditSink {
    fn emit(&mut self, value: &Value);
}

#[cfg(test)]
pub struct NoopAudit;

#[cfg(test)]
impl AuditSink for NoopAudit {
    fn emit(&mut self, _value: &Value) {}
}

pub struct StderrAudit;

impl AuditSink for StderrAudit {
    fn emit(&mut self, value: &Value) {
        let Ok(mut line) = serde_json::to_vec(value) else {
            return;
        };
        line.push(b'\n');
        let _ = std::io::stderr().lock().write_all(&line);
    }
}

pub struct BatchAudit<'a, S: AuditSink> {
    sink: &'a mut S,
    op: MutationOp,
    batch_id: [u8; ID_LEN],
    dry_run: bool,
    selection: &'static str,
    key_id: Option<String>,
    key_name: Option<String>,
    backend_version: Option<u32>,
    pub counts: BatchCounts,
    terminal: bool,
}

impl<'a, S: AuditSink> BatchAudit<'a, S> {
    pub fn new(
        sink: &'a mut S,
        op: MutationOp,
        batch_id: [u8; ID_LEN],
        dry_run: bool,
        select_all: bool,
        key_id: Option<&str>,
    ) -> Self {
        let mut audit = Self {
            sink,
            op,
            batch_id,
            dry_run,
            selection: if select_all { "all" } else { "explicit" },
            key_id: key_id.map(str::to_string),
            key_name: None,
            backend_version: None,
            counts: BatchCounts::default(),
            terminal: false,
        };
        audit.emit("batch_start", "started", "ok", None, None);
        audit
    }

    pub fn set_identity(&mut self, key_name: &str, backend_version: u32) {
        self.key_name = Some(key_name.to_string());
        self.backend_version = Some(backend_version);
    }

    pub const fn set_selected(&mut self, selected: usize) {
        self.counts.selected = selected;
    }

    pub const fn unchanged(&mut self) {
        self.counts.unchanged = self.counts.unchanged.saturating_add(1);
    }

    pub const fn preview_change(&mut self) {
        self.counts.preview_changes = self.counts.preview_changes.saturating_add(1);
    }

    pub const fn signature_observed(&mut self, source: SignatureSource) {
        self.count_signature(source);
    }

    pub fn durable_commit(
        &mut self,
        store_path: &[u8],
        fingerprint: Option<&[u8]>,
        request_id: Option<[u8; ID_LEN]>,
        source: SignatureSource,
        mutation: &'static str,
    ) {
        self.counts.durable_commits = self.counts.durable_commits.saturating_add(1);
        if mutation == "installed" {
            self.counts.signatures_installed = self.counts.signatures_installed.saturating_add(1);
        }
        let mut fields = Map::new();
        fields.insert(
            "selected_path_sha256".into(),
            Value::String(sha256_hex(store_path)),
        );
        fields.insert(
            "fingerprint_sha256".into(),
            fingerprint.map_or(Value::Null, |bytes| Value::String(sha256_hex(bytes))),
        );
        fields.insert(
            "request_id".into(),
            request_id.map_or(Value::Null, |id| Value::String(hex_id(id))),
        );
        fields.insert(
            "signature_source".into(),
            Value::String(source.token().into()),
        );
        fields.insert("mutation".into(), Value::String(mutation.into()));
        self.emit(
            "path_commit",
            "committed",
            "durable_commit",
            Some(fields),
            None,
        );
    }

    pub fn complete(&mut self) {
        self.emit(
            "batch_completion",
            "completed",
            "ok",
            None,
            Some(self.counts),
        );
        self.terminal = true;
    }

    pub fn fail(&mut self, reason: &'static str) {
        self.emit("batch_failure", "failed", reason, None, Some(self.counts));
        self.terminal = true;
    }

    pub fn cancel(&mut self, signal: &'static str) {
        let mut fields = Map::new();
        fields.insert("signal".into(), Value::String(signal.into()));
        self.emit(
            "batch_cancellation",
            "cancelled",
            "signal",
            Some(fields),
            Some(self.counts),
        );
        self.terminal = true;
    }

    pub fn cancel_task(&mut self) {
        let mut fields = Map::new();
        fields.insert("signal".into(), Value::Null);
        self.emit(
            "batch_cancellation",
            "cancelled",
            "task_cancelled",
            Some(fields),
            Some(self.counts),
        );
        self.terminal = true;
    }

    const fn count_signature(&mut self, source: SignatureSource) {
        match source {
            SignatureSource::NotApplicable => {}
            SignatureSource::Produced => {
                self.counts.signatures_produced = self.counts.signatures_produced.saturating_add(1);
            }
            SignatureSource::Reused => {
                self.counts.signatures_reused = self.counts.signatures_reused.saturating_add(1);
            }
        }
    }

    fn emit(
        &mut self,
        phase: &'static str,
        outcome: &'static str,
        reason: &'static str,
        extra: Option<Map<String, Value>>,
        counts: Option<BatchCounts>,
    ) {
        let occurred_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok());
        let mut value = Map::new();
        value.insert(
            "event".into(),
            json!({ "kind": "basil.audit.nix_cache_mutation", "version": 1 }),
        );
        value.insert(
            "occurred_at_unix_ms".into(),
            occurred_at_unix_ms.map_or(Value::Null, Value::from),
        );
        value.insert("phase".into(), Value::String(phase.into()));
        value.insert("operation".into(), Value::String(self.op.token().into()));
        value.insert("batch_id".into(), Value::String(hex_id(self.batch_id)));
        value.insert("dry_run".into(), self.dry_run.into());
        value.insert("selection".into(), Value::String(self.selection.into()));
        value.insert(
            "key_id".into(),
            self.key_id.clone().map_or(Value::Null, Value::String),
        );
        value.insert(
            "key_name".into(),
            self.key_name.clone().map_or(Value::Null, Value::String),
        );
        value.insert(
            "backend_version".into(),
            self.backend_version.map_or(Value::Null, Value::from),
        );
        value.insert("outcome".into(), Value::String(outcome.into()));
        value.insert("reason".into(), Value::String(reason.into()));
        if let Some(fields) = extra {
            value.extend(fields);
        }
        if let Some(counts) = counts {
            value.insert(
                "counts".into(),
                json!({
                    "selected": counts.selected,
                    "durable_commits": counts.durable_commits,
                    "unchanged": counts.unchanged,
                    "preview_changes": counts.preview_changes,
                    "signatures_produced": counts.signatures_produced,
                    "signatures_reused": counts.signatures_reused,
                    "signatures_installed": counts.signatures_installed,
                }),
            );
        }
        self.sink.emit(&Value::Object(value));
    }
}

impl<S: AuditSink> Drop for BatchAudit<'_, S> {
    fn drop(&mut self) {
        if !self.terminal && !std::thread::panicking() {
            self.cancel_task();
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hex_id(id: [u8; ID_LEN]) -> String {
    hex::encode(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Captured(Vec<Value>);

    impl AuditSink for Captured {
        fn emit(&mut self, value: &Value) {
            self.0.push(value.clone());
        }
    }

    #[test]
    fn exact_ids_digests_and_dispositions_are_secret_free() {
        let mut captured = Captured::default();
        {
            let mut audit = BatchAudit::new(
                &mut captured,
                MutationOp::Sign,
                [0xab; ID_LEN],
                false,
                false,
                Some("cache.signing"),
            );
            audit.set_identity("cache.example-1", 7);
            audit.set_selected(1);
            audit.signature_observed(SignatureSource::Produced);
            audit.durable_commit(
                b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-private-name",
                Some(b"1;/nix/store/private;sha256:payload;42;"),
                Some([0x01; ID_LEN]),
                SignatureSource::Produced,
                "installed",
            );
            audit.complete();
        }
        let commit = &captured.0[1];
        assert_eq!(commit["batch_id"], "abababababababababababababababab");
        assert_eq!(commit["request_id"], "01010101010101010101010101010101");
        assert_eq!(
            commit["selected_path_sha256"],
            "439e4f73bd68314fca39ec70160eb8ea784c68087293498f27a7f89d9e2c12bb"
        );
        assert_eq!(
            commit["fingerprint_sha256"],
            "37f539ac6367d6f5980a7c3f2400f79fa4a8d36890eb9e1bff79c5478918dbe8"
        );
        assert_eq!(commit["signature_source"], "produced");
        assert_eq!(commit["mutation"], "installed");
        let rendered = serde_json::to_string(&captured.0).unwrap();
        for forbidden in [
            "/nix/store/",
            "private-name",
            "sha256:payload",
            "fingerprint_bytes",
            "signature_bytes",
            "private_material",
        ] {
            assert!(!rendered.contains(forbidden), "leaked {forbidden}");
        }
        assert_eq!(captured.0[2]["counts"]["signatures_produced"], 1);
        assert_eq!(captured.0[2]["counts"]["signatures_installed"], 1);
    }

    #[test]
    fn dry_run_and_cancellation_never_emit_path_commits() {
        let mut captured = Captured::default();
        {
            let mut audit = BatchAudit::new(
                &mut captured,
                MutationOp::Remove,
                [0x02; ID_LEN],
                true,
                true,
                None,
            );
            audit.set_selected(2);
            audit.preview_change();
            audit.unchanged();
            audit.cancel("SIGTERM");
        }
        assert_eq!(captured.0.len(), 2);
        assert_eq!(captured.0[0]["phase"], "batch_start");
        assert_eq!(captured.0[1]["phase"], "batch_cancellation");
        assert_eq!(captured.0[1]["signal"], "SIGTERM");
        assert_eq!(captured.0[1]["counts"]["preview_changes"], 1);
    }

    #[test]
    fn dropped_batch_records_task_cancellation() {
        let mut captured = Captured::default();
        {
            let _audit = BatchAudit::new(
                &mut captured,
                MutationOp::Replace,
                [0x03; ID_LEN],
                false,
                false,
                Some("cache.signing"),
            );
        }
        assert_eq!(captured.0.len(), 2);
        assert_eq!(captured.0[1]["phase"], "batch_cancellation");
        assert_eq!(captured.0[1]["reason"], "task_cancelled");
    }
}
