//! JWT-SVID revocation deny-list.

use std::collections::BTreeMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::backend::BackendError;
use crate::catalog::{Class, KeyEntry};
use crate::manager::{BackendManager, ManagerError};

const STORE_LABEL: &str = "revocation_store";
const JWT_SVID_STORE: &str = "jwt-svid";
const STORE_VERSION: u32 = 1;

/// In-memory JWT-SVID deny-list with optional catalog-backed persistence.
#[derive(Debug)]
pub struct JwtRevocationStore {
    storage_key: RwLock<Option<String>>,
    entries: RwLock<BTreeMap<RevocationKey, u64>>,
}

impl Default for JwtRevocationStore {
    fn default() -> Self {
        Self {
            storage_key: RwLock::new(None),
            entries: RwLock::new(BTreeMap::new()),
        }
    }
}

impl JwtRevocationStore {
    /// Load the configured deny-list from the catalog value key labeled
    /// `revocation_store=jwt-svid`, if present.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::Backend`] when the configured store is malformed,
    /// unreadable, or attached to a non-value catalog key.
    pub async fn load_from_manager(manager: &BackendManager) -> Result<Self, ManagerError> {
        let Some(storage_key) = jwt_revocation_store_key(manager)? else {
            return Ok(Self::default());
        };
        let routed = manager.resolve(&storage_key)?;
        let entries = match routed.backend.kv_get(routed.path(), None).await {
            Ok(value) => stored_entries(&value.value)?,
            Err(BackendError::KeyNotFound(_)) => BTreeMap::new(),
            Err(e) => return Err(ManagerError::Backend(e)),
        };
        Ok(Self {
            storage_key: RwLock::new(Some(storage_key)),
            entries: RwLock::new(prune_expired(entries, now_unix_secs())),
        })
    }

    /// Re-read the configured backing store and union it into the live deny-list.
    ///
    /// Existing in-memory entries win when they live longer than the reloaded
    /// value, so a concurrent live revocation is never shortened or removed by a
    /// reload. A read/load error leaves this store untouched.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] when the backing store cannot be loaded or the
    /// live deny-list locks are poisoned.
    pub async fn refresh_from_manager(&self, manager: &BackendManager) -> Result<(), ManagerError> {
        let loaded = Self::load_from_manager(manager).await?;
        self.merge_from(loaded)
    }

    /// Return true when `jti` is currently denied for `trust_domain`.
    ///
    /// Expired entries are pruned before the lookup. Lock poisoning fails closed:
    /// a validator must not accept a token if the deny-list cannot be read.
    #[must_use]
    pub fn is_revoked(&self, trust_domain: &str, jti: &str) -> bool {
        let Ok(mut entries) = self.entries.write() else {
            return true;
        };
        let now = now_unix_secs();
        entries.retain(|_, expires_at| *expires_at > now);
        entries.contains_key(&RevocationKey::new(trust_domain, jti))
    }

    /// Add or extend a revoked JWT-SVID `jti`.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::Backend`] if the in-memory deny-list lock is
    /// poisoned.
    pub fn insert(
        &self,
        trust_domain: &str,
        jti: &str,
        expires_at_unix: u64,
    ) -> Result<(), ManagerError> {
        if expires_at_unix > now_unix_secs() {
            let mut entries = self.entries.write().map_err(|_| {
                ManagerError::Backend(BackendError::Backend(
                    "jwt revocation store lock poisoned".into(),
                ))
            })?;
            entries.insert(RevocationKey::new(trust_domain, jti), expires_at_unix);
        }
        Ok(())
    }

    /// Persist the current deny-list if a catalog-backed store is configured.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError`] if the configured backend write fails or the
    /// in-memory deny-list cannot be serialized.
    pub async fn persist(&self, manager: &BackendManager) -> Result<(), ManagerError> {
        let storage_key = {
            let storage_key = self.storage_key.read().map_err(|_| {
                ManagerError::Backend(BackendError::Backend(
                    "jwt revocation store key lock poisoned".into(),
                ))
            })?;
            storage_key.clone()
        };
        let Some(storage_key) = storage_key else {
            return Ok(());
        };
        let routed = manager.resolve(&storage_key)?;
        let payload = self.snapshot_json()?;
        routed.backend.kv_put(routed.path(), &payload).await?;
        Ok(())
    }

    /// Whether live revocations have a configured catalog-backed value store.
    ///
    /// # Errors
    ///
    /// Returns [`ManagerError::Backend`] if the store-key lock is poisoned.
    pub fn has_persistent_store(&self) -> Result<bool, ManagerError> {
        let storage_key = self.storage_key.read().map_err(|_| {
            ManagerError::Backend(BackendError::Backend(
                "jwt revocation store key lock poisoned".into(),
            ))
        })?;
        Ok(storage_key.is_some())
    }

    fn merge_from(&self, loaded: Self) -> Result<(), ManagerError> {
        let loaded_storage_key = loaded.storage_key.into_inner().map_err(|_| {
            ManagerError::Backend(BackendError::Backend(
                "jwt revocation loaded store key lock poisoned".into(),
            ))
        })?;
        let loaded_entries = loaded.entries.into_inner().map_err(|_| {
            ManagerError::Backend(BackendError::Backend(
                "jwt revocation loaded entries lock poisoned".into(),
            ))
        })?;

        let mut storage_key = self.storage_key.write().map_err(|_| {
            ManagerError::Backend(BackendError::Backend(
                "jwt revocation store key lock poisoned".into(),
            ))
        })?;
        *storage_key = loaded_storage_key;
        drop(storage_key);

        let now = now_unix_secs();
        let mut entries = self.entries.write().map_err(|_| {
            ManagerError::Backend(BackendError::Backend(
                "jwt revocation store lock poisoned".into(),
            ))
        })?;
        entries.retain(|_, expires_at| *expires_at > now);
        for (key, expires_at) in prune_expired(loaded_entries, now) {
            entries
                .entry(key)
                .and_modify(|current| *current = (*current).max(expires_at))
                .or_insert(expires_at);
        }
        drop(entries);
        Ok(())
    }

    fn snapshot_json(&self) -> Result<Vec<u8>, ManagerError> {
        let entries = self.entries.read().map_err(|_| {
            ManagerError::Backend(BackendError::Backend(
                "jwt revocation store lock poisoned".into(),
            ))
        })?;
        let snapshot = entries
            .iter()
            .map(|(key, expires_at_unix)| StoredRevocation {
                trust_domain: key.trust_domain.clone(),
                jti: key.jti.clone(),
                expires_at_unix: *expires_at_unix,
            })
            .collect();
        drop(entries);
        let stored = StoredRevocations {
            version: STORE_VERSION,
            entries: snapshot,
        };
        serde_json::to_vec(&stored).map_err(|e| {
            ManagerError::Backend(BackendError::Backend(format!(
                "jwt revocation store serialize: {e}"
            )))
        })
    }
}

fn jwt_revocation_store_key(manager: &BackendManager) -> Result<Option<String>, ManagerError> {
    let mut found = None;
    for (name, entry) in manager.keys().filter(|(_, entry)| is_jwt_store(entry)) {
        validate_jwt_store_key(name, entry)?;
        record_jwt_store_key(&mut found, name)?;
    }
    Ok(found)
}

fn is_jwt_store(entry: &KeyEntry) -> bool {
    // ubs false positive - not secret comparison
    /* ubs:ignore */
    entry.labels.get(STORE_LABEL) == Some(JWT_SVID_STORE)
}

fn validate_jwt_store_key(name: &str, entry: &KeyEntry) -> Result<(), ManagerError> {
    if entry.class == Class::Value {
        return Ok(());
    }
    Err(ManagerError::Backend(BackendError::Backend(format!(
        "jwt revocation store `{name}` must be a value key"
    ))))
}

fn record_jwt_store_key(found: &mut Option<String>, name: &str) -> Result<(), ManagerError> {
    if found.is_some() {
        return Err(ManagerError::Backend(BackendError::Backend(
            "multiple jwt revocation stores configured".into(),
        )));
    }
    *found = Some(name.to_string());
    Ok(())
}

fn stored_entries(input: &[u8]) -> Result<BTreeMap<RevocationKey, u64>, ManagerError> {
    let stored: StoredRevocations = serde_json::from_slice(input).map_err(|e| {
        ManagerError::Backend(BackendError::Backend(format!(
            "jwt revocation store parse: {e}"
        )))
    })?;
    // ubs false positive - not secret comparison
    /* ubs:ignore */
    if stored.version != STORE_VERSION {
        return Err(ManagerError::Backend(BackendError::Backend(format!(
            "unsupported jwt revocation store version {}",
            stored.version
        ))));
    }
    Ok(stored
        .entries
        .into_iter()
        .filter(|entry| !entry.trust_domain.is_empty() && !entry.jti.is_empty())
        .map(|entry| {
            (
                RevocationKey::new(&entry.trust_domain, &entry.jti),
                entry.expires_at_unix,
            )
        })
        .collect())
}

fn prune_expired(
    mut entries: BTreeMap<RevocationKey, u64>,
    now: u64,
) -> BTreeMap<RevocationKey, u64> {
    entries.retain(|_, expires_at| *expires_at > now);
    entries
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RevocationKey {
    trust_domain: String,
    jti: String,
}

impl RevocationKey {
    fn new(trust_domain: &str, jti: &str) -> Self {
        Self {
            trust_domain: trust_domain.to_string(),
            jti: jti.to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRevocations {
    version: u32,
    entries: Vec<StoredRevocation>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRevocation {
    trust_domain: String,
    jti: String,
    expires_at_unix: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_entry_matches_until_expiry() {
        let store = JwtRevocationStore::default();
        let expires_at = now_unix_secs().saturating_add(60);
        store
            .insert("example.org", "jti-1", expires_at)
            .expect("insert");
        assert!(store.is_revoked("example.org", "jti-1"));
        assert!(!store.is_revoked("other.example", "jti-1"));
        assert!(!store.is_revoked("example.org", "other"));
    }

    #[test]
    fn expired_entries_are_pruned_on_load() {
        let mut entries = BTreeMap::new();
        entries.insert(RevocationKey::new("example.org", "old"), 1);
        entries.insert(RevocationKey::new("example.org", "live"), 100);
        let entries = prune_expired(entries, 50);
        assert!(!entries.contains_key(&RevocationKey::new("example.org", "old")));
        assert!(entries.contains_key(&RevocationKey::new("example.org", "live")));
    }

    #[test]
    fn merge_refresh_unions_entries_and_preserves_longer_live_expiry() {
        let now = now_unix_secs();
        let store = JwtRevocationStore::default();
        store
            .insert("example.org", "live-only", now.saturating_add(200))
            .expect("live insert");
        store
            .insert("example.org", "shared", now.saturating_add(300))
            .expect("live shared insert");

        let mut loaded_entries = BTreeMap::new();
        loaded_entries.insert(
            RevocationKey::new("example.org", "loaded-only"),
            now.saturating_add(250),
        );
        loaded_entries.insert(
            RevocationKey::new("example.org", "shared"),
            now.saturating_add(100),
        );
        let loaded = JwtRevocationStore {
            storage_key: RwLock::new(Some("revocations".to_string())),
            entries: RwLock::new(loaded_entries),
        };

        store.merge_from(loaded).expect("merge");
        assert!(store.is_revoked("example.org", "live-only"));
        assert!(store.is_revoked("example.org", "loaded-only"));
        assert!(store.is_revoked("example.org", "shared"));

        let snapshot = store.snapshot_json().expect("snapshot");
        let stored: StoredRevocations = serde_json::from_slice(&snapshot).expect("stored json");
        let shared = stored
            .entries
            .iter()
            .find(|entry| entry.jti == "shared")
            .expect("shared entry");
        assert_eq!(shared.expires_at_unix, now.saturating_add(300));
    }
}
