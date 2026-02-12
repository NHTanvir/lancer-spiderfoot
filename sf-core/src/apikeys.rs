//! API key store with multi-key rotation and cooling on 401/403/429.

use crate::config::Config;
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;

/// A single key with usage / health metadata.
#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub value: String,
    pub last_used: Option<DateTime<Utc>>,
    pub fail_count: u32,
    pub cooling_until: Option<DateTime<Utc>>,
}

impl KeyEntry {
    fn new(value: String) -> Self {
        KeyEntry {
            value,
            last_used: None,
            fail_count: 0,
            cooling_until: None,
        }
    }

    fn is_cooling(&self, now: DateTime<Utc>) -> bool {
        self.cooling_until.map(|c| c > now).unwrap_or(false)
    }
}

/// Per-module pool of API keys with round-robin rotation.
#[derive(Default)]
pub struct ApiKeyStore {
    keys: DashMap<String, Vec<KeyEntry>>,
    rr: DashMap<String, usize>,
}

impl ApiKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a store from config plus `SPIDERFOOT_<MODULE>_API_KEY` env vars.
    pub fn from_config(cfg: &Config) -> Self {
        let store = ApiKeyStore::new();
        for (module, settings) in &cfg.modules {
            let mut entries = Vec::new();
            if let Some(k) = &settings.api_key {
                if !k.is_empty() {
                    entries.push(KeyEntry::new(k.clone()));
                }
            }
            for k in &settings.api_keys {
                if !k.is_empty() {
                    entries.push(KeyEntry::new(k.clone()));
                }
            }
            if !entries.is_empty() {
                store.keys.insert(module.clone(), entries);
            }
        }
        // Environment override / addition.
        for module in cfg.modules.keys() {
            if let Some(k) = Self::env_key(module) {
                store
                    .keys
                    .entry(module.clone())
                    .or_default()
                    .push(KeyEntry::new(k));
            }
        }
        store
    }

    fn env_key(module: &str) -> Option<String> {
        let var = format!("SPIDERFOOT_{}_API_KEY", module.to_ascii_uppercase());
        std::env::var(var).ok().filter(|v| !v.is_empty())
    }

    /// Register a key for a module at runtime.
    pub fn add_key(&self, module: &str, key: impl Into<String>) {
        self.keys
            .entry(module.to_string())
            .or_default()
            .push(KeyEntry::new(key.into()));
    }

    /// True if any usable key exists for the module (config, runtime, or env).
    pub fn has_key(&self, module: &str) -> bool {
        if self.keys.get(module).map(|v| !v.is_empty()).unwrap_or(false) {
            return true;
        }
        Self::env_key(module).is_some()
    }

    /// Return the next usable key for a module, round-robin over non-cooling keys.
    pub fn next_key(&self, module: &str) -> Option<String> {
        // Lazily import from env on first use.
        if !self.keys.contains_key(module) {
            if let Some(k) = Self::env_key(module) {
                self.keys.insert(module.to_string(), vec![KeyEntry::new(k)]);
            }
        }
        let mut entry = self.keys.get_mut(module)?;
        let now = Utc::now();
        let len = entry.len();
        if len == 0 {
            return None;
        }
        let start = self.rr.get(module).map(|r| *r).unwrap_or(0) % len;
        for off in 0..len {
            let idx = (start + off) % len;
            if !entry[idx].is_cooling(now) {
                entry[idx].last_used = Some(now);
                self.rr.insert(module.to_string(), idx + 1);
                return Some(entry[idx].value.clone());
            }
        }
        // All cooling — fall back to least-recently-used.
        let idx = start;
        entry[idx].last_used = Some(now);
        Some(entry[idx].value.clone())
    }

    /// Mark a key as failed (401/403): cool it for 60s, bump fail count.
    pub fn mark_failure(&self, module: &str, key: &str) {
        if let Some(mut entry) = self.keys.get_mut(module) {
            for e in entry.iter_mut() {
                if e.value == key {
                    e.fail_count += 1;
                    e.cooling_until = Some(Utc::now() + Duration::seconds(60));
                }
            }
        }
    }

    /// Honour a `Retry-After` on 429.
    pub fn mark_rate_limited(&self, module: &str, key: &str, retry_after_secs: i64) {
        if let Some(mut entry) = self.keys.get_mut(module) {
            for e in entry.iter_mut() {
                if e.value == key {
                    e.cooling_until = Some(Utc::now() + Duration::seconds(retry_after_secs.max(1)));
                }
            }
        }
    }
}
