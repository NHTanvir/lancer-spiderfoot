//! Configuration: global options + per-module settings.
//!
//! Loaded from `~/.config/spiderfoot/sf.cfg` (TOML), env vars, or constructed
//! programmatically. Mirrors upstream's `[global]` / `[modules.*]` layout.

use crate::error::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn default_dns() -> String {
    "8.8.8.8".to_string()
}
fn default_timeout() -> u64 {
    30
}
fn default_ua() -> String {
    "Mozilla/5.0 (compatible; lancer-spiderfoot/0.1; +https://github.com/NHTanvir/lancer-spiderfoot)"
        .to_string()
}
fn default_generic_users() -> Vec<String> {
    ["admin", "root", "info", "support", "noreply", "webmaster", "postmaster"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_max_threads() -> usize {
    20
}

/// Global scan configuration (the `[global]` table).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GlobalConfig {
    pub _dnsserver: String,
    pub _fetchtimeout: u64,
    pub _socks_proxy: Option<String>,
    pub _useragent: String,
    pub _genericusers: Vec<String>,
    pub _maxthreads: usize,
    /// Idle timeout (seconds) before a scan with no activity is declared finished.
    pub _idle_timeout: u64,
    /// Hard cap on total events emitted per scan (0 = unlimited).
    pub _max_events: u64,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        GlobalConfig {
            _dnsserver: default_dns(),
            _fetchtimeout: default_timeout(),
            _socks_proxy: None,
            _useragent: default_ua(),
            _genericusers: default_generic_users(),
            _maxthreads: default_max_threads(),
            _idle_timeout: 30,
            _max_events: 0,
        }
    }
}

/// Per-module settings (the `[modules.<name>]` tables).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModuleSettings {
    pub api_key: Option<String>,
    #[serde(default)]
    pub api_keys: Vec<String>,
    pub delay_secs: Option<f64>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(flatten, default)]
    pub extra: HashMap<String, toml::Value>,
}

impl ModuleSettings {
    /// Get an option value as a string, checking known fields then `extra`.
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "api_key" => self.api_key.clone(),
            "delay_secs" => self.delay_secs.map(|d| d.to_string()),
            _ => self.extra.get(key).map(stringify_toml),
        }
    }
}

fn stringify_toml(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// The merged configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub modules: HashMap<String, ModuleSettings>,
}

impl Config {
    /// The default config-file location for the current OS.
    pub fn default_path() -> Option<PathBuf> {
        directories::BaseDirs::new()
            .map(|d| d.config_dir().join("spiderfoot").join("sf.cfg"))
    }

    /// Load config from a TOML file. Missing file → defaults.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&text)?;
        Ok(cfg)
    }

    /// Load from the default path if present, else defaults.
    pub fn load_default() -> Self {
        Self::default_path()
            .and_then(|p| Self::load(&p).ok())
            .unwrap_or_default()
    }

    /// Settings for a specific module (or an empty default).
    pub fn module(&self, name: &str) -> ModuleSettings {
        self.modules.get(name).cloned().unwrap_or_default()
    }

    /// Get a module option as a string.
    pub fn module_opt(&self, module: &str, key: &str) -> Option<String> {
        self.modules.get(module).and_then(|m| m.get(key))
    }
}
