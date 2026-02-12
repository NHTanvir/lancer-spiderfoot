//! `sf-core` — the orchestration engine for lancer-spiderfoot.
//!
//! Defines the event taxonomy, target types, the `Module` trait, the async
//! event bus + scan state machine, persistence, config, API-key rotation and
//! per-source rate limiting. GUI- and web-agnostic; both frontends drive it.

pub mod apikeys;
pub mod config;
pub mod context;
pub mod dedupe;
pub mod error;
pub mod event;
pub mod http;
pub mod module;
pub mod persist;
pub mod policy;
pub mod ratelimit;
pub mod scan;
pub mod target;

// Re-export the `inventory` crate so the `register_module!` macro can reach it
// via `$crate::inventory`.
pub use inventory;

pub use apikeys::ApiKeyStore;
pub use config::{Config, GlobalConfig, ModuleSettings};
pub use context::ScanContext;
pub use dedupe::Dedupe;
pub use error::{Error, Result};
pub use event::{event_hash, EventId, EventType, RiskLevel, SfEvent};
pub use http::HttpClient;
pub use module::{
    registered_count, registered_modules, Category, Module, ModuleFlag, ModuleOpt,
    ModuleRegistration, OptType,
};
pub use policy::Policy;
pub use ratelimit::RateLimiters;
pub use scan::{EventSink, Scan, ScanEngine, ScanResult, ScanStatus};
pub use target::{Target, TargetType};
