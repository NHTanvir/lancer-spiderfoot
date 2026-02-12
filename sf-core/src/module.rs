//! The `Module` trait every source/detector implements, plus registration.

use crate::context::ScanContext;
use crate::error::Result;
use crate::event::{EventType, SfEvent};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Module category — controls which scan policies include the module.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    /// Never touches the target — only third-party APIs / public data.
    Passive,
    /// Passive + queries the target's own public surface (DNS, robots.txt).
    Footprint,
    /// Targeted queries about one specific entity.
    Investigate,
    /// Sends non-passive traffic to the target. Off by default.
    Active,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Passive => "Passive",
            Category::Footprint => "Footprint",
            Category::Investigate => "Investigate",
            Category::Active => "Active",
        }
    }
}

/// Behavioural flags used for filtering and safety.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleFlag {
    /// Needs a vendor API key to function.
    ApiKey,
    /// Calls an external binary (nmap, whois, ...).
    ToolExec,
    /// Average runtime > 30s per event.
    Slow,
    /// Known-flaky source; auto-disable after N failures.
    Errorprone,
    /// Touches the target with non-passive traffic.
    Invasive,
}

impl ModuleFlag {
    pub fn as_str(&self) -> &'static str {
        match self {
            ModuleFlag::ApiKey => "apikey",
            ModuleFlag::ToolExec => "tool",
            ModuleFlag::Slow => "slow",
            ModuleFlag::Errorprone => "errorprone",
            ModuleFlag::Invasive => "invasive",
        }
    }
}

/// The data type of a configurable module option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptType {
    String,
    Int,
    Bool,
    List,
}

/// A user-configurable per-module option.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleOpt {
    pub name: String,
    pub default: String,
    pub descr: String,
    pub data_type: OptType,
}

impl ModuleOpt {
    pub fn string(name: &str, default: &str, descr: &str) -> Self {
        ModuleOpt {
            name: name.to_string(),
            default: default.to_string(),
            descr: descr.to_string(),
            data_type: OptType::String,
        }
    }
    pub fn int(name: &str, default: i64, descr: &str) -> Self {
        ModuleOpt {
            name: name.to_string(),
            default: default.to_string(),
            descr: descr.to_string(),
            data_type: OptType::Int,
        }
    }
    pub fn bool(name: &str, default: bool, descr: &str) -> Self {
        ModuleOpt {
            name: name.to_string(),
            default: default.to_string(),
            descr: descr.to_string(),
            data_type: OptType::Bool,
        }
    }
}

/// The core trait. One implementor per source / detector / tool.
#[async_trait]
pub trait Module: Send + Sync + 'static {
    /// Stable module name, e.g. `sfp_dnsresolve`.
    fn name(&self) -> &'static str;
    /// One-line human description.
    fn descr(&self) -> &'static str;
    /// Categories this module belongs to.
    fn categories(&self) -> &'static [Category];
    /// Behavioural flags.
    fn flags(&self) -> &'static [ModuleFlag];
    /// Event types this module consumes.
    fn watched_events(&self) -> &'static [EventType];
    /// Event types this module can produce.
    fn produced_events(&self) -> &'static [EventType];
    /// Configurable options (with defaults).
    fn opts(&self) -> Vec<ModuleOpt> {
        Vec::new()
    }

    /// Called once before the scan starts.
    async fn setup(&self, _opts: &HashMap<String, String>, _ctx: &ScanContext) -> Result<()> {
        Ok(())
    }

    /// Handle a single inbound event, returning zero or more produced events.
    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>>;

    /// Called when the scan completes.
    fn finished(&self) {}

    /// True if this module needs an API key.
    fn needs_api_key(&self) -> bool {
        self.flags().contains(&ModuleFlag::ApiKey)
    }

    /// True if this module shells out to an external tool.
    fn is_tool(&self) -> bool {
        self.flags().contains(&ModuleFlag::ToolExec)
    }
}

/// A compile-time module registration collected via the `inventory` crate.
pub struct ModuleRegistration {
    pub name: &'static str,
    pub factory: fn() -> Box<dyn Module>,
}

inventory::collect!(ModuleRegistration);

/// Instantiate every registered module.
pub fn registered_modules() -> Vec<Box<dyn Module>> {
    inventory::iter::<ModuleRegistration>
        .into_iter()
        .map(|r| (r.factory)())
        .collect()
}

/// Number of registered modules.
pub fn registered_count() -> usize {
    inventory::iter::<ModuleRegistration>.into_iter().count()
}

/// Convenience macro for module crates to register a unit-struct module.
#[macro_export]
macro_rules! register_module {
    ($ty:ty) => {
        $crate::inventory::submit! {
            $crate::ModuleRegistration {
                name: stringify!($ty),
                factory: || Box::new(<$ty>::default()),
            }
        }
    };
    ($name:literal, $ty:ty) => {
        $crate::inventory::submit! {
            $crate::ModuleRegistration {
                name: $name,
                factory: || Box::new(<$ty>::default()),
            }
        }
    };
}
