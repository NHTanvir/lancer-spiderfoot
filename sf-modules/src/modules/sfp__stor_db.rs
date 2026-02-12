//! sfp__stor_db — internal SQLite event sink.
//!
//! In this implementation persistence is handled centrally by the scan engine's
//! `Store`; this module exists for upstream catalog parity and is a no-op.

use crate::prelude::*;

#[derive(Default)]
pub struct SfpStorDb;

#[async_trait]
impl Module for SfpStorDb {
    fn name(&self) -> &'static str {
        "sfp__stor_db"
    }
    fn descr(&self) -> &'static str {
        "Stores scan results into the back-end SQLite database (internal)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[]
    }
    async fn handle_event(&self, _evt: &SfEvent, _ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        Ok(Vec::new())
    }
}

register_module!("sfp__stor_db", SfpStorDb);
