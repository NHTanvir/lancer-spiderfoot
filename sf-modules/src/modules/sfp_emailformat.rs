//! sfp_emailformat — sfp_emailformat — OSINT source module (identity group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpEmailformat;

#[async_trait]
impl Module for SfpEmailformat {
    fn name(&self) -> &'static str {
        "sfp_emailformat"
    }
    fn descr(&self) -> &'static str {
        "sfp_emailformat — OSINT source module (identity group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::EMAILADDR, EventType::DOMAIN_NAME, EventType::HUMAN_NAME, EventType::USERNAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::EMAILADDR, EventType::ACCOUNT_EXTERNAL_OWNED, EventType::BREACHED_DATA]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_emailformat lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_emailformat", SfpEmailformat);
