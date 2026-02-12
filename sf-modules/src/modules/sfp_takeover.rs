//! sfp_takeover — sfp_takeover — OSINT source module (active group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpTakeover;

#[async_trait]
impl Module for SfpTakeover {
    fn name(&self) -> &'static str {
        "sfp_takeover"
    }
    fn descr(&self) -> &'static str {
        "sfp_takeover — OSINT source module (active group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Active]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::Invasive]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::IP_ADDRESS, EventType::INTERNET_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::TCP_PORT_OPEN, EventType::TCP_PORT_OPEN_BANNER]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_takeover lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_takeover", SfpTakeover);
