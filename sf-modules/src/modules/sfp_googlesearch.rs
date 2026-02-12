//! sfp_googlesearch — sfp_googlesearch — OSINT source module (search group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpGooglesearch;

#[async_trait]
impl Module for SfpGooglesearch {
    fn name(&self) -> &'static str {
        "sfp_googlesearch"
    }
    fn descr(&self) -> &'static str {
        "sfp_googlesearch — OSINT source module (search group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Footprint]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::DOMAIN_NAME, EventType::EMAILADDR, EventType::HUMAN_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::SEARCH_ENGINE_WEB_CONTENT, EventType::LINKED_URL_EXTERNAL]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_googlesearch lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_googlesearch", SfpGooglesearch);
