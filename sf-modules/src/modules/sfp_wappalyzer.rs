//! sfp_wappalyzer — sfp_wappalyzer — OSINT source module (web group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpWappalyzer;

#[async_trait]
impl Module for SfpWappalyzer {
    fn name(&self) -> &'static str {
        "sfp_wappalyzer"
    }
    fn descr(&self) -> &'static str {
        "sfp_wappalyzer — OSINT source module (web group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Footprint]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::INTERNET_NAME, EventType::DOMAIN_NAME, EventType::TARGET_WEB_CONTENT]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::WEBSERVER_TECHNOLOGY, EventType::LINKED_URL_INTERNAL, EventType::SOFTWARE_USED]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_wappalyzer lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_wappalyzer", SfpWappalyzer);
