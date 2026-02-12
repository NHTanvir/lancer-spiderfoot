//! sfp_base64 — sfp_base64 — OSINT source module (web group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpBase64;

#[async_trait]
impl Module for SfpBase64 {
    fn name(&self) -> &'static str {
        "sfp_base64"
    }
    fn descr(&self) -> &'static str {
        "sfp_base64 — OSINT source module (web group)."
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
        // TODO: implement the sfp_base64 lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_base64", SfpBase64);
