//! sfp_pastebin — sfp_pastebin — OSINT source module (darkweb group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpPastebin;

#[async_trait]
impl Module for SfpPastebin {
    fn name(&self) -> &'static str {
        "sfp_pastebin"
    }
    fn descr(&self) -> &'static str {
        "sfp_pastebin — OSINT source module (darkweb group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::DOMAIN_NAME, EventType::EMAILADDR, EventType::HUMAN_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::DARKNET_MENTION_URL, EventType::LEAKSITE_URL]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_pastebin lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_pastebin", SfpPastebin);
