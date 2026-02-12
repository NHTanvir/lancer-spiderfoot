//! sfp_darknet — sfp_darknet — OSINT source module (darkweb group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpDarknet;

#[async_trait]
impl Module for SfpDarknet {
    fn name(&self) -> &'static str {
        "sfp_darknet"
    }
    fn descr(&self) -> &'static str {
        "sfp_darknet — OSINT source module (darkweb group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::ApiKey]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::DOMAIN_NAME, EventType::EMAILADDR, EventType::HUMAN_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::DARKNET_MENTION_URL, EventType::LEAKSITE_URL]
    }
    fn opts(&self) -> Vec<ModuleOpt> {
        vec![ModuleOpt::string("api_key", "", "API key for sfp_darknet")]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        if !ctx.has_api_key(self.name()) {
            return Ok(Vec::new());
        }
        // TODO: query the sfp_darknet API for the inbound entity and map to events.
        Ok(Vec::new())
    }
}

register_module!("sfp_darknet", SfpDarknet);
