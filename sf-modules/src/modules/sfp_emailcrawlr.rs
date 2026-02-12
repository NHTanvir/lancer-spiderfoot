//! sfp_emailcrawlr — sfp_emailcrawlr — OSINT source module (identity group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpEmailcrawlr;

#[async_trait]
impl Module for SfpEmailcrawlr {
    fn name(&self) -> &'static str {
        "sfp_emailcrawlr"
    }
    fn descr(&self) -> &'static str {
        "sfp_emailcrawlr — OSINT source module (identity group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::ApiKey]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::EMAILADDR, EventType::DOMAIN_NAME, EventType::HUMAN_NAME, EventType::USERNAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::EMAILADDR, EventType::ACCOUNT_EXTERNAL_OWNED, EventType::BREACHED_DATA]
    }
    fn opts(&self) -> Vec<ModuleOpt> {
        vec![ModuleOpt::string("api_key", "", "API key for sfp_emailcrawlr")]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        if !ctx.has_api_key(self.name()) {
            return Ok(Vec::new());
        }
        // TODO: query the sfp_emailcrawlr API for the inbound entity and map to events.
        Ok(Vec::new())
    }
}

register_module!("sfp_emailcrawlr", SfpEmailcrawlr);
