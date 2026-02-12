//! sfp_haveibeenpwned — sfp_haveibeenpwned — OSINT source module (identity group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpHaveibeenpwned;

#[async_trait]
impl Module for SfpHaveibeenpwned {
    fn name(&self) -> &'static str {
        "sfp_haveibeenpwned"
    }
    fn descr(&self) -> &'static str {
        "sfp_haveibeenpwned — OSINT source module (identity group)."
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
        vec![ModuleOpt::string("api_key", "", "API key for sfp_haveibeenpwned")]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        if !ctx.has_api_key(self.name()) {
            return Ok(Vec::new());
        }
        // TODO: query the sfp_haveibeenpwned API for the inbound entity and map to events.
        Ok(Vec::new())
    }
}

register_module!("sfp_haveibeenpwned", SfpHaveibeenpwned);
