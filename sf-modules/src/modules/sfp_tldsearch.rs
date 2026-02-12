//! sfp_tldsearch — sfp_tldsearch — OSINT source module (dns group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpTldsearch;

#[async_trait]
impl Module for SfpTldsearch {
    fn name(&self) -> &'static str {
        "sfp_tldsearch"
    }
    fn descr(&self) -> &'static str {
        "sfp_tldsearch — OSINT source module (dns group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::ApiKey]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::ROOT, EventType::DOMAIN_NAME, EventType::INTERNET_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::INTERNET_NAME, EventType::IP_ADDRESS, EventType::RAW_RIR_DATA]
    }
    fn opts(&self) -> Vec<ModuleOpt> {
        vec![ModuleOpt::string("api_key", "", "API key for sfp_tldsearch")]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        if !ctx.has_api_key(self.name()) {
            return Ok(Vec::new());
        }
        // TODO: query the sfp_tldsearch API for the inbound entity and map to events.
        Ok(Vec::new())
    }
}

register_module!("sfp_tldsearch", SfpTldsearch);
