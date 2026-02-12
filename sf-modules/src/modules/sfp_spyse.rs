//! sfp_spyse — sfp_spyse — OSINT source module (threat group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpSpyse;

#[async_trait]
impl Module for SfpSpyse {
    fn name(&self) -> &'static str {
        "sfp_spyse"
    }
    fn descr(&self) -> &'static str {
        "sfp_spyse — OSINT source module (threat group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::ApiKey]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::IP_ADDRESS, EventType::AFFILIATE_IPADDR, EventType::INTERNET_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::MALICIOUS_IPADDR, EventType::MALICIOUS_INTERNET_NAME, EventType::RAW_RIR_DATA]
    }
    fn opts(&self) -> Vec<ModuleOpt> {
        vec![ModuleOpt::string("api_key", "", "API key for sfp_spyse")]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        if !ctx.has_api_key(self.name()) {
            return Ok(Vec::new());
        }
        // TODO: query the sfp_spyse API for the inbound entity and map to events.
        Ok(Vec::new())
    }
}

register_module!("sfp_spyse", SfpSpyse);
