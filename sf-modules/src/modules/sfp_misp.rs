//! sfp_misp — sfp_misp — OSINT source module (threat group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpMisp;

#[async_trait]
impl Module for SfpMisp {
    fn name(&self) -> &'static str {
        "sfp_misp"
    }
    fn descr(&self) -> &'static str {
        "sfp_misp — OSINT source module (threat group)."
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
        vec![ModuleOpt::string("api_key", "", "API key for sfp_misp")]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        if !ctx.has_api_key(self.name()) {
            return Ok(Vec::new());
        }
        // TODO: query the sfp_misp API for the inbound entity and map to events.
        Ok(Vec::new())
    }
}

register_module!("sfp_misp", SfpMisp);
