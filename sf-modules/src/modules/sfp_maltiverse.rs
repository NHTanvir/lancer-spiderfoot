//! sfp_maltiverse — sfp_maltiverse — OSINT source module (threat group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpMaltiverse;

#[async_trait]
impl Module for SfpMaltiverse {
    fn name(&self) -> &'static str {
        "sfp_maltiverse"
    }
    fn descr(&self) -> &'static str {
        "sfp_maltiverse — OSINT source module (threat group)."
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
        vec![ModuleOpt::string("api_key", "", "API key for sfp_maltiverse")]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        if !ctx.has_api_key(self.name()) {
            return Ok(Vec::new());
        }
        // TODO: query the sfp_maltiverse API for the inbound entity and map to events.
        Ok(Vec::new())
    }
}

register_module!("sfp_maltiverse", SfpMaltiverse);
