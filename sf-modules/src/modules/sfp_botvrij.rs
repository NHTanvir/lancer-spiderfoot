//! sfp_botvrij — sfp_botvrij — OSINT source module (threat group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpBotvrij;

#[async_trait]
impl Module for SfpBotvrij {
    fn name(&self) -> &'static str {
        "sfp_botvrij"
    }
    fn descr(&self) -> &'static str {
        "sfp_botvrij — OSINT source module (threat group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::IP_ADDRESS, EventType::AFFILIATE_IPADDR, EventType::INTERNET_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::MALICIOUS_IPADDR, EventType::MALICIOUS_INTERNET_NAME, EventType::RAW_RIR_DATA]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_botvrij lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_botvrij", SfpBotvrij);
