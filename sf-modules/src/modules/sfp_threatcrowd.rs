//! sfp_threatcrowd — sfp_threatcrowd — OSINT source module (threat group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpThreatcrowd;

#[async_trait]
impl Module for SfpThreatcrowd {
    fn name(&self) -> &'static str {
        "sfp_threatcrowd"
    }
    fn descr(&self) -> &'static str {
        "sfp_threatcrowd — OSINT source module (threat group)."
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
        // TODO: implement the sfp_threatcrowd lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_threatcrowd", SfpThreatcrowd);
