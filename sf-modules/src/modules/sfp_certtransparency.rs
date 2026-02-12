//! sfp_certtransparency — sfp_certtransparency — OSINT source module (dns group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpCerttransparency;

#[async_trait]
impl Module for SfpCerttransparency {
    fn name(&self) -> &'static str {
        "sfp_certtransparency"
    }
    fn descr(&self) -> &'static str {
        "sfp_certtransparency — OSINT source module (dns group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::ROOT, EventType::DOMAIN_NAME, EventType::INTERNET_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::INTERNET_NAME, EventType::IP_ADDRESS, EventType::RAW_RIR_DATA]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_certtransparency lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_certtransparency", SfpCerttransparency);
