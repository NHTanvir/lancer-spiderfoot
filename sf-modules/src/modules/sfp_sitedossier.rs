//! sfp_sitedossier — sfp_sitedossier — OSINT source module (dns group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpSitedossier;

#[async_trait]
impl Module for SfpSitedossier {
    fn name(&self) -> &'static str {
        "sfp_sitedossier"
    }
    fn descr(&self) -> &'static str {
        "sfp_sitedossier — OSINT source module (dns group)."
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
        // TODO: implement the sfp_sitedossier lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_sitedossier", SfpSitedossier);
