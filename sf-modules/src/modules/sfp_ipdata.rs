//! sfp_ipdata — sfp_ipdata — OSINT source module (geo group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpIpdata;

#[async_trait]
impl Module for SfpIpdata {
    fn name(&self) -> &'static str {
        "sfp_ipdata"
    }
    fn descr(&self) -> &'static str {
        "sfp_ipdata — OSINT source module (geo group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::ApiKey]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::IP_ADDRESS]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::GEOINFO, EventType::PHYSICAL_COORDINATES, EventType::COUNTRY_NAME]
    }
    fn opts(&self) -> Vec<ModuleOpt> {
        vec![ModuleOpt::string("api_key", "", "API key for sfp_ipdata")]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        if !ctx.has_api_key(self.name()) {
            return Ok(Vec::new());
        }
        // TODO: query the sfp_ipdata API for the inbound entity and map to events.
        Ok(Vec::new())
    }
}

register_module!("sfp_ipdata", SfpIpdata);
