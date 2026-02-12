//! sfp_numverify — sfp_numverify — OSINT source module (phone group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpNumverify;

#[async_trait]
impl Module for SfpNumverify {
    fn name(&self) -> &'static str {
        "sfp_numverify"
    }
    fn descr(&self) -> &'static str {
        "sfp_numverify — OSINT source module (phone group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::ApiKey]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::PHONE_NUMBER]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::PHONE_NUMBER_TYPE, EventType::GEOINFO]
    }
    fn opts(&self) -> Vec<ModuleOpt> {
        vec![ModuleOpt::string("api_key", "", "API key for sfp_numverify")]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        if !ctx.has_api_key(self.name()) {
            return Ok(Vec::new());
        }
        // TODO: query the sfp_numverify API for the inbound entity and map to events.
        Ok(Vec::new())
    }
}

register_module!("sfp_numverify", SfpNumverify);
