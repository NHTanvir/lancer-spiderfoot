//! sfp_iptoasn — sfp_iptoasn — OSINT source module (geo group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpIptoasn;

#[async_trait]
impl Module for SfpIptoasn {
    fn name(&self) -> &'static str {
        "sfp_iptoasn"
    }
    fn descr(&self) -> &'static str {
        "sfp_iptoasn — OSINT source module (geo group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::IP_ADDRESS]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::GEOINFO, EventType::PHYSICAL_COORDINATES, EventType::COUNTRY_NAME]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_iptoasn lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_iptoasn", SfpIptoasn);
