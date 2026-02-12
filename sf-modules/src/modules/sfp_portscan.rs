//! sfp_portscan — sfp_portscan — OSINT source module (active group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpPortscan;

#[async_trait]
impl Module for SfpPortscan {
    fn name(&self) -> &'static str {
        "sfp_portscan"
    }
    fn descr(&self) -> &'static str {
        "sfp_portscan — OSINT source module (active group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Active]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::Invasive]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::IP_ADDRESS, EventType::INTERNET_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::TCP_PORT_OPEN, EventType::TCP_PORT_OPEN_BANNER]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_portscan lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_portscan", SfpPortscan);
