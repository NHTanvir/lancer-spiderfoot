//! sfp_tool_wafw00f — sfp_tool_wafw00f — OSINT source module (tool group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpToolWafw00f;

#[async_trait]
impl Module for SfpToolWafw00f {
    fn name(&self) -> &'static str {
        "sfp_tool_wafw00f"
    }
    fn descr(&self) -> &'static str {
        "sfp_tool_wafw00f — OSINT source module (tool group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Active]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::ToolExec, ModuleFlag::Invasive]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::INTERNET_NAME, EventType::IP_ADDRESS, EventType::DOMAIN_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::VULNERABILITY_GENERAL, EventType::SOFTWARE_USED, EventType::TCP_PORT_OPEN]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: shell out to the external `sfp_tool_wafw00f` tool via tokio::process if on $PATH.
        Ok(Vec::new())
    }
}

register_module!("sfp_tool_wafw00f", SfpToolWafw00f);
