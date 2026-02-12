//! sfp_gravatar — sfp_gravatar — OSINT source module (identity group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpGravatar;

#[async_trait]
impl Module for SfpGravatar {
    fn name(&self) -> &'static str {
        "sfp_gravatar"
    }
    fn descr(&self) -> &'static str {
        "sfp_gravatar — OSINT source module (identity group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::EMAILADDR, EventType::DOMAIN_NAME, EventType::HUMAN_NAME, EventType::USERNAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::EMAILADDR, EventType::ACCOUNT_EXTERNAL_OWNED, EventType::BREACHED_DATA]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_gravatar lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_gravatar", SfpGravatar);
