//! sfp_digitaloceanspace — sfp_digitaloceanspace — OSINT source module (cloud group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpDigitaloceanspace;

#[async_trait]
impl Module for SfpDigitaloceanspace {
    fn name(&self) -> &'static str {
        "sfp_digitaloceanspace"
    }
    fn descr(&self) -> &'static str {
        "sfp_digitaloceanspace — OSINT source module (cloud group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Active]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::Invasive]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::DOMAIN_NAME, EventType::INTERNET_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::CLOUD_STORAGE_BUCKET, EventType::CLOUD_STORAGE_BUCKET_OPEN]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_digitaloceanspace lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_digitaloceanspace", SfpDigitaloceanspace);
