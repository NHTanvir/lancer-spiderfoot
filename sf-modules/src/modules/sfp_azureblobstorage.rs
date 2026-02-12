//! sfp_azureblobstorage — sfp_azureblobstorage — OSINT source module (cloud group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpAzureblobstorage;

#[async_trait]
impl Module for SfpAzureblobstorage {
    fn name(&self) -> &'static str {
        "sfp_azureblobstorage"
    }
    fn descr(&self) -> &'static str {
        "sfp_azureblobstorage — OSINT source module (cloud group)."
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
        // TODO: implement the sfp_azureblobstorage lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_azureblobstorage", SfpAzureblobstorage);
