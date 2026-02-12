//! sfp_amazon_aws — sfp_amazon_aws — OSINT source module (cloud group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpAmazonAws;

#[async_trait]
impl Module for SfpAmazonAws {
    fn name(&self) -> &'static str {
        "sfp_amazon_aws"
    }
    fn descr(&self) -> &'static str {
        "sfp_amazon_aws — OSINT source module (cloud group)."
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
        // TODO: implement the sfp_amazon_aws lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_amazon_aws", SfpAmazonAws);
