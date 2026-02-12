//! sfp_email — extract email addresses from any collected content.

use crate::prelude::*;

#[derive(Default)]
pub struct SfpEmail;

#[async_trait]
impl Module for SfpEmail {
    fn name(&self) -> &'static str {
        "sfp_email"
    }
    fn descr(&self) -> &'static str {
        "Identify email addresses in collected web/leak/file content."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Footprint]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[
            EventType::TARGET_WEB_CONTENT,
            EventType::LEAKSITE_CONTENT,
            EventType::RAW_FILE_META_DATA,
            EventType::AFFILIATE_WEB_CONTENT,
            EventType::SEARCH_ENGINE_WEB_CONTENT,
            EventType::DARKNET_MENTION_CONTENT,
        ]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::EMAILADDR, EventType::EMAILADDR_GENERIC]
    }

    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let me = self.name();
        let generics = &ctx.config.global._genericusers;
        let mut out = Vec::new();
        for email in extract_emails(&evt.data) {
            let local = email.split('@').next().unwrap_or("");
            let ty = if generics.iter().any(|g| g == local) {
                EventType::EMAILADDR_GENERIC
            } else {
                EventType::EMAILADDR
            };
            out.push(child_event(ty, email, me, evt));
        }
        Ok(out)
    }
}

register_module!("sfp_email", SfpEmail);
