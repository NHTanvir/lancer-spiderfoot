//! sfp_securitytxt — fetch /.well-known/security.txt (footprint).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpSecurityTxt;

#[async_trait]
impl Module for SfpSecurityTxt {
    fn name(&self) -> &'static str {
        "sfp_securitytxt"
    }
    fn descr(&self) -> &'static str {
        "Retrieve security.txt and extract contact emails and policy URLs."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Footprint]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::INTERNET_NAME, EventType::DOMAIN_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[
            EventType::EMAILADDR,
            EventType::LINKED_URL_INTERNAL,
            EventType::RAW_FILE_META_DATA,
        ]
    }

    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let host = evt.data.trim();
        if !host.contains('.') {
            return Ok(Vec::new());
        }
        let me = self.name();
        for path in ["/.well-known/security.txt", "/security.txt"] {
            let url = format!("https://{host}{path}");
            if let Ok((200, body)) = ctx.http().get_status_text("sfp_securitytxt", &url).await {
                if body.to_lowercase().contains("contact") {
                    let mut out =
                        vec![child_event(EventType::RAW_FILE_META_DATA, body.clone(), me, evt)];
                    for email in extract_emails(&body) {
                        out.push(child_event(EventType::EMAILADDR, email, me, evt));
                    }
                    for url in extract_urls(&body) {
                        out.push(child_event(EventType::LINKED_URL_INTERNAL, url, me, evt));
                    }
                    return Ok(out);
                }
            }
        }
        Ok(Vec::new())
    }
}

register_module!("sfp_securitytxt", SfpSecurityTxt);
