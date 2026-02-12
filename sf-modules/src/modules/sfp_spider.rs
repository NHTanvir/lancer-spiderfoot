//! sfp_spider — fetch a target's web root and extract content + links (footprint).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpSpider;

#[async_trait]
impl Module for SfpSpider {
    fn name(&self) -> &'static str {
        "sfp_spider"
    }
    fn descr(&self) -> &'static str {
        "Fetch the target's web root, emit page content and internal/external links."
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
            EventType::TARGET_WEB_CONTENT,
            EventType::LINKED_URL_INTERNAL,
            EventType::LINKED_URL_EXTERNAL,
            EventType::HTTP_CODE,
        ]
    }

    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let host = evt.data.trim().to_lowercase();
        if !host.contains('.') {
            return Ok(Vec::new());
        }
        let url = format!("https://{host}/");
        let (status, body) = match ctx.http().get_status_text("sfp_spider", &url).await {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };
        let me = self.name();
        let mut out = vec![child_event(EventType::HTTP_CODE, status.to_string(), me, evt)];
        if status >= 400 || body.is_empty() {
            return Ok(out);
        }
        let trimmed: String = body.chars().take(200_000).collect();
        out.push(child_event(
            EventType::TARGET_WEB_CONTENT,
            trimmed.clone(),
            me,
            evt,
        ));
        for link in extract_urls(&trimmed) {
            let ty = if is_subdomain_of(
                link.split('/').nth(2).unwrap_or(""),
                &root_domain(&host),
            ) {
                EventType::LINKED_URL_INTERNAL
            } else {
                EventType::LINKED_URL_EXTERNAL
            };
            out.push(child_event(ty, link, me, evt));
        }
        Ok(out)
    }
}

register_module!("sfp_spider", SfpSpider);
