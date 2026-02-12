//! sfp_robotstxt — fetch and parse robots.txt for a host (footprint).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpRobotsTxt;

#[async_trait]
impl Module for SfpRobotsTxt {
    fn name(&self) -> &'static str {
        "sfp_robotstxt"
    }
    fn descr(&self) -> &'static str {
        "Retrieve robots.txt and extract disallowed paths and linked URLs."
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
        &[EventType::ROBOTS_TXT, EventType::LINKED_URL_INTERNAL]
    }

    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let host = evt.data.trim();
        if !host.contains('.') {
            return Ok(Vec::new());
        }
        let url = format!("https://{host}/robots.txt");
        let (status, body) = match ctx.http().get_status_text("sfp_robotstxt", &url).await {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };
        if status != 200 || body.is_empty() || body.len() > 100_000 {
            return Ok(Vec::new());
        }
        let me = self.name();
        let mut out = vec![child_event(EventType::ROBOTS_TXT, body.clone(), me, evt)];
        for line in body.lines() {
            let line = line.trim();
            if let Some(rest) = line
                .strip_prefix("Disallow:")
                .or_else(|| line.strip_prefix("Allow:"))
            {
                let path = rest.trim();
                if path.starts_with('/') && path.len() > 1 {
                    out.push(child_event(
                        EventType::LINKED_URL_INTERNAL,
                        format!("https://{host}{path}"),
                        me,
                        evt,
                    ));
                }
            }
        }
        Ok(out)
    }
}

register_module!("sfp_robotstxt", SfpRobotsTxt);
