//! sfp_hackertarget — HackerTarget hostsearch / reverse-DNS (keyless tier).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpHackerTarget;

#[async_trait]
impl Module for SfpHackerTarget {
    fn name(&self) -> &'static str {
        "sfp_hackertarget"
    }
    fn descr(&self) -> &'static str {
        "Query HackerTarget for hostnames and IPs associated with a domain."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::Errorprone]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::ROOT, EventType::DOMAIN_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::INTERNET_NAME, EventType::IP_ADDRESS]
    }

    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let domain = evt.data.trim().to_lowercase();
        if !domain.contains('.') {
            return Ok(Vec::new());
        }
        let url = format!("https://api.hackertarget.com/hostsearch/?q={domain}");
        let text = match ctx.http().get_text("sfp_hackertarget", &url).await {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };
        if text.contains("API count exceeded") || text.contains("error") {
            return Ok(Vec::new());
        }
        let me = self.name();
        let mut out = Vec::new();
        for line in text.lines() {
            let mut parts = line.splitn(2, ',');
            if let (Some(host), Some(ip)) = (parts.next(), parts.next()) {
                let host = host.trim().to_lowercase();
                if is_subdomain_of(&host, &domain) {
                    out.push(child_event(EventType::INTERNET_NAME, host, me, evt));
                }
                let ip = ip.trim();
                if !ip.is_empty() {
                    out.push(child_event(EventType::IP_ADDRESS, ip.to_string(), me, evt));
                }
            }
        }
        Ok(out)
    }
}

register_module!("sfp_hackertarget", SfpHackerTarget);
