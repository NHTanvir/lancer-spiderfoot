//! sfp_crtsh — Certificate Transparency search via crt.sh.

use crate::prelude::*;
use serde::Deserialize;

#[derive(Default)]
pub struct SfpCrtsh;

#[derive(Deserialize)]
struct CrtRow {
    #[serde(default)]
    name_value: String,
}

#[async_trait]
impl Module for SfpCrtsh {
    fn name(&self) -> &'static str {
        "sfp_crtsh"
    }
    fn descr(&self) -> &'static str {
        "Search Certificate Transparency logs (crt.sh) for subdomains and cert SANs."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::ROOT, EventType::DOMAIN_NAME]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[
            EventType::INTERNET_NAME,
            EventType::SSL_CERTIFICATE_ISSUED,
            EventType::DOMAIN_NAME,
        ]
    }

    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let domain = evt.data.trim().to_lowercase();
        if !domain.contains('.') {
            return Ok(Vec::new());
        }
        let url = format!("https://crt.sh/?q=%25.{domain}&output=json");
        let rows: Vec<CrtRow> = match ctx.http().get_json("sfp_crtsh", &url).await {
            Ok(r) => r,
            Err(_) => return Ok(Vec::new()),
        };
        let me = self.name();
        let mut hosts = std::collections::HashSet::new();
        for row in rows {
            for raw in row.name_value.split('\n') {
                let h = raw.trim().trim_start_matches("*.").to_lowercase();
                if !h.is_empty() && is_subdomain_of(&h, &domain) {
                    hosts.insert(h);
                }
            }
        }
        Ok(hosts
            .into_iter()
            .map(|h| child_event(EventType::INTERNET_NAME, h, me, evt))
            .collect())
    }
}

register_module!("sfp_crtsh", SfpCrtsh);
