//! sfp_certspotter — SSLMate Cert Spotter CT log search.

use crate::prelude::*;
use serde::Deserialize;

#[derive(Default)]
pub struct SfpCertSpotter;

#[derive(Deserialize)]
struct Issuance {
    #[serde(default)]
    dns_names: Vec<String>,
}

#[async_trait]
impl Module for SfpCertSpotter {
    fn name(&self) -> &'static str {
        "sfp_certspotter"
    }
    fn descr(&self) -> &'static str {
        "Search Cert Spotter (SSLMate) Certificate Transparency logs for subdomains."
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
        &[EventType::INTERNET_NAME]
    }

    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let domain = evt.data.trim().to_lowercase();
        if !domain.contains('.') {
            return Ok(Vec::new());
        }
        let url = format!(
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        );
        let issuances: Vec<Issuance> =
            match ctx.http().get_json("sfp_certspotter", &url).await {
                Ok(v) => v,
                Err(_) => return Ok(Vec::new()),
            };
        let me = self.name();
        let mut hosts = std::collections::HashSet::new();
        for issuance in issuances {
            for name in issuance.dns_names {
                let h = name.trim().trim_start_matches("*.").to_lowercase();
                if is_subdomain_of(&h, &domain) {
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

register_module!("sfp_certspotter", SfpCertSpotter);
