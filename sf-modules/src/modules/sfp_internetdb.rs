//! sfp_internetdb — Shodan InternetDB (keyless) host enrichment for IPs.

use crate::prelude::*;
use serde::Deserialize;

#[derive(Default)]
pub struct SfpInternetDb;

#[derive(Deserialize)]
struct InternetDbResp {
    #[serde(default)]
    ports: Vec<u32>,
    #[serde(default)]
    cpes: Vec<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    vulns: Vec<String>,
}

#[async_trait]
impl Module for SfpInternetDb {
    fn name(&self) -> &'static str {
        "sfp_internetdb"
    }
    fn descr(&self) -> &'static str {
        "Enrich IP addresses via Shodan InternetDB (open ports, CPEs, hostnames, CVEs) — no key."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Investigate]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::IP_ADDRESS]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[
            EventType::TCP_PORT_OPEN,
            EventType::SOFTWARE_USED,
            EventType::INTERNET_NAME,
            EventType::VULNERABILITY_CVE_HIGH,
        ]
    }

    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let ip = evt.data.trim();
        let url = format!("https://internetdb.shodan.io/{ip}");
        let resp: InternetDbResp = match ctx.http().get_json("sfp_internetdb", &url).await {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let me = self.name();
        let mut out = Vec::new();
        for p in resp.ports {
            out.push(child_event(
                EventType::TCP_PORT_OPEN,
                format!("{ip}:{p}"),
                me,
                evt,
            ));
        }
        for c in resp.cpes {
            out.push(child_event(EventType::SOFTWARE_USED, c, me, evt));
        }
        for h in resp.hostnames {
            out.push(child_event(EventType::INTERNET_NAME, h, me, evt));
        }
        for v in resp.vulns {
            out.push(
                child_event(EventType::VULNERABILITY_CVE_HIGH, v, me, evt)
                    .with_risk(RiskLevel::HIGH),
            );
        }
        Ok(out)
    }
}

register_module!("sfp_internetdb", SfpInternetDb);
