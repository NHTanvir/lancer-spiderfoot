//! sfp_shodan — Shodan host lookup (requires API key).

use crate::prelude::*;
use serde_json::Value;

#[derive(Default)]
pub struct SfpShodan;

#[async_trait]
impl Module for SfpShodan {
    fn name(&self) -> &'static str {
        "sfp_shodan"
    }
    fn descr(&self) -> &'static str {
        "Look up host details (ports, banners, hostnames, vulns) via the Shodan API."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Investigate]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[ModuleFlag::ApiKey]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::IP_ADDRESS]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[
            EventType::TCP_PORT_OPEN,
            EventType::TCP_PORT_OPEN_BANNER,
            EventType::INTERNET_NAME,
            EventType::SOFTWARE_USED,
            EventType::GEOINFO,
        ]
    }
    fn opts(&self) -> Vec<ModuleOpt> {
        vec![ModuleOpt::string("api_key", "", "Shodan API key")]
    }

    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let key = match ctx.api_key(self.name()) {
            Some(k) => k,
            None => return Ok(Vec::new()),
        };
        let ip = evt.data.trim();
        let url = format!("https://api.shodan.io/shodan/host/{ip}?key={key}");
        let v: Value = match ctx.http().get_json("sfp_shodan", &url).await {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()),
        };
        let me = self.name();
        let mut out = Vec::new();
        if let Some(ports) = v["ports"].as_array() {
            for p in ports {
                if let Some(port) = p.as_u64() {
                    out.push(child_event(
                        EventType::TCP_PORT_OPEN,
                        format!("{ip}:{port}"),
                        me,
                        evt,
                    ));
                }
            }
        }
        if let Some(hostnames) = v["hostnames"].as_array() {
            for h in hostnames {
                if let Some(h) = h.as_str() {
                    out.push(child_event(EventType::INTERNET_NAME, h.to_string(), me, evt));
                }
            }
        }
        if let (Some(city), Some(country)) =
            (v["city"].as_str(), v["country_name"].as_str())
        {
            out.push(child_event(
                EventType::GEOINFO,
                format!("{city}, {country}"),
                me,
                evt,
            ));
        }
        Ok(out)
    }
}

register_module!("sfp_shodan", SfpShodan);
