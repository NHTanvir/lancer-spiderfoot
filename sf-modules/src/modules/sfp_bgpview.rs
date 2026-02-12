//! sfp_bgpview — BGPView.io ASN / IP / prefix lookups (keyless).

use crate::prelude::*;
use serde_json::Value;

#[derive(Default)]
pub struct SfpBgpView;

#[async_trait]
impl Module for SfpBgpView {
    fn name(&self) -> &'static str {
        "sfp_bgpview"
    }
    fn descr(&self) -> &'static str {
        "Look up ASN ownership, peers and prefixes for IPs and ASNs via BGPView."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::IP_ADDRESS, EventType::BGP_AS_MEMBER]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[
            EventType::BGP_AS_OWNER,
            EventType::BGP_AS_MEMBER,
            EventType::NETBLOCK_MEMBER,
            EventType::RAW_RIR_DATA,
        ]
    }

    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let me = self.name();
        let mut out = Vec::new();
        match evt.type_ {
            EventType::IP_ADDRESS => {
                let url = format!("https://api.bgpview.io/ip/{}", evt.data.trim());
                if let Ok(v) = ctx.http().get_json::<Value>("sfp_bgpview", &url).await {
                    if let Some(prefixes) = v["data"]["prefixes"].as_array() {
                        for p in prefixes {
                            if let Some(prefix) = p["prefix"].as_str() {
                                out.push(child_event(
                                    EventType::NETBLOCK_MEMBER,
                                    prefix.to_string(),
                                    me,
                                    evt,
                                ));
                            }
                            if let Some(asn) = p["asn"]["asn"].as_u64() {
                                out.push(child_event(
                                    EventType::BGP_AS_MEMBER,
                                    format!("AS{asn}"),
                                    me,
                                    evt,
                                ));
                            }
                        }
                    }
                }
            }
            EventType::BGP_AS_MEMBER => {
                let asn = evt.data.trim().trim_start_matches("AS");
                let url = format!("https://api.bgpview.io/asn/{asn}");
                if let Ok(v) = ctx.http().get_json::<Value>("sfp_bgpview", &url).await {
                    if let Some(name) = v["data"]["name"].as_str() {
                        out.push(child_event(
                            EventType::BGP_AS_OWNER,
                            name.to_string(),
                            me,
                            evt,
                        ));
                    }
                }
            }
            _ => {}
        }
        Ok(out)
    }
}

register_module!("sfp_bgpview", SfpBgpView);
