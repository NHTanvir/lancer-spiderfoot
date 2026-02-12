//! sfp_dnsresolve — resolve A/AAAA/MX/NS/TXT records for hostnames.

use crate::prelude::*;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

#[derive(Default)]
pub struct SfpDnsResolve;

fn looks_like_host(s: &str) -> bool {
    s.contains('.') && !s.contains(' ') && !s.contains('@') && !s.contains('/')
}

#[async_trait]
impl Module for SfpDnsResolve {
    fn name(&self) -> &'static str {
        "sfp_dnsresolve"
    }
    fn descr(&self) -> &'static str {
        "Resolve hostnames to IPs and gather A/AAAA/MX/NS/TXT DNS records."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Footprint]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[
            EventType::ROOT,
            EventType::DOMAIN_NAME,
            EventType::INTERNET_NAME,
            EventType::AFFILIATE_INTERNET_NAME,
        ]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[
            EventType::IP_ADDRESS,
            EventType::IPV6_ADDRESS,
            EventType::INTERNET_NAME,
            EventType::DNS_TEXT,
            EventType::PROVIDER_MAIL,
            EventType::PROVIDER_DNS,
            EventType::RAW_DNS_RECORDS,
        ]
    }

    async fn handle_event(&self, evt: &SfEvent, _ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let host = evt.data.trim().to_string();
        if !looks_like_host(&host) {
            return Ok(Vec::new());
        }
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let me = self.name();
        let mut out = Vec::new();

        if let Ok(resp) = resolver.lookup_ip(host.as_str()).await {
            for ip in resp.iter() {
                if ip.is_ipv4() {
                    out.push(child_event(EventType::IP_ADDRESS, ip.to_string(), me, evt));
                } else {
                    out.push(child_event(EventType::IPV6_ADDRESS, ip.to_string(), me, evt));
                }
            }
        }
        if let Ok(mx) = resolver.mx_lookup(host.as_str()).await {
            for r in mx.iter() {
                let exch = r.exchange().to_string();
                out.push(child_event(EventType::PROVIDER_MAIL, exch.clone(), me, evt));
                out.push(child_event(EventType::INTERNET_NAME, exch, me, evt));
            }
        }
        if let Ok(ns) = resolver.ns_lookup(host.as_str()).await {
            for r in ns.iter() {
                out.push(child_event(EventType::PROVIDER_DNS, r.to_string(), me, evt));
            }
        }
        if let Ok(txt) = resolver.txt_lookup(host.as_str()).await {
            for r in txt.iter() {
                let joined = r.to_string();
                out.push(child_event(EventType::DNS_TEXT, joined.clone(), me, evt));
                out.push(child_event(EventType::RAW_DNS_RECORDS, joined, me, evt));
            }
        }
        Ok(out)
    }
}

register_module!("sfp_dnsresolve", SfpDnsResolve);
