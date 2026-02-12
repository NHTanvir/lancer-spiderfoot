//! sfp_dnscommonsrv — probe common subdomain labels via DNS (footprint).

use crate::prelude::*;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

#[derive(Default)]
pub struct SfpDnsCommonSrv;

const COMMON: &[&str] = &[
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure", "vpn",
    "m", "shop", "ftp", "mail2", "test", "portal", "dev", "staging", "api", "admin", "cdn", "cloud",
    "git", "gitlab", "jenkins", "jira", "wiki", "support", "status", "dashboard", "internal",
    "intranet", "vpn2", "owa", "autodiscover", "imap", "pop", "mx", "ns", "db", "backup",
];

#[async_trait]
impl Module for SfpDnsCommonSrv {
    fn name(&self) -> &'static str {
        "sfp_dnscommonsrv"
    }
    fn descr(&self) -> &'static str {
        "Probe a list of common subdomain labels via DNS to find live hosts."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Footprint]
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
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let me = self.name();
        let mut out = Vec::new();
        for label in COMMON {
            if ctx.is_cancelled() {
                break;
            }
            let host = format!("{label}.{domain}");
            if resolver.lookup_ip(host.as_str()).await.is_ok() {
                out.push(child_event(EventType::INTERNET_NAME, host, me, evt));
            }
        }
        Ok(out)
    }
}

register_module!("sfp_dnscommonsrv", SfpDnsCommonSrv);
