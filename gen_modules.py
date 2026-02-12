#!/usr/bin/env python3
"""Generate sf-modules/src/modules/*.rs stubs + mod.rs from a catalog manifest.

Hand-written module files that already exist are preserved (only mod.rs lists
them). Every other catalog module gets a uniform, compiling trait-impl stub.
"""
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
MODDIR = os.path.join(ROOT, "sf-modules", "src", "modules")
os.makedirs(MODDIR, exist_ok=True)

# group -> template metadata
GROUPS = {
    "threat":   dict(cats=["Passive"], flags=["ApiKey"],
                     watched=["IP_ADDRESS", "AFFILIATE_IPADDR", "INTERNET_NAME"],
                     produced=["MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME", "RAW_RIR_DATA"],
                     body="apikey"),
    "dns":      dict(cats=["Passive"], flags=["ApiKey"],
                     watched=["ROOT", "DOMAIN_NAME", "INTERNET_NAME"],
                     produced=["INTERNET_NAME", "IP_ADDRESS", "RAW_RIR_DATA"],
                     body="apikey"),
    "web":      dict(cats=["Footprint"], flags=[],
                     watched=["INTERNET_NAME", "DOMAIN_NAME", "TARGET_WEB_CONTENT"],
                     produced=["WEBSERVER_TECHNOLOGY", "LINKED_URL_INTERNAL", "SOFTWARE_USED"],
                     body="plain"),
    "identity": dict(cats=["Passive"], flags=["ApiKey"],
                     watched=["EMAILADDR", "DOMAIN_NAME", "HUMAN_NAME", "USERNAME"],
                     produced=["EMAILADDR", "ACCOUNT_EXTERNAL_OWNED", "BREACHED_DATA"],
                     body="apikey"),
    "cloud":    dict(cats=["Active"], flags=["Invasive"],
                     watched=["DOMAIN_NAME", "INTERNET_NAME"],
                     produced=["CLOUD_STORAGE_BUCKET", "CLOUD_STORAGE_BUCKET_OPEN"],
                     body="plain"),
    "crypto":   dict(cats=["Passive"], flags=[],
                     watched=["BITCOIN_ADDRESS", "ETHEREUM_ADDRESS"],
                     produced=["BITCOIN_BALANCE", "RAW_RIR_DATA"],
                     body="plain"),
    "darkweb":  dict(cats=["Passive"], flags=["ApiKey"],
                     watched=["DOMAIN_NAME", "EMAILADDR", "HUMAN_NAME"],
                     produced=["DARKNET_MENTION_URL", "LEAKSITE_URL"],
                     body="apikey"),
    "active":   dict(cats=["Active"], flags=["Invasive"],
                     watched=["IP_ADDRESS", "INTERNET_NAME"],
                     produced=["TCP_PORT_OPEN", "TCP_PORT_OPEN_BANNER"],
                     body="plain"),
    "tool":     dict(cats=["Active"], flags=["ToolExec", "Invasive"],
                     watched=["INTERNET_NAME", "IP_ADDRESS", "DOMAIN_NAME"],
                     produced=["VULNERABILITY_GENERAL", "SOFTWARE_USED", "TCP_PORT_OPEN"],
                     body="tool"),
    "search":   dict(cats=["Footprint"], flags=[],
                     watched=["DOMAIN_NAME", "EMAILADDR", "HUMAN_NAME"],
                     produced=["SEARCH_ENGINE_WEB_CONTENT", "LINKED_URL_EXTERNAL"],
                     body="plain"),
    "phone":    dict(cats=["Passive"], flags=["ApiKey"],
                     watched=["PHONE_NUMBER"],
                     produced=["PHONE_NUMBER_TYPE", "GEOINFO"],
                     body="apikey"),
    "geo":      dict(cats=["Passive"], flags=["ApiKey"],
                     watched=["IP_ADDRESS"],
                     produced=["GEOINFO", "PHYSICAL_COORDINATES", "COUNTRY_NAME"],
                     body="apikey"),
    "ai":       dict(cats=["Passive"], flags=["ApiKey"],
                     watched=["ROOT", "CORRELATION_RISK", "VULNERABILITY_GENERAL"],
                     produced=["AI_SUMMARY", "AI_RISK_SCORE", "AI_PERSONA"],
                     body="apikey"),
}

# name -> group
CATALOG = {}

def add(group, names):
    for n in names.split():
        CATALOG[n] = group

add("threat", """
sfp_abstractapi sfp_abusech sfp_abuseipdb sfp_alienvault sfp_apility sfp_badpackets
sfp_blocklistde sfp_botscout sfp_botvrij sfp_cleantalk sfp_comodo sfp_cybercrime_tracker
sfp_darkbit sfp_emergingthreats sfp_fortinet sfp_fraudguard sfp_greensnow sfp_greynoise
sfp_hybrid_analysis sfp_ipqualityscore sfp_malwarebazaar sfp_maltiverse sfp_minc sfp_misp
sfp_nessus_essentials sfp_openbugbounty sfp_otx sfp_phishstats sfp_phishtank sfp_psbdmp
sfp_pulsedive sfp_pulse sfp_quad9 sfp_riskiq sfp_robtex sfp_spamhaus sfp_spamcop sfp_spur
sfp_spyonweb sfp_spyse sfp_stopforumspam sfp_talosintel sfp_threatcrowd sfp_threatfox
sfp_threatminer sfp_threatjammer sfp_trashpanda sfp_uceprotect sfp_urlhaus sfp_urlscan
sfp_virustotal sfp_voipbl sfp_vxvault sfp_xforce sfp_zetalytics sfp_dronebl
""")

add("dns", """
sfp_accounts sfp_arin sfp_binaryedge sfp_c99 sfp_chaos sfp_circl sfp_citadel sfp_cloudflare
sfp_commoncrawl sfp_crossref sfp_crt sfp_crobat sfp_dnsbrute sfp_dnsdb sfp_dnsdumpster
sfp_dnsgrep sfp_dnsneutral sfp_dnsraw sfp_fofa sfp_fullhunt sfp_iknowwhatyoudownload
sfp_intelx sfp_leakix sfp_merklemap sfp_mnemonic sfp_onyphe sfp_passivetotal sfp_quake
sfp_recondev sfp_recon_wave sfp_ripe sfp_securitytrails sfp_sitedossier sfp_subdomaincenter
sfp_subdomainwhitelist sfp_tldsearch sfp_torch sfp_torexits sfp_viewdns sfp_whoxy sfp_whoisology
sfp_jsonwhois sfp_zoomeye sfp_certtransparency sfp_asnlookup sfp_dnszonexfer sfp_zonecruncher
sfp_securitytrails_scroll sfp_dnsdumpster2 sfp_certificatedetails sfp_crobat2
""")

add("geo", """
sfp_ipinfo sfp_ipinfodb sfp_ipdata sfp_ipregistry sfp_ipstack sfp_ipwhois sfp_iptoasn
sfp_maxmind sfp_ip2location sfp_ipgeolocation
""")

add("web", """
sfp_archiveorg sfp_base64 sfp_builtwith sfp_cookie sfp_creditcard sfp_errors sfp_filemeta
sfp_flickr sfp_google_tag_manager sfp_googlemaps sfp_hashes sfp_iban sfp_junkfiles
sfp_metadefender sfp_pageinfo sfp_securityheaders sfp_sitemap sfp_socialmediahyperlinks
sfp_strangeheaders sfp_subdomain_takeover sfp_tags sfp_validatewebsite sfp_wappalyzer
sfp_waybackarchive sfp_webanalytics sfp_webcrawl sfp_webframework sfp_wikileaks sfp_wikipedia
sfp_yandex_csv sfp_socialprofiles sfp_clearbit sfp_builtwith2 sfp_wellknown sfp_favicon
sfp_httpheaders sfp_cookies sfp_securitytxt2 sfp_pagehistory
""")

add("search", """
sfp_bingsearch sfp_duckduckgo sfp_google sfp_googlesearch sfp_yandexsearch sfp_commoncrawl_search
""")

add("identity", """
sfp_emailcrawlr sfp_emailformat sfp_emailrep sfp_emailhippo sfp_fullcontact sfp_gravatar
sfp_haveibeenpwned sfp_hunter sfp_namechk sfp_pipl sfp_sherlock sfp_skymem sfp_snusbase
sfp_thatsthem sfp_dehashed sfp_leakcheck sfp_leak_lookup sfp_pgp sfp_keybase sfp_gist
sfp_npmjs sfp_pypi
""")

add("phone", "sfp_callername sfp_numverify sfp_twilio sfp_phone sfp_neutrinoapi")

add("crypto", """
sfp_bitcoin sfp_bitcoinabuse sfp_bitcoinwhoswho sfp_blockchain sfp_blockchain_info
sfp_ethereum sfp_etherscan
""")

add("cloud", """
sfp_amazon_aws sfp_azureblobstorage sfp_azureblob sfp_digitaloceanspace sfp_googleobjectstorage
sfp_gcs sfp_grayhatwarfare sfp_s3bucket sfp_docker
""")

add("darkweb", "sfp_darknet sfp_pastebin")

add("active", """
sfp_open_passive sfp_portscan_basic sfp_portscan_tcp sfp_portscan sfp_subdomain_brute
sfp_dirsearch sfp_takeover
""")

add("tool", """
sfp_tool_nmap sfp_tool_whatweb sfp_tool_cmseek sfp_tool_nuclei sfp_tool_wafw00f
sfp_tool_testssl sfp_tool_retire sfp_tool_trufflehog sfp_tool_dnstwist
""")

add("ai", "sfp_ai_summarizer sfp_ai_risk_classifier sfp_ai_persona_inference sfp_ai_policy_generator")

# Keyless overrides — these sources work without an API key.
KEYLESS = set("""
sfp_abusech sfp_blocklistde sfp_botvrij sfp_comodo sfp_cybercrime_tracker sfp_dronebl
sfp_emergingthreats sfp_greensnow sfp_phishtank sfp_quad9 sfp_robtex sfp_spamcop sfp_spamhaus
sfp_stopforumspam sfp_talosintel sfp_threatcrowd sfp_threatfox sfp_threatminer sfp_uceprotect
sfp_urlhaus sfp_voipbl sfp_vxvault sfp_arin sfp_ripe sfp_iptoasn sfp_crt sfp_dnsdumpster
sfp_dnsgrep sfp_dnsneutral sfp_dnsraw sfp_commoncrawl sfp_archiveorg sfp_waybackarchive
sfp_sitedossier sfp_subdomaincenter sfp_crobat sfp_wikipedia sfp_wikileaks sfp_pastebin
sfp_emailformat sfp_gravatar sfp_pgp sfp_certtransparency
""".split())

# Hand-written modules that already exist — never overwrite, just list in mod.rs.
HANDWRITTEN = set("""
sfp_dnsresolve sfp_crtsh sfp_hackertarget sfp_certspotter sfp_internetdb sfp_bgpview
sfp_robotstxt sfp_securitytxt sfp_dnscommonsrv sfp_email sfp_spider sfp__stor_db
sfp__stor_stdout sfp_shodan
""".split())
for n in HANDWRITTEN:
    CATALOG.setdefault(n, "dns")


def camel(name):
    return "".join(p.capitalize() for p in name.split("_"))


def variants(prefix, items):
    return ", ".join(f"{prefix}::{i}" for i in items)


def render(name, g):
    meta = GROUPS[g]
    flags = [] if name in KEYLESS else list(meta["flags"])
    body_kind = meta["body"]
    struct = camel(name)
    descr = f"{name} — OSINT source module ({g} group)."
    cats = variants("Category", meta["cats"])
    flagstr = variants("ModuleFlag", flags)
    watched = variants("EventType", meta["watched"])
    produced = variants("EventType", meta["produced"])

    opts = ""
    if "ApiKey" in flags:
        opts = (f'    fn opts(&self) -> Vec<ModuleOpt> {{\n'
                f'        vec![ModuleOpt::string("api_key", "", "API key for {name}")]\n'
                f'    }}\n')

    if "ApiKey" in flags:
        body = (f'        if !ctx.has_api_key(self.name()) {{\n'
                f'            return Ok(Vec::new());\n'
                f'        }}\n'
                f'        // TODO: query the {name} API for the inbound entity and map to events.\n'
                f'        Ok(Vec::new())')
    elif body_kind == "tool":
        body = (f'        let _ = ctx;\n'
                f'        // TODO: shell out to the external `{name}` tool via tokio::process if on $PATH.\n'
                f'        Ok(Vec::new())')
    else:
        body = (f'        let _ = ctx;\n'
                f'        // TODO: implement the {name} lookup.\n'
                f'        Ok(Vec::new())')

    return f'''//! {name} — {descr}

use crate::prelude::*;

#[derive(Default)]
pub struct {struct};

#[async_trait]
impl Module for {struct} {{
    fn name(&self) -> &'static str {{
        "{name}"
    }}
    fn descr(&self) -> &'static str {{
        "{descr}"
    }}
    fn categories(&self) -> &'static [Category] {{
        &[{cats}]
    }}
    fn flags(&self) -> &'static [ModuleFlag] {{
        &[{flagstr}]
    }}
    fn watched_events(&self) -> &'static [EventType] {{
        &[{watched}]
    }}
    fn produced_events(&self) -> &'static [EventType] {{
        &[{produced}]
    }}
{opts}    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {{
{body}
    }}
}}

register_module!("{name}", {struct});
'''


written = 0
skipped = 0
names = sorted(CATALOG.keys())
for name in names:
    path = os.path.join(MODDIR, f"{name}.rs")
    if name in HANDWRITTEN or os.path.exists(path):
        skipped += 1
        continue
    with open(path, "w", encoding="utf-8") as f:
        f.write(render(name, CATALOG[name]))
    written += 1

# mod.rs
lines = [
    "//! Auto-generated module registry. Each `sfp_*` self-registers via inventory.",
    "//! Regenerate with `python gen_modules.py`.",
    "#![allow(clippy::module_inception)]",
    "#![allow(non_snake_case)]",
    "",
]
for name in names:
    lines.append(f"pub mod {name};")
lines += [
    "",
    "/// Referenced from `ensure_linked()` to retain module object files at link time.",
    "pub fn touch() {}",
    "",
]
with open(os.path.join(MODDIR, "mod.rs"), "w", encoding="utf-8") as f:
    f.write("\n".join(lines))

print(f"catalog={len(names)} written={written} preserved={skipped}")
