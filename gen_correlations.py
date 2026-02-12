#!/usr/bin/env python3
"""Generate the 37 upstream-parity correlation rule YAML files."""
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "correlations")
os.makedirs(OUT, exist_ok=True)

# (id, name, desc, risk, scope, [(method, field, value)...], agg|None, analysis_method, minimum, headline)
RULES = [
 ("cert_expired","Expired TLS certificate","An SSL/TLS certificate in the target's footprint has expired.","MEDIUM","host",
  [("has_value","type","SSL_CERTIFICATE_EXPIRED")],None,"threshold",1,"Expired TLS certificate: {data}"),
 ("cloud_bucket_open","Open cloud storage bucket","A publicly accessible cloud storage bucket was found.","HIGH","domain",
  [("has_value","type","CLOUD_STORAGE_BUCKET_OPEN")],None,"threshold",1,"Publicly accessible cloud bucket: {data}"),
 ("cloud_bucket_open_related","Open bucket on related org","An open cloud bucket on an affiliate / related org.","HIGH","network",
  [("has_value","type","CLOUD_STORAGE_BUCKET_OPEN")],"data","threshold",1,"Open bucket on related org: {data}"),
 ("data_from_base64","Sensitive data in base64","Base64-encoded data discovered that may hide secrets.","LOW","host",
  [("regex","data","[A-Za-z0-9+/]{40,}={0,2}")],None,"threshold",1,"Possible base64-encoded data: {data}"),
 ("data_from_docmeta","Data in document metadata","Hostnames / PII extracted from document metadata.","LOW","host",
  [("has_value","type","RAW_FILE_META_DATA")],None,"threshold",1,"Data extracted from document metadata"),
 ("database_exposed","Internet-exposed database","A database service is reachable from the internet.","HIGH","host",
  [("regex","data",":(3306|5432|27017|6379|9200|5984|11211|1433|9300)$")],None,"threshold",1,"Exposed database service: {data}"),
 ("dev_or_test_system","Dev/test system in DNS","A development / staging / test host is indexed in DNS.","MEDIUM","host",
  [("regex","data","(?i)(^|\\.)(dev|test|staging|uat|qa|sandbox|demo)\\.")],None,"threshold",1,"Dev/test system exposed: {data}"),
 ("dns_zone_transfer_possible","DNS zone transfer possible","A nameserver allows AXFR zone transfers.","HIGH","domain",
  [("exact","module","sfp_dnszonexfer")],None,"threshold",1,"Zone transfer possible: {data}"),
 ("egress_ip_from_wikipedia","Egress IP in Wikipedia history","A corporate egress IP appears in Wikipedia edit history.","LOW","network",
  [("exact","type","IP_ADDRESS"),("exact","module","sfp_wikipedia")],None,"threshold",1,"Egress IP in Wikipedia edits: {data}"),
 ("email_in_multiple_breaches","Email in multiple breaches","An email address appears in two or more breaches.","MEDIUM","host",
  [("exact","type","EMAILADDR_COMPROMISED")],"data","threshold",2,"Email in multiple breaches: {data}"),
 ("email_in_whois","Personal email in WHOIS","A personal email address leaked via WHOIS records.","MEDIUM","domain",
  [("exact","type","EMAILADDR"),("in_list","module","sfp_whois,sfp_whoxy,sfp_jsonwhois,sfp_whoisology")],None,"threshold",1,"Email leaked via WHOIS: {data}"),
 ("email_only_from_pasteleak_site","Email only from paste/leak site","An email seen only on a paste/leak source.","LOW","host",
  [("exact","type","EMAILADDR"),("in_list","module","sfp_pastebin,sfp_psbdmp")],None,"threshold",1,"Email only from paste site: {data}"),
 ("host_only_from_bruteforce","Host only from brute force","A host found only via subdomain brute force.","INFO","domain",
  [("exact","type","INTERNET_NAME"),("in_list","module","sfp_dnsbrute,sfp_dnscommonsrv,sfp_subdomain_brute")],None,"threshold",1,"Host only found via brute force: {data}"),
 ("host_only_from_certificatetransparency","Host only from CT logs","A host present only in CT logs.","INFO","domain",
  [("exact","type","INTERNET_NAME"),("in_list","module","sfp_crtsh,sfp_certspotter,sfp_certtransparency")],None,"threshold",1,"Host only from CT logs: {data}"),
 ("http_errors","Cluster of HTTP 5xx errors","An unusual number of HTTP 5xx responses.","LOW","host",
  [("regex","data","^5\\d\\d$")],None,"threshold",3,"Cluster of HTTP server errors"),
 ("human_name_in_whois","Personal name in WHOIS","A personal name leaked via WHOIS records.","MEDIUM","domain",
  [("exact","type","HUMAN_NAME"),("in_list","module","sfp_whois,sfp_whoxy,sfp_jsonwhois")],None,"threshold",1,"Name leaked via WHOIS: {data}"),
 ("internal_host","Internal hostname exposed","An internal-only hostname is exposed externally.","MEDIUM","host",
  [("regex","data","(?i)(^|\\.)(internal|intranet|corp|local|priv)\\.")],None,"threshold",1,"Internal hostname exposed: {data}"),
 ("multiple_malicious","Host flagged by multiple sources","An IP flagged malicious by 2+ threat-intel sources.","HIGH","host",
  [("exact","type","MALICIOUS_IPADDR")],"data","threshold",2,"IP flagged by multiple TI sources: {data}"),
 ("multiple_malicious_affiliate","Affiliate flagged by multiple sources","An affiliate flagged by 2+ TI sources.","MEDIUM","network",
  [("exact","type","MALICIOUS_AFFILIATE_INTERNET_NAME")],"data","threshold",2,"Affiliate flagged by multiple TI sources: {data}"),
 ("multiple_malicious_cohost","Co-host flagged by multiple sources","A co-hosted site flagged by 2+ TI sources.","MEDIUM","network",
  [("exact","type","MALICIOUS_COHOST")],"data","threshold",2,"Co-host flagged by multiple TI sources: {data}"),
 ("name_only_from_pasteleak_site","Name only from paste/leak site","A name seen only on a paste/leak source.","LOW","host",
  [("exact","type","HUMAN_NAME"),("exact","module","sfp_pastebin")],None,"threshold",1,"Name only from paste site: {data}"),
 ("open_port_version","Service banner reveals version","An open port banner discloses a software version.","MEDIUM","host",
  [("exact","type","TCP_PORT_OPEN_BANNER"),("regex","data","\\d+\\.\\d+")],None,"threshold",1,"Service banner discloses version: {data}"),
 ("outlier_cloud","Cloud provider outlier","A cloud provider outlier in the target footprint.","INFO","network",
  [("has_value","type","CLOUD_STORAGE_BUCKET")],"data","outlier",1,"Cloud provider outlier: {data}"),
 ("outlier_country","Geographic outlier","A geographic outlier in the target footprint.","INFO","network",
  [("exact","type","COUNTRY_NAME")],"data","outlier",1,"Geographic outlier: {data}"),
 ("outlier_email","Atypical email pattern","An atypical email pattern relative to the org baseline.","INFO","domain",
  [("exact","type","EMAILADDR")],"data","outlier",1,"Atypical email pattern: {data}"),
 ("outlier_hostname","Anomalous hostname","A hostname anomalous to the naming convention.","INFO","domain",
  [("exact","type","INTERNET_NAME")],"data","outlier",1,"Anomalous hostname: {data}"),
 ("outlier_ipaddress","IP outside normal blocks","An IP outside the normal allocation blocks.","INFO","network",
  [("exact","type","IP_ADDRESS")],"data","outlier",1,"IP outside normal blocks: {data}"),
 ("outlier_registrar","Unusual registrar","A domain with an unusual registrar vs siblings.","INFO","domain",
  [("exact","type","DOMAIN_REGISTRAR")],"data","outlier",1,"Unusual registrar: {data}"),
 ("outlier_webserver","Rare webserver header","A rare webserver header amid common ones.","INFO","host",
  [("exact","type","WEBSERVER_BANNER")],"data","outlier",1,"Rare webserver header: {data}"),
 ("remote_desktop_exposed","Remote desktop exposed","RDP / VNC / SSH is publicly reachable.","HIGH","host",
  [("regex","data",":(3389|5900|5901|22|23)$")],None,"threshold",1,"Remote access service exposed: {data}"),
 ("root_path_needs_auth","Root path requires auth","A site root requires authentication (forgotten panel).","LOW","host",
  [("exact","type","HTTP_CODE"),("in_list","data","401,403")],None,"threshold",1,"Root path requires auth (HTTP {data})"),
 ("stale_host","Stale / abandoned host","A host with abandoned or outdated signals.","LOW","host",
  [("exact","type","INTERNET_NAME"),("exact","module","sfp_waybackarchive")],None,"threshold",1,"Stale host signal: {data}"),
 ("strong_affiliate_certs","Strong affiliate cert linkage","Strong certificate linkage between target and affiliate.","INFO","network",
  [("exact","type","AFFILIATE_INTERNET_NAME"),("in_list","module","sfp_crtsh,sfp_certspotter")],None,"threshold",1,"Cert linkage to affiliate: {data}"),
 ("strong_similardomain_crossref","Similar domain cross-references infra","A similar-looking domain cross-refs target infra.","LOW","domain",
  [("has_value","type","SIMILARDOMAIN")],None,"threshold",1,"Similar domain cross-referencing infra: {data}"),
 ("vulnerability_critical","Critical vulnerability","A critical-severity vulnerability was found.","CRITICAL","host",
  [("has_value","type","VULNERABILITY_CVE_CRITICAL")],None,"threshold",1,"Critical vulnerability: {data}"),
 ("vulnerability_high","High vulnerability","A high-severity vulnerability was found.","HIGH","host",
  [("has_value","type","VULNERABILITY_CVE_HIGH")],None,"threshold",1,"High vulnerability: {data}"),
 ("vulnerability_mediumlow","Medium/Low vulnerabilities","Aggregated medium/low-severity vulnerabilities.","MEDIUM","host",
  [("regex","type","VULNERABILITY_CVE_(MEDIUM|LOW)")],"data","threshold",1,"Medium/Low vulnerability: {data}"),
]


def emit(rule):
    rid, name, desc, risk, scope, collects, agg, method, minimum, headline = rule
    lines = [
        f"id: {rid}",
        "version: 1",
        "meta:",
        f'  name: "{name}"',
        f'  description: "{desc}"',
        f"  risk: {risk}",
        f"  scope: {scope}",
        '  author: "lancer-spiderfoot"',
        "collections:",
        "  - collect:",
    ]
    for (m, f, v) in collects:
        lines.append(f"      - method: {m}")
        lines.append(f"        field: {f}")
        lines.append(f"        value: '{v}'")
    if agg:
        lines += ["aggregation:", f"  field: {agg}"]
    lines += ["analysis:", f"  - method: {method}", f"    minimum: {minimum}"]
    lines.append(f'headline: "{headline}"')
    return "\n".join(lines) + "\n"


for rule in RULES:
    with open(os.path.join(OUT, f"{rule[0]}.yaml"), "w", encoding="utf-8") as fh:
        fh.write(emit(rule))

print(f"wrote {len(RULES)} correlation rules to {OUT}")
ids = [r[0] for r in RULES]
assert len(ids) == len(set(ids)), "duplicate rule id"
assert len(RULES) == 37, f"expected 37, got {len(RULES)}"
