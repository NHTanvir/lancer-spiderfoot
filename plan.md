# RESEARCH DOSSIER: SpiderFoot

> Part of the Lancer ecosystem. A Rust clone of Steve Micallef's SpiderFoot — automated OSINT reconnaissance with 200+ data sources, event-driven correlation, and entity graph output. Build with Claude Code.
> Upstream: github.com/smicallef/spiderfoot (Python, MIT, 4.0.x → 4.x dev as of May 2026, 13k+ stars, 230+ modules)

## Feature Parity Mandate

**`lancer-spiderfoot` MUST ship with 100% feature parity to the upstream `spiderfoot` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `spiderfoot --help` (and the long-form man page / docs) must work in `lancer-spiderfoot --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-spiderfoot` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-spiderfoot --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

SpiderFoot is the canonical **automated OSINT reconnaissance platform**. Point it at a `target` (domain, IP, subnet, email address, phone number, username, Bitcoin address, ASN, person's name, bank account number, etc.) and it fans out across **200+ external data sources** — DNS lookups, WHOIS, Certificate Transparency logs (crt.sh, Censys, Google CT), Shodan, Have I Been Pwned, HackerTarget, Spyse, BinaryEdge, AlienVault OTX, ThreatCrowd, VirusTotal, GreyNoise, Hunter.io, SecurityTrails, Pulsedive, RiskIQ, AbuseIPDB, SpyOnWeb, RobtexDNS, FullContact, Pipl, Snusbase, Dehashed, IntelX, GitHub, Pastebin scrapers — and correlates the findings into a typed event graph. Every discovered datum (a subdomain, an email, a leaked credential, a CIDR, a cert SAN) is an **event** with a type from a 100+-entry taxonomy, and modules subscribe to event types they consume and emit event types they produce.

It runs as either: (a) a **web UI server** (the canonical mode — `python sf.py -l 127.0.0.1:5001` opens a Tornado-served dashboard with scan history, live event feed, entity graph viz, settings, correlation-rule editor), (b) a **CLI scanner** (`python sf.py -s acme.com -t IP_ADDRESS,EMAILADDR -o json`), or (c) a **REST API** (the same Tornado server exposes `/api/*` endpoints for programmatic scan launch + result polling). The differentiator vs subfinder/amass: SpiderFoot is **multi-entity** (not just subdomains — emails, breaches, leaks, phone numbers, crypto addresses, social handles, dark-web mentions) and **correlation-aware** (cross-event rules like "if a subdomain has an open S3 bucket AND the bucket name matches a leaked AWS key from HIBP, raise a CORRELATION_RISK event"). Outputs to CSV / JSON / GEXF (Gephi graph viz) / SQLite.

## Internal architecture

**Workspace** (`Cargo.toml`):
```
[workspace]
members = ["lancer-spiderfoot", "sf-core", "sf-modules", "sf-graph", "sf-web"]
```

- **`lancer-spiderfoot`** — CLI binary (clap 4.5). Parses args, picks UI/CLI/API mode, calls `sf-core`. Provides `-s target`, `-t types`, `-m modules`, `-T types-only`, `-l listen-addr`, `-o output-format`, `-q quiet`.
- **`sf-core`** — Orchestration engine: event bus, scan state machine, module loader, target validator, persistence layer (SQLite), correlation rule engine, config merging from `~/.config/spiderfoot/sf.cfg`.
- **`sf-modules`** — The 200+ source modules. Each is a Rust struct implementing the `Module` trait, declaring which event types it consumes (`watched_events`) and produces (`produced_events`). One module per file in `sf-modules/src/modules/<name>.rs`.
- **`sf-graph`** — Entity correlation engine: petgraph-backed event graph, correlation rule evaluator (YAML rules over event tuples), graph-export (GEXF/GraphML/JSON).
- **`sf-web`** — Web UI + REST API: `axum` server, `askama` templates for HTML, `tower-http` for static assets, SSE-streamed live event feed, sigma.js/vis.js front-end for graph viz.

**Key modules in `sf-core/src/`:**
- `target.rs` — `Target { value: String, type_: TargetType }`. `TargetType` enum: `DomainName`, `IpAddress`, `NetBlock`, `EmailAddress`, `PhoneNumber`, `HumanName`, `Username`, `BitcoinAddress`, `Asn`, `Iban`, `BankAccountNumber`. Validation regex per type at construct time.
- `event.rs` — `SfEvent { type_: EventType, data: String, module: String, source_event: Option<EventId>, confidence: u8, visibility: u8, risk: RiskLevel, generated_at: DateTime<Utc>, hash: u64 }`. `EventType` is a 100+-variant enum (see catalog below).
- `module.rs` — The `Module` trait:
```rust
#[async_trait]
pub trait Module: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn descr(&self) -> &'static str;
    fn categories(&self) -> &'static [Category]; // Passive, Footprint, Investigate, Active
    fn flags(&self) -> &'static [ModuleFlag];    // ApiKey, ToolExec, Slow, Errorprone, Invasive
    fn watched_events(&self) -> &'static [EventType];
    fn produced_events(&self) -> &'static [EventType];
    fn opts(&self) -> Vec<ModuleOpt>;
    async fn handle_event(&self, evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>>;
    async fn setup(&self, opts: &HashMap<String, String>, ctx: &ScanContext) -> Result<()>;
    fn finished(&self) {}  // called when scan completes
}
```
- `bus.rs` — Async event bus (`tokio::sync::broadcast` + `tokio::sync::mpsc`). On every emitted event, dispatcher looks up subscribed modules from a `HashMap<EventType, Vec<Arc<dyn Module>>>` index, fans out via `JoinSet`. Backpressure via bounded channels (default 1024 events buffered per consumer). Deduplication via `DashMap<EventHash, ()>` — duplicate-event hash check before fan-out.
- `scan.rs` — `Scan { id: Uuid, target: Target, modules: Vec<String>, started_at: DateTime, status: ScanStatus, event_count: u64, error_count: u64 }`. State machine: `Created → Starting → Running → Finished | Aborted | Failed`. Heartbeat into SQLite every 5s.
- `correlate.rs` — Loads `correlations/*.yaml` rules; each rule is a tuple-pattern: `match: { type1: SUBDOMAIN, type2: HTTP_RESPONSE_BODY, predicate: "contains:s3.amazonaws.com" }` → emit `CORRELATION_RISK` event linked to both.
- `persist.rs` — `sqlx` SQLite store: tables `tbl_scan`, `tbl_scan_log`, `tbl_scan_config`, `tbl_scan_results`, `tbl_event_types`. WAL mode. Per-scan SQLite file under `~/.local/share/spiderfoot/scans/<scan-id>.db` (matches upstream layout).
- `apikeys.rs` — Global API key store + per-module key requirement check. Keys via env (`SPIDERFOOT_<MODULE>_API_KEY=...`), config file, or web-UI Settings panel. Rotation logic for sources accepting multiple keys (GitHub, Shodan-paid).
- `ratelimit.rs` — Per-source `governor` rate limiter map. Defaults derived from upstream (HIBP: 1.5s between calls free tier; Shodan: 1/s; VirusTotal: 4/min free; HackerTarget: 2/s).

**Key modules in `sf-modules/src/modules/`** (each file = one source/module):
- `sfp_dnsresolve.rs` — DNS A/AAAA/MX/NS/TXT resolution.
- `sfp_whois.rs` — WHOIS for domains + IPs.
- `sfp_crtsh.rs` — Certificate Transparency search.
- `sfp_shodan.rs` — Shodan host/dns search.
- `sfp_haveibeenpwned.rs` — HIBP breach lookup for email.
- `sfp_hackertarget.rs` — HackerTarget reverse-DNS/hostsearch.
- `sfp_virustotal.rs` — VT domain/IP/URL/hash report.
- `sfp_alienvault.rs` — AlienVault OTX indicator lookup.
- `sfp_censys.rs` — Censys Platform v3 cert + host search.
- `sfp_binaryedge.rs` — BinaryEdge subdomain/host enrichment.
- `sfp_github.rs` — GitHub code search for target strings.
- `sfp_pastebin.rs` — Pastebin scraper + Google CSE fallback.
- `sfp_s3bucket.rs` — Amazon S3 bucket name enumeration + ACL probe.
- `sfp_azureblob.rs` — Azure blob container enumeration.
- `sfp_gcs.rs` — Google Cloud Storage bucket discovery.
- `sfp_dehashed.rs` — Dehashed breach DB.
- `sfp_intelx.rs` — IntelligenceX phonebook + leaks.
- `sfp_emailrep.rs` — EmailRep.io reputation.
- `sfp_hunter.rs` — Hunter.io email discovery for domains.
- (~200 more — see catalog)

**Storage / internal modules (upstream prefix `sfp__`):**
- `sfp__stor_db.rs` — primary SQLite event sink (always-on internal module).
- `sfp__stor_stdout.rs` — stdout/tab/csv/json streaming sink for CLI mode.

**External tool integration modules (upstream wires `subprocess` shellouts; we wire `tokio::process::Command`):**
- `sfp_tool_dnstwist.rs` — bit-squatting / typosquat domain discovery via local `dnstwist`.
- `sfp_tool_nmap.rs` — port scan + OS fingerprint via local `nmap` (XML output parsed back to events).
- `sfp_tool_whatweb.rs` — web technology fingerprint via local `whatweb`.
- `sfp_tool_cmseek.rs` — CMS detection + version + plugin/theme enumeration via local `cmseek`.
- `sfp_tool_nuclei.rs` — template-based vulnerability scanner via local `nuclei` (JSON output parsed → `VULNERABILITY_CVE_*`).
- `sfp_tool_retire.rs` — JS library CVE check via `retire.js` (optional).
- `sfp_tool_wafw00f.rs` — WAF detection via `wafw00f`.
- `sfp_tool_testssl.rs` — TLS config grading via `testssl.sh` (optional).
- `sfp_tool_trufflehog.rs` — secret scanner over found `GITHUB_REPO_CONTENT` (optional).
- All tool modules carry `ModuleFlag::ToolExec` and gracefully no-op if the external binary is missing on `$PATH`.

**Event dispatch flow (the core loop):**
1. Scan starts with `Target { value: "acme.com", type_: DomainName }`. The orchestrator emits a `ROOT` event with that target value as `data`.
2. Bus dispatcher reads `ROOT` from the broadcast channel; looks up all modules whose `watched_events()` contains `EventType::Root` — typically `sfp_dnsresolve`, `sfp_whois`, `sfp_crtsh`, `sfp_shodan`, etc.
3. Each module's `handle_event(evt, ctx)` runs in its own `JoinSet` task, makes API calls, emits zero-or-more downstream events (e.g., `DOMAIN_NAME`, `IP_ADDRESS`, `INTERNET_NAME`, `RAW_DNS_RECORDS`).
4. Each emitted event is hashed; dedupe set checked; if new, broadcast back on the bus. Goes to step 2 for the new type. The graph builds organically.
5. When the broadcast channel sits idle for `idle_timeout` (default 30s) AND no module is producing, orchestrator declares the scan `Finished`.
6. Correlation engine runs over the final event set, emits `CORRELATION_RISK` events for each rule that fires.

## Granular feature catalog

**CLI:** `lancer-spiderfoot [target]` plus flags — `-s <target>`, `-t <event-types>`, `-m <module-list>`, `-T <type-only-list>`, `-M` (list modules), `-l <ip:port>` (web UI), `-o <csv|json|gexf|xlsx>`, `-q` (quiet), `-x` (strict mode — only emit declared types), `-r` (recurse subdomains), `-X` (no recursion), `--max-threads N`, `--max-events N`, `--correlations <yaml-dir>`.

**Upstream `sf.py` CLI flags to match exactly (parity contract):**
- `-s TARGET` — scan target
- `-m mod1,mod2,...` — enable specific modules
- `-t type1,type2,...` — event types to collect
- `-u {all|footprint|investigate|passive}` — select modules by use-case profile
- `-o {tab|csv|json}` — output format (upstream default is `tab`; we additionally support `gexf|xlsx|html` per § Report formats)
- `-H` — suppress field headers in output
- `-n` — strip newlines from data
- `-r` — **upstream meaning:** include source-data field in tab/csv output (NOT "recurse" — clarify: our `--recurse` becomes the long form for subdomain recursion; `-r` matches upstream "include source data" semantics).
- `-S LENGTH` — limit max data display length
- `-D DELIMITER` — custom CSV delimiter
- `-F type1,type2,...` — show only specified event types
- `-M` / `--modules` — list available modules
- `-T` / `--types` — list available event types
- `-l IP:port` — listen address for web server mode
- `-C scanID` — run correlation rules against an existing finished scan ID
- `-d` / `--debug` — enable debug output
- `-q` — disable logging
- `-x` — strict mode (only modules consuming declared target type)
- `-f` — filter out unspecified event types
- `--max-threads N` — concurrent module count
- `-V` / `--version` — version info

**Config (`~/.config/spiderfoot/sf.cfg`):**
```toml
[global]
_dnsserver = "8.8.8.8"
_fetchtimeout = 30
_socks_proxy = "socks5://127.0.0.1:9050"
_useragent = "Mozilla/5.0 ..."
_genericusers = ["admin", "root", "info", "support"]

[modules.sfp_shodan]
api_key = "abc..."

[modules.sfp_haveibeenpwned]
api_key = "def..."
delay_secs = 1.5

[modules.sfp_github]
api_keys = ["tok1", "tok2", "tok3"]  # rotation pool
```

**Target types (11):**
1. `DOMAIN_NAME` — `acme.com`
2. `IP_ADDRESS` — `1.2.3.4`
3. `NETBLOCK` — `1.2.3.0/24` (CIDR)
4. `EMAILADDR` — `alice@acme.com`
5. `PHONE_NUMBER` — `+15551234567` (E.164)
6. `HUMAN_NAME` — `"Alice Smith"`
7. `USERNAME` — `alice42`
8. `BITCOIN_ADDRESS` — `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
9. `ASN` — `AS15169`
10. `IBAN_NUMBER` — `GB82WEST12345698765432`
11. `BANK_ACCOUNT_NUM` — generic account number

**Event types (100+ from upstream's `dbinit.sql`):**
- Identity-class: `EMAILADDR`, `EMAILADDR_GENERIC`, `EMAILADDR_DISPOSABLE`, `EMAILADDR_COMPROMISED`, `USERNAME`, `HUMAN_NAME`, `PHONE_NUMBER`, `PHONE_NUMBER_COMPROMISED`.
- Network-class: `DOMAIN_NAME`, `INTERNET_NAME`, `INTERNET_NAME_UNRESOLVED`, `IP_ADDRESS`, `IPV6_ADDRESS`, `NETBLOCK`, `NETBLOCK_MEMBER`, `BGP_AS_OWNER`, `BGP_AS_MEMBER`, `BGP_AS_PEER`.
- DNS-class: `RAW_DNS_RECORDS`, `DNS_TEXT`, `DNS_SPF`, `DNS_FOR_TARGET`, `PROVIDER_DNS`, `PROVIDER_MAIL`, `PROVIDER_HOSTING`.
- Web-class: `URL_WEB_FRAMEWORK`, `URL_JAVASCRIPT`, `URL_FORM`, `URL_UPLOAD`, `URL_STATIC`, `URL_PASSWORD_LOGIN`, `URL_ADBLOCKED_EXTERNAL`, `LINKED_URL_INTERNAL`, `LINKED_URL_EXTERNAL`, `HTTP_CODE`, `WEBSERVER_BANNER`, `WEBSERVER_HTTPHEADERS`, `WEBSERVER_TECHNOLOGY`, `WEBAPPSEC_HEADER_MISSING`.
- Certs/crypto: `SSL_CERTIFICATE_RAW`, `SSL_CERTIFICATE_ISSUED`, `SSL_CERTIFICATE_ISSUER`, `SSL_CERTIFICATE_EXPIRING`, `SSL_CERTIFICATE_EXPIRED`, `SSL_CERTIFICATE_MISMATCH`, `BITCOIN_ADDRESS`, `BITCOIN_BALANCE`, `ETHEREUM_ADDRESS`.
- Breaches/leaks: `LEAKSITE_URL`, `LEAKSITE_CONTENT`, `PASSWORD_COMPROMISED`, `HASH_COMPROMISED`, `BREACHED_DATA`, `DARKNET_MENTION_URL`, `DARKNET_MENTION_CONTENT`, `MALICIOUS_IPADDR`, `MALICIOUS_INTERNET_NAME`, `MALICIOUS_EMAILADDR`.
- Geo: `GEOINFO`, `PHYSICAL_ADDRESS`, `PHYSICAL_COORDINATES`, `COUNTRY_NAME`.
- Storage/cloud: `CLOUD_STORAGE_BUCKET`, `CLOUD_STORAGE_BUCKET_OPEN`, `S3_BUCKET`, `S3_BUCKET_OPEN`, `AZURE_BLOB`, `GCS_BUCKET`.
- Misc: `RAW_RIR_DATA`, `RAW_FILE_META_DATA`, `SOFTWARE_USED`, `OPERATING_SYSTEM`, `DEFACED_INTERNET_NAME`, `TARGET_WEB_CONTENT`, `TCP_PORT_OPEN`, `TCP_PORT_OPEN_BANNER`, `UDP_PORT_OPEN`, `VULNERABILITY_GENERAL`, `VULNERABILITY_CVE_CRITICAL`, `VULNERABILITY_CVE_HIGH`, `VULNERABILITY_CVE_MEDIUM`, `VULNERABILITY_CVE_LOW`.
- Meta: `ROOT`, `ERROR_MESSAGE`, `CORRELATION_RISK`, `SEARCH_ENGINE_WEB_CONTENT`.

**Module categories (4):**
- **Passive** — never touches target (only third-party APIs / public data). The default safe set.
- **Footprint** — passive + queries-the-target's-public-surface (DNS, HTTP HEAD, robots.txt) without authenticated/probing behavior.
- **Investigate** — passive + targeted queries about *one specific entity* (e.g., enrich one IP via Shodan).
- **Active** — sends requests to the target that go beyond passive HTTP (port scans, S3 bucket ACL probes, brute subdomain wordlists). Off-by-default.

**Module flags (5):**
- `ApiKey` — module needs a vendor API key to function (filtered out if no key configured).
- `ToolExec` — calls an external binary (nmap, masscan, whois). Off when binary missing.
- `Slow` — average runtime >30s per event.
- `Errorprone` — known-flaky source; auto-disable after N consecutive failures.
- `Invasive` — touches target with non-passive traffic.

**Scan policies (named module-sets):**
- `all` — every registered module respecting flags.
- `passive` — only `Passive` category.
- `footprint` — `Passive` + `Footprint`.
- `investigate` — `Passive` + `Footprint` + `Investigate`.
- `custom` — comma-list of module names.
- Policies are user-extensible via YAML in `~/.config/spiderfoot/policies/`.

**Modules-by-tag/category mapping:**
- `passive`: ~140 modules (HIBP, Shodan-noscan, VirusTotal-noscan, GreyNoise, Censys-cert, IntelX, Dehashed, OTX, RiskIQ, Pulsedive, etc.).
- `footprint`: ~30 modules (DNS resolve, robots.txt, sitemap.xml, security.txt, .well-known, http banner).
- `investigate`: ~25 modules (enrich-one-IP via Shodan paid, enrich-one-email via FullContact).
- `active`: ~15 modules (port scan via nmap shellout, S3 bucket-name guessing, subdomain brute-force, GCS-bucket probing).

**Per-module API key config:** Settings page lists every module flagged `ApiKey`, surfaces "Get a key at <link>" link, accepts plaintext or env-var-ref. Stored AES-encrypted at rest if user sets a master password.

**Full 200+ module catalog to port (parity contract — alphabetical for clarity, grouped where natural):**

- **Storage/internal:** `sfp__stor_db`, `sfp__stor_stdout`.
- **Threat-intel / IP-rep:** `sfp_abstractapi`, `sfp_abusech`, `sfp_abuseipdb`, `sfp_alienvault`, `sfp_apility`, `sfp_badpackets`, `sfp_blocklistde`, `sfp_botscout`, `sfp_botvrij`, `sfp_cleantalk`, `sfp_comodo`, `sfp_crobat`, `sfp_cybercrime_tracker`, `sfp_darkbit`, `sfp_dnsdb`, `sfp_emergingthreats`, `sfp_fortinet`, `sfp_fraudguard`, `sfp_greensnow`, `sfp_greynoise`, `sfp_hybrid_analysis`, `sfp_ipinfodb`, `sfp_ipqualityscore`, `sfp_iptoasn`, `sfp_ipwhois`, `sfp_jsonwhois`, `sfp_malwarebazaar`, `sfp_maltiverse`, `sfp_minc`, `sfp_misp`, `sfp_nessus_essentials`, `sfp_openbugbounty`, `sfp_otx`, `sfp_phishstats`, `sfp_phishtank`, `sfp_psbdmp`, `sfp_pulsedive`, `sfp_quad9`, `sfp_recondev`, `sfp_riskiq`, `sfp_robtex`, `sfp_securitytrails`, `sfp_shodan`, `sfp_spamhaus`, `sfp_spamcop`, `sfp_spur`, `sfp_spyonweb`, `sfp_spyse`, `sfp_stopforumspam`, `sfp_talosintel`, `sfp_threatcrowd`, `sfp_threatfox`, `sfp_threatminer`, `sfp_trashpanda`, `sfp_uceprotect`, `sfp_urlhaus`, `sfp_urlscan`, `sfp_virustotal`, `sfp_voipbl`, `sfp_vxvault`, `sfp_whoisology`, `sfp_xforce`, `sfp_zetalytics`, `sfp_zoomeye`.
- **DNS / subdomain / infrastructure:** `sfp_accounts`, `sfp_arin`, `sfp_bgpview`, `sfp_binaryedge`, `sfp_c99`, `sfp_callername`, `sfp_certspotter`, `sfp_chaos`, `sfp_circl`, `sfp_citadel`, `sfp_cloudflare`, `sfp_commoncrawl`, `sfp_crossref`, `sfp_crt`, `sfp_dnsbrute`, `sfp_dnscommonsrv`, `sfp_dnsdumpster`, `sfp_dnsgrep`, `sfp_dnsneutral`, `sfp_dnsraw`, `sfp_dnsresolve`, `sfp_dnstwist` (tool), `sfp_dnszonexfer`, `sfp_dronebl`, `sfp_email`, `sfp_emailcrawlr`, `sfp_emailformat`, `sfp_fofa`, `sfp_fullhunt`, `sfp_grayhatwarfare`, `sfp_hackertarget`, `sfp_haveibeenpwned`, `sfp_hunter`, `sfp_iknowwhatyoudownload`, `sfp_internetdb`, `sfp_intelx`, `sfp_ipdata`, `sfp_ipinfo`, `sfp_ipregistry`, `sfp_ipstack`, `sfp_keybase` (deprecated), `sfp_leakix`, `sfp_leakcheck`, `sfp_leak_lookup`, `sfp_maxmind`, `sfp_merklemap` (new 2026), `sfp_mnemonic`, `sfp_neutrinoapi`, `sfp_numverify`, `sfp_onyphe`, `sfp_pageinfo`, `sfp_passivetotal`, `sfp_pgp`, `sfp_pulse`, `sfp_quake`, `sfp_recondev`, `sfp_recon_wave`, `sfp_ripe`, `sfp_robotstxt`, `sfp_securitytxt`, `sfp_sitedossier`, `sfp_skymem`, `sfp_snusbase`, `sfp_spider`, `sfp_subdomaincenter`, `sfp_subdomainwhitelist`, `sfp_threatjammer`, `sfp_tldsearch`, `sfp_torch`, `sfp_torexits`, `sfp_twilio`, `sfp_urlhaus`, `sfp_viewdns`, `sfp_whoxy`, `sfp_zoomeye`.
- **Web / footprint:** `sfp_archiveorg`, `sfp_base64`, `sfp_bingsearch`, `sfp_builtwith`, `sfp_clearbit`, `sfp_cookie`, `sfp_creditcard`, `sfp_duckduckgo`, `sfp_errors`, `sfp_filemeta`, `sfp_flickr`, `sfp_google`, `sfp_google_tag_manager`, `sfp_googlemaps`, `sfp_googleobjectstorage`, `sfp_googlesearch`, `sfp_hashes`, `sfp_iban`, `sfp_junkfiles`, `sfp_metadefender`, `sfp_pageinfo`, `sfp_pastebin`, `sfp_pgp`, `sfp_phone`, `sfp_psbdmp`, `sfp_robotstxt`, `sfp_securityheaders`, `sfp_securitytxt`, `sfp_sitemap`, `sfp_socialmediahyperlinks`, `sfp_spider`, `sfp_strangeheaders`, `sfp_subdomain_takeover`, `sfp_tags`, `sfp_tldsearch`, `sfp_tool_whatweb`, `sfp_tool_cmseek`, `sfp_tool_nuclei`, `sfp_torch`, `sfp_validatewebsite`, `sfp_wappalyzer`, `sfp_waybackarchive`, `sfp_webanalytics`, `sfp_webcrawl`, `sfp_webframework`, `sfp_wikileaks`, `sfp_wikipedia`, `sfp_yandex_csv`.
- **Email / identity / social:** `sfp_accounts`, `sfp_clearbit`, `sfp_email`, `sfp_emailcrawlr`, `sfp_emailformat`, `sfp_emailrep`, `sfp_emailhippo`, `sfp_fullcontact`, `sfp_gravatar`, `sfp_haveibeenpwned`, `sfp_hunter`, `sfp_namechk`, `sfp_pipl`, `sfp_riskiq`, `sfp_sherlock`-style (Sherlock username matrix across ~300 sites), `sfp_skymem`, `sfp_snusbase`, `sfp_socialprofiles`, `sfp_spur`, `sfp_thatsthem`.
- **Cloud storage:** `sfp_amazon_aws`, `sfp_azureblobstorage`, `sfp_digitaloceanspace`, `sfp_googleobjectstorage`, `sfp_grayhatwarfare`, `sfp_s3bucket`.
- **Blockchain / crypto:** `sfp_bitcoin`, `sfp_bitcoinabuse`, `sfp_bitcoinwhoswho`, `sfp_blockchain`, `sfp_blockchain_info`, `sfp_ethereum`, `sfp_etherscan`.
- **Dark web / paste:** `sfp_darknet`, `sfp_pastebin`, `sfp_psbdmp`, `sfp_torch`, `sfp_torexits`, `sfp_trashpanda`, `sfp_wikileaks`.
- **Active / invasive:** `sfp_dnsbrute`, `sfp_dnszonexfer`, `sfp_open_passive`, `sfp_portscan_basic`, `sfp_portscan_tcp`, `sfp_s3bucket`, `sfp_subdomain_takeover`, `sfp_tool_nmap`, `sfp_tool_nuclei`, `sfp_tool_wafw00f`, `sfp_tool_testssl`.
- **AI augmentation (Lancer net-new + community 2025-2026):** `sfp_ai_summarizer`, `sfp_ai_risk_classifier`, `sfp_ai_persona_inference`, `sfp_ai_policy_generator`.

This is the parity floor — every upstream module file in `modules/` must produce an `sfp_*.rs` here, marked `[N/A — see note]` only if genuinely impossible in Rust (none expected to qualify).

**Scan history:** Web UI shows past scans in a sortable table (`scan id, target, started, finished, event count, status, modules used`). Each row clickable → live event feed + entity graph + per-module log + correlation findings.

**Correlation rules:** Each rule is a YAML file in `correlations/`:
```yaml
id: github_token_leak_for_target
name: "GitHub personal access token in repo for target"
risk: HIGH
match:
  - type: GITHUB_REPO_CONTENT
    contains: "ghp_"
  - type: EMAILADDR
    same_root_as_event_1: true
description: "A ghp_-prefixed GitHub PAT appears in a repo associated with our target's email domain — likely live."
fix: "Rotate the token and audit repo for further secrets."
```
Engine evaluates rules over the post-scan event set; rules can JOIN events by predicates (`same_root_as_event_1`, `same_ip_as_event_2`, `text_contains_value_of_event_3`). Emits `CORRELATION_RISK` events.

**Upstream ships 37 seed correlation rules — every one must be ported to YAML in our `correlations/` dir (parity contract):**

| YAML | What it detects |
|---|---|
| `cert_expired.yaml` | Expired SSL/TLS certificates |
| `cloud_bucket_open.yaml` | Publicly accessible cloud storage buckets |
| `cloud_bucket_open_related.yaml` | Open buckets on affiliate/related orgs |
| `data_from_base64.yaml` | Sensitive data encoded in base64 strings |
| `data_from_docmeta.yaml` | PII / hostnames extracted from document metadata |
| `database_exposed.yaml` | Databases (MongoDB/Redis/ES/etc.) accessible on the internet |
| `dev_or_test_system.yaml` | Dev / staging / test systems indexed in DNS |
| `dns_zone_transfer_possible.yaml` | AXFR-vulnerable nameservers |
| `egress_ip_from_wikipedia.yaml` | Corp egress IP found in Wikipedia edit history |
| `email_in_multiple_breaches.yaml` | Email present in N+ HIBP/Dehashed breaches |
| `email_in_whois.yaml` | Personal email leaked via WHOIS |
| `email_only_from_pasteleak_site.yaml` | Email only ever seen on a paste-leak source |
| `host_only_from_bruteforce.yaml` | Host only found via subdomain brute (not in CT/DNS) |
| `host_only_from_certificatetransparency.yaml` | Host only present in CT logs |
| `http_errors.yaml` | Cluster of HTTP 5xx / unusual error responses |
| `human_name_in_whois.yaml` | Personal name leaked via WHOIS |
| `internal_host.yaml` | Internal-only hostname exposed externally |
| `multiple_malicious.yaml` | Host flagged by N+ threat-intel sources |
| `multiple_malicious_affiliate.yaml` | Affiliate domain flagged by N+ TI sources |
| `multiple_malicious_cohost.yaml` | Co-hosted domain on flagged shared IP |
| `name_only_from_pasteleak_site.yaml` | Name only ever seen on a paste-leak source |
| `open_port_version.yaml` | Service banner reveals version (CVE pivot) |
| `outlier_cloud.yaml` | Cloud provider outlier in target's footprint |
| `outlier_country.yaml` | Geographic outlier in target's footprint |
| `outlier_email.yaml` | Atypical email pattern relative to org baseline |
| `outlier_hostname.yaml` | Anomalous hostname relative to naming convention |
| `outlier_ipaddress.yaml` | IP outside normal allocation blocks |
| `outlier_registrar.yaml` | Domain with an unusual registrar vs sibling domains |
| `outlier_webserver.yaml` | Rare webserver header amid common ones |
| `remote_desktop_exposed.yaml` | RDP / VNC / SSH publicly reachable |
| `root_path_needs_auth.yaml` | Site root requires auth (often forgotten admin panel) |
| `stale_host.yaml` | Host with abandoned/outdated signals |
| `strong_affiliate_certs.yaml` | Strong cert linkage between target + affiliate |
| `strong_similardomain_crossref.yaml` | Similar-looking domain that cross-refs target infra |
| `vulnerability_critical.yaml` | Critical CVSS finding pivot |
| `vulnerability_high.yaml` | High CVSS finding pivot |
| `vulnerability_mediumlow.yaml` | Medium/Low CVSS finding aggregation |

**Correlation rule YAML schema (upstream-compatible):**
```yaml
id: snake_case_unique
version: 1
meta:
  name: "Human-friendly title"
  description: "What this finds + why it matters"
  risk: INFO | LOW | MEDIUM | HIGH | CRITICAL
  scope: host | domain | network
  author: "..."
collections:
  - collect:
      - method: exact   # or regex, has_value, in_list
        field: type     # type | data | module | source_data
        value: TCP_PORT_OPEN_BANNER
aggregation:
  field: data
analysis:
  - method: threshold   # threshold | outlier | first_only | match_all_pairs
    minimum: 1
headline: "Open port banner discloses version: {data}"
```
Engine must accept the upstream `collections` / `aggregation` / `analysis` / `headline` four-section grammar verbatim, not just our simpler match-list grammar.

**Report formats:**
- **CSV** — flat table `(scan_id, type, data, module, source_event, generated_at, confidence, visibility, risk)`.
- **JSON** — `{ scan: {...}, events: [...] }`.
- **GEXF / GraphML** — for Gephi / Cytoscape: nodes = events, edges = `source_event` links, node attrs include type/data/risk.
- **XLSX** — multi-sheet workbook (one sheet per event type).
- **HTML report** — Askama-templated standalone document with embedded graph viz.

**Web UI panels:**
- **New Scan** — wizard: target → target-type-detect → scan-policy → modules-confirm → start.
- **Scans** — list view with status, filter by target/date/status.
- **Live View** — running scan's event stream (SSE), per-module status, abort button.
- **Graph** — interactive entity graph (sigma.js); click node → show data + linked events.
- **Settings** — global config + per-module options + API key store.
- **Modules** — table of all modules with category/flags/docs/last-success/last-error.
- **Correlations** — list of rule files; load/edit/test against a finished scan.

**REST API:**
- `POST /api/scan` — body `{ target, policy, modules?, ... }` → `{ scan_id }`.
- `GET /api/scan/{id}` — scan metadata + counts.
- `GET /api/scan/{id}/events` — paginated event list.
- `GET /api/scan/{id}/events/stream` — SSE live feed.
- `GET /api/scan/{id}/graph` — GEXF/JSON graph.
- `POST /api/scan/{id}/abort` — abort running scan.
- `GET /api/modules` — list registered modules + their flags.
- `GET /api/types` — list event types.
- `POST /api/correlate/{id}` — re-run correlation rules over a finished scan.

## Engineering hard parts

1. **Module registration via traits.** Compile-time registration via inventory crate (`inventory::submit!(MyModule)`) avoids the manual maintain-a-list pain that hits subfinder. Each `sfp_*.rs` file's `pub struct M; impl Module for M; inventory::submit!(M);` is enough to register. Runtime `iter::<Box<dyn Module>>()` collects all.
2. **Async event bus with backpressure.** A single `tokio::sync::broadcast` channel doesn't scale to 200 subscribers each at differing rates — slow subscribers will lag-and-drop. Solution: per-module bounded `mpsc::channel(1024)` fed by the dispatcher task that reads the broadcast. If a module's channel fills, dispatcher applies backpressure on the producer (slower upstream module) via tokio's natural `await` on send. Tracks dropped events in scan metadata for diagnostics.
3. **Deduplication of events across modules.** Two modules might emit `INTERNET_NAME "api.acme.com"` from different sources. The event hash is `xxhash(type || data)`. `DashMap<u64, ()>` insert-or-skip. Crucially **the dedupe is per-scan**, not global — `Arc<DashMap>` is scoped to a `Scan`.
4. **Rate-limit-per-source coordination.** A `governor::RateLimiter::keyed` over `&'static str` source-name. Module's HTTP client wrapper calls `.until_ready("source_name").await` before every request. Defaults baked in from upstream's empirical table; users override in config. For multi-key sources (GitHub, Shodan-paid), the limiter is keyed per `(source, key_idx)`.
5. **API key management + rotation.** `ApiKeyStore { keys: HashMap<String, Vec<KeyEntry>> }`. `KeyEntry { value, last_used, fail_count, rate_limit_reset_at }`. On 401/403, mark key `cooling_until = now + 60s`. On 429 with `Retry-After`, honor header. Rotation policy = round-robin among non-cooling keys; fallback to least-recently-used.
6. **Persistence (scan state, results).** SQLite per scan (`~/.local/share/spiderfoot/scans/<uuid>.db`) — isolates scans, lets users delete individual scans by file. Tables: `scan_meta`, `events`, `event_links`, `module_status`, `module_errors`, `correlation_results`. WAL mode for concurrent reads (UI) + writes (worker). Periodic vacuum on scan finish.
7. **Graph correlation engine.** Build `DiGraph<EventId, ()>` via petgraph during ingestion (edge for every `source_event` link). At correlation time, rules iterate node pairs/triples and apply predicates. Indexes: `HashMap<EventType, Vec<NodeId>>`, `HashMap<String /* data substr */, Vec<NodeId>>` for fast joins. Hot path can use `rayon::par_iter` over rule list.
8. **Plugin architecture for user-defined modules.** Two routes:
   - **Compile-time**: drop a `sfp_user_foo.rs` into `sf-modules/src/modules/`, add `mod sfp_user_foo;` to `mod.rs`, rebuild. Best for performance/reliability.
   - **Runtime via WASM**: experimental — `wasmtime` + a stable C-ABI for `handle_event`. Lets users ship `.wasm` modules without rebuilding the binary. Slower (~5-10x) but safer + hot-loadable.
9. **Graceful scan abort.** A `CancellationToken` propagated into every module's `handle_event` ctx. Modules must check `ctx.cancel.is_cancelled()` between HTTP calls. Forced module-task abort if a module doesn't check within `abort_grace` (default 10s).
10. **Memory blowup on huge scans.** A `*.gov` apex easily yields 100k events. SQLite append-only is fine; the in-memory dedupe set is the hot spot. Switch dedupe from `DashMap<u64, ()>` to a bloom filter (`bloom` crate) with FP rate 0.01 above 10k events — accept rare duplicate emission for orders-of-magnitude memory win.
11. **Output streaming.** CSV/JSON-lines must stream to disk as events arrive (not buffer to end) — otherwise crash = total loss. GEXF/HTML reports rendered at scan-finish (need the full graph).

## Rust library mapping

| Need | Crate | Version (May 2026) | Notes |
|---|---|---|---|
| Async runtime | `tokio` | 1.40 | Multi-thread runtime; bus + per-module tasks |
| HTTP client | `reqwest` | 0.12 | rustls-tls, pool_max_idle_per_host=100, randomized UA, optional SOCKS5 proxy (Tor) |
| SQLite persistence | `sqlx` | 0.7 | Compile-time-checked queries, WAL mode, per-scan DB file |
| Web UI server | `axum` | 0.7 | Tornado-equivalent; SSE via `tokio-stream` |
| Templates | `askama` | 0.14 | HTML reports + UI |
| Static assets | `tower-http` | 0.5 | `ServeDir` for `/static/` |
| Graph algorithms | `petgraph` | 0.x | `DiGraph<EventId, EdgeKind>` correlation engine |
| Config serialization | `serde` + `serde_yaml` (or `serde_yml`) + `toml` | 1.0 / 0.9 / 0.8 | Correlation YAML + main config TOML |
| Shared mutable state | `dashmap` | 5.x | Per-scan dedupe set, module-error counters |
| Rate limiting | `governor` | 0.6 | `RateLimiter::keyed` for per-source limits |
| Logging | `tracing` + `tracing-subscriber` | 0.1 / 0.3 | Structured per-module spans |
| CLI | `clap` (derive) | 4.5 | Subcommands `scan`, `serve`, `modules`, `report` |
| WHOIS | `rust-whois` or `whois-rust` | 0.3 | Iana-registry-aware WHOIS client |
| DNS | `hickory-resolver` | 0.24 | A/AAAA/MX/NS/TXT/SOA/SPF; configurable resolver pool |
| Certificate parsing | `x509-parser` | 0.16 | Parse SSL chains from `reqwest` peer-cert |
| Cert Transparency | direct REST against crt.sh + Censys + Google CT | — | Match upstream's three-CT-source strategy |
| Module registration | `inventory` | 0.3 | Compile-time `submit!()` collects all `Box<dyn Module>` |
| Identifiers / Uuid | `uuid` | 1.x | Scan IDs |
| HashSet/Map | `std::collections::HashMap` + `indexmap` 2.x | — | Insertion-order-stable when needed for output |
| JSON | `serde_json` | 1.0 | Plus `simd-json` 0.13 for hot paths |
| Image processing | `image` | 0.25 | Favicon hashing (for tech fingerprint) |
| URL parsing | `url` | 2.5 | URL normalization for dedupe |
| Email parsing | `lettre` / `mailparse` | 0.11 / 0.15 | Pattern: `MX` lookup + RFC-822 validation |
| Phone parsing | `phonenumber` | 0.3 | E.164 normalization + carrier inference |
| GeoIP | `maxminddb` | 0.24 | Local MaxMind DB lookup (no API call) |
| Bitcoin / blockchain | `bitcoin` + `bitcoinrpc` | 0.30 | Address validation + balance lookup |
| WASM runtime (for user modules) | `wasmtime` | 25.x | Optional `--wasm-modules` feature flag |
| Errors | `eyre` / `thiserror` | 0.6 / 1.0 | — |
| Random / hashing | `rand` + `xxhash-rust` | 0.8 / 0.8 | Event hash, key rotation |
| Parallelism (correlation) | `rayon` | 1.11 | par_iter over correlation rules |
| TUI (optional CLI mode) | `ratatui` | 0.28 | Live scan dashboard alternative to web UI |

## Bug bounty workflows

1. **Initial program recon.** Point `lancer-spiderfoot -s acme.com -p passive -o gexf > recon.gexf`. Get every subdomain, IP, cert SAN, email, breach hit, GitHub leak in one shot. Pipe `.gexf` into Gephi for visual scope-map. Identify cluster anomalies (one weird subdomain off in its own subgraph = likely forgotten asset).
2. **Bounty scope expansion.** Use WHOIS + Cert + ASN modules to find *related* domains the program might also own (same registrant org, same cert issuer, sibling ASN). Add to scope after manual confirmation. `INTERNET_NAME → BGP_AS_MEMBER → NETBLOCK → IP_ADDRESS → DOMAIN_NAME` chain finds sibling assets.
3. **Email exposure check.** Target = `acme.com`. Modules: Hunter.io, EmailRep, EmailHippo, HIBP, Dehashed, IntelX. Output: every public-facing email + breach status. Pivot: any compromised employee email → check for password reuse in their accounts.
4. **S3/blob exposure check.** Run `sfp_s3bucket` + `sfp_azureblob` + `sfp_gcs` with mutation wordlist (`acme`, `acme-prod`, `acme-staging`, `acmebackups`, `acmedb`, `acmedevops`, `acme-internal`). Any 200/403 with public ACL = candidate finding. Wire correlation rule: `CLOUD_STORAGE_BUCKET_OPEN` triggers `CORRELATION_RISK HIGH`.
5. **GitHub leakage check.** `sfp_github` searches GitHub for `acme.com` literally in code, then regex-extracts secrets (`AKIA[0-9A-Z]{16}`, `ghp_[a-zA-Z0-9]{36}`, `-----BEGIN PRIVATE KEY-----`). Correlate with `EMAILADDR` (matching `@acme.com` committer) to escalate confidence.
6. **Breach DB lookup.** HIBP + Dehashed + Snusbase + IntelX for each `EMAILADDR`. Output: which breaches the email appeared in, plaintext password if available (Dehashed). High-yield in account-takeover bounties.
7. **Technology stack discovery.** `sfp_wappalyzer` (port of Wappalyzer rules) + `sfp_builtwith` + favicon-hash lookup against Shodan. Inform vuln-class focus (WP → wpscan, Drupal → CVE-2018-7600, etc.).
8. **Dark-web/leak-site monitoring.** `sfp_darknet` + `sfp_intelx` for `LEAKSITE_*` events — domain or employee email appearing in dump-site indexes. Strong signal of active compromise.
9. **Multi-target sweep.** `acquisitions.txt` (one apex per line) → bulk scan → per-target SQLite → merge graph. Identify shared infra across acquired brands (legacy hosting, shared API gateway = priority).

## 2024-2026 state

- **SpiderFoot 4.x line** (stable since 2024). Active dev branch on GitHub adds modules quarterly.
- **Deprecated sources (removed in 2024-2026):** `sfp_keybase` (Keybase API closed), `sfp_threatminer` (broken), `sfp_riddler` (Cloudfront-gated), `sfp_punkspider` (offline), `sfp_pinterest` (API closed), `sfp_skymem` (gone), `sfp_pgp` (PGP keyserver shutdowns), `sfp_pwnedlist` (acquired and discontinued).
- **New sources added 2024-2026:**
  - **Censys Platform v3** — replaced old Search v2 (`api.platform.censys.io/v3/global/search/query`); requires PAT + Organization ID header. Cert + host queries. Old keys broke; this caught many users.
  - **HIBP v3** — Password-Pwned-Range endpoint stable; breach-list endpoint now requires authenticated API key with paid tier (free tier removed in 2024). `sfp_haveibeenpwned` updated to handle new auth.
  - **Shodan tier changes** — free tier capped at 100 queries/month (down from 1/s); `sfp_shodan_paid` separate module for paying users.
  - **RECON Wave** — new aggregator API, added late 2025.
  - **BinaryEdge** — major API v2 update, paginated + cursor-based.
  - **Pulsedive** — added rate-limit headers, modules updated.
  - **GreyNoise Community v3** — refreshed schema.
  - **AbuseIPDB v3** — new auth scheme.
  - **Snusbase** — new module 2025.
  - **MerkleMap** — CT log aggregator, new 2026.
  - **VulnersDB / NVD** — direct NVD JSON 2.0 fallback for CVE lookups.
- **AI module additions (2025-2026 — official + community):**
  - `sfp_ai_summarizer` — pipes scan result subset to a configured LLM endpoint, returns "narrative summary" event.
  - `sfp_ai_risk_classifier` — LLM-driven CVSS-style scoring on `VULNERABILITY_*` events.
  - `sfp_ai_persona_inference` — clusters `EMAILADDR` / `USERNAME` / `HUMAN_NAME` events into inferred personas.
- **Maintenance signals:** upstream has slowed (Steve Micallef now focuses on the commercial SpiderFoot HX SaaS). Community PRs accepted but reviews are slow. **Open opportunity for a Rust fork to take the mantle.**
- **Forks worth knowing:**
  - **SpiderFoot HX** — Micallef's hosted commercial version; richer correlation, hosted infra, $$. The proprietary moat over open-source SpiderFoot.
  - **OWASP Amass** — overlapping subdomain enumeration capabilities but narrower in entity-types (focuses on DNS/network).
  - **theHarvester** — much narrower (email + subdomain harvesting only); often run as a pre-stage before SpiderFoot.
  - **Maltego (commercial)** — closed-source entity-graph OSINT; SpiderFoot's UX inspiration. Maltego has prettier graphs; SpiderFoot has 10x more sources for free.

## AI augmentation ideas

1. **LLM-driven scan policy generation.** "Recon this PII-handling SaaS — focus on data leakage and infra exposure." LLM parses the natural-language intent, picks the optimal module subset from the 200+ catalog (avoiding noise modules), generates a YAML policy file, and tunes per-module options (e.g., enable s3 bucket guess wordlist for storage-focused scans).
2. **Entity-relationship summarization.** After scan finishes, send the entity graph (compressed: only top-K most-connected nodes + their edges) to Claude with a prompt: "Describe the target's attack surface in 5 bullets. Surface the 3 most-unusual findings." The 5-bullet summary becomes the lead of the scan report.
3. **Anomaly highlighting in result graph.** Pre-process the graph: compute per-node centrality + per-cluster size. Outlier nodes (high centrality but disconnected cluster, or single-edge node with unusual type combo) get a "weird" flag. LLM re-ranks weirdness vs known good patterns to suppress false positives.
4. **Auto-correlation rule generation.** "Write me a rule that fires when I find an exposed GitLab instance running an old version on a subdomain owned by the target's org." LLM emits YAML correlation file targeting `WEBSERVER_TECHNOLOGY: gitlab` + `WEBSERVER_BANNER: <version-regex>` + `INTERNET_NAME: <root-domain-match>`.
5. **Target persona inference from social-media signals.** For HUMAN_NAME + USERNAME targets, aggregate cross-platform handles (`sfp_sherlock`-style), let LLM cluster into "personas" (work persona, hobby persona, anonymous persona), surface inconsistencies (e.g., a "personal" handle leaked through a corporate breach).
6. **Smart key-budget allocation.** Given user has 4 keys (HIBP, Shodan, Censys, VirusTotal) at various tiers and a list of N targets, LLM allocates query budget per-target per-source to maximize information gain without overspending any single quota.
7. **Result triage co-pilot.** Final 5000-event scan is overwhelming. LLM ranks events by "exploitability * unusualness * recency" producing a top-50 list for human review.
8. **Auto-PoC scaffold.** For each `CORRELATION_RISK HIGH` event with enough context (URL + verb + payload-hint), LLM scaffolds a curl/python PoC. Human verifies + submits to bounty program.
9. **Natural-language module authoring.** "Write me a module that hits ChaosDB.cn for subdomains" → LLM emits a `sfp_chaosdb_cn.rs` skeleton conforming to the trait, including HTTP client setup, error handling, event emission. Compile-test locally.

## Implementation phases

### Phase 0 — Workspace & core abstractions (Week 1)
- `cargo new --workspace`; create `lancer-spiderfoot`, `sf-core`, `sf-modules`, `sf-graph`, `sf-web`. Get all 5 crates building empty.
- Define `EventType` enum (full 100+ variants). Define `Target` + `TargetType`. Define `SfEvent` struct.
- Define `Module` trait + `Category` + `ModuleFlag` enums. Wire `inventory` for compile-time registration.
- Deliverable: `lancer-spiderfoot --list-modules` runs (prints empty list).

### Phase 1 — Event bus + scan state machine (Week 2)
- `Scan` struct + state machine. `ScanContext` carries shared state to modules.
- Event bus with `tokio::sync::broadcast` + per-module `mpsc::channel(1024)` backpressure.
- Dedupe via `DashMap<u64, ()>` + bloom-filter fallback above 10k events.
- SQLite persistence via `sqlx` — `tbl_scan`, `tbl_events`, WAL mode.
- Deliverable: scan with zero modules runs, emits `ROOT`, persists, terminates.

### Phase 2 — First 10 core modules (Week 3)
- `sfp_dnsresolve`, `sfp_whois`, `sfp_crtsh` (Postgres + HTTP fallback), `sfp_hackertarget`, `sfp_alienvault`, `sfp_threatcrowd`, `sfp_robtex`, `sfp_certspotter`, `sfp_certtransparency`, `sfp_riskiq`.
- All keyless or optional-key.
- HTTP client wrapper with rate-limit + randomized UA + optional SOCKS5.
- Deliverable: `lancer-spiderfoot -s acme.com -m sfp_dnsresolve,sfp_crtsh -o json` returns 100s of subdomains.

### Phase 3 — Keyed sources + API key store (Week 4)
- `ApiKeyStore` with env-var + config-file + multi-key rotation.
- Modules: `sfp_shodan`, `sfp_haveibeenpwned`, `sfp_virustotal`, `sfp_censys` (Platform v3), `sfp_github` (multi-token), `sfp_hunter`, `sfp_emailrep`, `sfp_binaryedge`, `sfp_intelx`, `sfp_dehashed`.
- Per-source rate-limit defaults baked in.
- Deliverable: scan with `-p all` triggers all keyed sources gracefully (skip-if-no-key).

### Phase 4 — Subdomain/infrastructure modules expansion (Week 5)
- 30 more modules: `sfp_dnsdumpster`, `sfp_dnsdb`, `sfp_securitytrails` (scroll), `sfp_chaos`, `sfp_fofa`, `sfp_zoomeye`, `sfp_quake`, `sfp_fullhunt`, `sfp_leakix`, `sfp_urlscan`, `sfp_waybackarchive`, `sfp_commoncrawl`, plus enrich-modules (`sfp_ipinfo`, `sfp_ipwhois`, `sfp_maxmind`, `sfp_bgpview`, `sfp_asnlookup`).
- Deliverable: 60-module catalog; broader recon coverage.

### Phase 5 — Email/identity/breach modules (Week 6)
- 25 modules around identity: `sfp_hunter`, `sfp_emailhippo`, `sfp_emailrep`, `sfp_dehashed`, `sfp_snusbase`, `sfp_intelx`, `sfp_haveibeenpwned`, `sfp_pulse`, `sfp_pulsedive`, `sfp_fullcontact`, `sfp_pipl`, `sfp_namechk`, `sfp_sherlock`-style username search across 30 platforms.
- Deliverable: email/username targets work end-to-end.

### Phase 6 — Web/footprint modules (Week 7)
- Wappalyzer port (`sfp_wappalyzer`), `sfp_builtwith`, `sfp_securityheaders`, `sfp_robotstxt`, `sfp_sitemap`, `sfp_securitytxt`, `sfp_wellknown`, `sfp_favicon` (hash → Shodan lookup), `sfp_httpheaders`, `sfp_cookies`.
- Cert chain inspection via `x509-parser`.
- Deliverable: web-footprint pass produces tech-stack + header findings.

### Phase 7 — Cloud/storage/leak modules (Week 8)
- `sfp_s3bucket` (name mutation wordlist + ACL probe), `sfp_azureblob`, `sfp_gcs`, `sfp_digitaloceanspaces`, `sfp_github` (code-search), `sfp_pastebin`, `sfp_gist`, `sfp_npmjs` (typosquat/leakage), `sfp_pypi`, `sfp_docker`-hub (leaky tags).
- Deliverable: cloud-exposure modules find a known open S3 bucket on test corpus.

### Phase 8 — Graph + correlation engine (Week 9)
- Build petgraph from event stream (in-mem during scan, dump to SQLite + GEXF at end).
- YAML correlation rule loader; rule evaluator iterating event pairs/triples.
- Ship 30 seed rules (S3-open, GitHub-token-leak, expired-cert, exposed-admin-panel, default-creds-hint, blind-pwned-email).
- GEXF emitter + JSON graph dump.
- Deliverable: post-scan, correlation rules fire and emit `CORRELATION_RISK` events.

### Phase 9 — Web UI + REST API (Week 10-11)
- `axum` server, `askama` templates, SSE-streamed live-event feed.
- Pages: New Scan wizard, Scans list, Live View, Graph (sigma.js), Settings (API key store), Modules, Correlations.
- REST API endpoints (see spec above).
- Deliverable: `lancer-spiderfoot serve` opens functional web UI.

### Phase 10 — Active/intrusive modules (Week 12)
- `sfp_portscan` (shell out to `nmap` if available, fall back to async TCP-connect via `tokio`), `sfp_subdomain_brute` (wordlist + concurrency), `sfp_dirsearch`-lite, `sfp_takeover` (CNAME-to-deleted-SaaS detection).
- All flagged `Invasive`; off by default.
- Deliverable: opt-in active scan adds takeover + port-open findings.

### Phase 11 — AI augmentation + WASM plugins (Week 13)
- `sfp_ai_summarizer` module — pipes scan to `lancer-ai` crate (Claude/OpenAI/local).
- `sfp_ai_risk_classifier` for vuln events.
- WASM-runtime feature flag for user-shipped `.wasm` modules (experimental).
- Natural-language scan policy generator (LLM → YAML policy).
- Deliverable: `lancer-spiderfoot --ai-summary` produces a 5-bullet scan summary at finish.

### Phase 12 — Polish, docs, release (Week 14)
- Cross-platform binary builds (Windows, Linux glibc + musl, macOS arm + x86).
- Documentation: per-module docs auto-generated from trait metadata.
- Performance pass: bloom-filter dedupe, parallel correlation, simd-json hot paths.
- Validation corpus: run against `bbb-targets.txt` (10 known bounty targets with known public assets); compare module yield vs upstream SpiderFoot.
- Deliverable: tagged v0.1.0 release.

---

## GUI (Lancer-standard pattern)

`lancer-spiderfoot` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-spiderfoot-cli` companion binary), but the **plain `lancer-spiderfoot` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-spiderfoot/`, `%APPDATA%\lancer-spiderfoot\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-spiderfoot-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-spiderfoot.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-spiderfoot.exe` (double-click opens the GUI window).
- Linux: `build/lancer-spiderfoot` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-spiderfoot` (bundled into `lancer-spiderfoot.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-spiderfoot/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-spiderfoot.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-spiderfoot-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-spiderfoot
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-spiderfoot.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-spiderfoot-windows-x86_64\bin\lancer-spiderfoot.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-spiderfoot`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
