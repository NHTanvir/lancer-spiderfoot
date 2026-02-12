//! Event taxonomy and the `SfEvent` record.
//!
//! `EventType` mirrors upstream SpiderFoot's `dbinit.sql` event-type taxonomy.
//! Variant identifiers are the exact upstream string names so output is
//! byte-equivalent with the Python tool.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

/// An event identifier — the xxh3 hash of `(type_name || '\0' || data)`.
pub type EventId = u64;

macro_rules! event_types {
    ($($variant:ident),* $(,)?) => {
        /// The 130+ event-type taxonomy. Variant names equal upstream string names.
        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum EventType { $($variant),* }

        impl EventType {
            /// Upstream string name (e.g. `INTERNET_NAME`).
            pub fn as_str(&self) -> &'static str {
                match self { $(EventType::$variant => stringify!($variant)),* }
            }

            /// Parse from an upstream string name.
            pub fn from_name(s: &str) -> Option<EventType> {
                $( if s == stringify!($variant) { return Some(EventType::$variant); } )*
                None
            }

            /// Every known event type.
            pub const ALL: &'static [EventType] = &[ $(EventType::$variant),* ];
        }
    }
}

event_types! {
    // Meta
    ROOT, ERROR_MESSAGE, CORRELATION_RISK, SEARCH_ENGINE_WEB_CONTENT,
    // Identity
    EMAILADDR, EMAILADDR_GENERIC, EMAILADDR_DISPOSABLE, EMAILADDR_COMPROMISED,
    USERNAME, HUMAN_NAME, PHONE_NUMBER, PHONE_NUMBER_COMPROMISED,
    ACCOUNT_EXTERNAL_OWNED, ACCOUNT_EXTERNAL_OWNED_COMPROMISED, SOCIAL_MEDIA,
    // Network
    DOMAIN_NAME, DOMAIN_NAME_PARENT, INTERNET_NAME, INTERNET_NAME_UNRESOLVED,
    IP_ADDRESS, IPV6_ADDRESS, NETBLOCK_OWNER, NETBLOCK_MEMBER, NETBLOCKV6_OWNER,
    NETBLOCKV6_MEMBER, BGP_AS_OWNER, BGP_AS_MEMBER, BGP_AS_PEER, CO_HOSTED_SITE,
    CO_HOSTED_SITE_DOMAIN, SIMILARDOMAIN, AFFILIATE_DOMAIN_NAME,
    AFFILIATE_INTERNET_NAME, AFFILIATE_IPADDR, AFFILIATE_EMAILADDR,
    AFFILIATE_WEB_CONTENT, AFFILIATE_DOMAIN_WHOIS,
    // DNS
    RAW_DNS_RECORDS, DNS_TEXT, DNS_SPF, DNS_SRV, PROVIDER_DNS, PROVIDER_MAIL,
    PROVIDER_HOSTING, PROVIDER_TELCO, DOMAIN_WHOIS, DOMAIN_REGISTRAR,
    // Web
    LINKED_URL_INTERNAL, LINKED_URL_EXTERNAL, URL_WEB_FRAMEWORK, URL_JAVASCRIPT,
    URL_FORM, URL_UPLOAD, URL_STATIC, URL_PASSWORD_LOGIN, URL_ADBLOCKED_EXTERNAL,
    URL_FORM_HISTORIC, HTTP_CODE, WEBSERVER_BANNER, WEBSERVER_HTTPHEADERS,
    WEBSERVER_TECHNOLOGY, WEBAPPSEC_HEADER_MISSING, WEB_ANALYTICS_ID,
    TARGET_WEB_CONTENT, TARGET_WEB_COOKIE, TARGET_WEB_CONTENT_TYPE,
    INTERESTING_FILE, INTERESTING_FILE_HISTORIC, ROBOTS_TXT, SOFTWARE_USED,
    OPERATING_SYSTEM, DEFACED_INTERNET_NAME, DEFACED_AFFILIATE_INTERNET_NAME,
    // Certs / crypto
    SSL_CERTIFICATE_RAW, SSL_CERTIFICATE_ISSUED, SSL_CERTIFICATE_ISSUER,
    SSL_CERTIFICATE_EXPIRING, SSL_CERTIFICATE_EXPIRED, SSL_CERTIFICATE_MISMATCH,
    BITCOIN_ADDRESS, BITCOIN_BALANCE, ETHEREUM_ADDRESS, IBAN_NUMBER,
    BANK_ACCOUNT_NUMBER, CREDIT_CARD_NUMBER, PHONE_NUMBER_TYPE,
    // Breaches / leaks
    LEAKSITE_URL, LEAKSITE_CONTENT, PASSWORD_COMPROMISED, HASH, HASH_COMPROMISED,
    BREACHED_DATA, DARKNET_MENTION_URL, DARKNET_MENTION_CONTENT, MALICIOUS_IPADDR,
    MALICIOUS_INTERNET_NAME, MALICIOUS_EMAILADDR, MALICIOUS_AFFILIATE_INTERNET_NAME,
    MALICIOUS_AFFILIATE_IPADDR, MALICIOUS_NETBLOCK, MALICIOUS_ASN, MALICIOUS_COHOST,
    BLACKLISTED_IPADDR, BLACKLISTED_INTERNET_NAME, BLACKLISTED_NETBLOCK,
    // Geo
    GEOINFO, PHYSICAL_ADDRESS, PHYSICAL_COORDINATES, COUNTRY_NAME,
    // Storage / cloud
    CLOUD_STORAGE_BUCKET, CLOUD_STORAGE_BUCKET_OPEN, S3_BUCKET, S3_BUCKET_OPEN,
    AZURE_BLOB, AZURE_BLOB_OPEN, GCS_BUCKET, GCS_BUCKET_OPEN, DIGITALOCEAN_SPACE,
    // Ports / vulns
    TCP_PORT_OPEN, TCP_PORT_OPEN_BANNER, UDP_PORT_OPEN, UDP_PORT_OPEN_INFO,
    VULNERABILITY_GENERAL, VULNERABILITY_DISCLOSURE, VULNERABILITY_CVE_CRITICAL,
    VULNERABILITY_CVE_HIGH, VULNERABILITY_CVE_MEDIUM, VULNERABILITY_CVE_LOW,
    // Raw
    RAW_RIR_DATA, RAW_FILE_META_DATA, RAW_API_DATA,
    // AI augmentation (Lancer net-new)
    AI_SUMMARY, AI_RISK_SCORE, AI_PERSONA, AI_POLICY,
}

/// Risk severity for an event (matches upstream INFO..CRITICAL grading).
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum RiskLevel {
    #[default]
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::INFO => "INFO",
            RiskLevel::LOW => "LOW",
            RiskLevel::MEDIUM => "MEDIUM",
            RiskLevel::HIGH => "HIGH",
            RiskLevel::CRITICAL => "CRITICAL",
        }
    }

    pub fn from_name(s: &str) -> Option<RiskLevel> {
        match s.to_ascii_uppercase().as_str() {
            "INFO" => Some(RiskLevel::INFO),
            "LOW" => Some(RiskLevel::LOW),
            "MEDIUM" => Some(RiskLevel::MEDIUM),
            "HIGH" => Some(RiskLevel::HIGH),
            "CRITICAL" => Some(RiskLevel::CRITICAL),
            _ => None,
        }
    }
}

/// A single typed datum discovered during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SfEvent {
    #[serde(rename = "type")]
    pub type_: EventType,
    pub data: String,
    pub module: String,
    pub source_event: Option<EventId>,
    pub confidence: u8,
    pub visibility: u8,
    pub risk: RiskLevel,
    pub generated_at: DateTime<Utc>,
    pub hash: EventId,
}

/// Compute the canonical event hash from type + data.
pub fn event_hash(type_: EventType, data: &str) -> EventId {
    let mut buf = Vec::with_capacity(data.len() + 16);
    buf.extend_from_slice(type_.as_str().as_bytes());
    buf.push(0);
    buf.extend_from_slice(data.as_bytes());
    xxh3_64(&buf)
}

impl SfEvent {
    /// Construct an event with default confidence/visibility/risk.
    pub fn new(
        type_: EventType,
        data: impl Into<String>,
        module: impl Into<String>,
        source_event: Option<EventId>,
    ) -> Self {
        let data = data.into();
        let hash = event_hash(type_, &data);
        SfEvent {
            type_,
            data,
            module: module.into(),
            source_event,
            confidence: 100,
            visibility: 100,
            risk: RiskLevel::INFO,
            generated_at: Utc::now(),
            hash,
        }
    }

    /// The synthetic ROOT event that seeds a scan.
    pub fn root(target_value: impl Into<String>) -> Self {
        SfEvent::new(EventType::ROOT, target_value, "SpiderFoot", None)
    }

    pub fn with_risk(mut self, risk: RiskLevel) -> Self {
        self.risk = risk;
        self
    }

    pub fn with_confidence(mut self, c: u8) -> Self {
        self.confidence = c;
        self
    }

    pub fn with_visibility(mut self, v: u8) -> Self {
        self.visibility = v;
        self
    }
}
