//! Shared extraction helpers used across source modules.

use once_cell::sync::Lazy;
use regex::Regex;
use sf_core::{EventType, SfEvent};

static RE_EMAIL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap()
});
static RE_HOST: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(([a-z0-9_]([a-z0-9\-_]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b").unwrap()
});
static RE_IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b").unwrap()
});
static RE_URL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"https?://[^\s'"<>)\]]+"#).unwrap());
static RE_BTC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(bc1[a-z0-9]{20,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b").unwrap()
});

/// Extract unique email addresses from arbitrary text.
pub fn extract_emails(text: &str) -> Vec<String> {
    dedup(RE_EMAIL.find_iter(text).map(|m| m.as_str().to_lowercase()))
}

/// Extract unique hostnames from text.
pub fn extract_hosts(text: &str) -> Vec<String> {
    dedup(
        RE_HOST
            .captures_iter(text)
            .filter_map(|c| c.get(1))
            .map(|m| m.as_str().to_lowercase()),
    )
}

/// Extract hostnames that are subdomains of (or equal to) `domain`.
pub fn extract_subdomains(text: &str, domain: &str) -> Vec<String> {
    let domain = domain.to_lowercase();
    extract_hosts(text)
        .into_iter()
        .filter(|h| h == &domain || h.ends_with(&format!(".{domain}")))
        .collect()
}

/// Extract unique IPv4 addresses from text.
pub fn extract_ips(text: &str) -> Vec<String> {
    dedup(RE_IPV4.find_iter(text).map(|m| m.as_str().to_string()))
}

/// Extract unique URLs from text.
pub fn extract_urls(text: &str) -> Vec<String> {
    dedup(RE_URL.find_iter(text).map(|m| m.as_str().to_string()))
}

/// Extract unique Bitcoin addresses from text.
pub fn extract_bitcoin(text: &str) -> Vec<String> {
    dedup(RE_BTC.find_iter(text).map(|m| m.as_str().to_string()))
}

/// True if `host` is the domain itself or a subdomain of it.
pub fn is_subdomain_of(host: &str, domain: &str) -> bool {
    let h = host.to_lowercase();
    let d = domain.to_lowercase();
    h == d || h.ends_with(&format!(".{d}"))
}

/// Return the registrable root (last two labels) of a hostname.
pub fn root_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() >= 2 {
        labels[labels.len() - 2..].join(".")
    } else {
        host.to_string()
    }
}

fn dedup(iter: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for s in iter {
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

/// Build a child event of `parent` with the given type/data, attributed to `module`.
pub fn child_event(
    type_: EventType,
    data: impl Into<String>,
    module: &str,
    parent: &SfEvent,
) -> SfEvent {
    SfEvent::new(type_, data, module, Some(parent.hash))
}
