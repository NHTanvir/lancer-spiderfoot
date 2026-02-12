//! Scan targets and the 11 supported target types, with validation + auto-detect.

use crate::error::{Error, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// The 11 upstream target types.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetType {
    DOMAIN_NAME,
    IP_ADDRESS,
    NETBLOCK,
    EMAILADDR,
    PHONE_NUMBER,
    HUMAN_NAME,
    USERNAME,
    BITCOIN_ADDRESS,
    ASN,
    IBAN_NUMBER,
    BANK_ACCOUNT_NUM,
}

impl TargetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetType::DOMAIN_NAME => "DOMAIN_NAME",
            TargetType::IP_ADDRESS => "IP_ADDRESS",
            TargetType::NETBLOCK => "NETBLOCK",
            TargetType::EMAILADDR => "EMAILADDR",
            TargetType::PHONE_NUMBER => "PHONE_NUMBER",
            TargetType::HUMAN_NAME => "HUMAN_NAME",
            TargetType::USERNAME => "USERNAME",
            TargetType::BITCOIN_ADDRESS => "BITCOIN_ADDRESS",
            TargetType::ASN => "ASN",
            TargetType::IBAN_NUMBER => "IBAN_NUMBER",
            TargetType::BANK_ACCOUNT_NUM => "BANK_ACCOUNT_NUM",
        }
    }

    pub fn from_name(s: &str) -> Option<TargetType> {
        Some(match s {
            "DOMAIN_NAME" => TargetType::DOMAIN_NAME,
            "IP_ADDRESS" => TargetType::IP_ADDRESS,
            "NETBLOCK" => TargetType::NETBLOCK,
            "EMAILADDR" => TargetType::EMAILADDR,
            "PHONE_NUMBER" => TargetType::PHONE_NUMBER,
            "HUMAN_NAME" => TargetType::HUMAN_NAME,
            "USERNAME" => TargetType::USERNAME,
            "BITCOIN_ADDRESS" => TargetType::BITCOIN_ADDRESS,
            "ASN" => TargetType::ASN,
            "IBAN_NUMBER" => TargetType::IBAN_NUMBER,
            "BANK_ACCOUNT_NUM" => TargetType::BANK_ACCOUNT_NUM,
            _ => return None,
        })
    }
}

static RE_DOMAIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$").unwrap());
static RE_IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$").unwrap()
});
static RE_NETBLOCK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$").unwrap()
});
static RE_EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$").unwrap());
static RE_PHONE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\+[1-9]\d{6,14}$").unwrap());
static RE_ASN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?i)AS?\d+$").unwrap());
static RE_BTC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(bc1[a-z0-9]{20,80}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$").unwrap()
});
static RE_IBAN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$").unwrap());
static RE_USERNAME: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9_.\-]{2,64}$").unwrap());

fn is_ipv4(s: &str) -> bool {
    if let Some(c) = RE_IPV4.captures(s) {
        (1..=4).all(|i| c[i].parse::<u16>().map(|n| n <= 255).unwrap_or(false))
    } else {
        false
    }
}

/// A validated scan target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub value: String,
    #[serde(rename = "type")]
    pub type_: TargetType,
}

impl Target {
    /// Construct a target, validating `value` against the regex for `type_`.
    pub fn new(value: impl Into<String>, type_: TargetType) -> Result<Self> {
        let value = value.into();
        let ok = match type_ {
            TargetType::DOMAIN_NAME => RE_DOMAIN.is_match(&value),
            TargetType::IP_ADDRESS => is_ipv4(&value) || value.contains(':'),
            TargetType::NETBLOCK => RE_NETBLOCK.is_match(&value),
            TargetType::EMAILADDR => RE_EMAIL.is_match(&value),
            TargetType::PHONE_NUMBER => RE_PHONE.is_match(&value),
            TargetType::ASN => RE_ASN.is_match(&value),
            TargetType::BITCOIN_ADDRESS => RE_BTC.is_match(&value),
            TargetType::IBAN_NUMBER => RE_IBAN.is_match(&value),
            TargetType::USERNAME => RE_USERNAME.is_match(&value),
            TargetType::HUMAN_NAME => value.split_whitespace().count() >= 2,
            TargetType::BANK_ACCOUNT_NUM => value.chars().all(|c| c.is_ascii_alphanumeric()),
        };
        if !ok {
            return Err(Error::InvalidTarget(format!(
                "`{value}` is not a valid {}",
                type_.as_str()
            )));
        }
        Ok(Target { value, type_ })
    }

    /// Best-effort auto-detection of a target's type from its value.
    pub fn detect(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let v = value.trim();
        let ty = if RE_NETBLOCK.is_match(v) {
            TargetType::NETBLOCK
        } else if is_ipv4(v) {
            TargetType::IP_ADDRESS
        } else if v.contains(':') && v.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            TargetType::IP_ADDRESS
        } else if RE_EMAIL.is_match(v) {
            TargetType::EMAILADDR
        } else if RE_PHONE.is_match(v) {
            TargetType::PHONE_NUMBER
        } else if RE_ASN.is_match(v) && v.to_ascii_uppercase().starts_with("AS") {
            TargetType::ASN
        } else if RE_BTC.is_match(v) {
            TargetType::BITCOIN_ADDRESS
        } else if RE_IBAN.is_match(v) {
            TargetType::IBAN_NUMBER
        } else if RE_DOMAIN.is_match(v) {
            TargetType::DOMAIN_NAME
        } else if v.split_whitespace().count() >= 2 {
            TargetType::HUMAN_NAME
        } else if RE_USERNAME.is_match(v) {
            TargetType::USERNAME
        } else {
            return Err(Error::InvalidTarget(format!(
                "could not auto-detect type for `{v}`"
            )));
        };
        Target::new(v.to_string(), ty)
    }
}
