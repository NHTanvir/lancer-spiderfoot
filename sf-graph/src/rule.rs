//! Correlation rule schema (upstream-compatible four-section YAML grammar).

use serde::Deserialize;

/// A correlation rule loaded from a YAML file.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default = "one")]
    pub version: u32,
    pub meta: RuleMeta,
    #[serde(default)]
    pub collections: Vec<Collection>,
    #[serde(default)]
    pub aggregation: Option<Aggregation>,
    #[serde(default)]
    pub analysis: Vec<Analysis>,
    #[serde(default)]
    pub headline: Option<String>,
}

fn one() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleMeta {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "info_risk")]
    pub risk: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

fn info_risk() -> String {
    "INFO".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct Collection {
    #[serde(default)]
    pub collect: Vec<Collect>,
}

/// A single match predicate within a collection.
#[derive(Debug, Clone, Deserialize)]
pub struct Collect {
    /// `exact` | `regex` | `has_value` | `in_list`
    pub method: String,
    /// `type` | `data` | `module` | `source_data`
    pub field: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Aggregation {
    /// `type` | `data` | `module`
    pub field: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Analysis {
    /// `threshold` | `outlier` | `first_only` | `match_all_pairs`
    pub method: String,
    #[serde(default)]
    pub minimum: Option<u32>,
    #[serde(default)]
    pub maximum: Option<u32>,
}

impl Rule {
    /// Parse a rule from a YAML string.
    pub fn from_yaml(text: &str) -> Result<Rule, serde_yaml::Error> {
        serde_yaml::from_str(text)
    }
}
