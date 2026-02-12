//! Correlation rule evaluator.

use crate::rule::{Analysis, Collect, Rule};
use regex::Regex;
use sf_core::{EventType, RiskLevel, SfEvent};
use std::collections::HashMap;
use std::path::Path;

/// A fired correlation.
#[derive(Debug, Clone)]
pub struct CorrelationResult {
    pub rule_id: String,
    pub rule_name: String,
    pub risk: RiskLevel,
    pub headline: String,
    pub event_hashes: Vec<u64>,
}

/// Loads + evaluates correlation rules over a scan's event set.
#[derive(Default)]
pub struct CorrelationEngine {
    rules: Vec<Rule>,
}

impl CorrelationEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rules(rules: Vec<Rule>) -> Self {
        CorrelationEngine { rules }
    }

    /// Load every `*.yaml` / `*.yml` rule from a directory (bad files skipped).
    pub fn load_dir(dir: &Path) -> sf_core::Result<Self> {
        let mut rules = Vec::new();
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                let path = entry?.path();
                let is_yaml = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e == "yaml" || e == "yml")
                    .unwrap_or(false);
                if !is_yaml {
                    continue;
                }
                match std::fs::read_to_string(&path).map_err(sf_core::Error::from) {
                    Ok(text) => match Rule::from_yaml(&text) {
                        Ok(rule) => rules.push(rule),
                        Err(e) => tracing::warn!(path = ?path, error = %e, "bad correlation rule"),
                    },
                    Err(e) => tracing::warn!(path = ?path, error = %e, "cannot read rule"),
                }
            }
        }
        Ok(CorrelationEngine { rules })
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluate all rules; return the fired correlations.
    pub fn evaluate(&self, events: &[SfEvent]) -> Vec<CorrelationResult> {
        let mut out = Vec::new();
        for rule in &self.rules {
            out.extend(evaluate_rule(rule, events));
        }
        out
    }

    /// Evaluate and convert results to `CORRELATION_RISK` events.
    pub fn evaluate_to_events(&self, events: &[SfEvent]) -> Vec<SfEvent> {
        self.evaluate(events)
            .into_iter()
            .map(|r| {
                SfEvent::new(
                    EventType::CORRELATION_RISK,
                    r.headline,
                    "sfp_correlate",
                    r.event_hashes.first().copied(),
                )
                .with_risk(r.risk)
            })
            .collect()
    }
}

fn field_value<'a>(evt: &'a SfEvent, field: &str) -> &'a str {
    match field {
        "type" => evt.type_.as_str(),
        "module" => &evt.module,
        "data" | "source_data" => &evt.data,
        _ => "",
    }
}

fn matches_collect(evt: &SfEvent, c: &Collect) -> bool {
    let val = field_value(evt, &c.field);
    match c.method.as_str() {
        "exact" => val == c.value,
        "regex" => Regex::new(&c.value).map(|re| re.is_match(val)).unwrap_or(false),
        "has_value" => !val.is_empty(),
        "in_list" => c.value.split(',').any(|v| v.trim() == val),
        "contains" => val.contains(&c.value),
        _ => false,
    }
}

/// True if the event satisfies all predicates of any one collection.
fn collected(evt: &SfEvent, rule: &Rule) -> bool {
    rule.collections
        .iter()
        .any(|coll| !coll.collect.is_empty() && coll.collect.iter().all(|c| matches_collect(evt, c)))
}

fn fill_headline(rule: &Rule, rep: &SfEvent) -> String {
    let template = rule
        .headline
        .clone()
        .unwrap_or_else(|| rule.meta.name.clone());
    template
        .replace("{data}", &rep.data)
        .replace("{type}", rep.type_.as_str())
        .replace("{module}", &rep.module)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn corr_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../correlations")
    }

    #[test]
    fn all_37_rules_parse() {
        let engine = CorrelationEngine::load_dir(&corr_dir()).expect("load");
        assert_eq!(engine.len(), 37, "expected all 37 correlation rules to parse");
    }

    #[test]
    fn threshold_rule_fires() {
        let rule = Rule::from_yaml(
            "id: t\nmeta:\n  name: T\n  risk: HIGH\ncollections:\n  - collect:\n      - method: exact\n        field: type\n        value: MALICIOUS_IPADDR\naggregation:\n  field: data\nanalysis:\n  - method: threshold\n    minimum: 2\nheadline: \"flagged: {data}\"\n",
        )
        .unwrap();
        let engine = CorrelationEngine::with_rules(vec![rule]);
        let evts = vec![
            SfEvent::new(EventType::MALICIOUS_IPADDR, "1.2.3.4", "a", None),
            SfEvent::new(EventType::MALICIOUS_IPADDR, "1.2.3.4", "b", None),
        ];
        let results = engine.evaluate(&evts);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].risk, RiskLevel::HIGH);
    }
}

fn evaluate_rule(rule: &Rule, events: &[SfEvent]) -> Vec<CorrelationResult> {
    let collected: Vec<&SfEvent> = events.iter().filter(|e| collected(e, rule)).collect();
    if collected.is_empty() {
        return Vec::new();
    }
    let risk = RiskLevel::from_name(&rule.meta.risk).unwrap_or(RiskLevel::INFO);

    // Group by aggregation field (or one group for the whole set).
    let groups: HashMap<String, Vec<&SfEvent>> = match &rule.aggregation {
        Some(agg) => {
            let mut m: HashMap<String, Vec<&SfEvent>> = HashMap::new();
            for e in &collected {
                m.entry(field_value(e, &agg.field).to_string())
                    .or_default()
                    .push(e);
            }
            m
        }
        None => {
            let mut m = HashMap::new();
            m.insert(String::new(), collected.clone());
            m
        }
    };

    let analysis = rule
        .analysis
        .first()
        .cloned()
        .unwrap_or(Analysis {
            method: "threshold".to_string(),
            minimum: Some(1),
            maximum: None,
        });

    let mut out = Vec::new();
    let n_groups = groups.len();
    for (_key, group) in groups {
        let fire = match analysis.method.as_str() {
            "threshold" => group.len() as u32 >= analysis.minimum.unwrap_or(1),
            "first_only" => true,
            "outlier" => n_groups > 1 && group.len() == 1,
            "match_all_pairs" => group.len() >= 2,
            _ => !group.is_empty(),
        };
        if !fire {
            continue;
        }
        let rep = group[0];
        out.push(CorrelationResult {
            rule_id: rule.id.clone(),
            rule_name: rule.meta.name.clone(),
            risk,
            headline: fill_headline(rule, rep),
            event_hashes: group.iter().map(|e| e.hash).collect(),
        });
    }
    out
}
