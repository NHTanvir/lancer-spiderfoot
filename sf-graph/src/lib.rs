//! `sf-graph` — entity correlation engine + graph export.
//!
//! Builds a petgraph event graph, evaluates upstream-compatible YAML
//! correlation rules, and exports GEXF / GraphML / JSON.

pub mod engine;
pub mod export;
pub mod graph;
pub mod rule;

pub use engine::{CorrelationEngine, CorrelationResult};
pub use export::{events_to_json, graph_to_gexf, graph_to_graphml, graph_to_json};
pub use graph::{EventGraph, EventNode};
pub use rule::{Aggregation, Analysis, Collect, Collection, Rule, RuleMeta};
