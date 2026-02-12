//! petgraph-backed event graph built from `source_event` links.

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use sf_core::{EventId, RiskLevel, SfEvent};
use std::collections::HashMap;

/// A node in the event graph.
#[derive(Debug, Clone)]
pub struct EventNode {
    pub hash: EventId,
    pub type_: String,
    pub data: String,
    pub module: String,
    pub risk: RiskLevel,
}

/// A directed graph of events; an edge `parent -> child` means the child event
/// was derived from the parent (`child.source_event == parent.hash`).
pub struct EventGraph {
    pub graph: DiGraph<EventNode, ()>,
    index: HashMap<EventId, NodeIndex>,
}

impl Default for EventGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl EventGraph {
    pub fn new() -> Self {
        EventGraph {
            graph: DiGraph::new(),
            index: HashMap::new(),
        }
    }

    /// Build a graph from a slice of events.
    pub fn from_events(events: &[SfEvent]) -> Self {
        let mut g = EventGraph::new();
        for e in events {
            g.add_event(e);
        }
        for e in events {
            if let Some(parent) = e.source_event {
                g.link(parent, e.hash);
            }
        }
        g
    }

    pub fn add_event(&mut self, e: &SfEvent) -> NodeIndex {
        if let Some(idx) = self.index.get(&e.hash) {
            return *idx;
        }
        let idx = self.graph.add_node(EventNode {
            hash: e.hash,
            type_: e.type_.as_str().to_string(),
            data: e.data.clone(),
            module: e.module.clone(),
            risk: e.risk,
        });
        self.index.insert(e.hash, idx);
        idx
    }

    pub fn link(&mut self, parent: EventId, child: EventId) {
        if let (Some(&p), Some(&c)) = (self.index.get(&parent), self.index.get(&child)) {
            self.graph.add_edge(p, c, ());
        }
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Degree centrality (in + out) for each node, by event hash.
    pub fn centrality(&self) -> HashMap<EventId, usize> {
        let mut out = HashMap::new();
        for idx in self.graph.node_indices() {
            let deg = self
                .graph
                .neighbors_directed(idx, Direction::Incoming)
                .count()
                + self
                    .graph
                    .neighbors_directed(idx, Direction::Outgoing)
                    .count();
            out.insert(self.graph[idx].hash, deg);
        }
        out
    }
}
