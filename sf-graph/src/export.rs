//! Graph + event exporters: GEXF, GraphML, JSON.

use crate::graph::EventGraph;
use petgraph::visit::EdgeRef;
use sf_core::SfEvent;

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n).collect::<String>())
    } else {
        s.to_string()
    }
}

/// Serialize the event list to JSON `{ "events": [...] }`.
pub fn events_to_json(events: &[SfEvent]) -> String {
    serde_json::json!({ "events": events }).to_string()
}

/// Export the graph as Gephi GEXF 1.3.
pub fn graph_to_gexf(g: &EventGraph) -> String {
    let mut s = String::new();
    s.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    s.push('\n');
    s.push_str(r#"<gexf xmlns="http://gexf.net/1.3" version="1.3">"#);
    s.push_str("<graph mode=\"static\" defaultedgetype=\"directed\">");
    s.push_str(
        "<attributes class=\"node\">\
         <attribute id=\"0\" title=\"type\" type=\"string\"/>\
         <attribute id=\"1\" title=\"risk\" type=\"string\"/>\
         <attribute id=\"2\" title=\"module\" type=\"string\"/>\
         </attributes>",
    );
    s.push_str("<nodes>");
    for idx in g.graph.node_indices() {
        let n = &g.graph[idx];
        let label = xml_escape(&truncate(&format!("{}: {}", n.type_, n.data), 60));
        s.push_str(&format!(
            "<node id=\"{}\" label=\"{}\"><attvalues>\
             <attvalue for=\"0\" value=\"{}\"/>\
             <attvalue for=\"1\" value=\"{}\"/>\
             <attvalue for=\"2\" value=\"{}\"/>\
             </attvalues></node>",
            idx.index(),
            label,
            xml_escape(&n.type_),
            xml_escape(n.risk.as_str()),
            xml_escape(&n.module),
        ));
    }
    s.push_str("</nodes><edges>");
    for (i, e) in g.graph.edge_references().enumerate() {
        s.push_str(&format!(
            "<edge id=\"{}\" source=\"{}\" target=\"{}\"/>",
            i,
            e.source().index(),
            e.target().index()
        ));
    }
    s.push_str("</edges></graph></gexf>");
    s
}

/// Export the graph as GraphML.
pub fn graph_to_graphml(g: &EventGraph) -> String {
    let mut s = String::new();
    s.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    s.push('\n');
    s.push_str(r#"<graphml xmlns="http://graphml.graphdrawing.org/xmlns">"#);
    s.push_str(r#"<key id="d_type" for="node" attr.name="type" attr.type="string"/>"#);
    s.push_str(r#"<key id="d_data" for="node" attr.name="data" attr.type="string"/>"#);
    s.push_str(r#"<key id="d_risk" for="node" attr.name="risk" attr.type="string"/>"#);
    s.push_str(r#"<graph edgedefault="directed">"#);
    for idx in g.graph.node_indices() {
        let n = &g.graph[idx];
        s.push_str(&format!(
            "<node id=\"n{}\">\
             <data key=\"d_type\">{}</data>\
             <data key=\"d_data\">{}</data>\
             <data key=\"d_risk\">{}</data>\
             </node>",
            idx.index(),
            xml_escape(&n.type_),
            xml_escape(&truncate(&n.data, 200)),
            xml_escape(n.risk.as_str()),
        ));
    }
    for (i, e) in g.graph.edge_references().enumerate() {
        s.push_str(&format!(
            "<edge id=\"e{}\" source=\"n{}\" target=\"n{}\"/>",
            i,
            e.source().index(),
            e.target().index()
        ));
    }
    s.push_str("</graph></graphml>");
    s
}

/// Export the graph as JSON `{ nodes: [...], edges: [...] }` (for sigma.js / vis.js).
pub fn graph_to_json(g: &EventGraph) -> String {
    let nodes: Vec<_> = g
        .graph
        .node_indices()
        .map(|idx| {
            let n = &g.graph[idx];
            serde_json::json!({
                "id": idx.index(),
                "hash": n.hash.to_string(),
                "type": n.type_,
                "data": truncate(&n.data, 200),
                "module": n.module,
                "risk": n.risk.as_str(),
            })
        })
        .collect();
    let edges: Vec<_> = g
        .graph
        .edge_references()
        .map(|e| serde_json::json!({ "source": e.source().index(), "target": e.target().index() }))
        .collect();
    serde_json::json!({ "nodes": nodes, "edges": edges }).to_string()
}
