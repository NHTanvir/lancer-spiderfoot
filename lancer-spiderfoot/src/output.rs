//! Output formatting for CLI mode: tab, csv, json, gexf, graphml, html, xlsx.

use sf_core::SfEvent;
use std::collections::HashSet;

#[derive(Clone, Default)]
pub struct OutOpts {
    pub format: String,
    pub delimiter: String,
    pub no_headers: bool,
    pub strip_newlines: bool,
    pub source_data: bool,
    pub max_length: Option<usize>,
    pub filter_types: Option<HashSet<String>>,
}

impl OutOpts {
    /// True for streaming row formats (tab/csv); false for buffered formats.
    pub fn is_streaming(&self) -> bool {
        matches!(self.format.as_str(), "tab" | "csv")
    }

    fn keep(&self, evt: &SfEvent) -> bool {
        match &self.filter_types {
            Some(set) => set.contains(evt.type_.as_str()),
            None => true,
        }
    }

    fn field(&self, s: &str) -> String {
        let mut out = s.to_string();
        if self.strip_newlines {
            out = out.replace(['\n', '\r'], " ");
        }
        if let Some(n) = self.max_length {
            if out.chars().count() > n {
                out = out.chars().take(n).collect();
            }
        }
        out
    }
}

/// Header line for tab/csv (None if headers suppressed or format buffered).
pub fn header_line(opts: &OutOpts) -> Option<String> {
    if opts.no_headers {
        return None;
    }
    let cols: Vec<&str> = if opts.source_data {
        vec!["Source", "Type", "Data", "Module", "Risk"]
    } else {
        vec!["Type", "Data", "Module", "Risk"]
    };
    match opts.format.as_str() {
        "csv" => Some(cols.join(&opts.delimiter)),
        "tab" => Some(cols.join("\t")),
        _ => None,
    }
}

/// A single streamed row for tab/csv (None if filtered out or non-streaming).
pub fn row_line(evt: &SfEvent, opts: &OutOpts) -> Option<String> {
    if !opts.keep(evt) || !opts.is_streaming() {
        return None;
    }
    let mut cols: Vec<String> = Vec::new();
    if opts.source_data {
        cols.push(
            evt.source_event
                .map(|h| h.to_string())
                .unwrap_or_else(|| "ROOT".to_string()),
        );
    }
    cols.push(opts.field(evt.type_.as_str()));
    cols.push(opts.field(&evt.data));
    cols.push(opts.field(&evt.module));
    cols.push(evt.risk.as_str().to_string());
    let sep = if opts.format == "csv" {
        opts.delimiter.as_str()
    } else {
        "\t"
    };
    let line = if opts.format == "csv" {
        cols.iter()
            .map(|c| csv_escape(c, &opts.delimiter))
            .collect::<Vec<_>>()
            .join(sep)
    } else {
        cols.join(sep)
    };
    Some(line)
}

fn csv_escape(s: &str, delim: &str) -> String {
    if s.contains(delim) || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Full buffered output for json/gexf/graphml/html/xlsx.
pub fn final_output(events: &[SfEvent], scan_id: &str, opts: &OutOpts) -> String {
    let filtered: Vec<SfEvent> = events.iter().filter(|e| opts.keep(e)).cloned().collect();
    match opts.format.as_str() {
        "json" => serde_json::json!({
            "scan_id": scan_id,
            "event_count": filtered.len(),
            "events": filtered,
        })
        .to_string(),
        "gexf" => {
            let g = sf_graph::EventGraph::from_events(&filtered);
            sf_graph::graph_to_gexf(&g)
        }
        "graphml" => {
            let g = sf_graph::EventGraph::from_events(&filtered);
            sf_graph::graph_to_graphml(&g)
        }
        "html" => html_report(&filtered, scan_id),
        "xlsx" => {
            eprintln!("[warn] xlsx output is emitted as CSV in this build");
            let mut s = String::new();
            if let Some(h) = header_line(&OutOpts {
                format: "csv".into(),
                delimiter: ",".into(),
                ..opts.clone()
            }) {
                s.push_str(&h);
                s.push('\n');
            }
            for e in &filtered {
                let mut o = opts.clone();
                o.format = "csv".into();
                if o.delimiter.is_empty() {
                    o.delimiter = ",".into();
                }
                if let Some(r) = row_line(e, &o) {
                    s.push_str(&r);
                    s.push('\n');
                }
            }
            s
        }
        _ => serde_json::to_string_pretty(&filtered).unwrap_or_default(),
    }
}

fn html_report(events: &[SfEvent], scan_id: &str) -> String {
    let mut rows = String::new();
    for e in events {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"r-{}\">{}</td></tr>",
            html_escape(e.type_.as_str()),
            html_escape(&truncate(&e.data, 200)),
            html_escape(&e.module),
            e.risk.as_str(),
            e.risk.as_str()
        ));
    }
    format!(
        r#"<!doctype html><html><head><meta charset="utf-8"/>
<title>lancer-spiderfoot report {scan_id}</title>
<style>body{{font:14px system-ui;margin:30px;background:#0f1117;color:#d7dbe6}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #232838;padding:6px 10px;text-align:left}}
.r-HIGH,.r-CRITICAL{{color:#ff6b6b}}.r-MEDIUM{{color:#ffb454}}</style></head>
<body><h1>Scan report</h1><p>Scan <code>{scan_id}</code> — {n} events</p>
<table><thead><tr><th>Type</th><th>Data</th><th>Module</th><th>Risk</th></tr></thead><tbody>{rows}</tbody></table></body></html>"#,
        scan_id = scan_id,
        n = events.len(),
        rows = rows
    )
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        s.chars().take(n).collect::<String>() + "…"
    } else {
        s.to_string()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}
