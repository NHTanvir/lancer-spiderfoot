//! HTML pages (askama-templated shell + server-rendered bodies).

use crate::state::AppState;
use askama::Template;
use axum::extract::{Path, State};
use axum::response::Html;

#[derive(Template)]
#[template(
    source = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{{ title }} · lancer-spiderfoot</title>
<style>
:root{--bg:#0f1117;--panel:#171a23;--ac:#5b9dff;--tx:#d7dbe6;--mut:#8a93a6;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 system-ui,Segoe UI,sans-serif}
header{background:var(--panel);padding:12px 20px;display:flex;gap:18px;align-items:center;border-bottom:1px solid #232838}
header a{color:var(--tx);text-decoration:none;font-weight:600}header a:hover{color:var(--ac)}
.brand{color:var(--ac);font-weight:800;margin-right:12px}
main{padding:24px;max-width:1100px;margin:0 auto}
h1{font-size:20px;margin:0 0 16px}h2{font-size:16px;color:var(--mut);margin-top:28px}
table{width:100%;border-collapse:collapse;margin:12px 0}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #232838;font-size:13px}
th{color:var(--mut);font-weight:600}tr:hover td{background:#1b1f2b}
.card{background:var(--panel);border:1px solid #232838;border-radius:10px;padding:18px;margin:12px 0}
input,select,button{font:inherit;padding:8px 10px;border-radius:8px;border:1px solid #2a3040;background:#10131b;color:var(--tx)}
button{background:var(--ac);color:#06122b;border:0;font-weight:700;cursor:pointer}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;background:#222a3d;color:var(--ac)}
.risk-HIGH,.risk-CRITICAL{color:#ff6b6b}.risk-MEDIUM{color:#ffb454}.risk-LOW{color:#7bd88f}
code{color:#9fc5ff}#feed{max-height:420px;overflow:auto}
</style>
</head>
<body>
<header>
<span class="brand">🕷 lancer-spiderfoot</span>
<a href="/">Scans</a><a href="/modules">Modules</a><a href="/correlations">Correlations</a><a href="/settings">Settings</a>
</header>
<main>{{ body|safe }}</main>
</body></html>"#,
    ext = "html"
)]
struct PageTpl {
    title: String,
    body: String,
}

fn page(title: &str, body: String) -> Html<String> {
    Html(
        PageTpl {
            title: title.to_string(),
            body,
        }
        .render()
        .unwrap_or_else(|_| "<h1>render error</h1>".to_string()),
    )
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub async fn index(State(state): State<AppState>) -> Html<String> {
    let mut rows = String::new();
    let mut metas = state.all_meta();
    metas.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    for m in &metas {
        rows.push_str(&format!(
            "<tr><td><a href=\"/scan/{id}\"><code>{short}</code></a></td><td>{tgt}</td>\
             <td><span class=\"pill\">{tt}</span></td><td>{st}</td><td>{ec}</td><td>{mods}</td><td>{start}</td></tr>",
            id = m.id,
            short = &m.id.get(..8).unwrap_or(&m.id),
            tgt = esc(&m.target),
            tt = m.target_type,
            st = m.status,
            ec = m.event_count,
            mods = m.modules,
            start = m.started_at,
        ));
    }
    if rows.is_empty() {
        rows = "<tr><td colspan=7 style=\"color:#8a93a6\">No scans yet — start one above.</td></tr>".to_string();
    }
    let body = format!(
        r#"<h1>New Scan</h1>
<div class="card">
<form id="newscan" onsubmit="return startScan(event)">
<input id="target" placeholder="acme.com / 1.2.3.4 / alice@acme.com" size="40" required/>
<select id="policy">
<option value="passive">Passive</option><option value="footprint">Footprint</option>
<option value="investigate">Investigate</option><option value="all">All</option>
</select>
<button type="submit">Start scan</button>
</form>
</div>
<h2>Scan history</h2>
<table><thead><tr><th>ID</th><th>Target</th><th>Type</th><th>Status</th><th>Events</th><th>Modules</th><th>Started</th></tr></thead>
<tbody>{rows}</tbody></table>
<script>
async function startScan(e){{e.preventDefault();
 const target=document.getElementById('target').value;
 const policy=document.getElementById('policy').value;
 const r=await fetch('/api/scan',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{target,policy}})}});
 if(r.ok){{const j=await r.json();location.href='/scan/'+j.scan_id;}}else{{alert('Error: '+await r.text());}}
 return false;}}
</script>"#,
        rows = rows
    );
    page("Scans", body)
}

pub async fn scan_page(Path(id): Path<String>) -> Html<String> {
    let body = format!(
        r#"<h1>Scan <code>{short}</code></h1>
<div class="card" id="meta">Loading…</div>
<div style="margin:12px 0"><button onclick="abortScan()">Abort</button>
<button onclick="loadGraph()">Refresh graph</button>
<button onclick="runCorrelate()">Run correlations</button></div>
<h2>Live event feed</h2>
<div class="card" id="feed"><table id="ft"><thead><tr><th>Type</th><th>Data</th><th>Module</th><th>Risk</th></tr></thead><tbody></tbody></table></div>
<h2>Correlations</h2><div class="card" id="corr">—</div>
<script>
const ID="{id}";
async function refreshMeta(){{const r=await fetch('/api/scan/'+ID);if(r.ok){{const m=await r.json();
 document.getElementById('meta').innerHTML='<b>'+m.target+'</b> ('+m.target_type+') · status <span class="pill">'+m.status+'</span> · '+m.event_count+' events · '+m.modules+' modules';}}}}
function addRow(ev){{const tb=document.querySelector('#ft tbody');const tr=document.createElement('tr');
 tr.innerHTML='<td>'+ev.type+'</td><td><code>'+(ev.data||'').slice(0,120)+'</code></td><td>'+ev.module+'</td><td class="risk-'+ev.risk+'">'+ev.risk+'</td>';
 tb.prepend(tr);}}
const es=new EventSource('/api/scan/'+ID+'/events/stream');
es.onmessage=(e)=>{{try{{const ev=JSON.parse(e.data);if(ev.__event__){{refreshMeta();return;}}addRow(ev);}}catch(_){{}}}};
async function abortScan(){{await fetch('/api/scan/'+ID+'/abort',{{method:'POST'}});refreshMeta();}}
async function loadGraph(){{const r=await fetch('/api/scan/'+ID+'/graph');const g=await r.json();
 document.getElementById('meta').innerHTML+=' · graph: '+g.nodes.length+' nodes / '+g.edges.length+' edges';}}
async function runCorrelate(){{const r=await fetch('/api/scan/'+ID+'/correlate',{{method:'POST'}});const c=await r.json();
 document.getElementById('corr').innerHTML=c.length?c.map(x=>'<div class="risk-'+x.risk+'">['+x.risk+'] '+x.headline+'</div>').join(''):'No correlations fired.';}}
refreshMeta();setInterval(refreshMeta,4000);
</script>"#,
        short = id.get(..8).unwrap_or(&id),
        id = id
    );
    page("Scan", body)
}

pub async fn modules_page() -> Html<String> {
    let modules = sf_modules::all_modules();
    let mut rows = String::new();
    for m in &modules {
        let cats = m
            .categories()
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let flags = m
            .flags()
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            m.name(),
            esc(m.descr()),
            cats,
            flags
        ));
    }
    let body = format!(
        "<h1>Modules <span class=\"pill\">{}</span></h1>\
         <table><thead><tr><th>Name</th><th>Description</th><th>Categories</th><th>Flags</th></tr></thead><tbody>{}</tbody></table>",
        modules.len(),
        rows
    );
    page("Modules", body)
}

pub async fn settings_page() -> Html<String> {
    let body = r#"<h1>Settings</h1>
<div class="card">
<p>Global config is read from <code>~/.config/spiderfoot/sf.cfg</code> (TOML).</p>
<p>API keys: set per-module via <code>[modules.&lt;name&gt;]</code> <code>api_key</code> / <code>api_keys</code>,
or env <code>SPIDERFOOT_&lt;MODULE&gt;_API_KEY</code>.</p>
<pre><code>[global]
_dnsserver = "8.8.8.8"
_fetchtimeout = 30
_socks_proxy = "socks5://127.0.0.1:9050"

[modules.sfp_shodan]
api_key = "..."

[modules.sfp_github]
api_keys = ["tok1", "tok2"]
</code></pre>
</div>"#
        .to_string();
    page("Settings", body)
}

pub async fn correlations_page() -> Html<String> {
    let dir = std::env::var("SPIDERFOOT_CORRELATIONS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("correlations"));
    let engine = sf_graph::CorrelationEngine::load_dir(&dir).unwrap_or_default();
    let mut rows = String::new();
    for rule in engine.rules() {
        rows.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td class=\"risk-{}\">{}</td><td>{}</td></tr>",
            rule.id,
            esc(&rule.meta.name),
            rule.meta.risk,
            rule.meta.risk,
            esc(&rule.meta.description)
        ));
    }
    let body = format!(
        "<h1>Correlation rules <span class=\"pill\">{}</span></h1>\
         <table><thead><tr><th>ID</th><th>Name</th><th>Risk</th><th>Description</th></tr></thead><tbody>{}</tbody></table>",
        engine.len(),
        rows
    );
    page("Correlations", body)
}
