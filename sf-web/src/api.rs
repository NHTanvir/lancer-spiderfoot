//! REST API handlers.

use crate::state::{AppState, ScanMeta, ScanShared, WebSink};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::StreamExt;
use sf_core::{Config, EventSink, Policy, ScanEngine, Target, TargetType};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(serde::Deserialize)]
pub struct ScanRequest {
    pub target: String,
    #[serde(default)]
    pub target_type: Option<String>,
    #[serde(default)]
    pub policy: Option<String>,
    #[serde(default)]
    pub modules: Option<String>,
}

#[derive(serde::Serialize)]
pub struct ScanCreated {
    pub scan_id: String,
}

#[derive(serde::Deserialize)]
pub struct Page {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}
fn default_limit() -> usize {
    100
}

#[derive(serde::Deserialize)]
pub struct GraphQuery {
    #[serde(default)]
    pub format: Option<String>,
}

/// Build the engine and spawn a scan task; returns the tracking id.
pub fn start_scan(state: &AppState, req: ScanRequest) -> Result<Uuid, String> {
    let target = match &req.target_type {
        Some(t) => {
            let tt = TargetType::from_name(t).ok_or_else(|| format!("unknown target type {t}"))?;
            Target::new(req.target.clone(), tt).map_err(|e| e.to_string())?
        }
        None => Target::detect(req.target.clone()).map_err(|e| e.to_string())?,
    };

    let cfg = Config::load_default();
    let apikeys = sf_core::ApiKeyStore::from_config(&cfg);
    let all = sf_modules::all_modules();
    let policy = match &req.modules {
        Some(list) => Policy::custom(list),
        None => Policy::from_name(req.policy.as_deref().unwrap_or("passive"))
            .unwrap_or(Policy::Passive),
    };
    let selected = policy.select(all, |name| apikeys.has_key(name));
    let module_count = selected.len();
    let engine = ScanEngine::new(selected, cfg).map_err(|e| e.to_string())?;

    let id = Uuid::new_v4();
    let cancel = CancellationToken::new();
    let (tx, _rx) = broadcast::channel::<String>(4096);
    let meta = ScanMeta {
        id: id.to_string(),
        target: target.value.clone(),
        target_type: target.type_.as_str().to_string(),
        status: "RUNNING".to_string(),
        started_at: chrono::Utc::now().to_rfc3339(),
        finished_at: None,
        event_count: 0,
        error_count: 0,
        modules: module_count,
    };
    let shared = Arc::new(ScanShared {
        meta: Mutex::new(meta),
        events: Mutex::new(Vec::new()),
        tx,
        cancel: cancel.clone(),
    });
    if let Ok(mut map) = state.scans.lock() {
        map.insert(id, shared.clone());
    }
    let sink: Arc<dyn EventSink> = Arc::new(WebSink { shared });
    tokio::spawn(async move {
        let _ = engine.run(target, cancel, Some(sink)).await;
    });
    Ok(id)
}

pub async fn create_scan(
    State(state): State<AppState>,
    Json(req): Json<ScanRequest>,
) -> Response {
    match start_scan(&state, req) {
        Ok(id) => Json(ScanCreated {
            scan_id: id.to_string(),
        })
        .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

fn parse_id(id: &str) -> Option<Uuid> {
    Uuid::parse_str(id).ok()
}

pub async fn get_scan(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(uuid) = parse_id(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state.get(&uuid).and_then(|s| s.meta.lock().ok().map(|m| m.clone())) {
        Some(meta) => Json(meta).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn list_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(page): Query<Page>,
) -> Response {
    let Some(uuid) = parse_id(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(shared) = state.get(&uuid) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let events = shared.events.lock().map(|e| e.clone()).unwrap_or_default();
    let slice: Vec<_> = events.into_iter().skip(page.offset).take(page.limit).collect();
    Json(slice).into_response()
}

pub async fn stream_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let Some(uuid) = parse_id(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(shared) = state.get(&uuid) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let rx = shared.tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| async move {
        match msg {
            Ok(line) => Some(Ok::<Event, Infallible>(Event::default().data(line))),
            Err(_) => None,
        }
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

pub async fn scan_graph(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<GraphQuery>,
) -> Response {
    let Some(uuid) = parse_id(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(shared) = state.get(&uuid) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let events = shared.events.lock().map(|e| e.clone()).unwrap_or_default();
    let graph = sf_graph::EventGraph::from_events(&events);
    match q.format.as_deref() {
        Some("gexf") => (
            [("content-type", "application/xml")],
            sf_graph::graph_to_gexf(&graph),
        )
            .into_response(),
        Some("graphml") => (
            [("content-type", "application/xml")],
            sf_graph::graph_to_graphml(&graph),
        )
            .into_response(),
        _ => (
            [("content-type", "application/json")],
            sf_graph::graph_to_json(&graph),
        )
            .into_response(),
    }
}

pub async fn abort_scan(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(uuid) = parse_id(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match state.get(&uuid) {
        Some(shared) => {
            shared.cancel.cancel();
            if let Ok(mut m) = shared.meta.lock() {
                m.status = "ABORTING".to_string();
            }
            StatusCode::ACCEPTED.into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn list_modules() -> Response {
    let modules = sf_modules::all_modules();
    let json: Vec<_> = modules
        .iter()
        .map(|m| {
            serde_json::json!({
                "name": m.name(),
                "descr": m.descr(),
                "categories": m.categories().iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                "flags": m.flags().iter().map(|f| f.as_str()).collect::<Vec<_>>(),
                "watched": m.watched_events().iter().map(|e| e.as_str()).collect::<Vec<_>>(),
                "produced": m.produced_events().iter().map(|e| e.as_str()).collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(json).into_response()
}

pub async fn list_types() -> Response {
    let types: Vec<&str> = sf_core::EventType::ALL.iter().map(|e| e.as_str()).collect();
    Json(types).into_response()
}

fn correlations_dir() -> std::path::PathBuf {
    std::env::var("SPIDERFOOT_CORRELATIONS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("correlations"))
}

pub async fn correlate(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let Some(uuid) = parse_id(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(shared) = state.get(&uuid) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let events = shared.events.lock().map(|e| e.clone()).unwrap_or_default();
    let engine = sf_graph::CorrelationEngine::load_dir(&correlations_dir()).unwrap_or_default();
    let results = engine.evaluate(&events);
    let json: Vec<_> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "risk": r.risk.as_str(),
                "headline": r.headline,
                "event_count": r.event_hashes.len(),
            })
        })
        .collect();
    Json(json).into_response()
}
