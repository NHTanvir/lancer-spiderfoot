//! Shared web-server state + the event sink that feeds the live view.

use sf_core::{EventSink, Scan, SfEvent};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Scan metadata exposed over the REST API.
#[derive(Clone, serde::Serialize)]
pub struct ScanMeta {
    pub id: String,
    pub target: String,
    pub target_type: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub event_count: usize,
    pub error_count: usize,
    pub modules: usize,
}

/// Per-scan shared state (events + live SSE channel + cancel token).
pub struct ScanShared {
    pub meta: Mutex<ScanMeta>,
    pub events: Mutex<Vec<SfEvent>>,
    pub tx: broadcast::Sender<String>,
    pub cancel: CancellationToken,
}

/// The axum application state.
#[derive(Clone, Default)]
pub struct AppState {
    pub scans: Arc<Mutex<HashMap<Uuid, Arc<ScanShared>>>>,
}

impl AppState {
    pub fn get(&self, id: &Uuid) -> Option<Arc<ScanShared>> {
        self.scans.lock().ok()?.get(id).cloned()
    }

    pub fn all_meta(&self) -> Vec<ScanMeta> {
        self.scans
            .lock()
            .map(|m| {
                m.values()
                    .filter_map(|s| s.meta.lock().ok().map(|m| m.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Streams scan events into the per-scan buffer + SSE channel.
pub struct WebSink {
    pub shared: Arc<ScanShared>,
}

impl EventSink for WebSink {
    fn on_event(&self, evt: &SfEvent) {
        if let Ok(mut e) = self.shared.events.lock() {
            e.push(evt.clone());
        }
        if let Ok(mut m) = self.shared.meta.lock() {
            m.event_count += 1;
        }
        if let Ok(line) = serde_json::to_string(evt) {
            let _ = self.shared.tx.send(line);
        }
    }

    fn on_finish(&self, scan: &Scan) {
        if let Ok(mut m) = self.shared.meta.lock() {
            m.status = scan.status.as_str().to_string();
            m.finished_at = scan.finished_at.map(|t| t.to_rfc3339());
            m.error_count = scan.error_count as usize;
        }
        let _ = self
            .shared
            .tx
            .send(r#"{"__event__":"finished"}"#.to_string());
    }
}
