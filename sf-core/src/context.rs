//! `ScanContext` — the shared, cloneable handle passed into every module.

use crate::apikeys::ApiKeyStore;
use crate::config::Config;
use crate::dedupe::Dedupe;
use crate::event::SfEvent;
use crate::http::HttpClient;
use crate::ratelimit::RateLimiters;
use crate::target::Target;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Shared per-scan state. Cheaply cloneable (`Arc` interior).
#[derive(Clone)]
pub struct ScanContext {
    pub scan_id: Uuid,
    pub target: Arc<Target>,
    pub config: Arc<Config>,
    pub apikeys: Arc<ApiKeyStore>,
    pub http: Arc<HttpClient>,
    pub limiters: Arc<RateLimiters>,
    pub cancel: CancellationToken,
    pub dedupe: Arc<Dedupe>,
    pub event_count: Arc<AtomicU64>,
    pub max_events: u64,
    /// Resolved per-module options (module name -> key -> value).
    pub opts: Arc<HashMap<String, HashMap<String, String>>>,
    /// Optional sink for events emitted outside of `handle_event`'s return value.
    emit_tx: Option<UnboundedSender<SfEvent>>,
}

impl ScanContext {
    /// Build a context. `emit_tx` lets modules stream events incrementally.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scan_id: Uuid,
        target: Target,
        config: Arc<Config>,
        apikeys: Arc<ApiKeyStore>,
        http: Arc<HttpClient>,
        limiters: Arc<RateLimiters>,
        cancel: CancellationToken,
        dedupe: Arc<Dedupe>,
        opts: Arc<HashMap<String, HashMap<String, String>>>,
        max_events: u64,
        emit_tx: Option<UnboundedSender<SfEvent>>,
    ) -> Self {
        ScanContext {
            scan_id,
            target: Arc::new(target),
            config,
            apikeys,
            http,
            limiters,
            cancel,
            dedupe,
            event_count: Arc::new(AtomicU64::new(0)),
            max_events,
            opts,
            emit_tx,
        }
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn http(&self) -> &HttpClient {
        &self.http
    }

    /// True if the scan has been asked to abort.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// The next usable API key for a module, if any.
    pub fn api_key(&self, module: &str) -> Option<String> {
        self.apikeys.next_key(module)
    }

    /// Whether a module has any configured API key.
    pub fn has_api_key(&self, module: &str) -> bool {
        self.apikeys.has_key(module)
    }

    /// A resolved per-module option (falling back to config).
    pub fn opt(&self, module: &str, key: &str) -> Option<String> {
        self.opts
            .get(module)
            .and_then(|m| m.get(key).cloned())
            .or_else(|| self.config.module_opt(module, key))
    }

    /// True if total events emitted has reached the configured cap.
    pub fn at_event_cap(&self) -> bool {
        self.max_events > 0 && self.event_count.load(Ordering::Relaxed) >= self.max_events
    }

    /// Increment the global event counter; returns the new value.
    pub fn bump_event_count(&self) -> u64 {
        self.event_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Stream an event into the bus (in addition to any returned from `handle_event`).
    pub fn emit(&self, evt: SfEvent) {
        if let Some(tx) = &self.emit_tx {
            let _ = tx.send(evt);
        }
    }
}
