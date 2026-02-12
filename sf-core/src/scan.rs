//! Scan state machine + the async event-bus orchestrator.

use crate::apikeys::ApiKeyStore;
use crate::config::Config;
use crate::context::ScanContext;
use crate::dedupe::Dedupe;
use crate::error::{Error, Result};
use crate::event::{EventType, SfEvent};
use crate::http::HttpClient;
use crate::module::Module;
use crate::persist::Store;
use crate::ratelimit::RateLimiters;
use crate::target::Target;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Lifecycle of a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Created,
    Starting,
    Running,
    Finished,
    Aborted,
    Failed,
}

impl ScanStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Created => "CREATED",
            ScanStatus::Starting => "STARTING",
            ScanStatus::Running => "RUNNING",
            ScanStatus::Finished => "FINISHED",
            ScanStatus::Aborted => "ABORTED",
            ScanStatus::Failed => "FAILED",
        }
    }
}

/// Scan metadata + counters.
#[derive(Debug, Clone)]
pub struct Scan {
    pub id: Uuid,
    pub target: Target,
    pub modules: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub status: ScanStatus,
    pub event_count: u64,
    pub error_count: u64,
}

impl Scan {
    pub fn new(id: Uuid, target: Target, modules: Vec<String>) -> Self {
        Scan {
            id,
            target,
            modules,
            started_at: Utc::now(),
            finished_at: None,
            status: ScanStatus::Created,
            event_count: 0,
            error_count: 0,
        }
    }
}

/// The output of a completed scan run.
pub struct ScanResult {
    pub scan: Scan,
    pub events: Vec<SfEvent>,
}

/// A sink that receives every newly-deduplicated event (for streaming output).
pub trait EventSink: Send + Sync {
    fn on_event(&self, evt: &SfEvent);
    fn on_finish(&self, _scan: &Scan) {}
}

/// The scan orchestrator: holds the selected modules + shared services.
pub struct ScanEngine {
    modules: Vec<Arc<dyn Module>>,
    index: HashMap<EventType, Vec<Arc<dyn Module>>>,
    store: Option<Store>,
    config: Arc<Config>,
    apikeys: Arc<ApiKeyStore>,
    http: Arc<HttpClient>,
    limiters: Arc<RateLimiters>,
}

impl ScanEngine {
    /// Build an engine over the given module set and config.
    pub fn new(modules: Vec<Box<dyn Module>>, config: Config) -> Result<Self> {
        let modules: Vec<Arc<dyn Module>> = modules.into_iter().map(Arc::from).collect();
        let mut index: HashMap<EventType, Vec<Arc<dyn Module>>> = HashMap::new();
        for m in &modules {
            for &et in m.watched_events() {
                index.entry(et).or_default().push(m.clone());
            }
        }
        let limiters = Arc::new(RateLimiters::new());
        let apikeys = Arc::new(ApiKeyStore::from_config(&config));
        let http = Arc::new(HttpClient::new(&config.global, limiters.clone())?);
        Ok(ScanEngine {
            modules,
            index,
            store: None,
            config: Arc::new(config),
            apikeys,
            http,
            limiters,
        })
    }

    /// Attach a persistence store.
    pub fn with_store(mut self, store: Store) -> Self {
        self.store = Some(store);
        self
    }

    pub fn module_names(&self) -> Vec<&'static str> {
        self.modules.iter().map(|m| m.name()).collect()
    }

    /// Resolve per-module options: defaults overridden by config.
    fn resolve_opts(&self) -> HashMap<String, HashMap<String, String>> {
        let mut out = HashMap::new();
        for m in &self.modules {
            let mut opts = HashMap::new();
            for o in m.opts() {
                opts.insert(o.name.clone(), o.default.clone());
            }
            if let Some(settings) = self.config.modules.get(m.name()) {
                for (k, _) in opts.clone() {
                    if let Some(v) = settings.get(&k) {
                        opts.insert(k, v);
                    }
                }
            }
            out.insert(m.name().to_string(), opts);
        }
        out
    }

    /// Run a scan against `target`. Streams events to `sink` if provided.
    pub async fn run(
        &self,
        target: Target,
        cancel: CancellationToken,
        sink: Option<Arc<dyn EventSink>>,
    ) -> Result<ScanResult> {
        let scan_id = Uuid::new_v4();
        let mut scan = Scan::new(
            scan_id,
            target.clone(),
            self.modules.iter().map(|m| m.name().to_string()).collect(),
        );
        scan.status = ScanStatus::Starting;

        let sid = scan_id.to_string();
        if let Some(store) = &self.store {
            store
                .insert_scan(
                    &sid,
                    &target.value,
                    target.type_.as_str(),
                    &scan.started_at.to_rfc3339(),
                    scan.status.as_str(),
                    &scan.modules.join(","),
                )
                .await?;
        }

        let dedupe = Arc::new(Dedupe::new());
        let (emit_tx, mut emit_rx) = mpsc::unbounded_channel::<SfEvent>();
        let opts = Arc::new(self.resolve_opts());
        let ctx = ScanContext::new(
            scan_id,
            target.clone(),
            self.config.clone(),
            self.apikeys.clone(),
            self.http.clone(),
            self.limiters.clone(),
            cancel.clone(),
            dedupe.clone(),
            opts,
            self.config.global._max_events,
            Some(emit_tx),
        );

        // Per-module setup.
        for m in &self.modules {
            let mopts = ctx.opts.get(m.name()).cloned().unwrap_or_default();
            if let Err(e) = m.setup(&mopts, &ctx).await {
                scan.error_count += 1;
                tracing::warn!(module = m.name(), error = %e, "module setup failed");
            }
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<SfEvent>();
        let _ = tx.send(SfEvent::root(&target.value));

        let sem = Arc::new(Semaphore::new(self.config.global._maxthreads.max(1)));
        let mut tasks: JoinSet<Result<Vec<SfEvent>>> = JoinSet::new();
        let mut all_events: Vec<SfEvent> = Vec::new();
        let idle = Duration::from_secs(self.config.global._idle_timeout.max(1));

        scan.status = ScanStatus::Running;

        loop {
            if cancel.is_cancelled() {
                scan.status = ScanStatus::Aborted;
                break;
            }
            if ctx.at_event_cap() {
                break;
            }
            // Pull any events streamed by modules into the bus.
            while let Ok(e) = emit_rx.try_recv() {
                let _ = tx.send(e);
            }

            tokio::select! {
                biased;
                Some(res) = tasks.join_next(), if !tasks.is_empty() => {
                    match res {
                        Ok(Ok(events)) => {
                            for e in events {
                                let _ = tx.send(e);
                            }
                        }
                        Ok(Err(e)) => {
                            scan.error_count += 1;
                            tracing::debug!(error = %e, "module handler error");
                        }
                        Err(e) => {
                            scan.error_count += 1;
                            tracing::debug!(error = %e, "module task join error");
                        }
                    }
                }
                maybe = rx.recv() => {
                    match maybe {
                        Some(evt) => {
                            if !dedupe.insert(evt.hash) {
                                continue;
                            }
                            ctx.bump_event_count();
                            scan.event_count += 1;
                            if let Some(store) = &self.store {
                                let _ = store.insert_event(&sid, &evt).await;
                            }
                            if let Some(s) = &sink {
                                s.on_event(&evt);
                            }
                            all_events.push(evt.clone());

                            if let Some(mods) = self.index.get(&evt.type_) {
                                for m in mods {
                                    let m = m.clone();
                                    let evt2 = evt.clone();
                                    let ctx2 = ctx.clone();
                                    let sem2 = sem.clone();
                                    let cancel2 = cancel.clone();
                                    tasks.spawn(async move {
                                        let _permit = sem2
                                            .acquire_owned()
                                            .await
                                            .map_err(|_| Error::Aborted)?;
                                        if cancel2.is_cancelled() {
                                            return Ok(Vec::new());
                                        }
                                        m.handle_event(&evt2, &ctx2).await
                                    });
                                }
                            }
                        }
                        None => break,
                    }
                }
                _ = tokio::time::sleep(idle), if tasks.is_empty() => {
                    break;
                }
            }
        }

        // Drain any still-running tasks if not aborted.
        if !cancel.is_cancelled() {
            while let Some(res) = tasks.join_next().await {
                if let Ok(Ok(events)) = res {
                    for e in events {
                        if dedupe.insert(e.hash) {
                            ctx.bump_event_count();
                            scan.event_count += 1;
                            if let Some(store) = &self.store {
                                let _ = store.insert_event(&sid, &e).await;
                            }
                            if let Some(s) = &sink {
                                s.on_event(&e);
                            }
                            all_events.push(e);
                        }
                    }
                }
            }
        } else {
            tasks.shutdown().await;
        }

        for m in &self.modules {
            m.finished();
        }

        if scan.status == ScanStatus::Running {
            scan.status = ScanStatus::Finished;
        }
        scan.finished_at = Some(Utc::now());

        if let Some(store) = &self.store {
            let _ = store
                .update_scan_status(
                    &sid,
                    scan.status.as_str(),
                    scan.event_count as i64,
                    scan.error_count as i64,
                    scan.finished_at.map(|t| t.to_rfc3339()).as_deref(),
                )
                .await;
        }
        if let Some(s) = &sink {
            s.on_finish(&scan);
        }

        Ok(ScanResult {
            scan,
            events: all_events,
        })
    }
}
