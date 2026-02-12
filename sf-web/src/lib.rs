//! `sf-web` — axum web UI + REST API over the `sf-core` scan engine.

pub mod api;
pub mod pages;
pub mod state;

pub use state::AppState;

use axum::routing::{get, post};
use axum::Router;
use std::net::SocketAddr;

/// Build the full application router (UI pages + REST API).
pub fn router() -> Router {
    let state = AppState::default();
    Router::new()
        .route("/", get(pages::index))
        .route("/scan/:id", get(pages::scan_page))
        .route("/modules", get(pages::modules_page))
        .route("/settings", get(pages::settings_page))
        .route("/correlations", get(pages::correlations_page))
        .route("/api/scan", post(api::create_scan))
        .route("/api/scan/:id", get(api::get_scan))
        .route("/api/scan/:id/events", get(api::list_events))
        .route("/api/scan/:id/events/stream", get(api::stream_events))
        .route("/api/scan/:id/graph", get(api::scan_graph))
        .route("/api/scan/:id/abort", post(api::abort_scan))
        .route("/api/scan/:id/correlate", post(api::correlate))
        .route("/api/correlate/:id", post(api::correlate))
        .route("/api/modules", get(api::list_modules))
        .route("/api/types", get(api::list_types))
        .with_state(state)
}

/// Serve the web UI on `addr` until the process exits.
pub async fn serve(addr: SocketAddr) -> std::io::Result<()> {
    let app = router();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("lancer-spiderfoot web UI listening on http://{addr}");
    axum::serve(listener, app).await
}
