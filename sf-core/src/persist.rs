//! SQLite persistence via `sqlx` (runtime queries, WAL mode).
//!
//! One DB file per scan under the spiderfoot data dir, matching upstream's
//! per-scan layout. Uses runtime (non-macro) queries so no live DB is needed
//! at compile time.

use crate::error::Result;
use crate::event::SfEvent;
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::str::FromStr;

/// A row read back from the events table.
#[derive(Debug, Clone, Serialize)]
pub struct EventRow {
    #[serde(rename = "type")]
    pub type_: String,
    pub data: String,
    pub module: String,
    pub source_event: Option<i64>,
    pub confidence: i64,
    pub visibility: i64,
    pub risk: String,
    pub generated_at: String,
    pub hash: i64,
}

/// The per-scan SQLite store.
#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    /// Open (creating if needed) a per-scan DB file with WAL journaling.
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await?;
        let store = Store { pool };
        store.init().await?;
        Ok(store)
    }

    /// An in-memory store (tests / ephemeral CLI runs).
    pub async fn open_memory() -> Result<Self> {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")?;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await?;
        let store = Store { pool };
        store.init().await?;
        Ok(store)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn init(&self) -> Result<()> {
        let stmts = [
            "CREATE TABLE IF NOT EXISTS scan_meta (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                modules TEXT NOT NULL DEFAULT ''
            )",
            "CREATE TABLE IF NOT EXISTS events (
                scan_id TEXT NOT NULL,
                hash INTEGER NOT NULL,
                type TEXT NOT NULL,
                data TEXT NOT NULL,
                module TEXT NOT NULL,
                source_event INTEGER,
                confidence INTEGER NOT NULL,
                visibility INTEGER NOT NULL,
                risk TEXT NOT NULL,
                generated_at TEXT NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS idx_events_scan ON events(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_type ON events(scan_id, type)",
            "CREATE TABLE IF NOT EXISTS event_links (
                scan_id TEXT NOT NULL,
                parent_hash INTEGER NOT NULL,
                child_hash INTEGER NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS module_status (
                scan_id TEXT NOT NULL,
                module TEXT NOT NULL,
                events_produced INTEGER NOT NULL DEFAULT 0,
                last_success TEXT,
                PRIMARY KEY (scan_id, module)
            )",
            "CREATE TABLE IF NOT EXISTS module_errors (
                scan_id TEXT NOT NULL,
                module TEXT NOT NULL,
                error TEXT NOT NULL,
                occurred_at TEXT NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS correlation_results (
                scan_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                risk TEXT NOT NULL,
                event_hash INTEGER,
                created_at TEXT NOT NULL
            )",
        ];
        for s in stmts {
            sqlx::query(s).execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn insert_scan(
        &self,
        scan_id: &str,
        target: &str,
        target_type: &str,
        started_at: &str,
        status: &str,
        modules: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO scan_meta
             (scan_id, target, target_type, started_at, status, modules)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(scan_id)
        .bind(target)
        .bind(target_type)
        .bind(started_at)
        .bind(status)
        .bind(modules)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_scan_status(
        &self,
        scan_id: &str,
        status: &str,
        event_count: i64,
        error_count: i64,
        finished_at: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE scan_meta SET status = ?, event_count = ?, error_count = ?, finished_at = ?
             WHERE scan_id = ?",
        )
        .bind(status)
        .bind(event_count)
        .bind(error_count)
        .bind(finished_at)
        .bind(scan_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_event(&self, scan_id: &str, evt: &SfEvent) -> Result<()> {
        sqlx::query(
            "INSERT INTO events
             (scan_id, hash, type, data, module, source_event, confidence, visibility, risk, generated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(scan_id)
        .bind(evt.hash as i64)
        .bind(evt.type_.as_str())
        .bind(&evt.data)
        .bind(&evt.module)
        .bind(evt.source_event.map(|s| s as i64))
        .bind(evt.confidence as i64)
        .bind(evt.visibility as i64)
        .bind(evt.risk.as_str())
        .bind(evt.generated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        if let Some(parent) = evt.source_event {
            sqlx::query(
                "INSERT INTO event_links (scan_id, parent_hash, child_hash) VALUES (?, ?, ?)",
            )
            .bind(scan_id)
            .bind(parent as i64)
            .bind(evt.hash as i64)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn insert_correlation(
        &self,
        scan_id: &str,
        rule_id: &str,
        title: &str,
        risk: &str,
        event_hash: Option<i64>,
        created_at: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO correlation_results (scan_id, rule_id, title, risk, event_hash, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(scan_id)
        .bind(rule_id)
        .bind(title)
        .bind(risk)
        .bind(event_hash)
        .bind(created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn count_events(&self, scan_id: &str) -> Result<i64> {
        let row = sqlx::query("SELECT COUNT(*) as n FROM events WHERE scan_id = ?")
            .bind(scan_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get::<i64, _>("n")?)
    }

    pub async fn list_events(
        &self,
        scan_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<EventRow>> {
        let rows = sqlx::query(
            "SELECT type, data, module, source_event, confidence, visibility, risk, generated_at, hash
             FROM events WHERE scan_id = ? ORDER BY rowid LIMIT ? OFFSET ?",
        )
        .bind(scan_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(EventRow {
                type_: r.try_get("type")?,
                data: r.try_get("data")?,
                module: r.try_get("module")?,
                source_event: r.try_get("source_event")?,
                confidence: r.try_get("confidence")?,
                visibility: r.try_get("visibility")?,
                risk: r.try_get("risk")?,
                generated_at: r.try_get("generated_at")?,
                hash: r.try_get("hash")?,
            });
        }
        Ok(out)
    }
}
