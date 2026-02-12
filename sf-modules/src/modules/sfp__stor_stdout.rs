//! sfp__stor_stdout — internal stdout/tab/csv/json streaming sink.
//!
//! CLI output streaming is handled by the binary's `EventSink`; this module
//! exists for upstream catalog parity and is a no-op.

use crate::prelude::*;

#[derive(Default)]
pub struct SfpStorStdout;

#[async_trait]
impl Module for SfpStorStdout {
    fn name(&self) -> &'static str {
        "sfp__stor_stdout"
    }
    fn descr(&self) -> &'static str {
        "Streams scan results to stdout in tab/csv/json (internal, CLI mode)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[]
    }
    async fn handle_event(&self, _evt: &SfEvent, _ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        Ok(Vec::new())
    }
}

register_module!("sfp__stor_stdout", SfpStorStdout);
