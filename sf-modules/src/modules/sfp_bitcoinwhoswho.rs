//! sfp_bitcoinwhoswho — sfp_bitcoinwhoswho — OSINT source module (crypto group).

use crate::prelude::*;

#[derive(Default)]
pub struct SfpBitcoinwhoswho;

#[async_trait]
impl Module for SfpBitcoinwhoswho {
    fn name(&self) -> &'static str {
        "sfp_bitcoinwhoswho"
    }
    fn descr(&self) -> &'static str {
        "sfp_bitcoinwhoswho — OSINT source module (crypto group)."
    }
    fn categories(&self) -> &'static [Category] {
        &[Category::Passive]
    }
    fn flags(&self) -> &'static [ModuleFlag] {
        &[]
    }
    fn watched_events(&self) -> &'static [EventType] {
        &[EventType::BITCOIN_ADDRESS, EventType::ETHEREUM_ADDRESS]
    }
    fn produced_events(&self) -> &'static [EventType] {
        &[EventType::BITCOIN_BALANCE, EventType::RAW_RIR_DATA]
    }
    async fn handle_event(&self, _evt: &SfEvent, ctx: &ScanContext) -> Result<Vec<SfEvent>> {
        let _ = ctx;
        // TODO: implement the sfp_bitcoinwhoswho lookup.
        Ok(Vec::new())
    }
}

register_module!("sfp_bitcoinwhoswho", SfpBitcoinwhoswho);
