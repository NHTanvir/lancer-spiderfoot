//! Per-source rate limiting via `governor`.
//!
//! Defaults are derived from upstream's empirical table; users can override
//! per source. A module awaits `until_ready(source)` before each request.

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Build a quota allowing one request every `period`.
fn every(period: Duration) -> Quota {
    Quota::with_period(period)
        .unwrap_or_else(|| Quota::per_second(NonZeroU32::new(1).unwrap()))
}

/// Per-source defaults (min interval between calls).
fn default_period(source: &str) -> Duration {
    match source {
        "sfp_haveibeenpwned" | "hibp" => Duration::from_millis(1500),
        "sfp_shodan" | "shodan" => Duration::from_secs(1),
        "sfp_virustotal" | "virustotal" => Duration::from_millis(15_000),
        "sfp_hackertarget" | "hackertarget" => Duration::from_millis(500),
        "sfp_crtsh" | "crtsh" => Duration::from_millis(400),
        "sfp_censys" | "censys" => Duration::from_millis(500),
        "sfp_github" | "github" => Duration::from_millis(800),
        _ => Duration::from_millis(200),
    }
}

/// A registry of per-source rate limiters.
#[derive(Default)]
pub struct RateLimiters {
    limiters: DashMap<String, Arc<DirectLimiter>>,
    overrides: DashMap<String, Duration>,
}

impl RateLimiters {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the min interval for a source.
    pub fn set_period(&self, source: &str, period: Duration) {
        self.overrides.insert(source.to_string(), period);
        self.limiters.remove(source);
    }

    fn limiter(&self, source: &str) -> Arc<DirectLimiter> {
        if let Some(l) = self.limiters.get(source) {
            return l.clone();
        }
        let period = self
            .overrides
            .get(source)
            .map(|p| *p)
            .unwrap_or_else(|| default_period(source));
        let limiter = Arc::new(RateLimiter::direct(every(period)));
        self.limiters.insert(source.to_string(), limiter.clone());
        limiter
    }

    /// Wait until the source's limiter permits another request.
    pub async fn until_ready(&self, source: &str) {
        let limiter = self.limiter(source);
        limiter.until_ready().await;
    }
}
