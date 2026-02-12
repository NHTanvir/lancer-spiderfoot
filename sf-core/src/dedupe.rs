//! Per-scan event deduplication.
//!
//! Exact `DashSet` membership up to a threshold (default 10k events), then a
//! self-contained bloom filter for an orders-of-magnitude memory win on huge
//! scans (accepting a rare duplicate emission at the configured FP rate).

use dashmap::DashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// A minimal, dependency-free bloom filter over pre-hashed `u64` keys.
struct Bloom {
    bits: Vec<u64>,
    nbits: u64,
    k: u32,
}

impl Bloom {
    fn new(expected: usize, fp_rate: f64) -> Self {
        let n = expected.max(1) as f64;
        let ln2 = std::f64::consts::LN_2;
        let m = (-(n * fp_rate.ln()) / (ln2 * ln2)).ceil().max(64.0) as u64;
        let k = ((m as f64 / n) * ln2).round().clamp(1.0, 32.0) as u32;
        Bloom {
            bits: vec![0u64; ((m + 63) / 64) as usize],
            nbits: m,
            k,
        }
    }

    #[inline]
    fn bit_index(&self, h: u64, i: u32) -> u64 {
        let h1 = h;
        let h2 = h.rotate_left(32) | 1;
        h1.wrapping_add((i as u64).wrapping_mul(h2)) % self.nbits
    }

    fn set(&mut self, h: u64) {
        for i in 0..self.k {
            let b = self.bit_index(h, i);
            self.bits[(b / 64) as usize] |= 1u64 << (b % 64);
        }
    }

    fn check(&self, h: u64) -> bool {
        (0..self.k).all(|i| {
            let b = self.bit_index(h, i);
            self.bits[(b / 64) as usize] & (1u64 << (b % 64)) != 0
        })
    }
}

/// Deduplicates event hashes for a single scan.
pub struct Dedupe {
    seen: DashSet<u64>,
    bloom: Mutex<Bloom>,
    count: AtomicU64,
    threshold: u64,
}

impl Default for Dedupe {
    fn default() -> Self {
        Self::new()
    }
}

impl Dedupe {
    pub fn new() -> Self {
        Dedupe {
            seen: DashSet::new(),
            bloom: Mutex::new(Bloom::new(1_000_000, 0.01)),
            count: AtomicU64::new(0),
            threshold: 10_000,
        }
    }

    /// Insert a hash. Returns `true` if it was not seen before.
    pub fn insert(&self, hash: u64) -> bool {
        let c = self.count.load(Ordering::Relaxed);
        if c < self.threshold {
            let is_new = self.seen.insert(hash);
            if is_new {
                self.count.fetch_add(1, Ordering::Relaxed);
            }
            is_new
        } else {
            if self.seen.contains(&hash) {
                return false;
            }
            let mut b = self.bloom.lock().expect("bloom poisoned");
            if b.check(hash) {
                return false;
            }
            b.set(hash);
            self.count.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    /// Whether a hash has (probably) been seen.
    pub fn contains(&self, hash: u64) -> bool {
        if self.seen.contains(&hash) {
            return true;
        }
        if self.count.load(Ordering::Relaxed) >= self.threshold {
            return self.bloom.lock().expect("bloom poisoned").check(hash);
        }
        false
    }

    pub fn len(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
