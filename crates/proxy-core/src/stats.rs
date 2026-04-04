use std::sync::atomic::{AtomicU64, Ordering};

pub struct ProxyStats {
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub connections_ws: AtomicU64,
    pub connections_tcp_fallback: AtomicU64,
    pub connections_bad: AtomicU64,
    pub ws_errors: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub pool_hits: AtomicU64,
    pub pool_misses: AtomicU64,
}

impl ProxyStats {
    pub fn new() -> Self {
        Self {
            connections_total: AtomicU64::new(0),
            connections_active: AtomicU64::new(0),
            connections_ws: AtomicU64::new(0),
            connections_tcp_fallback: AtomicU64::new(0),
            connections_bad: AtomicU64::new(0),
            ws_errors: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            pool_hits: AtomicU64::new(0),
            pool_misses: AtomicU64::new(0),
        }
    }

    pub fn inc(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self, counter: &AtomicU64) {
        counter.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add(&self, counter: &AtomicU64, val: u64) {
        counter.fetch_add(val, Ordering::Relaxed);
    }

    pub fn get(&self, counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

impl Default for ProxyStats {
    fn default() -> Self {
        Self::new()
    }
}
