use crate::stats::ProxyStats;
use crate::ws::{ws_domains, WsFactory, WsTransport, WsConnectParams};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

type DcKey = (u8, bool);

struct PoolEntry {
    ws: Box<dyn WsTransport>,
    created: Instant,
}

pub struct WsPool {
    factory: WsFactory,
    idle: Mutex<HashMap<DcKey, Vec<PoolEntry>>>,
    pool_size: usize,
    max_age: Duration,
    dc_redirects: HashMap<u8, String>,
    stats: Arc<ProxyStats>,
    refilling: Mutex<HashSet<DcKey>>,
}

/// Resolve the target IP for a given DC/media pair.
/// Returns Some(ip) only if the user provided --dc-ip override.
/// Returns None otherwise — the caller should use DNS resolution.
pub fn resolve_dc_ip(dc: u8, _is_media: bool, dc_redirects: &HashMap<u8, String>) -> Option<String> {
    let dc_ws = crate::dc::dc_override(dc);
    dc_redirects.get(&dc_ws).cloned()
}

impl WsPool {
    pub fn new(
        factory: WsFactory,
        pool_size: usize,
        max_age: Duration,
        dc_redirects: HashMap<u8, String>,
        stats: Arc<ProxyStats>,
    ) -> Arc<Self> {
        Arc::new(Self {
            factory,
            idle: Mutex::new(HashMap::new()),
            pool_size,
            max_age,
            dc_redirects,
            stats,
            refilling: Mutex::new(HashSet::new()),
        })
    }

    /// Pop a healthy connection from the pool for the given DC/media key.
    /// Schedules a background refill if the bucket drops below pool_size.
    pub async fn get(self: &Arc<Self>, dc: u8, is_media: bool) -> Option<Box<dyn WsTransport>> {
        let key = (dc, is_media);
        let result = {
            let mut idle = self.idle.lock().await;
            let bucket = idle.entry(key).or_default();
            // Pop from the end, skipping stale or closed entries.
            loop {
                let entry = bucket.pop()?;
                if entry.ws.is_closed() || entry.created.elapsed() > self.max_age {
                    // discard and continue
                    continue;
                }
                break Some(entry.ws);
            }
        };

        // Schedule refill if we just consumed from (or depleted) the pool.
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.refill(dc, is_media).await;
        });

        if result.is_some() {
            self.stats.inc(&self.stats.pool_hits);
        } else {
            self.stats.inc(&self.stats.pool_misses);
        }

        result
    }

    /// Warm up the pool for a set of DC/media pairs in parallel.
    pub async fn warmup(self: &Arc<Self>, dcs: &[(u8, bool)]) {
        let mut handles = Vec::new();
        for &(dc, is_media) in dcs {
            let this = Arc::clone(self);
            handles.push(tokio::spawn(async move {
                this.refill(dc, is_media).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    }

    /// Returns which of the given DC/media keys have zero idle connections.
    pub async fn empty_keys(&self, keys: &[(u8, bool)]) -> Vec<(u8, bool)> {
        let idle = self.idle.lock().await;
        keys.iter()
            .copied()
            .filter(|k| idle.get(k).map(|b| b.is_empty()).unwrap_or(true))
            .collect()
    }

    /// Close all idle connections in the pool.
    pub async fn shutdown(&self) {
        let mut idle = self.idle.lock().await;
        for bucket in idle.values_mut() {
            for entry in bucket.iter_mut() {
                let _ = entry.ws.close().await;
            }
        }
        idle.clear();
    }

    /// Fill the pool bucket for a DC/media key up to pool_size.
    /// Prevents concurrent refills for the same key.
    async fn refill(&self, dc: u8, is_media: bool) {
        let key = (dc, is_media);

        // Guard: only one concurrent refill per key.
        {
            let mut refilling = self.refilling.lock().await;
            if refilling.contains(&key) {
                return;
            }
            refilling.insert(key);
        }

        let target_ip = resolve_dc_ip(dc, is_media, &self.dc_redirects);

        let domains = ws_domains(dc, is_media);

        // Determine how many connections to add.
        let needed = {
            let idle = self.idle.lock().await;
            let current = idle.get(&key).map(|b| b.len()).unwrap_or(0);
            self.pool_size.saturating_sub(current)
        };

        for _ in 0..needed {
            let mut connected = false;
            for domain in &domains {
                let params = WsConnectParams {
                    target_ip: target_ip.clone(),
                    domain: domain.clone(),
                    path: "/apiws".to_string(),
                };
                match tokio::time::timeout(
                    Duration::from_secs(10),
                    (self.factory)(params),
                ).await {
                    Ok(Ok(ws)) => {
                        let entry = PoolEntry {
                            ws,
                            created: Instant::now(),
                        };
                        let mut idle = self.idle.lock().await;
                        let bucket = idle.entry(key).or_default();
                        if bucket.len() < self.pool_size {
                            bucket.push(entry);
                            debug!("Pool refilled DC {dc} media={is_media}, size={}", bucket.len());
                        }
                        connected = true;
                        break;
                    }
                    Ok(Err(e)) => {
                        debug!("Pool refill failed for DC {dc} media={is_media} via {domain}: {e}");
                    }
                    Err(_) => {
                        debug!("Pool refill timed out for DC {dc} media={is_media} via {domain}");
                    }
                }
            }
            if !connected {
                warn!("Pool refill exhausted all domains for DC {dc} media={is_media}");
                break;
            }
            // Check if pool is already full (concurrent refill).
            let idle = self.idle.lock().await;
            if idle.get(&key).map(|b| b.len()).unwrap_or(0) >= self.pool_size {
                break;
            }
        }

        let mut refilling = self.refilling.lock().await;
        refilling.remove(&key);
    }
}
