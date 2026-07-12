pub mod backend;
pub mod backend_pool;
pub mod hash;
pub mod health;
pub mod load_balancing;
pub mod upstream_pool;

use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use rand::{Rng, SeedableRng, rngs::StdRng};
use spooky_config::config::{Backend, HealthCheck};

thread_local! {
    static LB_RANDOM_RNG: RefCell<StdRng> = RefCell::new(StdRng::from_entropy());
}

pub struct RoundRobin {
    next: usize,
    next_read: AtomicUsize,
}

impl RoundRobin {
    pub fn new() -> Self {
        Self {
            next: 0,
            next_read: AtomicUsize::new(0),
        }
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        if pool.healthy.is_empty() {
            return None;
        }

        let idx = pool.healthy[self.next % pool.healthy.len()];
        self.next = self.next.wrapping_add(1);
        Some(idx)
    }

    pub fn pick_readonly(&self, pool: &BackendPool) -> Option<usize> {
        if pool.healthy.is_empty() {
            return None;
        }

        let next = self.next_read.fetch_add(1, Ordering::Relaxed);
        let idx = pool.healthy[next % pool.healthy.len()];
        Some(idx)
    }
}

impl Default for RoundRobin {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ConsistentHash {
    replicas: u32,
    ring: Vec<(u64, usize)>,
    ring_epoch: Option<u64>,
    ring_rebuilds: u64,
}

impl ConsistentHash {
    pub fn new(replicas: u32) -> Self {
        Self {
            replicas: replicas.max(1),
            ring: Vec::new(),
            ring_epoch: None,
            ring_rebuilds: 0,
        }
    }

    pub fn pick(&mut self, key: &str, pool: &BackendPool) -> Option<usize> {
        if pool.is_empty() {
            return None;
        }

        let epoch = pool.membership_epoch();
        if self.ring_epoch != Some(epoch) {
            self.rebuild_ring(pool);
            self.ring_epoch = Some(epoch);
            self.ring_rebuilds = self.ring_rebuilds.wrapping_add(1);
        }

        if self.ring.is_empty() {
            return None;
        }

        let key_hash = hash64(key.as_bytes());
        let lookup_idx = match self.ring.binary_search_by(|(hash, _)| hash.cmp(&key_hash)) {
            Ok(idx) => idx,
            Err(idx) if idx < self.ring.len() => idx,
            Err(_) => 0,
        };

        Some(self.ring[lookup_idx].1)
    }

    fn rebuild_ring(&mut self, pool: &BackendPool) {
        self.ring.clear();

        let expected = expected_ring_entries(pool, self.replicas);
        if self.ring.capacity() < expected {
            self.ring.reserve(expected - self.ring.capacity());
        }

        for &idx in &pool.healthy {
            let backend = &pool.backends[idx];
            let replicas = self.replicas.saturating_mul(backend.weight());
            for replica in 0..replicas {
                self.ring
                    .push((hash_backend_replica(backend.address(), replica), idx));
            }
        }

        self.ring.sort_unstable();
    }
}

pub struct Random;

impl Random {
    pub fn new() -> Self {
        Self
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        self.pick_readonly(pool)
    }

    pub fn pick_readonly(&self, pool: &BackendPool) -> Option<usize> {
        if pool.healthy.is_empty() {
            return None;
        }

        let idx = LB_RANDOM_RNG.with(|state| {
            let mut rng = state.borrow_mut();
            rng.gen_range(0..pool.healthy.len())
        });
        Some(pool.healthy[idx])
    }
}

impl Default for Random {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LeastConnections;

impl LeastConnections {
    pub fn new() -> Self {
        Self
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        self.pick_readonly(pool)
    }

    pub fn pick_readonly(&self, pool: &BackendPool) -> Option<usize> {
        let mut best: Option<(usize, usize)> = None;
        for &idx in &pool.healthy {
            let active = pool.backends[idx].active_requests();
            match best {
                Some((best_active, best_idx)) => {
                    if active < best_active || (active == best_active && idx < best_idx) {
                        best = Some((active, idx));
                    }
                }
                None => best = Some((active, idx)),
            }
        }
        best.map(|(_, idx)| idx)
    }
}

impl Default for LeastConnections {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LatencyAware;

impl LatencyAware {
    pub fn new() -> Self {
        Self
    }

    pub fn pick(&mut self, pool: &BackendPool) -> Option<usize> {
        self.pick_readonly(pool)
    }

    pub fn pick_readonly(&self, pool: &BackendPool) -> Option<usize> {
        let mut unsampled_best: Option<(usize, usize)> = None;
        let mut sampled_best: Option<(f64, usize, usize)> = None;

        for &idx in &pool.healthy {
            let backend = &pool.backends[idx];
            let active = backend.active_requests();
            if let Some(ewma) = backend.ewma_latency_ms() {
                let score = ewma + (active as f64 * 10.0);
                match sampled_best {
                    Some((best_score, best_active, best_idx)) => {
                        if score < best_score
                            || (score == best_score
                                && (active < best_active
                                    || (active == best_active && idx < best_idx)))
                        {
                            sampled_best = Some((score, active, idx));
                        }
                    }
                    None => sampled_best = Some((score, active, idx)),
                }
            } else {
                match unsampled_best {
                    Some((best_active, best_idx)) => {
                        if active < best_active || (active == best_active && idx < best_idx) {
                            unsampled_best = Some((active, idx));
                        }
                    }
                    None => unsampled_best = Some((active, idx)),
                }
            }
        }

        if let Some((_, idx)) = unsampled_best {
            return Some(idx);
        }
        sampled_best.map(|(_, _, idx)| idx)
    }
}

impl Default for LatencyAware {
    fn default() -> Self {
        Self::new()
    }
}

pub struct StickyCid {
    inner: ConsistentHash,
}

impl StickyCid {
    pub fn new(replicas: u32) -> Self {
        Self {
            inner: ConsistentHash::new(replicas),
        }
    }

    pub fn pick(&mut self, key: &str, pool: &BackendPool) -> Option<usize> {
        if key.is_empty() {
            return pool.healthy.first().copied();
        }
        self.inner.pick(key, pool)
    }
}
