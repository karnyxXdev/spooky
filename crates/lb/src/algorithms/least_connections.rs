use crate::backend_pool::BackendPool;

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
