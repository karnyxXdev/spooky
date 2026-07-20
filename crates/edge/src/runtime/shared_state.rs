use std::sync::Arc;

use crate::runtime::generation::{RuntimeGenerationState, RuntimeSharedServices};

pub struct SharedRuntimeState {
    pub(crate) shared_services: Arc<RuntimeSharedServices>,
    pub(crate) generation_state: Arc<RuntimeGenerationState>,
}

impl SharedRuntimeState {
    pub(crate) fn from_parts(
        shared_services: RuntimeSharedServices,
        generation_state: RuntimeGenerationState,
    ) -> Self {
        let shared_services = Arc::new(shared_services);
        let generation_state = Arc::new(generation_state);

        Self {
            shared_services,
            generation_state,
        }
    }

    pub fn shared_services(&self) -> &RuntimeSharedServices {
        self.shared_services.as_ref()
    }

    pub fn generation_state(&self) -> &RuntimeGenerationState {
        self.generation_state.as_ref()
    }

    pub fn bind_metrics_worker_slot(&self, slot: usize) {
        self.shared_services.metrics.bind_worker_slot(slot);
    }

    pub fn inc_ingress_queue_drop(&self) {
        self.shared_services.metrics.inc_ingress_queue_drop();
    }

    pub fn inc_ingress_queue_drop_bytes(&self, bytes: usize) {
        self.shared_services
            .metrics
            .inc_ingress_queue_drop_bytes(bytes);
    }

    pub fn set_ingress_queue_bytes(&self, bytes: usize) {
        self.shared_services.metrics.set_ingress_queue_bytes(bytes);
    }

    pub fn snapshot_backend_health(&self) -> (usize, usize) {
        let mut healthy = 0usize;
        let mut total = 0usize;

        for pool in self.generation_state.upstream_pools.values() {
            let guard = match pool.read() {
                Ok(guard) => guard,
                Err(_) => continue,
            };
            let pool_total = guard.pool.len();
            total = total.saturating_add(pool_total);
            healthy = healthy.saturating_add(guard.pool.healthy_len().min(pool_total));
        }

        (healthy, total)
    }
}
