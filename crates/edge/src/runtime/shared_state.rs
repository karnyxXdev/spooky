use crate::Metrics;
use crate::resilience::runtime::RuntimeResilience;
use crate::routing::index::RouteIndex;
use crate::runtime::backend::store::RuntimeBackendResolutionStore;
use crate::runtime::tasks::RuntimeTaskRegistry;
use crate::runtime::tls::store::ListenerTlsReloadStore;
use crate::watchdog::coordinator::WatchdogCoordinator;
use spooky_config::backend_endpoint::BackendEndpoint;
use spooky_config::runtime::{ListenerRuntimeConfig, RuntimeUpstreamPolicy};
use spooky_lb::upstream_pool::UpstreamPool;
use spooky_transport::h2_client::SharedDnsResolver;
use spooky_transport::transport_pool::UpstreamTransportPool;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::Semaphore;

pub struct SharedRuntimeState {
    pub(crate) listener_runtime_configs: Arc<HashMap<String, ListenerRuntimeConfig>>,
    pub(crate) listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub(crate) transport_pool: Arc<UpstreamTransportPool>,
    pub(crate) backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub(crate) backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    pub(crate) backend_dns_resolver: SharedDnsResolver,
    pub(crate) upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub(crate) upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub(crate) upstream_inflight: HashMap<String, Arc<Semaphore>>,
    pub(crate) global_inflight: Arc<Semaphore>,
    pub(crate) routing_index: Arc<RouteIndex>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) resilience: Arc<RuntimeResilience>,
    pub(crate) watchdog: Arc<WatchdogCoordinator>,
    pub(crate) generation_tasks: Arc<RuntimeTaskRegistry>,
}

impl SharedRuntimeState {
    pub fn bind_metrics_worker_slot(&self, slot: usize) {
        self.metrics.bind_worker_slot(slot);
    }

    pub fn inc_ingress_queue_drop(&self) {
        self.metrics.inc_ingress_queue_drop();
    }

    pub fn inc_ingress_queue_drop_bytes(&self, bytes: usize) {
        self.metrics.inc_ingress_queue_drop_bytes(bytes);
    }

    pub fn set_ingress_queue_bytes(&self, bytes: usize) {
        self.metrics.set_ingress_queue_bytes(bytes);
    }

    pub fn snapshot_backend_health(&self) -> (usize, usize) {
        let mut healthy = 0usize;
        let mut total = 0usize;

        for pool in self.upstream_pools.values() {
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
