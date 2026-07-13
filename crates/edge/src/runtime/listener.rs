use crate::Metrics;
use crate::cid_radix::CidRadix;
use crate::constants::MAX_DATAGRAM_SIZE_BYTES;
use crate::resilience::runtime::RuntimeResilience;
use crate::routing::index::RouteIndex;
use crate::runtime::backend::store::RuntimeBackendResolutionStore;
use crate::runtime::bundle::RuntimeBundleHandle;
use crate::runtime::connection::quic::QuicConnection;
use crate::runtime::tls::store::ListenerTlsReloadStore;
use crate::watchdog::coordinator::WatchdogCoordinator;
use spooky_config::backend_endpoint::BackendEndpoint;
use spooky_config::runtime::ListenerRuntimeConfig;
use spooky_config::runtime::RuntimeUpstreamPolicy;
use spooky_lb::upstream_pool::UpstreamPool;
use spooky_transport::h2_client::SharedDnsResolver;
use spooky_transport::transport_pool::UpstreamTransportPool;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

pub struct QUICListener {
    pub socket: UdpSocket,
    pub local_addr: SocketAddr,
    pub config: ListenerRuntimeConfig,
    pub listener_label: String,
    pub listener_tls_store: Arc<ListenerTlsReloadStore>,
    pub tls_reload_generation: u64,
    pub runtime_bundle: Option<Arc<RuntimeBundleHandle>>,
    pub runtime_generation: u64,
    pub quic_config: quiche::Config,
    pub h3_config: Arc<quiche::h3::Config>,
    pub transport_pool: Arc<UpstreamTransportPool>,
    pub backend_endpoints: Arc<HashMap<String, BackendEndpoint>>,
    pub backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
    pub backend_dns_resolver: SharedDnsResolver,
    pub upstream_policies: Arc<HashMap<String, RuntimeUpstreamPolicy>>,
    pub upstream_pools: HashMap<String, Arc<RwLock<UpstreamPool>>>,
    pub upstream_inflight: HashMap<String, Arc<Semaphore>>,
    pub global_inflight: Arc<Semaphore>,
    pub(crate) routing_index: Arc<RouteIndex>,
    pub metrics: Arc<Metrics>,
    pub resilience: Arc<RuntimeResilience>,
    pub watchdog: Arc<WatchdogCoordinator>,
    pub draining: bool,
    pub drain_start: Option<Instant>,
    pub watchdog_worker_drained: bool,
    pub drain_timeout: Duration,
    pub backend_timeout: Duration,
    pub backend_body_idle_timeout: Duration,
    pub backend_body_total_timeout: Duration,
    pub client_body_idle_timeout: Duration,
    pub backend_total_request_timeout: Duration,
    pub inflight_acquire_wait: Duration,
    pub max_active_connections: usize,
    pub max_streams_per_connection: usize,
    pub max_request_body_bytes: usize,
    pub max_response_body_bytes: usize,
    pub request_buffer_global_cap_bytes: usize,
    pub unknown_length_response_prebuffer_bytes: usize,
    pub require_client_cert: bool,

    pub(crate) recv_buf: Box<[u8; MAX_DATAGRAM_SIZE_BYTES]>,
    pub(crate) send_buf: Box<[u8; MAX_DATAGRAM_SIZE_BYTES]>,

    pub(crate) connections: HashMap<Arc<[u8]>, QuicConnection>, // KEY: SCID(server connection id)
    pub(crate) cid_routes: HashMap<Arc<[u8]>, Arc<[u8]>>, // KEY: alias SCID, VALUE: primary SCID
    pub(crate) peer_routes: HashMap<SocketAddr, Arc<[u8]>>, // KEY: peer address, VALUE: primary SCID
    pub(crate) cid_radix: CidRadix,
    pub(crate) conn_rate_limiter: crate::quic_listener::TokenBucket,
}

impl QUICListener {
    pub fn connections(&self) -> &HashMap<Arc<[u8]>, QuicConnection> {
        &self.connections
    }

    pub fn cid_routes(&self) -> &HashMap<Arc<[u8]>, Arc<[u8]>> {
        &self.cid_routes
    }

    pub fn peer_routes(&self) -> &HashMap<SocketAddr, Arc<[u8]>> {
        &self.peer_routes
    }

    pub fn cid_radix(&self) -> &CidRadix {
        &self.cid_radix
    }
}
