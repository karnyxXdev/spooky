use super::*;
use spooky_config::runtime::RuntimeUpstreamPolicy;

pub(in crate::quic_listener) struct RouteResolutionRequest<'a> {
    pub(in crate::quic_listener) method: &'a str,
    pub(in crate::quic_listener) path: &'a str,
    pub(in crate::quic_listener) authority: Option<&'a str>,
    pub(in crate::quic_listener) cid_key: Option<&'a str>,
    pub(in crate::quic_listener) header_lookup: Option<&'a LbHeaderLookup<'a>>,
}

impl<'a> RouteResolutionRequest<'a> {
    pub(in crate::quic_listener) fn new(
        method: &'a str,
        path: &'a str,
        authority: Option<&'a str>,
        cid_key: Option<&'a str>,
        header_lookup: Option<&'a LbHeaderLookup<'a>>,
    ) -> Self {
        Self {
            method,
            path,
            authority,
            cid_key,
            header_lookup,
        }
    }
}

pub(crate) struct ResolvedRoute {
    pub(crate) upstream_name: String,
    pub(crate) upstream_pool: Arc<RwLock<UpstreamPool>>,
    pub(crate) upstream_policy: RuntimeUpstreamPolicy,
    pub(crate) route_path_len: usize,
    pub(crate) route_host_specific: bool,
    pub(crate) route_reason: RouteDecisionReason,
}

pub(crate) struct SelectedBackend {
    pub(crate) backend_addr: String,
    pub(crate) backend_index: usize,
    pub(crate) backend_lb: String,
}

pub(crate) struct ResolvedBackend {
    pub(crate) route: ResolvedRoute,
    pub(crate) backend: SelectedBackend,
}

struct BackendSelectionPlan {
    lb_type: String,
    lb_key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteResolutionFailureKind {
    NoRoute,
    MissingPool,
    PoolLockPoisoned,
    NoServers,
    NoHealthyServers,
    InvalidServerAddress,
    OtherTransport,
    Other,
}

impl QUICListener {
    fn classify_route_resolution_transport_reason(reason: &str) -> RouteResolutionFailureKind {
        if reason.starts_with("no route for ") {
            return RouteResolutionFailureKind::NoRoute;
        }
        if reason.starts_with("pool not found:") {
            return RouteResolutionFailureKind::MissingPool;
        }
        if reason == "upstream pool lock poisoned" {
            return RouteResolutionFailureKind::PoolLockPoisoned;
        }
        if reason == "no servers in upstream" {
            return RouteResolutionFailureKind::NoServers;
        }
        if reason == "no healthy servers" {
            return RouteResolutionFailureKind::NoHealthyServers;
        }
        if reason == "invalid server address" {
            return RouteResolutionFailureKind::InvalidServerAddress;
        }
        RouteResolutionFailureKind::OtherTransport
    }

    fn classify_route_resolution_failure(err: &ProxyError) -> RouteResolutionFailureKind {
        match err {
            ProxyError::Transport(reason) => {
                Self::classify_route_resolution_transport_reason(reason)
            }
            _ => RouteResolutionFailureKind::Other,
        }
    }

    fn log_route_resolution_failure(request: &RouteResolutionRequest<'_>, err: &ProxyError) {
        let authority = request.authority.unwrap_or("-");
        let failure_kind = Self::classify_route_resolution_failure(err);
        let message = format!(
            "route/backend resolution failed method={} path={} authority={} kind={:?}: {}",
            request.method, request.path, authority, failure_kind, err
        );
        match failure_kind {
            RouteResolutionFailureKind::NoRoute => debug!("{}", message),
            _ => warn!("{}", message),
        }
    }

    pub(in crate::quic_listener) fn observe_route_resolution_failure(
        request: &RouteResolutionRequest<'_>,
        err: &ProxyError,
        metrics: &Metrics,
        elapsed: Duration,
    ) {
        metrics.inc_failure();
        metrics.record_route("unrouted", elapsed, RouteOutcome::Failure);
        Self::log_route_resolution_failure(request, err);
    }

    pub(in crate::quic_listener) fn bootstrap_route_resolution_error_response(
        err: &ProxyError,
    ) -> (http::StatusCode, &'static [u8]) {
        match Self::classify_route_resolution_failure(err) {
            RouteResolutionFailureKind::NoRoute => (http::StatusCode::BAD_GATEWAY, b"no route\n"),
            RouteResolutionFailureKind::MissingPool => {
                (http::StatusCode::BAD_GATEWAY, b"no pool\n")
            }
            RouteResolutionFailureKind::PoolLockPoisoned => {
                (http::StatusCode::BAD_GATEWAY, b"pool error\n")
            }
            RouteResolutionFailureKind::NoServers
            | RouteResolutionFailureKind::InvalidServerAddress => {
                (http::StatusCode::SERVICE_UNAVAILABLE, b"no backends\n")
            }
            RouteResolutionFailureKind::NoHealthyServers => (
                http::StatusCode::SERVICE_UNAVAILABLE,
                b"no healthy backends\n",
            ),
            RouteResolutionFailureKind::OtherTransport | RouteResolutionFailureKind::Other => (
                http::StatusCode::BAD_GATEWAY,
                b"route/backend resolution failed\n",
            ),
        }
    }

    #[allow(clippy::type_complexity)]
    fn resolve_route_target(
        request: &RouteResolutionRequest<'_>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        upstream_policies: &HashMap<String, RuntimeUpstreamPolicy>,
        routing_index: &RouteIndex,
    ) -> Result<ResolvedRoute, ProxyError> {
        if request.method.is_empty() || request.path.is_empty() {
            return Err(ProxyError::Transport("empty method or path".into()));
        }

        let route_decision = routing_index
            .lookup_with_decision_for_method(request.path, request.authority, Some(request.method))
            .ok_or_else(|| ProxyError::Transport(format!("no route for {}", request.path)))?;
        let upstream_name = route_decision.upstream.to_string();
        let upstream_pool = upstream_pools
            .get(route_decision.upstream)
            .ok_or_else(|| ProxyError::Transport(format!("pool not found: {upstream_name}")))?
            .clone();
        let upstream_policy = upstream_policies
            .get(route_decision.upstream)
            .cloned()
            .unwrap_or_default();

        Ok(ResolvedRoute {
            upstream_name,
            upstream_pool,
            upstream_policy,
            route_path_len: route_decision.matched_path_len,
            route_host_specific: route_decision.host_specific,
            route_reason: route_decision.reason,
        })
    }

    fn build_backend_selection_plan(
        request: &RouteResolutionRequest<'_>,
        pool: &UpstreamPool,
    ) -> BackendSelectionPlan {
        let lb_type = pool.lb_name().to_string();
        let lb_key = Self::resolve_lb_request_key(
            &lb_type,
            pool.lb_key(),
            request.method,
            request.path,
            request.authority,
            request.cid_key,
            request.header_lookup,
        );
        BackendSelectionPlan { lb_type, lb_key }
    }

    fn no_servers_in_upstream_error() -> ProxyError {
        ProxyError::Transport("no servers in upstream".into())
    }

    fn no_healthy_servers_error(pool: &UpstreamPool) -> ProxyError {
        let total = pool.pool.len();
        let healthy = pool.pool.healthy_len();
        error!(
            "no healthy backends available: {}/{} backends healthy",
            healthy, total
        );
        ProxyError::Transport("no healthy servers".into())
    }

    fn select_backend_readonly(
        pool: &UpstreamPool,
        plan: &BackendSelectionPlan,
        begin_request: bool,
    ) -> Option<SelectedBackend> {
        if pool.pool.readmit_due() {
            return None;
        }

        pool.pick_readonly(plan.lb_key.as_str())
            .and_then(|idx| pool.pool.address(idx).map(|addr| (idx, addr.to_string())))
            .and_then(|(idx, addr)| {
                (!begin_request || pool.begin_request_if_healthy(idx)).then_some(SelectedBackend {
                    backend_addr: addr,
                    backend_index: idx,
                    backend_lb: plan.lb_type.clone(),
                })
            })
    }

    fn select_backend_with_write_lock(
        pool: &mut UpstreamPool,
        plan: &BackendSelectionPlan,
        begin_request: bool,
    ) -> Result<SelectedBackend, ProxyError> {
        let idx = if begin_request {
            pool.pick(plan.lb_key.as_str())
        } else {
            pool.pick_without_begin(plan.lb_key.as_str())
        }
        .ok_or_else(|| Self::no_healthy_servers_error(pool))?;
        let backend_addr = pool
            .pool
            .address(idx)
            .map(str::to_string)
            .ok_or_else(|| ProxyError::Transport("invalid server address".into()))?;
        Ok(SelectedBackend {
            backend_addr,
            backend_index: idx,
            backend_lb: plan.lb_type.clone(),
        })
    }

    fn select_backend_from_pool(
        request: &RouteResolutionRequest<'_>,
        upstream_pool: &Arc<RwLock<UpstreamPool>>,
        begin_request: bool,
    ) -> Result<SelectedBackend, ProxyError> {
        {
            let pool = upstream_pool
                .read()
                .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
            if pool.pool.is_empty() {
                return Err(Self::no_servers_in_upstream_error());
            }
            let plan = Self::build_backend_selection_plan(request, &pool);
            if let Some(selected) = Self::select_backend_readonly(&pool, &plan, begin_request) {
                return Ok(selected);
            }
        }

        let mut pool = upstream_pool
            .write()
            .map_err(|_| ProxyError::Transport("upstream pool lock poisoned".into()))?;
        if pool.pool.is_empty() {
            return Err(Self::no_servers_in_upstream_error());
        }
        let plan = Self::build_backend_selection_plan(request, &pool);
        Self::select_backend_with_write_lock(&mut pool, &plan, begin_request)
    }

    fn log_backend_selection(
        request: &RouteResolutionRequest<'_>,
        backend_addr: &str,
        lb_type: &str,
        upstream_name: &str,
        route_path_len: usize,
        route_host_specific: bool,
        route_reason: &RouteDecisionReason,
    ) {
        debug!(
            "Resolved backend method={} path={} authority={} route={} backend={} via={} path_len={} host_specific={} reason={:?}",
            request.method,
            request.path,
            request.authority.unwrap_or("-"),
            upstream_name,
            backend_addr,
            lb_type,
            route_path_len,
            route_host_specific,
            route_reason
        );
    }

    fn resolve_backend_internal(
        request: &RouteResolutionRequest<'_>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        upstream_policies: &HashMap<String, RuntimeUpstreamPolicy>,
        routing_index: &RouteIndex,
        begin_request: bool,
    ) -> Result<ResolvedBackend, ProxyError> {
        let route =
            Self::resolve_route_target(request, upstream_pools, upstream_policies, routing_index)?;
        let backend = Self::select_backend_from_pool(request, &route.upstream_pool, begin_request)?;

        Self::log_backend_selection(
            request,
            &backend.backend_addr,
            &backend.backend_lb,
            &route.upstream_name,
            route.route_path_len,
            route.route_host_specific,
            &route.route_reason,
        );
        Ok(ResolvedBackend { route, backend })
    }

    pub(super) fn resolve_backend_without_inflight_request(
        request: &RouteResolutionRequest<'_>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        upstream_policies: &HashMap<String, RuntimeUpstreamPolicy>,
        routing_index: &RouteIndex,
    ) -> Result<ResolvedBackend, ProxyError> {
        Self::resolve_backend_internal(
            request,
            upstream_pools,
            upstream_policies,
            routing_index,
            false,
        )
    }

    /// Resolve routing + LB for a request, returning `(backend_addr, backend_index, pool)`.
    pub(in crate::quic_listener) fn resolve_backend_request(
        request: &RouteResolutionRequest<'_>,
        upstream_pools: &HashMap<String, Arc<RwLock<UpstreamPool>>>,
        upstream_policies: &HashMap<String, RuntimeUpstreamPolicy>,
        routing_index: &RouteIndex,
    ) -> Result<ResolvedBackend, ProxyError> {
        Self::resolve_backend_internal(
            request,
            upstream_pools,
            upstream_policies,
            routing_index,
            true,
        )
    }
}
