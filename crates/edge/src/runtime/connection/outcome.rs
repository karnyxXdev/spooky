use std::{
    sync::{Arc, RwLock},
    time::Duration,
};

use http::StatusCode;
use log::{error, info};
use spooky_errors::{ClassifiedUpstreamProxyError, PoolError, ProxyError};
use spooky_lb::{
    backend::HealthTransition, health::HealthFailureReason, upstream_pool::UpstreamPool,
};

use crate::{Metrics, OverloadShedReason, RouteOutcome, runtime::health::outcome_from_status};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalRouteOutcome {
    Success,
    UpstreamFailure,
    Timeout,
    OverloadShed,
    RateLimited,
    AuthDenied,
    Unrouted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalBackendOutcome {
    Success,
    UpstreamFailure,
    Timeout,
    OverloadShed,
    RateLimited,
    AuthDenied,
    Unrouted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeStatusClass {
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
    Other,
}

impl From<StatusCode> for OutcomeStatusClass {
    fn from(status: StatusCode) -> Self {
        match status.as_u16() {
            100..=199 => Self::Informational,
            200..=299 => Self::Success,
            300..=399 => Self::Redirection,
            400..=499 => Self::ClientError,
            500..=599 => Self::ServerError,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutcomeResultClass {
    HttpStatus(OutcomeStatusClass),
    UpstreamError,
    Timeout,
    Overload,
    RateLimited,
    AuthDenied,
    Unrouted,
    InternalError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthEffectHint {
    None,
    Success,
    Neutral,
    Failure { reason: HealthFailureReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeRouteTarget<'a> {
    pub route: &'a str,
}

impl<'a> OutcomeRouteTarget<'a> {
    pub const UNROUTED: Self = Self { route: "unrouted" };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutcomeBackendTarget<'a> {
    pub upstream: &'a str,
    pub backend_addr: Option<&'a str>,
    pub backend_index: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestOutcomeInput<'a> {
    pub request_outcome: CanonicalRouteOutcome,
    pub route_target: OutcomeRouteTarget<'a>,
    pub backend_target: Option<OutcomeBackendTarget<'a>>,
    pub elapsed: Duration,
    pub result_class: OutcomeResultClass,
    pub overload_reason: Option<OverloadShedReason>,
    pub health_effect: HealthEffectHint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestOutcomeDecision {
    pub route_outcome: CanonicalRouteOutcome,
    pub backend_outcome: CanonicalBackendOutcome,
    pub overload_reason: Option<OverloadShedReason>,
    pub health_effect: HealthEffectHint,
}

#[derive(Clone, Copy, Debug)]
pub struct RequestMetricsObservation<'a> {
    pub route_target: OutcomeRouteTarget<'a>,
    pub backend_target: Option<OutcomeBackendTarget<'a>>,
    pub elapsed: Duration,
    pub status: Option<u16>,
    pub metrics_outcome: RouteOutcome,
    pub overload_reason: Option<OverloadShedReason>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionOutcomeClass {
    AuthDenied,
    RateLimited,
    OverloadShed {
        reason: Option<OverloadShedReason>,
    },
    Failed {
        timed_out: bool,
    },
}

impl CanonicalRouteOutcome {
    pub fn as_metrics_outcome(self) -> RouteOutcome {
        match self {
            Self::Success => RouteOutcome::Success,
            Self::UpstreamFailure | Self::AuthDenied | Self::Unrouted => RouteOutcome::Failure,
            Self::Timeout => RouteOutcome::Timeout,
            Self::OverloadShed => RouteOutcome::OverloadShed,
            Self::RateLimited => RouteOutcome::RateLimited,
        }
    }
}

impl CanonicalBackendOutcome {
    fn from_route_outcome(outcome: CanonicalRouteOutcome) -> Self {
        match outcome {
            CanonicalRouteOutcome::Success => Self::Success,
            CanonicalRouteOutcome::UpstreamFailure => Self::UpstreamFailure,
            CanonicalRouteOutcome::Timeout => Self::Timeout,
            CanonicalRouteOutcome::OverloadShed => Self::OverloadShed,
            CanonicalRouteOutcome::RateLimited => Self::RateLimited,
            CanonicalRouteOutcome::AuthDenied => Self::AuthDenied,
            CanonicalRouteOutcome::Unrouted => Self::Unrouted,
        }
    }
}

fn health_effect_from_status_class(status_class: OutcomeStatusClass) -> HealthEffectHint {
    match status_class {
        OutcomeStatusClass::ServerError => HealthEffectHint::Failure {
            reason: HealthFailureReason::HttpStatus5xx,
        },
        OutcomeStatusClass::ClientError => HealthEffectHint::Neutral,
        OutcomeStatusClass::Informational
        | OutcomeStatusClass::Success
        | OutcomeStatusClass::Redirection => HealthEffectHint::Success,
        OutcomeStatusClass::Other => HealthEffectHint::None,
    }
}

pub fn classify_status_outcome(status: StatusCode) -> RequestOutcomeDecision {
    let status_class = OutcomeStatusClass::from(status);
    let route_outcome = match status_class {
        OutcomeStatusClass::Informational
        | OutcomeStatusClass::Success
        | OutcomeStatusClass::Redirection => CanonicalRouteOutcome::Success,
        OutcomeStatusClass::ClientError => CanonicalRouteOutcome::UpstreamFailure,
        OutcomeStatusClass::ServerError => CanonicalRouteOutcome::UpstreamFailure,
        OutcomeStatusClass::Other => CanonicalRouteOutcome::UpstreamFailure,
    };

    RequestOutcomeDecision {
        route_outcome,
        backend_outcome: CanonicalBackendOutcome::from_route_outcome(route_outcome),
        overload_reason: None,
        health_effect: health_effect_from_status_class(status_class),
    }
}

pub fn classify_proxy_error_outcome(
    err: &ProxyError,
    overload_reason: Option<OverloadShedReason>,
) -> RequestOutcomeDecision {
    let (route_outcome, health_effect) = match err {
        ProxyError::Timeout => (
            CanonicalRouteOutcome::Timeout,
            HealthEffectHint::Failure {
                reason: HealthFailureReason::Timeout,
            },
        ),
        ProxyError::Pool(PoolError::BackendOverloaded(_))
        | ProxyError::Pool(PoolError::CircuitOpen(_)) => {
            (CanonicalRouteOutcome::OverloadShed, HealthEffectHint::None)
        }
        ProxyError::Pool(PoolError::InflightLimiterClosed)
        | ProxyError::Pool(PoolError::UnknownBackend(_)) => {
            (CanonicalRouteOutcome::UpstreamFailure, HealthEffectHint::None)
        }
        ProxyError::Pool(PoolError::Send(_)) => (
            CanonicalRouteOutcome::UpstreamFailure,
            HealthEffectHint::Failure {
                reason: HealthFailureReason::Transport,
            },
        ),
        ProxyError::Transport(_) | ProxyError::Protocol(_) => (
            CanonicalRouteOutcome::UpstreamFailure,
            HealthEffectHint::Failure {
                reason: HealthFailureReason::Transport,
            },
        ),
        ProxyError::Tls(_) => (CanonicalRouteOutcome::UpstreamFailure, HealthEffectHint::None),
        ProxyError::Bridge(_) => (CanonicalRouteOutcome::UpstreamFailure, HealthEffectHint::None),
    };

    RequestOutcomeDecision {
        route_outcome,
        backend_outcome: CanonicalBackendOutcome::from_route_outcome(route_outcome),
        overload_reason,
        health_effect,
    }
}

pub fn classify_admission_outcome(outcome: AdmissionOutcomeClass) -> RequestOutcomeDecision {
    let (route_outcome, overload_reason) = match outcome {
        AdmissionOutcomeClass::AuthDenied => (CanonicalRouteOutcome::AuthDenied, None),
        AdmissionOutcomeClass::RateLimited => (CanonicalRouteOutcome::RateLimited, None),
        AdmissionOutcomeClass::OverloadShed { reason } => {
            (CanonicalRouteOutcome::OverloadShed, reason)
        }
        AdmissionOutcomeClass::Failed { timed_out } => (
            if timed_out {
                CanonicalRouteOutcome::Timeout
            } else {
                CanonicalRouteOutcome::UpstreamFailure
            },
            None,
        ),
    };

    RequestOutcomeDecision {
        route_outcome,
        backend_outcome: CanonicalBackendOutcome::from_route_outcome(route_outcome),
        overload_reason,
        health_effect: HealthEffectHint::None,
    }
}

pub fn classify_request_outcome(input: RequestOutcomeInput<'_>) -> RequestOutcomeDecision {
    let RequestOutcomeInput {
        request_outcome,
        result_class,
        overload_reason,
        health_effect,
        ..
    } = input;

    let decision = match result_class {
        OutcomeResultClass::HttpStatus(status_class) => RequestOutcomeDecision {
            route_outcome: match status_class {
                OutcomeStatusClass::Informational
                | OutcomeStatusClass::Success
                | OutcomeStatusClass::Redirection => CanonicalRouteOutcome::Success,
                OutcomeStatusClass::ClientError
                | OutcomeStatusClass::ServerError
                | OutcomeStatusClass::Other => request_outcome,
            },
            backend_outcome: CanonicalBackendOutcome::from_route_outcome(request_outcome),
            overload_reason,
            health_effect: health_effect_from_status_class(status_class),
        },
        OutcomeResultClass::UpstreamError | OutcomeResultClass::InternalError => {
            RequestOutcomeDecision {
                route_outcome: request_outcome,
                backend_outcome: CanonicalBackendOutcome::from_route_outcome(request_outcome),
                overload_reason,
                health_effect,
            }
        }
        OutcomeResultClass::Timeout => RequestOutcomeDecision {
            route_outcome: CanonicalRouteOutcome::Timeout,
            backend_outcome: CanonicalBackendOutcome::Timeout,
            overload_reason,
            health_effect,
        },
        OutcomeResultClass::Overload => RequestOutcomeDecision {
            route_outcome: CanonicalRouteOutcome::OverloadShed,
            backend_outcome: CanonicalBackendOutcome::OverloadShed,
            overload_reason,
            health_effect,
        },
        OutcomeResultClass::RateLimited => RequestOutcomeDecision {
            route_outcome: CanonicalRouteOutcome::RateLimited,
            backend_outcome: CanonicalBackendOutcome::RateLimited,
            overload_reason,
            health_effect,
        },
        OutcomeResultClass::AuthDenied => RequestOutcomeDecision {
            route_outcome: CanonicalRouteOutcome::AuthDenied,
            backend_outcome: CanonicalBackendOutcome::AuthDenied,
            overload_reason,
            health_effect,
        },
        OutcomeResultClass::Unrouted => RequestOutcomeDecision {
            route_outcome: CanonicalRouteOutcome::Unrouted,
            backend_outcome: CanonicalBackendOutcome::Unrouted,
            overload_reason,
            health_effect,
        },
    };

    RequestOutcomeDecision {
        route_outcome: decision.route_outcome,
        backend_outcome: decision.backend_outcome,
        overload_reason: decision.overload_reason,
        health_effect: decision.health_effect,
    }
}

pub fn record_request_metrics_observation(
    metrics: &crate::Metrics,
    observation: RequestMetricsObservation<'_>,
) {
    let RequestMetricsObservation {
        route_target,
        backend_target,
        elapsed,
        status,
        metrics_outcome,
        overload_reason,
    } = observation;

    if !matches!(metrics_outcome, RouteOutcome::Success) {
        metrics.inc_failure();
    }

    if matches!(metrics_outcome, RouteOutcome::OverloadShed) {
        if let Some(reason) = overload_reason {
            metrics.inc_overload_shed_reason(reason);
        } else {
            metrics.inc_overload_shed();
        }
    }

    metrics.record_route(route_target.route, elapsed, metrics_outcome);
    metrics.record_request_result(
        route_target.route,
        backend_target.and_then(|target| target.backend_addr),
        status,
        metrics_outcome,
        elapsed,
    );
}

pub fn observe_request_outcome(
    metrics: &Metrics,
    route_target: OutcomeRouteTarget<'_>,
    backend_target: Option<OutcomeBackendTarget<'_>>,
    elapsed: Duration,
    status: Option<StatusCode>,
    decision: RequestOutcomeDecision,
) -> RequestOutcomeDecision {
    if matches!(decision.route_outcome, CanonicalRouteOutcome::Success) {
        metrics.inc_success();
    }

    record_request_metrics_observation(
        metrics,
        RequestMetricsObservation {
            route_target,
            backend_target,
            elapsed,
            status: status.map(|value| value.as_u16()),
            metrics_outcome: decision.route_outcome.as_metrics_outcome(),
            overload_reason: decision.overload_reason,
        },
    );

    decision
}

pub fn observe_status_outcome(
    metrics: &Metrics,
    route_target: OutcomeRouteTarget<'_>,
    backend_target: Option<OutcomeBackendTarget<'_>>,
    elapsed: Duration,
    status: StatusCode,
) -> RequestOutcomeDecision {
    observe_request_outcome(
        metrics,
        route_target,
        backend_target,
        elapsed,
        Some(status),
        classify_status_outcome(status),
    )
}

pub fn observe_proxy_error_outcome(
    metrics: &Metrics,
    route_target: OutcomeRouteTarget<'_>,
    backend_target: Option<OutcomeBackendTarget<'_>>,
    elapsed: Duration,
    status: Option<StatusCode>,
    err: &ProxyError,
    overload_reason: Option<OverloadShedReason>,
) -> RequestOutcomeDecision {
    observe_request_outcome(
        metrics,
        route_target,
        backend_target,
        elapsed,
        status,
        classify_proxy_error_outcome(err, overload_reason),
    )
}

pub fn observe_admission_outcome(
    metrics: &Metrics,
    route_target: OutcomeRouteTarget<'_>,
    backend_target: Option<OutcomeBackendTarget<'_>>,
    elapsed: Duration,
    status: StatusCode,
    outcome: AdmissionOutcomeClass,
) -> RequestOutcomeDecision {
    observe_request_outcome(
        metrics,
        route_target,
        backend_target,
        elapsed,
        Some(status),
        classify_admission_outcome(outcome),
    )
}

#[derive(Clone, Copy)]
pub struct BackendRequestFinishInput<'a> {
    pub upstream_pool: Option<&'a Arc<RwLock<UpstreamPool>>>,
    pub backend_index: Option<usize>,
    pub elapsed: Duration,
    pub status: Option<u16>,
}

#[derive(Clone, Copy)]
pub struct BackendHealthObservationInput<'a> {
    pub backend_addr: &'a str,
    pub backend_index: usize,
    pub upstream_pool: Option<&'a Arc<RwLock<UpstreamPool>>>,
    pub status: StatusCode,
}

#[derive(Clone, Copy)]
pub struct ClassifiedBackendFailureInput<'a> {
    pub metrics_phase: &'a str,
    pub backend_addr: &'a str,
    pub backend_index: usize,
    pub upstream_pool: Option<&'a Arc<RwLock<UpstreamPool>>>,
    pub metrics: &'a Metrics,
    pub classified: &'a ClassifiedUpstreamProxyError,
}

pub fn finish_backend_request_accounting(input: BackendRequestFinishInput<'_>) {
    let BackendRequestFinishInput {
        upstream_pool,
        backend_index,
        elapsed,
        status,
    } = input;

    if let (Some(pool), Some(index)) = (upstream_pool, backend_index)
        && let Ok(mut guard) = pool.write()
    {
        guard.finish_request(index, elapsed, status);
    }
}

pub fn observe_backend_response_status(
    input: BackendHealthObservationInput<'_>,
) -> Option<HealthTransition> {
    let BackendHealthObservationInput {
        backend_addr: _backend_addr,
        backend_index,
        upstream_pool,
        status,
    } = input;

    let pool = upstream_pool?;
    let mut pool = pool.write().ok()?;
    match outcome_from_status(status) {
        crate::runtime::health::HealthClassification::Success => pool.pool.mark_success(backend_index),
        crate::runtime::health::HealthClassification::Failure => {
            pool.pool
                .mark_request_failure(backend_index, HealthFailureReason::HttpStatus5xx)
        }
        crate::runtime::health::HealthClassification::Neutral => None,
    }
}

pub fn observe_classified_backend_failure(
    input: ClassifiedBackendFailureInput<'_>,
) -> Option<HealthTransition> {
    let ClassifiedBackendFailureInput {
        metrics_phase,
        backend_addr,
        backend_index,
        upstream_pool,
        metrics,
        classified,
    } = input;

    let health_mapping = classified.health_failure?;
    metrics.inc_health_failure(health_mapping.failure_reason);
    if health_mapping.failure_reason == HealthFailureReason::Tls {
        metrics.record_upstream_tls_failure(
            backend_addr,
            metrics_phase,
            health_mapping.metrics_reason,
        );
    }
    let pool = upstream_pool?;
    let mut pool = pool.write().ok()?;
    pool.pool
        .mark_request_failure(backend_index, health_mapping.failure_reason)
}

pub fn log_backend_health_transition(addr: &str, transition: HealthTransition) {
    match transition {
        HealthTransition::BecameHealthy => {
            info!("Backend {} became healthy", addr);
        }
        HealthTransition::BecameUnhealthy => {
            error!("Backend {} became unhealthy", addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use spooky_config::config::{
        Backend, ForwardedHeaderPolicy, HealthCheck, LoadBalancing, RouteAuth, RouteMatch,
        Upstream, UpstreamHostPolicy,
    };

    fn test_metrics() -> Metrics {
        Metrics::new(1, [String::from("api"), String::from("unrouted")])
    }

    fn test_upstream_pool() -> Arc<RwLock<UpstreamPool>> {
        Arc::new(RwLock::new(
            UpstreamPool::from_upstream(&Upstream {
                load_balancing: LoadBalancing {
                    lb_type: "round-robin".to_string(),
                    key: None,
                },
                auth: RouteAuth::default(),
                host_policy: UpstreamHostPolicy::default(),
                forwarded_headers: ForwardedHeaderPolicy::default(),
                tls: None,
                route: RouteMatch {
                    host: None,
                    path_prefix: Some("/".to_string()),
                    method: None,
                },
                backends: vec![Backend {
                    id: "a".to_string(),
                    address: "http://127.0.0.1:8080".to_string(),
                    weight: 1,
                    health_check: Some(HealthCheck {
                        path: "/health".to_string(),
                        interval: 0,
                        timeout_ms: 1000,
                        failure_threshold: 1,
                        success_threshold: 1,
                        cooldown_ms: 0,
                    }),
                }],
            })
            .expect("pool"),
        ))
    }

    fn upstream_request_count(
        metrics: &Metrics,
        upstream: &str,
        status_class: &str,
        outcome: &str,
    ) -> u64 {
        metrics
            .snapshot_upstream_request_counts()
            .into_iter()
            .find(|(key, _)| {
                key.upstream == upstream
                    && key.status_class == status_class
                    && key.outcome == outcome
            })
            .map(|(_, count)| count)
            .unwrap_or_default()
    }

    fn backend_request_count(
        metrics: &Metrics,
        upstream: &str,
        backend: &str,
        status_class: &str,
        outcome: &str,
    ) -> u64 {
        metrics
            .snapshot_backend_request_counts()
            .into_iter()
            .find(|(key, _)| {
                key.upstream == upstream
                    && key.backend == backend
                    && key.status_class == status_class
                    && key.outcome == outcome
            })
            .map(|(_, count)| count)
            .unwrap_or_default()
    }

    #[test]
    fn classifies_success_status_as_success() {
        let decision = classify_status_outcome(StatusCode::OK);
        assert_eq!(decision.route_outcome, CanonicalRouteOutcome::Success);
        assert_eq!(decision.backend_outcome, CanonicalBackendOutcome::Success);
        assert_eq!(decision.health_effect, HealthEffectHint::Success);
    }

    #[test]
    fn classifies_timeout_proxy_error_as_timeout() {
        let decision = classify_proxy_error_outcome(&ProxyError::Timeout, None);
        assert_eq!(decision.route_outcome, CanonicalRouteOutcome::Timeout);
        assert_eq!(decision.backend_outcome, CanonicalBackendOutcome::Timeout);
        assert_eq!(
            decision.health_effect,
            HealthEffectHint::Failure {
                reason: HealthFailureReason::Timeout,
            }
        );
    }

    #[test]
    fn classifies_overload_admission_outcome() {
        let decision = classify_admission_outcome(AdmissionOutcomeClass::OverloadShed {
            reason: Some(OverloadShedReason::GlobalInflight),
        });
        assert_eq!(decision.route_outcome, CanonicalRouteOutcome::OverloadShed);
        assert_eq!(decision.backend_outcome, CanonicalBackendOutcome::OverloadShed);
        assert_eq!(decision.overload_reason, Some(OverloadShedReason::GlobalInflight));
    }

    #[test]
    fn observe_status_outcome_records_success_metrics() {
        let metrics = test_metrics();

        let decision = observe_status_outcome(
            &metrics,
            OutcomeRouteTarget { route: "api" },
            Some(OutcomeBackendTarget {
                upstream: "api",
                backend_addr: Some("backend-a"),
                backend_index: Some(0),
            }),
            Duration::from_millis(12),
            StatusCode::OK,
        );

        assert_eq!(decision.route_outcome, CanonicalRouteOutcome::Success);
        assert_eq!(metrics.requests_success.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(metrics.requests_failure.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(upstream_request_count(&metrics, "api", "2xx", "success"), 1);
        assert_eq!(
            backend_request_count(&metrics, "api", "backend-a", "2xx", "success"),
            1
        );
    }

    #[test]
    fn observe_proxy_error_outcome_records_timeout_and_unrouted_failure() {
        let metrics = test_metrics();

        let timeout = observe_proxy_error_outcome(
            &metrics,
            OutcomeRouteTarget { route: "api" },
            Some(OutcomeBackendTarget {
                upstream: "api",
                backend_addr: Some("backend-a"),
                backend_index: Some(0),
            }),
            Duration::from_millis(50),
            Some(StatusCode::REQUEST_TIMEOUT),
            &ProxyError::Timeout,
            None,
        );
        let unrouted = observe_proxy_error_outcome(
            &metrics,
            OutcomeRouteTarget::UNROUTED,
            None,
            Duration::from_millis(5),
            Some(StatusCode::BAD_GATEWAY),
            &ProxyError::Transport("no route".into()),
            None,
        );

        assert_eq!(timeout.route_outcome, CanonicalRouteOutcome::Timeout);
        assert_eq!(unrouted.route_outcome, CanonicalRouteOutcome::UpstreamFailure);
        assert_eq!(metrics.requests_failure.load(std::sync::atomic::Ordering::Relaxed), 2);
        assert_eq!(upstream_request_count(&metrics, "api", "4xx", "timeout"), 1);
        assert_eq!(upstream_request_count(&metrics, "unrouted", "5xx", "failure"), 1);
    }

    #[test]
    fn observe_admission_outcome_records_overload_auth_and_rate_limit() {
        let metrics = test_metrics();

        let overload = observe_admission_outcome(
            &metrics,
            OutcomeRouteTarget { route: "api" },
            Some(OutcomeBackendTarget {
                upstream: "api",
                backend_addr: Some("backend-a"),
                backend_index: Some(0),
            }),
            Duration::from_millis(1),
            StatusCode::SERVICE_UNAVAILABLE,
            AdmissionOutcomeClass::OverloadShed {
                reason: Some(OverloadShedReason::GlobalInflight),
            },
        );
        let auth = observe_admission_outcome(
            &metrics,
            OutcomeRouteTarget { route: "api" },
            Some(OutcomeBackendTarget {
                upstream: "api",
                backend_addr: Some("backend-a"),
                backend_index: Some(0),
            }),
            Duration::from_millis(2),
            StatusCode::UNAUTHORIZED,
            AdmissionOutcomeClass::AuthDenied,
        );
        let rate_limited = observe_admission_outcome(
            &metrics,
            OutcomeRouteTarget { route: "api" },
            Some(OutcomeBackendTarget {
                upstream: "api",
                backend_addr: Some("backend-a"),
                backend_index: Some(0),
            }),
            Duration::from_millis(3),
            StatusCode::TOO_MANY_REQUESTS,
            AdmissionOutcomeClass::RateLimited,
        );

        assert_eq!(overload.route_outcome, CanonicalRouteOutcome::OverloadShed);
        assert_eq!(auth.route_outcome, CanonicalRouteOutcome::AuthDenied);
        assert_eq!(rate_limited.route_outcome, CanonicalRouteOutcome::RateLimited);
        assert_eq!(metrics.overload_shed.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(
            metrics
                .overload_shed_global_inflight
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(upstream_request_count(&metrics, "api", "5xx", "overload_shed"), 1);
        assert_eq!(upstream_request_count(&metrics, "api", "4xx", "failure"), 1);
        assert_eq!(upstream_request_count(&metrics, "api", "4xx", "rate_limited"), 1);
    }

    #[test]
    fn backend_accounting_and_health_hooks_remain_stable() {
        let metrics = test_metrics();
        let pool = test_upstream_pool();

        {
            let guard = pool.read().expect("read");
            assert!(guard.begin_request_if_healthy(0));
        }
        finish_backend_request_accounting(BackendRequestFinishInput {
            upstream_pool: Some(&pool),
            backend_index: Some(0),
            elapsed: Duration::from_millis(20),
            status: Some(StatusCode::OK.as_u16()),
        });
        {
            let guard = pool.read().expect("read");
            assert_eq!(guard.pool.backends[0].active_requests(), 0);
            assert!(guard.pool.backends[0].ewma_latency_ms().is_some());
        }

        let unhealthy = observe_backend_response_status(BackendHealthObservationInput {
            backend_addr: "backend-a",
            backend_index: 0,
            upstream_pool: Some(&pool),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        });
        assert!(matches!(unhealthy, Some(HealthTransition::BecameUnhealthy)));

        let healthy = observe_backend_response_status(BackendHealthObservationInput {
            backend_addr: "backend-a",
            backend_index: 0,
            upstream_pool: Some(&pool),
            status: StatusCode::OK,
        });
        assert!(matches!(healthy, Some(HealthTransition::BecameHealthy)));

        let classified = spooky_errors::classify_upstream_proxy_error(&ProxyError::Timeout)
            .expect("classified timeout");
        let transition = observe_classified_backend_failure(ClassifiedBackendFailureInput {
            metrics_phase: "bootstrap",
            backend_addr: "backend-a",
            backend_index: 0,
            upstream_pool: Some(&pool),
            metrics: &metrics,
            classified: &classified,
        });
        assert!(matches!(transition, Some(HealthTransition::BecameUnhealthy)));
        assert_eq!(
            metrics
                .health_failure_timeout
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn forwarding_and_bootstrap_shared_recorders_emit_same_metrics_shape() {
        let metrics = test_metrics();

        let forwarding = observe_proxy_error_outcome(
            &metrics,
            OutcomeRouteTarget { route: "api" },
            Some(OutcomeBackendTarget {
                upstream: "api",
                backend_addr: Some("backend-a"),
                backend_index: Some(0),
            }),
            Duration::from_millis(10),
            Some(StatusCode::BAD_GATEWAY),
            &ProxyError::Transport("forwarding upstream error".into()),
            None,
        );
        let bootstrap = observe_proxy_error_outcome(
            &metrics,
            OutcomeRouteTarget { route: "api" },
            Some(OutcomeBackendTarget {
                upstream: "api",
                backend_addr: Some("backend-a"),
                backend_index: Some(0),
            }),
            Duration::from_millis(12),
            Some(StatusCode::BAD_GATEWAY),
            &ProxyError::Transport("bootstrap upstream error".into()),
            None,
        );

        assert_eq!(forwarding.route_outcome, bootstrap.route_outcome);
        assert_eq!(forwarding.backend_outcome, bootstrap.backend_outcome);
        assert_eq!(upstream_request_count(&metrics, "api", "5xx", "failure"), 2);
        assert_eq!(
            backend_request_count(&metrics, "api", "backend-a", "5xx", "failure"),
            2
        );
    }
}
