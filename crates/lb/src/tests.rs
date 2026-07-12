use spooky_config::config::RouteMatch;

use super::*;

#[test]
fn unhealthy_backends_are_skipped() {
    let mut pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
    ]);

    pool.mark_failure(0);
    pool.mark_failure(0);
    pool.mark_failure(0);

    let mut rr = RoundRobin::new();
    let pick = rr.pick(&pool).unwrap();
    assert_eq!(pick, 1);
}

#[test]
fn least_connections_picks_lowest_active() {
    let pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
        create_backend_state("10.0.0.3:1", 1),
    ]);
    pool.begin_request(0);
    pool.begin_request(0);
    pool.begin_request(1);

    let mut lb = LeastConnections::new();
    assert_eq!(lb.pick(&pool), Some(2));
}

#[test]
fn latency_aware_prefers_lower_ewma() {
    let mut pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
    ]);

    pool.finish_request(0, Duration::from_millis(150), Some(200));
    pool.finish_request(1, Duration::from_millis(20), Some(200));

    let mut lb = LatencyAware::new();
    assert_eq!(lb.pick(&pool), Some(1));
}

#[test]
fn sticky_cid_is_deterministic_for_same_key() {
    let pool = BackendPool::new_from_states(vec![
        create_backend_state("10.0.0.1:1", 1),
        create_backend_state("10.0.0.2:1", 1),
        create_backend_state("10.0.0.3:1", 1),
    ]);

    let mut lb = StickyCid::new(16);
    let first = lb.pick("cid:abc123", &pool);
    let second = lb.pick("cid:abc123", &pool);
    assert_eq!(first, second);
}

#[test]
fn no_healthy_backends_returns_none() {
    let mut pool = BackendPool::new_from_states(vec![create_backend_state("10.0.0.1:1", 1)]);
    pool.mark_failure(0);
    pool.mark_failure(0);
    pool.mark_failure(0);

    let mut rr = RoundRobin::new();
    assert!(rr.pick(&pool).is_none());
}
#[test]
fn upstream_pool_from_config() {
    let upstream = spooky_config::config::Upstream {
        load_balancing: spooky_config::config::LoadBalancing {
            lb_type: "round-robin".to_string(),
            key: None,
        },
        auth: Default::default(),
        host_policy: Default::default(),
        forwarded_headers: Default::default(),
        tls: None,
        route: RouteMatch {
            path_prefix: Some("/".to_string()),
            ..Default::default()
        },
        backends: vec![
            Backend {
                id: "backend1".to_string(),
                address: "127.0.0.1:8001".to_string(),
                weight: 100,
                health_check: Some(HealthCheck {
                    path: "/health".to_string(),
                    interval: 5000,
                    timeout_ms: 2000,
                    failure_threshold: 3,
                    success_threshold: 2,
                    cooldown_ms: 10000,
                }),
            },
            Backend {
                id: "backend2".to_string(),
                address: "127.0.0.1:8002".to_string(),
                weight: 200,
                health_check: Some(HealthCheck {
                    path: "/health".to_string(),
                    interval: 5000,
                    timeout_ms: 2000,
                    failure_threshold: 3,
                    success_threshold: 2,
                    cooldown_ms: 10000,
                }),
            },
        ],
    };

    let upstream_pool = UpstreamPool::from_upstream(&upstream).unwrap();
    assert!(matches!(
        upstream_pool.load_balancer,
        LoadBalancing::RoundRobin(_)
    ));
    assert_eq!(upstream_pool.pool.len(), 2);
    assert_eq!(upstream_pool.pool.address(0), Some("127.0.0.1:8001"));
    assert_eq!(upstream_pool.pool.address(1), Some("127.0.0.1:8002"));
}
