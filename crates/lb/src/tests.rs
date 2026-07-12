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
