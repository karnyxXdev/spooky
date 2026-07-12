use spooky_lb::load_balancing::LoadBalancing;

#[test]
fn load_balancing_from_config() {
    assert!(LoadBalancing::from_config("round-robin").is_ok());
    assert!(LoadBalancing::from_config("consistent-hash").is_ok());
    assert!(LoadBalancing::from_config("random").is_ok());
    assert!(LoadBalancing::from_config("least-connections").is_ok());
    assert!(LoadBalancing::from_config("latency-aware").is_ok());
    assert!(LoadBalancing::from_config("sticky-cid").is_ok());
    assert!(LoadBalancing::from_config("unknown").is_err());
}
