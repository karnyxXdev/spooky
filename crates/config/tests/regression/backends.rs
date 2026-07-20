//! Backend endpoint and health-check canonicalization.

use std::time::Duration;

use spooky_config::{config::HealthCheck, runtime::RuntimeConfig};

use crate::common::sample_config;

#[test]
fn runtime_backend_health_check_and_endpoint_are_canonicalized() {
    let mut config = sample_config();
    config.upstream.get_mut("api").expect("api").backends[0].health_check = Some(HealthCheck {
        path: String::new(),
        interval: 2_000,
        timeout_ms: 250,
        failure_threshold: 4,
        success_threshold: 3,
        cooldown_ms: 5_000,
    });

    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
    let backend = &runtime.upstreams.get("api").expect("api").backends[0];
    let health = backend.health_check.as_ref().expect("health check");

    assert_eq!(backend.endpoint.origin, "https://api.internal:8443");
    assert_eq!(health.path, "/");
    assert_eq!(health.interval, Duration::from_millis(2_000));
    assert_eq!(health.timeout, Duration::from_millis(250));
    assert_eq!(health.failure_threshold, 4);
    assert_eq!(health.success_threshold, 3);
}
