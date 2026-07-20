//! Auth-contract lowering: external auth (HTTP/OIDC), JWT, and scoped rate limits.

use std::time::Duration;

use spooky_config::{
    config::{
        ExternalAuth, ExternalAuthFailureMode, JwtAuth, ScopedRateLimit, ScopedRateLimitScope,
    },
    runtime::{RuntimeConfig, RuntimeExternalAuth},
};

use crate::common::sample_config;

#[test]
fn runtime_config_preserves_external_auth_contract() {
    let mut config = sample_config();
    config
        .upstream
        .get_mut("api")
        .expect("api")
        .auth
        .external_auth = Some(ExternalAuth::Http {
        endpoint: "https://auth.internal/check".to_string(),
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_000,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
    let auth = &runtime
        .upstreams
        .get("api")
        .expect("api")
        .policy
        .upstream_auth;
    match auth.external_auth.as_ref() {
        Some(RuntimeExternalAuth::Http {
            endpoint,
            request_headers,
            response_header_allowlist,
            timeout,
            ..
        }) => {
            assert_eq!(endpoint, "https://auth.internal/check");
            assert!(request_headers.is_empty());
            assert!(response_header_allowlist.is_empty());
            assert_eq!(*timeout, Duration::from_millis(1_000));
        }
        other => panic!("unexpected external_auth contract: {:?}", other),
    }
}

#[test]
fn runtime_config_preserves_oidc_external_auth_metadata() {
    let mut config = sample_config();
    config
        .upstream
        .get_mut("api")
        .expect("api")
        .auth
        .external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some(
            "https://issuer.example.com/.well-known/openid-configuration".to_string(),
        ),
        issuer_url: Some("https://issuer.example.com".to_string()),
        client_id: "edge-gateway".to_string(),
        client_secret: Some("secret-1".to_string()),
        audience: Some("spooky-api".to_string()),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        request_headers: Vec::new(),
        response_header_allowlist: Vec::new(),
        timeout_ms: 1_500,
        failure_mode: ExternalAuthFailureMode::FailClosed,
    });

    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
    match runtime
        .upstreams
        .get("api")
        .expect("api")
        .policy
        .upstream_auth
        .external_auth
        .as_ref()
    {
        Some(RuntimeExternalAuth::Oidc {
            discovery_url,
            issuer_url,
            client_id,
            client_secret,
            audience,
            scopes,
            request_headers,
            response_header_allowlist,
            timeout,
            ..
        }) => {
            assert_eq!(
                discovery_url.as_deref(),
                Some("https://issuer.example.com/.well-known/openid-configuration")
            );
            assert_eq!(issuer_url.as_deref(), Some("https://issuer.example.com"));
            assert_eq!(client_id, "edge-gateway");
            assert_eq!(client_secret.as_deref(), Some("secret-1"));
            assert_eq!(audience.as_deref(), Some("spooky-api"));
            assert_eq!(scopes, &vec!["openid".to_string(), "profile".to_string()]);
            assert!(request_headers.is_empty());
            assert!(response_header_allowlist.is_empty());
            assert_eq!(*timeout, Duration::from_millis(1_500));
        }
        other => panic!("unexpected external_auth contract: {:?}", other),
    }
}

#[test]
fn runtime_config_normalizes_jwt_and_scoped_rate_limit_shapes() {
    let mut config = sample_config();
    let upstream = config.upstream.get_mut("api").expect("api upstream");
    upstream.auth.jwt = Some(JwtAuth {
        secret: "jwt-secret".to_string(),
        issuer: Some(" issuer-1 ".to_string()),
        audience: Some(" spooky-api ".to_string()),
        clock_skew_secs: 45,
    });
    upstream.auth.required_scopes = vec![" read:api ".to_string()];
    upstream.auth.required_roles = vec![" admin ".to_string()];
    config.resilience.scoped_rate_limits = vec![ScopedRateLimit {
        name: " tenant-default ".to_string(),
        scope: ScopedRateLimitScope::Tenant,
        requests_per_sec: 12,
        burst: 34,
        key: Some("header:x-tenant-id".to_string()),
        route_allowlist: vec![" api ".to_string()],
        idle_ttl_secs: 9,
    }];

    let runtime = RuntimeConfig::from_config(&config).expect("runtime config");
    let api = runtime.upstreams.get("api").expect("api runtime upstream");
    let jwt = api.policy.upstream_auth.jwt.as_ref().expect("jwt policy");
    let scoped_limit = runtime
        .policies
        .rate_limits
        .scoped_limits
        .first()
        .expect("scoped rate limit");

    assert_eq!(jwt.issuer.as_deref(), Some("issuer-1"));
    assert_eq!(jwt.audience.as_deref(), Some("spooky-api"));
    assert_eq!(jwt.clock_skew, Duration::from_secs(45));
    assert_eq!(
        api.policy.upstream_auth.required_scopes,
        vec!["read:api".to_string()]
    );
    assert_eq!(
        api.policy.upstream_auth.required_roles,
        vec!["admin".to_string()]
    );
    assert_eq!(scoped_limit.name, " tenant-default ");
    assert_eq!(scoped_limit.route_allowlist, vec!["api".to_string()]);
    assert_eq!(scoped_limit.key.as_deref(), Some("header:x-tenant-id"));
    assert_eq!(scoped_limit.idle_ttl, Duration::from_secs(9));
}
