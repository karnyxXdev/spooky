use super::*;

fn configure_http_external_auth(
    config: &mut Config,
    endpoint: String,
    timeout_ms: u64,
    failure_mode: ExternalAuthFailureMode,
    response_header_allowlist: Vec<String>,
) {
    let upstream = config
        .upstream
        .get_mut("test_pool")
        .expect("test_pool upstream");
    upstream.auth.external_auth = Some(ExternalAuth::Http {
        endpoint,
        request_headers: vec![ExternalAuthRequestHeader {
            name: "x-auth-static".to_string(),
            value: "1".to_string(),
        }],
        response_header_allowlist,
        timeout_ms,
        failure_mode,
    });
}

fn configure_oidc_external_auth(
    config: &mut Config,
    discovery_url: String,
    timeout_ms: u64,
    failure_mode: ExternalAuthFailureMode,
) {
    let upstream = config
        .upstream
        .get_mut("test_pool")
        .expect("test_pool upstream");
    upstream.auth.external_auth = Some(ExternalAuth::Oidc {
        discovery_url: Some(discovery_url),
        issuer_url: Some("https://issuer.example.com".to_string()),
        client_id: "edge-client".to_string(),
        client_secret: Some("edge-secret".to_string()),
        audience: Some("api://edge".to_string()),
        scopes: vec!["read".to_string()],
        request_headers: vec![],
        response_header_allowlist: vec![],
        timeout_ms,
        failure_mode,
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_allow_injects_headers_and_forwards() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend_service(|req| async move {
        let user = req
            .headers()
            .get("x-user-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing")
            .to_string();
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
            "backend user={user}"
        )))))
    })
    .await;

    let auth_addr = start_http_auth_server(|req| async move {
        assert_eq!(req.uri().path(), "/check");
        assert_eq!(req.method(), http::Method::GET);
        assert_eq!(
            req.headers()
                .get("x-spooky-original-method")
                .and_then(|value| value.to_str().ok()),
            Some("GET")
        );
        assert_eq!(
            req.headers()
                .get("x-auth-static")
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        let response = Response::builder()
            .status(http::StatusCode::NO_CONTENT)
            .header("x-user-id", "alice")
            .body(Full::new(Bytes::new()))
            .expect("auth allow response");
        Ok::<_, Infallible>(response)
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec!["x-user-id".to_string()],
    );

    let listener = QUICListener::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "backend user=alice");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_deny_returns_denial_response_and_headers() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("should not reach backend").await;
    let auth_addr = start_http_auth_server(|_req| async move {
        let response = Response::builder()
            .status(http::StatusCode::FORBIDDEN)
            .header("x-auth-reason", "policy")
            .body(Full::new(Bytes::from("denied by auth")))
            .expect("auth deny response");
        Ok::<_, Infallible>(response)
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec!["x-auth-reason".to_string()],
    );

    let listener = QUICListener::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 403);
    assert_eq!(response.header("x-auth-reason"), Some("policy"));
    assert!(response.body.contains("denied by auth"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_redirect_preserves_location() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("should not reach backend").await;
    let auth_addr = start_http_auth_server(|_req| async move {
        let response = Response::builder()
            .status(http::StatusCode::FOUND)
            .header("location", "https://login.example.com/")
            .body(Full::new(Bytes::new()))
            .expect("auth redirect response");
        Ok::<_, Infallible>(response)
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec![],
    );

    let listener = QUICListener::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 302);
    assert_eq!(
        response.header("location"),
        Some("https://login.example.com/")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_timeout_fail_closed_returns_gateway_timeout() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("should not reach backend").await;
    let auth_addr = start_http_auth_server(|_req| async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        15,
        ExternalAuthFailureMode::FailClosed,
        vec![],
    );

    let listener = QUICListener::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 504);
    assert!(response.body.contains("external auth timeout"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_auth_timeout_fail_open_allows_backend() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("backend after fail-open").await;
    let auth_addr = start_http_auth_server(|_req| async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        15,
        ExternalAuthFailureMode::FailOpen,
        vec![],
    );

    let listener = QUICListener::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(addr, "GET", "/", &[], None).expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "backend after fail-open");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oidc_external_auth_uses_discovery_and_introspection() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("oidc ok").await;
    let auth_addr = start_http_auth_server(|req| async move {
        match req.uri().path() {
            "/.well-known/openid-configuration" => {
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|value| value.to_str().ok())
                    .expect("host header");
                let body = format!(
                    "{{\"introspection_endpoint\":\"http://{host}/introspect\"}}"
                );
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(http::StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(body)))
                        .expect("discovery response"),
                )
            }
            "/introspect" => {
                let body = req
                    .into_body()
                    .collect()
                    .await
                    .expect("introspection body")
                    .to_bytes();
                let encoded = String::from_utf8_lossy(&body);
                assert!(encoded.contains("token=good-token"));
                assert!(encoded.contains("client_id=edge-client"));
                assert!(encoded.contains("audience=api%3A%2F%2Fedge"));
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(http::StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(
                            r#"{"active":true,"scope":"openid profile read","aud":"api://edge","iss":"https://issuer.example.com"}"#,
                        )))
                        .expect("introspection response"),
                )
            }
            other => panic!("unexpected auth path: {other}"),
        }
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_oidc_external_auth(
        &mut config,
        format!("http://{auth_addr}/.well-known/openid-configuration"),
        250,
        ExternalAuthFailureMode::FailClosed,
    );

    let listener = QUICListener::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(
        addr,
        "GET",
        "/",
        &[("authorization", "Bearer good-token")],
        None,
    )
    .expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "oidc ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_body_is_buffered_while_auth_is_pending() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend_service(|req| async move {
        let user = req
            .headers()
            .get("x-user-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing")
            .to_string();
        let body = req
            .into_body()
            .collect()
            .await
            .expect("backend body")
            .to_bytes();
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
            "len={};user={user}",
            body.len()
        )))))
    })
    .await;

    let auth_addr = start_http_auth_server(|_req| async move {
        tokio::time::sleep(Duration::from_millis(40)).await;
        Ok::<_, Infallible>(
            Response::builder()
                .status(http::StatusCode::NO_CONTENT)
                .header("x-user-id", "buffered")
                .body(Full::new(Bytes::new()))
                .expect("auth allow response"),
        )
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);
    let mut config = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config,
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec!["x-user-id".to_string()],
    );

    let listener = QUICListener::new(config).expect("listener");
    let (addr, stop, handle) = spawn_listener_loop(listener);
    let response = run_h3_client_request(
        addr,
        "POST",
        "/upload",
        &[("content-length", "20")],
        Some(b"buffered auth body!!"),
    )
    .expect("h3 response");
    stop_listener_loop(stop, handle);

    assert_eq!(response.status, 200);
    assert_eq!(response.body, "len=20;user=buffered");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "manual perf smoke"]
async fn auth_allow_path_latency_smoke_does_not_explode_vs_disabled() {
    if !local_listener_bind_available() {
        return;
    }

    let backend_addr = start_h2_backend("benchmark backend").await;
    let auth_addr = start_http_auth_server(|_req| async move {
        Ok::<_, Infallible>(
            Response::builder()
                .status(http::StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .expect("auth allow response"),
        )
    })
    .await;

    let dir = tempdir().expect("tempdir");
    let (cert, key) = write_test_certs(&dir);

    let config_without_auth = make_config(0, cert.clone(), key.clone(), backend_addr.to_string());
    let listener_without_auth = QUICListener::new(config_without_auth).expect("listener");
    let (addr_without_auth, stop_without_auth, handle_without_auth) =
        spawn_listener_loop(listener_without_auth);
    let baseline_start = Instant::now();
    for _ in 0..10 {
        let response = run_h3_client_request(addr_without_auth, "GET", "/", &[], None)
            .expect("baseline response");
        assert_eq!(response.status, 200);
    }
    let baseline_elapsed = baseline_start.elapsed();
    stop_listener_loop(stop_without_auth, handle_without_auth);

    let mut config_with_auth = make_config(0, cert, key, backend_addr.to_string());
    configure_http_external_auth(
        &mut config_with_auth,
        format!("http://{auth_addr}/check"),
        250,
        ExternalAuthFailureMode::FailClosed,
        vec![],
    );
    let listener_with_auth = QUICListener::new(config_with_auth).expect("listener");
    let (addr_with_auth, stop_with_auth, handle_with_auth) =
        spawn_listener_loop(listener_with_auth);
    let auth_start = Instant::now();
    for _ in 0..10 {
        let response =
            run_h3_client_request(addr_with_auth, "GET", "/", &[], None).expect("auth response");
        assert_eq!(response.status, 200);
    }
    let auth_elapsed = auth_start.elapsed();
    stop_listener_loop(stop_with_auth, handle_with_auth);

    assert!(
        auth_elapsed <= baseline_elapsed.saturating_mul(10),
        "auth-enabled path regressed too far: baseline={baseline_elapsed:?} auth={auth_elapsed:?}"
    );
}
