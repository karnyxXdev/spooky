use std::{
    convert::Infallible,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use spooky_errors::ProxyError;
use spooky_transport::transport_pool::UpstreamTransportPool;

use crate::{
    Metrics,
    quic_listener::bootstrap::{
        BootstrapPreparedRoute, bootstrap_error_response, dispatch_bootstrap_websocket,
    },
};

use super::outcome::observe_bootstrap_dispatch_failure;

pub(in crate::quic_listener) struct BootstrapDispatchInput<'a> {
    pub(in crate::quic_listener) upstream_req: Request<BoxBody<Bytes, Infallible>>,
    pub(in crate::quic_listener) prepared_route: &'a BootstrapPreparedRoute,
    pub(in crate::quic_listener) transport_pool: &'a UpstreamTransportPool,
    pub(in crate::quic_listener) metrics: &'a Metrics,
    pub(in crate::quic_listener) request_start: Instant,
    pub(in crate::quic_listener) request_id: u64,
    pub(in crate::quic_listener) backend_timeout: Duration,
    pub(in crate::quic_listener) request_path: &'a str,
    pub(in crate::quic_listener) is_websocket_upgrade: bool,
    pub(in crate::quic_listener) alt_svc: &'a str,
}

async fn dispatch_bootstrap_http(
    input: BootstrapDispatchInput<'_>,
) -> Result<Response<Incoming>, Response<BoxBody<Bytes, Infallible>>> {
    match tokio::time::timeout(
        input.backend_timeout,
        input
            .transport_pool
            .send(&input.prepared_route.backend_addr, input.upstream_req),
    )
    .await
    {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(err)) => {
            let proxy_err = ProxyError::Pool(err);
            observe_bootstrap_dispatch_failure(
                input.prepared_route,
                input.metrics,
                input.request_start,
                input.request_id,
                StatusCode::BAD_GATEWAY,
                &proxy_err,
            );
            Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::BAD_GATEWAY,
                b"upstream error\n",
            ))
        }
        Err(_) => {
            observe_bootstrap_dispatch_failure(
                input.prepared_route,
                input.metrics,
                input.request_start,
                input.request_id,
                StatusCode::GATEWAY_TIMEOUT,
                &ProxyError::Timeout,
            );
            Err(bootstrap_error_response(
                input.alt_svc,
                StatusCode::GATEWAY_TIMEOUT,
                b"upstream timeout\n",
            ))
        }
    }
}

pub(in crate::quic_listener) async fn dispatch_bootstrap_upstream(
    input: BootstrapDispatchInput<'_>,
) -> Result<Response<Incoming>, Response<BoxBody<Bytes, Infallible>>> {
    if input.is_websocket_upgrade {
        dispatch_bootstrap_websocket(input).await
    } else {
        dispatch_bootstrap_http(input).await
    }
}
