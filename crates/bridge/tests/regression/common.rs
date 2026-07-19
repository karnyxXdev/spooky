//! Shared request-building fixtures for the bridge regression suite.

use std::{convert::Infallible, net::SocketAddr};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use quiche::h3::Header;
use spooky_config::{
    backend_endpoint::BackendEndpoint,
    config::{ForwardedHeaderPolicy, UpstreamHostPolicy},
};
use spooky_bridge::request::{
    RequestBuildInput, RequestBuildPolicies, RequestBuildTarget, RequestForwardedContext,
    RequestTraceContext,
};

#[derive(Clone, Copy)]
pub struct RequestInputMeta<'a> {
    pub authority: Option<&'a str>,
    pub content_length: Option<usize>,
    pub request_id: u64,
    pub traceparent: Option<&'a str>,
    pub client_addr: SocketAddr,
}

pub fn request_target<'a>(
    endpoint: &'a BackendEndpoint,
    host_policy: &'a UpstreamHostPolicy,
    forwarded_header_policy: &'a ForwardedHeaderPolicy,
) -> RequestBuildTarget<'a> {
    RequestBuildTarget {
        endpoint,
        policies: RequestBuildPolicies {
            host_policy,
            forwarded_header_policy,
        },
    }
}

pub fn request_input<'a>(
    method: &'a str,
    path: &'a str,
    headers: &'a [Header],
    meta: RequestInputMeta<'a>,
) -> RequestBuildInput<'a, BoxBody<Bytes, Infallible>> {
    RequestBuildInput {
        method,
        path,
        authority: meta.authority,
        headers,
        body: Empty::<Bytes>::new().boxed(),
        content_length: meta.content_length,
        body_mode: RequestBuildInput::<BoxBody<Bytes, Infallible>>::body_mode_for_length(
            meta.content_length,
        ),
        trace: RequestTraceContext {
            request_id: meta.request_id,
            traceparent: meta.traceparent,
        },
        forwarded: RequestForwardedContext {
            client_addr: meta.client_addr,
        },
    }
}
