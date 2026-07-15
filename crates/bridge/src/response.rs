use std::collections::HashSet;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseNormalizationProtocol {
    Http1,
    Http3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseBodyMode {
    Normal,
    HeadRequest,
    BodylessRequest,
    TunnelSuccess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseBodyPolicy {
    Forward,
    Suppress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentLengthPolicy {
    Preserve,
    Strip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentTypePolicy {
    Preserve,
    SynthesizeTextPlain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseProtocolConstraints {
    pub protocol: ResponseNormalizationProtocol,
    pub strip_connection_headers: bool,
    pub allow_trailers: bool,
    pub preserve_upgrade: bool,
}

#[derive(Debug)]
pub struct UpstreamResponseView<'a> {
    pub status: StatusCode,
    pub headers: &'a HeaderMap,
    pub trailers: Option<&'a HeaderMap>,
}

#[derive(Debug)]
pub struct ResponseNormalizationInput<'a> {
    pub upstream: UpstreamResponseView<'a>,
    pub body_mode: ResponseBodyMode,
    pub constraints: ResponseProtocolConstraints,
}

#[derive(Debug)]
pub struct NormalizedHeader {
    pub name: HeaderName,
    pub value: HeaderValue,
}

#[derive(Debug)]
pub struct NormalizedResponseHead {
    pub status: StatusCode,
    pub headers: Vec<NormalizedHeader>,
}

#[derive(Debug)]
pub struct ResponseEmissionPolicy {
    pub body: ResponseBodyPolicy,
    pub content_length: ContentLengthPolicy,
    pub content_type: ContentTypePolicy,
    pub emit_end_stream_on_headers: bool,
}

#[derive(Debug)]
pub struct NormalizedResponse {
    pub head: NormalizedResponseHead,
    pub trailers: Vec<NormalizedHeader>,
    pub emission: ResponseEmissionPolicy,
}

fn is_hop_by_hop_response_header(name: &HeaderName, preserve_upgrade: bool) -> bool {
    if preserve_upgrade && name == http::header::UPGRADE {
        return false;
    }

    name == http::header::CONNECTION
        || name == http::header::PROXY_AUTHENTICATE
        || name == http::header::PROXY_AUTHORIZATION
        || name == http::header::TE
        || name == http::header::TRAILER
        || name == http::header::TRANSFER_ENCODING
        || name == http::header::UPGRADE
        || name.as_str().eq_ignore_ascii_case("keep-alive")
        || name.as_str().eq_ignore_ascii_case("proxy-connection")
}

pub fn response_connection_tokens(headers: &HeaderMap) -> HashSet<String> {
    let mut tokens = HashSet::new();
    for value in headers.get_all(http::header::CONNECTION) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        for part in raw.split(',') {
            let token = part.trim().to_ascii_lowercase();
            if !token.is_empty() {
                tokens.insert(token);
            }
        }
    }
    tokens
}

pub fn should_strip_response_header(
    name: &HeaderName,
    connection_tokens: &HashSet<String>,
    constraints: ResponseProtocolConstraints,
) -> bool {
    (constraints.strip_connection_headers && connection_tokens.contains(name.as_str()))
        || is_hop_by_hop_response_header(name, constraints.preserve_upgrade)
        || matches!(constraints.protocol, ResponseNormalizationProtocol::Http3)
            && name == http::header::CONTENT_LENGTH
        || matches!(constraints.protocol, ResponseNormalizationProtocol::Http1)
            && name.as_str().eq_ignore_ascii_case("alt-svc")
}

pub fn normalize_response_trailers(
    trailers: &HeaderMap,
    constraints: ResponseProtocolConstraints,
) -> Vec<NormalizedHeader> {
    if !constraints.allow_trailers {
        return Vec::new();
    }

    let connection_tokens = response_connection_tokens(trailers);
    let mut normalized = Vec::with_capacity(trailers.len());
    for (name, value) in trailers {
        if should_strip_response_header(name, &connection_tokens, constraints) {
            continue;
        }
        normalized.push(NormalizedHeader {
            name: name.clone(),
            value: value.clone(),
        });
    }
    normalized
}
