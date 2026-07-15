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
