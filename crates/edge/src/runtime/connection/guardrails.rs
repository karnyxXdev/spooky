use std::time::Duration;

/// Shared limits for request-body ingress handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestBodyGuardrailConfig {
    pub idle_timeout: Duration,
    pub total_timeout: Duration,
    pub max_body_bytes: usize,
    pub max_buffered_bytes: usize,
}

/// Point-in-time request-body state evaluated against ingress guardrails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestBodyGuardrailInput {
    pub elapsed: Duration,
    pub idle_for: Duration,
    pub bytes_received: usize,
    pub buffered_bytes: usize,
    pub next_chunk_bytes: usize,
    pub declared_content_length: Option<usize>,
    pub exempt_from_body_size_cap: bool,
}

/// Shared limits for response-body egress handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseBodyGuardrailConfig {
    pub idle_timeout: Duration,
    pub total_timeout: Duration,
    pub max_body_bytes: usize,
    pub unknown_length_prebuffer_bytes: usize,
    pub chunk_bytes: usize,
}

/// Point-in-time response-body state evaluated against egress guardrails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseBodyGuardrailInput {
    pub elapsed: Duration,
    pub idle_for: Duration,
    pub bytes_received: usize,
    pub prebuffered_bytes: usize,
    pub next_chunk_bytes: usize,
    pub declared_content_length: Option<usize>,
    pub headers_emitted: bool,
    pub progressive_emission_allowed: bool,
}

/// Canonical timeout reasons shared by request and response body handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyTimeoutKind {
    Idle,
    Total,
}

/// Canonical body-size and buffering rejection reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLimitKind {
    BodySizeCap,
    BufferedBodyCap,
    UnknownLengthPrebufferCap,
}

/// Policy describing how response body bytes may be emitted downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressiveEmissionPolicy {
    StreamProgressively,
    PrebufferUntilValidated,
    SuppressBody,
}

/// Canonical decision for request-body ingress guardrails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestBodyGuardrailDecision {
    Continue,
    Timeout { kind: BodyTimeoutKind },
    Reject { kind: BodyLimitKind },
}

/// Canonical decision for response-body egress guardrails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseBodyGuardrailDecision {
    Continue { emission: ProgressiveEmissionPolicy },
    Timeout { kind: BodyTimeoutKind },
    Reject { kind: BodyLimitKind },
}

/// Explicit chunk-emission sizing policy for progressive downstream writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseChunkEmissionPolicy {
    Passthrough,
    FixedSize { max_chunk_bytes: usize },
}
