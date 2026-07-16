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

pub(crate) fn evaluate_request_body_timeouts(
    config: RequestBodyGuardrailConfig,
    input: RequestBodyGuardrailInput,
) -> RequestBodyGuardrailDecision {
    if input.elapsed >= config.total_timeout {
        return RequestBodyGuardrailDecision::Timeout {
            kind: BodyTimeoutKind::Total,
        };
    }

    if input.idle_for >= config.idle_timeout {
        return RequestBodyGuardrailDecision::Timeout {
            kind: BodyTimeoutKind::Idle,
        };
    }

    RequestBodyGuardrailDecision::Continue
}

pub(crate) fn evaluate_request_body_ingress(
    config: RequestBodyGuardrailConfig,
    input: RequestBodyGuardrailInput,
) -> RequestBodyGuardrailDecision {
    let next_total = input.bytes_received.saturating_add(input.next_chunk_bytes);
    if !input.exempt_from_body_size_cap && next_total > config.max_body_bytes {
        return RequestBodyGuardrailDecision::Reject {
            kind: BodyLimitKind::BodySizeCap,
        };
    }

    let next_buffered = input.buffered_bytes.saturating_add(input.next_chunk_bytes);
    if next_buffered > config.max_buffered_bytes {
        let kind = if input.declared_content_length.is_some() {
            BodyLimitKind::BufferedBodyCap
        } else {
            BodyLimitKind::UnknownLengthPrebufferCap
        };
        return RequestBodyGuardrailDecision::Reject { kind };
    }

    RequestBodyGuardrailDecision::Continue
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_idle_timeout_rejects() {
        let decision = evaluate_request_body_timeouts(
            RequestBodyGuardrailConfig {
                idle_timeout: Duration::from_secs(5),
                total_timeout: Duration::from_secs(30),
                max_body_bytes: usize::MAX,
                max_buffered_bytes: usize::MAX,
            },
            RequestBodyGuardrailInput {
                elapsed: Duration::from_secs(4),
                idle_for: Duration::from_secs(5),
                bytes_received: 0,
                buffered_bytes: 0,
                next_chunk_bytes: 0,
                declared_content_length: None,
                exempt_from_body_size_cap: false,
            },
        );

        assert_eq!(
            decision,
            RequestBodyGuardrailDecision::Timeout {
                kind: BodyTimeoutKind::Idle,
            }
        );
    }

    #[test]
    fn request_body_total_timeout_rejects() {
        let decision = evaluate_request_body_timeouts(
            RequestBodyGuardrailConfig {
                idle_timeout: Duration::from_secs(5),
                total_timeout: Duration::from_secs(30),
                max_body_bytes: usize::MAX,
                max_buffered_bytes: usize::MAX,
            },
            RequestBodyGuardrailInput {
                elapsed: Duration::from_secs(30),
                idle_for: Duration::from_secs(1),
                bytes_received: 0,
                buffered_bytes: 0,
                next_chunk_bytes: 0,
                declared_content_length: None,
                exempt_from_body_size_cap: false,
            },
        );

        assert_eq!(
            decision,
            RequestBodyGuardrailDecision::Timeout {
                kind: BodyTimeoutKind::Total,
            }
        );
    }

    #[test]
    fn request_body_size_cap_respects_connect_exemption() {
        let config = RequestBodyGuardrailConfig {
            idle_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30),
            max_body_bytes: 16,
            max_buffered_bytes: usize::MAX,
        };
        let input = RequestBodyGuardrailInput {
            elapsed: Duration::ZERO,
            idle_for: Duration::ZERO,
            bytes_received: 12,
            buffered_bytes: 0,
            next_chunk_bytes: 8,
            declared_content_length: None,
            exempt_from_body_size_cap: true,
        };

        assert_eq!(
            evaluate_request_body_ingress(config, input),
            RequestBodyGuardrailDecision::Continue
        );
    }

    #[test]
    fn request_body_unknown_length_prebuffer_cap_rejects() {
        let decision = evaluate_request_body_ingress(
            RequestBodyGuardrailConfig {
                idle_timeout: Duration::from_secs(5),
                total_timeout: Duration::from_secs(30),
                max_body_bytes: usize::MAX,
                max_buffered_bytes: 10,
            },
            RequestBodyGuardrailInput {
                elapsed: Duration::ZERO,
                idle_for: Duration::ZERO,
                bytes_received: 0,
                buffered_bytes: 6,
                next_chunk_bytes: 5,
                declared_content_length: None,
                exempt_from_body_size_cap: false,
            },
        );

        assert_eq!(
            decision,
            RequestBodyGuardrailDecision::Reject {
                kind: BodyLimitKind::UnknownLengthPrebufferCap,
            }
        );
    }
}
