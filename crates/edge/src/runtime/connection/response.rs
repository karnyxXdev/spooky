use bytes::Bytes;
use spooky_errors::{
    HedgeOutcomeTelemetryReason, HedgeTriggerTelemetryReason, ProxyError,
    RetryAttemptTelemetryReason, RetryPolicyDenialReason,
};
use tokio::sync::mpsc;

pub enum ForwardSuccess {
    Response {
        status: http::StatusCode,
        headers: http::HeaderMap,
        body: hyper::body::Incoming,
    },
    Tunnel {
        status: http::StatusCode,
        headers: http::HeaderMap,
        response_chunk_rx: mpsc::Receiver<ResponseChunk>,
    },
}

pub type ForwardResult = Result<ForwardSuccess, ProxyError>;

#[derive(Debug, Clone, Copy, Default)]
pub struct RetryTelemetry {
    pub count: u8,
    pub attempt_reason: Option<RetryAttemptTelemetryReason>,
    pub denial_reason: Option<RetryPolicyDenialReason>,
}

impl RetryTelemetry {
    pub fn record_attempt(&mut self, reason: RetryAttemptTelemetryReason) {
        self.count = self.count.saturating_add(1);
        self.attempt_reason = Some(reason);
    }

    pub fn record_denial(&mut self, denial_reason: Option<RetryPolicyDenialReason>) {
        if self.denial_reason.is_none() {
            self.denial_reason = denial_reason;
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ForwardingPolicyTelemetry {
    pub hedge: HedgeTelemetry,
    pub retry: RetryTelemetry,
}

pub struct UpstreamResult {
    pub forward: ForwardResult,
    pub policy: ForwardingPolicyTelemetry,
}

/// A chunk of the upstream response being streamed back to the client.
#[derive(Debug)]
pub enum ResponseChunk {
    /// Emit downstream response headers (used when headers are deferred until
    /// body-size validation completes).
    Start {
        status: http::StatusCode,
        headers: Vec<(Vec<u8>, Vec<u8>)>,
    },
    Data(Bytes),
    Trailers {
        headers: Vec<(Vec<u8>, Vec<u8>)>,
    },
    End,
    Error(ProxyError),
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HedgeTelemetry {
    pub trigger_reason: Option<HedgeTriggerTelemetryReason>,
    pub outcome_reason: Option<HedgeOutcomeTelemetryReason>,
    pub primary_late_ms: u64,
}

impl HedgeTelemetry {
    pub fn record_trigger(&mut self, reason: HedgeTriggerTelemetryReason) {
        self.trigger_reason = Some(reason);
    }

    pub fn record_outcome(&mut self, reason: HedgeOutcomeTelemetryReason) {
        self.outcome_reason = Some(reason);
    }

    pub fn observe_primary_late_ms(&mut self, late_ms: u64) {
        self.primary_late_ms = late_ms;
    }
}
