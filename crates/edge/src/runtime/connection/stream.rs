#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamPhase {
    /// Still receiving request headers/body from the QUIC client.
    ReceivingRequest,
    /// Request fully received; waiting for the upstream response.
    AwaitingUpstream,
    /// Upstream responded; streaming response back to the QUIC client.
    SendingResponse,
    /// Stream finished cleanly.
    Completed,
    /// Stream terminated with an error.
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAdmissionState {
    /// Request admission is still pending an external auth/authz decision.
    WaitingForAuth,
    /// Request cleared admission checks and may proceed to upstream forwarding.
    ReadyToForward,
    /// Request was denied by admission/auth checks and should not be forwarded.
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelMode {
    None,
    Connect,
    Websocket,
}
