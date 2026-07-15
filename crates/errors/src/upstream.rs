#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamErrorDetails {
    pub detail: String,
    pub is_connect: bool,
}

impl UpstreamErrorDetails {
    pub fn new(detail: String, is_connect: bool) -> Self {
        Self { detail, is_connect }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamErrorCategory {
    Timeout,
    Transport,
    Tls,
    Protocol,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamTlsReason {
    UnknownIssuer,
    ExpiredCertificate,
    HostnameMismatch,
    Alpn,
    Handshake,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpstreamErrorClassification {
    pub category: UpstreamErrorCategory,
    pub tls_reason: Option<UpstreamTlsReason>,
}

impl UpstreamErrorClassification {
    pub const fn timeout() -> Self {
        Self {
            category: UpstreamErrorCategory::Timeout,
            tls_reason: None,
        }
    }

    pub const fn transport() -> Self {
        Self {
            category: UpstreamErrorCategory::Transport,
            tls_reason: None,
        }
    }

    pub const fn tls(reason: UpstreamTlsReason) -> Self {
        Self {
            category: UpstreamErrorCategory::Tls,
            tls_reason: Some(reason),
        }
    }

    pub const fn protocol() -> Self {
        Self {
            category: UpstreamErrorCategory::Protocol,
            tls_reason: None,
        }
    }

    pub const fn internal() -> Self {
        Self {
            category: UpstreamErrorCategory::Internal,
            tls_reason: None,
        }
    }
}
