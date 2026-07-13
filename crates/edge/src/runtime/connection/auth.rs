use spooky_errors::ProxyError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalAuthDecision {
    Allow {
        request_header_mutations: Vec<PendingHeaderMutation>,
    },
    Deny(ExternalAuthDenyResponse),
    Redirect(ExternalAuthRedirectResponse),
    Challenge(ExternalAuthChallengeResponse),
}

pub type ExternalAuthResult = Result<ExternalAuthDecision, ProxyError>;

/// Result type returned by the in-flight upstream forwarding task.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthDenyResponse {
    pub status: http::StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthRedirectResponse {
    pub status: http::StatusCode,
    pub headers: Vec<(String, String)>,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalAuthChallengeResponse {
    pub status: http::StatusCode,
    pub headers: Vec<(String, String)>,
    pub www_authenticate: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingHeaderMutation {
    Upsert { name: Vec<u8>, value: Vec<u8> },
    Remove { name: Vec<u8> },
}
