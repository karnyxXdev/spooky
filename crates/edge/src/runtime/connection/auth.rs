use std::time::Duration;

use spooky_config::runtime::{
    RuntimeExternalAuth, RuntimeExternalAuthFailureMode, RuntimeExternalAuthRequestHeader,
};
use spooky_errors::ProxyError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAuthProviderKind {
    Http,
    Oidc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalAuthFailureDisposition {
    FailOpen,
    FailClosed,
}

impl ExternalAuthFailureDisposition {
    pub fn from_failure_mode(mode: RuntimeExternalAuthFailureMode) -> Self {
        match mode {
            RuntimeExternalAuthFailureMode::FailOpen => Self::FailOpen,
            RuntimeExternalAuthFailureMode::FailClosed => Self::FailClosed,
        }
    }

    pub fn fail_open(self) -> bool {
        matches!(self, Self::FailOpen)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAuthExecutionPolicy {
    pub timeout: Duration,
    pub failure_mode: RuntimeExternalAuthFailureMode,
}

impl ExternalAuthExecutionPolicy {
    pub fn disposition(self) -> ExternalAuthFailureDisposition {
        ExternalAuthFailureDisposition::from_failure_mode(self.failure_mode)
    }
}

#[derive(Debug, Clone)]
pub enum ExternalAuthProviderInput<'a> {
    Http {
        endpoint: &'a str,
        request_headers: &'a [RuntimeExternalAuthRequestHeader],
        response_header_allowlist: &'a [String],
    },
    Oidc {
        discovery_url: Option<&'a str>,
        issuer_url: Option<&'a str>,
        client_id: &'a str,
        client_secret: Option<&'a str>,
        audience: Option<&'a str>,
        scopes: &'a [String],
        request_headers: &'a [RuntimeExternalAuthRequestHeader],
        response_header_allowlist: &'a [String],
    },
}

impl<'a> ExternalAuthProviderInput<'a> {
    pub fn kind(&self) -> ExternalAuthProviderKind {
        match self {
            Self::Http { .. } => ExternalAuthProviderKind::Http,
            Self::Oidc { .. } => ExternalAuthProviderKind::Oidc,
        }
    }

    pub fn request_headers(&self) -> &'a [RuntimeExternalAuthRequestHeader] {
        match self {
            Self::Http {
                request_headers, ..
            }
            | Self::Oidc {
                request_headers, ..
            } => request_headers,
        }
    }

    pub fn response_header_allowlist(&self) -> &'a [String] {
        match self {
            Self::Http {
                response_header_allowlist,
                ..
            }
            | Self::Oidc {
                response_header_allowlist,
                ..
            } => response_header_allowlist,
        }
    }
}

impl<'a> From<&'a RuntimeExternalAuth> for ExternalAuthProviderInput<'a> {
    fn from(value: &'a RuntimeExternalAuth) -> Self {
        match value {
            RuntimeExternalAuth::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
                ..
            } => Self::Http {
                endpoint,
                request_headers,
                response_header_allowlist,
            },
            RuntimeExternalAuth::Oidc {
                discovery_url,
                issuer_url,
                client_id,
                client_secret,
                audience,
                scopes,
                request_headers,
                response_header_allowlist,
                ..
            } => Self::Oidc {
                discovery_url: discovery_url.as_deref(),
                issuer_url: issuer_url.as_deref(),
                client_id,
                client_secret: client_secret.as_deref(),
                audience: audience.as_deref(),
                scopes,
                request_headers,
                response_header_allowlist,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalAuthRequestContext<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub authority: Option<&'a str>,
    pub upstream_name: &'a str,
    pub backend_addr: &'a str,
}

#[derive(Debug)]
pub struct ExternalAuthResponseMetadata<'a> {
    pub status: http::StatusCode,
    pub headers: &'a http::HeaderMap,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalAuthMutationIntent {
    Upsert { name: Vec<u8>, value: Vec<u8> },
    Remove { name: Vec<u8> },
}

impl From<ExternalAuthMutationIntent> for PendingHeaderMutation {
    fn from(value: ExternalAuthMutationIntent) -> Self {
        match value {
            ExternalAuthMutationIntent::Upsert { name, value } => Self::Upsert { name, value },
            ExternalAuthMutationIntent::Remove { name } => Self::Remove { name },
        }
    }
}

impl From<PendingHeaderMutation> for ExternalAuthMutationIntent {
    fn from(value: PendingHeaderMutation) -> Self {
        match value {
            PendingHeaderMutation::Upsert { name, value } => Self::Upsert { name, value },
            PendingHeaderMutation::Remove { name } => Self::Remove { name },
        }
    }
}

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

#[derive(Debug)]
pub enum ExternalAuthDecisionOutcome {
    Allow {
        request_header_mutations: Vec<ExternalAuthMutationIntent>,
    },
    Deny(ExternalAuthDenyResponse),
    Redirect(ExternalAuthRedirectResponse),
    Challenge(ExternalAuthChallengeResponse),
    Timeout {
        disposition: ExternalAuthFailureDisposition,
    },
    Error {
        disposition: ExternalAuthFailureDisposition,
        error: ProxyError,
    },
}

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
