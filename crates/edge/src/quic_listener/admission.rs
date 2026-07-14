#![allow(dead_code)]

use http::StatusCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthChallengeKind {
    ApiKey,
    Bearer,
}

impl AuthChallengeKind {
    pub(crate) fn as_www_authenticate(self) -> &'static str {
        match self {
            Self::ApiKey => "ApiKey",
            Self::Bearer => "Bearer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnauthorizedDecision {
    pub(crate) challenge: AuthChallengeKind,
    pub(crate) status: StatusCode,
    pub(crate) body: &'static [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RateLimitedDecision {
    pub(crate) status: StatusCode,
    pub(crate) body: &'static [u8],
    pub(crate) retry_after_seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverloadDecisionReason {
    Brownout,
    AdaptiveAdmission,
    RouteCap,
    RouteGlobalCap,
    GlobalInflight,
    UpstreamInflight,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverloadDecision {
    pub(crate) reason: OverloadDecisionReason,
    pub(crate) status: StatusCode,
    pub(crate) body: &'static [u8],
    pub(crate) retry_after_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmissionPolicyDecision {
    AdmitReady,
    Unauthorized(UnauthorizedDecision),
    RateLimited(RateLimitedDecision),
    Overloaded(OverloadDecision),
}
