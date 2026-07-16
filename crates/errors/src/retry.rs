use crate::{PoolError, ProxyError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamRetryReason {
    Timeout,
    Transport,
    Pool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamTerminalErrorKind {
    PoolSend,
    Tls,
    Protocol,
    Bridge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpstreamRetryability {
    Retryable(UpstreamRetryReason),
    Terminal(UpstreamTerminalErrorKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicyDenialReason {
    TerminalError(UpstreamTerminalErrorKind),
    MethodNotIdempotent,
    RequestBodyNotReplayable,
    AttemptLimitReached,
    BudgetDenied,
    NoAlternateBackend,
    AlternateBackendUnhealthy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicyFacts {
    pub retryability: UpstreamRetryability,
    pub method_idempotent: bool,
    pub request_body_replayable: bool,
    pub attempt_count: u8,
    pub max_attempts: u8,
    pub budget_available: bool,
    pub alternate_backend_available: bool,
    pub alternate_backend_healthy: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryPolicyDecision {
    Retry { reason: UpstreamRetryReason },
    DoNotRetry {
        denial: Option<RetryPolicyDenialReason>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryTelemetryReason {
    Timeout,
    Transport,
    Pool,
}

impl From<UpstreamRetryReason> for RetryTelemetryReason {
    fn from(value: UpstreamRetryReason) -> Self {
        match value {
            UpstreamRetryReason::Timeout => Self::Timeout,
            UpstreamRetryReason::Transport => Self::Transport,
            UpstreamRetryReason::Pool => Self::Pool,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HedgePolicyFacts {
    pub hedging_configured: bool,
    pub bodyless_mode: bool,
    pub tunnel_allowed: bool,
    pub method_allowed: bool,
    pub alternate_backend_available: bool,
    pub budget_available: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgePolicyDenialReason {
    HedgingDisabled,
    NotBodylessMode,
    TunnelRequest,
    MethodNotAllowed,
    NoAlternateBackend,
    BudgetDenied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgePolicyDecision {
    Hedge,
    DoNotHedge { denial: HedgePolicyDenialReason },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HedgeTelemetryReason {
    DelayElapsed,
    PrimaryWonAfterTrigger,
    HedgeWon,
    HedgeWasted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlternateBackendChoice<Backend> {
    pub backend: Backend,
    pub index: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AlternateBackendPolicyFacts {
    pub candidate_available: bool,
    pub excluded_primary_backend: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlternateBackendDenialReason {
    NoCandidateAvailable,
    PrimaryBackendNotExcluded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AlternateBackendDecision<Backend> {
    Select(AlternateBackendChoice<Backend>),
    DoNotSelect { denial: AlternateBackendDenialReason },
}

pub type RetryPolicyInput = RetryPolicyFacts;
pub type RetryPolicyDenial = RetryPolicyDenialReason;

pub fn is_idempotent_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "TRACE"
    )
}

pub fn classify_retryability(err: &ProxyError) -> UpstreamRetryability {
    match err {
        ProxyError::Transport(_) => UpstreamRetryability::Retryable(UpstreamRetryReason::Transport),
        ProxyError::Timeout => UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout),
        ProxyError::Pool(PoolError::Send(_)) => {
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::PoolSend)
        }
        ProxyError::Pool(_) => UpstreamRetryability::Retryable(UpstreamRetryReason::Pool),
        ProxyError::Tls(_) => UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls),
        ProxyError::Protocol(_) => {
            UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Protocol)
        }
        ProxyError::Bridge(_) => UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Bridge),
    }
}

pub fn evaluate_retry_policy(input: RetryPolicyFacts) -> RetryPolicyDecision {
    match input.retryability {
        UpstreamRetryability::Terminal(kind) => RetryPolicyDecision::DoNotRetry {
            denial: Some(RetryPolicyDenialReason::TerminalError(kind)),
        },
        UpstreamRetryability::Retryable(reason) => {
            if !input.method_idempotent {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::MethodNotIdempotent),
                }
            } else if !input.request_body_replayable {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::RequestBodyNotReplayable),
                }
            } else if input.attempt_count >= input.max_attempts {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::AttemptLimitReached),
                }
            } else if !input.budget_available {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::BudgetDenied),
                }
            } else if !input.alternate_backend_available {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::NoAlternateBackend),
                }
            } else if !input.alternate_backend_healthy {
                RetryPolicyDecision::DoNotRetry {
                    denial: Some(RetryPolicyDenialReason::AlternateBackendUnhealthy),
                }
            } else {
                RetryPolicyDecision::Retry { reason }
            }
        }
    }
}

pub fn is_retryable(err: &ProxyError) -> bool {
    matches!(
        classify_retryability(err),
        UpstreamRetryability::Retryable(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retry_facts() -> RetryPolicyFacts {
        RetryPolicyFacts {
            retryability: UpstreamRetryability::Retryable(UpstreamRetryReason::Timeout),
            method_idempotent: true,
            request_body_replayable: true,
            attempt_count: 0,
            max_attempts: 1,
            budget_available: true,
            alternate_backend_available: true,
            alternate_backend_healthy: true,
        }
    }

    #[test]
    fn idempotent_method_helper_matches_expected_methods() {
        assert!(is_idempotent_method("GET"));
        assert!(is_idempotent_method("delete"));
        assert!(!is_idempotent_method("POST"));
        assert!(!is_idempotent_method("PATCH"));
    }

    #[test]
    fn terminal_errors_return_explicit_denial() {
        let mut facts = retry_facts();
        facts.retryability = UpstreamRetryability::Terminal(UpstreamTerminalErrorKind::Tls);

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::TerminalError(
                    UpstreamTerminalErrorKind::Tls
                )),
            }
        );
    }

    #[test]
    fn method_idempotency_blocks_retry() {
        let mut facts = retry_facts();
        facts.method_idempotent = false;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::MethodNotIdempotent),
            }
        );
    }

    #[test]
    fn request_body_replayability_blocks_retry() {
        let mut facts = retry_facts();
        facts.request_body_replayable = false;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::RequestBodyNotReplayable),
            }
        );
    }

    #[test]
    fn attempt_limit_blocks_retry() {
        let mut facts = retry_facts();
        facts.attempt_count = 1;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::AttemptLimitReached),
            }
        );
    }

    #[test]
    fn unhealthy_alternate_backend_blocks_retry() {
        let mut facts = retry_facts();
        facts.alternate_backend_healthy = false;

        assert_eq!(
            evaluate_retry_policy(facts),
            RetryPolicyDecision::DoNotRetry {
                denial: Some(RetryPolicyDenialReason::AlternateBackendUnhealthy),
            }
        );
    }

    #[test]
    fn retryable_timeout_allows_retry() {
        assert_eq!(
            evaluate_retry_policy(retry_facts()),
            RetryPolicyDecision::Retry {
                reason: UpstreamRetryReason::Timeout,
            }
        );
    }
}
