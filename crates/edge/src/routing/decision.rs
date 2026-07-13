#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutePreference {
    KeepCurrent,
    TakeCandidatePathLen,
    TakeCandidateHostSpecific,
    TakeCandidateExactHost,
    TakeCandidateWildcardSpecificity,
    TakeCandidateMethodSpecific,
    TakeCandidateLexicalOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteDecisionReason {
    HostTrieNoDefault,
    HostPathLongerOrEqual,
    DefaultPathLonger,
    HostSpecificTieBreak,
    ExactHostTieBreak,
    WildcardSpecificityTieBreak,
    MethodSpecificTieBreak,
    LexicalTieBreak,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteDecision<'a> {
    /// Name of the upstream selected by route matching; auth/policy stays attached to that upstream.
    pub upstream: &'a str,
    pub matched_path_len: usize,
    pub host_specific: bool,
    pub reason: RouteDecisionReason,
}

#[inline(always)]
pub fn route_preference_reason(preference: RoutePreference) -> Option<RouteDecisionReason> {
    match preference {
        RoutePreference::KeepCurrent => None,
        RoutePreference::TakeCandidatePathLen => Some(RouteDecisionReason::HostPathLongerOrEqual),
        RoutePreference::TakeCandidateHostSpecific => {
            Some(RouteDecisionReason::HostSpecificTieBreak)
        }
        RoutePreference::TakeCandidateExactHost => Some(RouteDecisionReason::ExactHostTieBreak),
        RoutePreference::TakeCandidateWildcardSpecificity => {
            Some(RouteDecisionReason::WildcardSpecificityTieBreak)
        }
        RoutePreference::TakeCandidateMethodSpecific => {
            Some(RouteDecisionReason::MethodSpecificTieBreak)
        }
        RoutePreference::TakeCandidateLexicalOrder => Some(RouteDecisionReason::LexicalTieBreak),
    }
}
