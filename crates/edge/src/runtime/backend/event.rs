use std::{net::SocketAddr, time::{Duration, SystemTime}};

use spooky_lb::health::HealthFailureReason;

use super::{
    state::{
        BackendHealthState, BackendIdentity, BackendLifecycleSnapshot, BackendMembershipState,
        BackendResolutionState,
    },
    update::RuntimeBackendResolutionUpdate,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendLifecycleEvent {
    Refresh(BackendRefreshResult),
    HealthObservation(BackendHealthObservation),
    RequestFeedback(BackendRequestFeedback),
    Mutation(BackendLifecycleMutation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendLifecycleMutation {
    ResolutionUpdated {
        identity: BackendIdentity,
        state: BackendResolutionState,
        result: BackendRefreshResult,
    },
    HealthUpdated {
        identity: BackendIdentity,
        state: BackendHealthState,
    },
    MembershipUpdated {
        identity: BackendIdentity,
        state: BackendMembershipState,
    },
    SnapshotPublished(BackendLifecycleSnapshot),
    Noop {
        identity: BackendIdentity,
        reason: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRefreshResult {
    pub identity: BackendIdentity,
    pub outcome: BackendRefreshOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendRefreshOutcome {
    Updated {
        previous_addrs: Vec<SocketAddr>,
        current_addrs: Vec<SocketAddr>,
        refreshed_at: Option<SystemTime>,
        refresh_generation: u64,
    },
    Unchanged {
        current_addrs: Vec<SocketAddr>,
        refreshed_at: Option<SystemTime>,
        refresh_generation: u64,
    },
    EmptyAnswerRetained {
        retained_addrs: Vec<SocketAddr>,
    },
    LookupFailed {
        retained_addrs: Vec<SocketAddr>,
        error: String,
    },
}

impl From<&RuntimeBackendResolutionUpdate> for BackendRefreshResult {
    fn from(value: &RuntimeBackendResolutionUpdate) -> Self {
        let outcome = if value.changed() {
            BackendRefreshOutcome::Updated {
                previous_addrs: value.previous_addrs.clone(),
                current_addrs: value.current_addrs.clone(),
                refreshed_at: value.last_refresh_success_at,
                refresh_generation: value.refresh_generation,
            }
        } else {
            BackendRefreshOutcome::Unchanged {
                current_addrs: value.current_addrs.clone(),
                refreshed_at: value.last_refresh_success_at,
                refresh_generation: value.refresh_generation,
            }
        };

        Self {
            identity: BackendIdentity::new(value.backend_addr.clone()),
            outcome,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendHealthObservation {
    pub identity: BackendIdentity,
    pub source: BackendHealthObservationSource,
    pub outcome: BackendHealthObservationOutcome,
    pub reason: Option<HealthFailureReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealthObservationSource {
    ActiveCheck,
    PassiveRequest,
    RequestCompletion,
    ControlPlane,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendHealthObservationOutcome {
    Success,
    Failure,
    Neutral,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRequestFeedback {
    pub identity: BackendIdentity,
    pub elapsed: Duration,
    pub status: Option<u16>,
    pub outcome: BackendRequestFeedbackOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendRequestFeedbackOutcome {
    Success,
    Neutral,
    Failure {
        reason: Option<HealthFailureReason>,
    },
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::SystemTime};

    use super::*;
    use crate::runtime::backend::{
        resolution::{RuntimeBackendAddressKind, RuntimeBackendResolution},
        update::RuntimeBackendResolutionUpdate,
    };

    #[test]
    fn refresh_result_from_update_marks_changed_updates() {
        let now = SystemTime::now();
        let update = RuntimeBackendResolutionUpdate {
            backend_addr: "https://backend.internal:8443".to_string(),
            authority_host: "backend.internal".to_string(),
            authority_port: 8443,
            address_kind: RuntimeBackendAddressKind::Hostname,
            previous_addrs: vec!["10.0.0.10:8443".parse::<SocketAddr>().expect("addr")],
            current_addrs: vec!["10.0.0.11:8443".parse::<SocketAddr>().expect("addr")],
            last_refresh_success_at: Some(now),
            refresh_generation: 2,
        };

        let result = BackendRefreshResult::from(&update);

        assert_eq!(result.identity.backend_addr, update.backend_addr);
        assert!(matches!(
            result.outcome,
            BackendRefreshOutcome::Updated {
                refresh_generation: 2,
                ..
            }
        ));
    }

    #[test]
    fn refresh_result_from_update_marks_unchanged_updates() {
        let resolution = RuntimeBackendResolution::hostname(
            "https://backend.internal:8443".to_string(),
            "backend.internal".to_string(),
            8443,
        );
        let state = BackendResolutionState::from(&resolution);
        let update = RuntimeBackendResolutionUpdate {
            backend_addr: resolution.backend_addr.clone(),
            authority_host: state.authority_host,
            authority_port: state.authority_port,
            address_kind: state.address_kind,
            previous_addrs: vec!["10.0.0.10:8443".parse::<SocketAddr>().expect("addr")],
            current_addrs: vec!["10.0.0.10:8443".parse::<SocketAddr>().expect("addr")],
            last_refresh_success_at: None,
            refresh_generation: 1,
        };

        let result = BackendRefreshResult::from(&update);

        assert!(matches!(
            result.outcome,
            BackendRefreshOutcome::Unchanged {
                refresh_generation: 1,
                ..
            }
        ));
    }
}
