use super::{
    resolution::RuntimeBackendResolution,
    state::{
        BackendHealthState, BackendIdentity, BackendLifecycleSnapshot, BackendMembershipState,
        BackendResolutionState,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendLifecycleState {
    pub identity: BackendIdentity,
    pub resolution: BackendResolutionState,
    pub health: BackendHealthState,
    pub membership: BackendMembershipState,
}

impl RuntimeBackendLifecycleState {
    pub fn new(
        identity: BackendIdentity,
        resolution: BackendResolutionState,
        health: BackendHealthState,
        membership: BackendMembershipState,
    ) -> Self {
        Self {
            identity,
            resolution,
            health,
            membership,
        }
    }

    pub fn from_resolution_seed(resolution: &RuntimeBackendResolution) -> Self {
        Self {
            identity: BackendIdentity::from(resolution),
            resolution: BackendResolutionState::from(resolution),
            health: BackendHealthState::Unknown,
            membership: BackendMembershipState::Active,
        }
    }

    pub fn snapshot(&self) -> BackendLifecycleSnapshot {
        BackendLifecycleSnapshot {
            identity: self.identity.clone(),
            resolution: self.resolution.clone(),
            health: self.health.clone(),
            membership: self.membership,
        }
    }
}

impl From<&RuntimeBackendResolution> for RuntimeBackendLifecycleState {
    fn from(value: &RuntimeBackendResolution) -> Self {
        Self::from_resolution_seed(value)
    }
}

impl From<&RuntimeBackendLifecycleState> for BackendLifecycleSnapshot {
    fn from(value: &RuntimeBackendLifecycleState) -> Self {
        value.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_state_seeds_from_resolution_with_unknown_health() {
        let resolution = RuntimeBackendResolution::hostname(
            "https://backend.internal:8443".to_string(),
            "backend.internal".to_string(),
            8443,
        );

        let state = RuntimeBackendLifecycleState::from(&resolution);

        assert_eq!(state.identity.backend_addr, "https://backend.internal:8443");
        assert_eq!(state.membership, BackendMembershipState::Active);
        assert_eq!(state.health, BackendHealthState::Unknown);
        assert!(state.resolution.is_hostname());
    }
}
