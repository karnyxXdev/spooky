use std::{net::SocketAddr, time::SystemTime};

use crate::runtime::backend::{
    event::BackendRefreshResult,
    resolution::RuntimeBackendAddressKind,
    state::{BackendIdentity, BackendResolutionState},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBackendResolutionUpdate {
    pub backend_addr: String,
    pub authority_host: String,
    pub authority_port: u16,
    pub address_kind: RuntimeBackendAddressKind,
    pub previous_addrs: Vec<SocketAddr>,
    pub current_addrs: Vec<SocketAddr>,
    pub last_refresh_success_at: Option<SystemTime>,
    pub refresh_generation: u64,
}

impl RuntimeBackendResolutionUpdate {
    pub fn changed(&self) -> bool {
        self.previous_addrs != self.current_addrs
    }

    pub fn cleared(&self) -> bool {
        self.current_addrs.is_empty()
    }

    pub fn identity(&self) -> BackendIdentity {
        BackendIdentity::new(self.backend_addr.clone())
    }

    pub fn resolution_state(&self) -> BackendResolutionState {
        BackendResolutionState {
            authority_host: self.authority_host.clone(),
            authority_port: self.authority_port,
            address_kind: self.address_kind,
            resolved_addrs: self.current_addrs.clone(),
            last_refresh_success_at: self.last_refresh_success_at,
            refresh_generation: self.refresh_generation,
        }
    }

    pub fn refresh_result(&self) -> BackendRefreshResult {
        BackendRefreshResult::from(self)
    }
}
