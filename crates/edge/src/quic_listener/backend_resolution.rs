use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use log::{debug, error, info, warn};

use super::*;

impl QUICListener {
    pub(super) fn spawn_backend_dns_refresh(
        config: &RuntimeConfig,
        backend_resolution_store: Arc<RuntimeBackendResolutionStore>,
        backend_dns_resolver: SharedDnsResolver,
        metrics: Arc<Metrics>,
    ) {
        if !config.performance.backend_dns_refresh_enabled {
            return;
        }

        if backend_resolution_store.hostname_entries().is_empty() {
            debug!("backend DNS refresh disabled: no hostname-based backends configured");
            return;
        }

        let interval_ms = config.performance.backend_dns_refresh_interval_ms.max(1);
        let handle = match runtime_handle() {
            Some(handle) => handle,
            None => {
                error!("Backend DNS refresh disabled: no Tokio runtime available");
                return;
            }
        };

        spawn_supervised_async_task(&handle, "backend-dns-refresh", Some(metrics), async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                ticker.tick().await;
                for backend in backend_resolution_store.hostname_entries() {
                    let lookup_host = backend.authority_host.clone();
                    let resolved = match tokio::net::lookup_host((lookup_host.as_str(), 0)).await {
                        Ok(addrs) => addrs
                            .map(|addr| SocketAddr::new(addr.ip(), backend.authority_port))
                            .collect::<Vec<_>>(),
                        Err(err) => {
                            warn!(
                                "backend DNS refresh failed for '{}' (backend '{}'): {}",
                                backend.authority_host, backend.backend_addr, err
                            );
                            continue;
                        }
                    };

                    if resolved.is_empty() {
                        warn!(
                            "backend DNS refresh returned no addresses for '{}' (backend '{}'); keeping last known good addresses",
                            backend.authority_host, backend.backend_addr
                        );
                        continue;
                    }

                    let refreshed_at = SystemTime::now();
                    let Some(update) = backend_resolution_store.update_hostname_resolution(
                        &backend.backend_addr,
                        resolved.clone(),
                        refreshed_at,
                    ) else {
                        continue;
                    };

                    let resolver_update = backend_dns_resolver.replace_host_addrs(
                        &backend.authority_host,
                        resolved
                            .into_iter()
                            .map(|addr| SocketAddr::new(ip_only(addr), 0)),
                    );

                    if update.changed() || resolver_update.changed() {
                        info!(
                            "backend DNS refresh updated '{}' (backend '{}'): {:?} -> {:?} generation={}",
                            update.authority_host,
                            update.backend_addr,
                            update.previous_addrs,
                            update.current_addrs,
                            update.refresh_generation
                        );
                    } else {
                        debug!(
                            "backend DNS refresh unchanged for '{}' (backend '{}') generation={}",
                            update.authority_host, update.backend_addr, update.refresh_generation
                        );
                    }
                }
            }
        });
    }
}

fn ip_only(addr: SocketAddr) -> IpAddr {
    addr.ip()
}
