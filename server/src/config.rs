//! Hub inputs: the data directory, admission hosts, the resolver and timing limits.

use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::dns::{Resolver, SystemResolver};

/// Inputs for a [`Hub`](crate::Hub). Start from [`Config::new`], which selects
/// the production limits, and adjust fields as needed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Directory that holds `ips.json`.
    pub data_dir: PathBuf,
    /// Host names whose current addresses may connect. Empty admits only
    /// loopback, private and link-local sources.
    pub allowed_hosts: Vec<String>,
    /// Resolver used for admission lookups.
    pub resolver: Arc<dyn Resolver>,
    /// Deadline for the first Hello frame on a new connection.
    pub handshake_timeout: Duration,
    /// How long an open request waits for the destination to accept.
    pub accept_timeout: Duration,
    /// How long a control stream may stay silent before it is closed.
    pub control_idle: Duration,
    /// How long a UDP flow may stay idle before it is closed.
    pub udp_idle: Duration,
}

impl Config {
    /// Production defaults for the given data directory and admission hosts.
    #[must_use]
    pub fn new(data_dir: PathBuf, allowed_hosts: Vec<String>) -> Self {
        Self {
            data_dir,
            allowed_hosts,
            resolver: Arc::new(SystemResolver),
            handshake_timeout: Duration::from_secs(10),
            accept_timeout: Duration::from_secs(10),
            control_idle: Duration::from_secs(90),
            udp_idle: Duration::from_secs(120),
        }
    }
}
