//! Hub inputs: files, admission hosts, the resolver and timing limits.

use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::dns::{Resolver, SystemResolver};

/// Inputs for a [`Hub`](crate::Hub). Start from [`Config::new`], which selects
/// the production limits, and adjust fields as needed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Path of the read-only peers table.
    pub peers_path: PathBuf,
    /// Directory that holds `ips.json`.
    pub data_dir: PathBuf,
    /// Host names whose current addresses may connect. Empty admits nobody.
    pub allowed_hosts: Vec<String>,
    /// Resolver used for admission lookups.
    pub resolver: Arc<dyn Resolver>,
    /// How often the peers table file is checked for changes. Must be nonzero.
    pub poll_interval: Duration,
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
    /// Production defaults for the given files and admission hosts.
    #[must_use]
    pub fn new(peers_path: PathBuf, data_dir: PathBuf, allowed_hosts: Vec<String>) -> Self {
        Self {
            peers_path,
            data_dir,
            allowed_hosts,
            resolver: Arc::new(SystemResolver),
            poll_interval: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(10),
            accept_timeout: Duration::from_secs(10),
            control_idle: Duration::from_secs(90),
            udp_idle: Duration::from_secs(120),
        }
    }
}
