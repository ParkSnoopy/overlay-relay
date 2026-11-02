//! `overlay-hub`: serves the overlay relay inside its container.
//!
//! Admitted hosts come only from the `OVERLAY_ALLOWED_HOST` environment
//! variable, a comma-separated list. The peers table is read-only.

use std::{env, path::PathBuf, process::ExitCode};

use overlay_relay::{Config, Error, Hub, LISTEN_ADDRESS, Result};
use tokio::{
    net::TcpListener,
    select,
    signal::unix::{SignalKind, signal},
};
use tokio_util::sync::CancellationToken;
use tracing::{Level, error, info};

const ALLOWED_HOST_ENV: &str = "OVERLAY_ALLOWED_HOST";
const PEERS_PATH_ENV: &str = "OVERLAY_PEERS_PATH";
const DATA_DIR_ENV: &str = "OVERLAY_DATA_DIR";
const LISTEN_ADDRESS_ENV: &str = "OVERLAY_LISTEN_ADDRESS";
const PEERS_PATH: &str = "/etc/overlay-relay/peers.json";
const DATA_DIR: &str = "/var/lib/overlay-relay";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(Level::INFO)
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            error!(error = %failure, "overlay hub stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let hosts = allowed_hosts(&env::var(ALLOWED_HOST_ENV).unwrap_or_default());
    if hosts.is_empty() {
        return Err(Error::Config("overlay admission requires an allowed host"));
    }
    let host_count = hosts.len();
    let peers_path =
        env::var(PEERS_PATH_ENV).map_or_else(|_| PathBuf::from(PEERS_PATH), PathBuf::from);
    let data_dir = env::var(DATA_DIR_ENV).map_or_else(|_| PathBuf::from(DATA_DIR), PathBuf::from);
    let listen = env::var(LISTEN_ADDRESS_ENV).unwrap_or_else(|_| LISTEN_ADDRESS.to_owned());
    let config = Config::new(peers_path, data_dir, hosts);
    let hub = Hub::new(config).await?;
    let listener = TcpListener::bind(listen).await?;
    let shutdown = CancellationToken::new();
    tokio::spawn(stop_on_signal(shutdown.clone()));
    info!(hosts = host_count, "overlay hub listening");
    hub.serve(listener, shutdown).await
}

/// Splits the comma-separated environment value, dropping empty entries.
fn allowed_hosts(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .collect()
}

async fn stop_on_signal(shutdown: CancellationToken) {
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(terminate) => terminate,
        Err(failure) => {
            error!(error = %failure, "cannot listen for SIGTERM");
            return;
        }
    };
    select! {
        biased;
        _ = terminate.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    info!("overlay hub shutdown requested");
    shutdown.cancel();
}

#[cfg(test)]
mod tests {
    use super::allowed_hosts;

    #[test]
    fn host_list_drops_empty_entries() {
        assert_eq!(
            allowed_hosts("engine,,other,"),
            vec!["engine".to_owned(), "other".to_owned()]
        );
        assert_eq!(allowed_hosts(""), Vec::<String>::new());
    }
}
