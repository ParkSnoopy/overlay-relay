//! `overlay-hub`: serves the overlay relay inside its container.
//!
//! Everything is optional. `OVERLAY_ALLOWED_HOST` is a comma-separated list
//! of host names that may connect; without it every private-network source
//! may. A client needs no enrollment: its own key is its identity.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::LazyLock,
};

use clap::{Args, Parser, Subcommand};
use overlay_relay::{AddressSpace, Config, Hub, LISTEN_ADDRESS, Result};
use tokio::{
    net::TcpListener,
    select,
    signal::unix::{SignalKind, signal},
};
use tokio_util::sync::CancellationToken;
use tracing::{Level, error, info};

const ALLOWED_HOST_ENV: &str = "OVERLAY_ALLOWED_HOST";
const DATA_DIR_ENV: &str = "OVERLAY_DATA_DIR";
const LISTEN_ADDRESS_ENV: &str = "OVERLAY_LISTEN_ADDRESS";
const DATA_DIR: &str = "/var/lib/overlay-relay";

static CLI_VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{} (protocol v{})",
        env!("CARGO_PKG_VERSION"),
        overlay_relay::VERSION
    )
});

/// Serve the overlay hub, or administer its persisted configuration.
#[derive(Debug, Parser)]
#[command(name = "overlay-hub", version = CLI_VERSION.as_str())]
struct Arguments {
    /// Directory containing address assignments and room policy.
    #[arg(long, env = DATA_DIR_ENV, default_value = DATA_DIR, global = true)]
    data_dir: PathBuf,
    /// Comma-separated VPN engine hosts admitted to the hub.
    #[arg(long, env = ALLOWED_HOST_ENV, default_value = "")]
    allowed_host: String,
    /// TCP listening address.
    #[arg(long, env = LISTEN_ADDRESS_ENV, default_value = LISTEN_ADDRESS)]
    listen_address: String,
    /// Canonical RFC 1918 subnet (/8 through /30).
    #[arg(long, env = "OVERLAY_CIDR")]
    cidr: Option<AddressSpace>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage address allocation; restart the hub after saving changes.
    Dhcp {
        #[command(subcommand)]
        command: DhcpCommand,
    },
    /// Manage rooms without restarting the hub.
    Rooms {
        #[command(subcommand)]
        command: RoomCommand,
    },
}

#[derive(Debug, Clone, Copy, Subcommand)]
enum DhcpCommand {
    /// Print the validated DHCP policy as JSON.
    Show,
    /// Read and validate a complete JSON policy from standard input, then save atomically.
    Set,
}

#[derive(Debug, Args)]
struct RoomArguments {
    /// Unique private-room identifier.
    id: String,
    /// Room display name.
    name: String,
    /// Client-derived password proof, not the password itself.
    proof: String,
    /// Allow payload relay; omission preserves existing policy.
    #[arg(action = clap::ArgAction::Set)]
    relay: Option<bool>,
}

#[derive(Debug, Subcommand)]
enum RoomCommand {
    /// Print public and private room policies as JSON.
    List,
    /// Create a private room, refusing an existing identifier.
    Create(RoomArguments),
    /// Replace an existing room only with explicit confirmation.
    Replace {
        #[arg(long, required = true)]
        confirm: bool,
        #[command(flatten)]
        room: RoomArguments,
    },
    /// Enable or disable payload relay; discovery and signaling stay available.
    Relay {
        /// "public" or the private room's hashed key.
        room: String,
        /// Whether payload relay is allowed.
        #[arg(action = clap::ArgAction::Set)]
        relay: bool,
    },
    /// Remove a private room by its hashed key.
    Remove { room: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    let arguments = match Arguments::try_parse() {
        Ok(arguments) => arguments,
        Err(failure) => {
            let status = if failure.use_stderr() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
            return if failure.print().is_ok() {
                status
            } else {
                ExitCode::FAILURE
            };
        }
    };
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .with_max_level(Level::INFO)
        .init();
    let outcome = match &arguments.command {
        None => run(&arguments).await,
        Some(Command::Rooms { command }) => rooms_command(&arguments.data_dir, command).await,
        Some(Command::Dhcp { command }) => dhcp_command(&arguments, *command).await,
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            error!(error = %failure, "overlay hub stopped");
            ExitCode::FAILURE
        }
    }
}

/// Dispatch validated room commands through the existing authoritative store.
async fn rooms_command(data_dir: &Path, command: &RoomCommand) -> Result<()> {
    match command {
        RoomCommand::List => {
            let listing = serde_json::to_string(&overlay_relay::listing(data_dir).await?)?;
            writeln!(std::io::stdout(), "{listing}")?;
            Ok(())
        }
        RoomCommand::Create(room) => {
            overlay_relay::configure(
                data_dir,
                &room.id,
                &room.name,
                &room.proof,
                false,
                room.relay,
            )
            .await
        }
        RoomCommand::Replace { room, .. } => {
            overlay_relay::configure(
                data_dir,
                &room.id,
                &room.name,
                &room.proof,
                true,
                room.relay,
            )
            .await
        }
        RoomCommand::Relay { room, relay } => {
            overlay_relay::set_relay(data_dir, room, *relay).await
        }
        RoomCommand::Remove { room } => overlay_relay::remove(data_dir, room).await,
    }
}

async fn dhcp_command(arguments: &Arguments, command: DhcpCommand) -> Result<()> {
    let space = arguments.cidr.unwrap_or_default();
    match command {
        DhcpCommand::Show => {
            let policy = overlay_relay::dhcp::load(&arguments.data_dir, space).await?;
            writeln!(std::io::stdout(), "{}", serde_json::to_string(&policy)?)?;
            Ok(())
        }
        DhcpCommand::Set => {
            let mut raw = Vec::new();
            std::io::stdin()
                .take(overlay_relay::dhcp::MAX_DHCP_BYTES as u64 + 1)
                .read_to_end(&mut raw)?;
            overlay_relay::dhcp::save(&arguments.data_dir, space, &raw).await
        }
    }
}

async fn run(arguments: &Arguments) -> Result<()> {
    let hosts = allowed_hosts(&arguments.allowed_host);
    let host_count = hosts.len();
    let mut config = Config::new(arguments.data_dir.clone(), hosts);
    config.address_space = arguments.cidr.unwrap_or_default();
    let hub = Hub::new(config).await?;
    let listener = TcpListener::bind(&arguments.listen_address).await?;
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
