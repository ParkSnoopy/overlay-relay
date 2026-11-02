//! The hub: startup, peers-table reloads, the accept loop, source admission and
//! dispatch of each connection to its stream kind.

use std::collections::HashMap;
use std::fmt;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::Mutex;
use tokio::time::{interval, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::accept;
use crate::address::{LAST_ADDRESS, assign};
use crate::assignments;
use crate::config::Config;
use crate::control;
use crate::dns::admitted;
use crate::error::{Error, Result};
use crate::frame::{read_frame, send_frame};
use crate::open;
use crate::peers::{Account, MAX_PEERS_FILE, Peers};
use crate::protocol::{
    ERR_INVALID_REQUEST, ERR_UNAUTHORIZED, Hello, KIND_ACCEPT, KIND_CONTROL, KIND_OPEN, Reply,
    VERSION,
};
use crate::state::{Requester, State};
use crate::verifier::Verifier;

/// Inputs the hub keeps for its lifetime.
#[derive(Debug)]
pub struct Shared {
    /// Immutable configuration.
    pub config: Config,
    /// Accounts, controls, pending requests and flows.
    pub state: Mutex<State>,
    /// Serializes table reloads and owns the persisted address assignments.
    pub gate: Mutex<Gate>,
}

/// Reload bookkeeping, guarded by [`Shared::gate`].
#[derive(Debug, Default)]
pub struct Gate {
    fingerprint: Option<Fingerprint>,
    assignments: HashMap<Verifier, Ipv4Addr>,
}

/// File identity of the peers table. A change in any field triggers a re-read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    device: u64,
    inode: u64,
    modified_secs: i64,
    modified_nanos: i64,
    length: u64,
}

impl Fingerprint {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            modified_secs: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            length: metadata.len(),
        }
    }
}

/// The overlay relay hub. Clones share one state.
#[derive(Clone)]
pub struct Hub {
    shared: Arc<Shared>,
}

impl fmt::Debug for Hub {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Hub").finish_non_exhaustive()
    }
}

impl Hub {
    /// Loads the persisted address assignments and the current peers table.
    /// A missing or invalid peers table yields an empty table (fail closed)
    /// and leaves the persisted assignments untouched.
    ///
    /// # Errors
    /// Returns `Error::Config` for a zero poll interval and an error when the
    /// assignments file is corrupt or unreadable.
    pub async fn new(config: Config) -> Result<Self> {
        if config.poll_interval.is_zero() {
            return Err(Error::Config("overlay poll interval must be positive"));
        }
        let loaded = assignments::load(&config.data_dir.join(assignments::FILE_NAME)).await?;
        let shared = Shared {
            config,
            state: Mutex::new(State::default()),
            gate: Mutex::new(Gate {
                fingerprint: None,
                assignments: loaded,
            }),
        };
        let hub = Self {
            shared: Arc::new(shared),
        };
        if let Err(error) = hub.reload().await {
            warn!(error = %error, "overlay peers table is unavailable");
        }
        Ok(hub)
    }

    /// Re-reads the peers table when its file identity, timestamp or size has
    /// changed. A missing file empties the table. Invalid content keeps the
    /// last good table.
    ///
    /// # Errors
    /// Returns an error when the file cannot be inspected, is too large or
    /// invalid, or when the new address assignments cannot be persisted.
    pub async fn reload(&self) -> Result<()> {
        let mut gate = self.shared.gate.lock().await;
        self.reload_locked(&mut gate).await
    }

    async fn reload_locked(&self, gate: &mut Gate) -> Result<()> {
        let path = &self.shared.config.peers_path;
        let metadata = match tokio::fs::metadata(path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return self.clear_table(gate).await;
            }
            Err(error) => return Err(error.into()),
        };
        let fingerprint = Fingerprint::of(&metadata);
        if gate.fingerprint == Some(fingerprint) {
            return Ok(());
        }
        gate.fingerprint = Some(fingerprint);
        if metadata.len() > MAX_PEERS_FILE {
            return Err(Error::Peers("overlay peers table is too large"));
        }
        let raw = tokio::fs::read(path).await?;
        let peers = Peers::parse(&raw)?;
        self.apply(gate, &peers).await
    }

    /// Returns the overlay address assigned to `verifier`, if it is in the table.
    #[must_use]
    pub async fn address_of(&self, verifier: Verifier) -> Option<Ipv4Addr> {
        self.shared.state.lock().await.address_of(&verifier)
    }

    /// Serves admitted connections until `shutdown` fires or the listener fails.
    /// Also polls the peers table in the background.
    ///
    /// # Errors
    /// Returns `Error::Io` when accepting a connection fails.
    pub async fn serve(&self, listener: TcpListener, shutdown: CancellationToken) -> Result<()> {
        let session = shutdown.child_token();
        let _stop_on_return = session.clone().drop_guard();
        tokio::spawn(poll(self.clone(), session.clone()));
        loop {
            let accepted = select! {
                biased;
                () = session.cancelled() => return Ok(()),
                accepted = listener.accept() => accepted,
            };
            let (stream, _) = accepted?;
            let hub = self.clone();
            let token = session.clone();
            tokio::spawn(async move { hub.admit_and_serve(stream, token).await });
        }
    }

    async fn admit_and_serve(self, stream: TcpStream, session: CancellationToken) {
        let Ok(remote) = stream.peer_addr() else {
            return;
        };
        let config = &self.shared.config;
        if !admitted(config.resolver.as_ref(), &config.allowed_hosts, remote.ip()).await {
            return;
        }
        self.serve_connection(stream, session).await;
    }

    async fn serve_connection(&self, mut stream: TcpStream, session: CancellationToken) {
        let handshake = self.shared.config.handshake_timeout;
        let hello: Hello = match timeout(handshake, read_frame(&mut stream)).await {
            Ok(Ok(hello)) => hello,
            _ => return,
        };
        if hello.version != VERSION {
            return;
        }
        let Some(requester) = self.authenticate(&hello.token).await else {
            send_frame(&mut stream, &Reply::failed(ERR_UNAUTHORIZED))
                .await
                .ok();
            return;
        };
        match hello.kind.as_str() {
            KIND_CONTROL => control::serve(&self.shared, stream, requester, session).await,
            KIND_OPEN => open::serve(&self.shared, stream, requester, &hello, session).await,
            KIND_ACCEPT => {
                accept::serve(&self.shared, stream, requester.verifier, &hello.id).await;
            }
            _ => {
                send_frame(&mut stream, &Reply::failed(ERR_INVALID_REQUEST))
                    .await
                    .ok();
            }
        }
    }

    async fn authenticate(&self, token: &str) -> Option<Requester> {
        let verifier = Verifier::from_token(token)?;
        self.shared.state.lock().await.authenticate(&verifier)
    }

    async fn clear_table(&self, gate: &mut Gate) -> Result<()> {
        let was_loaded = gate.fingerprint.take().is_some();
        let change = self.shared.state.lock().await.replace_table(Vec::new());
        if was_loaded {
            info!(
                accounts = change.accounts,
                closed_controls = change.closed_controls,
                closed_flows = change.closed_flows,
                "overlay peers table is missing; admitting no accounts"
            );
        }
        Ok(())
    }

    async fn apply(&self, gate: &mut Gate, peers: &Peers) -> Result<()> {
        let verifiers: Vec<Verifier> = peers.accounts().iter().map(Account::verifier).collect();
        let assigned = assign(&verifiers, &gate.assignments, LAST_ADDRESS)?;
        let path = self.shared.config.data_dir.join(assignments::FILE_NAME);
        assignments::save(&path, &assigned).await?;
        let mut entries = Vec::with_capacity(verifiers.len());
        for account in peers.accounts() {
            if let Some(ip) = assigned.get(&account.verifier()) {
                entries.push((account.verifier(), account.name().to_owned(), *ip));
            }
        }
        gate.assignments = assigned;
        let change = self.shared.state.lock().await.replace_table(entries);
        info!(
            accounts = change.accounts,
            closed_controls = change.closed_controls,
            closed_flows = change.closed_flows,
            "overlay peers table applied"
        );
        Ok(())
    }
}

async fn poll(hub: Hub, session: CancellationToken) {
    let mut ticker = interval(hub.shared.config.poll_interval);
    loop {
        select! {
            biased;
            () = session.cancelled() => return,
            _ = ticker.tick() => {}
        }
        if let Err(error) = hub.reload().await {
            debug!(error = %error, "overlay peers reload kept the last good table");
        }
    }
}
