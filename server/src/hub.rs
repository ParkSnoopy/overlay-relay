//! The hub: startup, identity persistence, the accept loop, source admission
//! and dispatch of each connection to its stream kind.

use std::{
    fmt,
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P384_SHA384_ASN1, UnparsedPublicKey},
};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
    sync::{Mutex, watch},
    time::{interval, timeout},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    accept,
    assignments,
    config::Config,
    control,
    dns::admitted,
    error::Result,
    frame::{read_frame, send_frame},
    open,
    protocol::{
        Challenge,
        ERR_INVALID_REQUEST,
        ERR_ROOM_DENIED,
        ERR_ROOM_UNKNOWN,
        ERR_UNAUTHORIZED,
        Hello,
        KIND_ACCEPT,
        KIND_CONTROL,
        KIND_OPEN,
        KIND_SIGNAL,
        Proof,
        Reply,
        VERSION,
        valid_name,
    },
    rooms::{self, Admission},
    state::{Requester, State},
    verifier::Verifier,
};

/// Inputs the hub keeps for its lifetime.
#[derive(Debug)]
pub struct Shared {
    /// Immutable configuration.
    pub config: Config,
    /// Identities, controls, pending requests and flows.
    pub state: Mutex<State>,
    /// Serializes writes of the persisted identities.
    pub store: Mutex<()>,
    /// Notifies active relay streams after room policy files change.
    pub policy_changes: watch::Sender<()>,
}

async fn watch_policy(shared: &Shared, cancel: CancellationToken) {
    let mut tick = interval(Duration::from_millis(250));
    let mut previous = None;
    loop {
        select! {
            () = cancel.cancelled() => return,
            _ = tick.tick() => {
                let current = tokio::fs::metadata(shared.config.data_dir.join(rooms::ROOMS_FILE)).await.ok().and_then(|entry| entry.modified().ok().map(|modified| (modified, entry.len())));
                if current != previous {
                    shared.policy_changes.send_replace(());
                    previous = current;
                }
            }
        }
    }
}

/// Seconds since the Unix epoch.
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Writes the identities to disk when they changed. A failed write keeps them
/// marked changed, so the next call retries.
pub async fn persist(shared: &Shared) {
    let _writer = shared.store.lock().await;
    let Some(records) = shared.state.lock().await.take_dirty() else {
        return;
    };
    let path = shared.config.data_dir.join(assignments::FILE_NAME);
    if let Err(error) = assignments::save(&path, &records).await {
        warn!(error = %error, "overlay identities could not be saved");
        shared.state.lock().await.mark_dirty();
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
    /// Loads the persisted identities and their addresses.
    ///
    /// # Errors
    /// Returns an error when the identities file is corrupt or unreadable.
    pub async fn new(config: Config) -> Result<Self> {
        let records =
            assignments::load(&config.data_dir.join(assignments::FILE_NAME), unix_now()).await?;
        let dhcp = crate::dhcp::load(&config.data_dir, config.address_space).await?;
        let state = State::load_dhcp(&records, config.address_space, dhcp);
        info!(identities = records.len(), "overlay identities loaded");
        let hub = Self {
            shared: Arc::new(Shared {
                config,
                state: Mutex::new(state),
                store: Mutex::new(()),
                policy_changes: watch::channel(()).0,
            }),
        };
        persist(&hub.shared).await;
        Ok(hub)
    }

    /// Returns the overlay address assigned to `verifier`, if it is known.
    #[must_use]
    pub async fn address_of(&self, verifier: Verifier) -> Option<Ipv4Addr> {
        self.shared.state.lock().await.address_of(&verifier)
    }

    /// Serves admitted connections until `shutdown` fires or the listener fails.
    ///
    /// # Errors
    /// Returns `Error::Io` when accepting a connection fails.
    pub async fn serve(&self, listener: TcpListener, shutdown: CancellationToken) -> Result<()> {
        let session = shutdown.child_token();
        let _stop_on_return = session.clone().drop_guard();
        let shared = Arc::clone(&self.shared);
        let token = session.clone();
        tokio::spawn(async move { watch_policy(&shared, token).await });
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
        let domain = match hello.version {
            VERSION => crate::AUTH_DOMAIN,
            // Release 0.4.x used wire v3 before release-derived numbering.
            3 if VERSION == 5 => "overlay-relay/auth/v3:",
            _ => return,
        };
        let Ok(Some(requester)) =
            timeout(handshake, self.authenticate(&mut stream, &hello, domain)).await
        else {
            send_frame(&mut stream, &Reply::failed(ERR_UNAUTHORIZED))
                .await
                .ok();
            return;
        };
        let mut requester = requester;
        if !requester.room.is_empty() {
            match self.admit_room(&requester, &hello).await {
                Admission::Admitted(name) => {
                    requester.room_name = name;
                    requester.room = format!("{}:{}", rooms::key(&hello.room_id), requester.room);
                }
                Admission::Unavailable => {
                    send_frame(&mut stream, &Reply::failed("rooms are unavailable"))
                        .await
                        .ok();
                    return;
                }
                Admission::Unknown => {
                    send_frame(&mut stream, &Reply::failed(ERR_ROOM_UNKNOWN))
                        .await
                        .ok();
                    return;
                }
                Admission::Denied => {
                    send_frame(&mut stream, &Reply::failed(ERR_ROOM_DENIED))
                        .await
                        .ok();
                    return;
                }
            }
        }
        match hello.kind.as_str() {
            KIND_CONTROL => {
                control::serve(&self.shared, stream, requester, &hello, session).await;
            }
            KIND_OPEN => {
                open::serve(&self.shared, stream, requester, &hello, session).await;
            }
            KIND_SIGNAL if hello.version == VERSION => {
                open::serve(&self.shared, stream, requester, &hello, session).await;
            }
            KIND_ACCEPT => {
                accept::serve(&self.shared, stream, requester.verifier, &hello).await;
            }
            _ => {
                send_frame(&mut stream, &Reply::failed(ERR_INVALID_REQUEST))
                    .await
                    .ok();
            }
        }
    }

    /// Admits a private room only when the operator created it and the device
    /// proves its password. The hub never creates a room.
    async fn admit_room(&self, requester: &Requester, hello: &Hello) -> Admission {
        match rooms::admit(
            &self.shared.config.data_dir,
            &hello.room_id,
            &requester.room,
        )
        .await
        {
            Ok(admission) => admission,
            Err(error) => {
                warn!(error = %error, "overlay rooms could not be checked");
                Admission::Unavailable
            }
        }
    }

    /// Challenges the peer to sign a fresh nonce with the key it presented.
    /// The same key with a valid signature is always the same identity.
    async fn authenticate(
        &self,
        stream: &mut TcpStream,
        hello: &Hello,
        domain: &str,
    ) -> Option<Requester> {
        let room = &hello.room;
        let room_id = &hello.room_id;
        // A private room needs both its password proof and a room ID.
        if room.is_empty() != room_id.is_empty() {
            return None;
        }
        if !room.is_empty() && (!rooms::valid_room(room) || !valid_name(room_id)) {
            return None;
        }
        let verifier = Verifier::from_public_key(&hello.public_key)?;
        let public = hex::decode(&hello.public_key).ok()?;
        let mut nonce = [0_u8; 32];
        SystemRandom::new().fill(&mut nonce).ok()?;
        send_frame(
            stream,
            &Challenge {
                nonce: hex::encode(nonce),
            },
        )
        .await
        .ok()?;
        let proof: Proof = read_frame(stream).await.ok()?;
        let signature = hex::decode(proof.signature).ok()?;
        let mut message = domain.as_bytes().to_vec();
        message.extend_from_slice(&nonce);
        message.extend_from_slice(room.as_bytes());
        if !room.is_empty() {
            message.push(0);
            message.extend_from_slice(room_id.as_bytes());
        }
        UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public)
            .verify(&message, &signature)
            .ok()?;
        let mut requester = self
            .shared
            .state
            .lock()
            .await
            .identify(verifier, unix_now())?;
        persist(&self.shared).await;
        requester.room = room.to_owned();
        Some(requester)
    }
}
