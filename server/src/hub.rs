//! The hub: startup, identity persistence, the accept loop, source admission
//! and dispatch of each connection to its stream kind.

use std::{
    collections::BTreeMap,
    fmt,
    net::Ipv4Addr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P384_SHA384_ASN1, UnparsedPublicKey},
};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
    sync::Mutex,
    time::timeout,
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
        ERR_ROOM_PENDING,
        ERR_UNAUTHORIZED,
        Hello,
        KIND_ACCEPT,
        KIND_CONTROL,
        KIND_OPEN,
        Proof,
        Reply,
        VERSION,
        valid_name,
    },
    rooms::{self, MAX_PENDING, Request},
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
    /// Private rooms that asked for approval and have not received it.
    pub pending_rooms: Mutex<BTreeMap<String, Request>>,
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
        let state = State::load_in(&records, config.address_space);
        info!(identities = records.len(), "overlay identities loaded");
        let pending_rooms = rooms::load_pending(&config.data_dir)
            .await
            .unwrap_or_else(|error| {
                warn!(error = %error, "overlay room requests could not be loaded");
                BTreeMap::new()
            });
        let hub = Self {
            shared: Arc::new(Shared {
                config,
                state: Mutex::new(state),
                store: Mutex::new(()),
                pending_rooms: Mutex::new(pending_rooms),
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
        let Ok(Some(requester)) = timeout(
            handshake,
            self.authenticate(&mut stream, &hello.public_key, &hello.room),
        )
        .await
        else {
            send_frame(&mut stream, &Reply::failed(ERR_UNAUTHORIZED))
                .await
                .ok();
            return;
        };
        if !self.room_approved(&requester, &hello.name).await {
            send_frame(&mut stream, &Reply::failed(ERR_ROOM_PENDING))
                .await
                .ok();
            return;
        }
        match hello.kind.as_str() {
            KIND_CONTROL => {
                control::serve(&self.shared, stream, requester, &hello.name, session).await;
            }
            KIND_OPEN => open::serve(&self.shared, stream, requester, &hello, session).await,
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

    /// Admits a private room only after the operator approved its capability.
    /// An unapproved room is recorded once, with its first requester, so the
    /// operator can approve it; the public room needs no approval.
    async fn room_approved(&self, requester: &Requester, name: &str) -> bool {
        if requester.room.is_empty() {
            return true;
        }
        let directory = &self.shared.config.data_dir;
        let mut pending = self.shared.pending_rooms.lock().await;
        match rooms::load_approved(directory).await {
            Ok(approved) if approved.contains(&requester.room) => {
                if pending.remove(&requester.room).is_some() {
                    rooms::save_pending(directory, &pending).await.ok();
                }
                return true;
            }
            Ok(_) => {}
            Err(error) => {
                warn!(error = %error, "overlay approved rooms could not be read");
                return false;
            }
        }
        if pending.contains_key(&requester.room) || pending.len() >= MAX_PENDING {
            return false;
        }
        let name = if name.is_empty() || !valid_name(name) {
            &requester.name
        } else {
            name
        };
        pending.insert(
            requester.room.clone(),
            Request {
                peer: requester.verifier.to_hex(),
                name: name.to_owned(),
                requested: unix_now(),
            },
        );
        if let Err(error) = rooms::save_pending(directory, &pending).await {
            warn!(error = %error, "overlay room request could not be saved");
        }
        drop(pending);
        false
    }

    /// Challenges the peer to sign a fresh nonce with the key it presented.
    /// The same key with a valid signature is always the same identity.
    async fn authenticate(
        &self,
        stream: &mut TcpStream,
        public_key: &str,
        room: &str,
    ) -> Option<Requester> {
        if !room.is_empty()
            && (room.len() != 64
                || !room
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return None;
        }
        let verifier = Verifier::from_public_key(public_key)?;
        let public = hex::decode(public_key).ok()?;
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
        let mut message = b"overlay-relay/auth/v3:".to_vec();
        message.extend_from_slice(&nonce);
        message.extend_from_slice(room.as_bytes());
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
