//! Control streams: registration, peer snapshots, incoming requests and keep-alive.
//!
//! A control stream is served by two halves that run together: a writer that
//! sends queued events and the freshest snapshot, and a reader that answers
//! pings. Either half ending cancels the other.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::select;
use tokio::sync::{Notify, mpsc};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::frame::{read_frame, send_frame};
use crate::hub::Shared;
use crate::protocol::{Event, Ping, Reply};
use crate::state::Requester;
use crate::verifier::Verifier;

/// Events that may wait for a control writer before the stream is dropped.
const EVENT_QUEUE: usize = 16;

/// The hub's side of one registered control stream.
#[derive(Debug, Clone)]
pub struct ControlHandle {
    /// Serial that distinguishes this registration from a later replacement.
    pub generation: u64,
    /// Queue of events for the writer. A full queue drops the control.
    pub outbound: mpsc::Sender<Event>,
    /// Signals the writer that the peer snapshot is stale.
    pub dirty: Arc<Notify>,
    /// Ends both halves of the control stream when cancelled.
    pub close: CancellationToken,
}

/// Serves one registered control stream until it ends.
pub async fn serve(
    shared: &Shared,
    stream: TcpStream,
    requester: Requester,
    session: CancellationToken,
) {
    let (reader, mut writer) = stream.into_split();
    let (outbound, events) = mpsc::channel(EVENT_QUEUE);
    let close = session.child_token();
    let dirty = Arc::new(Notify::new());
    let (generation, replaced) = {
        let mut state = shared.state.lock().await;
        let generation = state.next_serial();
        let handle = ControlHandle {
            generation,
            outbound: outbound.clone(),
            dirty: Arc::clone(&dirty),
            close: close.clone(),
        };
        (generation, state.register_control(requester.verifier, handle))
    };
    if let Some(old) = replaced {
        old.close.cancel();
    }
    let reply = Reply::registered(&requester.ip.to_string(), &requester.name);
    if send_frame(&mut writer, &reply).await.is_err() {
        close.cancel();
        shared
            .state
            .lock()
            .await
            .unregister_control(requester.verifier, generation);
        return;
    }
    debug!("overlay control registered");
    shared.state.lock().await.notify_all();
    let idle = shared.config.control_idle;
    tokio::join!(
        write_events(
            shared,
            requester.verifier,
            writer,
            events,
            dirty,
            close.clone()
        ),
        read_pings(reader, outbound, idle, close.clone()),
    );
    shared
        .state
        .lock()
        .await
        .unregister_control(requester.verifier, generation);
}

async fn write_events(
    shared: &Shared,
    verifier: Verifier,
    mut writer: OwnedWriteHalf,
    mut events: mpsc::Receiver<Event>,
    dirty: Arc<Notify>,
    close: CancellationToken,
) {
    loop {
        let event = select! {
            biased;
            () = close.cancelled() => break,
            queued = events.recv() => match queued {
                Some(event) => event,
                None => break,
            },
            () = dirty.notified() => {
                let peers = shared.state.lock().await.snapshot(verifier);
                Event::Peers(peers)
            }
        };
        if send_frame(&mut writer, &event).await.is_err() {
            close.cancel();
            break;
        }
    }
}

async fn read_pings(
    mut reader: OwnedReadHalf,
    outbound: mpsc::Sender<Event>,
    idle: Duration,
    close: CancellationToken,
) {
    loop {
        let frame = select! {
            biased;
            () = close.cancelled() => return,
            received = timeout(idle, read_frame::<_, Ping>(&mut reader)) => received,
        };
        if !matches!(frame, Ok(Ok(Ping { ping: true }))) {
            close.cancel();
            return;
        }
        if matches!(
            outbound.try_send(Event::Pong(true)),
            Err(mpsc::error::TrySendError::Full(_))
        ) {
            close.cancel();
            return;
        }
    }
}
