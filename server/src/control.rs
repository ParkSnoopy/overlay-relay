//! Control streams: registration, peer snapshots, incoming flows, DNS and keep-alive.
//!
//! A control stream is served by two halves that run together: a writer that
//! sends queued events and the freshest snapshot, and a reader that answers
//! pings and name queries. Either half ending cancels the other.

use std::sync::Arc;

use tokio::{
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    select,
    sync::{Notify, mpsc},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    frame::{read_frame, send_frame},
    hub::{Shared, persist, unix_now},
    names,
    protocol::{
        ControlRequest,
        ERR_INVALID_REQUEST,
        Event,
        Hello,
        NameAnswer,
        NameQuery,
        Reply,
        valid_name,
    },
    rooms::{self, Admission},
    state::{Requester, advertised_name},
    verifier::Verifier,
};

/// Events that may wait for a control writer before the stream is dropped.
const EVENT_QUEUE: usize = 16;

/// The hub's side of one registered control stream.
#[derive(Debug, Clone)]
pub struct ControlHandle {
    /// Opaque room membership, never exposed in snapshots or diagnostics.
    pub room: String,
    pub version: u32,
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
    mut stream: TcpStream,
    mut requester: Requester,
    hello: &Hello,
    session: CancellationToken,
) {
    if !valid_name(&hello.name) {
        send_frame(&mut stream, &Reply::failed(ERR_INVALID_REQUEST))
            .await
            .ok();
        return;
    }
    let advertised = advertised_name(&hello.name, &requester.verifier);
    shared
        .names
        .lock()
        .await
        .reserve(
            names::room_key(&requester.room),
            &advertised,
            requester.verifier,
        )
        .await;
    let (reader, mut writer) = stream.into_split();
    let (outbound, events) = mpsc::channel(EVENT_QUEUE);
    let close = session.child_token();
    let dirty = Arc::new(Notify::new());
    let (generation, replaced) = {
        let mut state = shared.state.lock().await;
        let Some(name) = state.set_name(&requester.verifier, &hello.name) else {
            return;
        };
        let Some(ip) = state.address_of(&requester.verifier) else {
            return;
        };
        requester.name = name;
        requester.ip = ip;
        let generation = state.next_serial();
        let handle = ControlHandle {
            room: requester.room.clone(),
            version: hello.version,
            generation,
            outbound: outbound.clone(),
            dirty: Arc::clone(&dirty),
            close: close.clone(),
        };
        (
            generation,
            state.register_control(requester.verifier, handle),
        )
    };
    if let Some(old) = replaced {
        old.close.cancel();
    }
    let mut reply = Reply::registered(&requester.ip.to_string(), &requester.name);
    reply.cidr = shared.config.address_space.to_string();
    reply.room_name.clone_from(&requester.room_name);
    reply.name_lookup = Some(1);
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
    persist(shared).await;
    shared.state.lock().await.notify_all();
    tokio::join!(
        write_events(
            shared,
            requester.verifier,
            writer,
            events,
            dirty,
            close.clone()
        ),
        read_requests(
            shared,
            &requester,
            generation,
            reader,
            outbound,
            close.clone()
        ),
    );
    {
        let mut state = shared.state.lock().await;
        state.unregister_control(requester.verifier, generation);
        state.touch(&requester.verifier, unix_now());
    }
    persist(shared).await;
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

async fn read_requests(
    shared: &Shared,
    requester: &Requester,
    generation: u64,
    mut reader: OwnedReadHalf,
    outbound: mpsc::Sender<Event>,
    close: CancellationToken,
) {
    loop {
        let frame = select! {
            biased;
            () = close.cancelled() => return,
            received = timeout(shared.config.control_idle, read_frame::<_, ControlRequest>(&mut reader)) => received,
        };
        let event = match frame {
            Ok(Ok(ControlRequest {
                ping: true,
                resolve: None,
            })) => Event::Pong(true),
            Ok(Ok(ControlRequest {
                ping: false,
                resolve: Some(query),
            })) if query.id != 0 => {
                Event::Resolved(resolve_name(shared, requester, generation, query).await)
            }
            _ => break,
        };
        if outbound.try_send(event).is_err() {
            break;
        }
    }
    close.cancel();
}

async fn resolve_name(
    shared: &Shared,
    requester: &Requester,
    generation: u64,
    query: NameQuery,
) -> NameAnswer {
    let mut answer = NameAnswer {
        id: query.id,
        ip: None,
        unavailable: false,
    };
    if let Some((room, proof)) = requester.room.split_once(':') {
        match rooms::admit_key(&shared.config.data_dir, room, proof).await {
            Ok(Admission::Admitted(_)) => (),
            Ok(_) => return answer,
            Err(_) => {
                answer.unavailable = true;
                return answer;
            }
        }
    }
    let owner = shared
        .names
        .lock()
        .await
        .owner(names::room_key(&requester.room), &query.label);
    match owner {
        Ok(Some(owner)) => {
            answer.ip = shared
                .state
                .lock()
                .await
                .lookup_name(requester, generation, &owner);
        }
        Ok(None) => (),
        Err(_) => answer.unavailable = true,
    }
    answer
}
