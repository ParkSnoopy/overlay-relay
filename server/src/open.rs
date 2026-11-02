//! Open requests: relay a flow from one broadcasting account to another.
//!
//! Every refusal (bad request, missing or hidden destination, self, limits,
//! timeout) gets the same `peer unavailable` reply, so a requester cannot
//! tell those cases apart.

use std::net::Ipv4Addr;

use tokio::{
    net::TcpStream,
    select,
    sync::{mpsc::error::TrySendError, oneshot},
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{
    frame::send_frame,
    hub::Shared,
    protocol::{ERR_UNAVAILABLE, Event, Hello, Incoming, Offer, PROTO_TCP, PROTO_UDP, Reply},
    splice::splice,
    state::{Accepted, Requester},
};

/// A validated open request.
struct OpenRequest {
    destination: Ipv4Addr,
    port: u16,
    udp: bool,
    offer: Offer,
}

/// How the wait for an accept ended.
enum Answer {
    Accepted(Accepted),
    Expired,
    Shutdown,
}

/// Outcome of one wait step, before any state is touched.
enum Wait {
    Shutdown,
    Received(Option<Accepted>),
    TimedOut,
}

/// Serves one open request, from admission through the relayed flow.
pub async fn serve(
    shared: &Shared,
    mut stream: TcpStream,
    requester: Requester,
    hello: &Hello,
    session: CancellationToken,
) {
    let Some(request) = parse_open(hello) else {
        refuse(&mut stream).await;
        return;
    };
    let id = request_id();
    let (accept_tx, accept_rx) = oneshot::channel();
    let admitted =
        shared
            .state
            .lock()
            .await
            .admit_request(&requester, request.destination, &id, accept_tx);
    let Some((destination, target)) = admitted else {
        refuse(&mut stream).await;
        return;
    };
    let incoming = Incoming {
        id: id.clone(),
        proto: hello.proto.clone(),
        src: requester.ip.to_string(),
        port: request.port,
        fingerprint: request.offer.fingerprint.clone(),
        endpoint: request.offer.endpoint.clone(),
    };
    if let Err(error) = target.outbound.try_send(Event::Incoming(incoming)) {
        if matches!(error, TrySendError::Full(_)) {
            target.close.cancel();
        }
        shared.state.lock().await.remove_pending(&id);
        refuse(&mut stream).await;
        return;
    }
    let Accepted {
        stream: mut acceptor,
        offer: accepted,
    } = match await_answer(shared, &id, accept_rx, &session).await {
        Answer::Accepted(accepted) => accepted,
        Answer::Expired => {
            refuse(&mut stream).await;
            return;
        }
        Answer::Shutdown => return,
    };
    if request.offer.direct() && accepted.direct() {
        // Both sides continue on a direct connection; the hub relays nothing.
        send_frame(&mut stream, &Reply::paired(&id, &request.offer, &accepted))
            .await
            .ok();
        send_frame(
            &mut acceptor,
            &Reply::paired(&id, &accepted, &request.offer),
        )
        .await
        .ok();
        debug!("overlay flow handed to a direct connection");
        return;
    }
    let cancel = session.child_token();
    let flow = shared
        .state
        .lock()
        .await
        .open_flow([requester.verifier, destination], cancel.clone());
    let Some(flow_id) = flow else {
        refuse(&mut stream).await;
        refuse(&mut acceptor).await;
        return;
    };
    let opened = send_frame(&mut stream, &Reply::paired(&id, &request.offer, &accepted))
        .await
        .is_ok()
        && send_frame(
            &mut acceptor,
            &Reply::paired(&id, &accepted, &request.offer),
        )
        .await
        .is_ok();
    if opened {
        let proto = if request.udp { PROTO_UDP } else { PROTO_TCP };
        debug!(proto, "overlay flow opened");
        splice(
            stream,
            acceptor,
            request.udp,
            shared.config.udp_idle,
            cancel,
        )
        .await;
        debug!(proto, "overlay flow closed");
    }
    shared.state.lock().await.remove_flow(flow_id);
}

/// Validates the fields of an open request. Any failure is a refusal.
fn parse_open(hello: &Hello) -> Option<OpenRequest> {
    let port = hello.port.filter(|port| *port != 0)?;
    let udp = match hello.proto.as_str() {
        PROTO_TCP => false,
        PROTO_UDP => true,
        _ => return None,
    };
    let destination = hello.dst.parse().ok()?;
    let offer = Offer::parse(&hello.fingerprint, &hello.endpoint)?;
    Some(OpenRequest {
        destination,
        port,
        udp,
        offer,
    })
}

/// Waits for the destination to accept the request `id`, bounded by the accept timeout.
async fn await_answer(
    shared: &Shared,
    id: &str,
    mut accepted: oneshot::Receiver<Accepted>,
    session: &CancellationToken,
) -> Answer {
    let timer = sleep(shared.config.accept_timeout);
    tokio::pin!(timer);
    let outcome = select! {
        biased;
        () = session.cancelled() => Wait::Shutdown,
        received = &mut accepted => Wait::Received(received.ok()),
        () = &mut timer => Wait::TimedOut,
    };
    match outcome {
        Wait::Shutdown => {
            shared.state.lock().await.remove_pending(id);
            Answer::Shutdown
        }
        Wait::Received(stream) => stream.map_or(Answer::Expired, Answer::Accepted),
        Wait::TimedOut => {
            let still_waiting = shared.state.lock().await.remove_pending(id).is_some();
            if still_waiting {
                return Answer::Expired;
            }
            // The acceptor claimed the request just before the deadline and is
            // handing over its stream, so the answer is already on its way.
            accepted
                .await
                .ok()
                .map_or(Answer::Expired, Answer::Accepted)
        }
    }
}

fn request_id() -> String {
    let bytes: [u8; 16] = rand::random();
    hex::encode(bytes)
}

async fn refuse(stream: &mut TcpStream) {
    send_frame(stream, &Reply::failed(ERR_UNAVAILABLE))
        .await
        .ok();
}
