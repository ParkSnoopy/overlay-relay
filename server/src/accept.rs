//! Accept requests: the destination answers a pending `Incoming` request by
//! handing over a new stream and its offer. The waiting open request writes
//! the success replies and owns the relay (or the direct hand-off) from then on.

use tokio::net::TcpStream;

use crate::{
    frame::send_frame,
    hub::Shared,
    protocol::{ERR_INVALID_REQUEST, ERR_UNAUTHORIZED, Hello, Offer, Reply},
    state::Accepted,
    verifier::Verifier,
};

/// Claims the pending request named by `hello.id` for `acceptor` and hands
/// over `stream`. Requests that are unknown, expired, already used, or
/// addressed to another account all get the same `unauthorized` reply.
pub async fn serve(shared: &Shared, mut stream: TcpStream, acceptor: Verifier, hello: &Hello) {
    let Some(offer) = Offer::parse(&hello.fingerprint, &hello.endpoint) else {
        send_frame(&mut stream, &Reply::failed(ERR_INVALID_REQUEST))
            .await
            .ok();
        return;
    };
    let claimed = shared
        .state
        .lock()
        .await
        .claim_pending(&hello.id, &acceptor);
    let Some(pending) = claimed else {
        send_frame(&mut stream, &Reply::failed(ERR_UNAUTHORIZED))
            .await
            .ok();
        return;
    };
    // If the open request already gave up, the stream is dropped here.
    pending.accept.send(Accepted { stream, offer }).ok();
}
