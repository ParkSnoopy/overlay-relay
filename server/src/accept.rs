//! Accept requests: the destination answers a pending `Incoming` request by
//! handing over a new stream. The waiting open request writes the success reply
//! and owns the relay from then on.

use tokio::net::TcpStream;

use crate::frame::send_frame;
use crate::hub::Shared;
use crate::protocol::{ERR_UNAUTHORIZED, Reply};
use crate::verifier::Verifier;

/// Claims the pending request `id` for `acceptor` and hands over `stream`.
/// Requests that are unknown, expired, already used, or addressed to another
/// account all get the same `unauthorized` reply.
pub async fn serve(shared: &Shared, mut stream: TcpStream, acceptor: Verifier, id: &str) {
    let claimed = shared.state.lock().await.claim_pending(id, &acceptor);
    let Some(pending) = claimed else {
        send_frame(&mut stream, &Reply::failed(ERR_UNAUTHORIZED))
            .await
            .ok();
        return;
    };
    // If the open request already gave up, the stream is dropped here.
    pending.accept.send(stream).ok();
}
