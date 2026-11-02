//! Bidirectional relay between two accepted streams.
//!
//! Each direction copies until its source ends. A clean end half-closes the
//! destination's write side; an error or a cancelled flow closes both sides.
//! UDP flows carry datagram records as raw bytes, so copying preserves framing.
//! A UDP flow with no traffic for the idle period is cancelled.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::select;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

/// Bytes moved per read.
const CHUNK: usize = 16 << 10;

/// Relays bytes between `first` and `second` until both directions end or
/// `cancel` fires. `udp` enables the idle watchdog with `idle` as its limit.
pub async fn splice(
    first: TcpStream,
    second: TcpStream,
    udp: bool,
    idle: Duration,
    cancel: CancellationToken,
) {
    let (first_read, first_write) = first.into_split();
    let (second_read, second_write) = second.into_split();
    let activity = Activity::new();
    let done = CancellationToken::new();
    let forward = relay(first_read, second_write, &activity, &cancel);
    let backward = relay(second_read, first_write, &activity, &cancel);
    let finish = async {
        tokio::join!(forward, backward);
        done.cancel();
    };
    let watch = async {
        if udp {
            watch_idle(&activity, idle, &cancel, &done).await;
        }
    };
    tokio::join!(finish, watch);
}

async fn relay(
    mut source: OwnedReadHalf,
    mut destination: OwnedWriteHalf,
    activity: &Activity,
    cancel: &CancellationToken,
) {
    let mut buffer = vec![0_u8; CHUNK];
    loop {
        let read = select! {
            biased;
            () = cancel.cancelled() => return,
            result = source.read(&mut buffer) => result,
        };
        let count = match read {
            Ok(0) => {
                destination.shutdown().await.ok();
                return;
            }
            Ok(count) => count,
            Err(_) => {
                cancel.cancel();
                return;
            }
        };
        let written = select! {
            biased;
            () = cancel.cancelled() => return,
            result = destination.write_all(&buffer[..count]) => result,
        };
        if written.is_err() {
            cancel.cancel();
            return;
        }
        activity.touch();
    }
}

async fn watch_idle(
    activity: &Activity,
    idle: Duration,
    cancel: &CancellationToken,
    done: &CancellationToken,
) {
    let tick = (idle / 4).max(Duration::from_millis(1));
    loop {
        select! {
            biased;
            () = cancel.cancelled() => return,
            () = done.cancelled() => return,
            () = sleep(tick) => {}
        }
        if activity.idle_for() >= idle {
            cancel.cancel();
            return;
        }
    }
}

/// Time of the most recent forwarded chunk, in milliseconds since creation.
struct Activity {
    base: Instant,
    last_millis: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            last_millis: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let millis = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_millis.store(millis, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_millis.load(Ordering::Relaxed));
        self.base.elapsed().saturating_sub(last)
    }
}
