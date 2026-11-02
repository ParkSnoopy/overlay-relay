//! End-to-end tests for the hub over real local sockets. They use only the
//! public API and mirror the behaviour of the Go overlay hub tests.

use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

use overlay_relay::{
    Config,
    ERR_INVALID_REQUEST,
    ERR_UNAUTHORIZED,
    ERR_UNAVAILABLE,
    Event,
    Hello,
    Hub,
    Incoming,
    KIND_ACCEPT,
    KIND_CONTROL,
    KIND_OPEN,
    MAX_DATAGRAM,
    MAX_PENDING_PER_ACCOUNT,
    PROTO_TCP,
    PROTO_UDP,
    Ping,
    Proof,
    Reply,
    Resolver,
    VERSION,
    Verifier,
    read_datagram,
    read_frame,
    write_datagram,
    write_frame,
};
use p384::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Returns `Err` with the formatted message when `condition` is false.
macro_rules! ensure {
    ($condition:expr, $($message:tt)+) => {
        if !($condition) {
            return Err(format!($($message)+).into());
        }
    };
    ($condition:expr $(,)?) => {
        ensure!($condition, "condition failed")
    };
}

/// Returns `Err` with both values when they differ.
macro_rules! ensure_eq {
    ($left:expr, $right:expr, $($message:tt)+) => {
        match (&$left, &$right) {
            (left, right) => {
                if left != right {
                    return Err(format!(
                        "{}: {:?} != {:?}",
                        format_args!($($message)+),
                        left,
                        right
                    )
                    .into());
                }
            }
        }
    };
    ($left:expr, $right:expr $(,)?) => {
        ensure_eq!($left, $right, "values differ")
    };
}

const IO_WAIT: Duration = Duration::from_secs(5);
const ALLOWED: &str = "engine";

#[derive(Debug)]
struct TestResolver {
    addresses: Arc<Mutex<Vec<IpAddr>>>,
}

impl Resolver for TestResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>> {
        Box::pin(async move {
            if host != ALLOWED {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no such host"));
            }
            Ok(self.addresses.lock().await.clone())
        })
    }
}

/// A running hub on a loopback port, with its peers table and admission setup.
struct Fixture {
    hub: Hub,
    address: SocketAddr,
    peers: PathBuf,
    _dir: TempDir,
    addresses: Arc<Mutex<Vec<IpAddr>>>,
    shutdown: CancellationToken,
    held: Vec<TcpStream>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl Fixture {
    async fn ip(&self, name: &str) -> TestResult<Ipv4Addr> {
        self.hub
            .address_of(verifier_of(name))
            .await
            .ok_or_else(|| format!("{name} has no address").into())
    }
}

async fn fixture(names: &[&str], tune: impl FnOnce(&mut Config)) -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let peers = dir.path().join("peers.json");
    write_peers(&peers, names).await?;
    let addresses = Arc::new(Mutex::new(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]));
    let resolver: Arc<dyn Resolver> = Arc::new(TestResolver {
        addresses: Arc::clone(&addresses),
    });
    let mut config = Config::new(
        peers.clone(),
        dir.path().to_path_buf(),
        vec![ALLOWED.to_owned()],
    );
    config.resolver = resolver;
    config.poll_interval = Duration::from_millis(20);
    config.accept_timeout = Duration::from_secs(2);
    tune(&mut config);
    let hub = Hub::new(config).await?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let shutdown = CancellationToken::new();
    let serving = hub.clone();
    let token = shutdown.clone();
    tokio::spawn(async move { serving.serve(listener, token).await });
    Ok(Fixture {
        hub,
        address,
        peers,
        _dir: dir,
        addresses,
        shutdown,
        held: Vec::new(),
    })
}

fn key_of(name: &str) -> Option<SigningKey> {
    let mut bytes = [0_u8; 48];
    bytes[16..].copy_from_slice(&Sha256::digest(format!("test-key-{name}")));
    SigningKey::from_slice(&bytes).ok()
}

fn public_of(name: &str) -> String {
    key_of(name).map_or_else(String::new, |key| {
        hex::encode(key.verifying_key().to_encoded_point(false).as_bytes())
    })
}

fn verifier_of(name: &str) -> Verifier {
    Verifier::from_public_key(&public_of(name)).unwrap_or(Verifier::from_digest([0; 32]))
}

async fn write_peers(path: &Path, names: &[&str]) -> TestResult {
    let accounts: Vec<serde_json::Value> = names
        .iter()
        .map(|name| serde_json::json!({"public_key": public_of(name), "name": name}))
        .collect();
    let raw = serde_json::to_vec(&serde_json::json!({"version": VERSION, "accounts": accounts}))?;
    let temporary = path.with_extension("tmp");
    tokio::fs::write(&temporary, raw).await?;
    tokio::fs::rename(&temporary, path).await?;
    Ok(())
}

fn control_hello(name: &str) -> Hello {
    Hello {
        version: VERSION,
        kind: KIND_CONTROL.to_owned(),
        public_key: public_of(name),
        ..Hello::default()
    }
}

fn open_hello(name: &str, dst: &str, proto: &str, port: Option<u16>) -> Hello {
    Hello {
        version: VERSION,
        kind: KIND_OPEN.to_owned(),
        public_key: public_of(name),
        proto: proto.to_owned(),
        dst: dst.to_owned(),
        port,
        ..Hello::default()
    }
}

fn accept_hello(name: &str, id: &str) -> Hello {
    Hello {
        version: VERSION,
        kind: KIND_ACCEPT.to_owned(),
        public_key: public_of(name),
        id: id.to_owned(),
        ..Hello::default()
    }
}

async fn dial(address: SocketAddr, hello: &Hello) -> TestResult<(TcpStream, Reply)> {
    let mut stream = TcpStream::connect(address).await?;
    write_frame(&mut stream, hello).await?;
    let first: serde_json::Value = timeout(IO_WAIT, read_frame(&mut stream)).await??;
    if let Some(nonce) = first.get("nonce").and_then(serde_json::Value::as_str) {
        let key = ["alice", "bob", "carol", "dave", "hidden", "mallory"]
            .into_iter()
            .find(|name| public_of(name) == hello.public_key)
            .and_then(key_of)
            .ok_or("unknown test identity")?;
        let mut message = b"overlay-relay/auth/v2:".to_vec();
        message.extend_from_slice(&hex::decode(nonce)?);
        let signature: Signature = key.sign(&message);
        write_frame(
            &mut stream,
            &Proof {
                signature: hex::encode(signature.to_der().as_bytes()),
            },
        )
        .await?;
    } else {
        return Ok((stream, serde_json::from_value(first)?));
    }
    let reply = timeout(IO_WAIT, read_frame::<_, Reply>(&mut stream)).await??;
    Ok((stream, reply))
}

/// Registers a control stream and requires success.
async fn register(address: SocketAddr, name: &str) -> TestResult<(TcpStream, Reply)> {
    let (stream, reply) = dial(address, &control_hello(name)).await?;
    if !reply.ok {
        return Err(format!("control for {name} rejected: {reply:?}").into());
    }
    Ok((stream, reply))
}

async fn open_flow(address: SocketAddr, hello: Hello) -> TestResult<(TcpStream, Reply)> {
    dial(address, &hello).await
}

async fn next_event(stream: &mut TcpStream) -> TestResult<Event> {
    Ok(timeout(IO_WAIT, read_frame(stream)).await??)
}

async fn next_incoming(stream: &mut TcpStream) -> TestResult<Incoming> {
    loop {
        if let Event::Incoming(incoming) = next_event(stream).await? {
            return Ok(incoming);
        }
    }
}

/// Reads events until the control stream reports exactly the names in `want`.
async fn await_peers(
    stream: &mut TcpStream,
    want: &[&str],
) -> TestResult<Vec<overlay_relay::Peer>> {
    let mut expected: Vec<String> = want.iter().map(|name| (*name).to_owned()).collect();
    expected.sort();
    loop {
        if let Event::Peers(peers) = next_event(stream).await? {
            let mut names: Vec<String> = peers.iter().map(|peer| peer.name.clone()).collect();
            names.sort();
            if names == expected {
                return Ok(peers);
            }
        }
    }
}

/// Drains the stream until the peer ends it. Data is discarded; a timeout fails.
async fn expect_closed(stream: &mut TcpStream) -> TestResult {
    let mut buffer = vec![0_u8; 4096];
    loop {
        match timeout(IO_WAIT, stream.read(&mut buffer)).await? {
            Ok(0) | Err(_) => return Ok(()),
            Ok(_) => {}
        }
    }
}

async fn refused(address: SocketAddr, hello: Hello) -> TestResult {
    let (mut stream, reply) = dial(address, &hello).await?;
    if reply != Reply::failed(ERR_UNAVAILABLE) {
        return Err(format!("expected peer unavailable, got {reply:?}").into());
    }
    expect_closed(&mut stream).await
}

/// A flow between alice and bob. The control streams stay in the fixture.
struct Flow {
    alice: TcpStream,
    bob: TcpStream,
    incoming: Incoming,
}

/// Opens a flow from alice to bob on `proto`/`port` and returns both relayed ends.
async fn establish(f: &mut Fixture, proto: &str, port: u16) -> TestResult<Flow> {
    let (bob_control, _) = register(f.address, "bob").await?;
    let (alice_control, _) = register(f.address, "alice").await?;
    let bob_ip = f.ip("bob").await?;
    f.held.push(alice_control);
    let mut bob_control = bob_control;
    let opened = tokio::spawn(open_flow(
        f.address,
        open_hello("alice", &bob_ip.to_string(), proto, Some(port)),
    ));
    let incoming = next_incoming(&mut bob_control).await?;
    f.held.push(bob_control);
    let (bob, accepted) = dial(f.address, &accept_hello("bob", &incoming.id)).await?;
    if !accepted.ok {
        return Err(format!("accept rejected: {accepted:?}").into());
    }
    let (alice, reply) = opened.await??;
    if !reply.ok {
        return Err(format!("open rejected: {reply:?}").into());
    }
    Ok(Flow {
        alice,
        bob,
        incoming,
    })
}

#[tokio::test]
async fn bad_identities_get_unauthorized_and_are_closed() -> TestResult {
    let f = fixture(&["alice"], |_| {}).await?;
    for public_key in [public_of("mallory"), "not-hex".to_owned(), String::new()] {
        let hello = Hello {
            version: VERSION,
            kind: KIND_CONTROL.to_owned(),
            public_key,
            ..Hello::default()
        };
        let (mut stream, reply) = dial(f.address, &hello).await?;
        ensure!(!reply.ok, "bad identity must not authenticate");
        ensure_eq!(reply.error, ERR_UNAUTHORIZED);
        ensure!(reply.ip.is_empty(), "no address may leak to a bad identity");
        expect_closed(&mut stream).await?;
    }
    Ok(())
}

#[tokio::test]
async fn invalid_public_key_gets_unauthorized_reply() -> TestResult {
    let f = fixture(&["alice"], |_| {}).await?;
    let hello = Hello {
        version: VERSION,
        kind: KIND_CONTROL.to_owned(),
        public_key: "0".repeat(64),
        ..Hello::default()
    };
    let (mut stream, reply) = dial(f.address, &hello).await?;
    ensure_eq!(reply, Reply::failed(ERR_UNAUTHORIZED));
    expect_closed(&mut stream).await
}

#[tokio::test]
async fn rejects_wrong_key_and_replayed_proof() -> TestResult {
    let f = fixture(&["alice", "bob"], |_| {}).await?;
    let mut saved = String::new();
    for signer in ["bob", "alice", "replay"] {
        let mut stream = TcpStream::connect(f.address).await?;
        write_frame(&mut stream, &control_hello("alice")).await?;
        let challenge: overlay_relay::Challenge =
            timeout(IO_WAIT, read_frame(&mut stream)).await??;
        let signature = if signer == "replay" {
            saved.clone()
        } else {
            let mut message = b"overlay-relay/auth/v2:".to_vec();
            message.extend_from_slice(&hex::decode(challenge.nonce)?);
            let key = key_of(signer).ok_or("invalid test key")?;
            let signature: Signature = key.sign(&message);
            hex::encode(signature.to_der().as_bytes())
        };
        if signer == "alice" {
            saved.clone_from(&signature);
        }
        write_frame(&mut stream, &Proof { signature }).await?;
        let reply: Reply = timeout(IO_WAIT, read_frame(&mut stream)).await??;
        if signer == "alice" {
            ensure!(reply.ok, "matching key must authenticate");
        } else {
            ensure_eq!(reply, Reply::failed(ERR_UNAUTHORIZED));
            expect_closed(&mut stream).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn unknown_kind_gets_invalid_request_after_authentication() -> TestResult {
    let f = fixture(&["alice"], |_| {}).await?;
    let hello = Hello {
        version: VERSION,
        kind: "bogus".to_owned(),
        public_key: public_of("alice"),
        ..Hello::default()
    };
    let (mut stream, reply) = dial(f.address, &hello).await?;
    ensure_eq!(reply, Reply::failed(ERR_INVALID_REQUEST));
    expect_closed(&mut stream).await
}

#[tokio::test]
async fn oversized_and_wrong_version_frames_are_dropped() -> TestResult {
    let f = fixture(&["alice"], |_| {}).await?;
    let mut raw = TcpStream::connect(f.address).await?;
    raw.write_all(&[0xff, 0xff]).await?;
    expect_closed(&mut raw).await?;
    let mut wrong = TcpStream::connect(f.address).await?;
    let hello = Hello {
        version: 9,
        ..control_hello("alice")
    };
    write_frame(&mut wrong, &hello).await?;
    expect_closed(&mut wrong).await
}

#[tokio::test]
async fn silent_connection_hits_the_handshake_deadline() -> TestResult {
    let f = fixture(&["alice"], |c| {
        c.handshake_timeout = Duration::from_millis(100);
    })
    .await?;
    let mut stream = TcpStream::connect(f.address).await?;
    expect_closed(&mut stream).await
}

#[tokio::test]
async fn unadmitted_source_is_closed_before_any_frame() -> TestResult {
    let cases: [fn(&mut Config); 3] = [
        |c| c.allowed_hosts.clear(),
        |c| c.allowed_hosts = vec!["missing".to_owned()],
        |c| c.allowed_hosts = vec![ALLOWED.to_owned(), "missing".to_owned()],
    ];
    for (index, tune) in cases.into_iter().enumerate() {
        let f = fixture(&["alice"], tune).await?;
        if index == 2 {
            *f.addresses.lock().await = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))];
        }
        let mut stream = TcpStream::connect(f.address).await?;
        // Admission precedes reading: even a valid hello must get no reply.
        write_frame(&mut stream, &control_hello("alice")).await.ok();
        expect_closed(&mut stream).await?;
    }
    Ok(())
}

#[tokio::test]
async fn unlisted_source_address_is_refused() -> TestResult {
    let f = fixture(&["alice"], |_| {}).await?;
    *f.addresses.lock().await = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))];
    let mut stream = TcpStream::connect(f.address).await?;
    write_frame(&mut stream, &control_hello("alice")).await.ok();
    expect_closed(&mut stream).await
}

#[tokio::test]
async fn admission_follows_current_resolution() -> TestResult {
    let f = fixture(&["alice"], |_| {}).await?;
    *f.addresses.lock().await = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))];
    let mut refused_stream = TcpStream::connect(f.address).await?;
    expect_closed(&mut refused_stream).await?;
    // An IPv4-mapped IPv6 address of the connecting client is the same source.
    let mapped: IpAddr = "::ffff:127.0.0.1".parse()?;
    *f.addresses.lock().await = vec![mapped];
    let (_stream, reply) = register(f.address, "alice").await?;
    ensure!(
        reply.ok,
        "mapped loopback must be admitted after re-resolution"
    );
    Ok(())
}

#[tokio::test]
async fn control_registration_replies_then_sends_peers() -> TestResult {
    let f = fixture(&["alice", "bob", "carol"], |_| {}).await?;
    let (mut alice, reply) = register(f.address, "alice").await?;
    ensure_eq!(reply.ip, "10.77.0.1");
    ensure_eq!(reply.name, "alice");
    await_peers(&mut alice, &[]).await?;
    let (mut bob, bob_reply) = register(f.address, "bob").await?;
    ensure_eq!(bob_reply.ip, "10.77.0.2");
    await_peers(&mut alice, &["bob"]).await?;
    await_peers(&mut bob, &["alice"]).await?;
    let (_carol, _) = register(f.address, "carol").await?;
    await_peers(&mut alice, &["bob", "carol"]).await?;
    drop(bob);
    await_peers(&mut alice, &["carol"]).await?;
    Ok(())
}

#[tokio::test]
async fn broadcast_lists_only_other_broadcasting_accounts() -> TestResult {
    let f = fixture(&["alice", "bob", "carol", "hidden"], |_| {}).await?;
    let (mut alice, _) = register(f.address, "alice").await?;
    let (_bob, _) = register(f.address, "bob").await?;
    let (mut carol, _) = register(f.address, "carol").await?;
    // The hidden account has an address but no control stream, so it never appears.
    await_peers(&mut alice, &["bob", "carol"]).await?;
    await_peers(&mut carol, &["alice", "bob"]).await?;
    write_frame(&mut alice, &Ping { ping: true }).await?;
    loop {
        if let Event::Pong(_) = next_event(&mut alice).await? {
            break;
        }
    }
    Ok(())
}

#[tokio::test]
async fn refused_opens_are_indistinguishable() -> TestResult {
    let mut f = fixture(&["alice", "bob", "hidden"], |_| {}).await?;
    let (bob_control, _) = register(f.address, "bob").await?;
    let (mut alice_control, _) = register(f.address, "alice").await?;
    await_peers(&mut alice_control, &["bob"]).await?;
    let hidden = f.ip("hidden").await?.to_string();
    let bob = f.ip("bob").await?.to_string();
    let alice = f.ip("alice").await?.to_string();
    let cases = vec![
        open_hello("alice", &hidden, PROTO_TCP, Some(80)),
        open_hello("alice", "10.77.200.200", PROTO_TCP, Some(80)),
        open_hello("alice", &alice, PROTO_TCP, Some(80)),
        open_hello("alice", "not-an-address", PROTO_TCP, Some(80)),
        open_hello("alice", "", PROTO_TCP, Some(80)),
        open_hello("hidden", &bob, PROTO_TCP, Some(80)),
        open_hello("alice", &bob, "icmp", Some(80)),
        open_hello("alice", &bob, PROTO_TCP, None),
        open_hello("alice", &bob, PROTO_TCP, Some(0)),
    ];
    for hello in cases {
        refused(f.address, hello).await?;
    }
    let mut bob_control = bob_control;
    while let Ok(Ok(event)) = timeout(
        Duration::from_millis(200),
        read_frame::<_, Event>(&mut bob_control),
    )
    .await
    {
        ensure!(
            !matches!(event, Event::Incoming(_)),
            "a refused request reached a peer"
        );
    }
    f.held.push(bob_control);
    Ok(())
}

#[tokio::test]
async fn tcp_flow_splices_both_ways_with_half_close() -> TestResult {
    let mut f = fixture(&["alice", "bob"], |_| {}).await?;
    let mut flow = establish(&mut f, PROTO_TCP, 2222).await?;
    ensure_eq!(flow.incoming.proto, PROTO_TCP);
    ensure_eq!(flow.incoming.port, 2222);
    ensure_eq!(flow.incoming.src, "10.77.0.1");
    ensure_eq!(flow.incoming.id.len(), 32);

    flow.alice.write_all(b"to-bob").await?;
    let mut buffer = [0_u8; 6];
    timeout(IO_WAIT, flow.bob.read_exact(&mut buffer)).await??;
    ensure_eq!(&buffer, b"to-bob");
    flow.bob.write_all(b"to-alice").await?;
    let mut buffer = [0_u8; 8];
    timeout(IO_WAIT, flow.alice.read_exact(&mut buffer)).await??;
    ensure_eq!(&buffer, b"to-alice");

    // Alice half-closes: bob sees end-of-stream but can still answer.
    flow.alice.shutdown().await?;
    let mut rest = Vec::new();
    timeout(IO_WAIT, flow.bob.read_to_end(&mut rest)).await??;
    ensure!(rest.is_empty(), "bob must see a clean end of stream");
    flow.bob.write_all(b"tail").await?;
    flow.bob.shutdown().await?;
    let mut tail = Vec::new();
    timeout(IO_WAIT, flow.alice.read_to_end(&mut tail)).await??;
    ensure_eq!(tail, b"tail");
    Ok(())
}

/// A fingerprint-shaped value made of one repeated hex digit.
fn print(digit: char) -> String {
    digit.to_string().repeat(64)
}

/// Opens a TCP flow from alice to bob where each side attaches its offer
/// (`fingerprint`, `endpoint`). Returns the flow and both success replies.
async fn establish_offered(
    f: &mut Fixture,
    alice: (&str, &str),
    bob: (&str, &str),
) -> TestResult<(Flow, Reply, Reply)> {
    let (mut bob_control, _) = register(f.address, "bob").await?;
    let (alice_control, _) = register(f.address, "alice").await?;
    let bob_ip = f.ip("bob").await?;
    f.held.push(alice_control);
    let mut open = open_hello("alice", &bob_ip.to_string(), PROTO_TCP, Some(2222));
    alice.0.clone_into(&mut open.fingerprint);
    alice.1.clone_into(&mut open.endpoint);
    let opened = tokio::spawn(open_flow(f.address, open));
    let incoming = next_incoming(&mut bob_control).await?;
    f.held.push(bob_control);
    let mut accept = accept_hello("bob", &incoming.id);
    bob.0.clone_into(&mut accept.fingerprint);
    bob.1.clone_into(&mut accept.endpoint);
    let (bob_stream, bob_reply) = dial(f.address, &accept).await?;
    let (alice_stream, alice_reply) = opened.await??;
    let flow = Flow {
        alice: alice_stream,
        bob: bob_stream,
        incoming,
    };
    Ok((flow, alice_reply, bob_reply))
}

#[tokio::test]
async fn matching_fingerprints_secure_the_relayed_flow() -> TestResult {
    let mut f = fixture(&["alice", "bob"], |_| {}).await?;
    let (alice_print, bob_print) = (print('a'), print('B'));
    let (mut flow, alice_reply, bob_reply) =
        establish_offered(&mut f, (&alice_print, ""), (&bob_print, "")).await?;
    // The destination sees the requester's offer before it answers.
    ensure_eq!(flow.incoming.fingerprint, alice_print);
    ensure_eq!(flow.incoming.endpoint, "");
    // Each side learns the other side's fingerprint, lowercase, and nothing else.
    ensure_eq!(
        alice_reply,
        Reply {
            ok: true,
            secure: true,
            fingerprint: bob_print.to_ascii_lowercase(),
            ..Reply::default()
        }
    );
    ensure_eq!(
        bob_reply,
        Reply {
            ok: true,
            secure: true,
            fingerprint: alice_print,
            ..Reply::default()
        }
    );
    // The flow is still relayed: the hub carries the bytes unchanged.
    flow.alice.write_all(b"sealed").await?;
    let mut buffer = [0_u8; 6];
    timeout(IO_WAIT, flow.bob.read_exact(&mut buffer)).await??;
    ensure_eq!(&buffer, b"sealed");
    Ok(())
}

#[tokio::test]
async fn matching_endpoints_hand_the_flow_to_a_direct_connection() -> TestResult {
    let mut f = fixture(&["alice", "bob"], |_| {}).await?;
    let (alice_print, bob_print) = (print('a'), print('b'));
    let (mut flow, alice_reply, bob_reply) = establish_offered(
        &mut f,
        (&alice_print, "203.0.113.7:4001"),
        (&bob_print, "198.51.100.9:4002"),
    )
    .await?;
    ensure_eq!(flow.incoming.endpoint, "203.0.113.7:4001");
    ensure_eq!(
        alice_reply,
        Reply {
            ok: true,
            secure: true,
            direct: true,
            id: flow.incoming.id.clone(),
            fingerprint: bob_print,
            endpoint: "198.51.100.9:4002".to_owned(),
            ..Reply::default()
        }
    );
    ensure_eq!(
        bob_reply,
        Reply {
            ok: true,
            secure: true,
            direct: true,
            id: flow.incoming.id.clone(),
            fingerprint: alice_print,
            endpoint: "203.0.113.7:4001".to_owned(),
            ..Reply::default()
        }
    );
    // The hub relays nothing and ends both streams.
    expect_closed(&mut flow.alice).await?;
    expect_closed(&mut flow.bob).await
}

#[tokio::test]
async fn one_sided_offers_fall_back_to_the_plain_relay() -> TestResult {
    let mut f = fixture(&["alice", "bob"], |_| {}).await?;
    let alice_print = print('a');
    let (mut flow, alice_reply, bob_reply) =
        establish_offered(&mut f, (&alice_print, "203.0.113.7:4001"), ("", "")).await?;
    // Without a counter-offer neither reply carries anything but success.
    ensure_eq!(alice_reply, Reply::accepted());
    ensure_eq!(bob_reply, Reply::accepted());
    flow.alice.write_all(b"plain").await?;
    let mut buffer = [0_u8; 5];
    timeout(IO_WAIT, flow.bob.read_exact(&mut buffer)).await??;
    ensure_eq!(&buffer, b"plain");
    Ok(())
}

#[tokio::test]
async fn malformed_offers_are_refused() -> TestResult {
    let mut f = fixture(&["alice", "bob"], |_| {}).await?;
    let (mut bob_control, _) = register(f.address, "bob").await?;
    let (alice_control, _) = register(f.address, "alice").await?;
    let bob_ip = f.ip("bob").await?.to_string();
    f.held.push(alice_control);

    let valid = print('a');
    let bad_opens = [
        ("", "203.0.113.7:4001"),
        ("not-a-fingerprint", ""),
        (valid.as_str(), "not-an-endpoint"),
        (valid.as_str(), "203.0.113.7:0"),
        (valid.as_str(), "0.0.0.0:4001"),
    ];
    for (fingerprint, endpoint) in bad_opens {
        let mut hello = open_hello("alice", &bob_ip, PROTO_TCP, Some(2222));
        fingerprint.clone_into(&mut hello.fingerprint);
        endpoint.clone_into(&mut hello.endpoint);
        refused(f.address, hello).await?;
    }

    // A malformed accept offer is rejected as an invalid request and leaves the
    // pending request claimable.
    let mut open = open_hello("alice", &bob_ip, PROTO_TCP, Some(2222));
    print('a').clone_into(&mut open.fingerprint);
    let opened = tokio::spawn(open_flow(f.address, open));
    let incoming = next_incoming(&mut bob_control).await?;
    f.held.push(bob_control);
    let mut bad = accept_hello("bob", &incoming.id);
    "zz".clone_into(&mut bad.fingerprint);
    let (_, reply) = dial(f.address, &bad).await?;
    ensure_eq!(reply, Reply::failed(ERR_INVALID_REQUEST));
    let mut good = accept_hello("bob", &incoming.id);
    print('b').clone_into(&mut good.fingerprint);
    let (_, reply) = dial(f.address, &good).await?;
    ensure!(
        reply.ok && reply.secure,
        "a valid accept must still succeed"
    );
    let (_, reply) = opened.await??;
    ensure!(reply.ok && reply.secure, "the open must succeed: {reply:?}");
    Ok(())
}

#[tokio::test]
async fn udp_flow_preserves_datagram_framing() -> TestResult {
    let mut f = fixture(&["alice", "bob"], |_| {}).await?;
    let mut flow = establish(&mut f, PROTO_UDP, 5353).await?;
    ensure_eq!(flow.incoming.proto, PROTO_UDP);
    let datagrams: Vec<Vec<u8>> = vec![
        b"a".to_vec(),
        Vec::new(),
        vec![b'x'; 1400],
        b"last".to_vec(),
    ];
    for datagram in &datagrams {
        write_datagram(&mut flow.alice, datagram).await?;
    }
    let mut buffer = vec![0_u8; MAX_DATAGRAM];
    for want in &datagrams {
        let size = timeout(IO_WAIT, read_datagram(&mut flow.bob, &mut buffer)).await??;
        ensure_eq!(
            &buffer[..size],
            want.as_slice(),
            "datagram boundaries must survive"
        );
    }
    write_datagram(&mut flow.bob, b"pong").await?;
    let size = timeout(IO_WAIT, read_datagram(&mut flow.alice, &mut buffer)).await??;
    ensure_eq!(&buffer[..size], b"pong");
    Ok(())
}

#[tokio::test]
async fn udp_flow_ends_when_idle() -> TestResult {
    let mut f = fixture(&["alice", "bob"], |c| {
        c.udp_idle = Duration::from_millis(150);
    })
    .await?;
    let mut flow = establish(&mut f, PROTO_UDP, 53).await?;
    expect_closed(&mut flow.alice).await?;
    expect_closed(&mut flow.bob).await
}

#[tokio::test]
async fn missing_accept_reports_unavailable_and_late_accept_fails() -> TestResult {
    let f = fixture(&["alice", "bob"], |c| {
        c.accept_timeout = Duration::from_millis(150);
    })
    .await?;
    let (mut bob_control, _) = register(f.address, "bob").await?;
    let (_alice_control, _) = register(f.address, "alice").await?;
    let bob_ip = f.ip("bob").await?.to_string();
    let started = Instant::now();
    let (_stream, reply) =
        open_flow(f.address, open_hello("alice", &bob_ip, PROTO_TCP, Some(80))).await?;
    ensure_eq!(reply, Reply::failed(ERR_UNAVAILABLE));
    ensure!(
        started.elapsed() >= Duration::from_millis(100),
        "must wait for the accept"
    );
    let id = next_incoming(&mut bob_control).await?.id;
    let (_late, late) = dial(f.address, &accept_hello("bob", &id)).await?;
    ensure_eq!(
        late,
        Reply::failed(ERR_UNAUTHORIZED),
        "a late accept finds nothing"
    );
    Ok(())
}

#[tokio::test]
async fn accept_is_bound_to_destination_and_single_use() -> TestResult {
    let f = fixture(&["alice", "bob", "carol", "hidden"], |_| {}).await?;
    let (mut bob_control, _) = register(f.address, "bob").await?;
    let (_alice_control, _) = register(f.address, "alice").await?;
    let (_carol_control, _) = register(f.address, "carol").await?;
    let bob_ip = f.ip("bob").await?.to_string();
    let opened: JoinHandle<TestResult<(TcpStream, Reply)>> = tokio::spawn(open_flow(
        f.address,
        open_hello("alice", &bob_ip, PROTO_TCP, Some(80)),
    ));
    let id = next_incoming(&mut bob_control).await?.id;
    for name in ["carol", "hidden", "alice", "mallory"] {
        let (_stream, reply) = dial(f.address, &accept_hello(name, &id)).await?;
        ensure_eq!(
            reply,
            Reply::failed(ERR_UNAUTHORIZED),
            "{name} accepted a foreign request"
        );
    }
    let (_stream, reply) = dial(f.address, &accept_hello("bob", &"0".repeat(32))).await?;
    ensure_eq!(
        reply,
        Reply::failed(ERR_UNAUTHORIZED),
        "an unknown id must not be accepted"
    );
    let (_accepted, reply) = dial(f.address, &accept_hello("bob", &id)).await?;
    ensure!(reply.ok, "the destination's accept must succeed");
    let (_flow, open_reply) = opened.await??;
    ensure!(open_reply.ok, "the open must succeed once accepted");
    let (_second, reply) = dial(f.address, &accept_hello("bob", &id)).await?;
    ensure_eq!(
        reply,
        Reply::failed(ERR_UNAUTHORIZED),
        "an accept is single use"
    );
    Ok(())
}

#[tokio::test]
async fn pending_requests_are_bounded_per_destination() -> TestResult {
    let f = fixture(&["alice", "bob"], |c| {
        c.accept_timeout = Duration::from_secs(1);
    })
    .await?;
    let (mut bob_control, _) = register(f.address, "bob").await?;
    let (_alice_control, _) = register(f.address, "alice").await?;
    let bob_ip = f.ip("bob").await?.to_string();
    let mut handles = Vec::new();
    for _ in 0..=MAX_PENDING_PER_ACCOUNT {
        handles.push(tokio::spawn(open_flow(
            f.address,
            open_hello("alice", &bob_ip, PROTO_TCP, Some(80)),
        )));
        sleep(Duration::from_millis(20)).await;
    }
    let mut incoming = 0;
    while let Ok(Ok(event)) = timeout(
        Duration::from_millis(300),
        read_frame::<_, Event>(&mut bob_control),
    )
    .await
    {
        if matches!(event, Event::Incoming(_)) {
            incoming += 1;
        }
    }
    ensure_eq!(
        incoming,
        MAX_PENDING_PER_ACCOUNT,
        "only the pending cap may reach bob"
    );
    for handle in handles {
        let (_stream, reply) = handle.await??;
        ensure_eq!(
            reply,
            Reply::failed(ERR_UNAVAILABLE),
            "every request ends unavailable"
        );
    }
    Ok(())
}

#[tokio::test]
async fn control_replacement_and_idle_close() -> TestResult {
    let f = fixture(&["alice", "bob"], |c| {
        c.control_idle = Duration::from_millis(300);
    })
    .await?;
    let (mut first, _) = register(f.address, "alice").await?;
    let (mut second, _) = register(f.address, "alice").await?;
    expect_closed(&mut first).await?;
    let (mut bob, _) = register(f.address, "bob").await?;
    await_peers(&mut second, &["bob"]).await?;
    // Pings keep bob alive past the idle limit.
    for _ in 0..4 {
        sleep(Duration::from_millis(120)).await;
        write_frame(&mut bob, &Ping { ping: true }).await?;
    }
    loop {
        if let Event::Pong(_) = next_event(&mut bob).await? {
            break;
        }
    }
    // Silent alice is closed by the idle limit; bob then sees her leave.
    expect_closed(&mut second).await?;
    await_peers(&mut bob, &[]).await?;
    Ok(())
}

#[tokio::test]
async fn removed_account_loses_control_and_flows() -> TestResult {
    let mut f = fixture(&["alice", "bob", "carol"], |_| {}).await?;
    let mut flow = establish(&mut f, PROTO_TCP, 22).await?;
    let (mut carol, _) = register(f.address, "carol").await?;
    // Re-registering alice replaces the earlier control stream.
    let (mut alice_control, _) = register(f.address, "alice").await?;
    await_peers(&mut carol, &["alice", "bob"]).await?;
    write_peers(&f.peers, &["bob", "carol"]).await?;
    expect_closed(&mut alice_control).await?;
    expect_closed(&mut flow.alice).await?;
    expect_closed(&mut flow.bob).await?;
    await_peers(&mut carol, &["bob"]).await?;
    let (_stream, reply) = dial(f.address, &control_hello("alice")).await?;
    ensure_eq!(
        reply,
        Reply::failed(ERR_UNAUTHORIZED),
        "a removed account must not authenticate"
    );
    Ok(())
}

#[tokio::test]
async fn invalid_peers_table_keeps_last_good() -> TestResult {
    let f = fixture(&["alice"], |_| {}).await?;
    let invalid = [
        "{".to_owned(),
        r#"{"version":1,"accounts":[]}"#.to_owned(),
        r#"{"version":2,"accounts":[{"public_key":"zz","name":"x"}]}"#.to_owned(),
    ];
    for content in invalid {
        tokio::fs::write(&f.peers, content.as_bytes()).await?;
        sleep(Duration::from_millis(80)).await;
        let (_stream, reply) = register(f.address, "alice").await?;
        ensure!(reply.ok, "last good table must survive invalid content");
    }
    write_peers(&f.peers, &["alice", "dave"]).await?;
    sleep(Duration::from_millis(80)).await;
    let (_stream, reply) = register(f.address, "dave").await?;
    ensure!(reply.ok, "a new valid table must take effect");
    Ok(())
}

async fn load_hub(peers: &Path, data: &Path, names: &[&str]) -> TestResult<Hub> {
    write_peers(peers, names).await?;
    let config = Config::new(peers.to_path_buf(), data.to_path_buf(), Vec::new());
    Ok(Hub::new(config).await?)
}

async fn addresses_of(hub: &Hub, names: &[&str]) -> Vec<Option<Ipv4Addr>> {
    let mut found = Vec::with_capacity(names.len());
    for name in names {
        found.push(hub.address_of(verifier_of(name)).await);
    }
    found
}

#[tokio::test]
async fn addresses_are_stable_across_restart_and_reused_on_removal() -> TestResult {
    let dir = tempfile::tempdir()?;
    let peers = dir.path().join("peers.json");
    let first = load_hub(&peers, dir.path(), &["a", "b", "c"]).await?;
    ensure_eq!(
        addresses_of(&first, &["a", "b", "c"]).await,
        vec![
            Some("10.77.0.1".parse::<Ipv4Addr>()?),
            Some("10.77.0.2".parse::<Ipv4Addr>()?),
            Some("10.77.0.3".parse::<Ipv4Addr>()?)
        ]
    );
    let second = load_hub(&peers, dir.path(), &["c", "b", "a"]).await?;
    ensure_eq!(
        addresses_of(&second, &["a", "b", "c"]).await,
        vec![
            Some("10.77.0.1".parse::<Ipv4Addr>()?),
            Some("10.77.0.2".parse::<Ipv4Addr>()?),
            Some("10.77.0.3".parse::<Ipv4Addr>()?)
        ],
        "reordering and restart keep addresses"
    );
    let third = load_hub(&peers, dir.path(), &["a", "c"]).await?;
    ensure_eq!(
        addresses_of(&third, &["a", "c"]).await,
        vec![
            Some("10.77.0.1".parse::<Ipv4Addr>()?),
            Some("10.77.0.3".parse::<Ipv4Addr>()?)
        ],
        "survivors keep addresses"
    );
    let fourth = load_hub(&peers, dir.path(), &["a", "c", "d"]).await?;
    ensure_eq!(
        addresses_of(&fourth, &["d"]).await,
        vec![Some("10.77.0.2".parse::<Ipv4Addr>()?)],
        "the freed address is reused"
    );

    let assignments = dir.path().join("ips.json");
    let saved = tokio::fs::read(&assignments).await?;
    tokio::fs::write(&peers, b"{").await?;
    Hub::new(Config::new(
        peers.clone(),
        dir.path().to_path_buf(),
        Vec::new(),
    ))
    .await?;
    ensure_eq!(
        tokio::fs::read(&assignments).await?,
        saved,
        "a broken table must not erase assignments"
    );

    tokio::fs::write(&assignments, b"garbage").await?;
    let corrupt = Hub::new(Config::new(peers, dir.path().to_path_buf(), Vec::new())).await;
    ensure!(
        corrupt.is_err(),
        "corrupt assignments must be an error, not renumbering"
    );
    Ok(())
}
