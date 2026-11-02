# overlay-hub

`overlay-hub` is the relay server for overlay-relay. It accepts connections from admitted hosts, authenticates accounts by public key, and relays TCP and UDP flows between broadcasting accounts.

Every client connection must use an authenticated VPN. The hub itself accepts TCP and does not authenticate or protect that transport against an active intermediary.

- Listens on TCP `6697` by default.
- Reads its accounts from a read-only peers table that you manage.
- Assigns each account a stable address in `10.77.0.0/16` and remembers it in `ips.json`.
- Never inspects relayed payloads and never logs private keys, identifiers, payloads or peer names.
- Pairs the encryption offers of the two agents of a flow. Each agent may send a certificate `fingerprint` (end-to-end encryption) and a public UDP `endpoint` (direct connection) in its `open` or `accept` hello. The hub validates them and tells each side the other's values only when both made the offer. It never holds a key. When both offered an endpoint, the hub relays nothing and ends both streams after the hand-off.

## Build

```text
cd server
cargo build --release --locked --bin overlay-hub
```

The binary is `target/release/overlay-hub`. The crate needs Rust with edition 2024 support.

## Run

```text
OVERLAY_ALLOWED_HOST=client-host \
OVERLAY_PEERS_PATH=./peers.json \
OVERLAY_DATA_DIR=./data \
OVERLAY_LISTEN_ADDRESS=0.0.0.0:6697 \
./target/release/overlay-hub
```

| Variable | Meaning | Required |
|---|---|---|
| `OVERLAY_ALLOWED_HOST` | Comma-separated host names. Only connections from an address one of these names currently resolves to are admitted. Empty entries are ignored. | Yes. Without it the hub refuses to start. |
| `OVERLAY_PEERS_PATH` | Path to the peers table (see below). | Recommended |
| `OVERLAY_DATA_DIR` | Directory where `ips.json` is written. Must be writable. | Recommended |
| `OVERLAY_LISTEN_ADDRESS` | Address to bind. | Default `0.0.0.0:6697` |

If `OVERLAY_PEERS_PATH` or `OVERLAY_DATA_DIR` is unset, the binary uses built-in default paths from `src/main.rs`. Set both explicitly.

The hub logs to standard error through `tracing`. Set the level in code, not by environment. Stop it with `SIGTERM` or `Ctrl+C`.

## Peers table

A JSON file. The hub reads it at startup and checks it every 2 seconds for changes.

Each account contains `public_key` and `name`. Generate a valid table with the tool below.

- `version` must be `2`.
- At most 4096 accounts. Each `public_key` is a unique hex-encoded uncompressed P-384 point.
- Each `name` is at most 128 bytes.
- The file is at most 4 MiB.
- A missing file at startup means no accounts. An invalid file at startup also means no accounts. An invalid file after startup keeps the last good table.

Generate the identity on the client and transfer only its public key to the hub operator. Generate the table with the example tool:

```text
cd ../examples && go run ./peers 'alice=<alice-public-key>' > ./peers.json
```

Replace the file atomically (write a temporary file, then rename it over the target). Removing an account closes its control stream and its flows.

## Container

The repository root has a `Dockerfile` that builds this crate as a static musl binary on `rust:1-slim` and runs it on `debian:13-slim` as a non-root user:

```text
docker build -t overlay-relay:0.1.0 ..
docker run -d \
  -e OVERLAY_ALLOWED_HOST=client-host \
  -v ./peers-dir:/etc/overlay-relay:ro \
  -v overlay-relay-data:/var/lib/overlay-relay \
  overlay-relay:0.1.0
```

- The image sets `OVERLAY_PEERS_PATH=/etc/overlay-relay/peers.json`, `OVERLAY_DATA_DIR=/var/lib/overlay-relay`, `OVERLAY_LISTEN_ADDRESS=0.0.0.0:6697`.
- Attach the container to the authenticated VPN network. Do not expose the hub directly to an untrusted network.
- Mount the peers directory, not a single file. The hub watches the directory for renames.
- The data volume must be writable by uid `65532`.

## Admission

Before reading any frame, the hub resolves each `OVERLAY_ALLOWED_HOST` name (2 second lookup timeout) and compares the connection's remote address with the results. Connections from other addresses are closed without a reply. Make sure clients reach the hub from an address that one of the allowed names resolves to.

## Limits

| Item | Limit |
|---|---|
| Frame payload | 16 KiB |
| Datagram payload | 65535 bytes |
| Accounts | 4096 |
| Flows per account | 256 |
| Pending requests per destination | 4 |
| First frame deadline | 10 s |
| Accept wait | 10 s |
| Control stream idle | 90 s without a ping |
| UDP flow idle | 120 s |

The wire format and message schemas are in [`../docs/LLM_WIKI.md`](../docs/LLM_WIKI.md).

## Test

```text
cargo test
cargo clippy --all-targets -- -D warnings
```

`tests/hub.rs` runs the hub over real loopback TCP and UDP sockets, covering admission, authentication, accept, pending limits, idle timeouts, peers reload, and address stability.

## License

GPL-3.0-only.
