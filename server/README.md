# overlay-hub

`overlay-hub` is the relay server for overlay-relay. It accepts connections from admitted hosts, authenticates accounts by token, and relays TCP and UDP flows between broadcasting accounts.

- Listens on TCP `6697` by default.
- Reads its accounts from a read-only peers table that you manage.
- Assigns each account a stable address in `10.77.0.0/16` and remembers it in `ips.json`.
- Never inspects relayed payloads and never logs tokens, verifiers, payloads or peer names.

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

```json
{
  "version": 1,
  "accounts": [
    { "verifier": "c061fc54bb1a7534356bbe32c554c1a3985851a3d1749107b677793ffcb5ba9f", "name": "alice" }
  ]
}
```

- `version` must be `1`.
- At most 4096 accounts. Each `verifier` is 64 lowercase or uppercase hex digits and unique.
- Each `name` is at most 128 bytes.
- The file is at most 4 MiB.
- A missing file at startup means no accounts. An invalid file at startup also means no accounts. An invalid file after startup keeps the last good table.

Generate verifiers from client secrets with the example tool:

```text
cd ../examples && go run ./peers alice=hysteria:alice:alice-pass > ./peers.json
```

Replace the file atomically (write a temporary file, then rename it over the target). Removing an account closes its control stream and its flows.

## Container

The repository root has a `Dockerfile` that builds this crate into a distroless, non-root image:

```text
docker build -t overlay-relay:0.1.0 ..
docker run -d -p 6697:6697 \
  -e OVERLAY_ALLOWED_HOST=client-host \
  -v ./peers-dir:/etc/overlay-relay:ro \
  -v overlay-relay-data:/var/lib/overlay-relay \
  overlay-relay:0.1.0
```

- The image sets `OVERLAY_PEERS_PATH=/etc/overlay-relay/peers.json`, `OVERLAY_DATA_DIR=/var/lib/overlay-relay`, `OVERLAY_LISTEN_ADDRESS=0.0.0.0:6697`.
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
