# overlay-hub

`overlay-hub` is the relay server for overlay-relay. It accepts connections from admitted hosts, identifies each client by the public key it proves, and relays TCP and UDP flows between broadcasting clients. Install it and run it: nothing needs configuring.

Every client connection must use an authenticated VPN. The hub itself accepts TCP and does not authenticate or protect that transport against an active intermediary.

- Listens on TCP `6697` by default.
- Assigns each identity a stable address in `10.77.0.0/16` and remembers it in `ips.json`.
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
./target/release/overlay-hub
```

The hub needs no configuration. Every variable below is optional.

| Variable | Meaning | Default |
|---|---|---|
| `OVERLAY_ALLOWED_HOST` | Comma-separated host names. Only connections from an address one of these names currently resolves to are admitted. Empty entries are ignored. | Unset: every loopback, private or link-local source is admitted. |
| `OVERLAY_DATA_DIR` | Directory where `ips.json` is written. Must be writable. | `/var/lib/overlay-relay` |
| `OVERLAY_LISTEN_ADDRESS` | Address to bind. | `0.0.0.0:6697` |

The hub logs to standard error through `tracing`. Set the level in code, not by environment. Stop it with `SIGTERM` or `Ctrl+C`.

Clap provides `--help`, `--version`, `--data-dir`, `--allowed-host`, `--listen-address` and `--cidr`. Existing environment variables remain supported; `OVERLAY_CIDR` selects a canonical RFC 1918 `/8`–`/30` subnet. Put `--cidr` before an administrative subcommand, or set the same environment as the running hub. `--data-dir` is accepted before or after subcommands.

## DHCP policy

`overlay-hub dhcp show` prints the validated policy as one JSON object. Pipe a complete policy to `overlay-hub dhcp set`, then restart the hub to activate it:

```json
{"start":"10.77.0.10","end":"10.77.0.200","lease_seconds":3600,"bindings":[]}
```

The dynamic endpoints are inclusive usable addresses in the hub's actual subnet. `lease_seconds` is zero (legacy capacity-based idle reclamation) or 60–31536000; unexpired leases are not evicted under pool pressure. Active controls/flows and permanent reservations are never reclaimed. Bindings contain `public_key` (the canonical uncompressed P-384 public-key hex, not its ID digest) and `ip` (a usable reserved address, inside or outside the dynamic pool). Dynamic allocation skips every reserved address, including offline reservations. Policy changes discard conflicting saved assignments on startup.

The hub validates subnet bounds, ordering, lease limits, real public points and unique keys/addresses before any write. It rejects unknown fields, malformed JSON, documents above 64 KiB and more than 256 bindings. Custom policy is atomically saved in `dhcp.json` with private permissions. Saving the full usable range with a zero lease and no bindings clears the override, so defaults follow the subnet. Before changing to a subnet that excludes the current pool or reservations, restore and apply defaults on the old subnet, then change the subnet. Corrupt or unreadable policy prevents startup rather than falling back to a permissive default. The client cannot override this policy. There are no server port bans; clients may independently filter their own incoming relayed TCP/UDP flows.

## Room relay policy

Run these against the hub's `OVERLAY_DATA_DIR`:

```text
overlay-hub rooms list
overlay-hub rooms relay public false
overlay-hub rooms create <id> <name> <password-proof> false
overlay-hub rooms relay <room-key> true
overlay-hub rooms replace --confirm <id> <name> <password-proof> false
```

`rooms list` returns `public_relay` and each private room's `relay` flag. Room keys are SHA-256 hashes of IDs. Omitted policy defaults to enabled for new or legacy rooms; replacement without a policy preserves the existing setting. Toggling policy leaves the room's credentials unchanged.

The hub rejects new TCP/UDP relay flows when disabled and closes existing relay streams after detecting the policy change (checked every 250 ms). Invalid policy fails closed. Discovery and bounded direct-link signaling remain available; WebRTC, ICE and P2P payloads continue directly between peers. Direct links still require mutual device approval. Room policy is persisted in `rooms.json`.

## Identities

There is no account table and no enrollment. A client generates its own P-384 key pair and keeps the private key. On every connection the hub sends a fresh challenge and the client signs it with that key.

- A valid signature makes the hub treat the connection as the identity of that public key. The same key is always the same peer, and a different key is a different peer.
- The first valid signature of a new key assigns the lowest free address in `10.77.0.0/16`. The hub remembers it in `ips.json` with the time the key was last seen, so the address survives restarts and reconnects.
- A peer's display name is `peer-` followed by the first 8 hex digits of its key digest.
- A key proves only possession. Whoever can reach the hub through the VPN can join with a new key, so keep the hub reachable only through your VPN.
- The hub keeps at most 4096 identities. When the table is full, a new key takes the address of the identity seen longest ago that has no control stream and no flow. When all 4096 are in use, new keys are refused.
- A client that loses its private key becomes a new peer with a new address.

## Container

The repository root has a `Dockerfile` that builds this crate as a static musl binary on `rust:1-slim` and runs it on `debian:13-slim` as a non-root user:

```text
docker build -t overlay-relay:latest ..
docker run -d -v overlay-relay-data:/var/lib/overlay-relay overlay-relay:latest
```

- The image sets `OVERLAY_DATA_DIR=/var/lib/overlay-relay` and `OVERLAY_LISTEN_ADDRESS=0.0.0.0:6697`.
- Attach the container to the authenticated VPN network. Do not expose the hub directly to an untrusted network.
- The data volume must be writable by uid `65532`.

## Admission

Before reading any frame, the hub checks the remote address of the connection.

- With `OVERLAY_ALLOWED_HOST`, it resolves each name (2 second lookup timeout) and compares the remote address with the results. Connections from other addresses are closed without a reply.
- Without it, it admits loopback, private (`10/8`, `172.16/12`, `192.168/16`), link-local and unique-local addresses, which covers every peer on the container network. A source with a public address is closed without a reply.

## Limits

| Item | Limit |
|---|---|
| Frame payload | 16 KiB |
| Datagram payload | 65535 bytes |
| Identities | 4096 |
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

`tests/hub.rs` runs the hub over real loopback TCP and UDP sockets, covering admission, authentication, accept, pending limits, idle timeouts, and address stability.

## License

GPL-3.0-only.
