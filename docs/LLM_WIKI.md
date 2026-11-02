# Overlay Relay: Developer Wiki for Building a Client

This document is written so that an agent with no prior knowledge can build a new client application that joins the overlay network. It is the complete contract: identity, addressing, wire format, message semantics, timing, limits, error values, and client behavior. Everything needed to interoperate with the hub is here. Implementation details of the hub are included only where a client must know them.

Where this document and the code disagree, the code in `server/` (hub) and `client/` (Go reference agent) is the reference. The Go agent in `client/overlayagent` is a complete, tested client; a new client in another language should mirror it.

## 1. What the system does

- A **hub** (Rust binary `overlay-hub`, source in `server/`) is reachable over TCP on port `6697`.
- Each **account** holds one stable private IPv4 address in `10.77.0.0/16`.
- A **client** that "broadcasts" registers a **control stream** with the hub. The hub then tells it which other broadcasting accounts exist (`peers`).
- A client opens a **flow** (TCP or UDP) to a peer's overlay address and port. The hub asks the peer to accept, pairs the two streams, and relays bytes between them.
- The hub never inspects payload bytes after the handshake. It forwards them unchanged.
- Agents may optionally compress flow bytes (section 8.5). The hub is unaware of it.
- Hidden accounts (not broadcasting) hold an address but never register a control stream, so they are never listed and cannot be reached.

## 2. Glossary

| Term | Meaning |
|---|---|
| Hub | The server process. Accepts TCP connections, authenticates them, and relays. |
| Account | One identity, identified by its verifier. Has a display name and an overlay address. |
| Secret | Client-side credential bytes. Never sent to the hub. |
| Token | 32-byte bearer value derived from the secret. Sent to the hub as 64 lowercase hex digits. |
| Verifier | SHA-256 of the token's 32 raw bytes. Stored in the peers table as 64 lowercase hex digits. |
| Peers table | Read-only JSON file on the hub that lists the accounts. |
| Control stream | Long-lived TCP connection that registers a broadcasting account and receives events. |
| Open stream | TCP connection that requests a flow to a peer. |
| Accept stream | TCP connection the destination peer opens to answer an incoming request. |
| Flow | A relayed TCP or UDP conversation between two accounts. |
| Incoming | Event on a control stream asking the destination to open an accept stream. |

## 3. Repository layout

```
server/            Rust hub crate "overlay-relay", binary "overlay-hub"
  src/main.rs      reads environment, runs the hub
  src/lib.rs       library API (Hub, Config, Peers, Verifier, frame helpers)
  src/protocol.rs  wire constants and message types
  tests/hub.rs     integration tests over real loopback sockets
client/            Go module github.com/ParkSnoopy/overlay-relay/client
  overlay/         wire types, frame codec, token/verifier helpers, Peers validation
  overlayagent/    reference agent: registration, peers, outbound and inbound flows, probe
tests/             Go tests that run the Rust hub and the Go agent together
examples/          Go programs: peers table generator, client program
docs/              this wiki, server and client notes, release gate
Dockerfile         builds the server image
```

## 4. Identity: secrets, tokens, verifiers

The client holds a **secret** (bytes). The derivation is fixed:

```
token    = lowercase_hex( HMAC-SHA256(key = secret, message = "snoo-box/overlay/v1") )   // 64 hex digits
verifier = lowercase_hex( SHA-256( hex_decode(token) ) )                                  // 64 hex digits
```

- The message `snoo-box/overlay/v1` is a fixed protocol label. It is part of the wire contract and must be used byte-for-byte as written. Do not change it.
- The hub stores only the verifier. It cannot recover the token or the secret from it.
- The secret must never be sent on the wire. Only the token is sent.

Test vector (verified against the reference implementation):

| Input | Value |
|---|---|
| secret (ASCII) | `hysteria:alice:alice-pass` |
| token | `b4e68d9cca310616f5359d5ff5c9e82fb7e4e880a6fb83a0b0a7a1b01b6e1c70` |
| verifier | `c061fc54bb1a7534356bbe32c554c1a3985851a3d1749107b677793ffcb5ba9f` |

The library helpers (`overlay.Token`, `overlay.Verifier`, `overlay.SecretUserPass`, `overlay.SecretXray`) implement these conventions. Any secret format works as long as the client and the operator who writes the peers table use the same bytes.

### Peers table (hub input)

A JSON file read by the hub:

```json
{
  "version": 1,
  "accounts": [
    { "verifier": "c061fc54bb1a7534356bbe32c554c1a3985851a3d1749107b677793ffcb5ba9f", "name": "alice" },
    { "verifier": "d7a251289707b2f388411c5aa04961a52d12ab890b786e3a3cbdc2c04c5fca02", "name": "bob" }
  ]
}
```

Validation rules (enforced by the hub; a violation makes the whole table invalid):

- `version` must equal `1`.
- At most `4096` accounts.
- Each `verifier` is exactly 64 hex digits and unique.
- Each `name` is at most `128` bytes.
- The file is at most `4 MiB` (4194304 bytes).

The file is read-only to the hub. A writer should replace it atomically (write a temporary file, then rename over the target).

## 5. Addresses

- Overlay CIDR: `10.77.0.0/16`.
- Assignable addresses: `10.77.0.1` through `10.77.255.255`, excluding `10.77.0.0` and `10.77.255.255`. Helper: `overlay.Assignable` and `overlay_relay::assignable`.
- The hub assigns each account an address. Assignments persist in `ips.json` in the data directory (JSON object: verifier hex to IPv4 text).
- When the table reloads:
  - Accounts that keep their stored, still-assignable, unclaimed address keep it.
  - Every other account receives the lowest free assignable address, starting at `10.77.0.1`.
  - An account removed from the table loses its address, its control stream is closed, and its flows and pending requests are dropped.
- A client learns its own address from the registration reply. Do not compute it.

## 6. Transport and framing

- Transport: TCP to the hub (default `0.0.0.0:6697` on the hub side; clients connect to the hub's host and port).
- Every stream starts with a **Hello** frame sent by the client.
- **Frame**: 2-byte unsigned big-endian length `N`, then `N` bytes of UTF-8 JSON.
  - `N` must be `1 <= N <= 16384` (16 KiB). `N = 0` or `N > 16384` is a protocol error.
  - The JSON object is one message. Fields absent from a message are omitted or treated as their zero value, as described per message.
- **Datagram record** (UDP flows only): 2-byte unsigned big-endian length `N`, then `N` raw payload bytes. `0 <= N <= 65535`.
- After a flow is opened (section 8), the stream stops being framed JSON for TCP flows. Bytes flow raw in both directions. For UDP flows the stream carries datagram records.

## 7. Messages

All field names are lowercase JSON keys.

### 7.1 Hello (client to hub, first frame of every stream)

| Field | Type | Used by | Meaning |
|---|---|---|---|
| `version` | integer | all | Must be `1`. Otherwise the hub closes the stream silently. |
| `kind` | string | all | `"control"`, `"open"` or `"accept"`. Anything else gets reply `invalid request`. |
| `token` | string | all | 64 lowercase hex digits (section 4). |
| `proto` | string | open | `"tcp"` or `"udp"`. |
| `dst` | string | open | Destination overlay IPv4 text, for example `"10.77.0.2"`. |
| `port` | integer | open | Destination port, `1..65535`. `0` or absent is refused. |
| `id` | string | accept | The `id` from the Incoming event being answered. |

Optional fields that do not apply to a kind may be omitted. The hub ignores unrelated fields.

### 7.2 Reply (hub to client)

| Field | Type | Meaning |
|---|---|---|
| `ok` | bool | `true` on success. |
| `error` | string | Present when `ok` is `false`. One of the error values in section 9. |
| `ip` | string | Control only. This account's overlay address. |
| `name` | string | Control only. This account's display name from the table. |

The hub omits empty string fields. A client must treat a missing `ok` as `false`.

### 7.3 Events on a control stream (hub to client, after the registration reply)

Each event is one frame with exactly one of these top-level keys:

```json
{"peers":  [{"ip":"10.77.0.2","name":"bob"}]}
{"incoming": {"id":"<32 hex digits>","proto":"tcp","src":"10.77.0.1","port":7000}}
{"pong": true}
```

- `peers`: the full current list of **other** broadcasting accounts, sorted by IP ascending. It is sent once after registration and again on every change. Each change replaces the previous list; it is not a delta.
- `incoming`: a request that the receiving account must answer on a new accept stream (section 8.3).
- `pong`: reply to a ping (section 8.1).

### 7.4 Ping (client to hub, on a control stream)

```json
{"ping": true}
```

Any other content on a control stream ends the control stream (see section 8.1).

## 8. Stream lifecycles

### 8.1 Control stream

1. Client dials the hub, sends `Hello{version:1, kind:"control", token}`.
2. Hub replies:
   - Success: `Reply{ok:true, ip, name}`. The account is now registered. The client's address is `ip`.
   - Failure: `Reply{ok:false, error:"unauthorized"}` and the stream closes.
3. After the success reply, the hub sends `peers` events (initial list and on every change) and `incoming` events, and answers pings with `pong`.
4. The client must send `{"ping":true}` at least once per `90` seconds. The hub closes the stream if it does not receive a valid ping within that window, and also closes it on any invalid frame.
5. A second control stream for the same account replaces the first. The earlier stream is closed.
6. The reference client sends a ping every `30` seconds and treats the control stream as dead after `75` seconds without any frame from the hub.

Writes from the hub to a control stream have a `10` second write deadline. A stalled reader is disconnected.

### 8.2 Open stream (requester side)

Preconditions the hub enforces: the requester has an active control stream; the destination has an active control stream; the destination is not the requester; each side has fewer than `256` active flows; the destination has fewer than `4` pending requests.

1. Client dials the hub, sends `Hello{version:1, kind:"open", token, proto, dst, port}`.
2. The hub validates `proto`, `dst`, `port`. Any invalid value gets `Reply{ok:false, error:"peer unavailable"}`.
3. The hub looks up the destination. If the destination is missing, hidden, not connected, the requester itself, or a precondition fails, the reply is `peer unavailable`. This is intentionally identical for every case, so a requester cannot discover hidden accounts.
4. The hub sends an `incoming` event to the destination's control stream with a fresh random `id` (16 random bytes, 32 hex digits) and waits up to `10` seconds for the destination to answer.
5. On success, the hub sends `Reply{ok:true}` on the open stream and the same `Reply{ok:true}` on the destination's accept stream. Both sides then switch to relay mode (section 8.4).
6. On timeout or refusal, the open stream receives `Reply{ok:false, error:"peer unavailable"}`.

### 8.3 Accept stream (destination side)

1. The destination receives an `incoming` event `{id, proto, src, port}` on its control stream. `src` is the requester's overlay address. `port` is the destination port requested.
2. The destination dials the hub and sends `Hello{version:1, kind:"accept", token, id}`. The `id` must be the one from the event.
3. The hub pairs the stream with the pending request only if the token belongs to the destination account that was asked. Otherwise: `Reply{ok:false, error:"unauthorized"}`.
4. The accept stream waits (up to the `10` second accept timeout measured from the incoming event). When the open side is accepted, the accept stream receives `Reply{ok:true}` and switches to relay mode.
5. If the pending request expired or was refused, the accept stream is closed without a successful reply.
6. The destination then connects to its local service on `port` (for TCP, a stream; for UDP, a datagram socket). `src` is informational; the application chooses the local target. The reference `LocalDialer` dials the device's own address, so the local service sees this device as its peer, and services bound only to loopback are not reachable through it.

### 8.5 Optional flow compression (client-side, not hub)

The hub relays flow bytes unchanged, so compression is an agreement between the two agents of one flow. The reference agent enables it with `Config.Compression` (default off). The setting must match on the requester and on the destination. Otherwise the destination reads garbage.

When enabled, the bytes after the handshake use chunks:

```
kind (1 byte) | body length (uint16, big-endian) | body
kind 0: body is the plain bytes (raw)
kind 1: body is a raw DEFLATE stream that inflates to the plain bytes
```

- A writer splits plain data into chunks of at most `16384` bytes.
- A writer uses kind `1` only for chunks of at least `512` bytes whose compressed form is smaller.
- A reader rejects unknown kinds and rejects inflated output above `16384` bytes.
- The hub never sees the chunk framing. The same bytes relayed in either mode look like any other flow.

### 8.4 Relay mode

- **TCP**: raw bytes in both directions. A half-close (write shutdown) from one side is forwarded as a write shutdown to the other side. The flow ends when both directions have finished or on any I/O error. There is no hub-side idle timeout for TCP.
- **UDP**: both directions carry datagram records (section 6). The hub forwards bytes unchanged, so record boundaries are preserved by the sender's framing. The hub ends the flow after `120` seconds with no forwarded bytes in either direction. The reference client closes its UDP flow after `120` seconds idle as well.

## 9. Errors

Exact error strings in `Reply.error`:

| Value | When |
|---|---|
| `unauthorized` | Token is malformed or unknown on a control or accept stream. Accept answers this also when the id is unknown, expired, already used, or addressed to another account. |
| `peer unavailable` | Open request is invalid, destination is missing or hidden, a precondition fails, or the destination did not accept in time. |
| `invalid request` | Known token, but `kind` is not `control`, `open` or `accept`. |

A client must not show or log tokens, secrets or verifiers.

## 10. Server-side admission (what the client must satisfy)

Before reading any frame, the hub checks the **source address** of every new TCP connection:

- The hub resolves each name in its `OVERLAY_ALLOWED_HOST` list at connection time (lookup timeout `2` seconds per name). The connection is admitted only if its remote IP equals one of the resolved addresses. IPv4-mapped IPv6 addresses compare equal to their IPv4 form.
- Unresolvable names are skipped. If no name matches, the connection is closed without any reply.
- An empty allowed list admits nobody.

Consequence for a new client: the client must reach the hub from a source address that one of the allowed names resolves to. How the packet gets there (VPN tunnel, container network, host networking) is the deployer's choice.

After admission, the first frame must arrive within `10` seconds. Otherwise the connection is closed silently.

## 11. Limits and timers

| Name | Value | Owner |
|---|---|---|
| Overlay port | `6697` | hub listens |
| Max frame payload | `16384` bytes | both |
| Max datagram payload | `65535` bytes | both |
| Max accounts in table | `4096` | hub |
| Max account name | `128` bytes | hub |
| Max peers file size | `4 MiB` | hub |
| Max active flows per account | `256` | hub |
| Max pending requests per destination | `4` | hub |
| Handshake deadline (first frame) | `10` s | hub |
| Accept timeout | `10` s | hub |
| Control stream idle (no ping) | `90` s | hub |
| UDP flow idle | `120` s | hub |
| Peers file poll interval | `2` s | hub |
| Frame write deadline | `10` s | hub |
| Admission DNS lookup | `2` s per name | hub |
| Client ping interval | `30` s | reference client |
| Client liveness timeout | `75` s | reference client |
| Client handshake timeout | `10` s | reference client |
| Client reconnect backoff | `1` s doubling to `30` s; reset to `1` s after a successful registration | reference client |
| Client concurrent incoming flows | `128` | reference client |
| Client UDP idle | `120` s | reference client |

## 12. Peers table reload and hub state

- The hub reads the table at startup. A missing file or an invalid table at startup means an empty table, which admits no accounts.
- The hub polls the file every `2` seconds and reloads when the file's identity, modification time or size changes.
- A missing file at reload empties the table (all controls and flows close).
- An invalid file at reload keeps the last good table.
- A table change sends a fresh `peers` event to every affected control stream.

## 13. Reference client behavior (overlayagent)

A conforming client needs these behaviors. The Go reference implements all of them.

### 13.1 State machine

- `Run` loops forever until its context ends:
  1. Dial the hub. Send the control Hello.
  2. On `ok:false`, record the reason and back off.
  3. On success, read `ip` and `name`. Validate `ip` is assignable. If not, back off.
  4. Mark connected. Start the ping loop. Read events until error or liveness timeout.
  5. On disconnect, clear peers and back off. Reset backoff to `1` s if the registration had succeeded.
- The first successful registration publishes the address once. Other consumers can wait for it.

### 13.2 Published state

Emit a state on every change. The shape is:

```json
{
  "available": true,
  "reason": "optional, present when not connected",
  "broadcasting": true,
  "connected": true,
  "ip": "10.77.0.1",
  "name": "alice",
  "peers": [{"ip": "10.77.0.2", "name": "bob"}]
}
```

- `connected` is true only after a successful control registration.
- `peers` is empty when not connected.
- The callback must not block.

### 13.3 Outbound flow (requester)

Pre-checks before dialing (the hub is the authority; these only save round trips):

- `proto` is `tcp` or `udp`.
- Destination port is nonzero.
- Destination is inside `10.77.0.0/16` and assignable.
- Destination is not this client's own address.
- Destination is in the latest `peers` list. Otherwise return `peer unavailable` locally.

Then: dial the hub, send the open Hello, read the reply. On `ok:true` the stream is the flow (TCP) or a datagram adapter over it (UDP). On failure, close and return the hub's reason.

### 13.4 Inbound flow (destination)

- On an `incoming` event, validate: `proto` is `tcp` or `udp`; `port` nonzero; `id` nonempty; `src` assignable. Ignore invalid requests silently (do not log tokens or payloads).
- Enforce the concurrency bound (128). Drop requests over the bound.
- Dial the hub with the accept Hello. Wait for `ok:true`. Then dial the local service at `port` and relay until either side ends. For UDP, relay datagram records to the local datagram socket.

### 13.5 Local service dialing

- `DialLocal(proto, port, src)` is supplied by the application. The reference client does not choose a host.
- A service bound only to loopback is reachable only if the application dials loopback. Choose the target carefully.

### 13.6 Readiness probe

`overlayagent.Probe(ctx, address)` proves that a hub admits this source and parses frames without any real account:

1. Dial the hub.
2. Send `Hello{version:1, kind:"control", token:"000...0"}` (64 zeros).
3. Expect `Reply{ok:false, error:"unauthorized"}`.

Use it as a health check. Any other reply means a misconfigured hub or an unexpected source.

## 14. Building a client in another language

Implement, in order, and test each step against the Rust hub (section 15):

1. **Secret to token**: HMAC-SHA256 with the label from section 4. Check against the test vector.
2. **Verifier**: SHA-256 of the token's raw 32 bytes. Check against the test vector.
3. **Framing**: 2-byte big-endian length plus JSON. Reject `0` and `> 16384`.
4. **Control stream**: Hello, read Reply, store `ip` and `name`. Then loop: read events, send a ping every 30 s, drop the connection after 75 s without frames.
5. **Peers**: replace the list on each `peers` event. Filter your own address out if it appears.
6. **Outbound TCP**: open stream with Hello `kind:"open"`. On `ok:true`, pipe bytes raw. Propagate half-close.
7. **Outbound UDP**: after `ok:true`, send and receive datagram records (2-byte length + payload).
8. **Inbound**: handle `incoming`, open an accept stream with the `id`, wait for `ok:true`, then pipe to the local service.
9. **Reconnect**: exponential backoff from 1 s to 30 s. Reset after a successful registration.
10. **Probe**: implement section 13.6 as a health check.

Keep these rules in any port:

- Never send the secret. Never log tokens, secrets, or verifiers.
- Do not rely on any field beyond those listed in section 7.
- Treat unknown events as ignorable, but treat a malformed frame as a dead stream.
- Keep frame writes under a deadline so a stalled hub cannot pin a task.

## 15. Testing and verification

Run from the repository root with the workspace file (`go.work`):

```text
cd server && cargo test
cd server && cargo clippy --all-targets -- -D warnings
cd client && go test -race ./...
cd tests && go test -race -count=1 ./...
cd examples && go vet ./...
```

- `server/tests/hub.rs` runs the hub over real loopback TCP and UDP: admission, auth, accept, pending cap, idle timeouts, peers reload, address stability.
- `tests/` builds the hub with cargo, starts it as a process, and connects two Go agents to it. It verifies registration, peers, a TCP round trip, and refusal of an unknown address.

To run the hub by hand:

```text
OVERLAY_ALLOWED_HOST=<name-that-resolves-to-your-client> \
OVERLAY_PEERS_PATH=./peers.json \
OVERLAY_DATA_DIR=./data \
OVERLAY_LISTEN_ADDRESS=127.0.0.1:6697 \
./server/target/release/overlay-hub
```

Generate a peers table from secrets:

```text
cd examples && go run ./peers alice=hysteria:alice:alice-pass bob=xray:bob-secret > ./peers.json
```

## 16. Hub configuration

| Variable | Meaning | Required |
|---|---|---|
| `OVERLAY_ALLOWED_HOST` | Comma-separated host names whose addresses may connect. Empty entries are dropped. | Yes; empty fails startup |
| `OVERLAY_PEERS_PATH` | Path to the peers table. | Recommended |
| `OVERLAY_DATA_DIR` | Directory for `ips.json`. Must be writable. | Recommended |
| `OVERLAY_LISTEN_ADDRESS` | Bind address. Default `0.0.0.0:6697`. | No |

Without `OVERLAY_PEERS_PATH` and `OVERLAY_DATA_DIR`, the binary uses built-in defaults (constants in `server/src/main.rs`). Set both explicitly in any new deployment. The container image sets them (section 17).

The hub logs with `tracing`. It never logs tokens, verifiers, payloads or peer names.

## 17. Container

- `Dockerfile` at the repository root builds the hub from `server/` with `cargo build --release --locked`.
- Runtime image: distroless `cc-debian12:nonroot`, user `65532`, entrypoint `/usr/local/bin/overlay-hub`.
- Defaults set in the image: `OVERLAY_PEERS_PATH=/etc/overlay-relay/peers.json`, `OVERLAY_DATA_DIR=/var/lib/overlay-relay`, `OVERLAY_LISTEN_ADDRESS=0.0.0.0:6697`.
- Mount the peers table as a **directory** (for example `/etc/overlay-relay`), not as a single file. The hub watches for replacement by rename, which a single-file bind mount does not see.
- The data directory must be writable by uid `65532`.
- Expose `6697/tcp`.

## 18. Security properties

- Authentication is a bearer token with a stored SHA-256 verifier. Compare-by-verifier is constant-time across stored entries.
- Admission by source address is a first gate; the token is the second.
- The hub returns the same `peer unavailable` for missing, hidden, self, and refused destinations. A requester cannot enumerate accounts.
- The hub does not interpret relayed payloads.
- Tokens and secrets are never logged by the reference code.

## 19. Non-goals

- The hub does not encrypt traffic. Confidentiality and integrity of relayed bytes come from the transport the deployer places underneath (for example, a VPN tunnel).
- The hub does not route to the internet or to addresses outside `10.77.0.0/16`.
- The hub has no accounting or quotas beyond the flow and pending limits in section 11.
- No version negotiation beyond `version: 1`. A new wire version requires a new `version` value and a coordinated release.

## 20. Release and versioning

- The hub and the Go module share one release version: the `version` field in `server/Cargo.toml`.
- Go module tags follow the same version as `client/vX.Y.Z`, where `X.Y.Z` matches `server/Cargo.toml`.
- The wire version is separate (`version: 1`). It changes only on incompatible wire changes.
