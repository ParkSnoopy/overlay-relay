# Overlay Relay: Developer Wiki for Building a Client

This document is written so that an agent with no prior knowledge can build a new client application that joins the overlay network. It is the complete contract: identity, addressing, wire format, message semantics, timing, limits, error values, and client behavior. Everything needed to interoperate with the hub is here. Implementation details of the hub are included only where a client must know them.

Where this document and the code disagree, the code in `server/` (hub) and `client/` (Go reference agent) is the reference. The Go agent in `client/overlayagent` is a complete, tested client; a new client in another language should mirror it.

## 1. What the system does

- A **hub** (Rust binary `overlay-hub`, source in `server/`) is reachable over TCP on port `6697`.
- Each **peer** holds one stable private IPv4 address in `10.77.0.0/16`. A peer is a client key pair that the client generated itself; nobody enrolls it.
- A **client** that "broadcasts" registers a **control stream** with the hub. The hub then tells it which other broadcasting peers exist (`peers`).
- A client opens a **flow** (TCP or UDP) to a peer's overlay address and port. The hub asks the peer to accept, pairs the two streams, and relays bytes between them.
- The hub never inspects payload bytes after the handshake. It forwards them unchanged.
- Agents encrypt flows end to end by default (section 8.6) and may connect directly, bypassing the hub (section 8.7). The hub only forwards the offers.
- Agents may optionally compress flow bytes (section 8.5). The hub is unaware of it.
- Hidden peers (not broadcasting) hold an address but never register a control stream, so they are never listed and cannot be reached.

## 2. Glossary

| Term | Meaning |
|---|---|
| Hub | The server process. Accepts TCP connections, authenticates them, and relays. |
| Peer | One client identity, identified by its public key. Has a derived display name and an overlay address. |
| Private key | Persistent client-side P-384 identity key. Never sent to the hub. |
| Public key | Uncompressed P-384 point the client presents and proves it holds. |
| Verifier | SHA-256 of the 97-byte public key, used internally as the peer identifier. |
| Control stream | Long-lived TCP connection that registers a broadcasting account and receives events. |
| Open stream | TCP connection that requests a flow to a peer. |
| Accept stream | TCP connection the destination peer opens to answer an incoming request. |
| Flow | A relayed TCP or UDP conversation between two accounts. |
| Incoming | Event on a control stream asking the destination to open an accept stream. |

## 3. Repository layout

```
server/            Rust hub crate "overlay-relay", binary "overlay-hub"
  src/main.rs      reads environment, runs the hub
  src/lib.rs       library API (Hub, Config, Verifier, frame helpers)
  src/protocol.rs  wire constants and message types
  tests/hub.rs     integration tests over real loopback sockets
client/            Go module github.com/ParkSnoopy/overlay-relay/client
  overlay/         wire types, frame codec, identity helpers
  overlayagent/    reference agent: registration, peers, outbound and inbound flows, probe
tests/             Go tests that run the Rust hub and the Go agent together
examples/          Go program: a client
docs/              this wiki, server and client notes, release gate
Dockerfile         builds the server image
```

## 4. Identity: P-384 key pairs

Generate one P-384 key pair on each client. Persist the private key securely and reuse it across connections. The hub needs no enrollment: the public key in the Hello, together with a valid signature of the challenge, is the identity. The Go helpers provide PKCS#8 PEM encoding and parsing. The hub identifies the peer by SHA-256 of the 97 raw uncompressed public-key bytes. The same key is always the same peer, and a client that loses its key becomes a new peer.

Every hub stream must traverse an authenticated VPN. The challenge authenticates the client to the hub, not the hub to the client. It does not protect a connection from an active intermediary. The caller and deployment must enforce the VPN boundary.

### Identity table (hub state)

The hub keeps every key it has verified in `ips.json` in its data directory: verifier hex mapped to an object with the peer's `ip` and `seen` (Unix seconds of its last authentication or disconnect). No operator writes this file. The hub rewrites it atomically with mode `0600`.

- At most `4096` peers. When the table is full, a new key takes over the address of the peer with the oldest `seen` that has no control stream and no flow. When every peer is in use, the new key is refused with `unauthorized`.
- The default display name of a peer is `peer-` followed by the first 8 hex digits of its verifier. An authenticated control Hello may advertise its own name, up to 128 Unicode characters without control characters or surrounding whitespace. Empty or absent restores the default. Names are transient, never written to `ips.json`, and do not change identity or address.
- A file written by an older hub (verifier hex mapped to a bare address) loads, and each entry counts as seen at load time. A corrupt file stops the hub rather than renumbering peers.

## 5. Addresses

- Overlay CIDR: `10.77.0.0/16`.
- Assignable addresses: `10.77.0.1` through `10.77.255.255`, excluding `10.77.0.0` and `10.77.255.255`. Helper: `overlay.Assignable` and `overlay_relay::assignable`.
- The hub assigns each peer an address when its key first proves possession. Assignments persist in `ips.json` in the data directory (JSON object: verifier hex to `{ip, seen}`).
- A known peer keeps its address. A new peer receives the lowest free assignable address, starting at `10.77.0.1`.
- A peer loses its address only by eviction from a full table (section 4).
- A client learns its own address from the registration reply. Do not compute it.

## 6. Transport and framing

- Transport: TCP through an authenticated VPN to the hub (default `0.0.0.0:6697` on the hub side). The overlay does not enforce the VPN.
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
| `version` | integer | all | Must be `2`. Otherwise the hub closes the stream silently. |
| `kind` | string | all | `"control"`, `"open"` or `"accept"`. Anything else gets reply `invalid request`. |
| `public_key` | string | all | Hex-encoded uncompressed P-384 public key (section 4). |
| `name` | string | control | Optional advertised name for the authenticated device. Empty uses the identity-derived default; invalid names receive `invalid request` without replacing an existing control. |
| `proto` | string | open | `"tcp"` or `"udp"`. |
| `dst` | string | open | Destination overlay IPv4 text, for example `"10.77.0.2"`. |
| `port` | integer | open | Destination port, `1..65535`. `0` or absent is refused. |
| `id` | string | accept | The `id` from the Incoming event being answered. |
| `fingerprint` | string | open, accept | Offer of end-to-end encryption: the SHA-256 of the sender's flow certificate, 64 hex digits (any case; the hub lowercases it). |
| `endpoint` | string | open, accept | Offer of a direct connection: the sender's public UDP address `ip:port`. Valid only with a `fingerprint`. Port `0`, unspecified and multicast addresses are refused. |

A malformed or inconsistent offer (bad fingerprint, bad endpoint, endpoint without fingerprint) gets `Reply{ok:false, error:"invalid request"}`. A refused `accept` leaves the pending request claimable.

Optional fields that do not apply to a kind may be omitted. The hub ignores unrelated fields.

After a valid Hello, the hub sends `{"nonce":"<hex>"}` with 32 random bytes. The client signs the UTF-8 bytes `overlay-relay/auth/v2:` followed by the raw nonce using ECDSA P-384 with SHA-384. It sends `{"signature":"<hex>"}` with the ASN.1 DER signature. The hub verifies the proof before issuing the reply; a valid proof of any key is accepted, and a key seen for the first time receives an address. A malformed public key can receive an unauthorized reply without a challenge.

### 7.2 Reply (hub to client)

| Field | Type | Meaning |
|---|---|---|
| `ok` | bool | `true` on success. |
| `error` | string | Present when `ok` is `false`. One of the error values in section 9. |
| `ip` | string | Control only. This account's overlay address. |
| `name` | string | Control only. This peer's display name, derived from its key. |
| `secure` | bool | Open and accept only. Both sides offered a fingerprint (section 8.6). |
| `fingerprint` | string | Secure only. The other side's flow certificate fingerprint, lowercase. |
| `direct` | bool | Open and accept only. Both sides also offered an endpoint (section 8.7). |
| `id` | string | Direct only. The flow identifier, equal to the `id` of the Incoming event. |
| `endpoint` | string | Direct only. The other side's public UDP address. |

The hub omits empty string fields and false booleans. A client must treat a missing `ok` as `false`.

### 7.3 Events on a control stream (hub to client, after the registration reply)

Each event is one frame with exactly one of these top-level keys:

```json
{"peers":  [{"ip":"10.77.0.2","name":"bob"}]}
{"incoming": {"id":"<32 hex digits>","proto":"tcp","src":"10.77.0.1","port":7000}}
{"pong": true}
```

- `peers`: the full current list of **other** broadcasting accounts, sorted by IP ascending. It is sent once after registration and again on every change. Each change replaces the previous list; it is not a delta.
- `incoming`: a request that the receiving account must answer on a new accept stream (section 8.3). It also carries the requester's `fingerprint` and `endpoint` when the requester made those offers.
- `pong`: reply to a ping (section 8.1).

### 7.4 Ping (client to hub, on a control stream)

```json
{"ping": true}
```

Any other content on a control stream ends the control stream (see section 8.1).

## 8. Stream lifecycles

### 8.1 Control stream

1. Client dials through the authenticated VPN, sends `Hello{version:2, kind:"control", public_key}`, and completes the challenge exchange.
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

1. Client dials through the authenticated VPN, sends `Hello{version:2, kind:"open", public_key, proto, dst, port}`, and completes the challenge exchange.
2. The hub validates `proto`, `dst`, `port`. Any invalid value gets `Reply{ok:false, error:"peer unavailable"}`.
3. The hub looks up the destination. If the destination is missing, hidden, not connected, the requester itself, or a precondition fails, the reply is `peer unavailable`. This is intentionally identical for every case, so a requester cannot discover hidden accounts.
4. The hub sends an `incoming` event to the destination's control stream with a fresh random `id` (16 random bytes, 32 hex digits) and waits up to `10` seconds for the destination to answer.
5. On success, the hub sends a success reply on the open stream and one on the destination's accept stream. The replies follow the two offers (sections 8.6 and 8.7). Without a common offer both are plain `Reply{ok:true}`. Both sides then switch to relay mode (section 8.4), unless the flow is direct.
6. On timeout or refusal, the open stream receives `Reply{ok:false, error:"peer unavailable"}`.

### 8.3 Accept stream (destination side)

1. The destination receives an `incoming` event `{id, proto, src, port}` on its control stream. `src` is the requester's overlay address. `port` is the destination port requested.
2. The destination dials through the authenticated VPN, sends `Hello{version:2, kind:"accept", public_key, id}`, and completes the challenge exchange. The `id` must be the one from the event.
3. The hub pairs the stream with the pending request only if the authenticated identity belongs to the destination account that was asked. Otherwise: `Reply{ok:false, error:"unauthorized"}`.
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
- Compression sits inside encryption: the agent compresses first, then encrypts (sections 8.6 and 8.7).

### 8.6 End-to-end encryption (client-side, default on)

The reference agent encrypts every flow unless `Config.DisableEncryption` is set.

1. The agent makes one self-signed ECDSA P-256 certificate per instance. Its fingerprint is the lowercase hex SHA-256 of the DER certificate.
2. The requester puts `fingerprint` in its `open` Hello. The destination reads it from the `incoming` event and puts its own in its `accept` Hello.
3. If both offered, the hub marks both success replies `secure:true` and gives each side the other's fingerprint. If either did not, neither reply is secure.
4. Right after the success reply, the requester runs a TLS 1.3 client handshake and the destination a TLS 1.3 server handshake over the stream. ALPN is `overlay-relay/flow-1` and the server name is `overlay-relay`. Both sides present their certificate and require the peer's (`RequireAnyClientCert`). Each side accepts exactly one certificate: the one whose SHA-256 equals the fingerprint the hub reported. Chain and name checks do not apply.
5. A handshake failure closes the stream. TCP flows carry the application bytes inside TLS. UDP flows carry their datagram records inside TLS.
6. An agent with encryption on treats a success reply without `secure:true` as a failure. It never falls back to plaintext. An agent with encryption off sends no fingerprint, so a flow with an encrypting peer fails on the peer's side.

Trust: the fingerprints reach each agent through the hub. A relaying hub and a network observer see only ciphertext, but a hub that substitutes fingerprints can intercept a flow.

### 8.7 Direct connection (client-side, opt-in)

The reference agent builds a direct link to a peer when `Config.Direct` is set and encryption is on. The hub takes no part: the agents negotiate over an encrypted relayed flow, and the hub never sees an endpoint. Agents send no `endpoint` offer. The hub still accepts and pairs one for compatibility, but no reference agent uses it.

A link is one authenticated, encrypted, multiplexed path to one peer. Every flow is one stream on it. A flow that opens while no link exists uses the relay from its first byte, so traffic never waits for traversal. Flows that open after the link is up use it. Flows already open stay on the relay.

1. The first relayed flow to a peer starts a negotiation in the background, unless direct is denied for that device or failed less than five minutes ago. The requester opens a relayed TCP flow to the reserved port `65535` (`overlay.LinkPort`). The destination agent answers that port itself; no local service sees it. The flow is sealed as in section 8.6, so both flow certificates are pinned. An agent that cannot negotiate closes it, and the requester records `unavailable`.
2. Each message on that flow is one length-prefixed JSON frame. `hello` carries the sender's methods in preference order, and the requester tries the methods both sides share, in its own order, until one works. The defaults are `webrtc`, `ice` and `libp2p`.
3. For each method the requester sends `offer`, and the destination answers with `answer` after it has gathered its candidates (at most 3 s). The requester sends `sync`. Both sides then connect for at most `DirectOptions.Timeout` (default 10 s). A method that needs both sides to start together (`libp2p`) first measures the round trip with `ping` and `pong`, and the requester delays its own start by half of it. On success the requester sends `done`. On failure it sends `next` and tries the next method, or `end` when none is left. All attempts failing is `failed`, and the peer is not offered a link again for five minutes.
4. `webrtc`: a Pion WebRTC peer connection with one detached data channel. The offer and answer are SDP with all candidates, gathered through the STUN servers of `DirectOptions.STUNServers`. DTLS secures the channel and a yamux session multiplexes the flows. The SDP travels over the pinned flow, so the DTLS fingerprints are authentic.
5. `ice`: a bare Pion ICE agent. The offer and answer carry the ICE credentials and candidates. Over the nominated pair, QUIC with ALPN `overlay-relay/direct-1` runs between the two flow certificates, pinned as in section 8.6. The requester is the QUIC client.
6. `libp2p`: a libp2p host with the QUIC transport and no relay. It listens on one UDP socket from `DirectOptions.ListenPacket` and learns that socket's public mapping from the STUN servers. The offer and answer carry a random per-attempt peer ID and addresses, which are that mapping and the interface addresses. The host accepts only the named peer ID. After `sync` both hosts dial each other, once per second, until a connection forms in either direction. This replaces the circuit relay that libp2p's DCUtR would use to coordinate its hole punch.
7. Every stream starts with a three-byte header: protocol (`1` TCP, `2` UDP) and the destination port in big-endian order. After that it carries the flow bytes exactly as a relayed flow would, so UDP flows use datagram records and compression, if enabled, sits on top.
8. A link ends when its multiplexer closes or ICE reports failure, when the peer leaves or changes identity, when the hub connection drops, or when the device is added to the relay-only list. The next relayed flow then starts a new negotiation, unless the device is denied.

All sockets must bypass the VPN (`DirectOptions.ListenPacket`). Only IPv4 UDP is used.
When both NATs use endpoint-dependent mappings with strict filtering, when UDP is blocked, or when hairpinning is missing, every method fails and flows keep the encrypted relay.
The hub's version-2 frames are unchanged.

### 8.4 Relay mode

- **TCP**: raw bytes in both directions. A half-close (write shutdown) from one side is forwarded as a write shutdown to the other side. The flow ends when both directions have finished or on any I/O error. There is no hub-side idle timeout for TCP.
- **UDP**: both directions carry datagram records (section 6). The hub forwards bytes unchanged, so record boundaries are preserved by the sender's framing. The hub ends the flow after `120` seconds with no forwarded bytes in either direction. The reference client closes its UDP flow after `120` seconds idle as well.

## 9. Errors

Exact error strings in `Reply.error`:

| Value | When |
|---|---|
| `unauthorized` | Public key or proof is malformed or invalid, or the identity table is full of active peers. Accept answers this also when the id is unknown, expired, already used, or addressed to another account. |
| `peer unavailable` | Open request is invalid, destination is missing or hidden, a precondition fails, or the destination did not accept in time. |
| `invalid request` | Authenticated identity, but `kind` is not `control`, `open` or `accept`. |

A client must not show or log private keys or account identifiers.

## 10. Server-side admission (what the client must satisfy)

Before reading any frame, the hub checks the **source address** of every new TCP connection:

- The hub resolves each name in its `OVERLAY_ALLOWED_HOST` list at connection time (lookup timeout `2` seconds per name). The connection is admitted only if its remote IP equals one of the resolved addresses. IPv4-mapped IPv6 addresses compare equal to their IPv4 form.
- Unresolvable names are skipped. If no name matches, the connection is closed without any reply.
- An empty allowed list (`OVERLAY_ALLOWED_HOST` unset) admits every source whose address is loopback, private (`10/8`, `172.16/12`, `192.168/16`), link-local or unique-local, and closes any other source.

The client must reach the hub from an allowed source address over an authenticated VPN. Source-address admission alone does not authenticate the transport.

After admission, the first frame must arrive within `10` seconds. Otherwise the connection is closed silently.

## 11. Limits and timers

| Name | Value | Owner |
|---|---|---|
| Overlay port | `6697` | hub listens |
| Max frame payload (wire) | `16384` bytes | both (readers) |
| Usable frame payload (writers) | `16256` bytes = 16384 − `SAFETY_SPACE` (128) | both (writers) |
| Max datagram payload (wire) | `65535` bytes | both (readers) |
| Usable datagram payload (writers) | `65407` bytes = 65535 − 128 | both (writers) |
| Max peers (identities) | `4096` | hub |
| Max active flows per account | `256` | hub |
| Max pending requests per destination | `4` | hub |
| Handshake deadline (first frame) | `10` s | hub |
| Accept timeout | `10` s | hub |
| Control stream idle (no ping) | `90` s | hub |
| UDP flow idle | `120` s | hub |
| Frame write deadline | `10` s | hub |
| Admission DNS lookup | `2` s per name | hub |
| Client ping interval | `30` s | reference client |
| Client liveness timeout | `75` s | reference client |
| Client handshake timeout | `10` s | reference client |
| Client reconnect backoff | `1` s doubling to `30` s; reset to `1` s after a successful registration | reference client |
| Client concurrent incoming flows | `128` | reference client |
| Client UDP idle | `120` s | reference client |

## 12. Hub state

- The hub loads `ips.json` at startup. A missing file means no peers yet.
- A peer is created, or its `seen` time refreshed, when a connection proves possession of its key. The file is rewritten when it changes.
- A peer connecting or disconnecting sends a fresh `peers` event to every control stream.

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

- On an `incoming` event, validate: `proto` is `tcp` or `udp`; `port` nonzero; `id` nonempty; `src` assignable. Ignore invalid requests silently (do not log private keys or payloads).
- Enforce the concurrency bound (128). Drop requests over the bound.
- Dial the hub with the accept Hello. Wait for `ok:true`. Then dial the local service at `port` and relay until either side ends. For UDP, relay datagram records to the local datagram socket.

### 13.5 Local service dialing

- `DialLocal(proto, port, src)` is supplied by the application. The reference client does not choose a host.
- A service bound only to loopback is reachable only if the application dials loopback. Choose the target carefully.

### 13.6 Readiness probe

`overlayagent.Probe(ctx, address)` proves that a hub admits this source and parses frames without registering a peer:

1. Dial the hub.
2. Send a version 2 control Hello with a malformed public key (`00`). The hub refuses it before any challenge, so no peer is created.
3. Expect `Reply{ok:false, error:"unauthorized"}`. Route the probe through the authenticated VPN.

Use it as a health check. Any other reply means a misconfigured hub or an unexpected source.

### 13.7 Local path observations

The reference agent projects `DirectAllowed` from this session's global direct setting and per-device deny list, not from reachability probes.
`DirectStatus` describes the latest actual direct attempt: `connecting`, `succeeded`, `failed`, `unavailable` or `canceled`.
`LastPath` records only an established `direct` or `relay` transport; live `DirectFlows` and `RelayFlows` remain separate current-flow counts.
Retain failed-attempt evidence through relay fallback and flow closure, but clear observations on peer departure, identity replacement and control disconnection.
These are local fields, not part of hub peer snapshots or evidence that a remote device permits direct connections.

## 14. Building a client in another language

Implement, in order, and test each step against the Rust hub (section 15):

1. **Identity**: Generate and securely persist a P-384 key pair. Nothing is enrolled.
2. **Authentication**: Sign the fresh challenge as specified in section 7.1 on each hub stream.
3. **Framing**: 2-byte big-endian length plus JSON. Reject `0` and `> 16384`.
4. **Control stream**: Hello, read Reply, store `ip` and `name`. Then loop: read events, send a ping every 30 s, drop the connection after 75 s without frames.
5. **Peers**: replace the list on each `peers` event. Filter your own address out if it appears.
6. **Outbound TCP**: open stream with Hello `kind:"open"`. On `ok:true`, pipe bytes raw. Propagate half-close.
7. **Outbound UDP**: after `ok:true`, send and receive datagram records (2-byte length + payload).
8. **Inbound**: handle `incoming`, open an accept stream with the `id`, wait for `ok:true`, then pipe to the local service.
9. **Reconnect**: exponential backoff from 1 s to 30 s. Reset after a successful registration.
10. **Probe**: implement section 13.6 as a health check.

Keep these rules in any port:

- Never send or log the private key. Never log peer identifiers.
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

- `server/tests/hub.rs` runs the hub over real loopback TCP and UDP: admission, auth, accept, pending cap, idle timeouts, address stability and eviction.
- `tests/` builds the hub with cargo, starts it as a process with no configuration, and connects two Go agents to it. It verifies registration without enrollment, peers, a TCP round trip, and refusal of an unknown address.

To run the hub by hand:

```text
OVERLAY_DATA_DIR=./data \
OVERLAY_LISTEN_ADDRESS=127.0.0.1:6697 \
./server/target/release/overlay-hub
```

```

## 16. Hub configuration

| Variable | Meaning | Required |
|---|---|---|
| `OVERLAY_ALLOWED_HOST` | Comma-separated host names whose addresses may connect. Empty entries are dropped. | No; unset admits every private-network source |
| `OVERLAY_DATA_DIR` | Directory for `ips.json`. Must be writable. | No; default `/var/lib/overlay-relay` |
| `OVERLAY_LISTEN_ADDRESS` | Bind address. Default `0.0.0.0:6697`. | No |

Every variable is optional: the hub runs with none of them set.

The hub logs with `tracing`. It never logs private keys, identifiers, payloads or peer names.

## 17. Container

- `Dockerfile` at the repository root builds the hub from `server/` with `cargo build --release --locked`.
- Build image: `rust:1-slim`, target `x86_64-unknown-linux-musl`, static binary.
- Runtime image: `debian:13-slim`, user `65532`, entrypoint `/usr/local/bin/overlay-hub`.
- Defaults set in the image: `OVERLAY_DATA_DIR=/var/lib/overlay-relay`, `OVERLAY_LISTEN_ADDRESS=0.0.0.0:6697`.
- The data directory must be writable by uid `65532`.
- Make `6697/tcp` reachable through the authenticated VPN, not directly from an untrusted network.

## 18. Security properties

- Authentication verifies a fresh P-384 signature of the presented public key. It proves possession only; whoever reaches the hub through the VPN can join with a new key.
- Admission by source address is a first gate; the signed challenge is the second. An authenticated VPN is required independently.
- The hub returns the same `peer unavailable` for missing, hidden, self, and refused destinations. A requester cannot enumerate peers.
- The hub does not interpret relayed payloads.
- Flows are end-to-end encrypted by default (section 8.6). A relaying hub and a network observer see only ciphertext. Fingerprints travel through the hub, so a hub that substitutes them can intercept a flow; the hub is a trusted party for fingerprints, not for payloads it relays honestly.
- A direct link leaves the VPN. Every method pins the same flow certificates, so it is authenticated and encrypted. It exposes the agent's public UDP address to the peer and the STUN servers.
- Private identity keys are never logged by the reference code.

## 19. Non-goals

- The hub does not encrypt traffic itself and holds no private identity keys. Encryption is the agents' job (section 8.6). Hub-to-agent control frames are not encrypted by the overlay; an authenticated VPN must protect that transport.
- No hub-side tracking of direct links, no TURN relay (the hub relay is the fallback), no certificate authority, and no STUN server in the hub.
- The hub does not route to the internet or to addresses outside `10.77.0.0/16`.
- The hub has no accounting or quotas beyond the flow and pending limits in section 11.
- No version negotiation beyond `version: 2`. A new wire version requires a new `version` value and a coordinated release.

## 20. Release and versioning

- The hub and the Go module share one release version: the `version` field in `server/Cargo.toml`.
- Go module tags follow the same version as `client/vX.Y.Z`, where `X.Y.Z` matches `server/Cargo.toml`.
- The wire version is separate (`version: 2`). It changes only on incompatible wire changes.
