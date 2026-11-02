# Overlay hub

Base: `server/` (crate `overlay-relay`, binary `overlay-hub`).
Client counterpart: [client](client.md).
The snoo-box server manager owns the container lifecycle and writes the peers table.
The [wire contract](../client/overlay/overlay.go) owns frames, datagram records, the address space and token derivation.

The hub is an authenticated rendezvous and byte relay between VPN accounts of one managed server that chose to broadcast.
`overlay-hub` runs it inside its container. The readiness probe is `server-helper overlay-probe <host:port>` in snoo-box, built on `client/overlayagent.Probe`.
The hub never learns credentials: it stores only verifiers, `overlay.Verifier(token)`, and a client proves an account by sending the token it derived from its native credential.

## Inputs

- `OVERLAY_ALLOWED_HOST` is a comma-separated list of engine container names and is required.
- `/etc/snoo-box-overlay/peers.json` is the read-only `overlay.Peers` table written by the manager.
- `/var/lib/snoo-box-overlay` is the only writable path and holds `ips.json`.

## Admission

The hub resolves every allowed host through Docker DNS on each connection and compares the connection's source address with the result.
A source that is not an allowed engine container is closed before any frame is read.
With no resolvable trusted host the hub fails closed.
The container never publishes `6697/tcp` to the host: it is reachable only through `snoo-box-network`.
Source admission still closes any source that is not an allowed engine container.

## Peers table and addresses

The table is polled every two seconds and re-read when its modification time or size changes.
New content is validated first, and invalid content keeps the last good table.
An account removed from the table loses its control stream and all of its relayed flows within one poll.
Every listed account, hidden or not, receives one stable address from `overlay.CIDR`, allocated from `10.77.0.1` with `overlay.Assignable`.
Allocations are written atomically with mode `0600` to `ips.json` keyed by verifier, are not reused while the account exists and are freed when it is removed.

## Protocol

The client sends a `Hello` within 10 seconds, and every frame it reads is bounded by `overlay.MaxFrame` (16 KiB on the wire).
The hub computes the verifier of the token, looks it up with a constant-time comparison and answers an unknown token with `unauthorized` before closing.

- `control` registers the account as broadcasting and replies with its address and name.
  A new control stream for the same account replaces and closes the old one.
  The hub pushes a full `Peers` snapshot of the other broadcasting accounts to every control stream whenever the broadcasting set changes, and answers `Ping` with `Pong`.
  A control stream without a ping for 90 seconds is closed.
- `open` requires that the requester has a control stream and that the destination address belongs to another broadcasting account.
  The hub then pushes an `Incoming` event with a random 128-bit identifier to the destination and waits up to 10 seconds for its `accept` stream.
  Both streams then receive `ok` and are spliced: TCP with half-close, and UDP as raw datagram records, which preserves framing.
  An unknown address, a hidden account, the requester itself, a missing accept and a requester that is not broadcasting all receive the identical `unavailable` reply.
- `accept` must carry the destination's token and a pending identifier, and each identifier is accepted once.
  Anything else receives `unauthorized`.

`open` and `accept` may carry an offer: `fingerprint` (64 hex digits, the SHA-256 of the agent's flow certificate) and `endpoint` (a public `ip:port`).
A malformed offer, an endpoint without a fingerprint, port zero and an unspecified or multicast address are refused with `invalid request`, and a refused `accept` leaves the pending request claimable.
The `Incoming` event repeats the requester's offer. Each success reply then follows the two offers:

- Both sent a fingerprint: `secure` is true and the reply carries the other side's `fingerprint`. The flow is still spliced.
- Both also sent an endpoint: `direct` is true, and the reply carries the flow `id` and the other side's `endpoint`. The hub sends the replies, relays nothing and closes both streams.
- Otherwise the reply is a plain `ok`, as before.

The hub only forwards the offers. Agents authenticate each other by the fingerprint, so anyone who watches or alters the network, and a hub that only relays, sees nothing but ciphertext. The fingerprints themselves travel through the hub, so a hub that replaces them can still intercept a flow. Run a hub you trust.

Hidden accounts never appear in a `Peers` event, an error or a log line, and an account without a control stream can neither open nor accept.

## Limits

An account has at most 256 concurrent relayed flows, and a destination has at most four pending incoming requests.
An idle UDP flow closes after two minutes, and TCP has no idle limit.
A control stream whose outgoing queue is full is dropped rather than blocking the hub.
Logs contain only counts and errors at DEBUG, never tokens, verifiers, payloads or names.

## Verification

The tests use `net.Pipe` and loopback TCP with an injected resolver and no Docker.
They cover authentication failure, admission, broadcast listing, hidden-account probing, error identity, TCP and UDP splices, control replacement, account removal closing flows and address stability across restart.
