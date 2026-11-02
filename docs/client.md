# Overlay client agent

Base: `client/overlayagent/` and `client/overlay/` in the overlay-relay repository.
The snoo-box client glue (tunnel start, route exclusion, Xray routing, account secret, connection state) is documented in [snoo-box overlay client](https://github.com/ParkSnoopy/snoo-box/blob/main/docs/app/backend/client/overlay/ARCHITECTURE.md).

## Agent

[agent.go](../client/overlayagent/agent.go) and [flow.go](../client/overlayagent/flow.go) hold the platform-independent agent.
The platform supplies `Dial` (one hub stream through the VPN session), `DialLocal` (where an incoming flow ends) and `OnState`.
`Run` dials the hub, sends `Hello{control}` with the derived token and tracks the reply, peer snapshots, incoming requests and pongs.
It pings every 30 seconds, treats 75 seconds without any frame as a dead hub, and reconnects with capped exponential backoff from 1 to 30 seconds while its context lives.
Every change calls `OnState` with `Available`, `Broadcasting` and `Connected`; a rejected account carries the hub's short reason.
`Ready` delivers the overlay address once at the first registration and `IP` returns the latest address.
`Run` returns after every goroutine it started has stopped.

For each incoming request the agent opens a new stream with `Hello{accept, id}`, requires an OK reply, calls `DialLocal` and splices.
TCP is a bidirectional copy with half-close, and an aborted direction closes both ends.
UDP carries one datagram per record on the hub side and one per Read or Write on the local side, with a two-minute idle timeout per flow.
At most 128 incoming flows run at once, and malformed requests are dropped without a hub round trip.

`Outbound` opens a flow to a peer with `Hello{open}` and returns the stream after an OK reply.
A UDP flow exposes one datagram per Read and Write and keeps partial records across read deadlines.
It refuses addresses outside `overlay.CIDR`, the agent's own address and addresses missing from the last peer snapshot before touching the hub, which stays the authority.
Tokens, secrets and payloads never enter logs.

## Checks

- Run `go test -race ./...` from `client/`; the agent tests use an in-process hub speaking the wire contract and covers registration, peers, TCP and UDP flows, refusals, concurrency bounds, reconnects, backoff, cancellation and goroutine leaks.
- Run `go test -race -count=1 ./...` from `tests/` for the Go agent against the Rust hub; it builds `server/` with cargo.
- Integration with the real hub and routed traffic on each platform is a separate acceptance step.
