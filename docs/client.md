# Overlay client agent

Base: `client/overlayagent/` and `client/overlay/` in the overlay-relay repository.
The snoo-box client glue (tunnel start, route exclusion, Xray routing and connection state) is documented in [snoo-box overlay client](https://github.com/ParkSnoopy/snoo-box/blob/main/docs/app/backend/client/overlay/ARCHITECTURE.md).

## Agent

[agent.go](../client/overlayagent/agent.go) and [flow.go](../client/overlayagent/flow.go) hold the platform-independent agent.
The platform supplies `Dial` (one hub stream through the VPN session), `DialLocal` (where an incoming flow ends) and `OnState`.
`Run` sends `Hello{control}` with the public identity, signs the hub's challenge, and tracks the reply, peer snapshots, incoming requests and pongs.
`Config.Name` optionally advertises this device's name during authenticated registration.
Empty uses the identity-derived default; nonempty names have at most 128 Unicode characters, no control characters and no surrounding whitespace.
The name is session metadata, not an identity or address change.
The caller must route each hub connection through an authenticated VPN. The challenge alone does not authenticate the hub or prevent active interception.
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
Private keys and payloads never enter logs.

Local peer state separates direct policy (`DirectAllowed`) from the latest real attempt (`DirectStatus`) and established transport (`LastPath`).
Attempt statuses are `connecting`, `succeeded`, `failed`, `unavailable` and `canceled`; no status is emitted before an attempt.
Current flow counts take precedence over historical paths when presenting activity.
Failed attempts remain visible through encrypted relay fallback and after flow closure, but observations clear on peer departure, identity replacement or disconnection.
These fields are local observations, not hub-supplied reachability guarantees.

## Checks

- Run `go test -race ./...` from `client/`; the agent tests use an in-process hub speaking the wire contract and covers registration, peers, TCP and UDP flows, refusals, concurrency bounds, reconnects, backoff, cancellation and goroutine leaks.
- Run `go test -race -count=1 ./...` from `tests/` for the Go agent against the Rust hub; it builds `server/` with cargo.
- The direct-transfer tests use Pion `vnet` for independent full-cone, address-restricted and port-restricted NATs, symmetric peer-port changes in both directions, packet loss, filtered punches and untraversable dual-symmetric NATs. They exercise real STUN and QUIC implementations, verify TCP/UDP file digests and hub byte budgets, and retain encrypted relay fallback. The simulator requires neither container runtime nor host network/firewall changes.
- Integration with the real hub and routed traffic on each platform is a separate acceptance step.
