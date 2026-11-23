# overlay-relay

Authenticated rendezvous and byte relay for overlay peers.

Each peer is a client-generated key pair with a hub-assigned private IPv4 address.
Broadcasting peers in the same room can discover each other and open TCP or UDP flows.
Agents encrypt relayed flows by default and can opt into direct connections.
Clients can serve `device-name.on.snoo` using the hub's authenticated room-local name lookups.

## Components

| Part | Language | Location | Purpose |
|---|---|---|---|
| Hub (`overlay-hub`) | Go | [`server/`](server/README.md) | Admits peers, owns name bindings, relays flows. |
| Client packages | Go | [`client/`](client/README.md) | Wire types, identity keys, and a reference agent. |
| Container image | Docker | [`Dockerfile`](Dockerfile) | Builds a local non-root hub image. |

See the [developer reference](docs/LLM_WIKI.md) for the wire format, message schemas, timers, and limits.

## Quick start

### 1. Run the hub

Build and run the Go binary using the [hub guide](server/README.md#build), or build a local image from the relay repository root:

```text
docker build -t overlay-relay:local .
```

Use an authenticated VPN between every client and the hub.  
The protocol does not authenticate the hub or protect its transport against an active intermediary.  
Use an existing VPN Docker network in place of `vpn-network`.

```text
docker run -d --name overlay-relay --network vpn-network \
  -v overlay-relay-data:/var/lib/overlay-relay \
  overlay-relay:local
```

There is no enrollment: clients generate and keep their own keys, and the hub challenges every connection.
Use `OVERLAY_ALLOWED_HOST` to restrict source hosts as described in the [hub guide](server/README.md#admission).

### 2. Use the client packages

```text
go get github.com/ParkSnoopy/overlay-relay@latest
```

Update hub and clients separately within the supported [wire compatibility window](#versioning).
Magic DNS requires client support and a hub advertising name lookup.

```go
agent := overlayagent.New(overlayagent.Config{
    Identity: identity, // the client's own P-384 private key, created once and kept
    Dial: func(ctx context.Context) (net.Conn, error) {
        var d net.Dialer
        return d.DialContext(ctx, "tcp", "hub.example.net:6697") // through the authenticated VPN
    },
    DialLocal: func(ctx context.Context, proto string, port uint16, src netip.Addr) (net.Conn, error) {
        var d net.Dialer
        return d.DialContext(ctx, proto, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
    },
    OnState: func(s overlay.State) { /* must not block */ },
})
go agent.Run(ctx)
ip := <-agent.Ready()
flow, err := agent.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(peerIP, 7000))
```

See the [client guide](client/README.md) for the full API.

## Examples and tests

- [`examples/client`](examples/client): runs one agent, prints its state, and optionally sends one line to a peer.
- [`tests/`](tests): exercises the Go hub and agent together, including enrollment-free registration, discovery, and flows.

Run these from the relay repository root:

```text
(cd server && GOWORK=off go test ./...)
go test -race ./client/...
(cd tests && go test -race -count=1 ./...)
(cd examples && go vet ./...)
```

Lint the current Go hub and client from the relay repository root:

```text
golangci-lint run ./...
```

The root [`go.mod`](go.mod) covers the hub and client packages.
The root [`go.work`](go.work) also includes the separate `tests/` and `examples/` modules.
Legacy Rust compatibility is a separate check against historical binaries or source; see [interop](docs/LLM_WIKI.md#15-testing-and-verification).

## Versioning

The relay root's [`version.go`](version.go) defines the shared release and wire metadata for the Go hub and client.
Release and wire generations are independent.
Tag the root module as `vX.Y.Z`; public package imports retain `/client/overlay` and `/client/overlayagent`.
Each stream declares its wire generation in `Hello.version`; the current hub accepts v5 and v4, not v3.

Preserve the existing [hub data directory](docs/server.md#inputs) when replacing an older hub.
See the [changelog](CHANGELOG.md) for migration notes.

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
