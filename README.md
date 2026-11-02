# overlay-relay

Authenticated rendezvous and byte relay for overlay accounts.

Each account gets a stable private IPv4 address in `10.77.0.0/16`. Accounts that choose to broadcast register with a hub, see the other broadcasting accounts, and open TCP or UDP flows to them. The hub pairs the two sides and relays bytes. It does not read the payload.

## Components

| Part | Language | Location | Purpose |
|---|---|---|---|
| Hub (`overlay-hub`) | Rust | [`server/`](server/README.md) | Admits connections, authenticates accounts, relays flows. |
| Client module | Go | [`client/`](client/README.md) | Wire types, token derivation, and a reference agent. |
| Container image | Docker | [`Dockerfile`](Dockerfile) | Builds the hub as a non-root image. |

The full developer reference, including the wire format, message schemas, timers, limits, and a checklist for writing a client in another language, is in [`docs/LLM_WIKI.md`](docs/LLM_WIKI.md).

## Quick start

### 1. Run the hub

Build the image:

```text
docker build -t overlay-relay:0.1.0 .
```

Create a peers table. Each account's secret is the same value its client uses. The example tool derives the verifiers:

```text
cd examples && go run ./peers alice=hysteria:alice:alice-pass bob=xray:bob-secret > ./peers.json
```

Start the hub. `OVERLAY_ALLOWED_HOST` lists the host names whose addresses may connect:

```text
docker run -d --name overlay-relay \
  -p 6697:6697 \
  -e OVERLAY_ALLOWED_HOST=my-client-host \
  -v ./peers-dir:/etc/overlay-relay:ro \
  -v overlay-relay-data:/var/lib/overlay-relay \
  overlay-relay:0.1.0
```

Put `peers.json` inside `./peers-dir`. Mount the directory, not the file. The hub reloads the table when it changes.

### 2. Use the client module

```text
go get github.com/ParkSnoopy/overlay-relay/client@v0.1.0
```

```go
agent := overlayagent.New(overlayagent.Config{
    Secret: []byte("hysteria:alice:alice-pass"),
    Dial: func(ctx context.Context) (net.Conn, error) {
        var d net.Dialer
        return d.DialContext(ctx, "tcp", "hub.example.net:6697")
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

See [`client/README.md`](client/README.md) for the full API.

## Examples and tests

- [`examples/peers`](examples/peers): builds a peers table from `name=secret` arguments.
- [`examples/client`](examples/client): runs one agent, prints its state, and optionally sends one line to a peer.
- [`tests/`](tests): builds the hub, starts it as a process, and checks registration, peers, a TCP round trip, and refusal of an unknown address against the Go agent.

Run them from the repository root:

```text
cd server && cargo test
cd client && go test -race ./...
cd tests && go test -race -count=1 ./...
cd examples && go vet ./...
```

Lint:

```text
cd server && cargo clippy --all-targets -- -D warnings
cd client && golangci-lint run ./...
```

Go modules are joined by the root [`go.work`](go.work). Run Go commands from a module directory so the workspace is used.

## Versioning

The release version is the `version` field in [`server/Cargo.toml`](server/Cargo.toml). Go module tags follow it as `client/vX.Y.Z`. The wire version is separate: messages carry `"version": 1`.

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
