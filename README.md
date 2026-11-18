# overlay-relay

Authenticated rendezvous and byte relay for overlay peers.

Each peer is a client key pair it generated itself and gets a stable private IPv4 address in `10.77.0.0/16`. Peers that choose to broadcast register with a hub, see the other broadcasting peers, and open TCP or UDP flows to them. The hub pairs the two sides and relays bytes. It does not read the payload: agents encrypt every flow end to end (TLS 1.3, certificate fingerprints exchanged through the hub), so a relaying hub sees only ciphertext. Two agents can also opt in to a direct QUIC connection, and the hub then relays nothing.

## Components

| Part | Language | Location | Purpose |
|---|---|---|---|
| Hub (`overlay-hub`) | Rust | [`server/`](server/README.md) | Admits connections, challenges client keys, relays flows. |
| Client module | Go | [`client/`](client/README.md) | Wire types, identity keys, and a reference agent. |
| Container image | Docker | [`Dockerfile`](Dockerfile) | Builds the hub as a non-root image. |

The full developer reference, including the wire format, message schemas, timers, limits, and a checklist for writing a client in another language, is in [`docs/LLM_WIKI.md`](docs/LLM_WIKI.md).

## Quick start

### 1. Run the hub

Build the image:

```text
docker build -t overlay-relay:latest .
```

Use an authenticated VPN between every client and the hub.  
The protocol does not authenticate the hub or protect its transport against an active intermediary.  
Connect the hub container to the VPN network before clients attempt to reach it, then start it. It needs no configuration:

```text
docker run -d --name overlay-relay \
  -v overlay-relay-data:/var/lib/overlay-relay \
  overlay-relay:latest
```

There is no enrollment. Each client generates its own key pair and keeps the private key. The hub challenges every connection, and a valid signature of a key is that key's peer: the same key is always the same peer with the same address. `OVERLAY_ALLOWED_HOST` can restrict which hosts may connect (see [`server/README.md`](server/README.md)).

### 2. Use the client module

```text
go get github.com/ParkSnoopy/overlay-relay/client@latest
```

Update the hub and clients separately if needed.  
The 0.5.x implementation prefers wire v5 and supports discovery, registration, and relayed traffic with 0.4.8 (wire v4).  
Both peers need v5 for direct connections on the new hub.  
Mixed-version traffic needs relay to be allowed by the hub.  

`server/Cargo.toml` is the release-version source.  
Run `python3 scripts/bump_version.py --sync` after changing it; `--check` verifies generated server/client metadata without writing.  
Set `wire` in `[package.metadata.overlay-relay]` independently of the release version.  
The generator derives the fallback as `wire - 1`; wire v1 has no fallback.  
The script does not increment versions or publish Go module tags.  

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

See [`client/README.md`](client/README.md) for the full API.

## Examples and tests

- [`examples/client`](examples/client): runs one agent, prints its state, and optionally sends one line to a peer.
- [`tests/`](tests): builds the hub, starts it as a process, and checks registration without enrollment, peers, a TCP round trip, and refusal of an unknown address against the Go agent.

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

The release version is the `version` field in [`server/Cargo.toml`](server/Cargo.toml).  
Go module tags follow it as `client/vX.Y.Z`.  
Each stream declares its wire version in `Hello.version`.  
The hub accepts wire v5 and v4; wire v3 (0.4.7) is outside the compatibility window.  
`TestPreviousReleaseInterop` uses hub and client binaries built from `00a8fd51fb93acfe31a51ea20a1d34e12fd4487d`.  

Version 2 is incompatible with token-based clients. Hub 0.2 reads no peers table: any key that signs the challenge is a peer, so remove the old `peers.json` mount. An `ips.json` from an older hub still loads, and addresses of keys that were already listed stay.

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
