# overlay-relay client (Go)

Go module `github.com/ParkSnoopy/overlay-relay/client`. It contains:

- `overlay`: wire types, frame codec, token and verifier derivation, peers table validation.
- `overlayagent`: a reference agent that registers with a hub, tracks peers, opens outbound flows, serves inbound flows, and probes a hub for readiness.

The module has no daemon and no platform code. Your application supplies the network dialers and the local service dialer. The agent runs in your process.

## Install

```text
go get github.com/ParkSnoopy/overlay-relay/client@v0.1.0
```

Module versions follow the server release. Tags are `client/vX.Y.Z`.

Requires Go 1.26.6 or later.

## Use the agent

```go
package main

import (
    "context"
    "log"
    "net"
    "net/netip"
    "strconv"

    "github.com/ParkSnoopy/overlay-relay/client/overlay"
    "github.com/ParkSnoopy/overlay-relay/client/overlayagent"
)

func main() {
    ctx := context.Background()

    agent := overlayagent.New(overlayagent.Config{
        // Canonical account secret. Use the same bytes the operator put in the peers table.
        Secret: []byte("hysteria:alice:alice-pass"),

        // Opens one stream to the hub. Route it through your VPN session if needed.
        Dial: func(ctx context.Context) (net.Conn, error) {
            var d net.Dialer
            return d.DialContext(ctx, "tcp", "hub.example.net:6697")
        },

        // Completes an inbound flow locally. For UDP, return a connected conn that
        // carries one datagram per Read and Write.
        DialLocal: func(ctx context.Context, proto string, port uint16, src netip.Addr) (net.Conn, error) {
            var d net.Dialer
            return d.DialContext(ctx, proto, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
        },

        // Receives every state change. Must not block.
        OnState: func(state overlay.State) {
            log.Printf("connected=%v ip=%s peers=%d", state.Connected, state.IP, len(state.Peers))
        },
    })

    go func() {
        if err := agent.Run(ctx); err != nil {
            log.Printf("agent stopped: %v", err)
        }
    }()

    myIP := <-agent.Ready() // closed after the first successful registration
    log.Printf("my address: %s", myIP)

    flow, err := agent.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(netip.MustParseAddr("10.77.0.2"), 7000))
    if err != nil {
        log.Fatal(err)
    }
    defer flow.Close()
    // flow is a plain net.Conn for TCP. For UDP, pass overlay.ProtoUDP and use one datagram per Read/Write.
}
```

Notes:

- `Run` blocks. Call it once per agent. It reconnects with backoff until its context ends.
- `Ready` delivers the address once, on the first registration.
- `Outbound` only reaches accounts in the current `Peers` list. It returns an error otherwise.
- `Outbound` refuses your own address and any address outside `10.77.0.0/16`.
- `IP()` returns the current address, or the zero value before the first registration.
- Inbound flows are served automatically. Up to 128 are handled at once. Extra requests are dropped.
- `Config.Compression` (default `false`) DEFLATEs flow bytes in chunks. Both peers of a flow must enable it.

## Account secrets and tokens

```go
token := overlay.Token(secret)          // 64 hex digits, sent to the hub
verifier, err := overlay.Verifier(token) // 64 hex digits, stored in the peers table
```

Helpers for the two account formats used in practice:

```go
overlay.SecretXray(uuid)                     // "xray:" + lowercase UUID
overlay.SecretUserPass(engine, user, pass)   // engine + ":" + user + ":" + pass
```

The derivation is documented in [`../docs/LLM_WIKI.md`](../docs/LLM_WIKI.md#4-identity-secrets-tokens-verifiers) with a test vector.

## State

`overlay.State` is emitted on every change:

| Field | Meaning |
|---|---|
| `Available` | The overlay can run in this session. |
| `Reason` | Why it is not connected, when known. |
| `Broadcasting` | Your connect-time choice, reported back. |
| `Connected` | Registered with the hub. |
| `IP`, `Name` | Your address and display name. |
| `Peers` | Other broadcasting accounts, sorted by address. |

## Probe a hub

```go
if err := overlayagent.Probe(ctx, "hub.example.net:6697"); err != nil {
    // the hub is unreachable, misconfigured, or not admitting this source
}
```

`Probe` sends an all-zero token and expects an `unauthorized` reply. It never uses a real account.

## Wire helpers

If you implement your own transport, `overlay` exposes the framing directly:

- `overlay.WriteFrame(w, value)` and `overlay.ReadFrame(r, &value)`: 2-byte big-endian length plus JSON, at most 16 KiB.
- `overlay.WriteDatagram(w, payload)` and `overlay.ReadDatagram(r, buf)`: 2-byte length plus raw payload, at most 65535 bytes.
- `overlay.Hello`, `overlay.Reply`, `overlay.Event`, `overlay.Ping`, `overlay.Peer`, `overlay.Incoming`: message types.

## Test

```text
go test -race ./...
```

End-to-end tests against the Rust hub live in [`../tests`](../tests).

## Lint

The module is linted with `golangci-lint` and the `gocritic` linter using [`../.golangci.yml`](../.golangci.yml):

```text
golangci-lint run ./...
```

## License

GPL-3.0-only.
