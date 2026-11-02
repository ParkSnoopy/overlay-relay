# overlay-relay client (Go)

Go module `github.com/ParkSnoopy/overlay-relay/client`. It contains:

- `overlay`: wire types, frame codec, identity keys, and peers table validation.
- `overlayagent`: a reference agent that registers with a hub, tracks peers, opens outbound flows, serves inbound flows, and probes a hub for readiness.

The module has no daemon and no platform code. Your application supplies the network dialers and the local service dialer. The agent runs in your process.

## Install

```text
go get github.com/ParkSnoopy/overlay-relay/client@latest
```

Check that the published client supports wire version 2 before use.  

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
    "os"
    "strconv"

    "github.com/ParkSnoopy/overlay-relay/client/overlay"
    "github.com/ParkSnoopy/overlay-relay/client/overlayagent"
)

func main() {
    ctx := context.Background()

    data, err := os.ReadFile("alice.pem")
    if err != nil { log.Fatal(err) }
    identity, err := overlay.ParseIdentity(data)
    if err != nil { log.Fatal(err) }

    agent := overlayagent.New(overlayagent.Config{
        Identity: identity,

        // Route every hub stream through an authenticated VPN session.
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
- Flows are encrypted end to end by default. See [Encryption and direct connections](#encryption-and-direct-connections).

## Encryption and direct connections

Every agent makes a self-signed flow certificate when it is created. It sends the certificate's SHA-256 fingerprint to the hub with each `open` or `accept`, and the hub hands the other side's fingerprint back. Each side then runs TLS 1.3 over the relayed stream and accepts only the certificate with that fingerprint, so a hub that only relays, and anyone on the network, sees nothing but ciphertext. The fingerprints themselves travel through the hub, so a hub that replaces them can intercept a flow: use a hub you trust. The private identity key never leaves the device.

- Encryption is on by default. Set `Config.DisableEncryption` to turn it off.
- An agent with encryption on refuses a peer that cannot encrypt: `Outbound` returns an error and an incoming flow is dropped. It never downgrades to plaintext.
- Both peers must agree. Run the same setting on both sides of a flow, or leave the default.

Direct connections are off by default. Set `Config.Direct` and two agents that both enable it connect to each other over the internet with QUIC, and the hub relays nothing:

```go
cfg.Direct = &overlayagent.DirectOptions{
    STUNServers: []string{"stun.example.net:3478"}, // required
    ListenPacket: func(ctx context.Context) (net.PacketConn, error) {
        // Return a UDP socket that bypasses the VPN. Nil listens on all addresses.
    },
}
```

- The agent asks the STUN server, over the socket the QUIC connection will use, for its public UDP endpoint. Query it from outside the VPN, or the hub-side address you learn is not reachable.
- Both peers hole-punch their NAT and connect. The QUIC handshake pins the same certificate fingerprints, so the connection is authenticated and encrypted.
- If only one side enables `Direct`, or an agent cannot learn its endpoint, the flow stays on the encrypted relay.
- A direct connection that fails to come up makes the flow fail. It does not fall back to the relay, because that would hide a network change from the caller.
- `DirectOptions.Timeout` bounds the connection attempt (default 10 seconds).

## Account identities

```go
key, err := overlay.GenerateIdentity()
encoded, err := overlay.EncodeIdentity(key) // store securely and reuse
public, err := overlay.PublicIdentity(key) // enroll this public key with the hub
```

The client must use the same key across reconnects. Use `overlay.ParseIdentity` to load the stored PKCS#8 PEM. An authenticated VPN is required for every hub stream. The signature exchange alone does not authenticate the hub or protect against an active intermediary.

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

`Probe` uses a fresh unregistered key and expects an `unauthorized` reply. It never uses a real account. Its TCP connection must also travel through the authenticated VPN.

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
