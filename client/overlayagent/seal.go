package overlayagent

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

// Fixed, secret-free reasons returned to callers. Details go to debug logs only.
var (
	errPlaintextPeer = errors.New("overlay peer does not support end-to-end encryption")
	errSealFailed    = errors.New("overlay end-to-end encryption failed")
	errDirectFailed  = errors.New("overlay direct connection failed")
)

// encrypted reports whether this agent offers and requires end-to-end encryption.
func (a *Agent) encrypted() bool { return !a.cfg.DisableEncryption }

// offer adds this agent's offer to a Hello: its flow fingerprint, and, when a
// direct connection is wanted and possible, its public endpoint.
func (a *Agent) offer(ctx context.Context, hello *overlay.Hello, wantDirect bool) {
	if !a.encrypted() || a.identity == nil {
		return
	}
	hello.Fingerprint = a.identity.fingerprint
	if !wantDirect {
		return
	}
	d := a.direct.Load()
	if d == nil {
		return
	}
	endpoint, err := d.endpoint(ctx)
	if err != nil {
		slog.Debug("Overlay could not learn its public endpoint; the flow stays on the relay")
		return
	}
	hello.Endpoint = endpoint.String()
}

// finishOutbound turns the hub's success reply into the requester's flow stream.
// A direct flow that fails to come up returns errDirectFailed; Outbound then retries on the relay.
func (a *Agent) finishOutbound(ctx context.Context, hub net.Conn, reply *overlay.Reply) (net.Conn, error) {
	if !reply.Direct {
		return a.seal(ctx, hub, reply, true)
	}
	closeConn(hub)
	d := a.direct.Load()
	if d == nil {
		return nil, errDirectFailed
	}
	flow, err := d.dial(ctx, reply)
	if err != nil {
		slog.Debug("Overlay direct dial failed")
		return nil, errDirectFailed
	}
	return flow, nil
}

// finishIncoming turns the hub's success reply into the destination's flow stream.
func (a *Agent) finishIncoming(ctx context.Context, hub net.Conn, reply *overlay.Reply, in *overlay.Incoming, exp *expectation) (net.Conn, error) {
	if !reply.Direct {
		return a.seal(ctx, hub, reply, false)
	}
	closeConn(hub)
	if exp == nil || reply.ID != in.ID || !sameFingerprint(reply.Fingerprint, in.Fingerprint) {
		return nil, errDirectFailed
	}
	flow, err := exp.await(ctx, reply)
	if err != nil {
		slog.Debug("Overlay direct accept failed")
		return nil, errDirectFailed
	}
	return flow, nil
}

// seal applies the end-to-end encryption the hub negotiated for a relayed
// flow: TLS 1.3 with both certificates pinned by fingerprint. The requester is
// the TLS client. On any failure the stream is closed.
func (a *Agent) seal(ctx context.Context, conn net.Conn, reply *overlay.Reply, requester bool) (net.Conn, error) {
	if !a.encrypted() {
		return conn, nil
	}
	if !reply.Secure || a.identity == nil {
		closeConn(conn)
		return nil, errPlaintextPeer
	}
	var secured *tls.Conn
	if requester {
		secured = tls.Client(conn, a.identity.clientConfig(reply.Fingerprint, relayServerName, relayALPN))
	} else {
		secured = tls.Server(conn, a.identity.serverConfig(reply.Fingerprint, relayALPN))
	}
	ctx, cancel := context.WithTimeout(ctx, a.timing.handshake)
	defer cancel()
	if err := secured.HandshakeContext(ctx); err != nil {
		slog.Debug("Overlay relay handshake failed")
		closeConn(conn)
		return nil, errSealFailed
	}
	return secured, nil
}

// startDirect opens the direct-connection socket when the configuration asks
// for it. Without it every flow stays on the relay; the reason is not an error.
func (a *Agent) startDirect(ctx context.Context) {
	options := a.cfg.Direct
	if options == nil || !a.encrypted() || a.identity == nil || len(options.STUNServers) == 0 {
		return
	}
	d, err := startDirect(ctx, options, a.identity)
	if err != nil {
		slog.Debug("Overlay direct connections are unavailable")
		return
	}
	a.direct.Store(d)
}

// expectDirect registers the flow with the direct listener before the accept
// is sent. It returns nil when this flow cannot go direct.
func (a *Agent) expectDirect(in *overlay.Incoming) *expectation {
	d := a.direct.Load()
	if d == nil || !a.encrypted() || in.Fingerprint == "" || in.Endpoint == "" {
		return nil
	}
	return d.expect(in.ID, in.Fingerprint)
}
