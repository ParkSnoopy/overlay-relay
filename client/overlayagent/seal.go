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

// offer adds this agent's offer to a Hello: its flow fingerprint.
func (a *Agent) offer(hello *overlay.Hello) {
	if !a.encrypted() || a.identity == nil {
		return
	}
	hello.Fingerprint = a.identity.fingerprint
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

// startDirect prepares direct links when the configuration asks for them.
// Without them every flow stays on the relay; the reason is not an error.
func (a *Agent) startDirect() {
	options := a.cfg.Direct
	if options == nil || !a.encrypted() || a.identity == nil || len(options.STUNServers) == 0 {
		return
	}
	d, err := newDirectState(options, a.identity)
	if err != nil {
		slog.Debug("Overlay direct connections are unavailable")
		return
	}
	a.direct.Store(d)
}
