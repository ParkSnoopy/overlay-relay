package overlayagent

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const (
	// flowHeaderSize is the proto byte and big-endian port that open every flow on a link.
	flowHeaderSize = 3
	flowTCP        = 1
	flowUDP        = 2
)

// link is one authenticated, multiplexed direct path to a single peer. Each
// flow is one stream; the first bytes of a stream are the flow header.
type link interface {
	method() string
	open(ctx context.Context) (net.Conn, error)
	accept(ctx context.Context) (net.Conn, error)
	close()
	done() <-chan struct{}
}

// linkBase gives every link the same close and done behavior.
type linkBase struct {
	name    string
	once    sync.Once
	ended   chan struct{}
	release func()
}

func newLinkBase(name string, release func()) *linkBase {
	return &linkBase{name: name, ended: make(chan struct{}), release: release}
}

func (b *linkBase) method() string        { return b.name }
func (b *linkBase) done() <-chan struct{} { return b.ended }

func (b *linkBase) close() {
	b.once.Do(func() {
		close(b.ended)
		b.release()
	})
}

// peerLink is an established link and the peer it belongs to.
type peerLink struct {
	link
	ip     netip.Addr
	peerID string
}

// muxStream is what a multiplexer stream offers a flow.
type muxStream interface {
	io.ReadWriteCloser
	CloseWrite() error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type namedAddr string

func (a namedAddr) Network() string { return "overlay-link" }
func (a namedAddr) String() string  { return string(a) }

// streamConn presents one multiplexed stream as a net.Conn with half-close.
type streamConn struct {
	muxStream
	local, remote net.Addr
}

func newStreamConn(stream muxStream, peerID string) *streamConn {
	return &streamConn{muxStream: stream, local: namedAddr("local"), remote: namedAddr(peerID)}
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

// linkFor returns the live link to ip, if any.
func (a *Agent) linkFor(ip netip.Addr, peerID string) *peerLink {
	a.mu.Lock()
	defer a.mu.Unlock()
	pl := a.links[ip]
	if pl == nil || pl.peerID != peerID || a.relayOnlyLocked(peerID) {
		return nil
	}
	return pl
}

// openLinkFlow opens one flow on a link. Like a relayed flow, it returns
// before the destination has dialed its local service.
func (a *Agent) openLinkFlow(ctx context.Context, pl *peerLink, proto string, port uint16) (net.Conn, error) {
	stream, err := pl.open(ctx)
	if err != nil {
		return nil, err
	}
	header := [flowHeaderSize]byte{flowTCP}
	if proto == overlay.ProtoUDP {
		header[0] = flowUDP
	}
	binary.BigEndian.PutUint16(header[1:], port)
	if _, err := stream.Write(header[:]); err != nil {
		closeConn(stream)
		return nil, err
	}
	return stream, nil
}

// installLink registers an established link unless the peer is gone, denied or
// already linked, and starts serving the peer's flows on it.
func (a *Agent) installLink(l link, ip netip.Addr, peerID string) bool {
	pl := &peerLink{link: l, ip: ip, peerID: peerID}
	a.mu.Lock()
	ctx := a.runCtx
	if ctx == nil || ctx.Err() != nil || !a.connected || a.peerIDLocked(ip) != peerID || a.relayOnlyLocked(peerID) {
		a.mu.Unlock()
		l.close()
		return false
	}
	if a.links == nil {
		a.links = map[netip.Addr]*peerLink{}
	}
	previous := a.links[ip]
	a.links[ip] = pl
	a.flows.Add(1)
	a.mu.Unlock()
	if previous != nil {
		previous.close()
	}
	slog.Debug("Overlay direct link is up", "method", l.method())
	a.recordDirect(ip, peerID, overlay.DirectSucceeded)
	go func() {
		defer a.flows.Done()
		a.serveLink(ctx, pl)
	}()
	return true
}

// serveLink answers the peer's flows until the link ends, then forgets it.
func (a *Agent) serveLink(ctx context.Context, pl *peerLink) {
	linkCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-pl.done():
		case <-linkCtx.Done():
		}
		cancel()
		pl.close()
	}()
	for {
		stream, err := pl.accept(linkCtx)
		if err != nil {
			break
		}
		select {
		case a.inflight <- struct{}{}:
		default:
			slog.Debug("Overlay dropped a link flow over the concurrency bound")
			closeConn(stream)
			continue
		}
		a.flows.Add(1)
		go func() {
			defer a.flows.Done()
			defer func() { <-a.inflight }()
			if err := a.serveLinkFlow(linkCtx, pl, stream); err != nil {
				slog.Debug("Overlay link flow ended with an error")
			}
		}()
	}
	a.mu.Lock()
	current := a.links[pl.ip] == pl
	if current {
		delete(a.links, pl.ip)
	}
	a.mu.Unlock()
	pl.close()
	if current && ctx.Err() == nil {
		a.recordDirect(pl.ip, pl.peerID, overlay.DirectFailed)
	}
}

func (a *Agent) serveLinkFlow(ctx context.Context, pl *peerLink, stream net.Conn) error {
	var header [flowHeaderSize]byte
	_ = stream.SetReadDeadline(time.Now().Add(a.timing.handshake))
	if _, err := io.ReadFull(stream, header[:]); err != nil {
		closeConn(stream)
		return err
	}
	_ = stream.SetReadDeadline(time.Time{})
	proto := overlay.ProtoTCP
	switch header[0] {
	case flowTCP:
	case flowUDP:
		proto = overlay.ProtoUDP
	default:
		closeConn(stream)
		return errors.New("overlay link flow has an unknown protocol")
	}
	port := binary.BigEndian.Uint16(header[1:])
	if port == 0 {
		closeConn(stream)
		return errors.New("overlay link flow has no port")
	}
	flow, err := a.trackFlow(stream, pl.ip, pl.peerID, true)
	if err != nil {
		return err
	}
	if a.cfg.Compression {
		flow = overlay.Compressed(flow)
	}
	local, err := a.cfg.DialLocal(ctx, proto, port, pl.ip)
	if err != nil {
		closeConn(flow)
		return err
	}
	if proto == overlay.ProtoUDP {
		return spliceUDP(ctx, flow, local, a.timing.udpIdle)
	}
	return spliceTCP(ctx, flow, local)
}

// closeLinks ends every link and negotiation whose peer keep rejects.
// A nil keep ends all of them.
func (a *Agent) closeLinks(keep func(ip netip.Addr, peerID string) bool) {
	a.mu.Lock()
	var closing []*peerLink
	for ip, pl := range a.links {
		if keep == nil || !keep(ip, pl.peerID) {
			closing = append(closing, pl)
			delete(a.links, ip)
		}
	}
	var canceling []*linkAttempt
	for ip, attempt := range a.linking {
		if keep == nil || !keep(ip, attempt.peerID) {
			canceling = append(canceling, attempt)
		}
	}
	a.mu.Unlock()
	for _, pl := range closing {
		pl.close()
		a.recordDirect(pl.ip, pl.peerID, overlay.DirectCanceled)
	}
	for _, attempt := range canceling {
		attempt.cancel()
	}
}

// linkAttempt is one negotiation in progress, as initiator or responder.
type linkAttempt struct {
	peerID    string
	initiator bool
	cancel    context.CancelFunc
}

// maybeLink starts a link negotiation to ip in the background when direct
// connections are on and neither a link nor a recent failure exists. Flows
// keep using the relay meanwhile.
func (a *Agent) maybeLink(ip netip.Addr, peerID string) {
	d := a.direct.Load()
	if d == nil || !overlay.ValidPeerID(peerID) || !a.directAllowed(ip) {
		return
	}
	a.mu.Lock()
	if a.runCtx == nil || a.runCtx.Err() != nil || !a.connected || a.links[ip] != nil || a.linking[ip] != nil {
		a.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(a.runCtx)
	attempt := &linkAttempt{peerID: peerID, initiator: true, cancel: cancel}
	if a.linking == nil {
		a.linking = map[netip.Addr]*linkAttempt{}
	}
	a.linking[ip] = attempt
	a.flows.Add(1)
	a.mu.Unlock()
	a.recordDirect(ip, peerID, overlay.DirectConnecting)
	go func() {
		defer a.flows.Done()
		defer cancel()
		l, err := a.negotiate(ctx, d, ip, peerID)
		a.mu.Lock()
		if a.linking[ip] == attempt {
			delete(a.linking, ip)
		}
		a.mu.Unlock()
		a.finishAttempt(ctx, ip, peerID, l, err)
	}()
}

// finishAttempt records the outcome of a negotiation. A failure is not retried for directRetryAfter.
func (a *Agent) finishAttempt(ctx context.Context, ip netip.Addr, peerID string, l link, err error) {
	switch {
	case err == nil:
		a.installLink(l, ip, peerID)
	case ctx.Err() != nil:
		a.recordDirect(ip, peerID, overlay.DirectCanceled)
	case errors.Is(err, errNoMethod) || errors.Is(err, errNoLink):
		a.blockDirect(ip)
		a.recordDirect(ip, peerID, overlay.DirectUnavailable)
	default:
		a.blockDirect(ip)
		a.recordDirect(ip, peerID, overlay.DirectFailed)
	}
}
