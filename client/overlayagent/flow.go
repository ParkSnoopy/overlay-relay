package overlayagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

// Outbound opens a flow to a broadcasting peer through the hub. A TCP flow is
// the returned stream itself; a UDP flow exposes one datagram per Read and Write.
// The checks here are a cheap pre-filter: the hub remains the authority.
func (a *Agent) Outbound(ctx context.Context, proto string, dst netip.AddrPort) (net.Conn, error) {
	if proto != overlay.ProtoTCP && proto != overlay.ProtoUDP {
		return nil, errors.New("unsupported overlay protocol")
	}
	ip := dst.Addr().Unmap()
	if dst.Port() == 0 || !overlay.CIDR.Contains(ip) || !overlay.Assignable(ip) {
		return nil, errors.New("destination is outside the overlay network")
	}
	a.mu.Lock()
	_, peer := a.peerSet[ip]
	peerID := a.peerIDLocked(ip)
	self := ip == a.ip
	a.mu.Unlock()
	if self {
		return nil, errors.New("destination is this device")
	}
	if !peer {
		return nil, errors.New(overlay.ErrUnavailable)
	}
	wantDirect := a.directAllowed(ip)
	flow, err := a.openFlow(ctx, proto, ip, dst.Port(), peerID, wantDirect)
	if wantDirect && errors.Is(err, errDirectFailed) && ctx.Err() == nil {
		// NAT or a firewall can refuse the direct path. The next attempt offers
		// no endpoint, so both peers use the relay for this flow and later ones.
		a.blockDirect(ip)
		flow, err = a.openFlow(ctx, proto, ip, dst.Port(), peerID, false)
	}
	if err != nil {
		return nil, err
	}
	if a.cfg.Compression {
		flow = overlay.Compressed(flow)
	}
	if proto == overlay.ProtoUDP {
		return &datagramConn{Conn: flow, buffer: make([]byte, 2+overlay.MaxDatagram)}, nil
	}
	return flow, nil
}

// openFlow asks the hub for one flow to ip and finishes it on the transport the
// hub negotiated. wantDirect adds this agent's direct offer to the request.
func (a *Agent) openFlow(ctx context.Context, proto string, ip netip.Addr, port uint16, peerID string, wantDirect bool) (net.Conn, error) {
	hello := &overlay.Hello{Version: overlay.Version, Kind: overlay.KindOpen, Proto: proto, Dst: ip.String(), Port: port, PeerID: peerID}
	a.offer(ctx, hello, wantDirect)
	conn, err := a.cfg.Dial(ctx)
	if err != nil {
		return nil, errors.New("overlay hub is unreachable")
	}
	reply, err := a.handshake(ctx, conn, hello)
	if err != nil {
		closeConn(conn)
		return nil, errors.New("overlay hub is unreachable")
	}
	if !reply.OK {
		closeConn(conn)
		return nil, errors.New(boundedReason(reply.Error))
	}
	flow, err := a.finishOutbound(ctx, conn, &reply)
	if err != nil {
		return nil, err
	}
	return a.trackFlow(flow, ip, peerID, reply.Direct)
}

// directAllowed reports whether a direct connection to ip may be offered: it
// is not when one failed recently.
func (a *Agent) directAllowed(ip netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.relayOnlyLocked(a.peerIDLocked(ip)) {
		return false
	}
	until, blocked := a.directBlocked[ip]
	if blocked && time.Now().After(until) {
		delete(a.directBlocked, ip)
		return true
	}
	return !blocked
}

// blockDirect stops offering direct connections to ip for directRetryAfter.
func (a *Agent) blockDirect(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.directBlocked == nil {
		a.directBlocked = map[netip.Addr]time.Time{}
	}
	a.directBlocked[ip] = time.Now().Add(directRetryAfter)
}

// accept starts handling one Incoming request unless the concurrency bound is reached.
func (a *Agent) accept(ctx context.Context, in *overlay.Incoming) {
	src, err := netip.ParseAddr(in.Src)
	if (in.Proto != overlay.ProtoTCP && in.Proto != overlay.ProtoUDP) || in.Port == 0 || in.ID == "" || err != nil || !overlay.Assignable(src.Unmap()) {
		slog.Debug("Overlay ignored a malformed incoming request")
		return
	}
	select {
	case a.inflight <- struct{}{}:
	default:
		slog.Debug("Overlay dropped an incoming request over the concurrency bound")
		return
	}
	a.flows.Add(1)
	go func() {
		defer a.flows.Done()
		defer func() { <-a.inflight }()
		if err := a.serveIncoming(ctx, in, src.Unmap()); err != nil {
			// Neither tokens nor payloads enter logs.
			slog.Debug("Overlay incoming flow ended with an error")
		}
	}()
}

func (a *Agent) serveIncoming(ctx context.Context, in *overlay.Incoming, src netip.Addr) error {
	// Register for a direct connection before the accept, so the requester can
	// never reach the listener ahead of the registration.
	var exp *expectation
	a.mu.Lock()
	allowed := !a.relayOnlyLocked(in.PeerID)
	a.mu.Unlock()
	if allowed {
		exp = a.expectDirect(in)
	}
	defer exp.cancel()
	hello := &overlay.Hello{Version: overlay.Version, Kind: overlay.KindAccept, ID: in.ID}
	a.offer(ctx, hello, exp != nil)
	if hello.Endpoint == "" {
		exp.cancel()
		exp = nil
	}
	hub, err := a.cfg.Dial(ctx)
	if err != nil {
		return err
	}
	reply, err := a.handshake(ctx, hub, hello)
	if err != nil || !reply.OK {
		closeConn(hub)
		return errors.Join(err, errors.New("hub refused the accept stream"))
	}
	flow, err := a.finishIncoming(ctx, hub, &reply, in, exp)
	if err != nil {
		return err
	}
	flow, err = a.trackFlow(flow, src, in.PeerID, reply.Direct)
	if err != nil {
		return err
	}
	if a.cfg.Compression {
		flow = overlay.Compressed(flow)
	}
	local, err := a.cfg.DialLocal(ctx, in.Proto, in.Port, src)
	if err != nil {
		closeConn(flow)
		return err
	}
	if in.Proto == overlay.ProtoUDP {
		return spliceUDP(ctx, flow, local, a.timing.udpIdle)
	}
	return spliceTCP(ctx, flow, local)
}

type closeWriter interface{ CloseWrite() error }

// halfClose signals the end of one direction. Without half-close support
// the whole connection closes, which is the best available end-of-stream.
func halfClose(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	closeConn(c)
}

func spliceTCP(ctx context.Context, a, b net.Conn) error {
	stop := context.AfterFunc(ctx, func() { closeConn(a); closeConn(b) })
	defer stop()
	defer closeConn(a)
	defer closeConn(b)
	errs := make(chan error, 2)
	copyDirection := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err != nil {
			// An aborted direction would otherwise leave the other one blocked.
			closeConn(a)
			closeConn(b)
		} else {
			halfClose(dst)
		}
		errs <- err
	}
	go copyDirection(a, b)
	go copyDirection(b, a)
	first, second := <-errs, <-errs
	return errors.Join(ignoreClosed(first), ignoreClosed(second))
}

func ignoreClosed(err error) error {
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
}

// spliceUDP relays datagrams between the hub stream (length-prefixed records)
// and a connected local datagram conn until idle, cancellation or failure.
func spliceUDP(ctx context.Context, hub, local net.Conn, idle time.Duration) error {
	var once sync.Once
	closeBoth := func() { once.Do(func() { closeConn(hub); closeConn(local) }) }
	defer closeBoth()
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	timer := time.AfterFunc(idle, closeBoth)
	defer timer.Stop()
	errs := make(chan error, 2)
	go func() {
		buffer := make([]byte, overlay.MaxDatagram)
		for {
			n, err := overlay.ReadDatagram(hub, buffer)
			if err == nil {
				timer.Reset(idle)
				_, err = local.Write(buffer[:n])
			}
			if err != nil {
				closeBoth()
				errs <- err
				return
			}
		}
	}()
	go func() {
		buffer := make([]byte, overlay.MaxDatagram)
		for {
			n, err := local.Read(buffer)
			if err == nil {
				timer.Reset(idle)
				err = overlay.WriteDatagram(hub, buffer[:n])
			}
			if err != nil {
				closeBoth()
				errs <- err
				return
			}
		}
	}()
	first, second := <-errs, <-errs
	return errors.Join(ignoreClosed(first), ignoreClosed(second))
}

// datagramConn presents the hub's record-framed UDP stream as a datagram conn.
// Reads keep partial progress across deadline errors, so a timeout never
// desynchronizes the framing.
type datagramConn struct {
	net.Conn
	rmu, wmu sync.Mutex
	buffer   []byte // header and payload of the record being read
	filled   int
}

func (c *datagramConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if err := c.fill(2); err != nil {
		return 0, err
	}
	size := int(c.buffer[0])<<8 | int(c.buffer[1])
	if err := c.fill(2 + size); err != nil {
		return 0, err
	}
	c.filled = 0
	return copy(p, c.buffer[2:2+size]), nil
}

// fill reads until total bytes of the current record are buffered.
func (c *datagramConn) fill(total int) error {
	for c.filled < total {
		n, err := c.Conn.Read(c.buffer[c.filled:total])
		c.filled += n
		if c.filled >= total {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *datagramConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := overlay.WriteDatagram(c.Conn, p); err != nil {
		return 0, fmt.Errorf("overlay datagram write: %w", err)
	}
	return len(p), nil
}
