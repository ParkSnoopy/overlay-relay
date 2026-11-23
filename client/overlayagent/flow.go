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
	if dst.Port() == 0 || !overlay.AssignableIn(a.Range(), ip) {
		return nil, errors.New("destination is outside the overlay network")
	}
	if dst.Port() == overlay.LinkPort {
		return nil, errors.New("destination port is reserved")
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
	finish := a.beginAttempt(ip, peerID)
	succeeded := false
	defer func() { finish(succeeded) }()
	flow, err := a.openPeerFlow(ctx, ip, peerID, proto, dst.Port())
	if err != nil {
		return nil, err
	}
	if a.cfg.Compression {
		flow = overlay.Compressed(flow)
	}
	if proto == overlay.ProtoUDP {
		succeeded = true
		return &datagramConn{Conn: flow, buffer: make([]byte, 2+overlay.MaxDatagram)}, nil
	}
	succeeded = true
	return flow, nil
}

func (a *Agent) openPeerFlow(ctx context.Context, ip netip.Addr, peerID, proto string, port uint16) (net.Conn, error) {
	if pl := a.linkFor(ip, peerID); pl != nil {
		flow, err := a.openLinkFlow(ctx, pl, proto, port)
		if err == nil {
			return a.trackDirect(flow, pl)
		}
		pl.close()
	}
	// Direct negotiation is signaling only, including when payload relay is forbidden.
	a.maybeLink(ip, peerID)
	relayCtx, admission, err := a.beginRelay(ctx, ip, peerID, false)
	if errors.Is(err, errDirectRequired) {
		pl, err := a.waitLink(ctx, ip, peerID)
		if err != nil {
			return nil, err
		}
		flow, err := a.openLinkFlow(ctx, pl, proto, port)
		if err != nil {
			pl.close()
			return nil, errors.Join(errDirectRequired, err)
		}
		return a.trackDirect(flow, pl)
	}
	if err != nil {
		return nil, err
	}
	defer a.finishRelay(admission)
	hello := &overlay.Hello{Version: a.wireVersion(), Kind: overlay.KindOpen, Proto: proto, Dst: ip.String(), Port: port, PeerID: peerID}
	raw, reply, err := a.dialHubStream(relayCtx, hello, admission)
	if err != nil {
		a.logRelay("outbound", ip, proto, port, "failed", "relay setup")
		return nil, err
	}
	flow, err := a.seal(relayCtx, raw, &reply, true)
	if err != nil {
		a.logRelay("outbound", ip, proto, port, "failed", "relay setup")
		return nil, err
	}
	flow, err = a.trackRelay(relayCtx, admission, flow)
	if err != nil {
		a.logRelay("outbound", ip, proto, port, "failed", "peer unavailable")
		return nil, err
	}
	a.logRelay("outbound", ip, proto, port, "opened", "")
	return flow, nil
}

func (a *Agent) dialHubStream(ctx context.Context, hello *overlay.Hello, admission *relayAdmission) (net.Conn, overlay.Reply, error) {
	if err := ctx.Err(); err != nil {
		return nil, overlay.Reply{}, err
	}
	a.offer(hello)
	conn, err := a.cfg.Dial(ctx)
	if err != nil {
		return nil, overlay.Reply{}, errors.New("overlay hub is unreachable")
	}
	if err := ctx.Err(); err != nil {
		closeConn(conn)
		return nil, overlay.Reply{}, err
	}
	if admission != nil {
		if err := a.bindRelay(ctx, admission, conn); err != nil {
			closeConn(conn)
			return nil, overlay.Reply{}, err
		}
	}
	reply, err := a.handshake(ctx, conn, hello)
	if err != nil || !reply.OK {
		closeConn(conn)
		if err != nil {
			return nil, reply, errors.New("overlay hub is unreachable")
		}
		return nil, reply, errors.New(boundedReason(reply.Error))
	}
	return conn, reply, nil
}

// logRelay records only validated endpoints, protocol and a fixed outcome. Never
// print stream IDs, keys, raw remote errors, or bytes from the flow.
func (a *Agent) logRelay(direction string, peer netip.Addr, proto string, port uint16, result, reason string) {
	line := fmt.Sprintf("Overlay relay %s: peer=%s protocol=%s port=%d result=%s", direction, peer, proto, port, result)
	if reason != "" {
		line += " reason=" + reason
	}
	if a.cfg.LogRelay != nil {
		a.cfg.LogRelay(line)
	} else {
		slog.Debug(line)
	}
}

// accept starts handling one Incoming request unless the concurrency bound is reached.
func (a *Agent) accept(ctx context.Context, in *overlay.Incoming) {
	src, err := netip.ParseAddr(in.Src)
	if (in.Proto != overlay.ProtoTCP && in.Proto != overlay.ProtoUDP) || in.Port == 0 || in.ID == "" || err != nil || !overlay.AssignableIn(a.Range(), src.Unmap()) {
		slog.Debug("Overlay ignored a malformed incoming request")
		return
	}
	select {
	case a.inflight <- struct{}{}:
	default:
		if !in.Signal {
			a.logRelay("incoming", src.Unmap(), in.Proto, in.Port, "dropped", "concurrency limit")
		}
		return
	}
	var admission *relayAdmission
	if !in.Signal {
		ctx, admission, err = a.beginRelay(ctx, src.Unmap(), in.PeerID, true)
		if err != nil {
			<-a.inflight
			reason := "peer unavailable"
			if errors.Is(err, errDirectRequired) {
				reason = "direct-only policy"
			}
			a.logRelay("incoming", src.Unmap(), in.Proto, in.Port, "blocked", reason)
			return
		}
	}
	a.flows.Add(1)
	go func() {
		defer a.flows.Done()
		defer func() { <-a.inflight }()
		if admission != nil {
			defer a.finishRelay(admission)
		}
		if err := a.serveIncoming(ctx, in, src.Unmap(), admission); err != nil {
			// Neither tokens nor payloads enter logs.
			slog.Debug("Overlay incoming flow ended with an error")
		}
	}()
}

func (a *Agent) serveIncoming(ctx context.Context, in *overlay.Incoming, src netip.Addr, admission *relayAdmission) error {
	result, reason := "failed", "relay setup"
	if !in.Signal {
		defer func() {
			if result != "allowed" {
				a.logRelay("incoming", src, in.Proto, in.Port, result, reason)
			}
		}()
	}
	hello := &overlay.Hello{Version: a.wireVersion(), Kind: overlay.KindAccept, ID: in.ID}
	hub, reply, err := a.dialHubStream(ctx, hello, admission)
	if err != nil {
		return err
	}
	if in.Signal {
		if in.Port != overlay.LinkPort || in.Proto != overlay.ProtoTCP || !reply.Secure || reply.Fingerprint == "" {
			closeConn(hub)
			return errors.New("invalid direct signaling request")
		}
		a.answerLink(ctx, hub, src, in.PeerID, reply.Fingerprint)
		return nil
	}
	if overlay.FirewallBlocked(a.cfg.RelayFirewall, in.PeerID, in.Proto, in.Port) {
		result, reason = "blocked", "relay firewall"
		closeConn(hub)
		return nil
	}
	reason = "peer stream"
	flow, err := a.seal(ctx, hub, &reply, false)
	if err != nil {
		return err
	}
	if in.Port == overlay.LinkPort && in.Proto == overlay.ProtoTCP {
		closeConn(flow)
		return errors.New("direct signaling requires the signal stream kind")
	}
	flow, err = a.trackRelay(ctx, admission, flow)
	if err != nil {
		return err
	}
	if a.cfg.Compression {
		flow = overlay.Compressed(flow)
	}
	local, err := a.cfg.DialLocal(ctx, in.Proto, in.Port, src)
	if err != nil {
		reason = "local service unavailable"
		closeConn(flow)
		return err
	}
	if err := ctx.Err(); err != nil {
		closeConn(local)
		closeConn(flow)
		return err
	}
	result = "allowed"
	a.logRelay("incoming", src, in.Proto, in.Port, result, "")
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
