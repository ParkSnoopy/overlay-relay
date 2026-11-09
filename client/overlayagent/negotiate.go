package overlayagent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

// Messages on the negotiation stream, which is an encrypted relayed flow to
// overlay.LinkPort. Each is one length-prefixed JSON frame.
const (
	msgHello  = "hello"  // both: the methods this side supports, in preference order
	msgOffer  = "offer"  // initiator: a method and its offer
	msgAnswer = "answer" // responder: the same method and its answer
	msgPing   = "ping"   // initiator: measure the round trip
	msgPong   = "pong"   // responder: reply to ping
	msgSync   = "sync"   // initiator: both sides start connecting now
	msgDone   = "done"   // initiator: the link is up
	msgNext   = "next"   // initiator: the method failed; drop it
	msgEnd    = "end"    // initiator: no method is left
	msgFail   = "fail"   // responder: refuses the request
)

var errNoLink = errors.New("overlay peer does not answer direct link negotiation")

type linkMessage struct {
	Type    string          `json:"t"`
	Methods []string        `json:"m,omitempty"`
	Method  string          `json:"s,omitempty"`
	Data    json.RawMessage `json:"d,omitempty"`
	Error   string          `json:"e,omitempty"`
}

func writeLinkMessage(conn net.Conn, message *linkMessage) error {
	return overlay.WriteFrame(conn, message)
}

// readLinkMessage reads one message within wait.
func readLinkMessage(conn net.Conn, message *linkMessage, wait time.Duration) error {
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		return err
	}
	*message = linkMessage{}
	if err := overlay.ReadFrame(conn, message); err != nil {
		return err
	}
	return conn.SetReadDeadline(time.Time{})
}

// replyWait bounds the wait for the peer's next message: it may gather
// candidates and connect before it answers.
func (a *Agent) replyWait(d *directState) time.Duration {
	return d.timeout + gatherTimeout + a.timing.handshake
}

// negotiate brings up a link to ip as the initiator. It tries the methods both
// sides support, in this side's order, over one relayed stream.
func (a *Agent) negotiate(ctx context.Context, d *directState, ip netip.Addr, peerID string) (link, error) {
	conn, fingerprint, err := a.openFlow(ctx, overlay.ProtoTCP, ip, overlay.LinkPort, peerID)
	if err != nil {
		return nil, errNoLink
	}
	defer closeConn(conn)
	stop := context.AfterFunc(ctx, func() { closeConn(conn) })
	defer stop()
	if err := writeLinkMessage(conn, &linkMessage{Type: msgHello, Methods: d.names()}); err != nil {
		return nil, errNoLink
	}
	var hello linkMessage
	if err := readLinkMessage(conn, &hello, a.timing.handshake); err != nil || hello.Type != msgHello {
		return nil, errNoLink
	}
	shared := d.common(hello.Methods)
	if len(shared) == 0 {
		return nil, errNoMethod
	}
	peer := &linkPeer{id: peerID, fingerprint: fingerprint, initiator: true}
	for _, name := range shared {
		l, err := a.attempt(ctx, d, conn, peer, d.method(name))
		if err == nil {
			_ = writeLinkMessage(conn, &linkMessage{Type: msgDone, Method: name})
			return l, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		slog.Debug("Overlay direct method failed", "method", name, "err", err)
		_ = writeLinkMessage(conn, &linkMessage{Type: msgNext})
	}
	_ = writeLinkMessage(conn, &linkMessage{Type: msgEnd})
	return nil, errDirectFailed
}

// attempt runs one method: offer, answer, synchronized start, connect.
func (a *Agent) attempt(ctx context.Context, d *directState, conn net.Conn, peer *linkPeer, m method) (link, error) {
	sess, offer, err := m.offer(ctx, peer)
	if err != nil {
		return nil, err
	}
	up := false
	defer func() {
		if !up {
			sess.close()
		}
	}()
	if err := writeLinkMessage(conn, &linkMessage{Type: msgOffer, Method: m.name(), Data: offer}); err != nil {
		return nil, err
	}
	var reply linkMessage
	if err := readLinkMessage(conn, &reply, a.replyWait(d)); err != nil {
		return nil, err
	}
	if reply.Type != msgAnswer || reply.Method != m.name() {
		return nil, errors.New("overlay peer refused the direct method")
	}
	if err := sess.apply(reply.Data); err != nil {
		return nil, err
	}
	var delay time.Duration
	if m.syncs() {
		start := time.Now()
		if err := writeLinkMessage(conn, &linkMessage{Type: msgPing}); err != nil {
			return nil, err
		}
		if err := readLinkMessage(conn, &reply, a.timing.handshake); err != nil || reply.Type != msgPong {
			return nil, errors.New("overlay peer did not answer the round trip probe")
		}
		delay = time.Since(start) / 2
	}
	if err := writeLinkMessage(conn, &linkMessage{Type: msgSync}); err != nil {
		return nil, err
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	connectCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	l, err := sess.connect(connectCtx)
	if err != nil {
		return nil, err
	}
	up = true
	return l, nil
}

type connectResult struct {
	link link
	err  error
}

// responder tracks the method attempt the initiator is currently driving.
type responder struct {
	sess   session
	cancel context.CancelFunc
	result chan connectResult // set by start
}

// start begins connecting. Calling it again does nothing.
func (r *responder) start(ctx context.Context, timeout time.Duration) {
	if r == nil || r.result != nil {
		return
	}
	r.result = make(chan connectResult, 1)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	r.cancel = func() { cancel() }
	go func() {
		defer cancel()
		l, err := r.sess.connect(ctx)
		r.result <- connectResult{link: l, err: err}
	}()
}

// stop ends the attempt and discards a link it already brought up.
func (r *responder) stop() {
	if r == nil {
		return
	}
	if r.cancel != nil {
		r.cancel()
	}
	r.sess.close()
	if r.result != nil {
		if got := <-r.result; got.err == nil {
			got.link.close()
		}
	}
}

// await waits for the connect started by start and hands over its link.
func (r *responder) await(ctx context.Context) (link, error) {
	if r == nil || r.result == nil {
		return nil, errNoLink
	}
	select {
	case got := <-r.result:
		return got.link, got.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// answerLink serves a negotiation stream as the responder. The stream is
// already sealed and its peer pinned; answerLink owns closing it.
func (a *Agent) answerLink(ctx context.Context, conn net.Conn, ip netip.Addr, peerID, fingerprint string) {
	defer closeConn(conn)
	d := a.direct.Load()
	a.mu.Lock()
	denied := d == nil || a.relayOnlyLocked(peerID) || a.peerIDLocked(ip) != peerID
	a.mu.Unlock()
	if denied {
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	attempt := &linkAttempt{peerID: peerID, cancel: cancel}
	a.mu.Lock()
	if existing := a.linking[ip]; existing != nil {
		if existing.initiator && a.identity.fingerprint < fingerprint {
			// Both sides started at once: the lower certificate fingerprint keeps the initiator role.
			a.mu.Unlock()
			_ = writeLinkMessage(conn, &linkMessage{Type: msgFail, Error: "busy"})
			return
		}
		existing.cancel()
	}
	if a.linking == nil {
		a.linking = map[netip.Addr]*linkAttempt{}
	}
	a.linking[ip] = attempt
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		if a.linking[ip] == attempt {
			delete(a.linking, ip)
		}
		a.mu.Unlock()
	}()
	stop := context.AfterFunc(ctx, func() { closeConn(conn) })
	defer stop()

	var hello linkMessage
	if err := readLinkMessage(conn, &hello, a.timing.handshake); err != nil || hello.Type != msgHello {
		return
	}
	if err := writeLinkMessage(conn, &linkMessage{Type: msgHello, Methods: d.names()}); err != nil {
		return
	}
	peer := &linkPeer{id: peerID, fingerprint: fingerprint}
	var current *responder
	defer func() { current.stop() }()
	for {
		var message linkMessage
		if err := readLinkMessage(conn, &message, a.replyWait(d)); err != nil {
			return
		}
		switch message.Type {
		case msgOffer:
			current.stop()
			current = nil
			m := d.method(message.Method)
			if m == nil {
				_ = writeLinkMessage(conn, &linkMessage{Type: msgFail, Error: "unsupported method"})
				return
			}
			sess, answer, err := m.answer(ctx, peer, message.Data)
			if err != nil {
				_ = writeLinkMessage(conn, &linkMessage{Type: msgFail, Error: "method failed"})
				return
			}
			current = &responder{sess: sess}
			if err := writeLinkMessage(conn, &linkMessage{Type: msgAnswer, Method: m.name(), Data: answer}); err != nil {
				return
			}
		case msgPing:
			if err := writeLinkMessage(conn, &linkMessage{Type: msgPong}); err != nil {
				return
			}
		case msgSync:
			current.start(ctx, d.timeout)
		case msgDone:
			l, err := current.await(ctx)
			current = nil
			if err == nil {
				a.installLink(l, ip, peerID)
			}
			return
		case msgNext:
			current.stop()
			current = nil
		case msgEnd:
			a.recordDirect(ip, peerID, overlay.DirectFailed)
			return
		default:
			return
		}
	}
}
