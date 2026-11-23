package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const (
	hubMaxFlows   = 256
	hubMaxPending = 4
)

type hubOpen struct {
	destination netip.Addr
	offer       hubOffer
	signal, udp bool
}

func parseHubOpen(hello *overlay.Hello) (hubOpen, bool) {
	dst, err := netip.ParseAddr(hello.Dst)
	if err != nil || !dst.Is4() || hello.Port == 0 ||
		(hello.Proto != overlay.ProtoTCP && hello.Proto != overlay.ProtoUDP) {
		return hubOpen{}, false
	}
	offer, ok := parseHubOffer(hello.Fingerprint, hello.Endpoint)
	if !ok {
		return hubOpen{}, false
	}
	signal := hello.Kind == overlay.KindSignal
	udp := hello.Proto == overlay.ProtoUDP
	if signal != (hello.Port == overlay.LinkPort) || (signal && (udp || offer.fingerprint == "" || offer.endpoint != "")) {
		return hubOpen{}, false
	}
	return hubOpen{destination: dst, signal: signal, udp: udp, offer: offer}, true
}

type hubPending struct {
	id       string
	from     string
	sourceIP netip.Addr
	target   *hubControl
	claimed  chan hubAccepted
}

type hubAccepted struct {
	conn  net.Conn
	offer hubOffer
}

type hubIncoming struct {
	Signal bool   `json:"signal"`
	PeerID string `json:"peer_id"`
	ID     string `json:"id"`
	Proto  string `json:"proto"`
	Src    string `json:"src"`
	Port   uint16 `json:"port"`

	Fingerprint string `json:"fingerprint,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
}

func (h *hubRuntime) serveOpen(ctx context.Context, conn net.Conn, id string, room hubRoom, hello *overlay.Hello) {
	request, ok := parseHubOpen(hello)
	if !ok || !h.flowPermitted(room, request.signal) {
		hubRefuse(conn, overlay.ErrUnavailable)
		return
	}
	pending := h.admitOpen(id, room.capability, hello, request)
	if pending == nil {
		hubRefuse(conn, overlay.ErrUnavailable)
		return
	}
	answer := h.awaitAccept(ctx, pending)
	if answer.conn == nil {
		if ctx.Err() == nil {
			hubRefuse(conn, overlay.ErrUnavailable)
		}
		return
	}
	acceptor := answer.conn
	stop := context.AfterFunc(ctx, func() { _ = acceptor.Close() })
	defer func() {
		stop()
		_ = acceptor.Close()
	}()
	if !request.signal && request.offer.endpoint != "" && answer.offer.endpoint != "" {
		pairHubStreams(conn, acceptor, pending.id, request.offer, answer.offer)
		return
	}
	// Subscribe before rechecking the room; a policy update between the
	// check and pairing must be observed by the active flow as well.
	changed := h.policyChanges()
	if !h.flowPermitted(room, request.signal) || !h.startFlow(pending) {
		hubRefuse(conn, overlay.ErrUnavailable)
		hubRefuse(acceptor, overlay.ErrUnavailable)
		return
	}
	defer h.finishFlow(pending)
	if pairHubStreams(conn, acceptor, pending.id, request.offer, answer.offer) {
		h.runFlow(ctx, conn, acceptor, changed, room, request, hello.Version, pending.target.version)
	}
}

func pairHubStreams(left, right net.Conn, id string, own, peer hubOffer) bool {
	return sendHubFrame(left, hubPairReply(id, own, peer)) == nil &&
		sendHubFrame(right, hubPairReply(id, peer, own)) == nil
}

func (h *hubRuntime) flowPermitted(room hubRoom, signal bool) bool {
	if signal {
		if room.id == "" {
			return true
		}
		_, _, failure := h.store.admitRoom(room.id, room.proof)
		return failure == ""
	}
	allowed, err := h.store.roomRelay(room.capability)
	return err == nil && allowed
}

func (h *hubRuntime) admitOpen(id, room string, hello *overlay.Hello, request hubOpen) *hubPending {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil
	}
	requestID := hex.EncodeToString(nonce[:])
	h.mu.Lock()
	defer h.mu.Unlock()
	from, target := h.controls[id], h.byIP[request.destination]
	if !hubControlInRoom(from, room) || !hubControlInRoom(target, room) || from == target ||
		(hello.PeerID != "" && hello.PeerID != target.id) || h.activeCount[id] >= hubMaxFlows ||
		h.activeCount[target.id] >= hubMaxFlows || h.pendingCount[target.id] >= hubMaxPending ||
		h.pending[requestID] != nil {
		return nil
	}
	incoming := hubIncoming{
		Signal: request.signal, PeerID: from.id, ID: requestID, Proto: hello.Proto,
		Src: from.ip.String(), Port: hello.Port, Fingerprint: request.offer.fingerprint,
		Endpoint: request.offer.endpoint,
	}
	if !target.enqueue(struct {
		Incoming hubIncoming `json:"incoming"`
	}{incoming}) {
		return nil
	}
	pending := &hubPending{id: requestID, from: id, sourceIP: from.ip, target: target, claimed: make(chan hubAccepted, 1)}
	h.pending[requestID] = pending
	h.pendingCount[target.id]++
	return pending
}

func hubControlInRoom(control *hubControl, room string) bool {
	return control != nil && control.ctx.Err() == nil && control.room.capability == room
}

// Both addresses advertised in the offer must still belong to the same live
// identities at acceptance and pairing. Caller holds h.mu.
func (h *hubRuntime) pendingEndpointsLive(p *hubPending) bool {
	room := p.target.room.capability
	from, to := h.controls[p.from], h.controls[p.target.id]
	return hubControlInRoom(from, room) && from.ip == p.sourceIP &&
		hubControlInRoom(to, room) && to.ip == p.target.ip
}

func (h *hubRuntime) serveAccept(conn net.Conn, id string, room hubRoom, hello *overlay.Hello) bool {
	offer, ok := parseHubOffer(hello.Fingerprint, hello.Endpoint)
	if !ok {
		hubRefuse(conn, hubInvalid)
		return false
	}
	if !h.claimPending(hello.ID, id, room.capability, hubAccepted{conn, offer}) {
		hubRefuse(conn, hubUnauthorized)
		return false
	}
	return true
}

func (h *hubRuntime) claimPending(requestID, id, room string, answer hubAccepted) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	pending := h.pending[requestID]
	if pending == nil || pending.target.id != id || pending.target.room.capability != room ||
		!h.pendingEndpointsLive(pending) {
		return false
	}
	// The transfer and pending removal are atomic with respect to the waiter:
	// if it sees no pending entry, the accept connection is already queued.
	h.removePendingLocked(pending)
	pending.claimed <- answer
	return true
}

func (h *hubRuntime) removePendingLocked(pending *hubPending) {
	delete(h.pending, pending.id)
	h.pendingCount[pending.target.id]--
	if h.pendingCount[pending.target.id] == 0 {
		delete(h.pendingCount, pending.target.id)
	}
}

func (h *hubRuntime) awaitAccept(ctx context.Context, pending *hubPending) hubAccepted {
	timer := time.NewTimer(h.timing.accept)
	defer timer.Stop()
	var answer hubAccepted
	select {
	case answer = <-pending.claimed:
	case <-timer.C:
	case <-ctx.Done():
	}
	if answer.conn == nil {
		h.mu.Lock()
		if h.pending[pending.id] == pending {
			h.removePendingLocked(pending)
		} else {
			answer = <-pending.claimed
		}
		h.mu.Unlock()
	}
	if answer.conn != nil && ctx.Err() != nil {
		_ = answer.conn.Close()
		return hubAccepted{}
	}
	return answer
}

func (h *hubRuntime) startFlow(pending *hubPending) bool {
	// Pin both live assignments before another identify can reclaim them.
	h.registration.Lock()
	defer h.registration.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	from, to := pending.from, pending.target.id
	if !h.pendingEndpointsLive(pending) ||
		h.activeCount[from] >= hubMaxFlows || h.activeCount[to] >= hubMaxFlows {
		return false
	}
	h.activeCount[from]++
	h.activeCount[to]++
	return true
}

func (h *hubRuntime) finishFlow(pending *hubPending) {
	ids := [2]string{pending.from, pending.target.id}
	now := hubUnixNow()
	for _, id := range ids {
		h.store.touch(id, now)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, id := range ids {
		h.activeCount[id]--
		if h.activeCount[id] == 0 {
			delete(h.activeCount, id)
		}
	}
}

func (h *hubRuntime) runFlow(ctx context.Context, left, right net.Conn, changed <-chan struct{}, room hubRoom, request hubOpen, leftWire, rightWire int) {
	var activity hubActivity
	var ticks <-chan time.Time
	if request.udp {
		activity.base = time.Now()
		ticker := time.NewTicker(max(h.timing.udpIdle/4, time.Millisecond))
		defer ticker.Stop()
		ticks = ticker.C
	}
	forward := func(src, dst net.Conn, wire int) error {
		if request.signal {
			return forwardHubSignal(src, dst, wire)
		}
		var output io.Writer = dst
		if request.udp {
			output = hubActivityWriter{dst, &activity}
		}
		if _, err := io.Copy(output, src); err != nil {
			return err
		}
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			return half.CloseWrite()
		}
		return dst.Close()
	}
	if request.signal {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, hubSignalTimeout)
		defer cancel()
	}
	results := make(chan error, 2)
	go func() { results <- forward(left, right, leftWire) }()
	go func() { results <- forward(right, left, rightWire) }()
	remaining := 2
	defer func() {
		_ = left.Close()
		_ = right.Close()
		for range remaining {
			<-results
		}
	}()
	for remaining != 0 {
		select {
		case err := <-results:
			remaining--
			if request.signal || err != nil {
				return
			}
		case <-ctx.Done():
			return
		case <-changed:
			changed = h.policyChanges()
			if !h.flowPermitted(room, request.signal) {
				return
			}
		case <-ticks:
			if time.Since(activity.base)-time.Duration(activity.last.Load()) >= h.timing.udpIdle {
				return
			}
		}
	}
}

type hubActivity struct {
	base time.Time
	last atomic.Int64
}

type hubActivityWriter struct {
	io.Writer
	activity *hubActivity
}

func (w hubActivityWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		elapsed := int64(time.Since(w.activity.base))
		for last := w.activity.last.Load(); elapsed > last; last = w.activity.last.Load() {
			if w.activity.last.CompareAndSwap(last, elapsed) {
				break
			}
		}
	}
	return n, err
}
