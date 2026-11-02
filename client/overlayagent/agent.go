// Package overlayagent is the client side of the private overlay network.
// It registers a connected session with the hub as broadcasting, tracks the
// peer list, answers incoming flows and opens outgoing flows to peers.
// It is platform independent: callers supply how streams reach the hub and
// where incoming flows end up locally.
package overlayagent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const (
	// maxIncoming bounds concurrently handled incoming flows, including their handshakes.
	maxIncoming = 128
	maxPeers    = 4096
	maxReason   = 128
)

// Config wires an Agent to its platform.
type Config struct {
	// Identity is the persistent private key enrolled with the hub.
	Identity *ecdsa.PrivateKey
	// Dial opens one stream to the hub through an authenticated VPN session.
	// The caller must enforce this: the handshake does not authenticate the hub
	// or protect the stream against an active intermediary.
	Dial func(ctx context.Context) (net.Conn, error)
	// DialLocal completes an INCOMING flow locally. For UDP it returns a
	// connected net.Conn whose Read and Write each carry one datagram.
	DialLocal func(ctx context.Context, proto string, port uint16, src netip.Addr) (net.Conn, error)
	// OnState receives every state change. It must not block.
	OnState func(overlay.State)
	// Compression DEFLATEs flow bytes in chunks (see overlay.Compressed). Default
	// off. Both peers of a flow must enable it, because the hub relays bytes unchanged.
	Compression bool
	// DisableEncryption turns off end-to-end encryption. By default every flow
	// is encrypted between the two agents with TLS 1.3 (or QUIC on a direct
	// connection), and a flow whose peer does not support encryption fails.
	DisableEncryption bool
	// Direct lets flows bypass the hub when both peers enable it. Nil (the
	// default) keeps every flow on the relay.
	Direct *DirectOptions
}

// DirectOptions configures direct connections. Two peers connect directly
// over the internet with QUIC when both enable it, and the hub then relays
// nothing. It needs encryption. A direct flow that fails to connect fails; it
// never falls back to the relay.
type DirectOptions struct {
	// STUNServers lists host:port STUN servers, asked from outside the VPN to
	// learn the public UDP endpoint. At least one is required.
	STUNServers []string
	// ListenPacket opens the UDP socket for direct connections. Return a socket
	// that bypasses the VPN. Nil listens on all addresses, any port.
	ListenPacket func(ctx context.Context) (net.PacketConn, error)
	// Timeout bounds how long a direct connection may take to come up.
	// Zero means ten seconds.
	Timeout time.Duration
}

type timing struct {
	ping, liveness, handshake, backoffMin, backoffMax, udpIdle time.Duration
}

var defaultTiming = timing{
	ping:       30 * time.Second,
	liveness:   75 * time.Second,
	handshake:  10 * time.Second,
	backoffMin: time.Second,
	backoffMax: 30 * time.Second,
	udpIdle:    2 * time.Minute,
}

// Agent is one session's overlay participant. Create it with New and run it once.
type Agent struct {
	cfg       Config
	publicKey string
	timing    timing

	emitMu sync.Mutex // serializes snapshot-and-publish so states stay ordered

	mu        sync.Mutex
	ip        netip.Addr
	name      string
	connected bool
	reason    string
	peers     []overlay.Peer
	peerSet   map[netip.Addr]struct{}
	ready     chan netip.Addr
	readyOnce sync.Once
	started   bool

	flows    sync.WaitGroup
	inflight chan struct{}

	identity    *identity // flow certificate; nil when encryption is off or unavailable
	identityErr error
	direct      atomic.Pointer[direct]
}

// New builds an idle agent using its enrolled identity.
func New(cfg Config) *Agent {
	publicKey, identityErr := overlay.PublicIdentity(cfg.Identity)
	a := &Agent{
		cfg:         cfg,
		publicKey:   publicKey,
		identityErr: identityErr,
		timing:      defaultTiming,
		peerSet:     map[netip.Addr]struct{}{},
		ready:       make(chan netip.Addr, 1),
		inflight:    make(chan struct{}, maxIncoming),
	}
	if !cfg.DisableEncryption {
		var err error
		a.identity, err = newIdentity()
		a.identityErr = errors.Join(a.identityErr, err)
	}
	return a
}

// IP returns this account's overlay address, or the zero Addr before the first registration.
func (a *Agent) IP() netip.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ip
}

// Ready delivers the overlay address once at the first successful registration
// and is then closed. Receive once; afterwards use IP.
func (a *Agent) Ready() <-chan netip.Addr { return a.ready }

// Run keeps the control stream registered with the hub until ctx ends.
// It returns ctx.Err() after every goroutine it started has stopped.
func (a *Agent) Run(ctx context.Context) error {
	if a.cfg.Dial == nil || a.cfg.DialLocal == nil || a.cfg.Identity == nil {
		return errors.New("overlay agent is not configured")
	}
	if a.identityErr != nil {
		return errors.New("overlay identity or flow certificate is invalid")
	}
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return errors.New("overlay agent already ran")
	}
	a.started = true
	runCtx, cancel := context.WithCancel(ctx)
	a.mu.Unlock()
	defer func() {
		cancel()
		a.flows.Wait()
	}()
	a.startDirect(runCtx)

	a.emit()
	delay := a.timing.backoffMin
	for {
		registered, reason := a.session(runCtx)
		a.disconnected(reason)
		if runCtx.Err() != nil {
			return ctx.Err()
		}
		if registered {
			delay = a.timing.backoffMin
		}
		timer := time.NewTimer(delay)
		select {
		case <-runCtx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		delay = min(delay*2, a.timing.backoffMax)
	}
}

// session runs one control connection and reports whether the hub accepted it
// and, if not, a short nonsecret reason.
func (a *Agent) session(ctx context.Context) (registered bool, reason string) {
	conn, err := a.cfg.Dial(ctx)
	if err != nil {
		slog.Debug("Overlay hub dial failed")
		return false, "overlay hub is unreachable"
	}
	defer closeConn(conn)
	reply, err := a.handshake(ctx, conn, &overlay.Hello{Version: overlay.Version, Kind: overlay.KindControl})
	if err != nil {
		slog.Debug("Overlay control handshake failed")
		return false, "overlay hub is unreachable"
	}
	if !reply.OK {
		return false, boundedReason(reply.Error)
	}
	ip, err := netip.ParseAddr(reply.IP)
	if err != nil || !overlay.Assignable(ip) {
		return false, "overlay hub assigned an invalid address"
	}
	a.registered(ip, reply.Name)

	sctx, cancel := context.WithCancel(ctx)
	stopClose := context.AfterFunc(sctx, func() { closeConn(conn) })
	var pinger sync.WaitGroup
	pinger.Add(1)
	go func() {
		defer pinger.Done()
		defer cancel()
		a.ping(sctx, conn)
	}()
	a.readEvents(ctx, conn)
	cancel()
	stopClose()
	closeConn(conn)
	pinger.Wait()
	return true, "overlay hub connection was lost"
}

// handshake sends hello and reads the hub's reply within the handshake bound.
// The deadline is cleared on success so the stream can live on.
func (a *Agent) handshake(ctx context.Context, conn net.Conn, hello *overlay.Hello) (overlay.Reply, error) {
	var reply overlay.Reply
	stop := context.AfterFunc(ctx, func() { closeConn(conn) })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(a.timing.handshake)); err != nil {
		return reply, err
	}
	hello.PublicKey = a.publicKey
	if err := overlay.WriteFrame(conn, hello); err != nil {
		return reply, err
	}
	var challenge overlay.Challenge
	if err := overlay.ReadFrame(conn, &challenge); err != nil {
		return reply, err
	}
	nonce, err := hex.DecodeString(challenge.Nonce)
	if err != nil || len(nonce) != 32 {
		return reply, errors.New("invalid overlay challenge")
	}
	digest := sha512.Sum384(append([]byte("overlay-relay/auth/v2:"), nonce...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.cfg.Identity, digest[:])
	if err != nil {
		return reply, err
	}
	if err := overlay.WriteFrame(conn, overlay.Proof{Signature: hex.EncodeToString(signature)}); err != nil {
		return reply, err
	}
	if err := overlay.ReadFrame(conn, &reply); err != nil {
		return reply, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return reply, err
	}
	return reply, ctx.Err()
}

func (a *Agent) ping(ctx context.Context, conn net.Conn) {
	ticker := time.NewTicker(a.timing.ping)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := conn.SetWriteDeadline(time.Now().Add(a.timing.handshake)); err != nil {
			return
		}
		if err := overlay.WriteFrame(conn, overlay.Ping{Ping: true}); err != nil {
			return
		}
	}
}

// readEvents consumes hub events until the stream fails. A silent hub is
// detected by the liveness deadline: pings are answered with a Pong.
func (a *Agent) readEvents(ctx context.Context, conn net.Conn) {
	for {
		if err := conn.SetReadDeadline(time.Now().Add(a.timing.liveness)); err != nil {
			return
		}
		var event overlay.Event
		if err := overlay.ReadFrame(conn, &event); err != nil {
			return
		}
		switch {
		case event.Peers != nil:
			a.setPeers(*event.Peers)
		case event.Incoming != nil:
			a.accept(ctx, event.Incoming)
		}
	}
}

func (a *Agent) registered(ip netip.Addr, name string) {
	a.mu.Lock()
	a.ip, a.name, a.connected, a.reason = ip, name, true, ""
	first := a.ready
	a.mu.Unlock()
	a.readyOnce.Do(func() {
		first <- ip
		close(first)
	})
	a.emit()
}

func (a *Agent) disconnected(reason string) {
	a.mu.Lock()
	a.connected, a.reason = false, reason
	a.peers, a.peerSet = nil, map[netip.Addr]struct{}{}
	a.mu.Unlock()
	a.emit()
}

func (a *Agent) setPeers(peers []overlay.Peer) {
	kept := make([]overlay.Peer, 0, len(peers))
	set := make(map[netip.Addr]struct{}, len(peers))
	for _, peer := range peers {
		ip, err := netip.ParseAddr(peer.IP)
		if err != nil || !overlay.Assignable(ip) {
			continue
		}
		if _, duplicate := set[ip]; duplicate || len(kept) == maxPeers {
			continue
		}
		set[ip] = struct{}{}
		kept = append(kept, peer)
	}
	a.mu.Lock()
	a.peers, a.peerSet = kept, set
	a.mu.Unlock()
	a.emit()
}

// emit publishes the current state. The snapshot is taken under emitMu so
// consumers observe states in the order they were produced.
func (a *Agent) emit() {
	if a.cfg.OnState == nil {
		return
	}
	a.emitMu.Lock()
	defer a.emitMu.Unlock()
	a.mu.Lock()
	state := overlay.State{
		Available:    true,
		Broadcasting: true,
		Connected:    a.connected,
		Reason:       a.reason,
		Name:         a.name,
		Peers:        append([]overlay.Peer{}, a.peers...),
	}
	if a.ip.IsValid() {
		state.IP = a.ip.String()
	}
	a.mu.Unlock()
	a.cfg.OnState(state)
}

func boundedReason(text string) string {
	runes := make([]rune, 0, len(text))
	for _, r := range text {
		if r < ' ' || r == 0x7f || len(runes) == maxReason {
			break
		}
		runes = append(runes, r)
	}
	if len(runes) == 0 {
		return "overlay hub rejected this account"
	}
	return string(runes)
}

func closeConn(c net.Conn) {
	// Repeated closes from cancellation, teardown and the normal path are expected.
	_ = c.Close()
}
