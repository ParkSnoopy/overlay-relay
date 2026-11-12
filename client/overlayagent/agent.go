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
	// directRetryAfter is how long a peer whose direct connection failed is
	// served by the relay before a direct connection is offered again.
	directRetryAfter = 5 * time.Minute
	maxPeers         = 4096
	maxReason        = 128
)

// Config wires an Agent to its platform.
type Config struct {
	// CIDR optionally pins a range the caller already received from the hub.
	// It is never sent to the hub. When unset, the agent adopts the range from
	// the hub's first accepted reply and reports it through OnRange.
	CIDR netip.Prefix
	// OnRange is called once, without the agent's locks held, when the hub's
	// range becomes known. The caller installs its routes for the range here.
	OnRange func(netip.Prefix)
	// Room is the password proof derived with overlay.RoomToken.
	Room string
	// RoomID names the private room; it is required with Room.
	RoomID string
	// Name is this device's advertised name. Empty uses the hub's default.
	Name string
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
	// is encrypted between the two agents with TLS 1.3, and a flow whose peer
	// does not support encryption fails.
	DisableEncryption bool
	// Direct lets flows bypass the hub when both peers enable it. Nil (the
	// default) keeps every flow on the relay.
	Direct *DirectOptions
	// RelayOnly lists device IDs that must never use direct transport.
	RelayOnly []string
	// DirectPeers is the explicit direct allowlist. Empty permits relay only.
	DirectPeers []string
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
	roomName  string
	connected bool
	reason    string
	peers     []overlay.Peer
	peerSet   map[netip.Addr]struct{}
	ready     chan netip.Addr
	readyOnce sync.Once
	started   bool
	// directBlocked holds peers whose direct connection failed, until when.
	directBlocked map[netip.Addr]time.Time
	relayOnly     map[string]bool
	directPeers   map[string]bool
	active        map[*peerFlow]struct{}
	observations  map[netip.Addr]peerObservation
	// links holds the live direct link per peer; linking holds negotiations in progress.
	links   map[netip.Addr]*peerLink
	linking map[netip.Addr]*linkAttempt
	runCtx  context.Context

	flows    sync.WaitGroup
	inflight chan struct{}

	rng         atomic.Pointer[netip.Prefix] // hub range; nil until the hub assigns it
	identity    *identity                    // flow certificate; nil when encryption is off or unavailable
	identityErr error
	direct      atomic.Pointer[directState]
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
	a.identityErr = errors.Join(a.identityErr, a.SetRelayOnly(cfg.RelayOnly), overlay.ValidateName(cfg.Name))
	if cfg.CIDR.IsValid() {
		prefix, rangeErr := overlay.ParseCIDR(cfg.CIDR.String())
		a.identityErr = errors.Join(a.identityErr, rangeErr)
		a.rng.Store(&prefix)
	}
	a.identityErr = errors.Join(a.identityErr, a.SetDirectPeers(cfg.DirectPeers))
	if cfg.Room != "" && (!overlay.ValidPeerID(cfg.Room) || cfg.RoomID == "" || overlay.ValidateName(cfg.RoomID) != nil) || cfg.Room == "" && cfg.RoomID != "" {
		a.identityErr = errors.Join(a.identityErr, errors.New("invalid overlay room"))
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
	a.runCtx = runCtx
	a.mu.Unlock()
	defer func() {
		cancel()
		a.flows.Wait()
		if d := a.direct.Load(); d != nil {
			d.close()
		}
	}()
	a.startDirect()

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
	reply, err := a.handshake(ctx, conn, &overlay.Hello{Version: overlay.Version, Kind: overlay.KindControl, Name: a.cfg.Name})
	if err != nil {
		slog.Debug("Overlay control handshake failed")
		return false, "overlay hub is unreachable"
	}
	if !reply.OK {
		return false, boundedReason(reply.Error)
	}
	ip, err := netip.ParseAddr(reply.IP)
	prefix, rangeErr := overlay.ParseCIDR(reply.CIDR)
	if err != nil || rangeErr != nil || reply.CIDR != prefix.String() || !overlay.AssignableIn(prefix, ip) {
		return false, "overlay hub assigned an invalid address"
	}
	if !a.pinRange(prefix) {
		return false, "overlay hub changed its address range"
	}
	a.registered(ip, reply.Name, reply.RoomName)

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
	hello.Room, hello.RoomID = a.cfg.Room, a.cfg.RoomID
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
	message := append(append([]byte("overlay-relay/auth/v3:"), nonce...), []byte(hello.Room)...)
	if hello.Room != "" {
		message = append(append(message, 0), []byte(hello.RoomID)...)
	}
	digest := sha512.Sum384(message)
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

// DiscoverCIDR authenticates through the selected transport and reads the hub's
// assigned range before the application installs its routes. No client range
// is sent. The temporary control connection closes before the session starts.
func DiscoverCIDR(ctx context.Context, cfg Config) (netip.Prefix, error) {
	a := New(cfg)
	if a.identityErr != nil || cfg.Dial == nil || cfg.Identity == nil {
		return netip.Prefix{}, errors.New("overlay discovery is not configured")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := cfg.Dial(ctx)
	if err != nil {
		return netip.Prefix{}, errors.New("overlay hub is unreachable")
	}
	defer closeConn(conn)
	stop := context.AfterFunc(ctx, func() { closeConn(conn) })
	defer stop()
	reply, err := a.handshake(ctx, conn, &overlay.Hello{Version: overlay.Version, Kind: overlay.KindControl, Name: cfg.Name})
	if err != nil {
		return netip.Prefix{}, errors.New("overlay discovery failed")
	}
	if !reply.OK {
		return netip.Prefix{}, errors.New(boundedReason(reply.Error))
	}
	prefix, err := overlay.ParseCIDR(reply.CIDR)
	ip, ipErr := netip.ParseAddr(reply.IP)
	if err != nil || reply.CIDR != prefix.String() || ipErr != nil || !overlay.AssignableIn(prefix, ip) {
		return netip.Prefix{}, errors.New("overlay hub assigned an invalid address")
	}
	return prefix, nil
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

// Range is the hub's address space, or the zero prefix before the hub has
// assigned one.
func (a *Agent) Range() netip.Prefix {
	if prefix := a.rng.Load(); prefix != nil {
		return *prefix
	}
	return netip.Prefix{}
}

// pinRange fixes the range on first use and reports whether prefix is the
// pinned range. A hub that later answers with another range is refused, because
// the caller's routes were installed for the first one.
func (a *Agent) pinRange(prefix netip.Prefix) bool {
	if a.rng.CompareAndSwap(nil, &prefix) {
		if a.cfg.OnRange != nil {
			a.cfg.OnRange(prefix)
		}
		return true
	}
	return a.Range() == prefix
}

func (a *Agent) registered(ip netip.Addr, name, roomName string) {
	a.mu.Lock()
	a.ip, a.name, a.roomName, a.connected, a.reason = ip, name, roomName, true, ""
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
	a.observations, a.directBlocked = nil, nil
	a.mu.Unlock()
	a.closeLinks(nil)
	a.emit()
}

func (a *Agent) setPeers(peers []overlay.Peer) {
	kept := make([]overlay.Peer, 0, len(peers))
	set := make(map[netip.Addr]struct{}, len(peers))
	for _, peer := range peers {
		ip, err := netip.ParseAddr(peer.IP)
		if err != nil || !overlay.AssignableIn(a.Range(), ip) {
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
	for ip, observation := range a.observations {
		if _, exists := set[ip]; !exists || a.peerIDLocked(ip) != observation.id {
			delete(a.observations, ip)
			delete(a.directBlocked, ip)
		}
	}
	a.mu.Unlock()
	ids := make(map[netip.Addr]string, len(kept))
	for _, peer := range kept {
		ip, _ := netip.ParseAddr(peer.IP)
		ids[ip] = peer.ID
	}
	a.closeLinks(func(ip netip.Addr, id string) bool { return ids[ip] == id })
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
		RoomName:     a.roomName,
		Peers:        append([]overlay.Peer{}, a.peers...),
	}
	for i := range state.Peers {
		peer := &state.Peers[i]
		peer.DirectFlows, peer.RelayFlows = 0, 0
		peer.DirectAllowed = a.cfg.Direct != nil && overlay.ValidPeerID(peer.ID) && !a.relayOnlyLocked(peer.ID)
		peer.DirectStatus, peer.LastPath = "", ""
		if ip, err := netip.ParseAddr(peer.IP); err == nil {
			if observation := a.observations[ip]; observation.id == peer.ID {
				peer.DirectStatus, peer.LastPath = observation.status, observation.path
			}
		}
		for flow := range a.active {
			if flow.peerID == peer.ID && flow.ip.String() == peer.IP {
				if flow.direct {
					peer.DirectFlows++
				} else {
					peer.RelayFlows++
				}
			}
		}
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
