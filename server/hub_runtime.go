package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const (
	hubUnauthorized = "unauthorized"
	hubInvalid      = "invalid request"
	hubRoomsOffline = "rooms are unavailable"
	hubPolicyTick   = 250 * time.Millisecond
)

type hubTiming struct {
	handshake, accept, controlIdle, udpIdle time.Duration
}

func defaultHubTiming() hubTiming {
	return hubTiming{10 * time.Second, 10 * time.Second, 90 * time.Second, 120 * time.Second}
}

type hubRuntime struct {
	store  *hubStore
	space  netip.Prefix
	timing hubTiming

	// Lock order is registration -> store -> live state. Only identify's busy
	// callback takes the live-state lock from inside a store call. Live-state
	// transitions themselves never call the store or wait on network I/O.
	registration sync.Mutex
	mu           sync.Mutex
	controls     map[string]*hubControl
	byIP         map[netip.Addr]*hubControl
	pending      map[string]*hubPending
	pendingCount map[string]int
	activeCount  map[string]int
	policyEpoch  chan struct{}
}

func newHubRuntime(store *hubStore, space netip.Prefix, timing hubTiming) *hubRuntime {
	return &hubRuntime{
		store: store, space: space, timing: timing,
		controls: make(map[string]*hubControl), byIP: make(map[netip.Addr]*hubControl),
		pending: make(map[string]*hubPending), pendingCount: make(map[string]int),
		activeCount: make(map[string]int), policyEpoch: make(chan struct{}),
	}
}

// serveHub takes ownership of the bound listener, including on startup failure.
func serveHub(ctx context.Context, listener net.Listener, directory string, hosts []string, space netip.Prefix) error {
	defer func() { _ = listener.Close() }()
	store, err := openHubStore(directory, space)
	if err != nil {
		return fmt.Errorf("open overlay state: %w", err)
	}
	return newHubRuntime(store, space, defaultHubTiming()).serve(ctx, listener, directory, hosts)
}

func (h *hubRuntime) serve(parent context.Context, listener net.Listener, directory string, hosts []string) error {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	var workers sync.WaitGroup
	defer func() {
		cancel()
		stop()
		workers.Wait()
	}()
	workers.Go(func() { h.watchPolicy(ctx, filepath.Join(directory, roomsFile)) })
	for ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept overlay connection: %w", err)
		}
		workers.Go(func() { h.serveConnection(ctx, conn, hosts) })
	}
	return nil
}

func hubSourceAdmitted(ctx context.Context, source net.Addr, hosts []string) bool {
	host, _, err := net.SplitHostPort(source.String())
	if err != nil {
		return false
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	remote = remote.WithZone("").Unmap()
	if len(hosts) == 0 {
		return remote.IsLoopback() || remote.IsPrivate() || remote.IsLinkLocalUnicast()
	}
	for _, host := range hosts {
		if ctx.Err() != nil {
			return false
		}
		lookup, cancel := context.WithTimeout(ctx, 2*time.Second)
		addresses, err := net.DefaultResolver.LookupNetIP(lookup, "ip", host)
		cancel()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if address.WithZone("").Unmap() == remote {
				return true
			}
		}
	}
	return false
}

// A room capability matches both the stable room key and the proof used when
// the stream authenticated. It is never returned to a client or logged.
type hubRoom struct {
	id, proof, capability string
}

func (h *hubRuntime) serveConnection(ctx context.Context, conn net.Conn, hosts []string) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	transferred := false
	defer func() {
		stop()
		if !transferred {
			_ = conn.Close()
		}
	}()
	if !hubSourceAdmitted(ctx, conn.RemoteAddr(), hosts) {
		return
	}
	if conn.SetReadDeadline(time.Now().Add(h.timing.handshake)) != nil {
		return
	}
	hello, err := readHubHello(conn)
	if err != nil {
		return
	}
	domain := hubAuthDomain(hello.Version)
	if domain == "" {
		return
	}
	id := h.authenticate(conn, &hello, domain)
	if conn.SetReadDeadline(time.Time{}) != nil {
		return
	}
	if id == "" {
		hubRefuse(conn, hubUnauthorized)
		return
	}
	room := hubRoom{id: hello.RoomID, proof: hello.Room}
	// Keep assignment through control publication. Other session kinds can
	// only route using a live control, never an unpinned authentication IP.
	h.registration.Lock()
	ip, err := h.store.identify(id, hubUnixNow(), h.busy)
	if err != nil || !ip.IsValid() {
		h.registration.Unlock()
		hubRefuse(conn, hubUnauthorized)
		return
	}
	var display string
	if room.id != "" {
		var wireError string
		display, _, wireError = h.store.admitRoom(room.id, room.proof)
		if wireError != "" {
			h.registration.Unlock()
			hubRefuse(conn, wireError)
			return
		}
		room.capability = roomKey(room.id) + ":" + room.proof
	}
	if hello.Kind == overlay.KindControl {
		control := h.registerControl(ctx, id, ip, room, &hello)
		h.registration.Unlock()
		if control == nil {
			hubRefuse(conn, hubInvalid)
			return
		}
		h.serveControl(conn, control, display)
		return
	}
	h.registration.Unlock()
	switch hello.Kind {
	case overlay.KindOpen, overlay.KindSignal:
		h.serveOpen(ctx, conn, id, room, &hello)
	case overlay.KindAccept:
		transferred = h.serveAccept(conn, id, room, &hello)
	default:
		hubRefuse(conn, hubInvalid)
	}
}

func hubAuthDomain(version int) string {
	switch version {
	case overlay.Version:
		return overlay.AuthDomain
	case overlay.PreviousWireVersion:
		if version != 0 {
			return overlay.PreviousAuthDomain
		}
	}
	return ""
}

func (h *hubRuntime) authenticate(conn net.Conn, hello *overlay.Hello, domain string) string {
	if (hello.Room == "") != (hello.RoomID == "") ||
		(hello.Room != "" && (!overlay.ValidPeerID(hello.Room) || overlay.ValidateName(hello.RoomID) != nil)) {
		return ""
	}
	raw, err := hex.DecodeString(hello.PublicKey)
	if err != nil {
		return ""
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), raw)
	if err != nil || conn.SetReadDeadline(time.Now().Add(h.timing.handshake)) != nil {
		return ""
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ""
	}
	if sendHubFrame(conn, overlay.Challenge{Nonce: hex.EncodeToString(nonce[:])}) != nil {
		return ""
	}
	signature, err := readHubProof(conn)
	if err != nil {
		return ""
	}
	transcript := append([]byte(domain), nonce[:]...)
	if hello.Room != "" {
		transcript = append(transcript, hello.Room...)
		transcript = append(transcript, 0)
		transcript = append(transcript, hello.RoomID...)
	}
	digest := sha512.Sum384(transcript)
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		return ""
	}
	id := sha256.Sum256(raw)
	return hex.EncodeToString(id[:])
}

func (h *hubRuntime) busy(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.controls[id] != nil || h.activeCount[id] != 0
}

func hubUnixNow() uint64 {
	return uint64(max(0, time.Now().Unix()))
}

func (h *hubRuntime) watchPolicy(ctx context.Context, path string) {
	var previous os.FileInfo
	tick := time.NewTicker(hubPolicyTick)
	defer tick.Stop()
	for {
		current, _ := os.Stat(path)
		if hubPolicyChanged(previous, current) {
			h.mu.Lock()
			close(h.policyEpoch)
			h.policyEpoch = make(chan struct{})
			h.mu.Unlock()
		}
		previous = current
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func hubPolicyChanged(previous, current os.FileInfo) bool {
	if previous == nil || current == nil {
		return (previous == nil) != (current == nil)
	}
	return !os.SameFile(previous, current) || previous.Size() != current.Size() ||
		previous.Mode() != current.Mode() || !previous.ModTime().Equal(current.ModTime())
}

func (h *hubRuntime) policyChanges() <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.policyEpoch
}
