package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const hubTestWait = 5 * time.Second

type hubTestSocket struct {
	address string
	cancel  context.CancelFunc
	done    chan error
	once    sync.Once
}

func startHubSocket(t *testing.T, dir string, hosts []string, tune func(*hubTiming)) *hubTestSocket {
	t.Helper()
	return startHubSocketIn(t, dir, hosts, overlay.CIDR, tune)
}

func startHubSocketIn(t *testing.T, dir string, hosts []string, space netip.Prefix, tune func(*hubTiming)) *hubTestSocket {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	hubTestOK(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	hub := &hubTestSocket{address: listener.Addr().String(), cancel: cancel, done: make(chan error, 1)}
	t.Cleanup(func() { hub.stop(t) })
	if tune == nil {
		go func() { hub.done <- serveHub(ctx, listener, dir, hosts, space) }()
	} else {
		store, err := openHubStore(dir, space)
		if err != nil {
			_ = listener.Close()
			hub.done <- err
			t.Fatal(err)
		}
		timing := defaultHubTiming()
		tune(&timing)
		go func() {
			defer func() { _ = listener.Close() }()
			hub.done <- newHubRuntime(store, space, timing).serve(ctx, listener, dir, hosts)
		}()
	}
	return hub
}

func (h *hubTestSocket) stop(t *testing.T) {
	t.Helper()
	h.once.Do(func() {
		h.cancel()
		select {
		case err := <-h.done:
			hubTestOK(t, err)
		case <-time.After(hubTestWait):
			t.Fatal("hub did not stop")
		}
	})
}

func (h *hubTestSocket) connect(t *testing.T) *net.TCPConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", h.address, hubTestWait)
	hubTestOK(t, err)
	tcp := conn.(*net.TCPConn)
	t.Cleanup(func() { _ = tcp.Close() })
	hubTestOK(t, tcp.SetDeadline(time.Now().Add(hubTestWait)))
	return tcp
}

func hubTestOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type hubTestPeer struct {
	key     *ecdsa.PrivateKey
	hello   overlay.Hello
	id      string
	ip      string
	control *net.TCPConn
}

func newHubTestPeer(t *testing.T, wire int, name string) *hubTestPeer {
	t.Helper()
	key, err := overlay.GenerateIdentity()
	hubTestOK(t, err)
	public, err := overlay.PublicIdentity(key)
	hubTestOK(t, err)
	id, err := overlay.IdentityID(public)
	hubTestOK(t, err)
	return &hubTestPeer{key: key, id: id, hello: overlay.Hello{Version: wire, PublicKey: public, Name: name}}
}

func (p *hubTestPeer) register(t *testing.T, h *hubTestSocket) overlay.Reply {
	t.Helper()
	hello := p.hello
	hello.Kind = overlay.KindControl
	conn, _ := h.begin(t, &hello, p.key)
	reply := hubTestRead[overlay.Reply](t, conn)
	if reply.OK {
		p.control, p.ip = conn, reply.IP
	}
	return reply
}

func (h *hubTestSocket) begin(t *testing.T, hello *overlay.Hello, signer *ecdsa.PrivateKey) (*net.TCPConn, overlay.Proof) {
	t.Helper()
	conn := h.connect(t)
	hubTestOK(t, overlay.WriteFrame(conn, hello))
	challenge := hubTestRead[overlay.Challenge](t, conn)
	domain := overlay.AuthDomain
	if hello.Version == overlay.PreviousWireVersion {
		domain = overlay.PreviousAuthDomain
	}
	proof := hubTestProof(t, &challenge, hello, signer, domain)
	hubTestOK(t, overlay.WriteFrame(conn, proof))
	return conn, proof
}

func hubTestProof(t *testing.T, challenge *overlay.Challenge, hello *overlay.Hello, signer *ecdsa.PrivateKey, domain string) overlay.Proof {
	t.Helper()
	nonce, err := hex.DecodeString(challenge.Nonce)
	hubTestOK(t, err)
	if len(nonce) != 32 {
		t.Fatalf("bad challenge nonce length: %d", len(nonce))
	}
	message := append([]byte(domain), nonce...)
	if hello.Room != "" {
		message = append(message, hello.Room...)
		message = append(message, 0)
		message = append(message, hello.RoomID...)
	}
	digest := sha512.Sum384(message)
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest[:])
	hubTestOK(t, err)
	return overlay.Proof{Signature: hex.EncodeToString(sig)}
}

func hubTestRead[T any](t *testing.T, conn net.Conn) T {
	t.Helper()
	var data T
	hubTestOK(t, conn.SetReadDeadline(time.Now().Add(hubTestWait)))
	hubTestOK(t, overlay.ReadFrame(conn, &data))
	return data
}

func hubTestClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	hubTestOK(t, conn.SetReadDeadline(time.Now().Add(hubTestWait)))
	var one [1]byte
	n, err := conn.Read(one[:])
	var timeout net.Error
	if n != 0 || err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
		t.Fatalf("wanted closed connection, read %d bytes: %v", n, err)
	}
}

func hubTestReply(t *testing.T, conn net.Conn, reason string) {
	t.Helper()
	reply := hubTestRead[overlay.Reply](t, conn)
	if reply != (overlay.Reply{Error: reason}) {
		t.Fatalf("reply = %+v; want only error %q", reply, reason)
	}
}

func hubTestEvent(t *testing.T, control net.Conn, matches func(overlay.Event) bool) overlay.Event {
	t.Helper()
	hubTestOK(t, control.SetReadDeadline(time.Now().Add(hubTestWait)))
	for {
		var event overlay.Event
		hubTestOK(t, overlay.ReadFrame(control, &event))
		if matches(event) {
			return event
		}
	}
}

func hubTestPeers(t *testing.T, peer *hubTestPeer, want ...string) {
	t.Helper()
	hubTestEvent(t, peer.control, func(event overlay.Event) bool {
		if event.Peers == nil || len(*event.Peers) != len(want) {
			return false
		}
		for i := range *event.Peers {
			if (*event.Peers)[i].ID != want[i] {
				return false
			}
		}
		return true
	})
}

func hubTestResolve(t *testing.T, peer *hubTestPeer, id uint32, label string) overlay.NameAnswer {
	t.Helper()
	hubTestOK(t, overlay.WriteFrame(peer.control, overlay.ControlRequest{Resolve: &overlay.NameQuery{ID: id, Label: label}}))
	return *hubTestEvent(t, peer.control, func(event overlay.Event) bool {
		return event.Resolved != nil && event.Resolved.ID == id
	}).Resolved
}

func (h *hubTestSocket) open(t *testing.T, peer *hubTestPeer, proto, dest string, port uint16) *net.TCPConn {
	t.Helper()
	hello := peer.hello
	hello.Kind, hello.Proto, hello.Dst, hello.Port = overlay.KindOpen, proto, dest, port
	conn, _ := h.begin(t, &hello, peer.key)
	return conn
}

func (h *hubTestSocket) accept(t *testing.T, peer *hubTestPeer, id, fingerprint, endpoint string) *net.TCPConn {
	t.Helper()
	hello := peer.hello
	hello.Kind, hello.ID, hello.Fingerprint, hello.Endpoint = overlay.KindAccept, id, fingerprint, endpoint
	conn, _ := h.begin(t, &hello, peer.key)
	return conn
}

func hubTestIncoming(t *testing.T, peer *hubTestPeer) overlay.Incoming {
	t.Helper()
	return *hubTestEvent(t, peer.control, func(event overlay.Event) bool { return event.Incoming != nil }).Incoming
}

func TestHubRuntimeAuthenticatesSupportedWiresAndRejectsReplay(t *testing.T) {
	h := startHubSocket(t, t.TempDir(), []string{"127.0.0.2", "127.0.0.1"}, nil)
	legacy := newHubTestPeer(t, overlay.PreviousWireVersion, "previous")
	current := newHubTestPeer(t, overlay.Version, "")
	for _, peer := range []*hubTestPeer{legacy, current} {
		reply := peer.register(t, h)
		name := peer.hello.Name
		if name == "" {
			name = "peer-" + peer.id[:8]
		}
		if !reply.OK || reply.Name != name || reply.CIDR != overlay.CIDR.String() || reply.NameLookup != 1 {
			t.Fatalf("registration = %+v", reply)
		}
	}
	hubTestPeers(t, legacy, current.id)
	hubTestPeers(t, current, legacy.id)
	hubTestOK(t, overlay.WriteFrame(current.control, overlay.Ping{Ping: true}))
	hubTestEvent(t, current.control, func(e overlay.Event) bool { return e.Pong })

	hello := current.hello
	hello.Kind = overlay.KindControl
	wrong, _ := h.begin(t, &hello, legacy.key)
	hubTestReply(t, wrong, hubUnauthorized)
	_, proof := h.begin(t, &hello, current.key)
	replay := h.connect(t)
	hubTestOK(t, overlay.WriteFrame(replay, hello))
	_ = hubTestRead[overlay.Challenge](t, replay)
	hubTestOK(t, overlay.WriteFrame(replay, proof))
	hubTestReply(t, replay, hubUnauthorized)
	wrongDomain := h.connect(t)
	hubTestOK(t, overlay.WriteFrame(wrongDomain, hello))
	challenge := hubTestRead[overlay.Challenge](t, wrongDomain)
	hubTestOK(t, overlay.WriteFrame(wrongDomain, hubTestProof(t, &challenge, &hello, current.key, overlay.PreviousAuthDomain)))
	hubTestReply(t, wrongDomain, hubUnauthorized)

	for _, raw := range []json.RawMessage{json.RawMessage(`{"version":99}`), json.RawMessage(`{"version":5,"room":null}`)} {
		conn := h.connect(t)
		hubTestOK(t, overlay.WriteFrame(conn, raw))
		hubTestClosed(t, conn)
	}
	conn := h.connect(t)
	_, err := conn.Write(binary.BigEndian.AppendUint16(nil, overlay.MaxFrame+1))
	hubTestOK(t, err)
	hubTestClosed(t, conn)
	invalid := h.connect(t)
	hello.PublicKey = "04" + strings.Repeat("00", 96)
	hubTestOK(t, overlay.WriteFrame(invalid, hello))
	hubTestReply(t, invalid, hubUnauthorized)
}

func TestHubRuntimeSourceAdmissionAndDeadlines(t *testing.T) {
	for _, tc := range []struct {
		source  string
		allowed bool
	}{
		{"127.0.0.1", true}, {"172.18.0.5", true}, {"169.254.1.1", true}, {"fd00::1", true},
		{"fe80::1%engine", true}, {"::ffff:172.18.0.5", true}, {"::1", true},
		{"8.8.8.8", false}, {"::ffff:8.8.8.8", false}, {"2001:4860::1", false},
	} {
		if got := hubSourceAdmitted(t.Context(), testHubRemote(net.JoinHostPort(tc.source, "1")), nil); got != tc.allowed {
			t.Errorf("default admission for %s = %t, want %t", tc.source, got, tc.allowed)
		}
	}
	h := startHubSocket(t, t.TempDir(), []string{"127.0.0.2"}, nil)
	hubTestClosed(t, h.connect(t))
	h = startHubSocket(t, t.TempDir(), nil, func(timing *hubTiming) {
		timing.handshake, timing.controlIdle = 125*time.Millisecond, 250*time.Millisecond
	})
	hubTestClosed(t, h.connect(t))
	p := newHubTestPeer(t, overlay.Version, "idle")
	if reply := p.register(t, h); !reply.OK {
		t.Fatal(reply.Error)
	}
	hubTestPeers(t, p)
	hubTestClosed(t, p.control)
}

type testHubRemote string

func (testHubRemote) Network() string  { return "tcp" }
func (r testHubRemote) String() string { return string(r) }

func TestHubRuntimeRelayMatchesRustSessionRules(t *testing.T) {
	h := startHubSocket(t, t.TempDir(), nil, func(timing *hubTiming) { timing.udpIdle = 250 * time.Millisecond })
	a := newHubTestPeer(t, overlay.Version, "alice")
	b := newHubTestPeer(t, overlay.PreviousWireVersion, "bob")
	c := newHubTestPeer(t, overlay.Version, "charlie")
	for _, p := range []*hubTestPeer{a, b, c} {
		if reply := p.register(t, h); !reply.OK {
			t.Fatal(reply.Error)
		}
	}
	hubTestPeers(t, a, b.id, c.id)
	hubTestReply(t, h.open(t, a, overlay.ProtoTCP, a.ip, 80), overlay.ErrUnavailable)
	hubTestReply(t, h.open(t, a, overlay.ProtoTCP, "10.77.99.99", 80), overlay.ErrUnavailable)
	hello := a.hello
	hello.Kind, hello.Dst, hello.Proto, hello.Port, hello.PeerID = overlay.KindOpen, b.ip, overlay.ProtoTCP, 80, c.id
	mismatch, _ := h.begin(t, &hello, a.key)
	hubTestReply(t, mismatch, overlay.ErrUnavailable)

	left := h.open(t, a, overlay.ProtoTCP, b.ip, 8080)
	incoming := hubTestIncoming(t, b)
	if incoming.PeerID != a.id || incoming.Src != a.ip || incoming.Port != 8080 || incoming.Proto != overlay.ProtoTCP || incoming.Signal {
		t.Fatalf("incoming = %+v", incoming)
	}
	hubTestReply(t, h.accept(t, c, incoming.ID, "", ""), hubUnauthorized)
	hubTestReply(t, h.accept(t, b, incoming.ID, "invalid", ""), hubInvalid)
	right := h.accept(t, b, incoming.ID, "", "")
	assertHubPlainPair(t, left, right)
	hubTestReply(t, h.accept(t, b, incoming.ID, "", ""), hubUnauthorized)
	assertHubHalfClose(t, left, right, "request")
	assertHubHalfClose(t, right, left, "response after EOF")

	left = h.open(t, b, overlay.ProtoUDP, a.ip, 5353)
	right = h.accept(t, a, hubTestIncoming(t, a).ID, "", "")
	assertHubPlainPair(t, left, right)
	for _, record := range [][]byte{[]byte("first datagram"), {}, bytes.Repeat([]byte{'d'}, overlay.UsableDatagram)} {
		hubTestOK(t, overlay.WriteDatagram(left, record))
		buffer := make([]byte, overlay.MaxDatagram)
		n, err := overlay.ReadDatagram(right, buffer)
		hubTestOK(t, err)
		if !bytes.Equal(buffer[:n], record) {
			t.Fatalf("datagram changed: got %d bytes, want %d", n, len(record))
		}
	}
	hubTestClosed(t, left)
	hubTestClosed(t, right)
}

func assertHubPlainPair(t *testing.T, left, right net.Conn) {
	t.Helper()
	want := overlay.Reply{OK: true}
	assertHubPaired(t, left, right, &want, &want)
}

func assertHubPaired(t *testing.T, left, right net.Conn, wantLeft, wantRight *overlay.Reply) {
	t.Helper()
	if got := hubTestRead[overlay.Reply](t, left); got != *wantLeft {
		t.Fatalf("open reply = %+v; want %+v", got, wantLeft)
	}
	if got := hubTestRead[overlay.Reply](t, right); got != *wantRight {
		t.Fatalf("accept reply = %+v; want %+v", got, wantRight)
	}
}

func assertHubHalfClose(t *testing.T, source, dest *net.TCPConn, payload string) {
	t.Helper()
	_, err := io.WriteString(source, payload)
	hubTestOK(t, err)
	hubTestOK(t, source.CloseWrite())
	got, err := io.ReadAll(dest)
	hubTestOK(t, err)
	if string(got) != payload {
		t.Fatalf("half-close delivered %q, want %q", got, payload)
	}
}

func TestHubRuntimePendingBoundAndTimeout(t *testing.T) {
	h := startHubSocket(t, t.TempDir(), nil, func(timing *hubTiming) { timing.accept = time.Second })
	a, b := newHubTestPeer(t, overlay.Version, "a"), newHubTestPeer(t, overlay.Version, "b")
	if !a.register(t, h).OK || !b.register(t, h).OK {
		t.Fatal("registration failed")
	}
	var queued []*net.TCPConn
	var ids []string
	for range 4 {
		queued = append(queued, h.open(t, a, overlay.ProtoTCP, b.ip, 80))
		ids = append(ids, hubTestIncoming(t, b).ID)
	}
	hubTestReply(t, h.open(t, a, overlay.ProtoTCP, b.ip, 80), overlay.ErrUnavailable)
	for i, conn := range queued {
		hubTestReply(t, conn, overlay.ErrUnavailable)
		hubTestReply(t, h.accept(t, b, ids[i], "", ""), hubUnauthorized)
	}
	conn := h.open(t, a, overlay.ProtoTCP, b.ip, 80)
	acceptor := h.accept(t, b, hubTestIncoming(t, b).ID, "", "")
	assertHubPlainPair(t, conn, acceptor)
}

func TestHubPendingAcceptDoesNotFollowReassignedAddress(t *testing.T) {
	dir := t.TempDir()
	space := netip.MustParsePrefix("172.19.5.0/29")
	hubTestOK(t, saveDHCP(dir, space, []byte(`{"start":"172.19.5.1","end":"172.19.5.3","lease_seconds":0,"bindings":[]}`)))
	h := startHubSocketIn(t, dir, nil, space, nil)
	a, b := newHubTestPeer(t, overlay.Version, "a"), newHubTestPeer(t, overlay.Version, "b")
	c, other := newHubTestPeer(t, overlay.Version, "c"), newHubTestPeer(t, overlay.Version, "other")
	if !a.register(t, h).OK || !b.register(t, h).OK || !c.register(t, h).OK {
		t.Fatal("registration failed")
	}
	_ = h.open(t, a, overlay.ProtoTCP, b.ip, 80)
	offer := hubTestIncoming(t, b)
	hubTestOK(t, a.control.Close())
	hubTestPeers(t, b, c.id)
	if reply := other.register(t, h); !reply.OK || reply.IP != offer.Src {
		t.Fatalf("expected source lease reuse: %+v", reply)
	}
	hubTestOK(t, c.control.Close())
	hubTestPeers(t, b, other.id)
	if reply := a.register(t, h); !reply.OK || reply.IP == offer.Src {
		t.Fatalf("expected new source lease: %+v", reply)
	}
	hubTestReply(t, h.accept(t, b, offer.ID, "", ""), hubUnauthorized)
}

func TestHubRuntimeActiveRelayPinsDisconnectedAddress(t *testing.T) {
	space := netip.MustParsePrefix("172.19.5.0/30")
	h := startHubSocketIn(t, t.TempDir(), nil, space, nil)
	a := newHubTestPeer(t, overlay.Version, "a")
	b := newHubTestPeer(t, overlay.Version, "b")
	newcomer := newHubTestPeer(t, overlay.Version, "newcomer")
	if ar, br := a.register(t, h), b.register(t, h); !ar.OK || !br.OK ||
		ar.IP != "172.19.5.1" || br.IP != "172.19.5.2" || ar.CIDR != space.String() || br.CIDR != space.String() {
		t.Fatalf("unexpected range replies: %+v, %+v", ar, br)
	}
	left := h.open(t, a, overlay.ProtoTCP, b.ip, 80)
	right := h.accept(t, b, hubTestIncoming(t, b).ID, "", "")
	assertHubPlainPair(t, left, right)
	hubTestOK(t, b.control.Close())
	hubTestPeers(t, a)
	if reply := newcomer.register(t, h); reply.OK || reply.Error != hubUnauthorized {
		t.Fatalf("newcomer displaced a live flow: %+v", reply)
	}
	assertHubHalfClose(t, left, right, "existing relay still works")
	assertHubHalfClose(t, right, left, "half-closed reply")
	ctx, cancel := context.WithTimeout(t.Context(), hubTestWait)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if reply := newcomer.register(t, h); reply.OK {
			if reply.IP != b.ip {
				t.Fatalf("retired address = %s; want %s", reply.IP, b.ip)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("relay completion did not release the address")
		case <-tick.C:
		}
	}
}

func TestHubRuntimeOfferHandoffAndBoundedMixedWireSignaling(t *testing.T) {
	dir := t.TempDir()
	h := startHubSocket(t, dir, nil, nil)
	a := newHubTestPeer(t, overlay.PreviousWireVersion, "a")
	b := newHubTestPeer(t, overlay.Version, "b")
	if !a.register(t, h).OK || !b.register(t, h).OK {
		t.Fatal("registration failed")
	}
	hello := a.hello
	hello.Kind, hello.Proto, hello.Dst, hello.Port = overlay.KindOpen, overlay.ProtoTCP, b.ip, 80
	hello.Fingerprint, hello.Endpoint = strings.Repeat("AB", 32), "[2001:0DB8::1]:3443"
	left, _ := h.begin(t, &hello, a.key)
	incoming := hubTestIncoming(t, b)
	if incoming.Fingerprint != strings.Repeat("ab", 32) || incoming.Endpoint != "[2001:db8::1]:3443" {
		t.Fatalf("incoming offer = %+v", incoming)
	}
	otherPrint, otherEndpoint := strings.Repeat("cd", 32), "192.0.2.2:7887"
	right := h.accept(t, b, incoming.ID, otherPrint, otherEndpoint)
	assertHubPaired(t, left, right,
		&overlay.Reply{OK: true, Secure: true, Direct: true, ID: incoming.ID, Fingerprint: otherPrint, Endpoint: otherEndpoint},
		&overlay.Reply{OK: true, Secure: true, Direct: true, ID: incoming.ID, Fingerprint: incoming.Fingerprint, Endpoint: incoming.Endpoint})
	hubTestClosed(t, left)
	hubTestClosed(t, right)

	hubTestOK(t, setRoomRelay(dir, "public", false))
	hubTestReply(t, h.open(t, a, overlay.ProtoTCP, b.ip, 80), overlay.ErrUnavailable)
	for _, peers := range [][2]*hubTestPeer{{a, b}, {b, a}} {
		left, right := hubTestSignalPair(t, h, peers[0], peers[1])
		for i, conns := range [][2]net.Conn{{left, right}, {right, left}} {
			methods := []string{"webrtc", "ice"}
			if peers[i].hello.Version == overlay.PreviousWireVersion {
				methods = []string{"webrtc", "libp2p", "ice"}
			}
			hubTestOK(t, overlay.WriteFrame(conns[0], hubSignal{Type: "hello", Methods: methods}))
			got := hubTestRead[hubSignal](t, conns[1])
			if got.Type != "hello" || !slices.Equal(got.Methods, []string{"webrtc", "ice"}) {
				t.Fatalf("forwarded methods = %+v", got)
			}
		}
		hubTestOK(t, overlay.WriteFrame(left, json.RawMessage(`{"t":"offer","s":"ice","d":{"payload":"not signaling"}}`)))
		hubTestClosed(t, right)
		hubTestClosed(t, left)
	}
}

func hubTestSignalPair(t *testing.T, h *hubTestSocket, a, b *hubTestPeer) (left, right *net.TCPConn) {
	t.Helper()
	hello := a.hello
	hello.Kind, hello.Proto, hello.Dst, hello.Port = overlay.KindSignal, overlay.ProtoTCP, b.ip, overlay.LinkPort
	hello.Fingerprint = strings.Repeat("ab", 32)
	left, _ = h.begin(t, &hello, a.key)
	incoming := hubTestIncoming(t, b)
	if !incoming.Signal {
		t.Fatal("signal not marked on incoming event")
	}
	otherPrint := strings.Repeat("cd", 32)
	right = h.accept(t, b, incoming.ID, otherPrint, "")
	assertHubPaired(t, left, right,
		&overlay.Reply{OK: true, Secure: true, Fingerprint: otherPrint},
		&overlay.Reply{OK: true, Secure: true, Fingerprint: hello.Fingerprint})
	return left, right
}

func TestHubRuntimeRoomPolicyRevokesLiveRelayAndDNSProof(t *testing.T) {
	for _, private := range []bool{false, true} {
		name := "public"
		if private {
			name = "private"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			h := startHubSocket(t, dir, nil, nil)
			a, b := newHubTestPeer(t, overlay.Version, "observer"), newHubTestPeer(t, overlay.Version, "Desk PC")
			if private {
				roomID, proof := "one room", strings.Repeat("ab", 32)
				a.hello.RoomID, a.hello.Room = roomID, proof
				b.hello.RoomID, b.hello.Room = roomID, proof
				if reply := a.register(t, h); reply.OK || reply.Error != "room does not exist" {
					t.Fatalf("unknown room = %+v", reply)
				}
				hubTestOK(t, configureRoom(dir, roomID, "Fixture Room", proof, false, nil))
				name = roomKey(roomID)
			}
			for _, p := range []*hubTestPeer{a, b} {
				if reply := p.register(t, h); !reply.OK || (private && reply.RoomName != "Fixture Room") {
					t.Fatalf("registration = %+v", reply)
				}
			}
			hubTestOK(t, setRoomRelay(dir, name, false))
			hubTestReply(t, h.open(t, a, overlay.ProtoTCP, b.ip, 80), overlay.ErrUnavailable)
			want := overlay.NameAnswer{ID: 1, IP: b.ip}
			if got := hubTestResolve(t, a, 1, "desk-pc"); got != want {
				t.Fatalf("DNS under disabled relay = %+v, want %+v", got, want)
			}
			hubTestOK(t, setRoomRelay(dir, name, true))
			left := h.open(t, a, overlay.ProtoTCP, b.ip, 80)
			right := h.accept(t, b, hubTestIncoming(t, b).ID, "", "")
			assertHubPlainPair(t, left, right)
			_, err := io.WriteString(left, "payload")
			hubTestOK(t, err)
			var payload [7]byte
			_, err = io.ReadFull(right, payload[:])
			hubTestOK(t, err)
			if string(payload[:]) != "payload" {
				t.Fatalf("relay delivered %q", payload)
			}
			if private {
				// Keep relay enabled while rotating the proof: only capability
				// revalidation, not the relay flag, can close this stream.
				hubTestOK(t, configureRoom(dir, a.hello.RoomID, "Fixture Room", strings.Repeat("cd", 32), true, nil))
				if got := hubTestResolve(t, a, 2, "desk-pc"); got != (overlay.NameAnswer{ID: 2}) {
					t.Fatalf("stale DNS authority returned %+v", got)
				}
			} else {
				hubTestOK(t, setRoomRelay(dir, name, false))
			}
			hubTestClosed(t, left)
			hubTestClosed(t, right)
			hubTestOK(t, os.WriteFile(filepath.Join(dir, roomsFile), []byte("{"), 0o600))
			if private {
				if got := hubTestResolve(t, a, 3, "desk-pc"); got != (overlay.NameAnswer{ID: 3, Unavailable: true}) {
					t.Fatalf("broken DNS authority returned %+v", got)
				}
			} else {
				hubTestReply(t, h.open(t, a, overlay.ProtoTCP, b.ip, 80), overlay.ErrUnavailable)
			}
		})
	}
}

func TestHubRuntimeDurableRoomNamesRequireLiveOwner(t *testing.T) {
	dir := t.TempDir()
	h := startHubSocket(t, dir, nil, nil)
	a := newHubTestPeer(t, overlay.Version, "Desk PC")
	b := newHubTestPeer(t, overlay.PreviousWireVersion, "desk pc")
	if !a.register(t, h).OK || !b.register(t, h).OK {
		t.Fatal("registration failed")
	}
	firstIP := a.ip
	if got := hubTestResolve(t, b, 1, "desk-pc"); got != (overlay.NameAnswer{ID: 1, IP: firstIP}) {
		t.Fatalf("first owner = %+v", got)
	}
	old := a.control
	a.hello.Name = "New Name"
	if reply := a.register(t, h); !reply.OK || reply.IP != firstIP || reply.Name != "New Name" {
		t.Fatalf("re-registration = %+v", reply)
	}
	hubTestPeers(t, a, b.id)
	// The superseded control may have a queued roster frame, so drain until EOF.
	hubTestOK(t, old.SetReadDeadline(time.Now().Add(hubTestWait)))
	_, err := io.Copy(io.Discard, old)
	hubTestOK(t, err)
	if got := hubTestResolve(t, b, 2, "new-name"); got.IP != firstIP {
		t.Fatalf("new label = %+v", got)
	}
	hubTestOK(t, a.control.Close())
	hubTestPeers(t, b)
	if got := hubTestResolve(t, b, 3, "desk-pc"); got != (overlay.NameAnswer{ID: 3}) {
		t.Fatalf("offline owner lookup = %+v", got)
	}
	h.stop(t)
	h = startHubSocket(t, dir, nil, nil)
	if !b.register(t, h).OK || !a.register(t, h).OK {
		t.Fatal("registration after restart failed")
	}
	if got := hubTestResolve(t, b, 4, "desk-pc"); got != (overlay.NameAnswer{ID: 4, IP: firstIP}) {
		t.Fatalf("owner after restart = %+v", got)
	}
}
