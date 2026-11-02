package overlayagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

// fakeHub speaks the contract in overlay.go over loopback TCP. It relays
// flows between control-registered accounts and nothing more.
type fakeHub struct {
	t        *testing.T
	listener net.Listener
	wg       sync.WaitGroup

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	accounts map[string]*hubAccount
	pending  map[string]chan net.Conn
	nextID   int

	hellos   []overlay.Hello
	accepted atomic.Int32 // streams whose Hello was read
	acceptOK atomic.Int32 // accept streams answered ok
	pings    atomic.Int32

	silent        atomic.Bool // do not answer pings
	rejectControl atomic.Bool
	rejectOpen    atomic.Bool
}

type hubAccount struct {
	ip      netip.Addr
	name    string
	control net.Conn
	wmu     sync.Mutex
}

func newFakeHub(t *testing.T) *fakeHub {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &fakeHub{t: t, listener: listener, conns: map[net.Conn]struct{}{}, accounts: map[string]*hubAccount{}, pending: map[string]chan net.Conn{}}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.conns[conn] = struct{}{}
			h.mu.Unlock()
			h.wg.Add(1)
			go func() {
				defer h.wg.Done()
				h.serve(conn)
			}()
		}
	}()
	t.Cleanup(h.close)
	return h
}

func (h *fakeHub) close() {
	_ = h.listener.Close()
	h.mu.Lock()
	for conn := range h.conns {
		_ = conn.Close()
	}
	h.mu.Unlock()
	h.wg.Wait()
}

func (h *fakeHub) dial(ctx context.Context) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", h.listener.Addr().String())
}

func (h *fakeHub) account(token string) *hubAccount {
	h.mu.Lock()
	defer h.mu.Unlock()
	a := h.accounts[token]
	if a == nil {
		h.nextID++
		a = &hubAccount{ip: netip.AddrFrom4([4]byte{10, 77, 1, byte(h.nextID)}), name: fmt.Sprintf("acct-%d", h.nextID)}
		h.accounts[token] = a
	}
	return a
}

func (h *fakeHub) serve(conn net.Conn) {
	var hello overlay.Hello
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := overlay.ReadFrame(conn, &hello); err != nil {
		_ = conn.Close()
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		_ = conn.Close()
		return
	}
	if err := overlay.WriteFrame(conn, overlay.Challenge{Nonce: hex.EncodeToString(nonce)}); err != nil {
		_ = conn.Close()
		return
	}
	var proof overlay.Proof
	if err := overlay.ReadFrame(conn, &proof); err != nil {
		_ = conn.Close()
		return
	}
	public, err := hex.DecodeString(hello.PublicKey)
	if err != nil {
		_ = conn.Close()
		return
	}
	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), public)
	if err != nil {
		_ = conn.Close()
		return
	}
	signature, err := hex.DecodeString(proof.Signature)
	digest := sha512.Sum384(append([]byte("overlay-relay/auth/v2:"), nonce...))
	if err != nil || !ecdsa.VerifyASN1(publicKey, digest[:], signature) {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	h.mu.Lock()
	h.hellos = append(h.hellos, hello)
	h.mu.Unlock()
	h.accepted.Add(1)
	switch hello.Kind {
	case overlay.KindControl:
		h.serveControl(conn, &hello)
	case overlay.KindOpen:
		h.serveOpen(conn, &hello)
	case overlay.KindAccept:
		h.serveAccept(conn, &hello)
	default:
		_ = overlay.WriteFrame(conn, overlay.Reply{Error: "bad kind"})
		_ = conn.Close()
	}
}

func (h *fakeHub) serveControl(conn net.Conn, hello *overlay.Hello) {
	defer func() { _ = conn.Close() }()
	if h.rejectControl.Load() || hello.Version != overlay.Version {
		_ = overlay.WriteFrame(conn, overlay.Reply{Error: "unknown account"})
		return
	}
	account := h.account(hello.PublicKey)
	account.wmu.Lock()
	account.control = conn
	err := overlay.WriteFrame(conn, overlay.Reply{OK: true, IP: account.ip.String(), Name: account.name})
	account.wmu.Unlock()
	if err != nil {
		return
	}
	h.broadcastPeers()
	for {
		var ping overlay.Ping
		if err := overlay.ReadFrame(conn, &ping); err != nil {
			break
		}
		h.pings.Add(1)
		if !h.silent.Load() {
			h.send(account, overlay.Event{Pong: true})
		}
	}
	account.wmu.Lock()
	if account.control == conn {
		account.control = nil
	}
	account.wmu.Unlock()
	h.broadcastPeers()
}

func (h *fakeHub) send(account *hubAccount, event overlay.Event) {
	account.wmu.Lock()
	defer account.wmu.Unlock()
	if account.control != nil {
		_ = overlay.WriteFrame(account.control, event)
	}
}

func (h *fakeHub) broadcastPeers() {
	h.mu.Lock()
	var live []*hubAccount
	for _, a := range h.accounts {
		a.wmu.Lock()
		if a.control != nil {
			live = append(live, a)
		}
		a.wmu.Unlock()
	}
	h.mu.Unlock()
	for _, target := range live {
		peers := []overlay.Peer{}
		for _, other := range live {
			if other != target {
				peers = append(peers, overlay.Peer{IP: other.ip.String(), Name: other.name})
			}
		}
		h.send(target, overlay.Event{Peers: &peers})
	}
}

// push injects an Incoming event as if a requester existed.
func (h *fakeHub) push(ip netip.Addr, in *overlay.Incoming) {
	h.mu.Lock()
	var target *hubAccount
	for _, a := range h.accounts {
		if a.ip == ip {
			target = a
		}
	}
	h.mu.Unlock()
	h.send(target, overlay.Event{Incoming: in})
}

func (h *fakeHub) dropControls() {
	h.mu.Lock()
	var controls []net.Conn
	for _, a := range h.accounts {
		a.wmu.Lock()
		if a.control != nil {
			controls = append(controls, a.control)
		}
		a.wmu.Unlock()
	}
	h.mu.Unlock()
	for _, c := range controls {
		_ = c.Close()
	}
}

func (h *fakeHub) serveOpen(conn net.Conn, hello *overlay.Hello) {
	defer func() { _ = conn.Close() }()
	requester := h.account(hello.PublicKey)
	destination, _ := netip.ParseAddr(hello.Dst)
	var target *hubAccount
	h.mu.Lock()
	for _, a := range h.accounts {
		a.wmu.Lock()
		if a.ip == destination && a.control != nil {
			target = a
		}
		a.wmu.Unlock()
	}
	h.nextID++
	id := fmt.Sprintf("flow-%d", h.nextID)
	accepted := make(chan net.Conn, 1)
	h.pending[id] = accepted
	h.mu.Unlock()
	if target == nil || h.rejectOpen.Load() {
		_ = overlay.WriteFrame(conn, overlay.Reply{Error: overlay.ErrUnavailable})
		return
	}
	h.send(target, overlay.Event{Incoming: &overlay.Incoming{ID: id, Proto: hello.Proto, Src: requester.ip.String(), Port: hello.Port}})
	select {
	case other := <-accepted:
		if err := overlay.WriteFrame(conn, overlay.Reply{OK: true}); err != nil {
			_ = other.Close()
			return
		}
		relay(conn, other)
	case <-time.After(2 * time.Second):
		_ = overlay.WriteFrame(conn, overlay.Reply{Error: overlay.ErrUnavailable})
	}
}

func (h *fakeHub) serveAccept(conn net.Conn, hello *overlay.Hello) {
	h.mu.Lock()
	accepted := h.pending[hello.ID]
	delete(h.pending, hello.ID)
	h.mu.Unlock()
	if err := overlay.WriteFrame(conn, overlay.Reply{OK: true}); err != nil {
		_ = conn.Close()
		return
	}
	h.acceptOK.Add(1)
	if accepted == nil {
		// Injected request without a requester: hold the stream until it closes.
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
		return
	}
	accepted <- conn // the open handler relays and closes both ends
}

func relay(a, b net.Conn) {
	defer func() { _ = a.Close(); _ = b.Close() }()
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(*net.TCPConn); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(a, b)
	go pipe(b, a)
	<-done
	<-done
}

type testAgent struct {
	*Agent
	key    *ecdsa.PrivateKey
	mu     sync.Mutex
	states []overlay.State
}

type localCall struct {
	proto string
	port  uint16
	src   netip.Addr
}

func (h *fakeHub) newAgent(t *testing.T, name string, dialLocal func(context.Context, string, uint16, netip.Addr) (net.Conn, error)) *testAgent {
	t.Helper()
	key, err := overlay.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ta := &testAgent{key: key}
	if dialLocal == nil {
		dialLocal = func(context.Context, string, uint16, netip.Addr) (net.Conn, error) {
			return nil, errors.New("no local service")
		}
	}
	// The fake hub relays plain bytes; encryption has its own tests (seal_test.go).
	ta.Agent = New(Config{Identity: ta.key, DisableEncryption: true, Dial: h.dial, DialLocal: dialLocal, OnState: func(s overlay.State) {
		ta.mu.Lock()
		ta.states = append(ta.states, s)
		ta.mu.Unlock()
	}})
	ta.timing = timing{ping: 20 * time.Millisecond, liveness: 400 * time.Millisecond, handshake: time.Second, backoffMin: 5 * time.Millisecond, backoffMax: 40 * time.Millisecond, udpIdle: time.Minute}
	return ta
}

// start runs the agent and returns a function that stops it and checks Run's result.
func (ta *testAgent) start(t *testing.T) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- ta.Run(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("Run returned %v, want context.Canceled", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("Run did not stop after cancellation")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func (ta *testAgent) waitState(t *testing.T, what string, ok func(overlay.State) bool) overlay.State {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ta.mu.Lock()
		for i := len(ta.states) - 1; i >= 0; i-- {
			if ok(ta.states[i]) {
				s := ta.states[i]
				ta.mu.Unlock()
				return s
			}
		}
		ta.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for state: %s", what)
	return overlay.State{}
}

func (ta *testAgent) waitReady(t *testing.T) netip.Addr {
	t.Helper()
	select {
	case ip := <-ta.Ready():
		return ip
	case <-time.After(3 * time.Second):
		t.Fatal("agent did not register")
	}
	return netip.Addr{}
}

func hasPeer(ip netip.Addr) func(overlay.State) bool {
	return func(s overlay.State) bool {
		for _, p := range s.Peers {
			if p.IP == ip.String() {
				return true
			}
		}
		return false
	}
}

func tcpEcho(t *testing.T) (address string, shutdown func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = io.Copy(conn, conn)
				_ = conn.Close()
			}()
		}
	}()
	stop := func() { _ = listener.Close(); wg.Wait() }
	t.Cleanup(stop)
	return listener.Addr().String(), stop
}

func udpEcho(t *testing.T) (address string, shutdown func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buffer := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buffer[:n], from)
		}
	}()
	stop := func() { _ = pc.Close(); wg.Wait() }
	t.Cleanup(stop)
	return pc.LocalAddr().String(), stop
}

func echoServers(t *testing.T) (tcp, udp string, stop func()) {
	t.Helper()
	tcp, stopTCP := tcpEcho(t)
	udp, stopUDP := udpEcho(t)
	return tcp, udp, func() { stopTCP(); stopUDP() }
}

// echoLocal completes incoming flows against local echo servers and records them.
func echoLocal(tcp, udp string, calls chan<- localCall) func(context.Context, string, uint16, netip.Addr) (net.Conn, error) {
	return func(ctx context.Context, proto string, port uint16, src netip.Addr) (net.Conn, error) {
		calls <- localCall{proto, port, src}
		if proto == overlay.ProtoUDP {
			return (&net.Dialer{}).DialContext(ctx, "udp", udp)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", tcp)
	}
}

func TestRegistrationUsesPublicIdentity(t *testing.T) {
	hub := newFakeHub(t)
	a := hub.newAgent(t, "a", nil)
	a.start(t)
	ip := a.waitReady(t)
	if a.IP() != ip || !overlay.Assignable(ip) {
		t.Fatalf("IP() = %v, ready = %v", a.IP(), ip)
	}
	state := a.waitState(t, "connected", func(s overlay.State) bool { return s.Connected })
	if !state.Available || !state.Broadcasting || state.IP != ip.String() || state.Name == "" || state.Peers == nil {
		t.Fatalf("unexpected state %+v", state)
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	hello := hub.hellos[0]
	public, err := overlay.PublicIdentity(a.key)
	if err != nil {
		t.Fatal(err)
	}
	if hello.Kind != overlay.KindControl || hello.Version != overlay.Version || hello.PublicKey != public {
		t.Fatalf("unexpected hello %+v", hello)
	}
}

func TestPeersAreTrackedAndRemoved(t *testing.T) {
	hub := newFakeHub(t)
	a, b := hub.newAgent(t, "a", nil), hub.newAgent(t, "b", nil)
	a.start(t)
	a.waitReady(t)
	stopB := b.start(t)
	bIP := b.waitReady(t)
	a.waitState(t, "B listed", hasPeer(bIP))
	stopB()
	a.waitState(t, "B removed", func(s overlay.State) bool { return s.Connected && len(s.Peers) == 0 })
}

func TestTCPFlowWithHalfClose(t *testing.T) {
	hub := newFakeHub(t)
	calls := make(chan localCall, 4)
	tcp, udp, _ := echoServers(t)
	a := hub.newAgent(t, "a", nil)
	b := hub.newAgent(t, "b", echoLocal(tcp, udp, calls))
	a.start(t)
	aIP := a.waitReady(t)
	b.start(t)
	bIP := b.waitReady(t)
	a.waitState(t, "B listed", hasPeer(bIP))

	conn, err := a.Outbound(context.Background(), overlay.ProtoTCP, netip.AddrPortFrom(bIP, 8080))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("hello overlay")); err != nil {
		t.Fatal(err)
	}
	cw, ok := conn.(closeWriter)
	if !ok {
		t.Fatal("TCP flow lost half-close support")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "hello overlay" {
		t.Fatalf("echo = %q, %v", got, err)
	}
	call := <-calls
	if call.proto != overlay.ProtoTCP || call.port != 8080 || call.src != aIP {
		t.Fatalf("unexpected local call %+v", call)
	}
}

func TestUDPFlowKeepsDatagramBoundariesAndExpiresWhenIdle(t *testing.T) {
	hub := newFakeHub(t)
	calls := make(chan localCall, 4)
	tcp, udp, _ := echoServers(t)
	a := hub.newAgent(t, "a", nil)
	b := hub.newAgent(t, "b", echoLocal(tcp, udp, calls))
	b.timing.udpIdle = 300 * time.Millisecond
	a.start(t)
	a.waitReady(t)
	b.start(t)
	bIP := b.waitReady(t)
	a.waitState(t, "B listed", hasPeer(bIP))

	conn, err := a.Outbound(context.Background(), overlay.ProtoUDP, netip.AddrPortFrom(bIP, 5353))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	big := bytes.Repeat([]byte{7}, 3000)
	for _, payload := range [][]byte{[]byte("one"), big, {}, []byte("four")} {
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 65535)
	for i, want := range [][]byte{[]byte("one"), big, {}, []byte("four")} {
		n, err := conn.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], want) {
			t.Fatalf("datagram %d = %d bytes, %v", i, n, err)
		}
	}
	if call := <-calls; call.proto != overlay.ProtoUDP || call.port != 5353 {
		t.Fatalf("unexpected local call %+v", call)
	}
	// A short read buffer truncates like a UDP socket and keeps the framing intact.
	if _, err := conn.Write([]byte("truncate me")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("next")); err != nil {
		t.Fatal(err)
	}
	small := make([]byte, 4)
	if n, err := conn.Read(small); err != nil || string(small[:n]) != "trun" {
		t.Fatalf("truncated read = %q, %v", small[:n], err)
	}
	if n, err := conn.Read(buffer); err != nil || string(buffer[:n]) != "next" {
		t.Fatalf("framing lost after truncation: %q, %v", buffer[:n], err)
	}
	// With no traffic the incoming side expires the flow and the peer sees the end.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(buffer); err == nil {
		t.Fatal("idle UDP flow stayed open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("idle UDP flow was not closed by the incoming side")
	}
}

func TestUDPReadSurvivesDeadlineMidRecord(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()
	conn := &datagramConn{Conn: client, buffer: make([]byte, 2+overlay.MaxDatagram)}
	go func() {
		_, _ = server.Write([]byte{0, 5, 'h', 'e'})
		time.Sleep(150 * time.Millisecond)
		_, _ = server.Write([]byte{'l', 'l', 'o'})
	}()
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buffer := make([]byte, 16)
	if _, err := conn.Read(buffer); err == nil {
		t.Fatal("read finished before the record was complete")
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn.Read(buffer); err != nil || string(buffer[:n]) != "hello" {
		t.Fatalf("resumed read = %q, %v", buffer[:n], err)
	}
}

func TestOutboundRefusalsHappenBeforeTheHub(t *testing.T) {
	hub := newFakeHub(t)
	a, b := hub.newAgent(t, "a", nil), hub.newAgent(t, "b", nil)
	a.start(t)
	aIP := a.waitReady(t)
	b.start(t)
	bIP := b.waitReady(t)
	a.waitState(t, "B listed", hasPeer(bIP))
	before := hub.accepted.Load()
	for name, dst := range map[string]netip.AddrPort{
		"outside CIDR":  netip.MustParseAddrPort("192.0.2.1:80"),
		"IPv6":          netip.MustParseAddrPort("[fd00::1]:80"),
		"own address":   netip.AddrPortFrom(aIP, 80),
		"unknown peer":  netip.MustParseAddrPort("10.77.9.9:80"),
		"network zero":  netip.MustParseAddrPort("10.77.0.0:80"),
		"port zero":     netip.AddrPortFrom(bIP, 0),
		"broadcast net": netip.MustParseAddrPort("10.77.255.255:80"),
	} {
		if conn, err := a.Outbound(context.Background(), overlay.ProtoTCP, dst); err == nil {
			_ = conn.Close()
			t.Fatalf("%s: Outbound succeeded", name)
		}
	}
	if _, err := a.Outbound(context.Background(), "icmp", netip.AddrPortFrom(bIP, 80)); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
	if hub.accepted.Load() != before {
		t.Fatal("a refused flow reached the hub")
	}
	// The hub stays the authority: its refusal surfaces with the contract's generic reason.
	hub.rejectOpen.Store(true)
	if _, err := a.Outbound(context.Background(), overlay.ProtoTCP, netip.AddrPortFrom(bIP, 80)); err == nil || err.Error() != overlay.ErrUnavailable {
		t.Fatalf("hub refusal = %v", err)
	}
}

func TestIncomingConcurrencyIsBounded(t *testing.T) {
	hub := newFakeHub(t)
	var active, started atomic.Int32
	release := make(chan struct{})
	b := hub.newAgent(t, "b", func(ctx context.Context, _ string, _ uint16, _ netip.Addr) (net.Conn, error) {
		active.Add(1)
		started.Add(1)
		defer active.Add(-1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("closed")
	})
	b.start(t)
	bIP := b.waitReady(t)
	for i := range maxIncoming + 22 {
		hub.push(bIP, &overlay.Incoming{ID: fmt.Sprintf("x%d", i), Proto: overlay.ProtoTCP, Src: "10.77.7.7", Port: 80})
	}
	deadline := time.Now().Add(3 * time.Second)
	for started.Load() < maxIncoming && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	if got := started.Load(); got != maxIncoming {
		t.Fatalf("%d incoming flows started concurrently, want exactly %d", got, maxIncoming)
	}
	close(release)
	deadline = time.Now().Add(3 * time.Second)
	for active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	// Capacity returns once flows finish.
	hub.push(bIP, &overlay.Incoming{ID: "again", Proto: overlay.ProtoTCP, Src: "10.77.7.7", Port: 80})
	deadline = time.Now().Add(3 * time.Second)
	for started.Load() <= maxIncoming && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if started.Load() != maxIncoming+1 {
		t.Fatal("capacity was not released")
	}
}

func TestMalformedIncomingRequestsAreIgnored(t *testing.T) {
	hub := newFakeHub(t)
	var calls atomic.Int32
	b := hub.newAgent(t, "b", func(context.Context, string, uint16, netip.Addr) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("closed")
	})
	b.start(t)
	bIP := b.waitReady(t)
	for _, in := range []*overlay.Incoming{
		{ID: "", Proto: "tcp", Src: "10.77.7.7", Port: 80},
		{ID: "a", Proto: "sctp", Src: "10.77.7.7", Port: 80},
		{ID: "b", Proto: "tcp", Src: "192.0.2.1", Port: 80},
		{ID: "c", Proto: "tcp", Src: "nonsense", Port: 80},
		{ID: "d", Proto: "tcp", Src: "10.77.7.7", Port: 0},
	} {
		hub.push(bIP, in)
	}
	hub.push(bIP, &overlay.Incoming{ID: "ok", Proto: "tcp", Src: "10.77.7.7", Port: 80})
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 1 || hub.acceptOK.Load() != 1 {
		t.Fatalf("local calls = %d, accepted = %d, want 1 each", calls.Load(), hub.acceptOK.Load())
	}
}

func TestReconnectPingsAndSilentHub(t *testing.T) {
	hub := newFakeHub(t)
	a := hub.newAgent(t, "a", nil)
	a.start(t)
	ip := a.waitReady(t)
	deadline := time.Now().Add(3 * time.Second)
	for hub.pings.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if hub.pings.Load() < 3 {
		t.Fatal("agent did not ping")
	}

	hub.dropControls()
	a.waitState(t, "disconnected", func(s overlay.State) bool { return !s.Connected && s.Reason != "" })
	a.waitState(t, "reconnected", func(s overlay.State) bool { return s.Connected && s.IP == ip.String() })
	if a.IP() != ip {
		t.Fatal("overlay address changed across reconnect")
	}

	// A hub that stops answering is detected by the liveness bound.
	hellos := func() int {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return len(hub.hellos)
	}
	before := hellos()
	hub.silent.Store(true)
	deadline = time.Now().Add(3 * time.Second)
	for hellos() < before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hellos() < before+2 {
		t.Fatal("silent hub did not trigger reconnects")
	}
}

func TestRejectionIsReportedAndRetried(t *testing.T) {
	hub := newFakeHub(t)
	hub.rejectControl.Store(true)
	a := hub.newAgent(t, "a", nil)
	a.start(t)
	state := a.waitState(t, "rejected", func(s overlay.State) bool { return s.Reason == "unknown account" })
	if state.Connected || !state.Available || state.Peers == nil {
		t.Fatalf("unexpected state %+v", state)
	}
	select {
	case <-a.Ready():
		t.Fatal("ready fired for a rejected account")
	case <-time.After(100 * time.Millisecond):
	}
	if n := hub.accepted.Load(); n < 3 {
		t.Fatalf("only %d attempts, agent is not retrying", n)
	}
	hub.rejectControl.Store(false)
	a.waitReady(t)
}

func TestBackoffDoublesUpToTheCap(t *testing.T) {
	var mu sync.Mutex
	var attempts []time.Time
	key, err := overlay.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a := New(Config{
		Identity: key,
		Dial: func(context.Context) (net.Conn, error) {
			mu.Lock()
			attempts = append(attempts, time.Now())
			mu.Unlock()
			return nil, errors.New("unreachable")
		},
		DialLocal: func(context.Context, string, uint16, netip.Addr) (net.Conn, error) { return nil, errors.New("unused") },
	})
	a.timing.backoffMin, a.timing.backoffMax = 20*time.Millisecond, 80*time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if err := a.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(attempts) < 6 {
		t.Fatalf("only %d attempts", len(attempts))
	}
	want := []time.Duration{20, 40, 80, 80, 80}
	for i, w := range want {
		w *= time.Millisecond
		gap := attempts[i+1].Sub(attempts[i])
		if gap < w-2*time.Millisecond || gap > w+60*time.Millisecond {
			t.Fatalf("gap %d = %v, want about %v", i, gap, w)
		}
	}
}

func TestRunValidatesAndRunsOnce(t *testing.T) {
	if err := New(Config{}).Run(context.Background()); err == nil {
		t.Fatal("unconfigured agent ran")
	}
	hub := newFakeHub(t)
	a := hub.newAgent(t, "a", nil)
	stop := a.start(t)
	a.waitReady(t)
	if err := a.Run(context.Background()); err == nil {
		t.Fatal("second Run accepted")
	}
	stop()
}

func TestCancellationInterruptsABlockedHandshake(t *testing.T) {
	var peers []net.Conn
	var mu sync.Mutex
	key, err := overlay.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a := New(Config{
		Identity: key,
		Dial: func(context.Context) (net.Conn, error) {
			client, server := net.Pipe() // nobody reads the server end
			mu.Lock()
			peers = append(peers, server)
			mu.Unlock()
			return client, nil
		},
		DialLocal: func(context.Context, string, uint16, netip.Addr) (net.Conn, error) { return nil, errors.New("unused") },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run stayed blocked in the handshake")
	}
	mu.Lock()
	for _, p := range peers {
		_ = p.Close()
	}
	mu.Unlock()
}

func settledGoroutines(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > baseline {
		buffer := make([]byte, 1<<16)
		t.Fatalf("goroutines leaked: %d > %d\n%s", got, baseline, buffer[:runtime.Stack(buffer, true)])
	}
}

func TestNoGoroutineLeaksAfterTraffic(t *testing.T) {
	baseline := runtime.NumGoroutine()
	func() {
		hub := newFakeHub(t)
		calls := make(chan localCall, 8)
		tcp, udp, stopEcho := echoServers(t)
		a := hub.newAgent(t, "a", nil)
		b := hub.newAgent(t, "b", echoLocal(tcp, udp, calls))
		stopA, stopB := a.start(t), b.start(t)
		a.waitReady(t)
		bIP := b.waitReady(t)
		a.waitState(t, "B listed", hasPeer(bIP))
		var kept []net.Conn
		defer func() {
			for _, conn := range kept {
				_ = conn.Close()
			}
		}()
		for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
			conn, err := a.Outbound(context.Background(), proto, netip.AddrPortFrom(bIP, 9))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = conn.Write([]byte("ping"))
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buffer := make([]byte, 16)
			if n, err := conn.Read(buffer); err != nil || !strings.HasPrefix(string(buffer[:n]), "ping") {
				t.Fatalf("%s echo = %q, %v", proto, buffer[:n], err)
			}
			// Leave the flows open: cancellation must reap them.
			kept = append(kept, conn)
		}
		stopA()
		stopB()
		hub.close()
		stopEcho()
	}()
	settledGoroutines(t, baseline)
}
