package overlayagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/stun/v4"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

func startPolicyHub(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("OVERLAY_HUB_BIN")
	if binary == "" {
		t.Skip("OVERLAY_HUB_BIN is not set")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	command := exec.CommandContext(ctx, binary)
	command.Env = append(os.Environ(), "OVERLAY_ALLOWED_HOST=", "OVERLAY_LISTEN_ADDRESS="+address, "OVERLAY_DATA_DIR="+t.TempDir())
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = command.Wait() })
	wait, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := (&net.Dialer{}).DialContext(wait, "tcp4", address)
		if err == nil {
			closeConn(conn)
			return address
		}
		select {
		case <-wait.Done():
			t.Fatal("Rust hub did not start", err)
		case <-ticker.C:
		}
	}
}

func policySTUN(t *testing.T) string {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, from, err := socket.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			request := &stun.Message{Raw: buffer[:n]}
			if request.Decode() != nil || request.Type != stun.BindingRequest {
				continue
			}
			mapped := &stun.XORMappedAddress{IP: from.IP.To4(), Port: from.Port}
			response, err := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(request.TransactionID), mapped)
			if err == nil {
				_, _ = socket.WriteToUDP(response.Raw, from)
			}
		}
	}()
	return socket.LocalAddr().String()
}

// Observe hub stream kinds at the socket boundary. The hub cannot carry
// application data for a flow unless an open is paired with an accept.
type policyHubTap struct {
	opened, accepted, signaled atomic.Int32
}

type policyHubConn struct {
	net.Conn
	first sync.Once
	tap   *policyHubTap
}

func (c *policyHubConn) Write(p []byte) (int, error) {
	c.first.Do(func() {
		var hello overlay.Hello
		if overlay.ReadFrame(bytes.NewReader(p), &hello) != nil {
			return
		}
		switch hello.Kind {
		case overlay.KindOpen:
			c.tap.opened.Add(1)
		case overlay.KindAccept:
			c.tap.accepted.Add(1)
		case overlay.KindSignal:
			c.tap.signaled.Add(1)
		}
	})
	return c.Conn.Write(p)
}

func startPolicyAgent(t *testing.T, base *Config, address string) (*testAgent, *policyHubTap) {
	t.Helper()
	cfg := *base
	tap := new(policyHubTap)
	a := &testAgent{key: cfg.Identity}
	cfg.OnState = func(s overlay.State) {
		a.mu.Lock()
		a.states = append(a.states, s)
		a.mu.Unlock()
	}
	if cfg.Dial == nil {
		cfg.Dial = func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", address)
		}
	}
	dial := cfg.Dial
	cfg.Dial = func(ctx context.Context) (net.Conn, error) {
		conn, err := dial(ctx)
		if err != nil {
			return nil, err
		}
		return &policyHubConn{Conn: conn, tap: tap}, nil
	}
	a.Agent = New(cfg)
	a.start(t)
	a.waitReady(t)
	return a, tap
}

func policyAccounts(t *testing.T) (keys [2]*ecdsa.PrivateKey, ids [2]string) {
	t.Helper()
	for i := range keys {
		var err error
		keys[i], err = overlay.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		key, err := overlay.PublicIdentity(keys[i])
		if err == nil {
			ids[i], err = overlay.IdentityID(key)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return keys, ids
}

func policyFlow(t *testing.T, from, to *testAgent, proto string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	conn, err := from.Outbound(ctx, proto, netip.AddrPortFrom(to.IP(), 7000))
	if err != nil {
		t.Fatal(proto, err)
	}
	t.Cleanup(func() { closeConn(conn) })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func policyRoundTrip(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buffer); err != nil || string(buffer) != payload {
		t.Fatalf("payload round trip: got %q, %v; want %q", buffer, err, payload)
	}
}

func TestDirectOnlyPayloadUsesRealDirect(t *testing.T) {
	for _, method := range []string{methodWebRTC, methodICE} {
		for _, first := range []int{0, 1} {
			t.Run(method+"/initiator-"+string(rune('A'+first)), func(t *testing.T) {
				address := startPolicyHub(t)
				stunAddr := policySTUN(t)
				keys, ids := policyAccounts(t)
				tcp, udp, _ := echoServers(t)
				var agents [2]*testAgent
				var taps [2]*policyHubTap
				for i := range agents {
					cfg := Config{
						Identity: keys[i], DirectOnly: []string{ids[1-i]},
						DialLocal: echoLocal(tcp, udp, make(chan localCall, 8)),
						Direct: &DirectOptions{
							STUNServers: []string{stunAddr}, Methods: []string{method},
							ListenPacket: func(context.Context) (net.PacketConn, error) {
								return net.ListenPacket("udp4", "127.0.0.1:0")
							},
						},
					}
					agents[i], taps[i] = startPolicyAgent(t, &cfg, address)
				}
				for i, a := range agents {
					a.waitState(t, "direct-only authorizes the advertised peer", func(s overlay.State) bool {
						return len(s.Peers) == 1 && s.Peers[0].ID == ids[1-i] && s.Peers[0].DirectAllowed
					})
				}
				for _, i := range []int{first, 1 - first} {
					for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
						// The first call starts and awaits real direct setup.
						flow := policyFlow(t, agents[i], agents[1-i], proto)
						policyRoundTrip(t, flow, "first-attempt direct payload "+proto)
						agents[i].waitState(t, "payload carried by "+method, func(s overlay.State) bool {
							return len(s.Peers) == 1 && s.Peers[0].DirectMethod == method && s.Peers[0].DirectFlows > 0 && s.Peers[0].RelayFlows == 0
						})
						closeConn(flow)
					}
				}
				if taps[first].opened.Load() != 0 || taps[1-first].opened.Load() != 0 || taps[first].signaled.Load() != 1 || taps[1-first].accepted.Load() != 1 {
					t.Fatal("expected one hub signaling pair and no payload relay openings")
				}
			})
		}
	}
}

func TestDirectOnlyRevokesRealRelayBothWays(t *testing.T) {
	address := startPolicyHub(t)
	keys, ids := policyAccounts(t)
	tcp, udp, _ := echoServers(t)
	blocked := make(chan struct{}, 2)
	calls := make(chan localCall, 16)
	cfg := Config{
		Identity: keys[0], DialLocal: echoLocal(tcp, udp, calls),
		LogRelay: func(line string) {
			if strings.Contains(line, "result=blocked reason=direct-only policy") {
				blocked <- struct{}{}
			}
		},
	}
	a, aTap := startPolicyAgent(t, &cfg, address)
	cfg.Identity, cfg.LogRelay = keys[1], nil
	b, bTap := startPolicyAgent(t, &cfg, address)
	a.waitState(t, "receiver registered", hasPeer(b.IP()))
	b.waitState(t, "sender registered", hasPeer(a.IP()))

	var fromA, fromB []net.Conn
	for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
		fromA = append(fromA, policyFlow(t, a, b, proto))
		fromB = append(fromB, policyFlow(t, b, a, proto))
	}
	router := &Router{agent: a.Agent}
	id := []string{ids[1]}
	if err := router.SetPeerPolicy(id, nil, id); err == nil {
		t.Fatal("accepted conflicting policy")
	}
	for _, flow := range append(append([]net.Conn{}, fromA...), fromB...) {
		policyRoundTrip(t, flow, "relay before policy update")
	}
	if len(calls) != 4 || aTap.opened.Load() != 2 || aTap.accepted.Load() != 2 || bTap.opened.Load() != 2 || bTap.accepted.Load() != 2 {
		t.Fatal("expected four working payload relay streams before policy update")
	}
	if err := router.SetPeerPolicy(nil, nil, id); err != nil {
		t.Fatal(err)
	}
	for _, flow := range fromA {
		if n, err := io.WriteString(flow, "not relayed"); n != 0 || err == nil {
			t.Fatalf("revoked outgoing flow wrote %d bytes, err=%v", n, err)
		}
	}
	for _, flow := range fromB {
		n, err := flow.Read(make([]byte, 32))
		var netErr net.Error
		if n != 0 || err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
			t.Fatalf("revoked incoming flow did not close: n=%d err=%v", n, err)
		}
	}
	for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		if conn, err := a.Outbound(ctx, proto, netip.AddrPortFrom(b.IP(), 7000)); !errors.Is(err, errDirectRequired) {
			if conn != nil {
				closeConn(conn)
			}
			cancel()
			t.Fatalf("outgoing %s should fail without direct: %v", proto, err)
		}
		result := make(chan error, 1)
		go func() {
			conn, err := b.Outbound(ctx, proto, netip.AddrPortFrom(a.IP(), 7000))
			if conn != nil {
				closeConn(conn)
			}
			result <- err
		}()
		select {
		case <-blocked:
		case <-ctx.Done():
			cancel()
			t.Fatalf("receiver did not block incoming %s", proto)
		}
		cancel()
		if err := <-result; err == nil {
			t.Fatalf("remote %s dial succeeded despite receiver policy", proto)
		}
	}
	if len(calls) != 4 || aTap.opened.Load() != 2 || aTap.accepted.Load() != 2 || bTap.opened.Load() != 4 || bTap.accepted.Load() != 2 {
		t.Fatal("direct-only must open no payload relay and accept no incoming payload relay")
	}
	other, err := overlay.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Identity = other
	c, _ := startPolicyAgent(t, &cfg, address)
	a.waitState(t, "unrestricted peer registered", hasPeer(c.IP()))
	c.waitState(t, "restricted peer's neighbor registered", hasPeer(a.IP()))
	policyRoundTrip(t, policyFlow(t, a, c, overlay.ProtoTCP), "other peer still relays outbound")
	policyRoundTrip(t, policyFlow(t, c, a, overlay.ProtoUDP), "other peer still relays inbound")
	if err := router.SetPeerPolicy(id, nil, nil); err != nil {
		t.Fatal(err)
	}
	policyRoundTrip(t, policyFlow(t, a, b, overlay.ProtoTCP), "relay restored outbound")
	policyRoundTrip(t, policyFlow(t, b, a, overlay.ProtoUDP), "relay restored inbound")
}

// Pause after the hub pairs the stream but before the agent admits the flow.
type policyGateConn struct {
	net.Conn
	entered, release chan struct{}
}

func (c *policyGateConn) SetDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		close(c.entered)
		<-c.release
	}
	return c.Conn.SetDeadline(deadline)
}

func TestDirectOnlyRevokesPendingRelay(t *testing.T) {
	for _, tc := range []struct {
		name               string
		incoming, identity bool
	}{
		{name: "outgoing-policy"},
		{name: "incoming-policy", incoming: true},
		{name: "outgoing-identity", identity: true},
		{name: "incoming-identity", incoming: true, identity: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address := startPolicyHub(t)
			keys, ids := policyAccounts(t)
			tcp, udp, _ := echoServers(t)
			calls := make(chan localCall, 4)
			var armed atomic.Bool
			entered, release := make(chan struct{}), make(chan struct{})
			cfg := Config{Identity: keys[0], DisableEncryption: true, DialLocal: echoLocal(tcp, udp, calls)}
			cfg.Dial = func(ctx context.Context) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
				if err == nil && armed.Swap(false) {
					return &policyGateConn{Conn: conn, entered: entered, release: release}, nil
				}
				return conn, err
			}
			a, _ := startPolicyAgent(t, &cfg, address)
			cfg.Identity, cfg.Dial = keys[1], nil
			cfg.DialLocal = echoLocal(tcp, udp, make(chan localCall, 4))
			b, _ := startPolicyAgent(t, &cfg, address)
			a.waitState(t, "registered peer", hasPeer(b.IP()))
			b.waitState(t, "registered peer", hasPeer(a.IP()))
			resume := sync.OnceFunc(func() { close(release) })
			defer resume()
			armed.Store(true)
			from, to := a, b
			if tc.incoming {
				from, to = b, a
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			type result struct {
				conn net.Conn
				err  error
			}
			opened := make(chan result, 1)
			go func() {
				conn, err := from.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(to.IP(), 7000))
				opened <- result{conn, err}
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("hub handshake did not reach the admission gate")
			}
			// Restore the original policy or identity before resuming. A late
			// equality check without revocation would accept the stale stream.
			if tc.identity {
				a.setPeers([]overlay.Peer{{IP: b.IP().String(), ID: ids[0]}})
				a.setPeers([]overlay.Peer{{IP: b.IP().String(), ID: ids[1]}})
			} else {
				if err := a.SetPeerPolicy(nil, nil, []string{ids[1]}); err != nil {
					t.Fatal(err)
				}
				if err := a.SetPeerPolicy(nil, nil, nil); err != nil {
					t.Fatal(err)
				}
			}
			resume()
			var got result
			select {
			case got = <-opened:
			case <-ctx.Done():
				t.Fatal("pending relay did not finish")
			}
			if got.conn != nil {
				defer closeConn(got.conn)
				if !tc.incoming {
					t.Fatal("revoked outgoing handshake returned a flow")
				}
				// The sender can see the hub's pairing before the receiver
				// finishes its handshake. The receiver must abort that stream.
				if err := got.conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := got.conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("revoked incoming handshake did not close: %v", err)
				}
			} else if got.err == nil {
				t.Fatal("pending relay returned neither a flow nor an error")
			}
			if len(calls) != 0 {
				t.Fatal("revoked incoming handshake dialed the local service")
			}
			policyRoundTrip(t, policyFlow(t, from, to, overlay.ProtoTCP), "fresh flow after rollback")
		})
	}
}

func TestDirectOnlyNoFallbackAfterSignaling(t *testing.T) {
	address := startPolicyHub(t)
	keys, ids := policyAccounts(t)
	stunAddr := policySTUN(t)
	tcp, udp, _ := echoServers(t)
	calls := make(chan localCall, 2)
	cfg := Config{
		Identity: keys[0], DirectOnly: []string{ids[1]}, DialLocal: echoLocal(tcp, udp, calls),
		Direct: &DirectOptions{STUNServers: []string{stunAddr}, Methods: []string{methodWebRTC}},
	}
	a, aTap := startPolicyAgent(t, &cfg, address)
	cfg.Identity, cfg.DirectOnly, cfg.DirectPeers = keys[1], nil, []string{ids[0]}
	cfg.Direct = &DirectOptions{STUNServers: []string{stunAddr}, Methods: []string{methodICE}}
	b, bTap := startPolicyAgent(t, &cfg, address)
	a.waitState(t, "different-method peer registered", hasPeer(b.IP()))
	b.waitState(t, "different-method peer registered", hasPeer(a.IP()))
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := a.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(b.IP(), 7000))
	if conn != nil {
		closeConn(conn)
	}
	if conn != nil || !errors.Is(err, errDirectRequired) || len(calls) != 0 {
		t.Fatalf("incompatible direct methods must not fall back to relay: %v", err)
	}
	if aTap.signaled.Load() != 1 || aTap.opened.Load() != 0 || bTap.accepted.Load() != 1 {
		t.Fatal("hub must see a signaling pair but no payload open")
	}
}

func TestDirectOnlyPolicyValidation(t *testing.T) {
	keys, ids := policyAccounts(t)
	dial := func(context.Context) (net.Conn, error) {
		t.Error("conflicting initial policy dialed the hub")
		return nil, net.ErrClosed
	}
	cfg := Config{
		Identity: keys[0], RelayOnly: []string{ids[1]}, DirectOnly: []string{ids[1]},
		Dial: dial, DialLocal: func(context.Context, string, uint16, netip.Addr) (net.Conn, error) { return nil, net.ErrClosed },
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := New(cfg).Run(ctx); err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("conflicting initial policy did not fail validation: %v", err)
	}
	a := New(Config{Identity: keys[0], DirectOnly: []string{ids[1]}})
	if err := a.SetDirectPeers(nil); err != nil {
		t.Fatal(err)
	}
	if err := a.SetRelayOnly([]string{ids[1]}); err == nil {
		t.Fatal("legacy setter silently overwrote direct-only policy")
	}
	if err := a.SetPeerPolicy(nil, nil, []string{"not-a-device-id"}); err == nil {
		t.Fatal("accepted a malformed direct-only device ID")
	}
}
