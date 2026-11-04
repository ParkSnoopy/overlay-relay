package tests

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"github.com/ParkSnoopy/overlay-relay/client/overlayagent"
)

// plainMarker appears in every line of the text payload. Seeing it on the hub
// connection means the hub could read the file.
var plainMarker = []byte("overlay relay compressible payload")

// hubTap records every byte an agent exchanges with the hub.
type hubTap struct {
	mu    sync.Mutex
	bytes bytes.Buffer
}

func (h *hubTap) record(data []byte) {
	h.mu.Lock()
	h.bytes.Write(data)
	h.mu.Unlock()
}

func (h *hubTap) snapshot() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return bytes.Clone(h.bytes.Bytes())
}

type tappedConn struct {
	net.Conn
	tap *hubTap
}

func (c *tappedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.tap.record(p[:n])
	return n, err
}

func (c *tappedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.tap.record(p[:n])
	return n, err
}

// startSTUN answers Binding requests with the sender's address, like a public
// STUN server does. On loopback the address is the loopback address itself.
func startSTUN(t *testing.T) string {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, from, err := socket.ReadFrom(buffer)
			if err != nil {
				return
			}
			udp, ok := from.(*net.UDPAddr)
			if !ok || n < 20 || binary.BigEndian.Uint16(buffer[0:2]) != 0x0001 {
				continue
			}
			address, ok := netip.AddrFromSlice(udp.IP.To4())
			if !ok {
				continue
			}
			_, _ = socket.WriteTo(stunSuccess(buffer[8:20], address, uint16(udp.Port)), from)
		}
	}()
	return socket.LocalAddr().String()
}

// stunSuccess builds a Binding success response with an XOR-MAPPED-ADDRESS.
func stunSuccess(transaction []byte, address netip.Addr, port uint16) []byte {
	const cookie = 0x2112A442
	raw := address.As4()
	mask := binary.BigEndian.AppendUint32(nil, cookie)
	for i := range raw {
		raw[i] ^= mask[i]
	}
	value := []byte{0, 0x01}
	value = binary.BigEndian.AppendUint16(value, port^uint16(cookie>>16))
	value = append(value, raw[:]...)
	attribute := binary.BigEndian.AppendUint16(nil, 0x0020)
	attribute = binary.BigEndian.AppendUint16(attribute, uint16(len(value)))
	attribute = append(attribute, value...)
	packet := binary.BigEndian.AppendUint16(nil, 0x0101)
	packet = binary.BigEndian.AppendUint16(packet, uint16(len(attribute)))
	packet = binary.BigEndian.AppendUint32(packet, cookie)
	packet = append(packet, transaction...)
	return append(packet, attribute...)
}

// secureSide configures one agent of a secureEnv.
type secureSide struct {
	name   string
	plain  bool // DisableEncryption
	direct bool // offer a direct connection
	nat    bool // drop UDP to everything but the STUN server, like a NAT that refuses hole punching
}

// natConn drops datagrams to any address except the STUN server.
type natConn struct {
	net.PacketConn
	stun string
}

func (c natConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr.String() != c.stun {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

type secureEnv struct {
	alice, bob             *overlayagent.Agent
	aliceStates, bobStates chan overlay.State
	aliceIP, bobIP         netip.Addr
	aliceTap, bobTap       *hubTap
	aliceSink, bobSink     *fileSink
}

func newSecureAgent(hub string, account account, side secureSide, stun string, tap *hubTap, states chan<- overlay.State, sink *fileSink) *overlayagent.Agent {
	config := overlayagent.Config{
		Name:              side.name,
		Identity:          account.key,
		DisableEncryption: side.plain,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "tcp", hub)
			if err != nil {
				return nil, err
			}
			return &tappedConn{Conn: conn, tap: tap}, nil
		},
		DialLocal: func(ctx context.Context, _ string, _ uint16, _ netip.Addr) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", sink.tcp.Addr().String())
		},
		OnState: func(state overlay.State) {
			select {
			case states <- state:
			default:
			}
		},
	}
	if side.direct {
		config.Direct = &overlayagent.DirectOptions{
			STUNServers: []string{stun},
			// Bind loopback so the endpoint the STUN server reports is reachable.
			ListenPacket: func(context.Context) (net.PacketConn, error) {
				socket, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil || !side.nat {
					return socket, err
				}
				return natConn{PacketConn: socket, stun: stun}, nil
			},
			Timeout: 500 * time.Millisecond,
		}
	}
	return overlayagent.New(config)
}

func startSecureEnv(t *testing.T, alice, bob secureSide) *secureEnv {
	t.Helper()
	hubBinary := buildHub(t)
	aliceAccount := newAccount(t, "alice")
	bobAccount := newAccount(t, "bob")
	hub := startHub(t, hubBinary)
	stun := startSTUN(t)

	env := &secureEnv{aliceTap: &hubTap{}, bobTap: &hubTap{}, aliceSink: startSink(t, t.TempDir()), bobSink: startSink(t, t.TempDir())}
	aliceStates := make(chan overlay.State, 64)
	bobStates := make(chan overlay.State, 64)
	env.aliceStates, env.bobStates = aliceStates, bobStates
	env.alice = newSecureAgent(hub.address, aliceAccount, alice, stun, env.aliceTap, aliceStates, env.aliceSink)
	env.bob = newSecureAgent(hub.address, bobAccount, bob, stun, env.bobTap, bobStates, env.bobSink)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = env.alice.Run(ctx) }()
	go func() { _ = env.bob.Run(ctx) }()
	env.aliceIP = <-env.alice.Ready()
	env.bobIP = <-env.bob.Ready()
	waitFor(t, aliceStates, func(state overlay.State) bool {
		return state.Connected && len(state.Peers) == 1 && state.Peers[0].IP == env.bobIP.String()
	})
	waitFor(t, bobStates, func(state overlay.State) bool {
		return state.Connected && len(state.Peers) == 1 && state.Peers[0].IP == env.aliceIP.String()
	})
	return env
}

// sendFromAlice sends one text file from alice to bob over TCP.
func sendFromAlice(t *testing.T, env *secureEnv, size int) (source string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	source = writeSource(t, "from-alice.bin", size, true)
	_, err = sendFile(ctx, env.alice, env.bobIP, overlay.ProtoTCP, source)
	return source, err
}

const secureFileSize = 1 << 20

func TestPlaintextRelayIsVisibleToTheHub(t *testing.T) {
	// A control for the tests below: with encryption off the tap does see the file.
	env := startSecureEnv(t, secureSide{plain: true}, secureSide{plain: true})
	source, err := sendFromAlice(t, env, secureFileSize)
	if err != nil {
		t.Fatal(err)
	}
	requireSameFile(t, source, filepath.Join(env.bobSink.dir, "from-alice.bin"))
	if !bytes.Contains(env.aliceTap.snapshot(), plainMarker) {
		t.Fatal("the tap must see plaintext when encryption is disabled")
	}
}

func TestRelayedFlowIsEncryptedByDefault(t *testing.T) {
	env := startSecureEnv(t, secureSide{}, secureSide{})
	source, err := sendFromAlice(t, env, secureFileSize)
	if err != nil {
		t.Fatal(err)
	}
	requireSameFile(t, source, filepath.Join(env.bobSink.dir, "from-alice.bin"))
	for name, tap := range map[string]*hubTap{"alice": env.aliceTap, "bob": env.bobTap} {
		seen := tap.snapshot()
		if bytes.Contains(seen, plainMarker) {
			t.Errorf("%s: the hub connection carried plaintext", name)
		}
		if len(seen) < secureFileSize {
			t.Errorf("%s: the hub carried %d bytes, want the relayed file (at least %d)", name, len(seen), secureFileSize)
		}
	}
}

func TestDirectFlowBypassesTheHub(t *testing.T) {
	env := startSecureEnv(t, secureSide{direct: true, name: "DUMMY Alice laptop"}, secureSide{direct: true, name: "DUMMY Bob 기기"})
	source, err := sendFromAlice(t, env, 2*secureFileSize)
	if err != nil {
		t.Fatal(err)
	}
	requireSameFile(t, source, filepath.Join(env.bobSink.dir, "from-alice.bin"))
	// Control traffic (hello, pings, the hand-off replies) is small. A relayed
	// 2 MiB file would be far larger.
	for _, side := range []struct {
		states    <-chan overlay.State
		own, peer string
	}{
		{env.aliceStates, "DUMMY Alice laptop", "DUMMY Bob 기기"}, {env.bobStates, "DUMMY Bob 기기", "DUMMY Alice laptop"},
	} {
		state := waitFor(t, side.states, func(state overlay.State) bool {
			return len(state.Peers) == 1 && state.Peers[0].LastPath == overlay.PathDirect && state.Peers[0].DirectStatus == overlay.DirectSucceeded
		})
		if state.Name != side.own || state.Peers[0].Name != side.peer || !state.Peers[0].DirectAllowed {
			t.Fatal("device name or direct eligibility lost", state)
		}
		waitFor(t, side.states, func(state overlay.State) bool {
			return len(state.Peers) == 1 && state.Peers[0].DirectFlows == 0 && state.Peers[0].LastPath == overlay.PathDirect
		})
	}
	const hubBudget = 32 << 10
	for name, tap := range map[string]*hubTap{"alice": env.aliceTap, "bob": env.bobTap} {
		seen := tap.snapshot()
		if len(seen) > hubBudget {
			t.Errorf("%s: the hub carried %d bytes, want at most %d for a direct flow", name, len(seen), hubBudget)
		}
		if bytes.Contains(seen, plainMarker) {
			t.Errorf("%s: the hub connection carried plaintext", name)
		}
	}
}

func TestDevicePolicyClosesDirectFlowsAndRelaysBothDirections(t *testing.T) {
	both := secureSide{direct: true}
	env := startSecureEnv(t, both, both)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	flow, err := env.alice.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(env.bobIP, 7000))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = flow.Close() }()
	aliceState := waitFor(t, env.aliceStates, func(state overlay.State) bool {
		return len(state.Peers) == 1 && state.Peers[0].DirectFlows == 1 && state.Peers[0].RelayFlows == 0
	})
	bobState := waitFor(t, env.bobStates, func(state overlay.State) bool {
		return len(state.Peers) == 1 && state.Peers[0].DirectFlows == 1
	})
	aliceID, bobID := bobState.Peers[0].ID, aliceState.Peers[0].ID
	if !overlay.ValidPeerID(aliceID) || !overlay.ValidPeerID(bobID) || aliceID == bobID {
		t.Fatal("missing distinct device identities")
	}
	if err := env.bob.SetRelayOnly([]string{aliceID}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, env.bobStates, func(state overlay.State) bool {
		return len(state.Peers) == 1 && state.Peers[0].DirectFlows == 0 && !state.Peers[0].DirectAllowed
	})
	_ = flow.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := flow.Read(make([]byte, 1)); err == nil {
		t.Fatal("denied direct flow stayed open")
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatal("denied direct flow did not close promptly")
		}
	}
	_ = flow.Close()
	incoming, err := env.alice.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(env.bobIP, 7000))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = incoming.Close() }()
	outgoing, err := env.bob.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(env.aliceIP, 7000))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outgoing.Close() }()
	waitFor(t, env.bobStates, func(state overlay.State) bool {
		return len(state.Peers) == 1 && state.Peers[0].DirectFlows == 0 && state.Peers[0].RelayFlows == 2
	})
	_ = incoming.Close()
	_ = outgoing.Close()
	if err := env.bob.SetRelayOnly(nil); err != nil {
		t.Fatal(err)
	}
	restored, err := env.bob.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(env.aliceIP, 7000))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restored.Close() }()
	waitFor(t, env.bobStates, func(state overlay.State) bool {
		return len(state.Peers) == 1 && state.Peers[0].DirectFlows == 1
	})
}

func TestFailedDirectConnectionFallsBackToTheEncryptedRelay(t *testing.T) {
	blocked := secureSide{direct: true, nat: true}
	env := startSecureEnv(t, blocked, blocked)
	for _, name := range []string{"first", "second"} {
		source, err := sendFromAlice(t, env, secureFileSize)
		if err != nil {
			t.Fatalf("%s flow: %v", name, err)
		}
		requireSameFile(t, source, filepath.Join(env.bobSink.dir, "from-alice.bin"))
	}
	for name, tap := range map[string]*hubTap{"alice": env.aliceTap, "bob": env.bobTap} {
		seen := tap.snapshot()
		if len(seen) < 2*secureFileSize || bytes.Contains(seen, plainMarker) {
			t.Errorf("%s: the hub carried %d bytes, plaintext=%t; want both files relayed and encrypted", name, len(seen), bytes.Contains(seen, plainMarker))
		}
	}
}

func TestFailedDirectStatusSurvivesRelayFlowClosure(t *testing.T) {
	blocked := secureSide{direct: true, nat: true}
	env := startSecureEnv(t, blocked, blocked)
	for range 2 {
		if _, err := sendFromAlice(t, env, 4096); err != nil {
			t.Fatal(err)
		}
	}
	for _, states := range []<-chan overlay.State{env.aliceStates, env.bobStates} {
		waitFor(t, states, func(state overlay.State) bool {
			return len(state.Peers) == 1 && state.Peers[0].DirectAllowed && state.Peers[0].DirectStatus == overlay.DirectFailed && state.Peers[0].LastPath == overlay.PathRelay && state.Peers[0].DirectFlows == 0 && state.Peers[0].RelayFlows == 0
		})
	}
}

func TestOneSidedDirectOfferStaysOnTheEncryptedRelay(t *testing.T) {
	env := startSecureEnv(t, secureSide{direct: true}, secureSide{})
	source, err := sendFromAlice(t, env, secureFileSize)
	if err != nil {
		t.Fatal(err)
	}
	requireSameFile(t, source, filepath.Join(env.bobSink.dir, "from-alice.bin"))
	waitFor(t, env.aliceStates, func(state overlay.State) bool {
		return len(state.Peers) == 1 && state.Peers[0].DirectAllowed && state.Peers[0].DirectStatus == overlay.DirectUnavailable && state.Peers[0].LastPath == overlay.PathRelay
	})
	seen := env.aliceTap.snapshot()
	if len(seen) < secureFileSize || bytes.Contains(seen, plainMarker) {
		t.Fatalf("the flow must be relayed and encrypted: hub carried %d bytes, plaintext=%t", len(seen), bytes.Contains(seen, plainMarker))
	}
}

func TestEncryptingAgentRefusesAPlaintextPeer(t *testing.T) {
	env := startSecureEnv(t, secureSide{}, secureSide{plain: true})
	if _, err := sendFromAlice(t, env, 64<<10); err == nil {
		t.Fatal("an encrypting agent must not send to a peer that cannot encrypt")
	}
	entries, err := os.ReadDir(env.bobSink.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the plaintext peer received %d files, want none", len(entries))
	}
}
