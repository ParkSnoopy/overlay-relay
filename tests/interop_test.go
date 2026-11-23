package tests

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"github.com/ParkSnoopy/overlay-relay/client/overlayagent"
)

type hubProcess struct {
	address string
	dir     string
	cmd     *exec.Cmd
}

func buildHub(t *testing.T) string {
	t.Helper()
	if binary := os.Getenv("OVERLAY_TEST_HUB"); binary != "" {
		return binary
	}
	binary := filepath.Join(t.TempDir(), "overlay-hub")
	build := exec.Command("go", "build", "-mod=readonly", "-o", binary, ".")
	build.Dir = "../server"
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build overlay-hub: %v", err)
	}
	return binary
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().String()
}

// startHub starts the hub with no configuration and waits until it accepts a source.
func startHub(t *testing.T, binary string, environment ...string) hubProcess {
	t.Helper()
	dir := t.TempDir()
	address := freeAddress(t)
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"OVERLAY_DATA_DIR="+dir,
		"OVERLAY_LISTEN_ADDRESS="+address,
	)
	cmd.Env = append(cmd.Env, environment...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hub did not listen on %s: %v", address, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return hubProcess{address: address, dir: dir, cmd: cmd}
}

type account struct {
	name string
	key  *ecdsa.PrivateKey
}

func newAccount(t *testing.T, name string) account {
	t.Helper()
	key, err := overlay.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return account{name: name, key: key}
}

func newAgent(t *testing.T, hub string, account account, states chan<- overlay.State, local func(port uint16) string, configure ...func(*overlayagent.Config)) *overlayagent.Agent {
	t.Helper()
	config := overlayagent.Config{
		Identity: account.key,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", hub)
		},
		DialLocal: func(ctx context.Context, proto string, port uint16, src netip.Addr) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", local(port))
		},
		OnState: func(state overlay.State) {
			select {
			case states <- state:
			default:
			}
		},
	}
	for _, apply := range configure {
		apply(&config)
	}
	return overlayagent.New(config)
}

func waitFor(t *testing.T, states <-chan overlay.State, done func(overlay.State) bool) overlay.State {
	t.Helper()
	timeout := time.After(15 * time.Second)
	for {
		select {
		case state := <-states:
			if done(state) {
				return state
			}
		case <-timeout:
			t.Fatal("timed out waiting for overlay state")
		}
	}
}

func TestAgentAndHubPrivateRoomTCP(t *testing.T) {
	binary := buildHub(t)
	alice := newAccount(t, "alice")
	bob := newAccount(t, "bob")
	hub := startHub(t, binary, "OVERLAY_CIDR=10.0.0.0/8")
	room, err := overlay.RoomToken("DUMMY private room", "DUMMY password")
	if err != nil {
		t.Fatal(err)
	}
	const roomID = "DUMMY private room"
	configure := func(config *overlayagent.Config) {
		config.CIDR = netip.MustParsePrefix("10.0.0.0/8")
		config.Room = room
		config.RoomID = roomID
	}

	// The hub refuses a private room until the operator creates it.
	discover := overlayagent.Config{
		Identity: alice.key,
		Room:     room,
		RoomID:   roomID,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", hub.address)
		},
	}
	if _, err := overlayagent.DiscoverCIDR(context.Background(), discover); err == nil || !strings.Contains(err.Error(), "room does not exist") {
		t.Fatalf("missing room error = %v, want room does not exist", err)
	}
	other := discover
	other.Room, err = overlay.RoomToken(roomID, "DUMMY other password")
	if err != nil {
		t.Fatal(err)
	}
	create := exec.Command(binary, "rooms", "create", roomID, "DUMMY room name", room)
	create.Env = append(os.Environ(), "OVERLAY_DATA_DIR="+hub.dir)
	if output, err := create.CombinedOutput(); err != nil {
		t.Fatalf("create room: %v: %s", err, output)
	}
	if _, err := overlayagent.DiscoverCIDR(context.Background(), discover); err != nil {
		t.Fatalf("created room: %v", err)
	}
	// The room ID is unique: another password is denied.
	if _, err := overlayagent.DiscoverCIDR(context.Background(), other); err == nil || !strings.Contains(err.Error(), "room password is incorrect") {
		t.Fatalf("wrong password error = %v, want room password is incorrect", err)
	}

	// Bob's local service receives relayed flows at the overlay port.
	service, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	port := uint16(service.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			conn, err := service.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	localTarget := func(uint16) string { return service.Addr().String() }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aliceStates := make(chan overlay.State, 64)
	bobStates := make(chan overlay.State, 64)
	aliceAgent := newAgent(t, hub.address, alice, aliceStates, localTarget, configure)
	bobAgent := newAgent(t, hub.address, bob, bobStates, localTarget, configure)

	runErrs := make(chan error, 2)
	go func() { runErrs <- aliceAgent.Run(ctx) }()
	go func() { runErrs <- bobAgent.Run(ctx) }()

	aliceIP := <-aliceAgent.Ready()
	bobIP := <-bobAgent.Ready()
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	if !overlay.AssignableIn(prefix, aliceIP) || !overlay.AssignableIn(prefix, bobIP) || aliceIP == bobIP {
		t.Fatalf("invalid overlay addresses alice=%s bob=%s", aliceIP, bobIP)
	}
	waitFor(t, aliceStates, func(state overlay.State) bool {
		return state.Connected && len(state.Peers) == 1 && state.Peers[0].IP == bobIP.String()
	})

	flow, err := aliceAgent.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(bobIP, port))
	if err != nil {
		t.Fatalf("open flow to bob: %v", err)
	}
	defer func() { _ = flow.Close() }()
	if _, err := flow.Write([]byte("ping over overlay")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len("ping over overlay"))
	if err := flow.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(flow, reply); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(reply) != "ping over overlay" {
		t.Fatalf("echo mismatch: %q", reply)
	}

	// An address outside the peer snapshot is refused by the hub without relaying.
	unknown := netip.AddrPortFrom(netip.MustParseAddr("10.77.200.200"), port)
	if conn, err := aliceAgent.Outbound(ctx, overlay.ProtoTCP, unknown); err == nil {
		_ = conn.Close()
		t.Fatal("flow to unknown address succeeded")
	}

	cancel()
	for range 2 {
		if err := <-runErrs; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("agent run: %v", err)
		}
	}
}

func TestProbeNeedsNoEnrollment(t *testing.T) {
	hub := startHub(t, buildHub(t))
	if err := overlayagent.Probe(context.Background(), hub.address); err != nil {
		t.Fatal(err)
	}
}

func TestMixedWireDirect(t *testing.T) {
	legacy := os.Getenv("OVERLAY_TEST_LEGACY_SOURCE")
	if legacy == "" {
		t.Skip("set OVERLAY_TEST_LEGACY_SOURCE to an export of 00a8fd5 (wire v4)")
	}
	legacyHub := os.Getenv("OVERLAY_TEST_LEGACY_HUB")
	if legacyHub == "" {
		legacyHub = filepath.Join(legacy, "server", "target", "debug", "overlay-hub")
		build := exec.Command("cargo", "build", "--locked", "--quiet", "--bin", "overlay-hub")
		build.Dir = filepath.Join(legacy, "server")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build v4 hub: %v: %s", err, output)
		}
	}
	previous := filepath.Join(t.TempDir(), "wire-v4.test")
	args := []string{"test", "-c", "-o", previous}
	for _, name := range []string{"interop_test.go", "secure_test.go", "file_transfer_test.go", "direct_test.go"} {
		path, err := filepath.Abs(name)
		if err != nil {
			t.Fatal(err)
		}
		args = append(args, path)
	}
	build := exec.Command("go", args...)
	build.Dir = filepath.Join(legacy, "client")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build v4 peer: %v: %s", err, output)
	}
	t.Run("v4-baseline", func(t *testing.T) {
		baseline := exec.Command(previous, "-test.v", "-test.run=^TestNativeV4DirectBaseline$")
		baseline.Env = append(os.Environ(), "OVERLAY_V4_BASELINE_HUB="+legacyHub)
		if output, err := baseline.CombinedOutput(); err != nil {
			t.Fatalf("native v4 WebRTC baseline: %v: %s", err, output)
		}
	})
	for _, hub := range []struct{ name, binary string }{{"v5-hub", buildHub(t)}, {"v4-hub", legacyHub}} {
		for _, method := range []string{"webrtc", "ice"} {
			for _, initiator := range []string{"v5", "v4"} {
				t.Run(hub.name+"/"+method+"/"+initiator+"-initiates", func(t *testing.T) {
					testMixedWireDirect(t, hub.binary, previous, method, initiator == "v4")
				})
			}
		}
	}
}

func TestNativeV4DirectBaseline(t *testing.T) {
	hub := os.Getenv("OVERLAY_V4_BASELINE_HUB")
	if hub == "" {
		t.Skip("started by TestMixedWireDirect using the native v4 client")
	}
	if overlay.Version != 4 {
		t.Fatalf("baseline uses wire v%d, want v4", overlay.Version)
	}
	previous, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	testMixedWireDirect(t, hub, previous, "webrtc", false)
}

func interopPeerID(t *testing.T, peer account) string {
	t.Helper()
	public, err := overlay.PublicIdentity(peer.key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := overlay.IdentityID(public)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func testMixedWireDirect(t *testing.T, binary, previous, method string, oldInitiates bool) {
	t.Helper()
	hub := startHub(t, binary)
	deny := exec.Command(binary, "rooms", "relay", "public", "false")
	deny.Env = append(os.Environ(), "OVERLAY_DATA_DIR="+hub.dir)
	if output, err := deny.CombinedOutput(); err != nil {
		t.Fatalf("block relay: %v: %s", err, output)
	}
	stun := startSTUN(t)
	current, old := newAccount(t, "current"), newAccount(t, "previous")
	identity, err := overlay.EncodeIdentity(old.key)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "identity.pem")
	if err := os.WriteFile(key, identity, 0o600); err != nil {
		t.Fatal(err)
	}
	env := &secureEnv{aliceStates: make(chan overlay.State, 64), aliceTap: &hubTap{}, bobSink: &fileSink{dir: t.TempDir()}}
	options := &overlayagent.DirectOptions{STUNServers: []string{stun}, Methods: []string{method}}
	env.alice = newSecureAgent(hub.address, current, secureSide{transport: options}, stun, env.aliceTap, env.aliceStates, startSink(t, t.TempDir()))
	if err := env.alice.SetDirectPeers([]string{interopPeerID(t, old)}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	go func() { _ = env.alice.Run(ctx) }()
	child := exec.CommandContext(ctx, previous, "-test.run=^TestMixedWireDirectPeer$")
	child.Env = append(os.Environ(), "OVERLAY_TEST_DIRECT_HUB="+hub.address, "OVERLAY_TEST_DIRECT_STUN="+stun,
		"OVERLAY_TEST_DIRECT_IDENTITY="+key, "OVERLAY_TEST_DIRECT_APPROVAL="+interopPeerID(t, current),
		"OVERLAY_TEST_DIRECT_SINK="+env.bobSink.dir)
	if oldInitiates {
		child.Env = append(child.Env, "OVERLAY_TEST_DIRECT_INITIATE=1")
	}
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = child.Wait() }()
	state := waitFor(t, env.aliceStates, func(s overlay.State) bool { return s.Connected && len(s.Peers) == 1 })
	env.bobIP = netip.MustParseAddr(state.Peers[0].IP)
	if !oldInitiates {
		flow, err := env.alice.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(env.bobIP, 80))
		if err == nil {
			_ = flow.Close()
			t.Fatal("hub allowed payload relay")
		}
	}
	waitFor(t, env.aliceStates, func(s overlay.State) bool {
		return len(s.Peers) == 1 && s.Peers[0].DirectStatus == overlay.DirectSucceeded
	})
	for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
		if peer := transferDirect(t, env, false, proto); peer.DirectMethod != method {
			t.Fatalf("direct method = %q, want %q", peer.DirectMethod, method)
		}
	}
}

func TestMixedWireDirectPeer(t *testing.T) {
	hub := os.Getenv("OVERLAY_TEST_DIRECT_HUB")
	if hub == "" {
		t.Skip("started by TestMixedWireDirect")
	}
	if overlay.Version != 4 {
		t.Fatalf("built peer uses wire v%d, want v4", overlay.Version)
	}
	encoded, err := os.ReadFile(os.Getenv("OVERLAY_TEST_DIRECT_IDENTITY"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := overlay.ParseIdentity(encoded)
	if err != nil {
		t.Fatal(err)
	}
	states := make(chan overlay.State, 64)
	stun := os.Getenv("OVERLAY_TEST_DIRECT_STUN")
	options := &overlayagent.DirectOptions{STUNServers: []string{stun}}
	peer := newSecureAgent(hub, account{key: key}, secureSide{transport: options}, stun, &hubTap{}, states,
		startSink(t, os.Getenv("OVERLAY_TEST_DIRECT_SINK")))
	if err := peer.SetDirectPeers([]string{os.Getenv("OVERLAY_TEST_DIRECT_APPROVAL")}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() { _ = peer.Run(ctx) }()
	state := waitFor(t, states, func(s overlay.State) bool { return s.Connected && len(s.Peers) == 1 })
	if os.Getenv("OVERLAY_TEST_DIRECT_INITIATE") == "1" {
		ip := netip.MustParseAddr(state.Peers[0].IP)
		flow, err := peer.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(ip, 80))
		if err == nil {
			_ = flow.Close()
			t.Fatal("hub allowed payload relay")
		}
	}
	<-ctx.Done()
}

func TestPreviousReleaseInterop(t *testing.T) {
	legacyHub, legacyClient := os.Getenv("OVERLAY_TEST_LEGACY_HUB"), os.Getenv("OVERLAY_TEST_LEGACY_CLIENT")
	if legacyHub == "" || legacyClient == "" {
		t.Skip("set OVERLAY_TEST_LEGACY_HUB and OVERLAY_TEST_LEGACY_CLIENT to binaries built from 00a8fd5 (0.4.8, wire v4)")
	}
	for _, host := range []struct{ name, binary string }{{"updated-hub", buildHub(t)}, {"previous-hub", legacyHub}} {
		t.Run(host.name, func(t *testing.T) {
			hub := startHub(t, host.binary)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err := overlayagent.Probe(ctx, hub.address); err != nil {
				t.Fatal(err)
			}
			service, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = service.Close() }()
			go func() {
				for range 2 {
					conn, err := service.Accept()
					if err != nil {
						return
					}
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					_, _ = io.Copy(conn, conn)
					_ = conn.Close()
				}
			}()
			port := uint16(service.Addr().(*net.TCPAddr).Port)
			current := newAccount(t, "current")
			discover := overlayagent.Config{Identity: current.key, Dial: func(ctx context.Context) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", hub.address)
			}}
			_, ip, err := overlayagent.Discover(ctx, discover)
			if err != nil {
				t.Fatal(err)
			}
			states := make(chan overlay.State, 64)
			currentAgent := newAgent(t, hub.address, current, states, func(uint16) string { return service.Addr().String() })
			go func() { _ = currentAgent.Run(ctx) }()
			waitFor(t, states, func(state overlay.State) bool { return state.Connected })
			if registered := <-currentAgent.Ready(); registered != ip {
				t.Fatalf("registered address %s differs from discovery %s", registered, ip)
			}
			old := exec.CommandContext(ctx, legacyClient)
			old.Env = append(os.Environ(), "OVERLAY_HUB="+hub.address,
				"OVERLAY_IDENTITY="+filepath.Join(t.TempDir(), "identity.pem"), "OVERLAY_LOCAL=127.0.0.1",
				"OVERLAY_CONNECT="+netip.AddrPortFrom(ip, port).String())
			old.Stderr = os.Stderr
			stdout, err := old.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := old.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = old.Wait() }()
			lines := bufio.NewScanner(stdout)
			want := "reply from " + netip.AddrPortFrom(ip, port).String() + ": hello over overlay"
			for lines.Scan() && lines.Text() != want {
			}
			if lines.Text() != want {
				t.Fatalf("previous client did not receive an echo: %q (%v)", lines.Text(), lines.Err())
			}
			state := waitFor(t, states, func(state overlay.State) bool { return len(state.Peers) == 1 })
			previous, err := netip.ParseAddr(state.Peers[0].IP)
			if err != nil {
				t.Fatal(err)
			}
			flow, err := currentAgent.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(previous, port))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = flow.Close() }()
			_ = flow.SetDeadline(time.Now().Add(5 * time.Second))
			const message = "reverse direction"
			if _, err := io.WriteString(flow, message); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(message))
			if _, err := io.ReadFull(flow, got); err != nil || string(got) != message {
				t.Fatalf("unexpected echo %q: %v", got, err)
			}
		})
	}
}
