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

func TestVersionSynchronization(t *testing.T) {
	if output, err := exec.Command("python3", "../scripts/bump_version.py", "--check").CombinedOutput(); err != nil {
		t.Fatalf("checked-in version metadata: %v: %s", err, output)
	}
	script, err := os.ReadFile("../scripts/bump_version.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ release, protocol, previous string }{
		{"0.3.0", "1", "0"},
		{"0.5.3", "5", "4"},
		{"0.6.0", "6", "5"},
		{"1.0.0-rc.1", "6", "5"},
	} {
		t.Run(test.release, func(t *testing.T) {
			root := t.TempDir()
			for _, directory := range []string{"scripts", "server/src", "client/overlay"} {
				if err := os.MkdirAll(filepath.Join(root, directory), 0700); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(root, "scripts/bump_version.py")
			if err := os.WriteFile(path, script, 0600); err != nil {
				t.Fatal(err)
			}
			manifest := filepath.Join(root, "server/Cargo.toml")
			header := "[package]\nversion = \"" + test.release + "\"\n[package.metadata.overlay-relay]\n"
			if err := os.WriteFile(manifest, []byte(header+"wire = "+test.protocol+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := exec.Command("python3", path, "--check").Run(); err == nil {
				t.Fatal("missing generated versions accepted")
			}
			for _, mode := range []string{"--sync", "--check", "--sync", "--check"} {
				if output, err := exec.Command("python3", path, mode).CombinedOutput(); err != nil {
					t.Fatalf("%s: %v: %s", mode, err, output)
				}
			}
			client := filepath.Join(root, "client/overlay/version.go")
			data, err := os.ReadFile(client)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), `ReleaseVersion = "`+test.release+`"`) ||
				!strings.Contains(string(data), "const Version = "+test.protocol+"\n") ||
				!strings.Contains(string(data), "const PreviousWireVersion = "+test.previous+"\n") ||
				!strings.Contains(string(data), `const PreviousAuthDomain = "overlay-relay/auth/v`+test.previous+`:"`) {
				t.Fatalf("incorrect generated version: %s", data)
			}
			if err := os.WriteFile(client, []byte("DUMMY drift"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := exec.Command("python3", path, "--check").Run(); err == nil {
				t.Fatal("drift accepted")
			}
			if after, err := os.ReadFile(client); err != nil || string(after) != "DUMMY drift" {
				t.Fatal("check changed the client version")
			}
			if output, err := exec.Command("python3", path, "--sync").CombinedOutput(); err != nil {
				t.Fatalf("repair: %v: %s", err, output)
			}
			server := filepath.Join(root, "server/src/version.rs")
			hubData, err := os.ReadFile(server)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(hubData), "const VERSION: u32 = "+test.protocol+";") ||
				!strings.Contains(string(hubData), "const PREVIOUS_WIRE_VERSION: u32 = "+test.previous+";") ||
				!strings.Contains(string(hubData), `const PREVIOUS_AUTH_DOMAIN: &str = "overlay-relay/auth/v`+test.previous+`:";`) {
				t.Fatalf("incorrect generated hub version: %s", hubData)
			}
			for _, rejected := range []string{"0", "2147483648", "true"} {
				if err := os.WriteFile(manifest, []byte(header+"wire = "+rejected+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				for _, mode := range []string{"--check", "--sync"} {
					if output, err := exec.Command("python3", path, mode).CombinedOutput(); err == nil || !strings.Contains(string(output), "wire must be a positive signed 32-bit integer") {
						t.Fatalf("%s accepted invalid compatibility metadata or failed unexpectedly: %v: %s", mode, err, output)
					}
				}
				for filename, want := range map[string][]byte{client: data, server: hubData} {
					if after, err := os.ReadFile(filename); err != nil || string(after) != string(want) {
						t.Fatalf("rejected synchronization changed %s: %v", filename, err)
					}
				}
			}
		})
	}
}

// The Rust hub is built from the sibling server crate and run as a real process,
// so the Go agent and the Rust relay meet over loopback TCP with the shipped wire format.
const serverManifest = "../server/Cargo.toml"

type hubProcess struct {
	address string
	dir     string
	cmd     *exec.Cmd
}

func buildHub(t *testing.T) string {
	t.Helper()
	build := exec.Command("cargo", "build", "--locked", "--quiet", "--manifest-path", serverManifest, "--bin", "overlay-hub")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build overlay-hub: %v", err)
	}
	binary, err := filepath.Abs("../server/target/debug/overlay-hub")
	if err != nil {
		t.Fatal(err)
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

func TestGoAgentAndRustHubPrivateRoomTCP(t *testing.T) {
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
