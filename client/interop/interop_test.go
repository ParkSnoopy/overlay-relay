package interop

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"github.com/ParkSnoopy/overlay-relay/client/overlayagent"
)

// The Rust hub is built from the sibling server crate and run as a real process,
// so the Go agent and the Rust relay meet over loopback TCP with the shipped wire format.
const serverManifest = "../../server/Cargo.toml"

type hubProcess struct {
	address string
	cmd     *exec.Cmd
}

func buildHub(t *testing.T) string {
	t.Helper()
	build := exec.Command("cargo", "build", "--quiet", "--manifest-path", serverManifest, "--bin", "overlay-hub")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("build overlay-hub: %v", err)
	}
	binary, err := filepath.Abs("../../server/target/debug/overlay-hub")
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
	defer listener.Close()
	return listener.Addr().String()
}

// startHub writes the peers table, starts the hub and waits until it accepts a source.
func startHub(t *testing.T, binary string, peers overlay.Peers) hubProcess {
	t.Helper()
	dir := t.TempDir()
	peersPath := filepath.Join(dir, "peers.json")
	raw, err := json.Marshal(peers)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(peersPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	address := freeAddress(t)
	cmd := exec.Command(binary)
	cmd.Env = append(os.Environ(),
		"OVERLAY_ALLOWED_HOST=localhost",
		"OVERLAY_PEERS_PATH="+peersPath,
		"OVERLAY_DATA_DIR="+dir,
		"OVERLAY_LISTEN_ADDRESS="+address,
	)
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
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("hub did not listen on %s: %v", address, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return hubProcess{address: address, cmd: cmd}
}

type account struct {
	name   string
	secret []byte
}

func newAgent(t *testing.T, hub string, account account, states chan<- overlay.State, local func(port uint16) string) *overlayagent.Agent {
	t.Helper()
	return overlayagent.New(overlayagent.Config{
		Secret: account.secret,
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
	})
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

func accountEntry(t *testing.T, account account) overlay.Account {
	t.Helper()
	verifier, err := overlay.Verifier(overlay.Token(account.secret))
	if err != nil {
		t.Fatal(err)
	}
	return overlay.Account{Verifier: verifier, Name: account.name}
}

func TestGoAgentAndRustHubRelayTCP(t *testing.T) {
	binary := buildHub(t)
	alice := account{name: "alice", secret: overlay.SecretUserPass("hysteria", "alice", "alice-password")}
	bob := account{name: "bob", secret: overlay.SecretUserPass("hysteria", "bob", "bob-password")}
	hub := startHub(t, binary, overlay.Peers{Version: overlay.Version, Accounts: []overlay.Account{accountEntry(t, alice), accountEntry(t, bob)}})

	// Bob's local service receives relayed flows at the overlay port.
	service, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	port := uint16(service.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			conn, err := service.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	localTarget := func(uint16) string { return service.Addr().String() }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	aliceStates := make(chan overlay.State, 64)
	bobStates := make(chan overlay.State, 64)
	aliceAgent := newAgent(t, hub.address, alice, aliceStates, localTarget)
	bobAgent := newAgent(t, hub.address, bob, bobStates, localTarget)

	runErrs := make(chan error, 2)
	go func() { runErrs <- aliceAgent.Run(ctx) }()
	go func() { runErrs <- bobAgent.Run(ctx) }()

	aliceIP := <-aliceAgent.Ready()
	bobIP := <-bobAgent.Ready()
	if !overlay.CIDR.Contains(aliceIP) || !overlay.CIDR.Contains(bobIP) || aliceIP == bobIP {
		t.Fatalf("invalid overlay addresses alice=%s bob=%s", aliceIP, bobIP)
	}
	waitFor(t, aliceStates, func(state overlay.State) bool {
		return state.Connected && len(state.Peers) == 1 && state.Peers[0].IP == bobIP.String()
	})

	flow, err := aliceAgent.Outbound(ctx, overlay.ProtoTCP, netip.AddrPortFrom(bobIP, port))
	if err != nil {
		t.Fatalf("open flow to bob: %v", err)
	}
	defer flow.Close()
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
		conn.Close()
		t.Fatal("flow to unknown address succeeded")
	}

	cancel()
	for range 2 {
		if err := <-runErrs; err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("agent run: %v", err)
		}
	}
}
