package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
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
	build := exec.Command("cargo", "build", "--quiet", "--manifest-path", serverManifest, "--bin", "overlay-hub")
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

	// The hub refuses a private room until the operator approves its first request.
	discover := overlayagent.Config{
		Identity: alice.key,
		Room:     room,
		RoomID:   roomID,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", hub.address)
		},
	}
	if _, err := overlayagent.DiscoverCIDR(context.Background(), discover); err == nil || !strings.Contains(err.Error(), "room awaiting approval") {
		t.Fatalf("unapproved room error = %v, want room awaiting approval", err)
	}
	// The room ID is unique: another password is denied and never becomes a request.
	other := discover
	other.Room, err = overlay.RoomToken(roomID, "DUMMY other password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlayagent.DiscoverCIDR(context.Background(), other); err == nil || !strings.Contains(err.Error(), "room password is incorrect") {
		t.Fatalf("wrong password error = %v, want room password is incorrect", err)
	}
	digest := sha256.Sum256([]byte(roomID))
	key := hex.EncodeToString(digest[:])
	approve := exec.Command(binary, "rooms", "approve", key)
	approve.Env = append(os.Environ(), "OVERLAY_DATA_DIR="+hub.dir)
	if output, err := approve.CombinedOutput(); err != nil {
		t.Fatalf("approve room: %v: %s", err, output)
	}
	if _, err := overlayagent.DiscoverCIDR(context.Background(), discover); err != nil {
		t.Fatalf("approved room: %v", err)
	}
	if _, err := overlayagent.DiscoverCIDR(context.Background(), other); err == nil || !strings.Contains(err.Error(), "room password is incorrect") {
		t.Fatalf("approved wrong password error = %v, want room password is incorrect", err)
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
