package overlayagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func auditRoomHub(t *testing.T, directory string) string {
	if os.Getenv("OVERLAY_HUB_BIN") == "" {
		t.Skip("set OVERLAY_HUB_BIN to run real-hub integration")
	}
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	command := exec.CommandContext(ctx, os.Getenv("OVERLAY_HUB_BIN"))
	command.Env = append(os.Environ(), "OVERLAY_ALLOWED_HOST=", "OVERLAY_LISTEN_ADDRESS="+address, "OVERLAY_CIDR=192.168.100.0/24", "OVERLAY_DATA_DIR="+directory)
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = command.Wait() })
	for {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			return address
		}
		select {
		case <-ctx.Done():
			t.Fatal("hub not ready")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func auditRoomConfig(t *testing.T, address string) Config {
	t.Helper()
	identity, err := overlay.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := overlay.RoomToken("DUMMY-private", "DUMMY-password")
	if err != nil {
		t.Fatal(err)
	}
	return Config{Identity: identity, Name: "DUMMY audit", RoomID: "DUMMY-private", Room: proof, Dial: func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", address) }, DialLocal: func(context.Context, string, uint16, netip.Addr) (net.Conn, error) {
		return nil, errors.New("audit fixture has no local services")
	}}
}

func auditRoomData(t *testing.T, cfg Config, stale bool) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte(cfg.RoomID))
	rooms := map[string]any{hex.EncodeToString(digest[:]): map[string]string{"id": cfg.RoomID, "name": "DUMMY private", "proof": cfg.Room}}
	if stale {
		rooms[strings.Repeat("a", 64)] = map[string]string{"name": "DUMMY legacy"}
	}
	data, err := json.Marshal(rooms)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRegressionDuplicateRoomMustHaveMachineReadableError(t *testing.T) {
	if os.Getenv("OVERLAY_HUB_BIN") == "" {
		t.Skip("set OVERLAY_HUB_BIN to run real-hub integration")
	}
	directory := t.TempDir()
	run := func() ([]byte, error) {
		command := exec.Command(os.Getenv("OVERLAY_HUB_BIN"), "rooms", "create", "DUMMY", "Name", strings.Repeat("ab", 32))
		command.Env = append(os.Environ(), "OVERLAY_DATA_DIR="+directory)
		return command.CombinedOutput()
	}
	if output, err := run(); err != nil {
		t.Fatalf("initial create: %v %q", err, output)
	}
	output, err := run()
	if err == nil {
		t.Fatal("duplicate accepted")
	}
	if !strings.Contains(string(output), "error=room already exists") {
		t.Fatalf("manager's exact error classifier misses duplicate: ANSI=%v reasonPresent=%v", strings.Contains(string(output), "\x1b["), strings.Contains(string(output), "room already exists"))
	}
}

func TestRegressionStorageErrorMustNotTriggerPublicFallback(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "rooms.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := auditRoomConfig(t, auditRoomHub(t, directory))
	cfg.FallbackPublic = true
	a := &testAgent{key: cfg.Identity}
	cfg.OnState = func(state overlay.State) { a.mu.Lock(); a.states = append(a.states, state); a.mu.Unlock() }
	a.Agent = New(cfg)
	stop := a.start(t)
	defer stop()
	state := a.waitState(t, "storage error result", func(state overlay.State) bool { return state.Connected || state.Reason != "" })
	if state.Connected || state.PublicFallback || state.Reason != "rooms are unavailable" {
		t.Fatalf("corrupt room storage connected client to public overlay; reason=%q", state.Reason)
	}
}

func TestRegressionStaleRoomMustNotBlockHealthyRoom(t *testing.T) {
	directory := t.TempDir()
	address := auditRoomHub(t, directory)
	cfg := auditRoomConfig(t, address)
	if err := os.WriteFile(filepath.Join(directory, "rooms.json"), auditRoomData(t, cfg, true), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Getenv("OVERLAY_HUB_BIN"), "rooms", "list")
	command.Env = append(os.Environ(), "OVERLAY_DATA_DIR="+directory)
	_, listErr := command.CombinedOutput()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, admitErr := DiscoverCIDR(ctx, cfg)
	if listErr != nil || admitErr != nil {
		t.Fatalf("one stale record breaks listing=%v and healthy-room admission=%v", listErr != nil, admitErr)
	}
}

func TestRegressionReconnectMustRetryRepairedPrivateRoom(t *testing.T) {
	directory := t.TempDir()
	cfg := auditRoomConfig(t, auditRoomHub(t, directory))
	cfg.FallbackPublic = true
	var connectionMu sync.Mutex
	var connection net.Conn
	dial := cfg.Dial
	cfg.Dial = func(ctx context.Context) (net.Conn, error) {
		conn, err := dial(ctx)
		if err == nil {
			connectionMu.Lock()
			connection = conn
			connectionMu.Unlock()
		}
		return conn, err
	}
	a := &testAgent{key: cfg.Identity}
	cfg.OnState = func(state overlay.State) { a.mu.Lock(); a.states = append(a.states, state); a.mu.Unlock() }
	a.Agent = New(cfg)
	stop := a.start(t)
	defer stop()
	initial := a.waitState(t, "initial fallback", func(state overlay.State) bool { return state.Connected && state.PublicFallback })
	if err := os.WriteFile(filepath.Join(directory, "rooms.json"), auditRoomData(t, cfg, false), 0600); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.states = nil
	a.mu.Unlock()
	connectionMu.Lock()
	_ = connection.Close()
	connectionMu.Unlock()
	reconnected := a.waitState(t, "reconnected after repair", func(state overlay.State) bool { return state.Connected })
	if reconnected.PublicFallback || initial.Reason != "room does not exist" {
		t.Fatalf("agent stays public after private room repair and reconnect; initial rejection reason=%q", initial.Reason)
	}
}
