package overlayagent

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

// Opt in with OVERLAY_HUB_BIN pointing at the source-built Rust hub.
func TestServerAssignedRangeWithRustHub(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary)
	command.Env = append(os.Environ(), "OVERLAY_ALLOWED_HOST=", "OVERLAY_LISTEN_ADDRESS="+address, "OVERLAY_CIDR=192.168.100.0/24", "OVERLAY_DATA_DIR="+t.TempDir())
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = command.Wait() }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("Rust hub did not start", ctx.Err())
		case <-ticker.C:
		}
	}
	tcp, udp, stopEcho := echoServers(t)
	defer stopEcho()
	calls := make(chan localCall, 4)
	var agents []*testAgent
	for range 2 {
		key, err := overlay.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		a := &testAgent{key: key}
		cfg := Config{Identity: key, Name: "DUMMY", Dial: func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}, DialLocal: echoLocal(tcp, udp, calls)}
		prefix, err := DiscoverCIDR(ctx, cfg)
		if err != nil || prefix.String() != "192.168.100.0/24" {
			t.Fatal("did not discover the non-default hub range", prefix, err)
		}
		cfg.CIDR = prefix
		cfg.OnState = func(state overlay.State) {
			a.mu.Lock()
			a.states = append(a.states, state)
			a.mu.Unlock()
		}
		a.Agent = New(cfg)
		a.start(t)
		if ip := a.waitReady(t); !overlay.AssignableIn(prefix, ip) {
			t.Fatal("hub assigned an address outside its own range", ip)
		}
		agents = append(agents, a)
	}
	a, b := agents[0], agents[1]
	a.waitState(t, "second peer", hasPeer(b.IP()))
	for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
		conn, err := a.Outbound(ctx, proto, netip.AddrPortFrom(b.IP(), 7000))
		if err != nil {
			t.Fatal(proto, err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload := "DUMMY server-assigned subnet"
		if _, err := io.WriteString(conn, payload); err != nil {
			_ = conn.Close()
			t.Fatal(proto, err)
		}
		buffer := make([]byte, len(payload))
		_, err = io.ReadFull(conn, buffer)
		_ = conn.Close()
		if err != nil || string(buffer) != payload {
			t.Fatal("encrypted relay round trip failed", proto, err)
		}
	}
}
