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
	"github.com/miekg/dns"
)

// Opt in with OVERLAY_HUB_BIN pointing at the source-built hub.
func TestServerAssignedRangeWithHub(t *testing.T) {
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
			t.Fatal("hub did not start", ctx.Err())
		case <-ticker.C:
		}
	}
	tcp, udp, stopEcho := echoServers(t)
	defer stopEcho()
	calls := make(chan localCall, 4)
	var agents []*testAgent
	names := [2]string{"DUMMY Desk", "DUMMY Laptop"}
	for index := range 2 {
		key, err := overlay.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		a := &testAgent{key: key}
		cfg := Config{Identity: key, Name: names[index], Dial: func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		}, DialLocal: echoLocal(tcp, udp, calls)}
		if index == 0 {
			cfg.RoomID = "DUMMY missing room"
			cfg.Room, err = overlay.RoomToken(cfg.RoomID, "DUMMY password")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DiscoverCIDR(ctx, cfg); err == nil {
				t.Fatal("private room rejection must not fall back by default")
			}
			cfg.FallbackPublic = true
		}
		prefix, discovered, err := Discover(ctx, cfg)
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
		} else if ip != discovered {
			t.Fatal("session address differs from the discovered address", ip, discovered)
		}
		a.waitState(t, "public fallback state", func(state overlay.State) bool {
			return state.Connected && state.PublicFallback == (index == 0)
		})
		agents = append(agents, a)
	}
	a, b := agents[0], agents[1]
	a.waitState(t, "second peer", hasPeer(b.IP()))
	b.waitState(t, "first peer", hasPeer(a.IP()))
	answer := a.MagicDNS(ctx, new(dns.Msg).SetQuestion("dummy-laptop.on.snoo.", dns.TypeA))
	if answer == nil || answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 1 {
		t.Fatalf("missing advertised name: %v", answer)
	}
	record, ok := answer.Answer[0].(*dns.A)
	if !ok || record.Hdr.Ttl != 0 || record.A.String() != b.IP().String() {
		t.Fatalf("unexpected A record: %v (want %s, TTL 0)", answer.Answer[0], b.IP())
	}
	resolved := netip.MustParseAddr(record.A.String())
	for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
		conn, err := a.Outbound(ctx, proto, netip.AddrPortFrom(resolved, 7000))
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
