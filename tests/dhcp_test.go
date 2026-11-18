package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

func TestDHCPCLIAndAuthoritativeBindings(t *testing.T) {
	binary := buildHub(t)
	dir := t.TempDir()
	alice := newAccount(t, "DUMMY reserved")
	public, err := overlay.PublicIdentity(alice.key)
	if err != nil {
		t.Fatal(err)
	}
	policy := map[string]any{"start": "10.77.0.1", "end": "10.77.0.2", "lease_seconds": 60, "bindings": []any{map[string]any{"public_key": public, "ip": "10.77.0.1"}}}
	call := func(input []byte, args ...string) ([]byte, error) {
		cmd := exec.Command(binary, append([]string{"--data-dir", dir, "--cidr", "10.77.0.0/30"}, args...)...)
		cmd.Stdin = bytes.NewReader(input)
		return cmd.CombinedOutput()
	}
	raw, _ := json.Marshal(policy)
	if output, err := call(raw, "dhcp", "set"); err != nil {
		t.Fatalf("set: %v %s", err, output)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "dhcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(filepath.Join(dir, "dhcp.json")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("policy is not private")
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"10.77.0.2"`), []byte(`"192.0.2.1"`), 1),
		bytes.Replace(raw, []byte(`"lease_seconds":60`), []byte(`"lease_seconds":1`), 1),
		bytes.Replace(raw, []byte(public), []byte(strings.Repeat("0", 194)), 1),
		[]byte(`{"start":"10.77.0.0","end":"10.77.0.3","lease_seconds":60,"bindings":[]}`),
		[]byte(`{"start":"10.77.0.2","end":"10.77.0.1","lease_seconds":60,"bindings":[]}`),
		append(bytes.TrimSuffix(raw, []byte("}")), []byte(`,"port_bans":[80]}`)...),
		bytes.Repeat([]byte(" "), 65537),
	} {
		if output, err := call(bad, "dhcp", "set"); err == nil {
			t.Fatalf("invalid input accepted: %s", output)
		}
		after, _ := os.ReadFile(filepath.Join(dir, "dhcp.json"))
		if !bytes.Equal(saved, after) {
			t.Fatal("rejected policy changed storage")
		}
	}
	duplicate := map[string]any{"start": "10.77.0.2", "end": "10.77.0.2", "lease_seconds": 60, "bindings": []any{map[string]any{"public_key": public, "ip": "10.77.0.1"}, map[string]any{"public_key": public, "ip": "10.77.0.2"}}}
	duplicateRaw, _ := json.Marshal(duplicate)
	if _, err := call(duplicateRaw, "dhcp", "set"); err == nil {
		t.Fatal("duplicate binding accepted")
	}
	if output, err := call(nil, "dhcp", "show"); err != nil || !bytes.Equal(bytes.TrimSpace(output), saved) {
		t.Fatalf("readback: %v %s", err, output)
	}
	hub := startHub(t, binary, "OVERLAY_DATA_DIR="+dir, "OVERLAY_CIDR=10.77.0.0/30")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := func(a account) (*overlayagent.Agent, netip.Addr) {
		agent := newAgent(t, hub.address, a, make(chan overlay.State, 64), func(uint16) string { return "127.0.0.1:1" }, func(c *overlayagent.Config) { c.CIDR = netip.MustParsePrefix("10.77.0.0/30") })
		done := make(chan error, 1)
		go func() { done <- agent.Run(ctx) }()
		t.Cleanup(func() { cancel(); <-done })
		select {
		case ip := <-agent.Ready():
			return agent, ip
		case <-ctx.Done():
			t.Fatal("agent did not become ready")
			return nil, netip.Addr{}
		}
	}
	_, bobIP := start(newAccount(t, "DUMMY dynamic"))
	_, aliceIP := start(alice)
	if bobIP.String() != "10.77.0.2" || aliceIP.String() != "10.77.0.1" {
		t.Fatalf("reservation collision: %s %s", bobIP, aliceIP)
	}
	// An additional identity cannot evict either an active control or a reservation.
	config := overlayagent.Config{Identity: newAccount(t, "DUMMY excess").key, Dial: func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", hub.address)
	}}
	if _, err := overlayagent.DiscoverCIDR(ctx, config); err == nil {
		t.Fatal("exhausted pool admitted another identity")
	}
}

func TestRelayFirewallOverRealHub(t *testing.T) {
	binary := buildHub(t)
	for _, scope := range []string{"global", "device", "other-device"} {
		for _, proto := range []string{overlay.ProtoTCP, overlay.ProtoUDP} {
			t.Run(scope+"/"+proto, func(t *testing.T) {
				hub := startHub(t, binary)
				alice := newAccount(t, "DUMMY source")
				bob := newAccount(t, "DUMMY destination")
				public, err := overlay.PublicIdentity(alice.key)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := hex.DecodeString(public)
				digest := sha256.Sum256(raw)
				peer := ""
				if scope == "device" {
					peer = hex.EncodeToString(digest[:])
				}
				if scope == "other-device" {
					peer = strings.Repeat("ab", 32)
				}
				service, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer service.Close()
				udp, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				go func() {
					buffer := make([]byte, 2048)
					for {
						n, addr, err := udp.ReadFrom(buffer)
						if err != nil {
							return
						}
						_, _ = udp.WriteTo(buffer[:n], addr)
					}
				}()
				go func() {
					for {
						c, err := service.Accept()
						if err != nil {
							return
						}
						go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				astates, bstates := make(chan overlay.State, 64), make(chan overlay.State, 64)
				a := newAgent(t, hub.address, alice, astates, func(uint16) string { return service.Addr().String() })
				logged := make(chan string, 8)
				b := newAgent(t, hub.address, bob, bstates, func(uint16) string { return service.Addr().String() }, func(c *overlayagent.Config) {
					c.LogRelay = func(line string) { logged <- line }
					c.RelayFirewall = []overlay.FirewallRule{{Action: "allow", Peer: peer, Protocol: proto, Start: 4001, End: 4001}, {Action: "deny", Peer: peer, Protocol: proto, Start: 4000, End: 4001}}
					c.DialLocal = func(ctx context.Context, protocol string, _ uint16, _ netip.Addr) (net.Conn, error) {
						address := service.Addr().String()
						if protocol == overlay.ProtoUDP {
							address = udp.LocalAddr().String()
						}
						var dialer net.Dialer
						return dialer.DialContext(ctx, protocol, address)
					}
				})
				done := make(chan error, 2)
				go func() { done <- a.Run(ctx) }()
				go func() { done <- b.Run(ctx) }()
				defer func() { cancel(); <-done; <-done }()
				ip := <-b.Ready()
				src := <-a.Ready()
				checkLog := func(port uint16, result, reason string) {
					t.Helper()
					want := fmt.Sprintf("Overlay relay incoming: peer=%s device=%s protocol=%s port=%d result=%s%s",
						src, hex.EncodeToString(digest[:])[:7], proto, port, result, reason)
					select {
					case got := <-logged:
						if got != want {
							t.Fatalf("relay log = %q, want %q", got, want)
						}
					case <-ctx.Done():
						t.Fatalf("no log for port %d (%s)", port, result)
					}
				}
				waitFor(t, astates, func(s overlay.State) bool { return len(s.Peers) == 1 })
				conn, err := a.Outbound(ctx, proto, netip.AddrPortFrom(ip, 4000))
				if scope != "other-device" {
					if err == nil {
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(time.Second))
						_, _ = conn.Write([]byte("blocked"))
						buf := make([]byte, 16)
						if n, e := conn.Read(buf); n > 0 || e == nil {
							t.Fatal("blocked payload passed")
						}
					}
				} else if err != nil {
					t.Fatalf("unrelated peer denied: %v", err)
				}
				if scope == "other-device" {
					checkLog(4000, "allowed", "")
				} else {
					checkLog(4000, "blocked", " reason=relay firewall")
				}
				if conn != nil {
					conn.Close()
				}
				// The earlier allow exception takes precedence over the deny range.
				allowed, err := a.Outbound(ctx, proto, netip.AddrPortFrom(ip, 4001))
				if err != nil {
					t.Fatal(err)
				}
				defer allowed.Close()
				_ = allowed.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = allowed.Write([]byte("ok"))
				buf := make([]byte, 2)
				if _, err := io.ReadFull(allowed, buf); err != nil || string(buf) != "ok" {
					t.Fatalf("allowed payload: %q %v", buf, err)
				}
				checkLog(4001, "allowed", "")
			})
		}
	}
}
