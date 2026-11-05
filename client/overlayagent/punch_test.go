package overlayagent

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

func TestPunchMatchesOnlyExpectedFlowAndIP(t *testing.T) {
	id := strings.Repeat("a", 32)
	offered := netip.MustParseAddrPort("203.0.113.7:4000")
	reflexive := netip.MustParseAddrPort("203.0.113.7:5000")
	packet := append(bytes.Clone(punchPacket), id...)
	for _, test := range []struct {
		name     string
		packet   []byte
		from     netip.AddrPort
		want     netip.AddrPort
		observed bool
	}{
		{"new port", packet, reflexive, reflexive, true},
		{"offered port", packet, offered, offered, true},
		{"unknown flow", append(bytes.Clone(punchPacket), strings.Repeat("b", 32)...), reflexive, offered, false},
		{"wrong IP", packet, netip.MustParseAddrPort("203.0.113.8:5000"), offered, false},
		{"zero port", packet, netip.MustParseAddrPort("203.0.113.7:0"), offered, false},
		{"short ID", packet[:len(packet)-1], reflexive, offered, false},
		{"trailing data", append(bytes.Clone(packet), 0), reflexive, offered, false},
		{"wrong magic", []byte("not a punch"), reflexive, offered, false},
		{"legacy offered port", punchPacket, offered, offered, true},
		{"legacy new port", punchPacket, reflexive, offered, false},
		{"mapped IPv4", packet, netip.MustParseAddrPort("[::ffff:203.0.113.7]:5000"), reflexive, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := &direct{expected: map[string]*expectation{}}
			exp := d.expect(id, "pinned-peer", offered.String())
			d.observePunch(test.packet, net.UDPAddrFromAddrPort(test.from))
			if exp.endpoint != test.want {
				t.Fatalf("endpoint = %s, want %s", exp.endpoint, test.want)
			}
			if got := len(exp.observed) != 0; got != test.observed {
				t.Fatalf("observed = %t, want %t", got, test.observed)
			}
			exp.cancel()
			d.observePunch(packet, net.UDPAddrFromAddrPort(reflexive))
			if exp.endpoint != test.want {
				t.Fatal("a retired flow accepted a punch")
			}
		})
	}
}

func TestPunchWaitRetainsEndpointAndHonorsCancellation(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "cancellation"}[cancel], func(t *testing.T) {
			d := &direct{expected: map[string]*expectation{}, timeout: 20 * time.Millisecond}
			exp := d.expect(strings.Repeat("a", 32), "pinned-peer", "203.0.113.7:4000")
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			if cancel {
				stop()
			}
			done := make(chan net.Addr, 1)
			go func() { done <- exp.peerEndpoint(ctx) }()
			select {
			case endpoint := <-done:
				if endpoint.String() != "203.0.113.7:4000" {
					t.Fatal("unobserved endpoint changed", endpoint)
				}
			case <-time.After(time.Second):
				t.Fatal("endpoint discovery did not stop")
			}
		})
	}
}

func TestReflexivePortStillRequiresPinnedCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	options := &DirectOptions{Timeout: time.Second, ListenPacket: func(ctx context.Context) (net.PacketConn, error) {
		return (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
	}}
	alice, err := startDirect(ctx, options, sealedAgent(t).identity)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := startDirect(ctx, options, sealedAgent(t).identity)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	exp := bob.expect(id, alice.identity.fingerprint, alice.socket.LocalAddr().String())
	defer exp.cancel()
	done := make(chan error, 1)
	go func() {
		_, err := exp.await(ctx, &overlay.Reply{Endpoint: alice.socket.LocalAddr().String()})
		done <- err
	}()
	// The punch reveals Bob's actual port, but a wrong fingerprint must
	// still prevent the real QUIC connection from carrying any flow.
	conn, err := alice.dial(ctx, &overlay.Reply{ID: id, Endpoint: "127.0.0.1:1", Fingerprint: strings.Repeat("0", 64)})
	if conn != nil {
		_ = conn.Close()
		t.Fatal("a port hint bypassed certificate pinning")
	}
	if err == nil || !strings.Contains(err.Error(), errPinMismatch.Error()) {
		t.Fatalf("want a certificate pin failure after discovering the peer port, got %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed handshake did not stop")
	}
	probe := alice.expect(id, "", bob.socket.LocalAddr().String())
	defer probe.cancel()
	if _, ok := alice.fingerprintFor(id); ok {
		t.Fatal("outbound discovery authorized an incoming QUIC connection")
	}
}
