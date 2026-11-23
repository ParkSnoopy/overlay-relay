package overlayagent

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

func TestPagedPeerNameIndex(t *testing.T) {
	old := overlay.Peer{ID: strings.Repeat("a", 64), IP: "10.77.0.2", Domain: "old.on.snoo"}
	first := overlay.Peer{ID: old.ID, IP: old.IP, Domain: "desk.on.snoo"}
	second := overlay.Peer{ID: strings.Repeat("b", 64), IP: "10.77.0.3", Domain: "desk-2.on.snoo"}
	page := func(peer overlay.Peer, more bool) overlay.Event {
		return overlay.Event{PeerPage: &overlay.PeerPage{Peers: []overlay.Peer{peer}, More: more}}
	}
	for _, tc := range []struct {
		name     string
		last     overlay.Event
		complete bool
	}{
		{"completed", page(second, false), true},
		{"interrupted", overlay.Event{Pong: true}, false},
		{"invalid", page(overlay.Peer{ID: second.ID, IP: second.IP, Domain: "outside.example"}, false), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &Agent{connected: true, timing: defaultTiming}
			a.pinRange(overlay.CIDR)
			a.setPeers([]overlay.Peer{old})
			if id, ok := a.PeerIDByDomain(old.Domain); !ok || id != old.ID {
				t.Fatal("missing original identity")
			}
			reader, writer := net.Pipe()
			t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
			_ = writer.SetWriteDeadline(time.Now().Add(3 * time.Second))
			done := make(chan struct{})
			go func() { defer close(done); a.readEvents(t.Context(), reader, nil) }()
			if err := overlay.WriteFrame(writer, page(first, true)); err != nil {
				t.Fatal(err)
			}
			if _, ok := a.PeerIDByDomain(first.Domain); ok {
				t.Fatal("partial roster was published")
			}
			if err := overlay.WriteFrame(writer, tc.last); err != nil {
				t.Fatal(err)
			}
			_ = writer.Close()
			<-done
			if _, ok := a.PeerIDByDomain(old.Domain); ok == tc.complete {
				t.Fatal("wrong generation of name index")
			}
			for _, p := range []*overlay.Peer{&first, &second} {
				if id, ok := a.PeerIDByDomain(p.Domain); ok != tc.complete || (ok && id != p.ID) {
					t.Fatalf("incorrect owner for %s", p.Domain)
				}
			}
			a.disconnected("test finished")
			if _, ok := a.PeerIDByDomain(second.Domain); ok {
				t.Fatal("disconnected index retained a peer")
			}
		})
	}
}
