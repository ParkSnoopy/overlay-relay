package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

func hubTestDomain(t *testing.T, h *hubTestSocket, peer *hubTestPeer, want string) {
	t.Helper()
	if reply := peer.register(t, h); !reply.OK || reply.Domain != want || reply.NameLookup != 1 {
		t.Fatalf("registration with domain %q = %+v", want, reply)
	}
}

func hubTestPeerDomain(t *testing.T, observer, peer *hubTestPeer, want string) {
	t.Helper()
	hubTestEvent(t, observer.control, func(event overlay.Event) bool {
		if event.Peers == nil {
			return false
		}
		for i := range *event.Peers {
			entry := &(*event.Peers)[i]
			if entry.ID == peer.id && entry.Domain == want {
				if entry.IP != peer.ip || entry.Name != peer.hello.Name {
					t.Fatalf("roster changed the address or display name: %+v", entry)
				}
				return true
			}
		}
		return false
	})
}

func TestHubRuntimeExplicitDomainsAndPrivateRoomIsolation(t *testing.T) {
	dir := t.TempDir()
	h := startHubSocket(t, dir, nil, nil)
	public := newHubTestPeer(t, overlay.Version, "Public display")
	public.hello.Domain = "desk.on.snoo"
	private := newHubTestPeer(t, overlay.Version, "Private display")
	private.hello.Domain = public.hello.Domain
	private.hello.RoomID, private.hello.Room = "private", strings.Repeat("ab", 32)
	hubTestOK(t, configureRoom(dir, private.hello.RoomID, "Private", private.hello.Room, false, nil))
	hubTestDomain(t, h, public, "desk.on.snoo")
	hubTestDomain(t, h, private, "desk.on.snoo")
	hubTestPeers(t, public)
	hubTestPeers(t, private)
	for _, peer := range []*hubTestPeer{public, private} {
		if got := hubTestResolve(t, peer, 1, "desk"); got.IP != peer.ip || got.Unavailable {
			t.Fatalf("room-local DNS = %+v, want this room's owner %s", got, peer.ip)
		}
	}

	for _, domain := range []string{"Desk.on.snoo", "desk.on.snoo.", "desk.other", "two.labels.on.snoo",
		"id-" + strings.Repeat("a", 52) + ".on.snoo"} {
		public.hello.Domain = domain
		if reply := public.register(t, h); reply.OK || reply.Error != hubInvalid {
			t.Fatalf("accepted invalid domain %q: %+v", domain, reply)
		}
	}
	if got := hubTestResolve(t, public, 2, "desk"); got.IP != public.ip || got.Unavailable {
		t.Fatalf("invalid requests replaced the live control: %+v", got)
	}
	legacy := newHubTestPeer(t, overlay.PreviousWireVersion, "")
	hubTestDomain(t, h, legacy, "device.on.snoo")
	unusable := newHubTestPeer(t, overlay.Version, "🙂")
	hubTestDomain(t, h, unusable, "device-2.on.snoo")
}

func TestHubRuntimeDoesNotAdvertiseUnpersistedDomain(t *testing.T) {
	dir := t.TempDir()
	h := startHubSocket(t, dir, nil, nil)
	observer := newHubTestPeer(t, overlay.PreviousWireVersion, "observer")
	hubTestDomain(t, h, observer, "observer.on.snoo")
	nameFile := filepath.Join(dir, namesFile)
	hubTestOK(t, os.Remove(nameFile))
	hubTestOK(t, os.Mkdir(nameFile, 0o700))
	peer := newHubTestPeer(t, overlay.Version, "Desk")
	hubTestDomain(t, h, peer, "")
	hubTestPeerDomain(t, observer, peer, "")
	if got := hubTestResolve(t, observer, 1, "desk"); got != (overlay.NameAnswer{ID: 1, Unavailable: true}) {
		t.Fatalf("failed write did not fail DNS closed: %+v", got)
	}
}

func TestHubRuntimeDenseRoomPagesKeepDomainsAndLegacyDiscovery(t *testing.T) {
	h := startHubSocket(t, t.TempDir(), nil, nil)
	const zone = ".on.snoo"
	const name = `Desk "PC"`
	base := strings.Repeat("x", 63)
	var roster []hubPeer
	for i := 1; i <= 100; i++ {
		peer := newHubTestPeer(t, overlay.Version, name)
		peer.hello.Domain = base + zone
		label := base
		if i > 1 {
			suffix := fmt.Sprintf("-%d", i)
			label = base[:63-len(suffix)] + suffix
		}
		hubTestDomain(t, h, peer, label+zone)
		roster = append(roster, hubPeer{ID: peer.id, IP: peer.ip, Name: name, Domain: label + zone})
	}
	legacy := newHubTestPeer(t, overlay.PreviousWireVersion, "legacy")
	hubTestDomain(t, h, legacy, "legacy"+zone)
	t.Run("legacy full roster", func(t *testing.T) {
		event := hubTestRead[overlay.Event](t, legacy.control)
		if event.PeerPage != nil || event.Peers == nil || len(*event.Peers) != len(roster) {
			t.Fatal("legacy reader did not receive a complete unpaged roster")
		}
		for i := range *event.Peers {
			checkHubRosterEntry(t, &(*event.Peers)[i], &roster[i], "")
		}
	})
	roster = append(roster, hubPeer{ID: legacy.id, IP: legacy.ip, Name: "legacy", Domain: "legacy" + zone})
	modern := newHubTestPeer(t, overlay.Version, "modern")
	modern.hello.PeerPages = true
	hubTestDomain(t, h, modern, "modern"+zone)
	t.Run("capable paged roster", func(t *testing.T) {
		var count int
		for more := true; more; {
			event := hubTestRead[overlay.Event](t, modern.control)
			page := event.PeerPage
			if page == nil || len(page.Peers) == 0 || event.Peers != nil || event.Pong {
				t.Fatal("expected consecutive, nonempty roster pages")
			}
			if count == 0 {
				if !page.More {
					t.Fatal("dense roster fit on a single page")
				}
				hubTestOK(t, overlay.WriteFrame(modern.control, overlay.Ping{Ping: true}))
			}
			for i := range page.Peers {
				if count >= len(roster) {
					t.Fatal("paged roster returned extra peers")
				}
				checkHubRosterEntry(t, &page.Peers[i], &roster[count], roster[count].Domain)
				count++
			}
			more = page.More
		}
		if count != len(roster) {
			t.Fatalf("paged roster stopped at %d peers; want %d", count, len(roster))
		}
		hubTestEvent(t, modern.control, func(e overlay.Event) bool { return e.Pong })
	})
}

func checkHubRosterEntry(t *testing.T, got *overlay.Peer, want *hubPeer, domain string) {
	t.Helper()
	if got.ID != want.ID || got.IP != want.IP || got.Name != want.Name || got.Domain != domain {
		t.Fatalf("roster returned %+v; want %+v with domain %q", got, want, domain)
	}
}
