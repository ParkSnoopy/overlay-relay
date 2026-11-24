package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHubPeerRemainsManageableAfterAddressReclaim(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	space := netip.MustParsePrefix("10.77.0.0/30")
	s := testStore(t, dir, space)
	a, b, c := storeTestID(1), storeTestID(2), storeTestID(3)
	now := hubUnixNow()
	checkAssignment(t, s, a, now-3, nil, "10.77.0.1")
	checkAssignment(t, s, b, now-2, nil, "10.77.0.2")
	if got := s.reserveName("", "first", a); got != "first" {
		t.Fatalf("recorded DNS label = %q", got)
	}
	checkAssignment(t, s, c, now-1, nil, "10.77.0.1")
	records, err := loadAssignments(dir, 0)
	storeCheck(t, err)
	if _, assigned := records[a]; assigned {
		t.Fatal("reclaimed peer still holds an address")
	}
	listing, err := listPeers(dir, space)
	storeCheck(t, err)
	if device, known := listing.Devices[a]; !known || device != (listedPeer{}) {
		t.Fatalf("offline peer after address reclaim: %+v, known=%t", device, known)
	}
	edit := peerEdit{DeviceID: a, Name: "First device"}
	storeCheck(t, setPeer(dir, space, testDHCPJSON(t, edit)))
	listing, err = listPeers(dir, space)
	storeCheck(t, err)
	if device := listing.Devices[a]; device != (listedPeer{Name: edit.Name, NameOverride: edit.Name}) {
		t.Fatalf("edited offline peer without an address: %+v", device)
	}
	s = testStore(t, dir, space)
	checkAssignment(t, s, a, now, nil, "10.77.0.2")
	owner, err := s.nameOwner("", "first")
	storeCheck(t, err)
	if owner != a {
		t.Fatal("reclaimed address or peer edit changed durable name ownership")
	}
}

func TestHubPeerSettingsRejectCorruptState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a, b := storeTestID(1), storeTestID(2)
	input := testDHCPJSON(t, peerEdit{DeviceID: a, Name: "Valid", Binding: "10.77.0.1"})
	duplicateIP := fmt.Sprintf(`[{"device_id":%q,"name":"","binding":"10.77.0.1"},{"device_id":%q,"name":"","binding":"10.77.0.1"}]`, a, b)
	for _, raw := range []string{"null", "{}", "[]{}", `[{"device_id":"bad","name":"","binding":""}]`,
		"[" + string(input) + "," + string(input) + "]", duplicateIP,
		"[" + strings.Replace(string(input), "10.77.0.1", "10.78.0.1", 1) + "]",
		strings.Repeat(" ", maxPeerEditsFile+1),
	} {
		storeFixture(t, dir, peerEditsFile, raw)
		if _, err := openHubStore(dir, storeTestSpace); err == nil {
			t.Fatalf("corrupt peer settings loaded (length %d)", len(raw))
		}
		if _, err := listPeers(dir, storeTestSpace); err == nil {
			t.Fatalf("listed peers with corrupt settings (length %d)", len(raw))
		}
		if err := setPeer(dir, storeTestSpace, input); err == nil || !bytes.Equal(storeFile(t, dir, peerEditsFile), []byte(raw)) {
			t.Fatalf("editing corrupt settings succeeded or changed storage (length %d): %v", len(raw), err)
		}
	}
	storeFixture(t, dir, peerEditsFile, "[]")
	storeFixture(t, dir, namesFile, "null")
	if _, err := listPeers(dir, storeTestSpace); !errors.Is(err, errCorruptNames) {
		t.Fatalf("peer listing did not fail closed on a corrupt ledger: %v", err)
	}
	if err := setPeer(dir, storeTestSpace, input); !errors.Is(err, errCorruptNames) {
		t.Fatalf("peer edit did not fail closed on a corrupt ledger: %v", err)
	}
	path := filepath.Join(dir, peerEditsFile)
	storeCheck(t, os.Remove(path))
	storeCheck(t, os.Mkdir(path, 0o700))
	if _, err := openHubStore(dir, storeTestSpace); !errors.Is(err, errCorruptPeerEdits) {
		t.Fatalf("peer settings must be a regular file: %v", err)
	}
}

func TestPeerExpiryReleasesAllDeviceState(t *testing.T) {
	t.Parallel()
	for _, lease := range []uint64{0, 60} {
		t.Run(fmt.Sprint(lease), func(t *testing.T) {
			dir := t.TempDir()
			id, other := storeTestID(1), storeTestID(2)
			now := hubUnixNow()
			s := testStore(t, dir, storeTestSpace)
			checkAssignment(t, s, id, now, nil, "10.77.0.1")
			checkAssignment(t, s, other, now, nil, "10.77.0.2")
			storeCheck(t, s.setName(id, "Laptop"))
			s.reserveName("", "laptop", id)
			s.reserveName("", "former-laptop", id)
			s.reserveName("", "other", other)
			storeCheck(t, saveDHCP(dir, storeTestSpace, []byte(fmt.Sprintf(
				`{"start":"10.77.0.1","end":"10.77.0.254","lease_seconds":%d,"bindings":[{"device_id":%q,"ip":"10.77.0.1"}]}`, lease, id))))
			storeCheck(t, setPeer(dir, storeTestSpace, []byte(fmt.Sprintf(
				`{"device_id":%q,"name":"Office","binding":"10.77.0.1","domain":"office.on.snoo"}`, id))))

			s = testStore(t, dir, storeTestSpace)
			retention := lease
			if retention == 0 {
				retention = 7 * 24 * 60 * 60
			}
			deadline := now + retention
			storeCheck(t, s.expirePeers(deadline-1, nil))
			if peer := s.listKnownPeers(nil).Devices[id]; peer.Name != "Office" || peer.DomainOverride != "office.on.snoo" || peer.Binding != "10.77.0.1" {
				t.Fatalf("peer settings lost before expiry: %+v", peer)
			}
			storeCheck(t, s.expirePeers(deadline, func(string) bool { return true }))
			if len(s.listKnownPeers(nil).Devices) != 2 {
				t.Fatal("expired a live peer")
			}
			// Once the peer disconnects, its last authenticated activity starts a new window.
			s.touch(id, deadline)
			storeCheck(t, s.expirePeers(deadline+retention-1, func(peer string) bool { return peer == other }))
			if _, exists := s.listKnownPeers(nil).Devices[id]; !exists {
				t.Fatal("disconnect did not renew the countdown")
			}
			storeCheck(t, s.expirePeers(deadline+retention, func(peer string) bool { return peer == other }))

			s = testStore(t, dir, storeTestSpace)
			listing, err := listPeers(dir, storeTestSpace)
			storeCheck(t, err)
			if _, exists := listing.Devices[id]; exists || len(listing.Devices) != 1 || len(s.dhcp.Bindings) != 0 {
				t.Fatalf("expired DHCP or managed record survived restart: %+v", listing)
			}
			for _, label := range []string{"laptop", "former-laptop"} {
				owner, err := s.nameOwner("", label)
				storeCheck(t, err)
				if owner != "" {
					t.Fatalf("expired name %q retained", label)
				}
			}
			checkAssignment(t, s, id, deadline+retention, func(peer string) bool { return peer == other }, "10.77.0.1")
			if peer := s.listKnownPeers(nil).Devices[id]; peer.NameOverride != "" || peer.DomainOverride != "" || peer.Binding != "" {
				t.Fatalf("returning device recovered expired settings: %+v", peer)
			}
		})
	}
}
