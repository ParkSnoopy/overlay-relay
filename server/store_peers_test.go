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
	checkAssignment(t, s, a, 1, nil, "10.77.0.1")
	checkAssignment(t, s, b, 2, nil, "10.77.0.2")
	if got := s.reserveName("", "first", a); got != "first" {
		t.Fatalf("recorded DNS label = %q", got)
	}
	checkAssignment(t, s, c, 3, nil, "10.77.0.1")
	records, err := loadAssignments(dir, 0)
	storeCheck(t, err)
	if _, assigned := records[a]; assigned {
		t.Fatal("expected DNS ledger to be the only record of peer A")
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
	checkAssignment(t, s, a, 4, nil, "10.77.0.2")
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
