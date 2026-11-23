package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkNameOwner(t *testing.T, s *hubStore, room, label, want string) {
	t.Helper()
	got, err := s.nameOwner(room, label)
	storeCheck(t, err)
	if got != want {
		t.Fatalf("owner of %q = %q; want %q", label, got, want)
	}
}

func TestHubStableNamesFollowDeviceAndRoomNotAddress(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	space := netip.MustParsePrefix("10.77.0.0/30")
	s := testStore(t, dir, space)
	a, b, c := storeTestID(1), storeTestID(2), storeTestID(3)
	checkAssignment(t, s, a, 1, nil, "10.77.0.1")
	checkAssignment(t, s, b, 2, nil, "10.77.0.2")
	s.reserveName("", "Desk PC", a)
	s.reserveName("", "Desk.PC", b)
	s.reserveName("", "Bücher", a)
	s.reserveName("", "new name", a)
	checkAssignment(t, s, c, 3, nil, "10.77.0.1")
	s.reserveName("", "Desk PC", c)
	checkNameOwner(t, s, "", "desk-pc", a)
	checkNameOwner(t, s, "", "xn--bcher-kva", a)
	checkNameOwner(t, s, "", "new-name", a)
	checkNameOwner(t, s, "", "invalid.label", "")
	storePrivateMode(t, dir, namesFile)

	proof, next := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	disabled := false
	storeCheck(t, configureRoom(dir, "Private", "Private", proof, false, &disabled))
	private := roomKey("Private") + ":" + proof
	s.reserveName(private, "Desk PC", b)
	checkNameOwner(t, s, private, "desk-pc", b)
	storeCheck(t, configureRoom(dir, "Private", "Updated", next, true, nil))
	checkNameOwner(t, s, private, "desk-pc", "")
	newRoom := roomKey("Private") + ":" + next
	checkNameOwner(t, s, newRoom, "desk-pc", b)
	if strings.Contains(string(storeFile(t, dir, namesFile)), proof) || strings.Contains(string(storeFile(t, dir, namesFile)), next) {
		t.Fatal("a persisted label included the private room proof")
	}
	s = testStore(t, dir, space)
	checkNameOwner(t, s, newRoom, "desk-pc", b)
	checkNameOwner(t, s, "", "desk-pc", a)
	storeCheck(t, removeRoom(dir, roomKey("Private")))
	checkNameOwner(t, s, newRoom, "desk-pc", "")
	storeFixture(t, dir, roomsFile, "garbage")
	if got, err := s.nameOwner(newRoom, "desk-pc"); got != "" || err == nil {
		t.Fatalf("broken room storage did not disable its private DNS: %v", err)
	}
	checkNameOwner(t, s, "", "desk-pc", a)
}

func TestHubNameAliasesNormalizeAndCannotBeReserved(t *testing.T) {
	t.Parallel()
	s := testStore(t, t.TempDir(), storeTestSpace)
	a := strings.Repeat("ff", 32)
	raw, err := hex.DecodeString(a)
	storeCheck(t, err)
	label := "id-" + strings.ToLower(nameBase32.EncodeToString(raw))
	s.reserveName("", label, storeTestID(1))
	checkNameOwner(t, s, "", label, a)
	checkNameOwner(t, s, "", label[:len(label)-1]+"7", "")
	if s.names.count != 0 {
		t.Fatal("reserved alias was persisted as an ordinary name")
	}
	for name, want := range map[string]string{
		"Desk (PC)": "desk-pc", "Bücher": "xn--bcher-kva", "Ｂｏｘ": "box", "-A — B-": "a-b",
		"Peer_01": "peer-01", "A–-B": "a-b", "A$B": "", "🙂": "", "": "", strings.Repeat("a", 64): "",
	} {
		if got := normalizedDNSLabel(name); got != want {
			t.Errorf("label for %q = %q; want %q", name, got, want)
		}
	}
}

func TestHubDNSCorruptionAndFailedWritesDisableTheAuthority(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id := storeTestID(1)
	for _, invalid := range []string{`null`, `[{"room":"","label":"alice"}]`,
		fmt.Sprintf(`[{"room":"","label":"alice","device":%q,"extra":0}]`, id),
		fmt.Sprintf(`[{"room":"","label":"alice","device":%q},{"room":"","label":"alice","device":%q}]`, id, id)} {
		storeFixture(t, dir, namesFile, invalid)
		s := testStore(t, dir, storeTestSpace)
		checkAssignment(t, s, id, 1, nil, "10.77.0.1")
		s.reserveName("", "Alice", id)
		if _, err := s.nameOwner("", "alice"); !errors.Is(err, errNamesUnavailable) {
			t.Fatalf("corruption failed open: %v", err)
		}
		if string(storeFile(t, dir, namesFile)) != invalid {
			t.Fatal("corrupt DNS bindings were replaced")
		}
	}
	path := filepath.Join(dir, namesFile)
	storeCheck(t, os.Remove(path))
	s := testStore(t, dir, storeTestSpace)
	storeCheck(t, os.Mkdir(path, 0o700))
	s.reserveName("", "Alice", id)
	storeCheck(t, os.Remove(path))
	if _, err := s.nameOwner("", "alice"); !errors.Is(err, errNamesUnavailable) {
		t.Fatalf("failed write did not disable DNS until restart: %v", err)
	}
	s = testStore(t, dir, storeTestSpace)
	s.reserveName("", "Alice", id)
	checkNameOwner(t, s, "", "alice", id)
}

func TestHubDNSCapacityNeverEvictsLabels(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id := storeTestID(1)
	bindings := make([]nameBinding, maxNames)
	for i := range bindings {
		bindings[i] = nameBinding{Label: fmt.Sprintf("label-%d", i), Device: id}
	}
	storeCheck(t, saveStoreJSON(filepath.Join(dir, namesFile), ".names-", bindings, true))
	s := testStore(t, dir, storeTestSpace)
	s.reserveName("", "new name", storeTestID(2))
	checkNameOwner(t, s, "", "new-name", "")
	checkNameOwner(t, s, "", "label-0", id)
	bindings = append(bindings, nameBinding{Label: "too-many", Device: id})
	storeCheck(t, saveStoreJSON(filepath.Join(dir, namesFile), ".names-", bindings, true))
	s = testStore(t, dir, storeTestSpace)
	if _, err := s.nameOwner("", "label-0"); !errors.Is(err, errNamesUnavailable) {
		t.Fatalf("an over-capacity file must disable DNS: %v", err)
	}
}
