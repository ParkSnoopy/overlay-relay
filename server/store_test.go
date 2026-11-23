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

var storeTestSpace = netip.MustParsePrefix("10.77.0.0/16")

func storeTestID(n int) string { return fmt.Sprintf("%064x", n) }

func testStore(t *testing.T, dir string, space netip.Prefix) *hubStore {
	t.Helper()
	s, err := openHubStore(dir, space)
	storeCheck(t, err)
	return s
}

func storeCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func storeFixture(t *testing.T, dir, name, raw string) {
	t.Helper()
	storeCheck(t, os.WriteFile(filepath.Join(dir, name), []byte(raw), 0o600))
}

func storeFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	storeCheck(t, err)
	return raw
}

func storePrivateMode(t *testing.T, dir, name string) {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, name))
	storeCheck(t, err)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode = %o; want 600", name, info.Mode().Perm())
	}
}

func checkAssignment(t *testing.T, s *hubStore, id string, now uint64, busy func(string) bool, want string) {
	t.Helper()
	ip, err := s.identify(id, now, busy)
	storeCheck(t, err)
	if ip.String() != want {
		t.Fatalf("assigned %s; want %s", ip, want)
	}
}

func TestHubAddressSpaceRustParity(t *testing.T) {
	for _, cidr := range []string{"10.0.0.0/8", "10.77.0.0/16", "172.16.0.0/12", "172.31.255.252/30", "192.168.0.0/16", "192.168.77.0/30"} {
		if _, err := parseHubCIDR(cidr); err != nil {
			t.Errorf("%s: %v", cidr, err)
		}
	}
	for _, cidr := range []string{
		"10.77.0.1/16", "0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/8", "10.0.0.0/7", "10.77.0.0/31", "::/16",
		"176.77.0.0/16", "172.0.0.0/8", "172.16.0.0/11", "172.15.0.0/16", "172.32.0.0/16", "192.168.0.0/15",
		"192.169.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "10.0.0.0/08", "10.0.0.0/+8", "10.01.0.0/16",
		"10.0.0.1/32", "192.168.100.1/24", "192.168.100.0/24 ", "",
	} {
		if _, err := parseHubCIDR(cidr); !errors.Is(err, errHubCIDR) {
			t.Errorf("accepted %q: %v", cidr, err)
		}
	}
}

func TestHubAssignmentsReadLegacyAndRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	legacy := strings.Repeat("ab", 32)
	id := storeTestID(2)
	storeFixture(t, dir, assignmentsFile, fmt.Sprintf(`{%q:"10.77.0.4",%q:{"ip":"10.77.0.1","seen":12,"name":"Old name"}}`, strings.ToUpper(legacy), id))
	records, err := loadAssignments(dir, 42)
	storeCheck(t, err)
	if got := records[legacy]; got.Seen != 42 || got.Name != "" || got.IP.String() != "10.77.0.4" {
		t.Fatalf("legacy assignment = %+v", got)
	}
	s := testStore(t, dir, storeTestSpace)
	checkAssignment(t, s, legacy, 42, nil, "10.77.0.4")
	checkAssignment(t, s, id, 42, nil, "10.77.0.1")
	checkAssignment(t, s, storeTestID(3), 42, nil, "10.77.0.2")
	storeCheck(t, s.setName(id, "Test laptop"))
	if err := s.setName(id, "bad\nname"); err == nil {
		t.Fatal("invalid display name accepted")
	}
	storePrivateMode(t, dir, assignmentsFile)
	s = testStore(t, dir, storeTestSpace)
	checkAssignment(t, s, id, 42, nil, "10.77.0.1")
	if got := s.assignments[id].Name; got != "Test laptop" {
		t.Fatalf("persisted name = %q", got)
	}
	storeCheck(t, s.setName(id, ""))
	if bytes.Contains(storeFile(t, dir, assignmentsFile), []byte(`"name"`)) {
		t.Fatal("cleared names must be omitted on disk")
	}
}

func TestHubAssignmentsFailOnCorruption(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, data := range []string{"", `null`} {
		if data != "" {
			storeFixture(t, dir, assignmentsFile, data)
		}
		records, err := loadAssignments(dir, 0)
		if err != nil || len(records) != 0 {
			t.Fatalf("missing or null assignment table: %v, %v", records, err)
		}
	}
	for _, bad := range []string{"garbage", "", `[]`, `{"junk":null}`, `{"junk":{"ip":"10.77.0.4"}}`,
		`{"junk":{"ip":"10.77.0.4","seen":0,"name":null}}`, `{"junk":{"ip":"10.77.0.4","seen":0,"seen":1}}`,
		`{"junk":"fe80::1%eth0"}`} {
		storeFixture(t, dir, assignmentsFile, bad)
		if _, err := openHubStore(dir, storeTestSpace); !errors.Is(err, errCorruptAssignments) {
			t.Fatalf("assignment table %q was not refused: %v", bad, err)
		}
		if got := string(storeFile(t, dir, assignmentsFile)); got != bad {
			t.Fatal("corrupt assignments were replaced")
		}
	}
}

func TestHubAssignmentsBoundedEvictionAndTouch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fixture := make(map[string]assignment)
	ip := storeTestSpace.Addr().Next()
	for n := range maxAssignments {
		fixture[storeTestID(n)] = assignment{IP: ip, Seen: uint64(n)}
		ip = ip.Next()
	}
	storeCheck(t, saveStoreJSON(filepath.Join(dir, assignmentsFile), ".ips-", fixture, false))
	s := testStore(t, dir, storeTestSpace)
	s.touch(storeTestID(0), 10_000)
	if _, err := s.identify(storeTestID(maxAssignments), 11_000, func(string) bool { return true }); !errors.Is(err, errAddressExhausted) {
		t.Fatalf("all accounts busy: %v", err)
	}
	checkAssignment(t, s, storeTestID(maxAssignments), 11_000, func(id string) bool { return id == storeTestID(1) }, "10.77.0.3")
	records, err := loadAssignments(dir, 0)
	storeCheck(t, err)
	if len(records) != maxAssignments || records[storeTestID(0)].Seen != 10_000 || !records[storeTestID(1)].IP.IsValid() || records[storeTestID(2)].IP.IsValid() {
		t.Fatal("allocator must preserve touched/active identities, and evict only the oldest idle identity")
	}
}

func TestHubAssignmentsReconcileSubnetAndDuplicates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ids := []string{storeTestID(1), storeTestID(2), storeTestID(3), storeTestID(4)}
	storeFixture(t, dir, assignmentsFile, fmt.Sprintf(`{
		"%s":{"ip":"172.20.0.5","seen":10},
		"%s":{"ip":"172.20.0.5","seen":100},
		"%s":"10.77.0.1",
		"%s":"172.20.0.7"
	}`, ids[0], ids[1], ids[2], ids[3]))
	s := testStore(t, dir, netip.MustParsePrefix("172.20.0.0/29"))
	checkAssignment(t, s, ids[1], 42, nil, "172.20.0.5")
	checkAssignment(t, s, ids[0], 42, nil, "172.20.0.1")
	checkAssignment(t, s, ids[2], 42, nil, "172.20.0.2")
	checkAssignment(t, s, ids[3], 42, nil, "172.20.0.3")
}

func TestHubLeaseExpiryExhaustionAndActiveExemption(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	space := netip.MustParsePrefix("10.77.0.0/30")
	storeCheck(t, saveDHCP(dir, space, []byte(`{"start":"10.77.0.1","end":"10.77.0.2","lease_seconds":60,"bindings":[]}`)))
	s := testStore(t, dir, space)
	a, b, c, d := storeTestID(1), storeTestID(2), storeTestID(3), storeTestID(4)
	checkAssignment(t, s, a, 100, nil, "10.77.0.1")
	checkAssignment(t, s, b, 100, nil, "10.77.0.2")
	original := storeFile(t, dir, assignmentsFile)
	checkAssignment(t, s, a, 129, nil, "10.77.0.1")
	if !bytes.Equal(original, storeFile(t, dir, assignmentsFile)) {
		t.Fatal("reconnect rewrote a lease below the seen granularity")
	}
	if _, err := s.identify(c, 159, nil); !errors.Is(err, errAddressExhausted) {
		t.Fatalf("unexpired devices were not protected: %v", err)
	}
	checkAssignment(t, s, c, 160, func(id string) bool { return id == a }, "10.77.0.2")
	checkAssignment(t, s, d, 160, nil, "10.77.0.1")
	if _, err := s.identify(b, 1000, func(string) bool { return true }); !errors.Is(err, errAddressExhausted) {
		t.Fatalf("busy expired devices were not protected: %v", err)
	}
}

func TestHubAssignmentSaveRetriesAfterAtomicFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := testStore(t, dir, storeTestSpace)
	path := filepath.Join(dir, assignmentsFile)
	storeCheck(t, os.Mkdir(path, 0o700))
	id := storeTestID(1)
	checkAssignment(t, s, id, 100, nil, "10.77.0.1")
	entries, err := os.ReadDir(dir)
	storeCheck(t, err)
	if len(entries) != 1 || !entries[0].IsDir() {
		t.Fatalf("failed write leaked a temporary file: %v", entries)
	}
	storeCheck(t, os.Remove(path))
	checkAssignment(t, s, id, 100, nil, "10.77.0.1")
	storePrivateMode(t, dir, assignmentsFile)
}
