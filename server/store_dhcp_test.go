package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dhcpLegacyKey = "04" +
	"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7" +
	"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"

func testDHCPJSON(t *testing.T, policy any) []byte {
	t.Helper()
	raw, err := json.Marshal(policy)
	storeCheck(t, err)
	return raw
}

func TestHubDHCPPersistenceRejectsInvalidInputWithoutMutation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	space := netip.MustParsePrefix("10.77.0.0/30")
	policy := defaultDHCP(space)
	policy.LeaseSeconds = 3600
	raw := testDHCPJSON(t, policy)
	storeCheck(t, saveDHCP(dir, space, raw))
	storePrivateMode(t, dir, dhcpFile)
	read, err := loadDHCP(dir, space)
	storeCheck(t, err)
	if !bytes.Equal(raw, testDHCPJSON(t, read)) {
		t.Fatal("saved DHCP policy did not round-trip")
	}
	invalid := policy
	invalid.LeaseSeconds = 1
	for _, bad := range [][]byte{
		testDHCPJSON(t, invalid), []byte("null"), bytes.Repeat([]byte(" "), maxDHCPBytes+1),
		[]byte(`{"start":"10.77.0.1","end":"10.77.0.2","lease_seconds":0,"bindings":[],"extra":true}`),
		[]byte(`{"start":"10.77.0.1","end":"10.77.0.2","lease_seconds":null,"bindings":[]}`),
		[]byte(`{"start":"10.77.0.1","end":"10.77.0.2","lease_seconds":0,"bindings":null}`),
		[]byte(`{"start":"10.77.0.1","end":"10.77.0.2","lease_seconds":0,"bindings":[],"bindings":[]}`),
		[]byte(`{"START":"10.77.0.1","end":"10.77.0.2","lease_seconds":0,"bindings":[]}`),
		[]byte(`{"start":"10.77.0.1","end":"10.77.0.2","bindings":[]}`),
		[]byte(`{"start":"10.77.0.1","end":"10.77.0.2","lease_seconds":0,"bindings":[{"ip":"10.77.0.1","extra":true}]}`),
	} {
		if err := saveDHCP(dir, space, bad); err == nil || !bytes.Equal(storeFile(t, dir, dhcpFile), raw) {
			t.Fatalf("invalid DHCP input changed policy (length %d): %v", len(bad), err)
		}
	}
	for _, bad := range []string{"null", strings.Repeat(" ", maxDHCPBytes+1)} {
		storeFixture(t, dir, dhcpFile, bad)
		if _, err := openHubStore(dir, space); err == nil {
			t.Fatalf("corrupt policy of length %d loaded", len(bad))
		}
	}
	storeCheck(t, saveDHCP(dir, space, testDHCPJSON(t, defaultDHCP(space))))
	if _, err := os.Stat(filepath.Join(dir, dhcpFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("restoring defaults retained DHCP override: %v", err)
	}
	nextSpace := netip.MustParsePrefix("10.80.0.0/24")
	read, err = loadDHCP(dir, nextSpace)
	storeCheck(t, err)
	if !bytes.Equal(testDHCPJSON(t, read), testDHCPJSON(t, defaultDHCP(nextSpace))) {
		t.Fatal("defaults did not follow the selected subnet")
	}
}

func TestHubDHCPReservationsValidateLegacyAndCanonicalIDs(t *testing.T) {
	t.Parallel()
	space := netip.MustParsePrefix("10.77.0.0/30")
	policy := defaultDHCP(space)
	policy.LeaseSeconds = 60
	key := dhcpLegacyKey
	legacy := dhcpBinding{PublicKey: &key, IP: netip.MustParseAddr("10.77.0.1")}
	policy.Bindings = []dhcpBinding{legacy}
	storeCheck(t, policy.validate(space))
	policy.Bindings = append(policy.Bindings, legacy)
	if err := policy.validate(space); err == nil {
		t.Fatal("accepted duplicate reservation")
	}
	id := legacy.verifier()
	policy.Bindings[1] = dhcpBinding{DeviceID: &id, IP: netip.MustParseAddr("10.77.0.2")}
	if err := policy.validate(space); err == nil {
		t.Fatal("treated legacy public key and digest as different devices")
	}
	policy.Bindings = policy.Bindings[1:]
	storeCheck(t, policy.validate(space))
	id = strings.ToUpper(id)
	if err := policy.validate(space); err == nil {
		t.Fatal("accepted a noncanonical identifier")
	}
	key = strings.Repeat("04", 97)
	policy.Bindings = []dhcpBinding{legacy}
	if err := policy.validate(space); err == nil {
		t.Fatal("accepted an invalid P-384 point")
	}
}

func TestHubDHCPEditorAndReservationsSurviveRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	space := netip.MustParsePrefix("10.77.0.0/29")
	key := dhcpLegacyKey
	binding := dhcpBinding{PublicKey: &key, IP: netip.MustParseAddr("10.77.0.5")}
	id, unnamed := binding.verifier(), storeTestID(3)
	storeFixture(t, dir, assignmentsFile, fmt.Sprintf(`{
		"%s":{"ip":"10.77.0.2","seen":1,"name":"Test laptop"},
		"%s":{"ip":"10.77.0.3","seen":1}
	}`, id, unnamed))
	policy := defaultDHCP(space)
	policy.Bindings = []dhcpBinding{binding}
	storeCheck(t, saveDHCP(dir, space, testDHCPJSON(t, policy)))
	result, err := editDHCP(dir, space)
	storeCheck(t, err)
	if device := result.Devices[id]; device.IP != binding.IP || device.Name != "Test laptop" {
		t.Fatalf("wrong editor device: %+v", device)
	}
	if device := result.Devices[unnamed]; device.IP.String() != "10.77.0.3" || device.Name != "" {
		t.Fatalf("wrong unnamed editor device: %+v", device)
	}
	if got := result.Policy.Bindings[0]; got.PublicKey != nil || got.DeviceID == nil || *got.DeviceID != id {
		t.Fatal("legacy key exposed by editor or device ID not resolved")
	}
	s := testStore(t, dir, space)
	checkAssignment(t, s, id, 10, nil, "10.77.0.5")
	checkAssignment(t, s, storeTestID(4), 10, nil, "10.77.0.1")
	checkAssignment(t, s, storeTestID(5), 10, nil, "10.77.0.2")
	checkAssignment(t, s, storeTestID(6), 10, nil, "10.77.0.4")
	checkAssignment(t, s, storeTestID(7), 10, nil, "10.77.0.6")
	checkAssignment(t, s, storeTestID(8), 100, nil, "10.77.0.3")
	s = testStore(t, dir, space)
	checkAssignment(t, s, id, 100, nil, "10.77.0.5")
	storeCheck(t, saveDHCP(dir, space, testDHCPJSON(t, result.Policy)))
	unknown := storeTestID(100)
	result.Policy.Bindings[0].DeviceID = &unknown
	if err := saveDHCP(dir, space, testDHCPJSON(t, result.Policy)); err == nil || err.Error() != "DHCP binding requires a device known to this hub" {
		t.Fatalf("unknown reservation: %v", err)
	}
}

func TestHubDHCPReservesOfflineAddressOutsidePool(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	space := netip.MustParsePrefix("10.77.0.0/29")
	reserve := dhcpLegacyKey
	policy := defaultDHCP(space)
	policy.End = policy.Start
	policy.LeaseSeconds = 60
	policy.Bindings = []dhcpBinding{{PublicKey: &reserve, IP: netip.MustParseAddr("10.77.0.5")}}
	storeCheck(t, saveDHCP(dir, space, testDHCPJSON(t, policy)))
	s := testStore(t, dir, space)
	id := policy.Bindings[0].verifier()
	checkAssignment(t, s, storeTestID(1), 100, nil, "10.77.0.1")
	checkAssignment(t, s, id, 100, nil, "10.77.0.5")
	checkAssignment(t, s, storeTestID(2), 160, nil, "10.77.0.1")
	checkAssignment(t, s, id, 160, nil, "10.77.0.5")
}
