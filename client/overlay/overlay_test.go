package overlay

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestIdentityRoundTrip(t *testing.T) {
	key, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ParseIdentity(encoded)
	if err != nil {
		t.Fatal(err)
	}
	before, err := PublicIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	after, err := PublicIdentity(loaded)
	if err != nil || before != after {
		t.Fatal("identity changed on reload")
	}
	if _, err := IdentityID("zz"); err == nil {
		t.Fatal("invalid public key accepted")
	}
	if _, err := PublicIdentity(nil); err == nil {
		t.Fatal("identity without private key accepted")
	}
	other, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	mismatch := *key
	mismatch.PublicKey = other.PublicKey
	if _, err := PublicIdentity(&mismatch); err == nil {
		t.Fatal("identity with mismatched private key accepted")
	}
}

func TestAddressSpacesAndPrivateRooms(t *testing.T) {
	for _, value := range []string{"10.0.0.0/8", "10.77.0.0/16", "172.16.0.0/12", "172.31.255.252/30", "192.168.0.0/16", "192.168.77.0/30"} {
		prefix, err := ParseCIDR(value)
		if err != nil || !AssignableIn(prefix, prefix.Addr().Next()) || AssignableIn(prefix, prefix.Addr()) {
			t.Fatalf("invalid assignment in %s: %v", value, err)
		}
	}
	for _, value := range []string{"10.77.0.1/16", "0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/8", "10.0.0.0/7", "10.77.0.0/31", "::/16", "176.77.0.0/16", "172.0.0.0/8", "172.16.0.0/11", "172.15.0.0/16", "172.32.0.0/16", "192.168.0.0/15", "192.169.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "10.0.0.0/08", "10.0.0.0/+8", "10.01.0.0/16", "192.168.100.1/24"} {
		if _, err := ParseCIDR(value); err == nil {
			t.Fatalf("accepted invalid range %s", value)
		}
	}
	first, err := RoomToken("DUMMY room", "DUMMY password")
	if err != nil || !ValidPeerID(first) {
		t.Fatal("invalid private-room token", err)
	}
	same, _ := RoomToken("DUMMY room", "DUMMY password")
	other, _ := RoomToken("DUMMY room", "DUMMY different password")
	if first != same || first == other {
		t.Fatal("room membership is not credential-bound")
	}
	if _, err := RoomToken("DUMMY room", ""); err == nil {
		t.Fatal("accepted incomplete private-room credentials")
	}
}

func TestFramesRoundTripAndBounds(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, Hello{Version: Version, Kind: KindOpen, PublicKey: "t", Proto: ProtoTCP, Dst: "10.77.0.2", Port: 22}); err != nil {
		t.Fatal(err)
	}
	var hello Hello
	if err := ReadFrame(&buffer, &hello); err != nil || hello.Port != 22 || hello.Dst != "10.77.0.2" {
		t.Fatalf("hello = %+v, %v", hello, err)
	}
	if err := WriteFrame(&buffer, strings.Repeat("x", UsableFrame)); err == nil {
		t.Fatal("oversized frame accepted")
	}
	if err := ReadFrame(bytes.NewReader([]byte{0xff, 0xff}), &hello); err == nil {
		t.Fatal("oversized header accepted")
	}
}

func TestDatagramRoundTrip(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteDatagram(&buffer, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 16)
	if n, err := ReadDatagram(&buffer, out); err != nil || string(out[:n]) != "ping" {
		t.Fatalf("datagram = %q, %v", out[:n], err)
	}
}

func TestAssignable(t *testing.T) {
	for address, want := range map[string]bool{"10.77.0.1": true, "10.77.1.0": true, "10.77.0.0": false, "10.77.255.255": false, "10.78.0.1": false, "192.168.0.1": false} {
		if got := Assignable(netip.MustParseAddr(address)); got != want {
			t.Errorf("Assignable(%s) = %v", address, got)
		}
	}
}
