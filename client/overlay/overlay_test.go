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
