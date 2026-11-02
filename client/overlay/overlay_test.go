package overlay

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func TestTokenAndVerifierAreStable(t *testing.T) {
	token := Token(SecretXray("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"))
	if token != Token(SecretXray("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")) {
		t.Fatal("xray secret must be case-insensitive")
	}
	if token == Token(SecretUserPass("hysteria", "a", "b")) {
		t.Fatal("different accounts must derive different tokens")
	}
	verifier, err := Verifier(token)
	if err != nil || len(verifier) != 64 || verifier == token {
		t.Fatalf("verifier = %q, %v", verifier, err)
	}
	if _, err = Verifier("zz"); err == nil {
		t.Fatal("malformed token accepted")
	}
}

func TestFramesRoundTripAndBounds(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, Hello{Version: Version, Kind: KindOpen, Token: "t", Proto: ProtoTCP, Dst: "10.77.0.2", Port: 22}); err != nil {
		t.Fatal(err)
	}
	var hello Hello
	if err := ReadFrame(&buffer, &hello); err != nil || hello.Port != 22 || hello.Dst != "10.77.0.2" {
		t.Fatalf("hello = %+v, %v", hello, err)
	}
	if err := WriteFrame(&buffer, strings.Repeat("x", MaxFrame)); err == nil {
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

func TestPeersValidate(t *testing.T) {
	verifier, _ := Verifier(Token([]byte("x")))
	if err := (Peers{Version: Version, Accounts: []Account{{Verifier: verifier}}}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Peers{Version: Version, Accounts: []Account{{Verifier: verifier}, {Verifier: verifier}}}).Validate(); err == nil {
		t.Fatal("duplicate account accepted")
	}
}
