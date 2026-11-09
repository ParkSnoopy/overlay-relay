package overlayagent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

func sealedAgent(t *testing.T) *Agent {
	t.Helper()
	key, err := overlay.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a := New(Config{Identity: key})
	if a.identity == nil || a.identityErr != nil {
		t.Fatalf("identity not created: %v", a.identityErr)
	}
	a.timing = defaultTiming
	return a
}

func TestIdentityFingerprintIsTheCertificateHash(t *testing.T) {
	id, err := newIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(id.cert.Certificate[0])
	if id.fingerprint != hex.EncodeToString(sum[:]) || len(id.fingerprint) != 64 {
		t.Fatalf("fingerprint %q is not the SHA-256 of the certificate", id.fingerprint)
	}
	other, err := newIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if other.fingerprint == id.fingerprint {
		t.Fatal("two identities must differ")
	}
	if err := pinned(id.fingerprint)(id.cert.Certificate, nil); err != nil {
		t.Fatalf("own certificate must pass its pin: %v", err)
	}
	if err := pinned(other.fingerprint)(id.cert.Certificate, nil); !errors.Is(err, errPinMismatch) {
		t.Fatalf("a different certificate must fail the pin, got %v", err)
	}
	for _, bad := range []string{"", "zz", id.fingerprint[:62]} {
		if err := pinned(bad)(id.cert.Certificate, nil); !errors.Is(err, errPinMismatch) {
			t.Fatalf("pin %q must fail closed, got %v", bad, err)
		}
	}
	if !sameFingerprint(id.fingerprint, upper(id.fingerprint)) || sameFingerprint(id.fingerprint, other.fingerprint) {
		t.Fatal("sameFingerprint must ignore case and reject different values")
	}
}

func upper(text string) string {
	out := []byte(text)
	for i, c := range out {
		if c >= 'a' && c <= 'f' {
			out[i] = c - 32
		}
	}
	return string(out)
}

// sealed is the outcome of sealing one end of a pipe.
type sealed struct {
	conn net.Conn
	err  error
}

// sealPair runs seal on both ends of a pipe: the requester and the destination.
func sealPair(requester, destination *Agent, toRequester, toDestination *overlay.Reply) (requested, destined sealed) {
	left, right := net.Pipe()
	ctx := context.Background()
	done := make(chan sealed, 1)
	go func() {
		conn, err := destination.seal(ctx, right, toDestination, false)
		done <- sealed{conn, err}
	}()
	conn, err := requester.seal(ctx, left, toRequester, true)
	return sealed{conn, err}, <-done
}

func TestSealEncryptsAndPinsBothPeers(t *testing.T) {
	alice, bob := sealedAgent(t), sealedAgent(t)
	toAlice := &overlay.Reply{OK: true, Secure: true, Fingerprint: bob.identity.fingerprint}
	toBob := &overlay.Reply{OK: true, Secure: true, Fingerprint: alice.identity.fingerprint}
	requested, destined := sealPair(alice, bob, toAlice, toBob)
	if requested.err != nil || destined.err != nil {
		t.Fatalf("handshake failed: %v / %v", requested.err, destined.err)
	}
	aliceConn, bobConn := requested.conn, destined.conn
	defer func() { _ = aliceConn.Close(); _ = bobConn.Close() }()

	go func() { _, _ = aliceConn.Write([]byte("sealed hello")) }()
	got := make([]byte, len("sealed hello"))
	if err := bobConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(bobConn, got); err != nil || string(got) != "sealed hello" {
		t.Fatalf("read %q: %v", got, err)
	}
}

func TestSealRejectsAWrongFingerprint(t *testing.T) {
	alice, bob, mallory := sealedAgent(t), sealedAgent(t), sealedAgent(t)
	// Alice expects mallory's certificate but talks to bob.
	toAlice := &overlay.Reply{OK: true, Secure: true, Fingerprint: mallory.identity.fingerprint}
	toBob := &overlay.Reply{OK: true, Secure: true, Fingerprint: alice.identity.fingerprint}
	requested, destined := sealPair(alice, bob, toAlice, toBob)
	if !errors.Is(requested.err, errSealFailed) {
		t.Fatalf("requester must reject a certificate it did not pin, got %v", requested.err)
	}
	if destined.err == nil {
		t.Fatal("destination must fail when the requester aborts")
	}
}

func TestSealFailsWhenThePeerOffersNoEncryption(t *testing.T) {
	alice := sealedAgent(t)
	left, right := net.Pipe()
	defer func() { _ = right.Close() }()
	conn, err := alice.seal(context.Background(), left, &overlay.Reply{OK: true}, true)
	if conn != nil || !errors.Is(err, errPlaintextPeer) {
		t.Fatalf("a plaintext peer must fail the flow, got %v / %v", conn, err)
	}
	if _, err := left.Write([]byte("x")); err == nil {
		t.Fatal("the stream must be closed after the refusal")
	}
}

func TestSealIsSkippedWhenEncryptionIsDisabled(t *testing.T) {
	key, err := overlay.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a := New(Config{Identity: key, DisableEncryption: true})
	left, right := net.Pipe()
	defer func() { _ = left.Close(); _ = right.Close() }()
	conn, err := a.seal(context.Background(), left, &overlay.Reply{OK: true}, true)
	if err != nil || conn != left {
		t.Fatalf("plain relay must pass through unchanged, got %v / %v", conn, err)
	}
	hello := &overlay.Hello{}
	a.offer(hello)
	if hello.Fingerprint != "" || hello.Endpoint != "" {
		t.Fatalf("a disabled agent must offer nothing, got %+v", hello)
	}
}

func TestOfferCarriesTheFingerprintOnly(t *testing.T) {
	a := sealedAgent(t)
	hello := &overlay.Hello{}
	a.offer(hello)
	if hello.Fingerprint != a.identity.fingerprint || hello.Endpoint != "" {
		t.Fatalf("offer must carry the fingerprint only, got %+v", hello)
	}
}

func TestStunRoundTrip(t *testing.T) {
	var tx stunTransaction
	copy(tx[:], "0123456789ab")
	request := stunRequest(tx)
	if len(request) != stunHeaderSize || binary.BigEndian.Uint32(request[4:8]) != stunMagicCookie {
		t.Fatalf("malformed request: % x", request)
	}
	want := netip.MustParseAddrPort("203.0.113.7:54321")
	got, endpoint, err := parseSTUN(stunResponse(tx, want, true))
	if err != nil || got != tx || endpoint != want {
		t.Fatalf("xor response: %v %v %v", got, endpoint, err)
	}
	_, endpoint, err = parseSTUN(stunResponse(tx, want, false))
	if err != nil || endpoint != want {
		t.Fatalf("plain mapped response: %v %v", endpoint, err)
	}
	v6 := netip.MustParseAddrPort("[2001:db8::1]:4242")
	_, endpoint, err = parseSTUN(stunResponse(tx, v6, true))
	if err != nil || endpoint != v6 {
		t.Fatalf("ipv6 response: %v %v", endpoint, err)
	}
}

func TestStunRejectsGarbage(t *testing.T) {
	var tx stunTransaction
	good := stunResponse(tx, netip.MustParseAddrPort("203.0.113.7:1"), true)
	cases := map[string][]byte{
		"empty":     nil,
		"short":     good[:10],
		"request":   stunRequest(tx),
		"truncated": good[:len(good)-3],
		"no attrs":  append(append([]byte(nil), good[:2]...), append([]byte{0, 0}, good[4:stunHeaderSize]...)...),
	}
	for name, packet := range cases {
		if _, _, err := parseSTUN(packet); err == nil {
			t.Errorf("%s: garbage must not parse", name)
		}
	}
}

// stunResponse builds a Binding success response carrying endpoint.
func stunResponse(tx stunTransaction, endpoint netip.AddrPort, xor bool) []byte {
	var value []byte
	port := endpoint.Port()
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
	copy(mask[4:], tx[:])
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	addr := endpoint.Addr()
	family := byte(stunFamilyIPv4)
	raw := addr.AsSlice()
	if addr.Is6() {
		family = stunFamilyIPv6
	}
	if xor {
		for i := range raw {
			raw[i] ^= mask[i]
		}
	}
	value = append(value, 0, family)
	value = binary.BigEndian.AppendUint16(value, port)
	value = append(value, raw...)
	kind := uint16(stunAttrMapped)
	if xor {
		kind = stunAttrXORMapped
	}
	attribute := binary.BigEndian.AppendUint16(nil, kind)
	attribute = binary.BigEndian.AppendUint16(attribute, uint16(len(value)))
	attribute = append(attribute, value...)
	packet := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(packet[0:2], stunBindingSuccess)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(attribute)))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:], tx[:])
	return append(packet, attribute...)
}
