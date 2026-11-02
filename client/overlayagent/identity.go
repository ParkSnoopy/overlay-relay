package overlayagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"time"
)

const (
	// relayALPN names the TLS application protocol of an encrypted relayed flow.
	relayALPN = "overlay-relay/flow-1"
	// directALPN names the QUIC application protocol of a direct flow.
	directALPN = "overlay-relay/direct-1"
	// relayServerName is the nominal server name of a relayed flow. It only
	// satisfies TLS; the peer is identified by its pinned certificate.
	relayServerName = "overlay-relay"
	// certificateLifetime is long on purpose: nothing checks it, because a
	// peer is trusted by its fingerprint and an agent makes a new certificate per run.
	certificateLifetime = 10 * 365 * 24 * time.Hour
)

var errPinMismatch = errors.New("overlay peer certificate does not match its fingerprint")

// identity is the agent's self-signed flow certificate. Its SHA-256
// fingerprint travels through the hub, and the peer pins it, which replaces a
// certificate authority: the hub is the trusted channel for fingerprints.
type identity struct {
	cert        tls.Certificate
	fingerprint string
}

func newIdentity() (*identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: relayServerName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(certificateLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &identity{
		cert:        tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		fingerprint: hex.EncodeToString(sum[:]),
	}, nil
}

// clientConfig authenticates the server by its pinned fingerprint.
func (i *identity) clientConfig(peerFingerprint, serverName, protocol string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{i.cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{protocol},
		ServerName:   serverName,
		// The certificate is self-signed. Chain verification cannot apply, and
		// VerifyPeerCertificate pins the exact certificate instead.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: pinned(peerFingerprint),
	}
}

// serverConfig requires a client certificate and pins its fingerprint.
func (i *identity) serverConfig(peerFingerprint, protocol string) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{i.cert},
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{protocol},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinned(peerFingerprint),
	}
}

// pinned accepts exactly the certificate whose SHA-256 is expected.
func pinned(expected string) func([][]byte, [][]*x509.Certificate) error {
	want, decodeErr := hex.DecodeString(expected)
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		if decodeErr != nil || len(want) != sha256.Size || len(raw) == 0 {
			return errPinMismatch
		}
		sum := sha256.Sum256(raw[0])
		if subtle.ConstantTimeCompare(sum[:], want) != 1 {
			return errPinMismatch
		}
		return nil
	}
}

// sameFingerprint compares two hex fingerprints without regard to case.
func sameFingerprint(a, b string) bool {
	left, errA := hex.DecodeString(a)
	right, errB := hex.DecodeString(b)
	return errA == nil && errB == nil && len(left) == sha256.Size && subtle.ConstantTimeCompare(left, right) == 1
}
