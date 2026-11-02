package overlay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

// GenerateIdentity creates a private P-384 key. The caller must persist it securely.
func GenerateIdentity() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// EncodeIdentity encodes a P-384 private key as PKCS#8 PEM.
func EncodeIdentity(key *ecdsa.PrivateKey) ([]byte, error) {
	if key == nil || key.Curve != elliptic.P384() {
		return nil, errors.New("invalid P-384 identity")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseIdentity decodes a PKCS#8 PEM P-384 private key.
func ParseIdentity(data []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("invalid identity PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P384() {
		return nil, errors.New("identity must be a P-384 private key")
	}
	return key, nil
}

// PublicIdentity returns the hex-encoded uncompressed P-384 public key.
func PublicIdentity(key *ecdsa.PrivateKey) (string, error) {
	if key == nil || key.Curve != elliptic.P384() {
		return "", errors.New("invalid P-384 identity")
	}
	private, err := key.ECDH()
	if err != nil {
		return "", errors.New("invalid P-384 identity")
	}
	public, err := key.PublicKey.Bytes()
	if err != nil || !bytes.Equal(private.PublicKey().Bytes(), public) {
		return "", errors.New("invalid P-384 identity")
	}
	return hex.EncodeToString(public), nil
}

// IdentityID returns the SHA-256 digest of an encoded public identity.
func IdentityID(public string) (string, error) {
	raw, err := hex.DecodeString(public)
	if err != nil {
		return "", errors.New("invalid P-384 public identity")
	}
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), raw); err != nil {
		return "", errors.New("invalid P-384 public identity")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
