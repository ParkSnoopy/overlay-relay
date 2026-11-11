package overlay

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
)

// ParseCIDR accepts canonical subnets wholly inside RFC 1918 private space.
// Empty selects the default; network and broadcast addresses remain reserved.
func ParseCIDR(value string) (netip.Prefix, error) {
	if value == "" {
		return CIDR, nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.String() != value || prefix.Bits() < 8 || prefix.Bits() > 30 {
		return netip.Prefix{}, errors.New("overlay range must be a canonical IPv4 /8 through /30 CIDR")
	}
	for _, block := range []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	} {
		if prefix.Bits() >= block.Bits() && block.Contains(prefix.Addr()) {
			return prefix, nil
		}
	}
	return netip.Prefix{}, errors.New("overlay range must be within RFC 1918 private IPv4 space")
}

// AssignableIn excludes the network and broadcast addresses of prefix.
func AssignableIn(prefix netip.Prefix, address netip.Addr) bool {
	if !address.Is4() || !prefix.Contains(address) || address == prefix.Addr() {
		return false
	}
	bytes := address.As4()
	network := prefix.Addr().As4()
	var host, base uint32
	for i := range bytes {
		host = host<<8 | uint32(bytes[i])
		base = base<<8 | uint32(network[i])
	}
	return host-base != uint32(1)<<(32-prefix.Bits())-1
}

// RoomToken derives an opaque membership capability. Neither the room's name
// nor password is sent to the hub. Different passwords produce disjoint rooms,
// including after restart; there is no public room directory or first-join race.
// It must only travel over the authenticated VPN and never enter logs.
func RoomToken(id, password string) (string, error) {
	if err := ValidateRoom(id, password); err != nil {
		return "", err
	}
	if id == "" && password == "" {
		return "", nil
	}
	key, err := pbkdf2.Key(sha256.New, password, []byte("overlay-relay/room/v3:"+id), 210000, 32)
	if err != nil {
		return "", errors.New("overlay room key derivation failed")
	}
	return hex.EncodeToString(key), nil
}

// ValidateRoom accepts either public membership (both empty) or private
// membership with a complete credential. It performs no key derivation.
func ValidateRoom(id, password string) error {
	if id == "" && password == "" {
		return nil
	}
	if id == "" || password == "" || len(password) > 1024 || ValidateName(id) != nil {
		return errors.New("a private overlay room requires a valid room ID and password")
	}
	return nil
}
