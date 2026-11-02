package overlayagent

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Minimal STUN (RFC 5389) client messages: one Binding request and the parse
// of its success response. The agent asks a STUN server over the same UDP
// socket the direct connection will use, so the NAT mapping it learns is the
// mapping the peer will reach.
const (
	stunHeaderSize      = 20
	stunMagicCookie     = 0x2112A442
	stunBindingRequest  = 0x0001
	stunBindingSuccess  = 0x0101
	stunAttrMapped      = 0x0001
	stunAttrXORMapped   = 0x0020
	stunFamilyIPv4      = 0x01
	stunFamilyIPv6      = 0x02
	stunTransactionSize = 12
)

var errNotSTUN = errors.New("packet is not a STUN binding response")

type stunTransaction [stunTransactionSize]byte

// stunRequest builds a Binding request without attributes.
func stunRequest(tx stunTransaction) []byte {
	packet := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(packet[0:2], stunBindingRequest)
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:], tx[:])
	return packet
}

// parseSTUN extracts the transaction and the mapped address of a Binding
// success response.
func parseSTUN(packet []byte) (stunTransaction, netip.AddrPort, error) {
	var tx stunTransaction
	if len(packet) < stunHeaderSize || binary.BigEndian.Uint16(packet[0:2]) != stunBindingSuccess ||
		binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return tx, netip.AddrPort{}, errNotSTUN
	}
	copy(tx[:], packet[8:stunHeaderSize])
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	if length > len(packet)-stunHeaderSize {
		return tx, netip.AddrPort{}, errNotSTUN
	}
	attributes := packet[stunHeaderSize : stunHeaderSize+length]
	var fallback netip.AddrPort
	for len(attributes) >= 4 {
		kind := binary.BigEndian.Uint16(attributes[0:2])
		size := int(binary.BigEndian.Uint16(attributes[2:4]))
		if 4+size > len(attributes) {
			break
		}
		value := attributes[4 : 4+size]
		switch kind {
		case stunAttrXORMapped:
			if endpoint, ok := decodeMapped(value, true, tx); ok {
				return tx, endpoint, nil
			}
		case stunAttrMapped:
			if endpoint, ok := decodeMapped(value, false, tx); ok {
				fallback = endpoint
			}
		}
		padded := (size + 3) &^ 3
		if padded >= len(attributes)-4 {
			break
		}
		attributes = attributes[4+padded:]
	}
	if fallback.IsValid() {
		return tx, fallback, nil
	}
	return tx, netip.AddrPort{}, errNotSTUN
}

// decodeMapped reads a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS value.
func decodeMapped(value []byte, xor bool, tx stunTransaction) (netip.AddrPort, bool) {
	if len(value) < 4 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(value[2:4])
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
	copy(mask[4:], tx[:])
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}
	switch value[1] {
	case stunFamilyIPv4:
		if len(value) < 8 {
			return netip.AddrPort{}, false
		}
		var raw [4]byte
		copy(raw[:], value[4:8])
		if xor {
			for i := range raw {
				raw[i] ^= mask[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(raw), port), true
	case stunFamilyIPv6:
		if len(value) < 20 {
			return netip.AddrPort{}, false
		}
		var raw [16]byte
		copy(raw[:], value[4:20])
		if xor {
			for i := range raw {
				raw[i] ^= mask[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(raw), port), true
	default:
		return netip.AddrPort{}, false
	}
}
