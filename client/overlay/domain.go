package overlay

import (
	"errors"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// DeviceZone is the room-local suffix, without the DNS root dot.
const DeviceZone = "on.snoo"

// ValidateDeviceDomain accepts a canonical room-local domain or an empty override.
func ValidateDeviceDomain(domain string) error {
	if domain != "" && DomainLabel(domain) == "" {
		return errors.New("overlay domain must be a valid name ending in .on.snoo")
	}
	return nil
}

var deviceIDNA = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false), idna.BidiRule())

// DeviceDomain proposes a single normalized label; only the hub assigns ownership.
func DeviceDomain(name string) string {
	var value strings.Builder
	separator := false
	for _, c := range name {
		switch {
		case c == '-':
		case unicode.IsSpace(c) || unicode.IsPunct(c):
			separator = value.Len() != 0
			continue
		case unicode.IsLetter(c) || unicode.IsNumber(c) || unicode.IsMark(c):
		default:
			return ""
		}
		if separator && c != '-' {
			value.WriteByte('-')
		}
		separator = false
		value.WriteRune(c)
	}
	label, err := deviceIDNA.ToASCII(strings.Trim(value.String(), "-"))
	if err != nil || !ValidNameLabel(label) || reservedIdentityLabel(label) {
		return ""
	}
	return label + "." + DeviceZone
}

// DomainLabel accepts only a canonical wire domain, never a search suffix or wildcard.
func DomainLabel(domain string) string {
	label, ok := strings.CutSuffix(domain, "."+DeviceZone)
	if !ok || !ValidNameLabel(label) || reservedIdentityLabel(label) {
		return ""
	}
	if strings.HasPrefix(label, "xn--") {
		decoded, err := deviceIDNA.ToUnicode(label)
		if err != nil || DeviceDomain(decoded) != domain {
			return ""
		}
	}
	return label
}

// Legacy full-key aliases still resolve, but cannot be advertised as device names.
func reservedIdentityLabel(label string) bool {
	encoded, prefixed := strings.CutPrefix(label, "id-")
	return prefixed && len(encoded) == 52 && strings.Trim(encoded, "abcdefghijklmnopqrstuvwxyz234567") == ""
}

func ValidNameLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}
