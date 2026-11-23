package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const (
	dhcpFile     = "dhcp.json"
	maxDHCPBytes = 64 * 1024
)

type dhcpBinding struct {
	DeviceID  *string    `json:"device_id,omitempty"`
	PublicKey *string    `json:"public_key,omitempty"`
	IP        netip.Addr `json:"ip"`
}

func (b *dhcpBinding) UnmarshalJSON(raw []byte) error {
	return decodeStoreObject(raw, false, nullableField("device_id", &b.DeviceID),
		nullableField("public_key", &b.PublicKey), requiredField("ip", &b.IP))
}

func (b dhcpBinding) verifier() string {
	switch {
	case b.DeviceID != nil && b.PublicKey == nil && validStoreID(*b.DeviceID):
		return *b.DeviceID
	case b.DeviceID == nil && b.PublicKey != nil:
		key := *b.PublicKey
		if len(key) != 194 || key != strings.ToLower(key) || !strings.HasPrefix(key, "04") {
			return ""
		}
		decoded, err := hex.DecodeString(key)
		if err != nil {
			return ""
		}
		if _, err := ecdh.P384().NewPublicKey(decoded); err != nil {
			return ""
		}
		digest := sha256.Sum256(decoded)
		return hex.EncodeToString(digest[:])
	default:
		return ""
	}
}

type dhcpPolicy struct {
	Start        netip.Addr    `json:"start"`
	End          netip.Addr    `json:"end"`
	LeaseSeconds uint64        `json:"lease_seconds"`
	Bindings     []dhcpBinding `json:"bindings"`
}

func defaultDHCP(space netip.Prefix) dhcpPolicy {
	start, end := hostBounds(space)
	return dhcpPolicy{Start: start, End: end, Bindings: []dhcpBinding{}}
}

func (p *dhcpPolicy) validate(space netip.Prefix) error {
	if err := p.validateLegacyShape(); err != nil {
		return err
	}
	if !overlay.AssignableIn(space, p.Start) || !overlay.AssignableIn(space, p.End) {
		return errors.New("DHCP pool must be an ordered usable range within the hub subnet")
	}
	for _, binding := range p.Bindings {
		if !overlay.AssignableIn(space, binding.IP) {
			return errors.New("DHCP bindings must have unique device identities and unique usable addresses")
		}
	}
	return nil
}

// Legacy endpoints are preserved for the old CLI and rollback. They are not
// address authority and may refer to a previously configured subnet.
func (p *dhcpPolicy) validateLegacyShape() error {
	if !validLegacyPool(p.Start, p.End) {
		return errors.New("DHCP pool must be an ordered usable range within the hub subnet")
	}
	if p.LeaseSeconds > 31_536_000 || (p.LeaseSeconds != 0 && p.LeaseSeconds < 60) {
		return errors.New("DHCP lease must be 0 or 60 through 31536000 seconds")
	}
	if len(p.Bindings) > 256 {
		return errors.New("too many DHCP bindings")
	}
	ids := make(map[string]bool)
	ips := make(map[netip.Addr]bool)
	for _, binding := range p.Bindings {
		id := binding.verifier()
		if id == "" {
			return errors.New("DHCP binding requires one valid device identity")
		}
		if !binding.IP.Is4() || !binding.IP.IsPrivate() || ids[id] || ips[binding.IP] {
			return errors.New("DHCP bindings must have unique device identities and unique usable addresses")
		}
		ids[id], ips[binding.IP] = true, true
	}
	return nil
}

func validLegacyPool(start, end netip.Addr) bool {
	if !start.Is4() || !start.IsPrivate() || !end.Is4() || start.Compare(end) > 0 {
		return false
	}
	bits := 16
	switch start.As4()[0] {
	case 10:
		bits = 8
	case 172:
		bits = 12
	}
	block := netip.PrefixFrom(start, bits).Masked()
	return overlay.AssignableIn(block, start) && overlay.AssignableIn(block, end)
}

func decodeDHCP(raw []byte) (dhcpPolicy, error) {
	var policy dhcpPolicy
	if len(raw) > maxDHCPBytes {
		return policy, errors.New("DHCP policy is too large")
	}
	if err := decodeStoreObject(raw, false, requiredField("start", &policy.Start), requiredField("end", &policy.End),
		requiredField("lease_seconds", &policy.LeaseSeconds), requiredField("bindings", &policy.Bindings)); err != nil {
		return policy, fmt.Errorf("overlay json is invalid: %w", err)
	}
	return policy, nil
}

func loadDHCP(dir string, space netip.Prefix) (dhcpPolicy, error) {
	raw, err := readStoreFile(dir, dhcpFile, maxDHCPBytes)
	if err != nil {
		return dhcpPolicy{}, err
	}
	if raw == nil {
		return defaultDHCP(space), nil
	}
	policy, err := decodeDHCP(raw)
	if err != nil {
		return dhcpPolicy{}, err
	}
	err = policy.validateLegacyShape()
	return policy, err
}

type dhcpDevice struct {
	IP   netip.Addr `json:"ip"`
	Name string     `json:"name"`
}

type dhcpEditor struct {
	Devices map[string]dhcpDevice `json:"devices"`
	Policy  dhcpPolicy            `json:"policy"`
}

func editDHCP(dir string, space netip.Prefix) (dhcpEditor, error) {
	policy, err := loadDHCP(dir, space)
	if err != nil {
		return dhcpEditor{}, err
	}
	assignments, err := loadAssignments(dir, 0)
	if err != nil {
		return dhcpEditor{}, err
	}
	devices := make(map[string]dhcpDevice)
	for id, record := range assignments {
		devices[id] = dhcpDevice{IP: record.IP, Name: record.Name}
	}
	for i := range policy.Bindings {
		binding := &policy.Bindings[i]
		id := binding.verifier()
		devices[id] = dhcpDevice{IP: binding.IP, Name: devices[id].Name}
		binding.DeviceID, binding.PublicKey = &id, nil
	}
	return dhcpEditor{Devices: devices, Policy: policy}, nil
}

func saveDHCP(dir string, space netip.Prefix, raw []byte) error {
	policy, err := decodeDHCP(raw)
	if err != nil {
		return err
	}
	if err := policy.validate(space); err != nil {
		return err
	}
	edits, err := loadPeerEdits(dir)
	if err != nil {
		return err
	}
	if _, _, err := effectiveReservations(space, policy.Bindings, edits); err != nil {
		return err
	}
	path := filepath.Join(dir, dhcpFile)
	start, end := hostBounds(space)
	if policy.Start == start && policy.End == end && policy.LeaseSeconds == 0 && len(policy.Bindings) == 0 {
		// Removing an override means unlinking a file, not deleting a directory
		// that happens to occupy dhcp.json.
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err == nil && info.IsDir() {
			err = errors.New("DHCP policy path is a directory")
		}
		if err == nil {
			err = os.Remove(path)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("overlay i/o failed: %w", err)
		}
		return nil
	}
	if err := validateKnownBindings(dir, space, policy.Bindings); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return fmt.Errorf("overlay i/o failed: %w", err)
	}
	return saveStoreJSON(path, ".dhcp-", policy, false)
}

func validateKnownBindings(dir string, space netip.Prefix, bindings []dhcpBinding) error {
	usesIDs := false
	for _, binding := range bindings {
		usesIDs = usesIDs || binding.DeviceID != nil
	}
	if !usesIDs {
		return nil
	}
	assignments, err := loadAssignments(dir, 0)
	if err != nil {
		return err
	}
	previous, err := loadDHCP(dir, space)
	if err != nil {
		return err
	}
	known := make(map[string]bool)
	for id := range assignments {
		known[id] = true
	}
	for _, binding := range previous.Bindings {
		known[binding.verifier()] = true
	}
	for _, binding := range bindings {
		if binding.DeviceID != nil && !known[*binding.DeviceID] {
			return errors.New("DHCP binding requires a device known to this hub")
		}
	}
	return nil
}
