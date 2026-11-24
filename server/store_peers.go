package main

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const (
	peerEditsFile    = "peers.json"
	maxPeerEditBytes = 4 << 10
	maxPeerEditsFile = 4 << 20
)

var errCorruptPeerEdits = errors.New("overlay peer settings are corrupt")

// Keeping the complete edit in one sidecar makes name and address changes
// atomic without changing the strict persisted schemas of older hubs. A row
// takes precedence over a legacy binding, even if its Binding is empty.
type peerEdit struct {
	DeviceID string `json:"device_id"`
	Name     string `json:"name"`
	Binding  string `json:"binding"`
}

func (p *peerEdit) UnmarshalJSON(raw []byte) error {
	return decodeStoreObject(raw, false, requiredField("device_id", &p.DeviceID),
		requiredField("name", &p.Name), requiredField("binding", &p.Binding))
}

func (p peerEdit) validate() error {
	if !validStoreID(p.DeviceID) {
		return errInvalidIdentity
	}
	if err := overlay.ValidateName(p.Name); err != nil {
		return err
	}
	if p.Binding != "" && !p.bindingIP().IsPrivate() {
		return errors.New("peer binding must be a usable IPv4 address within the hub subnet")
	}
	return nil
}

func (p peerEdit) bindingIP() netip.Addr {
	ip, err := netip.ParseAddr(p.Binding)
	if err != nil || !ip.Is4() || ip.String() != p.Binding {
		return netip.Addr{}
	}
	return ip
}

func loadPeerEdits(dir string) (map[string]peerEdit, error) {
	edits := make(map[string]peerEdit)
	info, err := os.Lstat(filepath.Join(dir, peerEditsFile))
	if errors.Is(err, fs.ErrNotExist) {
		return edits, nil
	}
	if err != nil {
		return nil, fmt.Errorf("overlay i/o failed: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxPeerEditsFile {
		return nil, errCorruptPeerEdits
	}
	raw, err := readStoreFile(dir, peerEditsFile, maxPeerEditsFile)
	if err != nil {
		return nil, err
	}
	var rows []peerEdit
	if len(raw) > maxPeerEditsFile || unmarshalStoreJSON(raw, &rows) != nil || rows == nil || len(rows) > maxAssignments {
		return nil, errCorruptPeerEdits
	}
	for _, row := range rows {
		if row.validate() != nil || edits[row.DeviceID].DeviceID != "" {
			return nil, errCorruptPeerEdits
		}
		edits[row.DeviceID] = row
	}
	return edits, nil
}

func effectiveReservations(space netip.Prefix, legacy []dhcpBinding, edits map[string]peerEdit) (reservations map[string]netip.Addr, used map[netip.Addr]bool, err error) {
	reservations = make(map[string]netip.Addr)
	for _, binding := range legacy {
		id := binding.verifier()
		if _, overridden := edits[id]; !overridden {
			reservations[id] = binding.IP
		}
	}
	for id, edit := range edits {
		if ip := edit.bindingIP(); ip.IsValid() {
			reservations[id] = ip
		}
	}
	if len(reservations) > maxAssignments {
		return nil, nil, errors.New("too many peer bindings")
	}
	used = make(map[netip.Addr]bool, len(reservations))
	for _, ip := range reservations {
		if !overlay.AssignableIn(space, ip) || used[ip] {
			return nil, nil, errors.New("peer bindings must have unique usable addresses within the hub subnet")
		}
		used[ip] = true
	}
	return reservations, used, nil
}

type listedPeer struct {
	Name           string `json:"name"`
	NameOverride   string `json:"name_override"`
	IP             string `json:"ip"`
	Binding        string `json:"binding"`
	DomainOverride string `json:"domain_override"`
	Domain         string `json:"domain,omitempty"`
	Connected      bool   `json:"connected"`
}

type peerListing struct {
	Devices map[string]listedPeer `json:"devices"`
}

func listPeers(dir string, space netip.Prefix) (peerListing, error) {
	s, known, err := readPeerAdminState(dir, space)
	if err != nil {
		return peerListing{}, err
	}
	return s.listKnownPeers(known), nil
}

// Call with the store locked when its runtime is active.
func (s *hubStore) listKnownPeers(known map[string]assignment) peerListing {
	devices := make(map[string]listedPeer, len(known)+len(s.assignments)+len(s.cache))
	for id, record := range known {
		devices[id] = listedPeer{Name: record.Name}
	}
	for id, record := range s.cache {
		devices[id] = listedPeer{Name: record.Name, DomainOverride: record.Domain}
	}
	for id, record := range s.assignments {
		device := devices[id]
		device.IP, device.Name = record.IP.String(), record.Name
		devices[id] = device
	}
	for id, ip := range s.reservations {
		device := devices[id]
		device.IP, device.Binding = ip.String(), ip.String()
		devices[id] = device
	}
	for id, edit := range s.peerEdits {
		device := devices[id]
		device.NameOverride = edit.Name
		if edit.Name != "" {
			device.Name = edit.Name
		}
		devices[id] = device
	}
	return peerListing{Devices: devices}
}

func readPeerAdminState(dir string, space netip.Prefix) (*hubStore, map[string]assignment, error) {
	s, records, err := readHubStore(dir, space)
	if err != nil {
		return nil, nil, err
	}
	names, err := readNames(dir)
	if err != nil {
		return nil, nil, err
	}
	known := maps.Clone(records)
	now := hubUnixNow()
	add := func(id string) {
		if _, found := known[id]; !found {
			known[id] = assignment{Seen: now}
		}
	}
	for _, room := range names.rooms {
		for _, id := range room {
			add(id)
		}
	}
	for id := range s.peerEdits {
		add(id)
	}
	for _, binding := range s.dhcp.Bindings {
		add(binding.verifier())
	}
	return s, known, nil
}

type peerEditRequest struct {
	peerEdit
	Domain *string
}

func (p *peerEditRequest) UnmarshalJSON(raw []byte) error {
	return decodeStoreObject(raw, false, requiredField("device_id", &p.DeviceID),
		requiredField("name", &p.Name), requiredField("binding", &p.Binding),
		optionalField("domain", &p.Domain))
}

func (p peerEditRequest) validate() error {
	if p.Domain != nil {
		if err := overlay.ValidateDeviceDomain(*p.Domain); err != nil {
			return err
		}
	}
	return p.peerEdit.validate()
}

func setPeer(dir string, space netip.Prefix, raw []byte) error {
	if len(raw) > maxPeerEditBytes {
		return errors.New("peer settings are too large")
	}
	var request peerEditRequest
	if err := unmarshalStoreJSON(raw, &request); err != nil {
		return fmt.Errorf("overlay json is invalid: %w", err)
	}
	if err := request.validate(); err != nil {
		return err
	}
	s, known, err := readPeerAdminState(dir, space)
	if err != nil {
		return err
	}
	edit := request.peerEdit
	peer, cached := s.cache[edit.DeviceID]
	record, found := known[edit.DeviceID]
	if !found && !cached {
		return errors.New("peer settings require a device known to this hub")
	}
	// DNS-only records may lack a legacy timestamp; prefer their cached clock.
	if !cached || (record.IP.IsValid() && record.Seen >= peer.Seen) {
		peer.Name, peer.Seen = record.Name, record.Seen
	}
	if s.peerExpired(hubUnixNow(), peer.Seen) {
		return errors.New("device has expired")
	}
	if err := s.validatePeerEdit(space, edit, cached || found); err != nil {
		return err
	}
	oldCache := s.cache
	if request.Domain != nil && *request.Domain != peer.Domain {
		peer.Domain = *request.Domain
		next := maps.Clone(s.cache)
		next[edit.DeviceID] = peer
		if err := s.savePeerCache(next); err != nil {
			return err
		}
	}
	old, edited := s.peerEdits[edit.DeviceID]
	if old == edit || (!edited && edit.Name == "" && edit.bindingIP() == s.reservations[edit.DeviceID]) {
		return nil
	}
	s.peerEdits[edit.DeviceID] = edit
	if err := savePeerEdits(dir, s.peerEdits); err != nil {
		if !maps.Equal(oldCache, s.cache) {
			return errors.Join(err, s.savePeerCache(oldCache))
		}
		return err
	}
	return nil
}

func savePeerEdits(dir string, edits map[string]peerEdit) error {
	rows := make([]peerEdit, 0, len(edits))
	for _, id := range slices.Sorted(maps.Keys(edits)) {
		rows = append(rows, edits[id])
	}
	return saveStoreJSON(filepath.Join(dir, peerEditsFile), ".peers-", rows, true)
}

func (s *hubStore) validatePeerEdit(space netip.Prefix, edit peerEdit, seen bool) error {
	id := edit.DeviceID
	_, edited := s.peerEdits[id]
	current := s.reservations[id]
	if !seen && !edited && !current.IsValid() {
		return errors.New("peer settings require a device known to this hub")
	}
	if ip := edit.bindingIP(); ip.IsValid() {
		if !overlay.AssignableIn(space, ip) {
			return errors.New("peer binding must be a usable IPv4 address within the hub subnet")
		}
		if (s.reservedIPs[ip] && current != ip) || (s.byIP[ip] != "" && s.byIP[ip] != id) {
			return errors.New("peer binding address is already in use by another device")
		}
		if !current.IsValid() && len(s.reservations) == maxAssignments {
			return errors.New("too many peer bindings")
		}
	}
	if !edited && len(s.peerEdits) == maxAssignments && (edit.Name != "" || edit.bindingIP() != current) {
		return errors.New("too many managed peers")
	}
	return nil
}
