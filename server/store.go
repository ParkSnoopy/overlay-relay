package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const (
	assignmentsFile    = "ips.json"
	maxAssignmentsFile = 4 << 20
	maxAssignments     = 4096
	seenGranularity    = 3600
)

var (
	errCorruptAssignments = errors.New("overlay address assignments are corrupt")
	errAddressExhausted   = errors.New("overlay address space is exhausted")
	errInvalidIdentity    = errors.New("invalid device identity")
)

type assignment struct {
	IP   netip.Addr `json:"ip"`
	Seen uint64     `json:"seen"`
	Name string     `json:"name,omitempty"`
}

type hubStore struct {
	dir string

	mu           sync.Mutex
	firstIP      netip.Addr
	lastIP       netip.Addr
	leaseSeconds uint64
	peerEdits    map[string]peerEdit
	assignments  map[string]assignment
	byIP         map[netip.Addr]string
	reservations map[string]netip.Addr
	reservedIPs  map[netip.Addr]bool
	dirty        bool

	names *nameStore
}

func openHubStore(dir string, space netip.Prefix) (*hubStore, error) {
	s, _, err := readHubStore(dir, space)
	if err != nil {
		return nil, err
	}
	s.names = loadNames(dir)
	s.persistAssignments()
	return s, nil
}

// readHubStore builds the same effective address state for startup and CLI
// readback, without touching disk or loading the separate DNS ledger.
func readHubStore(dir string, space netip.Prefix) (*hubStore, map[string]assignment, error) {
	if _, err := parseHubCIDR(space.String()); err != nil {
		return nil, nil, err
	}
	records, err := loadAssignments(dir, uint64(max(0, time.Now().Unix())))
	if err != nil {
		return nil, nil, err
	}
	policy, err := loadDHCP(dir, space)
	if err != nil {
		return nil, nil, err
	}
	edits, err := loadPeerEdits(dir)
	if err != nil {
		return nil, nil, err
	}
	reservations, reservedIPs, err := effectiveReservations(space, policy.Bindings, edits)
	if err != nil {
		return nil, nil, err
	}
	firstIP, lastIP := hostBounds(space)
	s := &hubStore{
		dir: dir, firstIP: firstIP, lastIP: lastIP, leaseSeconds: policy.LeaseSeconds, peerEdits: edits,
		assignments: make(map[string]assignment), byIP: make(map[netip.Addr]string),
		reservations: reservations, reservedIPs: reservedIPs,
	}
	s.reconcileAssignments(space, records)
	return s, records, nil
}

func (s *hubStore) reconcileAssignments(space netip.Prefix, records map[string]assignment) {
	ids := slices.Collect(maps.Keys(records))
	// Prefer reservations and then the most recently seen device when repairing
	// duplicate addresses or trimming a hand-edited, over-capacity table.
	slices.SortFunc(ids, func(a, b string) int {
		ar, br := s.reservations[a].IsValid(), s.reservations[b].IsValid()
		switch {
		case ar && !br:
			return -1
		case br && !ar:
			return 1
		case records[a].Seen > records[b].Seen:
			return -1
		case records[a].Seen < records[b].Seen:
			return 1
		default:
			return strings.Compare(a, b)
		}
	})
	for _, id := range ids {
		record := records[id]
		oldIP := record.IP
		if reserved := s.reservations[id]; reserved.IsValid() {
			record.IP = reserved
		} else if s.reservedIPs[record.IP] {
			s.dirty = true
			continue
		}
		if !overlay.AssignableIn(space, record.IP) || s.byIP[record.IP] != "" || len(s.assignments) == maxAssignments {
			s.dirty = true
			continue
		}
		s.dirty = s.dirty || oldIP != record.IP
		s.assignments[id] = record
		s.byIP[record.IP] = id
	}
}

func loadAssignments(dir string, now uint64) (map[string]assignment, error) {
	data, err := readStoreFile(dir, assignmentsFile, maxAssignmentsFile)
	if err != nil {
		return nil, err
	}
	var stored map[string]json.RawMessage
	if len(data) > maxAssignmentsFile || (data != nil && unmarshalStoreJSON(data, &stored) != nil) {
		return nil, errCorruptAssignments
	}
	records := make(map[string]assignment)
	for _, key := range slices.Sorted(maps.Keys(stored)) {
		value := stored[key]
		var record assignment
		if len(value) != 0 && value[0] == '"' {
			if json.Unmarshal(value, &record.IP) != nil {
				return nil, errCorruptAssignments
			}
			record.Seen = now
		} else if err := decodeStoreObject(value, true,
			requiredField("ip", &record.IP), requiredField("seen", &record.Seen),
			optionalField("name", &record.Name)); err != nil {
			return nil, errCorruptAssignments
		}
		if !record.IP.IsValid() || record.IP.Zone() != "" {
			return nil, errCorruptAssignments
		}
		// Old Rust files accepted case-insensitive hex and ignored invalid keys
		// and IPv6 assignments. New writes use canonical lowercase IDs.
		id := strings.ToLower(key)
		if !validStoreID(id) || !record.IP.Is4() {
			continue
		}
		if overlay.ValidateName(record.Name) != nil {
			record.Name = ""
		}
		records[id] = record
	}
	return records, nil
}

// identify allocates while the runtime's busy predicate protects live
// accounts. The predicate must not call back into the store.
func (s *hubStore) identify(id string, now uint64, busy func(string) bool) (netip.Addr, error) {
	if !validStoreID(id) {
		return netip.Addr{}, errInvalidIdentity
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistAssignments()

	lease := s.leaseSeconds
	idle := func(other string) bool {
		return !s.reservations[other].IsValid() && (busy == nil || !busy(other))
	}
	if lease != 0 {
		for other, record := range s.assignments {
			if elapsed(now, record.Seen) >= lease && idle(other) {
				s.removeAssignment(other)
			}
		}
	}
	if record, found := s.assignments[id]; found {
		granularity := uint64(seenGranularity)
		if lease != 0 {
			granularity = min(granularity, lease/2)
		}
		if elapsed(now, record.Seen) >= granularity {
			record.Seen = now
			s.assignments[id] = record
			s.dirty = true
		}
		return record.IP, nil
	}

	ip := s.reservations[id]
	if !ip.IsValid() {
		ip = s.lowestDynamic()
	}
	if len(s.assignments) == maxAssignments || !ip.IsValid() {
		// With a nonzero lease every eligible expired entry was already
		// removed above. Never reclaim reservations or an active account.
		if lease != 0 {
			return netip.Addr{}, errAddressExhausted
		}
		var oldest string
		for other, record := range s.assignments {
			if idle(other) && (oldest == "" || record.Seen < s.assignments[oldest].Seen ||
				(record.Seen == s.assignments[oldest].Seen && other < oldest)) {
				oldest = other
			}
		}
		if oldest == "" {
			return netip.Addr{}, errAddressExhausted
		}
		freed := s.assignments[oldest].IP
		s.removeAssignment(oldest)
		if !s.reservations[id].IsValid() && (!ip.IsValid() || freed.Compare(ip) < 0) {
			ip = freed
		}
	}
	s.assignments[id] = assignment{IP: ip, Seen: now}
	s.byIP[ip] = id
	s.dirty = true
	return ip, nil
}

func (s *hubStore) lowestDynamic() netip.Addr {
	// The first gap is at most the number of assignments and reservations
	// away from the lower bound, even on a /8.
	for ip := s.firstIP; ip.Compare(s.lastIP) <= 0; ip = ip.Next() {
		if s.byIP[ip] == "" && !s.reservedIPs[ip] {
			return ip
		}
	}
	return netip.Addr{}
}

func (s *hubStore) removeAssignment(id string) {
	delete(s.byIP, s.assignments[id].IP)
	delete(s.assignments, id)
	s.dirty = true
}

func (s *hubStore) setName(id, name string) error {
	if err := overlay.ValidateName(name); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found := s.assignments[id]
	if !found {
		return errInvalidIdentity
	}
	if record.Name != name {
		record.Name = name
		s.assignments[id] = record
		s.dirty = true
	}
	s.persistAssignments()
	return nil
}

func (s *hubStore) touch(id string, now uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, found := s.assignments[id]; found {
		record.Seen = now
		s.assignments[id] = record
		s.dirty = true
	}
	s.persistAssignments()
}

// Assignment writes are best effort, as in the Rust hub. A failed save
// keeps the snapshot dirty so future activity retries it.
func (s *hubStore) persistAssignments() {
	if !s.dirty {
		return
	}
	if err := saveStoreJSON(filepath.Join(s.dir, assignmentsFile), ".ips-", s.assignments, false); err != nil {
		log.Printf("overlay identities could not be saved: %v", err)
		return
	}
	s.dirty = false
}

func elapsed(now, then uint64) uint64 {
	return max(now, then) - then
}

func validStoreID(id string) bool {
	if len(id) != hex.EncodedLen(32) {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

var errHubCIDR = errors.New("overlay range must be a canonical RFC 1918 IPv4 subnet, /8 through /30")

func parseHubCIDR(value string) (netip.Prefix, error) {
	prefix, err := overlay.ParseCIDR(value)
	if value == "" || err != nil {
		return netip.Prefix{}, errHubCIDR
	}
	return prefix, nil
}

func hostBounds(space netip.Prefix) (first, last netip.Addr) {
	bytes := space.Addr().As4()
	base := binary.BigEndian.Uint32(bytes[:])
	binary.BigEndian.PutUint32(bytes[:], base+(1<<(32-space.Bits()))-2)
	return space.Addr().Next(), netip.AddrFrom4(bytes)
}
