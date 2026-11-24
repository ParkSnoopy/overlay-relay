package main

import (
	"errors"
	"maps"
	"path/filepath"
	"slices"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const (
	peerCacheFile        = "peer-cache.json"
	maxPeerCache         = maxNames + maxAssignments*2
	maxPeerCacheBytes    = 24 << 20 // Allow a full cache even with JSON-escaped names.
	defaultPeerRetention = 7 * 24 * 60 * 60
)

// Keep detached records and DNS overrides outside the strict legacy files.
type cachedPeer struct {
	Seen   uint64 `json:"seen"`
	Name   string `json:"name,omitempty"`
	Domain string `json:"domain,omitempty"`
}

func (p *cachedPeer) UnmarshalJSON(raw []byte) error {
	return decodeStoreObject(raw, false, requiredField("seen", &p.Seen),
		optionalField("name", &p.Name), optionalField("domain", &p.Domain))
}

func loadPeerCache(dir string) (map[string]cachedPeer, error) {
	cache := make(map[string]cachedPeer)
	raw, err := readStoreFile(dir, peerCacheFile, maxPeerCacheBytes)
	if err != nil || raw == nil {
		return cache, err
	}
	if len(raw) > maxPeerCacheBytes || unmarshalStoreJSON(raw, &cache) != nil || cache == nil || len(cache) > maxPeerCache {
		return nil, errors.New("overlay peer cache is corrupt")
	}
	for id, peer := range cache {
		if !validStoreID(id) || overlay.ValidateName(peer.Name) != nil ||
			overlay.ValidateDeviceDomain(peer.Domain) != nil {
			return nil, errors.New("overlay peer cache is corrupt")
		}
	}
	return cache, nil
}

func (s *hubStore) savePeerCache(next map[string]cachedPeer) error {
	if len(next) > maxPeerCache {
		return errors.New("overlay peer cache is full")
	}
	if err := saveStoreJSON(filepath.Join(s.dir, peerCacheFile), ".peer-cache-", next, true); err != nil {
		return err
	}
	s.cache = next
	return nil
}

func (s *hubStore) cacheAssignment(id string, record assignment) error {
	next := maps.Clone(s.cache)
	peer := next[id]
	peer.Name, peer.Seen = record.Name, max(peer.Seen, record.Seen)
	next[id] = peer
	return s.savePeerCache(next)
}

func (s *hubStore) seedDetachedPeers(records map[string]assignment, now uint64) error {
	next := maps.Clone(s.cache)
	for id, record := range records {
		if _, assigned := s.assignments[id]; !assigned {
			peer := next[id]
			peer.Name, peer.Seen = record.Name, max(peer.Seen, record.Seen)
			next[id] = peer
		}
	}
	seed := func(id string) {
		if _, known := next[id]; !known && !s.assignments[id].IP.IsValid() {
			next[id] = cachedPeer{Seen: now}
		}
	}
	for id := range s.peerEdits {
		seed(id)
	}
	for _, binding := range s.dhcp.Bindings {
		seed(binding.verifier())
	}
	for _, labels := range s.names.rooms {
		for _, id := range labels {
			seed(id)
		}
	}
	if maps.Equal(s.cache, next) {
		return nil
	}
	return s.savePeerCache(next)
}

// Call under the runtime registration lock or while the hub is stopped.
func (s *hubStore) expirePeers(now uint64, busy func(string) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.expirePeersLocked(now, busy)
}

func (s *hubStore) expirePeersLocked(now uint64, busy func(string) bool) error {
	expired := make(map[string]bool)
	mark := func(id string, seen uint64) {
		if s.peerExpired(now, seen) && (busy == nil || !busy(id)) {
			expired[id] = true
		}
	}
	for id, record := range s.assignments {
		mark(id, max(record.Seen, s.cache[id].Seen))
	}
	for id, peer := range s.cache {
		if !s.assignments[id].IP.IsValid() {
			mark(id, peer.Seen)
		}
	}
	if len(expired) == 0 {
		return nil
	}

	// Delete settings first, then the files that hold the expiry timestamp.
	// An interrupted sweep can therefore finish deleting the remaining state.
	if err := s.names.removeDevices(s.dir, expired); err != nil {
		return err
	}
	edits := maps.Clone(s.peerEdits)
	maps.DeleteFunc(edits, func(id string, _ peerEdit) bool { return expired[id] })
	if len(edits) != len(s.peerEdits) {
		if err := savePeerEdits(s.dir, edits); err != nil {
			return err
		}
	}
	policy := s.dhcp
	policy.Bindings = slices.DeleteFunc(slices.Clone(policy.Bindings), func(binding dhcpBinding) bool { return expired[binding.verifier()] })
	if len(policy.Bindings) != len(s.dhcp.Bindings) {
		if err := saveStoreJSON(filepath.Join(s.dir, dhcpFile), ".dhcp-", policy, true); err != nil {
			return err
		}
	}
	assignments := maps.Clone(s.assignments)
	maps.DeleteFunc(assignments, func(id string, _ assignment) bool { return expired[id] })
	if len(assignments) != len(s.assignments) {
		if err := saveStoreJSON(filepath.Join(s.dir, assignmentsFile), ".ips-", assignments, true); err != nil {
			return err
		}
	}
	next := maps.Clone(s.cache)
	maps.DeleteFunc(next, func(id string, _ cachedPeer) bool { return expired[id] })
	if len(next) != len(s.cache) {
		if err := s.savePeerCache(next); err != nil {
			return err
		}
	}
	for id := range expired {
		delete(s.byIP, s.assignments[id].IP)
		delete(s.reservedIPs, s.reservations[id])
		delete(s.reservations, id)
	}
	s.assignments, s.peerEdits, s.dhcp = assignments, edits, policy
	return nil
}

func (s *hubStore) peerExpired(now, seen uint64) bool {
	retention := s.leaseSeconds
	if retention == 0 {
		retention = defaultPeerRetention
	}
	return elapsed(now, seen) >= retention
}

func (s *hubStore) peerPastRetention(id string, now uint64) bool {
	assigned, hasAssignment := s.assignments[id]
	cached, hasCache := s.cache[id]
	return (hasAssignment || hasCache) && s.peerExpired(now, max(assigned.Seen, cached.Seen))
}
