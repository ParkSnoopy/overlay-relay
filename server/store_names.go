package main

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"log"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"golang.org/x/net/idna"
)

const (
	namesFile    = "names.json"
	maxNames     = 16384
	maxNamesFile = 4 << 20
	aliasPrefix  = "id-"
)

var (
	errCorruptNames     = errors.New("overlay name bindings are corrupt")
	errNamesUnavailable = errors.New("overlay name bindings are unavailable")
	nameBase32          = base32.StdEncoding.WithPadding(base32.NoPadding)
)

type nameBinding struct {
	Room   string `json:"room"`
	Label  string `json:"label"`
	Device string `json:"device"`
}

func (b *nameBinding) UnmarshalJSON(raw []byte) error {
	return decodeStoreObject(raw, false, requiredField("room", &b.Room),
		requiredField("label", &b.Label), requiredField("device", &b.Device))
}

type nameStore struct {
	mu     sync.Mutex
	rooms  map[string]map[string]string
	count  int
	failed bool
}

func loadNames(dir string) *nameStore {
	n := &nameStore{rooms: make(map[string]map[string]string)}
	if err := n.load(dir); err != nil {
		log.Printf("overlay DNS is disabled until its name store is repaired and the hub restarts: %v", err)
		n.failed = true
	}
	return n
}

func (n *nameStore) load(dir string) error {
	raw, err := readStoreFile(dir, namesFile, maxNamesFile)
	if err != nil || raw == nil {
		return err
	}
	var records []nameBinding
	if len(raw) > maxNamesFile || unmarshalStoreJSON(raw, &records) != nil || records == nil || len(records) > maxNames {
		return errCorruptNames
	}
	for _, binding := range records {
		if (binding.Room != "" && !validStoreID(binding.Room)) || !validStoreID(binding.Device) ||
			!overlay.ValidNameLabel(binding.Label) || isAliasLabel(binding.Label) || n.rooms[binding.Room][binding.Label] != "" {
			return errCorruptNames
		}
		n.insert(binding.Room, binding.Label, binding.Device)
	}
	n.count = len(records)
	return nil
}

// reserveName assigns a canonical label for the requested base and device in
// the stable room. Claims are never released, so the same request also finds
// its earlier binding after disconnect, restart, or a legacy hub rewrite.
func (s *hubStore) reserveName(room, base, id string) string {
	key, _, _ := strings.Cut(room, ":")
	if !validStoreID(id) || (key != "" && !validStoreID(key)) || !overlay.ValidNameLabel(base) || isAliasLabel(base) {
		return ""
	}

	n := s.names
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failed {
		return ""
	}
	labels := n.rooms[key]
	label := base
	for suffix := 2; labels[label] != "" && labels[label] != id; suffix++ {
		label = numberedNameLabel(base, suffix)
	}
	if labels[label] == id {
		return label
	}
	if n.count >= maxNames {
		return ""
	}

	records := make([]nameBinding, 0, n.count+1)
	for _, key := range slices.Sorted(maps.Keys(n.rooms)) {
		labels := n.rooms[key]
		for _, label := range slices.Sorted(maps.Keys(labels)) {
			records = append(records, nameBinding{Room: key, Label: label, Device: labels[label]})
		}
	}
	records = append(records, nameBinding{Room: key, Label: label, Device: id})
	if err := saveStoreJSON(filepath.Join(s.dir, namesFile), ".names-", records, true); err != nil {
		// Rename may have succeeded before directory sync failed. Don't publish
		// either the old or new state until a restart loads it unambiguously.
		log.Printf("overlay DNS name bindings could not be saved: %v", err)
		n.failed = true
		return ""
	}
	n.insert(key, label, id)
	n.count++
	return label
}

func numberedNameLabel(base string, number int) string {
	suffix := "-" + strconv.Itoa(number)
	if strings.HasPrefix(base, "xn--") {
		// Append to the Unicode name before re-encoding. Appending to the
		// A-label itself would often produce invalid Punycode.
		if decoded, err := idna.Punycode.ToUnicode(base); err == nil {
			for decoded != "" {
				if label := overlay.DomainLabel(overlay.DeviceDomain(strings.TrimRight(decoded, "-") + suffix)); label != "" {
					return label
				}
				_, size := utf8.DecodeLastRuneInString(decoded)
				decoded = decoded[:len(decoded)-size]
			}
		}
		base = "xn-" + base[len("xn--"):]
	}
	return strings.TrimRight(base[:min(len(base), 63-len(suffix))], "-") + suffix
}

func (n *nameStore) insert(room, label, id string) {
	labels := n.rooms[room]
	if labels == nil {
		labels = make(map[string]string)
		n.rooms[room] = labels
	}
	labels[label] = id
}

// nameOwner rechecks private admission independently of relay permission. A
// revoked proof is a negative answer; unreadable policy or DNS state is an
// authority error. The caller must still check that the owner is online in room.
func (s *hubStore) nameOwner(room, label string) (string, error) {
	key, proof, _ := strings.Cut(room, ":")
	if room != "" {
		if _, err := readAdmittedRoom(s.dir, key, proof); err != nil {
			if errors.Is(err, errRoomUnknown) || errors.Is(err, errRoomDenied) {
				return "", nil
			}
			return "", err
		}
	}
	n := s.names
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failed {
		return "", errNamesUnavailable
	}
	if !overlay.ValidNameLabel(label) {
		return "", nil
	}
	if isAliasLabel(label) {
		encoded := strings.ToUpper(label[len(aliasPrefix):])
		raw, err := nameBase32.DecodeString(encoded)
		if err != nil || len(raw) != 32 || nameBase32.EncodeToString(raw) != encoded {
			return "", nil
		}
		return hex.EncodeToString(raw), nil
	}
	return n.rooms[key][label], nil
}

func isAliasLabel(label string) bool {
	if len(label) != len(aliasPrefix)+52 || !strings.HasPrefix(label, aliasPrefix) {
		return false
	}
	for _, c := range label[len(aliasPrefix):] {
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}
