package main

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"log"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unicode"

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
	nameIDNA            = idna.New(idna.MapForLookup(), idna.StrictDomainName(false), idna.CheckHyphens(false), idna.BidiRule())
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
			!validDNSLabel(binding.Label) || isAliasLabel(binding.Label) || n.rooms[binding.Room][binding.Label] != "" {
			return errCorruptNames
		}
		n.insert(binding.Room, binding.Label, binding.Device)
	}
	n.count = len(records)
	return nil
}

// reserveName stores the first owner of a label for the stable room key. The
// caller supplies the display name (including the default, if unadvertised).
func (s *hubStore) reserveName(room, name, id string) {
	key, _, _ := strings.Cut(room, ":")
	if !validStoreID(id) || (key != "" && !validStoreID(key)) {
		return
	}
	label := normalizedDNSLabel(name)
	if label == "" || isAliasLabel(label) {
		return
	}

	n := s.names
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failed || n.count >= maxNames || n.rooms[key][label] != "" {
		return
	}
	n.insert(key, label, id)
	records := make([]nameBinding, 0, n.count+1)
	for _, key := range slices.Sorted(maps.Keys(n.rooms)) {
		labels := n.rooms[key]
		for _, label := range slices.Sorted(maps.Keys(labels)) {
			records = append(records, nameBinding{Room: key, Label: label, Device: labels[label]})
		}
	}
	if err := saveStoreJSON(filepath.Join(s.dir, namesFile), ".names-", records, true); err != nil {
		// Rename may have succeeded before directory sync failed. Don't publish
		// either the old or new state until a restart loads it unambiguously.
		log.Printf("overlay DNS name bindings could not be saved: %v", err)
		n.failed = true
		return
	}
	n.count++
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
	if !validDNSLabel(label) {
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

func validDNSLabel(label string) bool {
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

func normalizedDNSLabel(name string) string {
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
	label, err := nameIDNA.ToASCII(strings.Trim(value.String(), "-"))
	if err != nil || !validDNSLabel(label) {
		return ""
	}
	return label
}
