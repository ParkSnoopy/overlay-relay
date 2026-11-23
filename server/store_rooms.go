package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const roomsFile = "rooms.json"

var (
	errRoomUnknown = errors.New("room does not exist")
	errRoomDenied  = errors.New("room password is incorrect")
)

type roomRecord struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Proof string `json:"proof"`
	Relay bool   `json:"relay"`
}

type listedRoom struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Relay bool   `json:"relay"`
}

type relayPolicy struct {
	Relay bool `json:"relay"`
}

type roomListing struct {
	PublicRelay bool                  `json:"public_relay"`
	Rooms       map[string]listedRoom `json:"rooms"`
}

type roomDocument map[string]json.RawMessage

func roomKey(id string) string {
	hash := sha256.Sum256([]byte(id))
	return hex.EncodeToString(hash[:])
}

// admitRoom returns the private room's display name, not its authenticated
// key. Empty credentials select public; a broken relay policy must not shut
// down public discovery and signaling.
func (s *hubStore) admitRoom(id, proof string) (displayName string, allowRelay bool, wireError string) {
	if id == "" && proof == "" {
		allow, _ := s.roomRelay("")
		return "", allow, ""
	}
	if id == "" || overlay.ValidateName(id) != nil || !validStoreID(proof) {
		return "", false, "unauthorized"
	}
	record, err := readAdmittedRoom(s.dir, roomKey(id), proof)
	switch {
	case errors.Is(err, errRoomUnknown), errors.Is(err, errRoomDenied):
		return "", false, err.Error()
	case err != nil:
		return "", false, "rooms are unavailable"
	default:
		return record.displayName(), record.Relay, ""
	}
}

// roomRelay re-reads the policy and revalidates the authenticated key:proof.
// The empty room is public. A failed read or a revoked proof never grants relay.
func (s *hubStore) roomRelay(room string) (bool, error) {
	if room == "" {
		records, err := loadRooms(s.dir)
		if err != nil {
			return false, err
		}
		return publicRoomRelay(records["public"])
	}
	key, proof, _ := strings.Cut(room, ":")
	record, err := readAdmittedRoom(s.dir, key, proof)
	return err == nil && record.Relay, err
}

func readAdmittedRoom(dir, key, proof string) (roomRecord, error) {
	if !validStoreID(key) || !validStoreID(proof) {
		return roomRecord{}, errRoomDenied
	}
	records, err := loadRooms(dir)
	if err != nil {
		return roomRecord{}, err
	}
	value, exists := records[key]
	if !exists {
		return roomRecord{}, errRoomUnknown
	}
	record, err := decodeRoom(key, value)
	if err != nil {
		return roomRecord{}, err
	}
	if subtle.ConstantTimeCompare([]byte(record.Proof), []byte(proof)) != 1 {
		return roomRecord{}, errRoomDenied
	}
	return record, nil
}

func loadRooms(dir string) (roomDocument, error) {
	data, err := readStoreFile(dir, roomsFile, 0)
	if err != nil {
		return nil, err
	}
	records := make(roomDocument)
	if data == nil {
		return records, nil
	}
	data = bytes.Trim(data, " 	\r\n")
	if len(data) > 0 && data[0] == '[' {
		var legacy []json.RawMessage
		if err := unmarshalStoreJSON(data, &legacy); err != nil {
			return nil, fmt.Errorf("overlay json is invalid: %w", err)
		}
		for _, value := range legacy {
			var key string
			if json.Unmarshal(value, &key) != nil || !validStoreID(key) {
				return nil, errors.New("legacy room key is not valid")
			}
			records[key] = json.RawMessage("null")
		}
		return records, nil
	}
	if err := unmarshalStoreJSON(data, &records); err != nil {
		return nil, fmt.Errorf("overlay json is invalid: %w", err)
	}
	if records == nil {
		return nil, errors.New("overlay json is invalid: expected a room object")
	}
	return records, nil
}

func decodeRoom(key string, raw []byte) (roomRecord, error) {
	record := roomRecord{Relay: true}
	if err := decodeStoreObject(raw, true, requiredField("id", &record.ID), requiredField("proof", &record.Proof),
		optionalField("name", &record.Name), optionalField("relay", &record.Relay)); err != nil {
		return roomRecord{}, fmt.Errorf("overlay json is invalid: %w", err)
	}
	if record.ID == "" || overlay.ValidateName(record.ID) != nil || overlay.ValidateName(record.Name) != nil ||
		!validStoreID(record.Proof) || roomKey(record.ID) != key {
		return roomRecord{}, errors.New("room record is not valid")
	}
	return record, nil
}

func (r roomRecord) displayName() string {
	if r.Name == "" {
		return r.ID
	}
	return r.Name
}

func publicRoomRelay(raw []byte) (bool, error) {
	if raw == nil {
		return true, nil
	}
	var policy relayPolicy
	if err := decodeStoreObject(raw, false, requiredField("relay", &policy.Relay)); err != nil {
		return false, fmt.Errorf("overlay json is invalid: %w", err)
	}
	return policy.Relay, nil
}

func listRooms(dir string) (roomListing, error) {
	records, err := loadRooms(dir)
	if err != nil {
		return roomListing{}, err
	}
	publicRelay, err := publicRoomRelay(records["public"])
	if err != nil {
		return roomListing{}, err
	}
	listing := roomListing{PublicRelay: publicRelay, Rooms: make(map[string]listedRoom)}
	for key, raw := range records {
		if key == "public" {
			continue
		}
		record, err := decodeRoom(key, raw)
		if err != nil {
			listing.Rooms[key] = listedRoom{Name: "Invalid room record — replace or remove"}
			continue
		}
		listing.Rooms[key] = listedRoom{ID: record.ID, Name: record.displayName(), Relay: record.Relay}
	}
	return listing, nil
}

func configureRoom(dir, id, name, proof string, replace bool, relay *bool) error {
	if id == "" || overlay.ValidateName(id) != nil {
		return errors.New("room ID is not valid")
	}
	if overlay.ValidateName(name) != nil {
		return errors.New("room name is not valid")
	}
	if !validStoreID(proof) {
		return errors.New("room password proof is not valid")
	}
	records, err := loadRooms(dir)
	if err != nil {
		return err
	}
	key := roomKey(id)
	old, exists := records[key]
	if exists && !replace {
		return errors.New("room already exists")
	}
	if !exists && replace {
		return errors.New("room is unknown")
	}
	var previous map[string]json.RawMessage
	var previousRelay *bool
	if relay == nil && json.Unmarshal(old, &previous) == nil {
		// Keep a known relay flag even when the rest of the old record is bad.
		if err := json.Unmarshal(previous["relay"], &previousRelay); err != nil {
			previousRelay = nil
		}
	}
	if relay == nil {
		relay = previousRelay
	}
	record := roomRecord{ID: id, Name: name, Proof: proof, Relay: relay == nil || *relay}
	return saveRoomRecord(dir, records, key, record)
}

func setRoomRelay(dir, key string, relay bool) error {
	if key != "public" && !validStoreID(key) {
		return errors.New("room is not a valid key")
	}
	records, err := loadRooms(dir)
	if err != nil {
		return err
	}
	if key == "public" {
		return saveRoomRecord(dir, records, key, relayPolicy{Relay: relay})
	}
	raw, exists := records[key]
	if !exists {
		return errors.New("room is unknown")
	}
	record, err := decodeRoom(key, raw)
	if err != nil {
		return err
	}
	record.Relay = relay
	return saveRoomRecord(dir, records, key, record)
}

func removeRoom(dir, key string) error {
	if !validStoreID(key) {
		return errors.New("room is not a valid key")
	}
	records, err := loadRooms(dir)
	if err != nil {
		return err
	}
	if _, exists := records[key]; !exists {
		return errors.New("room is unknown")
	}
	delete(records, key)
	return saveStoreJSON(filepath.Join(dir, roomsFile), ".rooms-", records, false)
}

func saveRoomRecord(dir string, rooms roomDocument, key string, record any) error {
	var raw bytes.Buffer
	if err := writeStoreJSON(&raw, record); err != nil {
		return err
	}
	rooms[key] = raw.Bytes()
	return saveStoreJSON(filepath.Join(dir, roomsFile), ".rooms-", rooms, false)
}
