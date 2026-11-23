package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func checkRoomAdmission(t *testing.T, s *hubStore, id, proof, name string, relay bool, failure string) {
	t.Helper()
	gotName, gotRelay, gotFailure := s.admitRoom(id, proof)
	if gotName != name || gotRelay != relay || gotFailure != failure {
		t.Fatalf("admission = (%q, %t, %q); want (%q, %t, %q)", gotName, gotRelay, gotFailure, name, relay, failure)
	}
}

func TestHubRoomsRequireAnOperatorAndTheCurrentProof(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := testStore(t, dir, storeTestSpace)
	old, next := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	key := roomKey("DUMMY room")
	if !validStoreID(key) || validStoreID(strings.ToUpper(old)) || validStoreID("ab") {
		t.Fatal("room keys and proofs must be 64 lowercase hexadecimal digits")
	}
	checkRoomAdmission(t, s, "", "", "", true, "")
	checkRoomAdmission(t, s, "DUMMY room", old, "", false, "room does not exist")
	for _, bad := range []struct{ id, name, proof string }{{"", "name", old}, {"id", "bad\nname", old}, {"id", "name", "short"}, {"id", "name", strings.ToUpper(old)}} {
		if err := configureRoom(dir, bad.id, bad.name, bad.proof, false, nil); err == nil {
			t.Fatal("invalid room created")
		}
	}
	storeCheck(t, configureRoom(dir, "DUMMY room", "", old, false, nil))
	storePrivateMode(t, dir, roomsFile)
	checkRoomAdmission(t, s, "DUMMY room", old, "DUMMY room", true, "")
	checkRoomAdmission(t, s, "DUMMY room", next, "", false, "room password is incorrect")
	listing, err := listRooms(dir)
	storeCheck(t, err)
	if got := listing.Rooms[key]; got.ID != "DUMMY room" || got.Name != "DUMMY room" || !got.Relay {
		t.Fatalf("unnamed listing did not fall back to ID: %+v", got)
	}
	if err := removeRoom(dir, "nope"); err == nil {
		t.Fatal("removed a malformed key")
	}
	storeCheck(t, setRoomRelay(dir, key, false))
	checkRoomAdmission(t, s, "DUMMY room", old, "DUMMY room", false, "")
	storeCheck(t, setRoomRelay(dir, "public", false))
	checkRoomAdmission(t, s, "", "", "", false, "")
	storeCheck(t, configureRoom(dir, "DUMMY room", "Renamed", next, true, nil))
	checkRoomAdmission(t, s, "DUMMY room", next, "Renamed", false, "")
	if allowed, err := s.roomRelay(key + ":" + old); allowed || !errors.Is(err, errRoomDenied) {
		t.Fatalf("relay did not revalidate rotated proof: %t, %v", allowed, err)
	}
	storeCheck(t, setRoomRelay(dir, key, true))
	if allowed, err := s.roomRelay(key + ":" + next); !allowed || err != nil {
		t.Fatalf("current proof was refused relay: %t, %v", allowed, err)
	}
	storeCheck(t, removeRoom(dir, key))
	if err := removeRoom(dir, key); err == nil || err.Error() != "room is unknown" {
		t.Fatalf("removed room still known: %v", err)
	}
	checkRoomAdmission(t, s, "DUMMY room", next, "", false, "room does not exist")
}

func TestHubRoomsLegacyRepairPreservesUnrelatedRecords(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := testStore(t, dir, storeTestSpace)
	old, next := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	legacyKey, otherKey := roomKey("DUMMY"), roomKey("OTHER")
	storeFixture(t, dir, roomsFile, fmt.Sprintf(`[%q]`, legacyKey))
	checkRoomAdmission(t, s, "DUMMY", old, "", false, "rooms are unavailable")
	storeCheck(t, configureRoom(dir, "OTHER", "Other", old, false, nil))
	listing, err := listRooms(dir)
	storeCheck(t, err)
	if len(listing.Rooms) != 2 || listing.Rooms[legacyKey].Name != "Invalid room record — replace or remove" {
		t.Fatalf("legacy key disappeared or enabled membership: %+v", listing)
	}
	storeFixture(t, dir, roomsFile, fmt.Sprintf(`{%q:{"legacy":true,"relay":false},%q:{"id":"OTHER","name":"Other","proof":%q,"extra":{"x":true}},"public":{"relay":false}}`, legacyKey, otherKey, old))
	checkRoomAdmission(t, s, "OTHER", old, "Other", true, "")
	checkRoomAdmission(t, s, "DUMMY", old, "", false, "rooms are unavailable")
	original := storeFile(t, dir, roomsFile)
	if err := configureRoom(dir, "DUMMY", "New", next, false, nil); err == nil || err.Error() != "room already exists" {
		t.Fatalf("create overwrote an existing broken room: %v", err)
	}
	if err := configureRoom(dir, "MISSING", "New", next, true, nil); err == nil || err.Error() != "room is unknown" {
		t.Fatalf("replace created an unknown room: %v", err)
	}
	if err := configureRoom(dir, "DUMMY", "New", "invalid", true, nil); err == nil {
		t.Fatal("accepted invalid proof on replacement")
	}
	if !bytes.Equal(original, storeFile(t, dir, roomsFile)) {
		t.Fatal("invalid room edits changed the persisted room table")
	}
	storeCheck(t, configureRoom(dir, "DUMMY", "Repaired", next, true, nil))
	checkRoomAdmission(t, s, "DUMMY", next, "Repaired", false, "")
	checkRoomAdmission(t, s, "OTHER", old, "Other", true, "")
	checkRoomAdmission(t, s, "", "", "", false, "")
	if !bytes.Contains(storeFile(t, dir, roomsFile), []byte(`"extra":{"x":true}`)) {
		t.Fatal("rewriting one room lost fields of an unrelated record")
	}
}

func TestHubRoomsFailClosedOnCorruption(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := testStore(t, dir, storeTestSpace)
	proof := strings.Repeat("ab", 32)
	for _, invalid := range []string{`{"public":{"relay":null}}`, `{"public":{"relay":true,"extra":false}}`, `{"public":null}`} {
		storeFixture(t, dir, roomsFile, invalid)
		checkRoomAdmission(t, s, "", "", "", false, "")
		if allowed, err := s.roomRelay(""); allowed || err == nil {
			t.Fatalf("allowed relay with invalid public config %s", invalid)
		}
	}
	for _, invalid := range []string{`null`, `{"truncated":`, `["short"]`} {
		storeFixture(t, dir, roomsFile, invalid)
		checkRoomAdmission(t, s, "DUMMY", proof, "", false, "rooms are unavailable")
		if err := configureRoom(dir, "DUMMY", "name", proof, false, nil); err == nil {
			t.Fatal("overwrote corrupt room storage")
		}
	}
}
