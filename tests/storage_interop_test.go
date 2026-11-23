package tests

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"github.com/ParkSnoopy/overlay-relay/client/overlayagent"
)

// Run both implementations in turn on the same directory. The rollback must
// see the name first claimed by the Go hub, not just survive its new JSON.
func TestHubStorageUpgradeAndRollback(t *testing.T) {
	reference := os.Getenv("OVERLAY_TEST_STORAGE_REFERENCE")
	if reference == "" {
		t.Skip("set OVERLAY_TEST_STORAGE_REFERENCE to the last Rust hub with room-local names")
	}
	current, dir := buildHub(t), t.TempDir()
	const roomID = "migration"
	proof, err := overlay.RoomToken(roomID, "fixture password")
	if err != nil {
		t.Fatal(err)
	}
	admin := func(binary, input string, args ...string) {
		t.Helper()
		cmd := exec.Command(binary, append([]string{"--data-dir", dir}, args...)...)
		cmd.Stdin = strings.NewReader(input)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", args[0], err, out)
		}
	}
	admin(reference, "", "rooms", "create", roomID, "Migration", proof, "false")
	admin(reference, `{"start":"10.77.0.40","end":"10.77.0.42","lease_seconds":600,"bindings":[]}`, "dhcp", "set")
	identity := newAccount(t, "migration owner")
	for _, step := range []struct {
		name, binary, advertise string
		labels                  []string
	}{
		{"rust", reference, "before", []string{"before"}},
		{"upgrade", current, "after", []string{"before", "after"}},
		{"rollback", reference, "restored", []string{"before", "after", "restored"}},
	} {
		if !t.Run(step.name, func(t *testing.T) {
			hub := startHub(t, step.binary, "OVERLAY_DATA_DIR="+dir)
			states := make(chan overlay.State, 16)
			peer := newAgent(t, hub.address, identity, states, nil, func(c *overlayagent.Config) {
				c.RoomID, c.Room, c.Name = roomID, proof, step.advertise
			})
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- peer.Run(ctx) }()
			defer func() { cancel(); <-done }()
			waitFor(t, states, func(s overlay.State) bool { return s.Connected })
			for _, label := range step.labels {
				if ip, err := peer.LookupName(ctx, label); err != nil || ip != netip.MustParseAddr("10.77.0.40") {
					t.Fatalf("lookup %q after %s: %s, %v", label, step.name, ip, err)
				}
			}
		}) {
			return
		}
	}
}
