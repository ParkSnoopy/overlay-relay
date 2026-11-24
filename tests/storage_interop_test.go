package tests

import (
	"context"
	"fmt"
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
		t.Skip("set OVERLAY_TEST_STORAGE_REFERENCE to a prior hub with room-local names")
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
	admin(reference, `{"start":"10.77.0.40","end":"10.77.0.40","lease_seconds":600,"bindings":[]}`, "dhcp", "set")
	identity := newAccount(t, "migration owner")
	id, _ := managementIdentity(t, identity)
	for _, step := range []struct {
		name, binary, advertise, effective, ip string
		labels                                 []string
	}{
		{"legacy", reference, "before", "before", "10.77.0.40", []string{"before"}},
		{"upgrade", current, "client", "after", "10.77.0.41", []string{"before", "custom"}},
		{"rollback", reference, "restored", "restored", "10.77.0.40", []string{"before", "custom", "restored"}},
		{"re-upgrade", current, "client", "after", "10.77.0.41", []string{"before", "custom", "restored"}},
	} {
		if step.name == "upgrade" {
			edit := fmt.Sprintf(`{"device_id":%q,"name":"after","binding":"10.77.0.41","domain":"custom.on.snoo"}`, id)
			admin(current, edit, "peers", "set")
		}
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
			state := waitFor(t, states, func(s overlay.State) bool { return s.Connected })
			if state.Name != step.effective || state.IP != step.ip {
				t.Fatalf("wrong peer state after %s: %+v", step.name, state)
			}
			if step.binary == current && state.Domain != "custom.on.snoo" {
				t.Fatalf("wrong domain after %s: %q", step.name, state.Domain)
			}
			for _, label := range step.labels {
				if ip, err := peer.LookupName(ctx, label); err != nil || ip.String() != step.ip {
					t.Fatalf("lookup %q after %s: %s, %v", label, step.name, ip, err)
				}
			}
		}) {
			return
		}
	}
}
