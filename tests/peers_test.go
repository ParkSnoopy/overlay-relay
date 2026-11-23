package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"github.com/ParkSnoopy/overlay-relay/client/overlayagent"
)

type managedPeer struct {
	Name         string `json:"name"`
	NameOverride string `json:"name_override"`
	IP           string `json:"ip"`
	Binding      string `json:"binding"`
}

func managementIdentity(t *testing.T, peer account) (id, public string) {
	t.Helper()
	public, err := overlay.PublicIdentity(peer.key)
	if err != nil {
		t.Fatal(err)
	}
	id, err = overlay.IdentityID(public)
	if err != nil {
		t.Fatal(err)
	}
	return id, public
}

func TestPeerCLIAndGoHub(t *testing.T) {
	binary, dir := buildHub(t), t.TempDir()

	const cidr = "10.77.0.0/29"
	alice, bob, never := newAccount(t, "Alice"), newAccount(t, "Bob"), newAccount(t, "Never registered")
	aliceID, _ := managementIdentity(t, alice)
	bobID, _ := managementIdentity(t, bob)
	neverID, neverKey := managementIdentity(t, never)
	call := func(input string, args ...string) (string, error) {
		cmd := exec.CommandContext(t.Context(), binary, append([]string{"--cidr", cidr, "--data-dir", dir}, args...)...)
		cmd.Stdin = strings.NewReader(input)
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	readFile := func(name string) []byte {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	list := func(id string, want managedPeer) {
		t.Helper()
		out, err := call("", "peers", "list")
		if err != nil {
			t.Fatalf("peers list: %v %s", err, out)
		}
		var listing struct {
			Devices map[string]managedPeer `json:"devices"`
		}
		if err := json.Unmarshal([]byte(out), &listing); err != nil || listing.Devices[id] != want {
			t.Fatalf("peers list = %s, %v; missing %s with %+v", out, err, id, want)
		}
		// Do not allow omitted zero-valued fields to pass the Go decode above.
		var fields struct {
			Devices map[string]map[string]json.RawMessage `json:"devices"`
		}
		if err := json.Unmarshal([]byte(out), &fields); err != nil || len(fields.Devices[id]) != 4 || fields.Devices[id]["name_override"] == nil {
			t.Fatalf("unexpected peer JSON: %s", out)
		}
	}
	editJSON := func(id, name, binding string) string {
		return fmt.Sprintf(`{"device_id":%q,"name":%q,"binding":%q}`, id, name, binding)
	}
	set := func(id, name, binding string) {
		t.Helper()
		if out, err := call(editJSON(id, name, binding), "peers", "set"); err != nil || out != "" {
			t.Fatalf("peers set: %v %s", err, out)
		}
	}
	if out, err := call("", "peers", "list"); err != nil || out != "{\"devices\":{}}\n" {
		t.Fatalf("empty peers list: %v %q", err, out)
	}
	legacy := fmt.Sprintf(`{"start":"10.77.0.1","end":"10.77.0.1","lease_seconds":0,"bindings":[{"public_key":%q,"ip":"10.77.0.6"}]}`, neverKey)
	if out, err := call(legacy, "dhcp", "set"); err != nil {
		t.Fatalf("legacy policy: %v %s", err, out)
	}
	list(neverID, managedPeer{IP: "10.77.0.6", Binding: "10.77.0.6"})
	set(neverID, "Offline", "10.77.0.6")
	list(neverID, managedPeer{Name: "Offline", NameOverride: "Offline", IP: "10.77.0.6", Binding: "10.77.0.6"})
	set(neverID, "", "")
	list(neverID, managedPeer{})
	set(neverID, "Offline", "10.77.0.6")

	checkHub := func(t *testing.T, advertised, name, label, ip string, aliases ...string) {
		t.Helper()
		// A container gets a fresh private runtime mount on every start.
		socketDir, err := os.MkdirTemp("", "peer-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
		t.Setenv("OVERLAY_PEER_SOCKET", filepath.Join(socketDir, "p"))
		hub := startHub(t, binary, "OVERLAY_DATA_DIR="+dir, "OVERLAY_CIDR="+cidr)
		start := func(peer account, name string) (*overlayagent.Agent, <-chan overlay.State, context.CancelFunc) {
			t.Helper()
			states := make(chan overlay.State, 16)
			agent := newAgent(t, hub.address, peer, states, nil, func(c *overlayagent.Config) {
				c.CIDR, c.Name = netip.MustParsePrefix(cidr), name
			})
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- agent.Run(ctx) }()
			t.Cleanup(func() { cancel(); <-done })
			return agent, states, cancel
		}
		_, aliceStates, stopAlice := start(alice, advertised)
		seen := waitFor(t, aliceStates, func(state overlay.State) bool { return state.Connected })
		if seen.Name != name || seen.Domain != label+".on.snoo" || seen.IP != ip {
			t.Fatalf("wrong owner registration: %+v", seen)
		}
		watcher, bobStates, _ := start(bob, "Bob")
		seen = waitFor(t, bobStates, func(state overlay.State) bool { return state.Connected && len(state.Peers) == 1 })
		if peer := seen.Peers[0]; seen.IP != "10.77.0.2" || peer.ID != aliceID || peer.Name != name || peer.Domain != label+".on.snoo" || peer.IP != ip {
			t.Fatalf("wrong address or peer roster: %+v", seen)
		}
		for _, lookup := range append(aliases, label) {
			if address, err := watcher.LookupName(t.Context(), lookup); err != nil || address.String() != ip {
				t.Fatalf("DNS %s = %s, %v; want %s", lookup, address, err, ip)
			}
		}
		live := func() map[string]managedPeer {
			out, err := call("", "peers", "connected")
			var roster struct{ Devices map[string]managedPeer }
			if err != nil || json.Unmarshal([]byte(out), &roster) != nil {
				t.Fatalf("live roster: %s (%v)", out, err)
			}
			return roster.Devices
		}
		if peers := live(); len(peers) != 2 || peers[aliceID].Name != name || peers[aliceID].IP != ip || peers[bobID].Name != "Bob" {
			t.Fatalf("unexpected online peers: %+v", peers)
		}
		edit := editJSON(aliceID, "Office Desk", "")
		if out, err := call(edit, "peers", "check-connected"); err != nil {
			t.Fatalf("online edit refused: %s", out)
		}
		stopAlice()
		deadline := time.Now().Add(3 * time.Second)
		for len(live()) != 1 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if out, err := call(edit, "peers", "check-connected"); err == nil || !strings.Contains(out, "no longer connected") {
			t.Fatalf("stale edit not rejected: %s", out)
		}
	}
	if !t.Run("automatic pool", func(t *testing.T) {
		checkHub(t, "Alice", "Alice", "alice", "10.77.0.1")
	}) {
		return
	}
	list(bobID, managedPeer{Name: "Bob", IP: "10.77.0.2"})
	ips, names, dhcp := readFile("ips.json"), readFile("names.json"), readFile("dhcp.json")
	set(aliceID, "Office Desk", "10.77.0.5")
	list(aliceID, managedPeer{Name: "Office Desk", NameOverride: "Office Desk", IP: "10.77.0.5", Binding: "10.77.0.5"})
	if !bytes.Equal(ips, readFile("ips.json")) || !bytes.Equal(names, readFile("names.json")) || !bytes.Equal(dhcp, readFile("dhcp.json")) {
		t.Fatal("peer command rewrote legacy state or durable DNS ownership")
	}
	if info, err := os.Stat(filepath.Join(dir, "peers.json")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("peer settings are not private")
	}
	saved := readFile("peers.json")
	for _, bad := range []string{
		`null`, `[]`, `{"device_id":"missing","name":"","binding":""}`,
		fmt.Sprintf(`{"device_id":%q,"name":"","name":"duplicate","binding":""}`, aliceID),
		fmt.Sprintf(`{"device_id":%q,"name":"","binding":null}`, aliceID),
		fmt.Sprintf(`{"device_id":%q,"name":""}`, aliceID),
		fmt.Sprintf(`{"device_id":%q,"name":"","binding":"","extra":1}`, aliceID),
		editJSON(aliceID, "", "") + `{}`,
		editJSON(strings.Repeat("0", 64), "", ""),
		editJSON(aliceID, " Alice", ""), editJSON(aliceID, strings.Repeat("é", 129), ""),
		editJSON(aliceID, "", "10.77.0.0"), editJSON(aliceID, "", "10.77.0.7"),
		editJSON(aliceID, "", "10.78.0.1"), editJSON(aliceID, "", "::ffff:10.77.0.3"),
		editJSON(aliceID, "", "10.77.0.02"), editJSON(aliceID, "", "10.77.0.2"),
		editJSON(aliceID, "", "10.77.0.6"), strings.Repeat(" ", 4097),
	} {
		if out, err := call(bad, "peers", "set"); err == nil || !bytes.Equal(saved, readFile("peers.json")) {
			t.Fatalf("invalid edit accepted or mutated disk (input length %d): %v %s", len(bad), err, out)
		}
	}
	if !t.Run("restart with override", func(t *testing.T) {
		checkHub(t, "Laptop", "Office Desk", "office-desk", "10.77.0.5", "alice")
	}) {
		return
	}
	set(aliceID, "", "")
	list(aliceID, managedPeer{Name: "Laptop", IP: "10.77.0.5"})
	list(bobID, managedPeer{Name: "Bob", IP: "10.77.0.2"})
	t.Run("restart after clear", func(t *testing.T) {
		checkHub(t, "New Laptop", "New Laptop", "new-laptop", "10.77.0.5", "alice", "office-desk")
	})
}
