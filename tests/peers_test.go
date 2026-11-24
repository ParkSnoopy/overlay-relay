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
	Name           string `json:"name"`
	NameOverride   string `json:"name_override"`
	IP             string `json:"ip"`
	Binding        string `json:"binding"`
	DomainOverride string `json:"domain_override"`
	Domain         string `json:"domain"`
	Connected      bool   `json:"connected"`
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
		if err := json.Unmarshal([]byte(out), &fields); err != nil || len(fields.Devices[id]) != 6 || fields.Devices[id]["name_override"] == nil || fields.Devices[id]["domain_override"] == nil {
			t.Fatalf("unexpected peer JSON: %s", out)
		}
	}
	editJSON := func(id, name, binding string) string {
		return fmt.Sprintf(`{"device_id":%q,"name":%q,"binding":%q}`, id, name, binding)
	}
	set := func(id, name, binding string, domain ...string) {
		t.Helper()
		input := editJSON(id, name, binding)
		if len(domain) != 0 {
			input = strings.TrimSuffix(input, "}") + fmt.Sprintf(`,"domain":%q}`, domain[0])
		}
		if out, err := call(input, "peers", "set"); err != nil || out != "" {
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

	checkHub := func(t *testing.T, advertised, custom, name, label, ip string, aliases ...string) {
		t.Helper()
		// A container gets a fresh private runtime mount on every start.
		socketDir, err := os.MkdirTemp("", "peer-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
		t.Setenv("OVERLAY_PEER_SOCKET", filepath.Join(socketDir, "p"))
		hub := startHub(t, binary, "OVERLAY_DATA_DIR="+dir, "OVERLAY_CIDR="+cidr)
		start := func(peer account, name, domain string) (*overlayagent.Agent, <-chan overlay.State, context.CancelFunc) {
			t.Helper()
			states := make(chan overlay.State, 16)
			agent := newAgent(t, hub.address, peer, states, nil, func(c *overlayagent.Config) {
				c.CIDR, c.Name = netip.MustParsePrefix(cidr), name
				c.Domain = domain
			})
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- agent.Run(ctx) }()
			t.Cleanup(func() { cancel(); <-done })
			return agent, states, cancel
		}
		_, aliceStates, stopAlice := start(alice, advertised, custom)
		seen := waitFor(t, aliceStates, func(state overlay.State) bool { return state.Connected })
		if seen.Name != name || seen.Domain != label+".on.snoo" || seen.IP != ip {
			t.Fatalf("wrong owner registration: %+v", seen)
		}
		watcher, bobStates, _ := start(bob, "Bob", "")
		seen = waitFor(t, bobStates, func(state overlay.State) bool { return state.Connected && len(state.Peers) == 1 })
		if peer := seen.Peers[0]; seen.IP != "10.77.0.2" || peer.ID != aliceID || peer.Name != name || peer.Domain != label+".on.snoo" || peer.IP != ip {
			t.Fatalf("wrong address or peer roster: %+v", seen)
		}
		for _, lookup := range append(aliases, label) {
			if address, err := watcher.LookupName(t.Context(), lookup); err != nil || address.String() != ip {
				t.Fatalf("DNS %s = %s, %v; want %s", lookup, address, err, ip)
			}
		}
		roster := func(mode string) map[string]managedPeer {
			out, err := call("", "peers", mode)
			var roster struct {
				Devices map[string]managedPeer `json:"devices"`
			}
			if err != nil || json.Unmarshal([]byte(out), &roster) != nil {
				t.Fatalf("live roster: %s (%v)", out, err)
			}
			return roster.Devices
		}
		if peers := roster("connected"); len(peers) != 2 || !peers[aliceID].Connected || peers[aliceID].Name != name || peers[aliceID].IP != ip || peers[bobID].Name != "Bob" {
			t.Fatalf("unexpected online peers: %+v", peers)
		}
		if peers := roster("managed"); peers[aliceID].Domain != label+".on.snoo" || peers[neverID].Domain != "" {
			t.Fatalf("unexpected assigned peer domains: %+v", peers)
		}
		edit := editJSON(aliceID, "Office Desk", "")
		if out, err := call(edit, "peers", "check-connected"); err != nil {
			t.Fatalf("online edit refused: %s", out)
		}
		stopAlice()
		deadline := time.Now().Add(3 * time.Second)
		for len(roster("connected")) != 1 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if out, err := call(edit, "peers", "check-connected"); err == nil || !strings.Contains(out, "no longer connected") {
			t.Fatalf("stale edit not rejected: %s", out)
		}
		if peers := roster("managed"); len(peers) != 3 || peers[aliceID].Connected || peers[aliceID].Domain != "" || peers[aliceID].Name != name || !peers[bobID].Connected {
			t.Fatalf("unexpected managed peers after disconnect: %+v", peers)
		}
		if out, err := call(edit, "peers", "check-managed"); err != nil {
			t.Fatalf("cached edit refused: %s", out)
		}
	}
	if !t.Run("automatic pool", func(t *testing.T) {
		checkHub(t, "Alice", "", "Alice", "alice", "10.77.0.1")
	}) {
		return
	}
	list(bobID, managedPeer{Name: "Bob", IP: "10.77.0.2"})
	set(aliceID, "", "", "hub-alice.on.snoo")
	list(aliceID, managedPeer{Name: "Alice", IP: "10.77.0.1", DomainOverride: "hub-alice.on.snoo"})
	if !t.Run("hub domain without rename", func(t *testing.T) {
		checkHub(t, "Alice", "", "Alice", "hub-alice", "10.77.0.1", "alice")
	}) {
		return
	}
	ips, names, dhcp := readFile("ips.json"), readFile("names.json"), readFile("dhcp.json")
	set(aliceID, "Office Desk", "10.77.0.5", "")
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
		fmt.Sprintf(`{"device_id":%q,"name":"","binding":"","domain":null}`, aliceID),
		fmt.Sprintf(`{"device_id":%q,"name":"","binding":"","domain":"test.example"}`, aliceID),
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
		checkHub(t, "Laptop", "", "Office Desk", "office-desk", "10.77.0.5", "alice")
	}) {
		return
	}
	set(aliceID, "Office Desk", "10.77.0.5", "hub-alice.on.snoo")
	if !t.Run("device domain takes precedence", func(t *testing.T) {
		checkHub(t, "Laptop", "laptop.on.snoo", "Office Desk", "laptop", "10.77.0.5", "hub-alice")
	}) {
		return
	}
	set(aliceID, "", "", "")
	list(aliceID, managedPeer{Name: "Laptop", IP: "10.77.0.5"})
	list(bobID, managedPeer{Name: "Bob", IP: "10.77.0.2"})
	t.Run("restart after clear", func(t *testing.T) {
		checkHub(t, "New Laptop", "", "New Laptop", "new-laptop", "10.77.0.5", "alice", "office-desk")
	})
	set(aliceID, "Office Desk", "10.77.0.5", "office.on.snoo")
	t.Run("expiry on startup", func(t *testing.T) {
		old := time.Now().Add(-7 * 24 * time.Hour).Unix()
		assignments := fmt.Sprintf(`{%q:{"ip":"10.77.0.5","seen":%d,"name":"Laptop"},%q:{"ip":"10.77.0.2","seen":%d,"name":"Bob"}}`, aliceID, old, bobID, time.Now().Unix())
		if err := os.WriteFile(filepath.Join(dir, "ips.json"), []byte(assignments), 0o600); err != nil {
			t.Fatal(err)
		}
		cache := fmt.Sprintf(`{%q:{"seen":%d,"domain":"office.on.snoo"}}`, aliceID, old)
		if err := os.WriteFile(filepath.Join(dir, "peer-cache.json"), []byte(cache), 0o600); err != nil {
			t.Fatal(err)
		}
		startHub(t, binary, "OVERLAY_DATA_DIR="+dir, "OVERLAY_CIDR="+cidr)
		out, err := call("", "peers", "list")
		if err != nil || strings.Contains(out, aliceID) || !strings.Contains(out, bobID) {
			t.Fatalf("startup expiry did not remove only the stale peer: %v %s", err, out)
		}
		for _, file := range []string{"ips.json", "names.json", "peer-cache.json", "peers.json"} {
			if bytes.Contains(readFile(file), []byte(aliceID)) {
				t.Fatalf("expired peer remains in %s", file)
			}
		}
	})
}
