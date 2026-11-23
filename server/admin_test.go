package main

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

func TestHubAllowedHostsDropsEmptyEntries(t *testing.T) {
	if !reflect.DeepEqual(allowedHosts("engine,,other,"), []string{"engine", "other"}) || len(allowedHosts("")) != 0 {
		t.Fatal("allow list did not drop empty entries")
	}
	if got := allowedHosts("engine, literal space"); !reflect.DeepEqual(got, []string{"engine", " literal space"}) {
		t.Fatalf("allow list changed a literal value: %v", got)
	}
}

func hubCLITest(t *testing.T, env map[string]string, input string, args ...string) (status int, out, diagnostic string) {
	t.Helper()
	lookup := func(key string) (string, bool) {
		value, ok := env[key]
		return value, ok
	}
	var stdout, stderr bytes.Buffer
	code := runHubCLI(t.Context(), args, lookup, strings.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestHubCLIOptionsAndHelp(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"OVERLAY_DATA_DIR": "/default", "OVERLAY_ALLOWED_HOST": "engine,,other", "OVERLAY_LISTEN_ADDRESS": "127.0.0.1:0", "OVERLAY_CIDR": "172.20.0.0/24",
	}
	lookup := func(key string) (string, bool) { value, ok := env[key]; return value, ok }
	options, response := parseHubCLI(nil, lookup)
	if response != nil || options.directory != "/default" || options.hosts != "engine,,other" || options.listen != "127.0.0.1:0" || options.space.String() != "172.20.0.0/24" || options.command != "" {
		t.Fatalf("environment overrides not applied: %+v, %+v", options, response)
	}
	options, response = parseHubCLI([]string{"--data-dir", "/override", "--cidr=10.80.0.0/24", "--allowed-host=one", "--listen-address", "127.0.0.2:0", "dhcp", "--data-dir", "/middle", "show", "--data-dir=/last"}, lookup)
	if response != nil || options.directory != "/last" || options.hosts != "one" || options.listen != "127.0.0.2:0" || options.space.String() != "10.80.0.0/24" || options.command != "dhcp show" {
		t.Fatalf("flag overrides not applied: %+v, %+v", options, response)
	}
	for _, flag := range []string{"--version", "-V"} {
		code, out, err := hubCLITest(t, nil, "", flag)
		if want := fmt.Sprintf("overlay-hub %s (protocol v%d)\n", overlay.ReleaseVersion, overlay.Version); code != 0 || out != want || err != "" {
			t.Fatalf("version = (%d, %q, %q); want %q", code, out, err, want)
		}
	}
	code, out, err := hubCLITest(t, env, "", "help", "rooms", "replace")
	if code != 0 || err != "" || !strings.Contains(out, "overlay-hub rooms replace [OPTIONS] --confirm <ID> <NAME> <PROOF> [RELAY]") || !strings.Contains(out, "[env: OVERLAY_DATA_DIR=/default]") {
		t.Fatalf("help = (%d, %q, %q)", code, out, err)
	}
	for _, invalid := range [][]string{{"--cidr="}, {"dhcp", "show", "--cidr", "10.80.0.0/24"}, {"rooms", "relay", "public", "True"}, {"rooms"}, {"dhcp", "show", "--version"}, {"--data-dir", "--help"}} {
		if code, out, err := hubCLITest(t, env, "", invalid...); code != 2 || out != "" || err == "" || strings.ContainsRune(err, '\x1b') {
			t.Fatalf("usage failure %v = (%d, %q, %q)", invalid, code, out, err)
		}
	}
}

func TestHubCLIAdminCommandsAndMachineErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	env := map[string]string{"OVERLAY_DATA_DIR": dir, "OVERLAY_CIDR": "10.77.0.0/30"}
	proof, next := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	key := roomKey("DUMMY")
	call := func(wantCode int, wantOut, wantErr, input string, args ...string) {
		t.Helper()
		code, out, err := hubCLITest(t, env, input, args...)
		if code != wantCode || out != wantOut || !strings.Contains(err, wantErr) || (wantErr == "" && err != "") || strings.ContainsRune(err, '\x1b') || strings.Contains(err, proof) || strings.Contains(err, next) {
			t.Fatalf("command %q = (%d, %q, %q)", args[:2], code, out, err)
		}
	}
	call(0, "{\"start\":\"10.77.0.1\",\"end\":\"10.77.0.2\",\"lease_seconds\":0,\"bindings\":[]}\n", "", "", "dhcp", "show")
	policy := `{"start":"10.77.0.1","end":"10.77.0.2","lease_seconds":60,"bindings":[]}`
	call(0, "", "", policy, "dhcp", "set")
	call(0, "{\"devices\":{},\"policy\":"+policy+"}\n", "", "", "dhcp", "editor")
	call(1, "", "DHCP lease must be 0 or 60 through 31536000 seconds", strings.Replace(policy, ":60", ":1", 1), "dhcp", "set")
	call(1, "", "DHCP policy is too large", strings.Repeat(" ", maxDHCPBytes*2), "dhcp", "set")
	call(0, "", "", "", "rooms", "create", "DUMMY", "Old", proof, "false", "--data-dir", dir)
	call(1, "", "room already exists", "", "rooms", "create", "DUMMY", "New", next)
	call(2, "", "--confirm", "", "rooms", "replace", "DUMMY", "New", next)
	call(0, "", "", "", "rooms", "replace", "DUMMY", "New", next, "--confirm")
	call(0, "", "", "", "rooms", "relay", "public", "false")
	call(0, fmt.Sprintf("{\"public_relay\":false,\"rooms\":{%q:{\"id\":\"DUMMY\",\"name\":\"New\",\"relay\":false}}}\n", key), "", "", "rooms", "list")
	call(1, "", "room is not a valid key", "", "rooms", "remove", "DUMMY")
	call(0, "", "", "", "rooms", "remove", key)
	call(0, "{\"public_relay\":false,\"rooms\":{}}\n", "", "", "rooms", "list")
}

func TestHubCLIStartRejectsCorruptAssignments(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	storeFixture(t, dir, assignmentsFile, "bad")
	var stderr bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	code := runHubCLI(ctx, []string{"--data-dir", dir, "--listen-address", "127.0.0.1:0"}, func(string) (string, bool) { return "", false }, nil, nil, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "overlay address assignments are corrupt") {
		t.Fatalf("startup with corrupt assignments = (%d, %q)", code, stderr.String())
	}
}
