package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const (
	defaultDataDir = "/var/lib/overlay-relay"
	defaultListen  = "0.0.0.0:6697"
)

type hubCLIOptions struct {
	peerSocket string
	directory  string
	hosts      string
	listen     string
	space      netip.Prefix
	command    string
	args       []string
	relay      *bool
}

type hubCLIResponse struct {
	status int
	text   string
}

type cliPosition struct {
	label       string
	description string
	optional    bool
	boolean     bool
}

type hubCommand struct {
	name, description string
	children          []hubCommand
	positions         []cliPosition
	confirm           bool
}

var roomPositions = []cliPosition{
	{label: "ID", description: "Unique private-room identifier"},
	{label: "NAME", description: "Room display name"},
	{label: "PROOF", description: "Client-derived password proof, not the password itself"},
	{label: "RELAY", description: "Allow payload relay; omission preserves existing policy", optional: true, boolean: true},
}

var hubCommands = hubCommand{description: "Serve the overlay hub, or administer its persisted configuration", children: []hubCommand{
	{name: "dhcp", description: "Manage legacy lease and binding policy; restart after saving", children: []hubCommand{
		{name: "show", description: "Print the validated DHCP policy as JSON"},
		{name: "editor", description: "Print editable policy and known devices, using only device identifiers"},
		{name: "set", description: "Read and validate a complete JSON policy from standard input, then save atomically"},
	}},
	{name: "peers", description: "Manage known devices; stop the hub before saving and restart to apply", children: []hubCommand{
		{name: "list", description: "Print known devices, effective names, and address bindings as JSON"},
		{name: "managed", description: "List connected and cached devices with live presence"},
		{name: "check-managed", description: "Check the device in a proposed JSON edit has not expired"},
		{name: "connected", description: "List only devices with a live authenticated control session"},
		{name: "check-connected", description: "Check the device in a proposed JSON edit is still connected"},
		{name: "set", description: "Set one device's name, address binding, and optional domain override from JSON"},
	}},
	{name: "rooms", description: "Manage rooms without restarting the hub", children: []hubCommand{
		{name: "list", description: "Print public and private room policies as JSON"},
		{name: "create", description: "Create a private room, refusing an existing identifier", positions: roomPositions},
		{name: "replace", description: "Replace an existing room only with explicit confirmation", positions: roomPositions, confirm: true},
		{name: "relay", description: "Enable or disable payload relay; discovery and signaling stay available", positions: []cliPosition{
			{label: "ROOM", description: `"public" or the private room's hashed key`},
			{label: "RELAY", description: "Whether payload relay is allowed", boolean: true},
		}},
		{name: "remove", description: "Remove a private room by its hashed key", positions: []cliPosition{{label: "ROOM"}}},
	}},
}}

func cliEnv(lookup func(string) (string, bool), key, fallback string) string {
	if value, ok := lookup(key); ok {
		return value
	}
	return fallback
}

func parseHubCLI(args []string, env func(string) (string, bool)) (hubCLIOptions, *hubCLIResponse) {
	options := hubCLIOptions{
		peerSocket: cliEnv(env, "OVERLAY_PEER_SOCKET", ""),
		directory:  cliEnv(env, "OVERLAY_DATA_DIR", defaultDataDir),
		hosts:      cliEnv(env, "OVERLAY_ALLOWED_HOST", ""),
		listen:     cliEnv(env, "OVERLAY_LISTEN_ADDRESS", defaultListen),
		space:      overlay.CIDR,
	}
	command := &hubCommands
	var path []string
	seen := make(map[string]bool)
	var literal, confirmed, explicitCIDR bool
	fail := func(text string, usage bool) (hubCLIOptions, *hubCLIResponse) {
		if usage {
			text += "\n\nUsage: " + command.usage(path, true)
		}
		return hubCLIOptions{}, cliError(text)
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !literal && arg == "--" {
			literal = true
			continue
		}
		if !literal && strings.HasPrefix(arg, "-") && arg != "-" {
			name, value, hasValue := strings.Cut(arg, "=")
			if !hasValue && (name == "--help" || name == "-h") {
				return options, &hubCLIResponse{0, command.help(path, env)}
			}
			if !hasValue && len(path) == 0 && (name == "--version" || name == "-V") {
				return options, &hubCLIResponse{0, fmt.Sprintf("overlay-hub %s (protocol v%d)\n", overlay.ReleaseVersion, overlay.Version)}
			}
			if name == "--confirm" && command.confirm {
				if hasValue {
					return fail(fmt.Sprintf("unexpected value '%s' for '--confirm' found; no more were expected\n\nUsage: %s", value, command.usage(path, false)), false)
				}
				if confirmed {
					return fail("the argument '--confirm' cannot be used multiple times", true)
				}
				confirmed = true
				continue
			}
			var label string
			if name == "--data-dir" || (len(path) == 0 && (name == "--allowed-host" || name == "--listen-address" || name == "--cidr")) {
				label = name + " <" + strings.ToUpper(strings.ReplaceAll(name[2:], "-", "_")) + ">"
			} else {
				return fail(fmt.Sprintf("unexpected argument '%s' found", arg), true)
			}
			if seen[name] {
				return fail(fmt.Sprintf("the argument '%s' cannot be used multiple times", label), true)
			}
			seen[name] = true
			if !hasValue {
				if i+1 >= len(args) || (strings.HasPrefix(args[i+1], "-") && args[i+1] != "-") {
					return fail(fmt.Sprintf("a value is required for '%s' but none was supplied", label), false)
				}
				i++
				value = args[i]
			}
			switch name {
			case "--data-dir":
				if value == "" {
					return fail(fmt.Sprintf("a value is required for '%s' but none was supplied", label), false)
				}
				options.directory = value
			case "--allowed-host":
				options.hosts = value
			case "--listen-address":
				options.listen = value
			case "--cidr":
				space, err := parseHubCIDR(value)
				if err != nil {
					return fail(fmt.Sprintf("invalid value '%s' for '%s': %s", value, label, err), false)
				}
				options.space, explicitCIDR = space, true
			}
			continue
		}
		if len(command.children) != 0 {
			if arg == "help" && !literal {
				return options, command.subcommandHelp(path, args[i+1:], env)
			}
			child := command.child(arg)
			if literal || child == nil {
				return fail(fmt.Sprintf("unrecognized subcommand '%s'", arg), true)
			}
			path = append(path, arg)
			command = child
			clear(seen)
			continue
		}
		if len(options.args) == len(command.positions) {
			return fail(fmt.Sprintf("unexpected argument '%s' found", arg), true)
		}
		position := command.positions[len(options.args)]
		if position.boolean {
			if arg != "true" && arg != "false" {
				return fail(fmt.Sprintf("invalid value '%s' for '%s'\n  [possible values: true, false]", arg, position.token()), false)
			}
			value := arg == "true"
			options.relay = &value
		}
		options.args = append(options.args, arg)
	}
	if len(path) == 1 {
		return hubCLIOptions{}, &hubCLIResponse{2, command.help(path, env)}
	}
	if !explicitCIDR {
		if raw, supplied := env("OVERLAY_CIDR"); supplied {
			space, err := parseHubCIDR(raw)
			if err != nil {
				return fail(fmt.Sprintf("invalid value '%s' for '--cidr <CIDR>': %s", raw, err), false)
			}
			options.space = space
		}
	}
	if options.directory == "" {
		return fail("a value is required for '--data-dir <DATA_DIR>' but none was supplied", false)
	}
	var missing []string
	if command.confirm && !confirmed {
		missing = append(missing, "--confirm")
	}
	for _, position := range command.positions[len(options.args):] {
		if !position.optional {
			missing = append(missing, position.token())
		}
	}
	if len(missing) != 0 {
		return fail("the following required arguments were not provided:\n  "+strings.Join(missing, "\n  ")+"\n\nUsage: "+command.usage(path, false), false)
	}
	options.command = strings.Join(path, " ")
	return options, nil
}

func runHubAdmin(options *hubCLIOptions, stdin io.Reader, stdout io.Writer) error {
	dir, space, args := options.directory, options.space, options.args
	switch options.command {
	case "dhcp show":
		policy, err := loadDHCP(dir, space)
		if err != nil {
			return err
		}
		return writeStoreJSON(stdout, policy)
	case "dhcp editor":
		result, err := editDHCP(dir, space)
		if err != nil {
			return err
		}
		return writeStoreJSON(stdout, result)
	case "dhcp set":
		raw, err := io.ReadAll(io.LimitReader(stdin, maxDHCPBytes+1))
		if err != nil {
			return fmt.Errorf("overlay i/o failed: %w", err)
		}
		return saveDHCP(dir, space, raw)
	case "peers connected", "peers check-connected", "peers managed", "peers check-managed":
		peers, err := queryManagedPeers(options.peerSocket)
		if err != nil {
			return err
		}
		if options.command == "peers connected" {
			for id, peer := range peers.Devices {
				if !peer.Connected {
					delete(peers.Devices, id)
				}
			}
		}
		if options.command == "peers connected" || options.command == "peers managed" {
			return writeStoreJSON(stdout, peers)
		}
		raw, err := io.ReadAll(io.LimitReader(stdin, maxPeerEditBytes+1))
		var edit peerEditRequest
		if err != nil || len(raw) > maxPeerEditBytes || unmarshalStoreJSON(raw, &edit) != nil || edit.validate() != nil {
			return errors.New("invalid peer edit")
		}
		peer, ok := peers.Devices[edit.DeviceID]
		if options.command == "peers check-connected" && !peer.Connected {
			return errors.New("device is no longer connected")
		}
		if !ok {
			return errors.New("device is no longer known to this hub")
		}
		return nil
	case "peers list":
		result, err := listPeers(dir, space)
		if err != nil {
			return err
		}
		return writeStoreJSON(stdout, result)
	case "peers set":
		raw, err := io.ReadAll(io.LimitReader(stdin, maxPeerEditBytes+1))
		if err != nil {
			return fmt.Errorf("overlay i/o failed: %w", err)
		}
		return setPeer(dir, space, raw)
	case "rooms list":
		listing, err := listRooms(dir)
		if err != nil {
			return err
		}
		return writeStoreJSON(stdout, listing)
	case "rooms create", "rooms replace":
		return configureRoom(dir, args[0], args[1], args[2], options.command == "rooms replace", options.relay)
	case "rooms relay":
		return setRoomRelay(dir, args[0], *options.relay)
	case "rooms remove":
		return removeRoom(dir, args[0])
	default:
		return errors.New("unknown administration command")
	}
}
