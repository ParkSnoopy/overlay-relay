package main

import (
	"fmt"
	"strings"
)

func cliError(text string) *hubCLIResponse {
	return &hubCLIResponse{2, "error: " + text + "\n\nFor more information, try '--help'.\n"}
}

func (p cliPosition) token() string {
	if p.optional {
		return "[" + p.label + "]"
	}
	return "<" + p.label + ">"
}

func (c *hubCommand) child(name string) *hubCommand {
	for i := range c.children {
		if c.children[i].name == name {
			return &c.children[i]
		}
	}
	return nil
}

func (c *hubCommand) usage(path []string, options bool) string {
	parts := append([]string{"overlay-hub"}, path...)
	if options {
		parts = append(parts, "[OPTIONS]")
	}
	if len(path) == 0 {
		parts = append(parts, "[COMMAND]")
	} else if len(c.children) != 0 {
		parts = append(parts, "<COMMAND>")
	}
	if c.confirm {
		parts = append(parts, "--confirm")
	}
	for _, position := range c.positions {
		parts = append(parts, position.token())
	}
	return strings.Join(parts, " ")
}

func (c *hubCommand) subcommandHelp(path, names []string, env func(string) (string, bool)) *hubCLIResponse {
	for _, name := range names {
		child := c.child(name)
		if child == nil {
			return cliError(fmt.Sprintf("unrecognized subcommand '%s'\n\nUsage: %s", name, c.usage(path, true)))
		}
		c = child
		path = append(path, name)
	}
	return &hubCLIResponse{0, c.help(path, env)}
}

func (c *hubCommand) help(path []string, env func(string) (string, bool)) string {
	var out strings.Builder
	fmt.Fprintf(&out, "%s\n\nUsage: %s\n", c.description, c.usage(path, true))
	if len(c.children) != 0 {
		out.WriteString("\nCommands:\n")
		width := len("help")
		for _, child := range c.children {
			width = max(width, len(child.name))
		}
		for _, child := range c.children {
			fmt.Fprintf(&out, "  %-*s  %s\n", width, child.name, child.description)
		}
		fmt.Fprintf(&out, "  %-*s  Print this message or the help of the given subcommand(s)\n", width, "help")
	}
	if len(c.positions) != 0 {
		out.WriteString("\nArguments:\n")
		width := 0
		for _, position := range c.positions {
			width = max(width, len(position.token()))
		}
		for _, position := range c.positions {
			fmt.Fprintf(&out, "  %-*s  %s", width, position.token(), position.description)
			if position.boolean {
				out.WriteString(" [possible values: true, false]")
			}
			out.WriteByte('\n')
		}
	}
	out.WriteString("\nOptions:\n")
	dataDirHelp := "Directory containing address assignments and room policy " +
		"[env: OVERLAY_DATA_DIR=" + cliEnv(env, "OVERLAY_DATA_DIR", "") + "] [default: " + defaultDataDir + "]"
	if len(path) != 0 {
		if c.confirm {
			out.WriteString("      --confirm              \n")
		}
		fmt.Fprintf(&out, "      --data-dir <DATA_DIR>  %s\n  -h, --help                 Print help\n", dataDirHelp)
	} else {
		fmt.Fprintf(&out, "      --data-dir <DATA_DIR>\n          %s\n", dataDirHelp)
		fmt.Fprintf(&out, "      --allowed-host <ALLOWED_HOST>\n          Comma-separated VPN engine hosts admitted to the hub [env: OVERLAY_ALLOWED_HOST=%s] [default: \"\"]\n", cliEnv(env, "OVERLAY_ALLOWED_HOST", ""))
		fmt.Fprintf(&out, "      --listen-address <LISTEN_ADDRESS>\n          TCP listening address [env: OVERLAY_LISTEN_ADDRESS=%s] [default: %s]\n", cliEnv(env, "OVERLAY_LISTEN_ADDRESS", ""), defaultListen)
		fmt.Fprintf(&out, "      --cidr <CIDR>\n          Canonical RFC 1918 subnet (/8 through /30) [env: OVERLAY_CIDR=%s]\n", cliEnv(env, "OVERLAY_CIDR", ""))
		out.WriteString("  -h, --help\n          Print help\n  -V, --version\n          Print version\n")
	}
	return out.String()
}
