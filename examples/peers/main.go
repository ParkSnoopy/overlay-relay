// Command peers writes a peers table for the overlay hub to stdout.
//
// Each argument is name=secret, where secret is the same canonical secret the
// client uses. Redirect the output to peers.json.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "peers:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: peers name=secret [name=secret ...]")
	}
	table := overlay.Peers{Version: overlay.Version}
	for _, arg := range args {
		name, secret, ok := strings.Cut(arg, "=")
		if !ok || name == "" || secret == "" {
			return fmt.Errorf("argument %q must be name=secret", arg)
		}
		verifier, err := overlay.Verifier(overlay.Token([]byte(secret)))
		if err != nil {
			return err
		}
		table.Accounts = append(table.Accounts, overlay.Account{Verifier: verifier, Name: name})
	}
	encoded, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, string(encoded))
	return err
}
