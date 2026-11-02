// Command peers writes a peers table for the overlay hub to stdout.
//
// Use keygen PATH to create an identity, or name=public-key arguments to
// construct the hub's peers table.
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
	if len(args) == 2 && args[0] == "keygen" {
		key, err := overlay.GenerateIdentity()
		if err != nil {
			return err
		}
		encoded, err := overlay.EncodeIdentity(key)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(args[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(encoded)
		closeErr := file.Close()
		if writeErr != nil {
			_ = os.Remove(args[1])
			return writeErr
		}
		if closeErr != nil {
			_ = os.Remove(args[1])
			return closeErr
		}
		public, err := overlay.PublicIdentity(key)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, public)
		return err
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: peers keygen PATH | name=public-key [name=public-key ...]")
	}
	table := overlay.Peers{Version: overlay.Version}
	for _, arg := range args {
		name, public, ok := strings.Cut(arg, "=")
		if !ok || name == "" || public == "" {
			return fmt.Errorf("argument must be name=public-key")
		}
		table.Accounts = append(table.Accounts, overlay.Account{PublicKey: public, Name: name})
	}
	if err := table.Validate(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(table, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, string(encoded))
	return err
}
