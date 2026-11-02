package overlayagent

import (
	"context"
	"errors"
	"net"

	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const errUnauthorized = "unauthorized"

// Probe checks admission using a fresh, unregistered identity.
func Probe(ctx context.Context, address string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	key, err := overlay.GenerateIdentity()
	if err != nil {
		return err
	}
	agent := New(Config{Identity: key, DisableEncryption: true})
	answer, err := agent.handshake(ctx, conn, &overlay.Hello{Version: overlay.Version, Kind: overlay.KindControl})
	if err != nil {
		return err
	}
	if answer.OK || answer.Error != errUnauthorized {
		return errors.New("unexpected overlay hub reply")
	}
	return nil
}
