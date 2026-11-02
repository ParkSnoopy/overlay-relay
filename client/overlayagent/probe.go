package overlayagent

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const errUnauthorized = "unauthorized"

// Probe proves that the hub admits this source and parses frames without any
// real account: an all-zero token must receive a well-formed unauthorized reply.
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
	hello := overlay.Hello{Version: overlay.Version, Kind: overlay.KindControl, Token: strings.Repeat("0", 64)}
	if err := overlay.WriteFrame(conn, hello); err != nil {
		return err
	}
	var answer overlay.Reply
	if err := overlay.ReadFrame(conn, &answer); err != nil {
		return err
	}
	if answer.OK || answer.Error != errUnauthorized {
		return errors.New("unexpected overlay hub reply")
	}
	return nil
}
