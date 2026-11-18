package overlayagent

import (
	"context"
	"errors"
	"io"
	"net"

	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const errUnauthorized = "unauthorized"

// Probe checks that the hub admits this source and answers frames. It sends a
// malformed public key, which the hub refuses before any challenge, so the
// probe never registers an identity or takes an overlay address.
func Probe(ctx context.Context, address string) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	version := overlay.Version
	err := probeVersion(ctx, address, version)
	if err == io.EOF && canRetryPreviousWire(ctx, version) {
		return probeVersion(ctx, address, overlay.PreviousWireVersion)
	}
	return err
}

func probeVersion(ctx context.Context, address string, version int) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { closeConn(conn) })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	hello := overlay.Hello{Version: version, Kind: overlay.KindControl, PublicKey: "00"}
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
