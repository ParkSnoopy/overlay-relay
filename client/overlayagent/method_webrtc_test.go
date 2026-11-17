package overlayagent

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v5/vnet"
)

// Exercise real ICE/DTLS/SCTP and the detached-channel adapter on an isolated
// in-process network. No public STUN service or host interface is required.
func TestWebRTCDataChannelRoundTrip(t *testing.T) {
	router, err := vnet.NewRouter(&vnet.RouterConfig{CIDR: "192.0.2.0/24", LoggerFactory: logging.NewDefaultLoggerFactory()})
	if err != nil {
		t.Fatal(err)
	}
	var methods []*webrtcMethod
	for _, address := range []string{"192.0.2.1", "192.0.2.2"} {
		network, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{address}})
		if err != nil {
			t.Fatal(err)
		}
		if err := router.AddNet(network); err != nil {
			t.Fatal(err)
		}
		methods = append(methods, &webrtcMethod{state: &directState{network: network}})
	}
	if err := router.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := router.Stop(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	initiator, offer, err := methods[0].offer(ctx, &linkPeer{id: "DUMMY-responder", initiator: true})
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.close()
	responder, answer, err := methods[1].answer(ctx, &linkPeer{id: "DUMMY-initiator"}, offer)
	if err != nil {
		t.Fatal(err)
	}
	defer responder.close()
	if err := initiator.apply(answer); err != nil {
		t.Fatal(err)
	}
	left, err := initiator.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer left.close()
	right, err := responder.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer right.close()
	stop := context.AfterFunc(ctx, func() { left.close(); right.close() })
	defer stop()
	deadline, _ := ctx.Deadline()

	// Repeat streams and cross the adapter's message and buffer boundaries.
	for range 2 {
		payload := bytes.Repeat([]byte("DUMMY WebRTC payload\n"), dataBuffer/8)
		done := make(chan error, 1)
		go func() {
			conn, err := right.accept(ctx)
			if err != nil {
				done <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(deadline)
			_, err = io.CopyN(conn, conn, int64(len(payload)))
			done <- err
		}()
		conn, err := left.open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(deadline)
		if _, err := conn.Write(payload); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
		actual := make([]byte, len(payload))
		_, err = io.ReadFull(conn, actual)
		_ = conn.Close()
		if err != nil || !bytes.Equal(actual, payload) {
			t.Fatal("WebRTC multiplexed payload did not round-trip", err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
