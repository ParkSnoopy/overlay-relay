package overlayagent

import (
	"context"
	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRegressionSmallSubnetReclaimsDisconnectedIdentity(t *testing.T) {
	binary := os.Getenv("OVERLAY_HUB_BIN")
	if binary == "" {
		t.Skip("set OVERLAY_HUB_BIN to run real-hub integration")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary)
	command.Env = append(os.Environ(), "OVERLAY_ALLOWED_HOST=", "OVERLAY_LISTEN_ADDRESS="+address, "OVERLAY_CIDR=192.168.100.0/30", "OVERLAY_DATA_DIR="+t.TempDir())
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = command.Wait() }()
	for {
		conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("hub not ready")
		case <-time.After(10 * time.Millisecond):
		}
	}
	dial := func(ctx context.Context) (net.Conn, error) { return (&net.Dialer{}).DialContext(ctx, "tcp", address) }
	for index := 0; index < 2; index++ {
		identity, err := overlay.GenerateIdentity()
		if err != nil {
			t.Fatal(err)
		}
		prefix, err := DiscoverCIDR(ctx, Config{Identity: identity, Name: "DUMMY audit", Dial: dial})
		if err != nil || prefix.String() != "192.168.100.0/30" {
			t.Fatal("initial discovery failed", err)
		}
		// DiscoverCIDR closes its temporary control connection before returning.
		time.Sleep(100 * time.Millisecond)
	}
	identity, err := overlay.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		_, lastErr = DiscoverCIDR(ctx, Config{Identity: identity, Name: "DUMMY replacement", Dial: dial})
		if lastErr == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("third identity denied after both earlier control connections closed: %v", lastErr)
}
