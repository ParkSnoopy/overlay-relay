// Command client runs one overlay agent against a hub and prints its state.
//
// Environment:
//
//	OVERLAY_HUB     hub address, host:port (default 127.0.0.1:6697)
//	OVERLAY_SECRET  canonical account secret, the same value used in peers.json
//	OVERLAY_LOCAL   host that serves incoming flows (default 127.0.0.1); the port is the one the peer requested
//	OVERLAY_CONNECT optional peer address, ip:port, to send one line to
//
// The program exits on SIGINT or SIGTERM.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"github.com/ParkSnoopy/overlay-relay/client/overlayagent"
)

const (
	defaultHub   = "127.0.0.1:6697"
	defaultLocal = "127.0.0.1"
	connectWait  = 30 * time.Second
)

func main() {
	os.Exit(execute())
}

func execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "client:", err)
		return 1
	}
	return 0
}

func run(ctx context.Context) error {
	secret := os.Getenv("OVERLAY_SECRET")
	if secret == "" {
		return errors.New("OVERLAY_SECRET is required")
	}
	hub := envOr("OVERLAY_HUB", defaultHub)
	local := hostOf(envOr("OVERLAY_LOCAL", defaultLocal))

	states := make(chan overlay.State, 64)
	agent := overlayagent.New(overlayagent.Config{
		Secret: []byte(secret),
		Dial: func(ctx context.Context) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", hub)
		},
		DialLocal: func(ctx context.Context, proto string, port uint16, _ netip.Addr) (net.Conn, error) {
			var dialer net.Dialer
			target := net.JoinHostPort(local, strconv.Itoa(int(port)))
			return dialer.DialContext(ctx, proto, target)
		},
		OnState: func(state overlay.State) {
			// OnState must not block: drop the update when the printer is behind.
			select {
			case states <- state:
			default:
			}
		},
	})

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- agent.Run(runCtx) }()
	go printStates(runCtx, states)

	select {
	case ip := <-agent.Ready():
		if _, err := fmt.Fprintf(os.Stdout, "registered address=%s\n", ip); err != nil {
			return err
		}
	case err := <-runErr:
		return err
	case <-ctx.Done():
		return nil
	}

	if peer := os.Getenv("OVERLAY_CONNECT"); peer != "" {
		if err := exchange(ctx, agent, peer); err != nil {
			return err
		}
	}

	<-ctx.Done()
	cancel()
	if err := <-runErr; err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// exchange opens one TCP flow to peer, sends a line and prints the echoed reply.
func exchange(ctx context.Context, agent *overlayagent.Agent, peer string) error {
	destination, err := netip.ParseAddrPort(peer)
	if err != nil {
		return fmt.Errorf("OVERLAY_CONNECT: %w", err)
	}
	deadline := time.Now().Add(connectWait)
	for {
		flow, err := agent.Outbound(ctx, overlay.ProtoTCP, destination)
		if err == nil {
			err = roundTrip(flow, destination)
			_ = flow.Close()
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("peer %s: %w", destination, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func roundTrip(flow net.Conn, destination netip.AddrPort) error {
	const line = "hello over overlay\n"
	if _, err := flow.Write([]byte(line)); err != nil {
		return err
	}
	if err := flow.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	reply, err := bufio.NewReader(flow).ReadString('\n')
	if err != nil {
		return fmt.Errorf("reply from %s: %w", destination, err)
	}
	_, err = fmt.Fprintf(os.Stdout, "reply from %s: %s", destination, reply)
	return err
}

func printStates(ctx context.Context, states <-chan overlay.State) {
	for {
		select {
		case <-ctx.Done():
			return
		case state := <-states:
			encoded, err := json.Marshal(state)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintln(os.Stdout, string(encoded)); err != nil {
				return
			}
		}
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func hostOf(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}
