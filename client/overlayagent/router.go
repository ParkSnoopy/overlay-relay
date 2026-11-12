package overlayagent

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

// Router lets a session's packet-stack handler send flows addressed to the
// overlay network to the agent instead of the VPN server's open internet.
// While no agent runs, flows to the overlay address space are refused rather
// than forwarded, so hidden sessions never leak overlay traffic to the server.
type Router struct {
	// Prefix optionally reserves a range the hub already assigned, even while
	// disconnected. Zero follows the running agent's range, which stays empty
	// until the hub assigns one.
	Prefix netip.Prefix
	mu     sync.RWMutex
	agent  *Agent
}

// Owns reports whether the destination belongs to the overlay address space.
func (r *Router) Owns(address netip.Addr) bool {
	prefix := r.Prefix
	if !prefix.IsValid() {
		r.mu.RLock()
		agent := r.agent
		r.mu.RUnlock()
		if agent == nil {
			return false
		}
		prefix = agent.Range()
	}
	return prefix.Contains(address.Unmap())
}

// SetDirectPeers replaces the running agent's explicit direct approvals.
func (r *Router) SetDirectPeers(ids []string) error {
	r.mu.RLock()
	agent := r.agent
	r.mu.RUnlock()
	if agent == nil {
		return errInactive
	}
	return agent.SetDirectPeers(ids)
}

var errInactive = errors.New("overlay network is not active")

// SetRelayOnly updates direct policy on the running agent.
func (r *Router) SetRelayOnly(ids []string) error {
	r.mu.RLock()
	agent := r.agent
	r.mu.RUnlock()
	if agent == nil {
		return errInactive
	}
	return agent.SetRelayOnly(ids)
}

// TCP relays one stack TCP flow to a broadcasting peer.
func (r *Router) TCP(ctx context.Context, local net.Conn, destination M.Socksaddr) error {
	upstream, err := r.open(ctx, overlay.ProtoTCP, destination)
	if err != nil {
		return err
	}
	defer closeConn(upstream)
	return bufio.CopyConn(ctx, local, upstream)
}

// UDP relays one stack UDP flow to a broadcasting peer.
func (r *Router) UDP(ctx context.Context, local N.PacketConn, destination M.Socksaddr) error {
	upstream, err := r.open(ctx, overlay.ProtoUDP, destination)
	if err != nil {
		return err
	}
	defer closeConn(upstream)
	return bufio.CopyPacketConn(ctx, local, bufio.NewUnbindPacketConnWithAddr(upstream, destination))
}

func (r *Router) open(ctx context.Context, proto string, destination M.Socksaddr) (net.Conn, error) {
	r.mu.RLock()
	agent := r.agent
	r.mu.RUnlock()
	if agent == nil || !destination.IsIP() {
		return nil, errInactive
	}
	return agent.Outbound(ctx, proto, destination.AddrPort())
}

// Start runs an agent until stop is called or ctx ends. onReady is called once
// with the registered overlay address and returns the platform's undo function,
// which stop calls. Stop blocks until the agent has finished and is idempotent.
func (r *Router) Start(ctx context.Context, config Config, onReady func(netip.Addr) (undo func())) (stop func()) {
	agent := New(config)
	runCtx, cancel := context.WithCancel(ctx)
	r.mu.Lock()
	r.agent = agent
	r.mu.Unlock()
	done := make(chan struct{})
	var undo func()
	go func() {
		defer close(done)
		select {
		case ip := <-agent.Ready():
			if onReady != nil {
				undo = onReady(ip)
			}
		case <-runCtx.Done():
		}
	}()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_ = agent.Run(runCtx)
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			r.agent = nil
			r.mu.Unlock()
			cancel()
			<-finished
			<-done
			if undo != nil {
				undo()
			}
		})
	}
}

// LocalDialer completes incoming flows by dialing address, which must be a
// local address of this device. The dialed service sees this device as its peer;
// services bound only to loopback are not reachable through it.
func LocalDialer(address func() (netip.Addr, bool)) func(context.Context, string, uint16, netip.Addr) (net.Conn, error) {
	return func(ctx context.Context, proto string, port uint16, _ netip.Addr) (net.Conn, error) {
		local, ok := address()
		if !ok {
			return nil, errors.New("overlay address is not installed")
		}
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, proto, netip.AddrPortFrom(local, port).String())
	}
}

// SyncWriter serializes whole writes from several goroutines onto one pipe.
type SyncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewSyncWriter wraps w.
func NewSyncWriter(w io.Writer) *SyncWriter { return &SyncWriter{w: w} }

// Write implements io.Writer.
func (s *SyncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
