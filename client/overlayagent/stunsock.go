package overlayagent

import (
	"context"
	"crypto/rand"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/stun/v4"
)

const (
	stunTimeout = 3 * time.Second
	stunRetry   = 500 * time.Millisecond
)

// stunConn is a UDP socket that can ask a STUN server for its public mapping
// while another protocol keeps using it. Binding responses never reach that
// protocol; every other packet does.
type stunConn struct {
	net.PacketConn

	mu     sync.Mutex
	probes map[stunTransaction]chan netip.AddrPort
}

// listenSocket opens one direct socket through the caller's ListenPacket.
func (d *directState) listenSocket(ctx context.Context) (*stunConn, error) {
	var (
		socket net.PacketConn
		err    error
	)
	if d.options.ListenPacket != nil {
		socket, err = d.options.ListenPacket(ctx)
	} else {
		var config net.ListenConfig
		socket, err = config.ListenPacket(ctx, "udp4", ":0")
	}
	if err != nil {
		return nil, err
	}
	return &stunConn{PacketConn: socket, probes: map[stunTransaction]chan netip.AddrPort{}}, nil
}

func (c *stunConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, from, err
		}
		tx, endpoint, parseErr := parseSTUN(p[:n])
		if parseErr != nil {
			return n, from, nil
		}
		c.mu.Lock()
		reply := c.probes[tx]
		c.mu.Unlock()
		if reply != nil {
			select {
			case reply <- endpoint:
			default:
			}
		}
	}
}

// SetReadBuffer and SetWriteBuffer let QUIC enlarge the kernel buffers.
func (c *stunConn) SetReadBuffer(n int) error {
	if s, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return s.SetReadBuffer(n)
	}
	return nil
}

func (c *stunConn) SetWriteBuffer(n int) error {
	if s, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return s.SetWriteBuffer(n)
	}
	return nil
}

// query asks the servers in order for this socket's public address.
func (c *stunConn) query(ctx context.Context, servers []*stun.URI) (netip.AddrPort, error) {
	for _, server := range servers {
		address, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(server.Host, itoa(server.Port)))
		if err != nil {
			continue
		}
		if endpoint, err := c.ask(ctx, address); err == nil {
			return endpoint, nil
		}
	}
	return netip.AddrPort{}, errNoAddress
}

func (c *stunConn) ask(ctx context.Context, server net.Addr) (netip.AddrPort, error) {
	var tx stunTransaction
	if _, err := rand.Read(tx[:]); err != nil {
		return netip.AddrPort{}, err
	}
	reply := make(chan netip.AddrPort, 1)
	c.mu.Lock()
	c.probes[tx] = reply
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.probes, tx)
		c.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, stunTimeout)
	defer cancel()
	request := stunRequest(tx)
	ticker := time.NewTicker(stunRetry)
	defer ticker.Stop()
	for {
		if _, err := c.PacketConn.WriteTo(request, server); err != nil {
			return netip.AddrPort{}, err
		}
		select {
		case endpoint := <-reply:
			return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()), nil
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		case <-ticker.C:
		}
	}
}
