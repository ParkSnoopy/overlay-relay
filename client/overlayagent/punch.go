package overlayagent

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"time"
)

// observePunch learns a peer-reflexive port, not a peer identity. Only the
// unpredictable hub-issued flow ID and the already offered IP may match;
// QUIC must still authenticate both pinned certificates before carrying data.
// Legacy punches can wake a dial only at the exact offered address.
func (d *direct) observePunch(packet []byte, from net.Addr) bool {
	if !bytes.HasPrefix(packet, punchPacket) {
		return false
	}
	udp, ok := from.(*net.UDPAddr)
	if !ok {
		return true
	}
	endpoint := unmap(udp.AddrPort())
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch len(packet) {
	case len(punchPacket):
		for _, exp := range d.expected {
			if exp.endpoint == endpoint {
				exp.observe(endpoint)
			}
		}
	case len(punchPacket) + 32: // the hub's 128-bit flow ID, hex encoded
		d.expected[string(packet[len(punchPacket):])].observe(endpoint)
	}
	return true
}

// observe requires owner.mu. The offered IP remains fixed; only its NAT port
// may change, so a punch cannot redirect traffic to another host.
func (e *expectation) observe(endpoint netip.AddrPort) {
	if e == nil || e.endpoint.Addr() != endpoint.Addr() {
		return
	}
	e.endpoint = endpoint
	select {
	case e.observed <- struct{}{}:
	default:
	}
}

// punch opens the NAT in both directions. The flow ID lets the peer associate
// a new source port with this rendezvous rather than discarding the packet.
func (e *expectation) punch(ctx context.Context) {
	packet := append(bytes.Clone(punchPacket), e.id...)
	ticker := time.NewTicker(punchEvery)
	defer ticker.Stop()
	for {
		e.owner.mu.Lock()
		remote := e.endpoint
		e.owner.mu.Unlock()
		_, _ = e.owner.transport.WriteTo(packet, net.UDPAddrFromAddrPort(remote))
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// peerEndpoint gives hole punching a bounded chance to reveal the peer's
// actual NAT mapping before QUIC commits to a remote address. An old peer or
// a network filtering punch packets can still use the original STUN endpoint.
func (e *expectation) peerEndpoint(ctx context.Context) net.Addr {
	timer := time.NewTimer(min(time.Second, e.owner.timeout/2))
	defer timer.Stop()
	select {
	case <-e.observed:
	case <-timer.C:
	case <-ctx.Done():
	}
	e.owner.mu.Lock()
	defer e.owner.mu.Unlock()
	return net.UDPAddrFromAddrPort(e.endpoint)
}
