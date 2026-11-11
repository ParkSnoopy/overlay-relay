package overlayagent

import (
	"net"
	"net/netip"
	"sync"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

// SetRelayOnly replaces the direct-connection deny list. IDs identify device
// keys, not addresses. Existing direct flows to denied peers are closed; new
// flows use the encrypted relay. It is safe to call while Run is active.
func (a *Agent) SetRelayOnly(ids []string) error {
	if err := overlay.ValidateRelayOnly(ids); err != nil {
		return err
	}
	policy := make(map[string]bool, len(ids))
	for _, id := range ids {
		policy[id] = true
	}
	a.mu.Lock()
	a.relayOnly = policy
	started := a.started
	var closing []*peerFlow
	for flow := range a.active {
		if flow.direct && a.relayOnlyLocked(flow.peerID) {
			closing = append(closing, flow)
		}
	}
	a.mu.Unlock()
	a.closeLinks(func(_ netip.Addr, id string) bool {
		_, denied := policy[id]
		return !denied
	})
	for _, flow := range closing {
		closeConn(flow)
	}
	if started {
		a.emit()
	}
	return nil
}

func (a *Agent) relayOnlyLocked(id string) bool {
	// An older hub cannot identify incoming devices. Fail closed when any
	// device restriction exists rather than silently bypassing that policy.
	return !overlay.ValidPeerID(id) || !a.directPeers[id] || a.relayOnly[id]
}

// SetDirectPeers replaces explicit device approvals, closing revoked direct
// flows and negotiations immediately. Relay remains available for every peer.
func (a *Agent) SetDirectPeers(ids []string) error {
	if err := overlay.ValidateRelayOnly(ids); err != nil {
		return err
	}
	policy := make(map[string]bool, len(ids))
	for _, id := range ids {
		policy[id] = true
	}
	a.mu.Lock()
	a.directPeers = policy
	started := a.started
	var closing []*peerFlow
	for flow := range a.active {
		if flow.direct && a.relayOnlyLocked(flow.peerID) {
			closing = append(closing, flow)
		}
	}
	a.mu.Unlock()
	a.closeLinks(func(_ netip.Addr, id string) bool { return policy[id] })
	for _, flow := range closing {
		closeConn(flow)
	}
	if started {
		a.emit()
	}
	return nil
}

func (a *Agent) peerIDLocked(ip netip.Addr) string {
	for _, peer := range a.peers {
		if peer.IP == ip.String() {
			return peer.ID
		}
	}
	return ""
}

type peerObservation struct {
	id     string
	status overlay.DirectStatus
	path   overlay.FlowPath
}

func (a *Agent) recordDirect(ip netip.Addr, id string, status overlay.DirectStatus) {
	a.mu.Lock()
	if a.connected && a.peerIDLocked(ip) == id {
		if a.observations == nil {
			a.observations = make(map[netip.Addr]peerObservation)
		}
		observation := a.observations[ip]
		if observation.id != id {
			observation = peerObservation{id: id}
		}
		observation.status = status
		a.observations[ip] = observation
	}
	a.mu.Unlock()
	a.emit()
}

func (a *Agent) trackFlow(conn net.Conn, ip netip.Addr, id string, direct bool) (net.Conn, error) {
	flow := &peerFlow{Conn: conn, agent: a, ip: ip, peerID: id, direct: direct}
	a.mu.Lock()
	if direct && a.relayOnlyLocked(id) {
		a.mu.Unlock()
		closeConn(conn)
		a.recordDirect(ip, id, overlay.DirectCanceled)
		return nil, errDirectFailed
	}
	if a.active == nil {
		a.active = make(map[*peerFlow]struct{})
	}
	a.active[flow] = struct{}{}
	if a.connected && a.peerIDLocked(ip) == id {
		if a.observations == nil {
			a.observations = make(map[netip.Addr]peerObservation)
		}
		observation := a.observations[ip]
		if observation.id != id {
			observation = peerObservation{id: id}
		}
		observation.path = overlay.PathRelay
		if direct {
			observation.path, observation.status = overlay.PathDirect, overlay.DirectSucceeded
		}
		a.observations[ip] = observation
	}
	a.mu.Unlock()
	a.emit()
	return flow, nil
}

// peerFlow retains the underlying half-close contract and removes its live
// path exactly once, even when cancellation and both splice directions close.
type peerFlow struct {
	net.Conn
	agent  *Agent
	ip     netip.Addr
	peerID string
	direct bool
	once   sync.Once
	err    error
}

func (f *peerFlow) Close() error {
	f.once.Do(func() {
		f.err = f.Conn.Close()
		f.agent.mu.Lock()
		delete(f.agent.active, f)
		f.agent.mu.Unlock()
		f.agent.emit()
	})
	return f.err
}

func (f *peerFlow) CloseWrite() error {
	if writer, ok := f.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return f.Close()
}
