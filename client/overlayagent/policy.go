package overlayagent

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

var (
	errDirectRequired = errors.New("overlay peer requires a direct connection")
	errPeerChanged    = errors.New(overlay.ErrUnavailable)
)

type peerPolicy struct {
	relayOnly, directPeers, directOnly map[string]bool
}

func peerIDs(ids []string) (map[string]bool, error) {
	if err := overlay.ValidateRelayOnly(ids); err != nil {
		return nil, err
	}
	result := make(map[string]bool, len(ids))
	for _, id := range ids {
		result[id] = true
	}
	return result, nil
}

// SetPeerPolicy atomically replaces all three device policy lists. Direct-only
// devices need no separate direct approval. Conflicting policies are rejected.
func (a *Agent) SetPeerPolicy(relayOnly, directPeers, directOnly []string) error {
	relay, err := peerIDs(relayOnly)
	if err != nil {
		return err
	}
	approved, err := peerIDs(directPeers)
	if err != nil {
		return err
	}
	direct, err := peerIDs(directOnly)
	if err != nil {
		return err
	}
	return a.updatePeerPolicy(func(peerPolicy) peerPolicy {
		return peerPolicy{relayOnly: relay, directPeers: approved, directOnly: direct}
	})
}

// SetRelayOnly replaces the direct deny list without changing other policies.
func (a *Agent) SetRelayOnly(ids []string) error {
	policy, err := peerIDs(ids)
	if err != nil {
		return err
	}
	return a.updatePeerPolicy(func(p peerPolicy) peerPolicy {
		p.relayOnly = policy
		return p
	})
}

// SetDirectPeers replaces explicit direct approvals without changing other policies.
func (a *Agent) SetDirectPeers(ids []string) error {
	policy, err := peerIDs(ids)
	if err != nil {
		return err
	}
	return a.updatePeerPolicy(func(p peerPolicy) peerPolicy {
		p.directPeers = policy
		return p
	})
}

func (a *Agent) updatePeerPolicy(update func(peerPolicy) peerPolicy) error {
	a.mu.Lock()
	next := update(a.policy)
	for id := range next.directOnly {
		if next.relayOnly[id] {
			a.mu.Unlock()
			return errors.New("overlay peer cannot be both relay-only and direct-only")
		}
	}
	a.policy = next
	closed := a.revokeTransportsLocked(func(netip.Addr, string) bool { return true })
	started := a.started
	a.mu.Unlock()
	closed.close()
	if started {
		a.emit()
	}
	return nil
}

func (a *Agent) relayOnlyLocked(id string) bool {
	return !overlay.ValidPeerID(id) || a.policy.relayOnly[id] || (!a.policy.directPeers[id] && !a.policy.directOnly[id])
}

func (a *Agent) relayAllowedLocked(id string, identified bool) bool {
	// An unidentified legacy stream cannot bypass a device restriction.
	return !a.policy.directOnly[id] && (identified || len(a.policy.directOnly) == 0)
}

// relayAdmission reserves the peer and path before the hub handshake. The same
// lock commits it as an active flow or revokes it on policy/identity changes.
// The control stream supplies the authenticated ID for incoming requests.
type relayAdmission struct {
	ip         netip.Addr
	id         string
	identified bool
	cancel     context.CancelFunc
	raw        net.Conn // set under Agent.mu before any hub handshake
}

func (a *Agent) beginRelay(ctx context.Context, ip netip.Addr, id string, incoming bool) (context.Context, *relayAdmission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	current, listed := a.peerSet[ip]
	identified := overlay.ValidPeerID(id)
	if incoming && listed && !identified {
		// Remember the advertised identity for revocation, but don't trust it
		// as authentication for a request with no usable device ID.
		id = current
	}
	if !a.connected || (listed && current != id) || (!listed && !incoming) {
		return ctx, nil, errPeerChanged
	}
	if !a.relayAllowedLocked(id, identified) {
		return ctx, nil, errDirectRequired
	}
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	pending := &relayAdmission{ip: ip, id: id, identified: identified, cancel: cancel}
	if a.pendingRelay == nil {
		a.pendingRelay = make(map[*relayAdmission]struct{})
	}
	a.pendingRelay[pending] = struct{}{}
	return ctx, pending, nil
}

func (a *Agent) finishRelay(pending *relayAdmission) {
	a.mu.Lock()
	// After trackRelay succeeds, the returned flow owns the dial context.
	// Canceling it here would close context-bound SOCKS streams before use.
	if _, ok := a.pendingRelay[pending]; ok {
		delete(a.pendingRelay, pending)
		pending.cancel()
	}
	a.mu.Unlock()
}

func (a *Agent) bindRelay(ctx context.Context, admission *relayAdmission, raw net.Conn) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, pending := a.pendingRelay[admission]; !pending || ctx.Err() != nil {
		return errPeerChanged
	}
	admission.raw = raw
	return nil
}

func (a *Agent) trackRelay(ctx context.Context, admission *relayAdmission, conn net.Conn) (net.Conn, error) {
	a.mu.Lock()
	if _, pending := a.pendingRelay[admission]; !pending || ctx.Err() != nil {
		a.mu.Unlock()
		closeConn(admission.raw)
		return nil, errPeerChanged
	}
	delete(a.pendingRelay, admission)
	flow := &peerFlow{Conn: conn, ip: admission.ip, peerID: admission.id, relay: admission}
	a.trackFlowLocked(flow)
	a.mu.Unlock()
	a.emit()
	return flow, nil
}

type revokedTransports struct {
	flows []*peerFlow
	links []*peerLink
	relay []net.Conn
}

func (closed *revokedTransports) revokeRelay(admission *relayAdmission) {
	admission.cancel()
	if admission.raw != nil {
		closed.relay = append(closed.relay, admission.raw)
	}
}

// revokeTransportsLocked detaches disallowed negotiations and marks flows before
// dropping mu. Socket closure and state callbacks must run outside the lock.
func (a *Agent) revokeTransportsLocked(keepPeer func(netip.Addr, string) bool) (closed revokedTransports) {
	for pending := range a.pendingRelay {
		if !keepPeer(pending.ip, pending.id) || !a.relayAllowedLocked(pending.id, pending.identified) {
			delete(a.pendingRelay, pending)
			closed.revokeRelay(pending)
		}
	}
	for flow := range a.active {
		allowed := !a.relayOnlyLocked(flow.peerID)
		if relay := flow.relay; relay != nil {
			allowed = a.relayAllowedLocked(relay.id, relay.identified)
		}
		if !allowed || !keepPeer(flow.ip, flow.peerID) {
			flow.revoked.Store(true)
			closed.flows = append(closed.flows, flow)
			if flow.relay != nil {
				closed.revokeRelay(flow.relay)
			}
		}
	}
	for ip, link := range a.links {
		if !keepPeer(ip, link.peerID) || a.relayOnlyLocked(link.peerID) {
			delete(a.links, ip)
			if o, ok := a.observations[ip]; ok && o.id == link.peerID {
				o.status = overlay.DirectCanceled
				a.observations[ip] = o
			}
			closed.links = append(closed.links, link)
		}
	}
	for ip, attempt := range a.linking {
		if !keepPeer(ip, attempt.peerID) || a.relayOnlyLocked(attempt.peerID) {
			delete(a.linking, ip)
			attempt.cancel()
		}
	}
	return closed
}

func (closed revokedTransports) close() {
	for _, raw := range closed.relay {
		// Interrupt TLS writes instead of waiting to send close_notify.
		closeConn(raw)
	}
	for _, link := range closed.links {
		link.close()
	}
	for _, flow := range closed.flows {
		closeConn(flow)
	}
}
