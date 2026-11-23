package overlayagent

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const maxNameQueries = 8

var errNameLookup = errors.New("overlay name authority unavailable")

// PeerIDByDomain returns the stable identity behind a current, room-local device name.
// Index a roster only if a caller needs it. A later roster or disconnect invalidates it.
func (a *Agent) PeerIDByDomain(domain string) (string, bool) {
	if overlay.DomainLabel(domain) == "" {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.connected {
		return "", false
	}
	if a.peerDomains == nil {
		a.peerDomains = make(map[string]string, len(a.peers))
		for i := range a.peers {
			p := &a.peers[i]
			if p.Domain == "" {
				continue
			}
			if _, duplicate := a.peerDomains[p.Domain]; duplicate {
				a.peerDomains[p.Domain] = "" // never choose between conflicting owners
			} else {
				a.peerDomains[p.Domain] = p.ID
			}
		}
	}
	id := a.peerDomains[domain]
	return id, id != ""
}

// LookupName resolves one device label on the current authenticated control
// stream. A zero address with no error means the hub has no live owner in this
// room. Disconnects and hubs without lookup support fail without a fallback.
func (a *Agent) LookupName(ctx context.Context, label string) (netip.Addr, error) {
	if !overlay.ValidNameLabel(label) {
		return netip.Addr{}, nil
	}
	a.mu.Lock()
	names := a.names
	a.mu.Unlock()
	if names == nil {
		return netip.Addr{}, errNameLookup
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	answer, err := names.lookup(ctx, label)
	if err != nil {
		return netip.Addr{}, err
	}
	if answer.Unavailable {
		return netip.Addr{}, errNameLookup
	}
	if answer.IP == "" {
		return netip.Addr{}, nil
	}
	ip, err := netip.ParseAddr(answer.IP)
	if err != nil || !overlay.AssignableIn(a.Range(), ip) {
		return netip.Addr{}, errNameLookup
	}
	return ip, nil
}

// A control stream owns its request IDs and waiters. IDs are never reused,
// so a late answer to a timed-out query cannot satisfy a different lookup.
type nameQueries struct {
	ctx      context.Context
	outbound chan overlay.NameQuery
	mu       sync.Mutex
	nextID   uint32
	pending  map[uint32]chan overlay.NameAnswer
}

func newNameQueries(ctx context.Context) *nameQueries {
	return &nameQueries{ctx: ctx, outbound: make(chan overlay.NameQuery), pending: make(map[uint32]chan overlay.NameAnswer)}
}

func (q *nameQueries) lookup(ctx context.Context, label string) (overlay.NameAnswer, error) {
	q.mu.Lock()
	if len(q.pending) >= maxNameQueries || q.nextID == math.MaxUint32 {
		q.mu.Unlock()
		return overlay.NameAnswer{}, errNameLookup
	}
	q.nextID++
	id := q.nextID
	replies := make(chan overlay.NameAnswer, 1)
	q.pending[id] = replies
	q.mu.Unlock()
	defer func() {
		q.mu.Lock()
		delete(q.pending, id)
		q.mu.Unlock()
	}()
	select {
	case <-ctx.Done():
		return overlay.NameAnswer{}, ctx.Err()
	case <-q.ctx.Done():
		return overlay.NameAnswer{}, errNameLookup
	case q.outbound <- overlay.NameQuery{ID: id, Label: label}:
	}
	select {
	case <-ctx.Done():
		return overlay.NameAnswer{}, ctx.Err()
	case <-q.ctx.Done():
		return overlay.NameAnswer{}, errNameLookup
	case answer := <-replies:
		if q.ctx.Err() != nil {
			return overlay.NameAnswer{}, errNameLookup
		}
		return answer, ctx.Err()
	}
}

func (q *nameQueries) respond(answer overlay.NameAnswer) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if reply := q.pending[answer.ID]; reply != nil {
		select {
		case reply <- answer:
		default:
		}
	}
}
