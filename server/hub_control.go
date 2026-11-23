package main

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const hubControlQueue = 16

// Pointer identity distinguishes a registration from a later replacement.
// Its identity, address, name, and room are immutable after publication.
type hubControl struct {
	id        string
	ip        netip.Addr
	name      string
	domain    string
	room      hubRoom
	version   int
	peerPages bool
	ctx       context.Context
	stop      context.CancelFunc
	events    chan any
	dirty     chan struct{}
}

type hubPeer struct {
	ID     string `json:"id"`
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Domain string `json:"domain,omitempty"`
}

type hubRoster struct {
	Peers []hubPeer `json:"peers"`
}

func requestedHubLabel(hello *overlay.Hello) string {
	if hello.Domain != "" {
		return overlay.DomainLabel(hello.Domain)
	}
	label := overlay.DomainLabel(overlay.DeviceDomain(hello.Name))
	if label == "" {
		return "device"
	}
	return label
}

// Called with the registration lock held; publish only after the name has
// passed validation and the already-identified address cannot be reclaimed.
func (h *hubRuntime) registerControl(ctx context.Context, id string, ip netip.Addr, room hubRoom, hello *overlay.Hello) *hubControl {
	if overlay.ValidateName(hello.Name) != nil {
		return nil
	}
	label := requestedHubLabel(hello)
	if label == "" {
		return nil
	}
	advertised := hello.Name
	if advertised == "" {
		advertised = "peer-" + id[:8]
	}
	if err := h.store.setName(id, hello.Name); err != nil {
		return nil
	}
	var domain string
	if canonical := h.store.reserveName(room.capability, label, id); canonical != "" {
		domain = canonical + "." + overlay.DeviceZone
	}
	ctx, stop := context.WithCancel(ctx)
	control := &hubControl{
		id: id, ip: ip, name: advertised, domain: domain, room: room, version: hello.Version,
		peerPages: hello.PeerPages,
		ctx:       ctx, stop: stop, events: make(chan any, hubControlQueue), dirty: make(chan struct{}, 1),
	}
	h.mu.Lock()
	if old := h.controls[id]; old != nil {
		old.stop()
		delete(h.byIP, old.ip)
	}
	h.controls[id], h.byIP[ip] = control, control
	h.mu.Unlock()
	return control
}

func (h *hubRuntime) serveControl(conn net.Conn, control *hubControl, display string) {
	stop := context.AfterFunc(control.ctx, func() { _ = conn.Close() })
	defer func() {
		control.stop()
		stop()
		h.mu.Lock()
		if h.controls[control.id] == control {
			delete(h.controls, control.id)
			delete(h.byIP, control.ip)
			h.notifyPeersLocked()
		}
		h.mu.Unlock()
		h.store.touch(control.id, hubUnixNow())
	}()
	reply := overlay.Reply{
		OK: true, IP: control.ip.String(), CIDR: h.space.String(), Name: control.name,
		Domain: control.domain, RoomName: display, NameLookup: 1,
	}
	if control.ctx.Err() != nil || sendHubFrame(conn, reply) != nil {
		return
	}
	h.mu.Lock()
	h.notifyPeersLocked()
	h.mu.Unlock()
	written := make(chan struct{})
	go func() {
		defer close(written)
		defer control.stop()
		h.writeControl(conn, control)
	}()
	h.readControl(conn, control)
	control.stop()
	<-written
}

func (h *hubRuntime) notifyPeersLocked() {
	for _, control := range h.controls {
		select {
		case control.dirty <- struct{}{}:
		default:
		}
	}
}

func (h *hubRuntime) snapshot(control *hubControl) []hubPeer {
	h.mu.Lock()
	defer h.mu.Unlock()
	peers := make([]hubPeer, 0)
	if h.controls[control.id] != control {
		return peers
	}
	for _, peer := range h.controls {
		if peer != control && peer.room.capability == control.room.capability && peer.ctx.Err() == nil {
			peers = append(peers, hubPeer{ID: peer.id, IP: peer.ip.String(), Name: peer.name, Domain: peer.domain})
		}
	}
	// IPv4 strings do not sort in address order. Use the current address index.
	slices.SortFunc(peers, func(a, b hubPeer) int { return h.controls[a.ID].ip.Compare(h.controls[b.ID].ip) })
	return peers
}

func (h *hubRuntime) writeControl(conn net.Conn, control *hubControl) {
	for control.ctx.Err() == nil {
		var event any
		select {
		case event = <-control.events:
		default:
			select {
			case <-control.ctx.Done():
				return
			case event = <-control.events:
			case <-control.dirty:
				peers := h.snapshot(control)
				if control.ctx.Err() != nil || !writeHubRoster(conn, peers, control.peerPages) {
					return
				}
				continue
			}
		}
		if control.ctx.Err() != nil || sendHubFrame(conn, event) != nil {
			return
		}
	}
}

func writeHubRoster(conn net.Conn, peers []hubPeer, paging bool) bool {
	payload, err := encodeHubJSON(hubRoster{peers})
	if err != nil {
		return false
	}
	if len(payload) > overlay.UsableFrame {
		if paging {
			return writeHubPeerPages(conn, peers)
		}
		// Old clients require a full snapshot. If optional DNS metadata is
		// what exceeded the envelope, retain the original discovery contract.
		for i := range peers {
			peers[i].Domain = ""
		}
		payload, err = encodeHubJSON(hubRoster{peers})
	}
	return err == nil && sendHubJSON(conn, payload) == nil
}

func writeHubPeerPages(conn net.Conn, peers []hubPeer) bool {
	const prefix = `{"peer_page":{"peers":[`
	const more = `],"more":true}}`
	const last = `],"more":false}}`
	const limit = overlay.UsableFrame - len(last)
	page := append(make([]byte, 0, overlay.UsableFrame), prefix...)
	for i := range peers {
		entry, err := encodeHubJSON(peers[i])
		if err != nil || len(prefix)+len(entry) > limit {
			return false
		}
		if len(page)+1+len(entry) > limit && len(page) > len(prefix) {
			if sendHubJSON(conn, append(page, more...)) != nil {
				return false
			}
			page = page[:len(prefix)]
		}
		if len(page) > len(prefix) {
			page = append(page, ',')
		}
		page = append(page, entry...)
	}
	return sendHubJSON(conn, append(page, last...)) == nil
}

func (c *hubControl) enqueue(event any) bool {
	if c.ctx.Err() != nil {
		return false
	}
	select {
	case c.events <- event:
		return true
	default:
		c.stop()
		return false
	}
}

func (h *hubRuntime) readControl(conn net.Conn, control *hubControl) {
	for control.ctx.Err() == nil {
		if conn.SetReadDeadline(time.Now().Add(h.timing.controlIdle)) != nil {
			return
		}
		request, err := readHubControlRequest(conn)
		if err != nil {
			return
		}
		var event overlay.Event
		switch {
		case request.Ping && request.Resolve == nil:
			event.Pong = true
		case !request.Ping && request.Resolve != nil && request.Resolve.ID != 0:
			answer := h.resolveName(control, *request.Resolve)
			event.Resolved = &answer
		default:
			return
		}
		if !control.enqueue(event) {
			return
		}
	}
}

func (h *hubRuntime) resolveName(control *hubControl, query overlay.NameQuery) overlay.NameAnswer {
	answer := overlay.NameAnswer{ID: query.ID}
	if room := control.room; room.id != "" {
		// Proof rotation invalidates lookups, irrespective of relay permission.
		_, _, reason := h.store.admitRoom(room.id, room.proof)
		if reason != "" {
			answer.Unavailable = reason == hubRoomsOffline
			return answer
		}
	}
	owner, err := h.store.nameOwner(control.room.capability, query.Label)
	if err != nil {
		answer.Unavailable = true
		return answer
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	target := h.controls[owner]
	if h.controls[control.id] == control && control.ctx.Err() == nil &&
		target != nil && target.room.capability == control.room.capability &&
		target.ctx.Err() == nil && h.byIP[target.ip] == target {
		answer.IP = target.ip.String()
	}
	return answer
}
