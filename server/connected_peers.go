package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"time"
)

// The manager mounts a private runtime directory for this read-only socket.
// Presence comes only from authenticated control sessions.
func (h *hubRuntime) managedPeers() peerListing {
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	listing := h.store.listKnownPeers(nil)
	h.mu.Lock()
	defer h.mu.Unlock()
	now := hubUnixNow()
	for id := range listing.Devices {
		if h.store.peerPastRetention(id, now) && !h.busyLocked(id) {
			delete(listing.Devices, id)
		}
	}
	for id, control := range h.controls {
		if control.ctx.Err() != nil {
			continue
		}
		peer := listing.Devices[id]
		peer.Name, peer.IP, peer.Connected = control.name, control.ip.String(), true
		peer.Domain = control.domain
		listing.Devices[id] = peer
	}
	return listing
}

func (h *hubRuntime) servePeerSocket(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = writeStoreJSON(conn, h.managedPeers())
		_ = conn.Close()
	}
}

func queryManagedPeers(path string) (peerListing, error) {
	var peers peerListing
	if path == "" {
		return peers, errors.New("managed peer query is not configured")
	}
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return peers, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = json.NewDecoder(io.LimitReader(conn, 32<<20)).Decode(&peers)
	if err == nil && peers.Devices == nil {
		err = errors.New("invalid live peer listing")
	}
	return peers, err
}

func privatePeerListener(path string) (net.Listener, error) {
	listener, err := net.Listen("unix", path)
	if err == nil {
		err = os.Chmod(path, 0o600)
		if err != nil {
			_ = listener.Close()
		}
	}
	return listener, err
}
