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
// Nothing about presence is persisted or inferred from an address reservation.
func (h *hubRuntime) connectedPeers() peerListing {
	h.mu.Lock()
	defer h.mu.Unlock()
	devices := make(map[string]listedPeer, len(h.controls))
	for id, control := range h.controls {
		if control.ctx.Err() != nil {
			continue
		}
		peer := listedPeer{Name: control.name, IP: control.ip.String(), NameOverride: h.store.peerEdits[id].Name}
		if ip := h.store.reservations[id]; ip.IsValid() {
			peer.Binding = ip.String()
		}
		devices[id] = peer
	}
	return peerListing{Devices: devices}
}

func (h *hubRuntime) servePeerSocket(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_ = json.NewEncoder(conn).Encode(h.connectedPeers())
		_ = conn.Close()
	}
}

func queryConnectedPeers(path string) (peerListing, error) {
	var peers peerListing
	if path == "" {
		return peers, errors.New("connected peer query is not configured")
	}
	conn, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		return peers, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = json.NewDecoder(io.LimitReader(conn, 16<<20)).Decode(&peers)
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
