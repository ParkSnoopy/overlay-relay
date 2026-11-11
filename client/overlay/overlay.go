// Package overlay owns the wire contract of the private overlay network that
// connects broadcasting VPN clients through their own VPN server.
//
// Roles:
//   - The hub (the overlay-relay server) runs on the managed server and is
//     reachable only through an established VPN transport at Address.
//   - The agent runs inside a connected client session. Only a client that
//     chose to broadcast ever contacts the hub with a control stream.
//
// Every account owns one stable private IPv4 address inside CIDR. A hidden
// (non-broadcasting) account holds an address but has no control stream, so
// the hub never lists it and never relays a stream to or from it.
package overlay

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// Hostname is the container name of the hub on the managed Docker network.
	Hostname = "snoo-box-overlay"
	// Port is the hub's private VPN destination port, not public ingress.
	Port = "6697"
	// Address is the hub destination used by native proxy engines.
	Address = Hostname + ":" + Port
	// ListenAddress binds the hub inside its private container network.
	ListenAddress = "0.0.0.0:" + Port
	// Version is the only wire version.
	Version = 3
	// MaxFrame bounds one control frame (JSON payload) in bytes.
	MaxFrame = 16 << 10
	// MaxDatagram bounds one UDP payload carried inside a UDP stream.
	MaxDatagram = 65535
	// SafetySpace is kept free below each transport limit, so headers and
	// encoding overhead never cross a hard bound. Writers stay under the usable
	// limits; readers accept up to the wire limits.
	SafetySpace = 128
	// UsableFrame is the largest payload a writer emits as one frame.
	UsableFrame = MaxFrame - SafetySpace
	// UsableDatagram is the largest payload a writer emits as one datagram record.
	UsableDatagram = MaxDatagram - SafetySpace
	// LinkPort is the overlay TCP port reserved for agent-to-agent direct link
	// negotiation. The destination agent answers it itself, so an incoming flow
	// to this port never reaches the local service dialer.
	LinkPort uint16 = 65535
)

// CIDR is the overlay address space. Network and broadcast addresses are never assigned.
var CIDR = netip.MustParsePrefix("10.77.0.0/16")

// Stream kinds in Hello.Kind.
const (
	KindControl = "control" // register as broadcasting; receive peers and incoming requests
	KindOpen    = "open"    // open a relayed flow to a broadcasting peer
	KindAccept  = "accept"  // answer an Incoming request received on the control stream
)

// Transport protocols carried by a flow.
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
)

// Hello is the first frame on every stream a client opens to the hub.
type Hello struct {
	// PeerID optionally binds an open request to its expected device identity.
	PeerID    string `json:"peer_id,omitempty"`
	Version   int    `json:"version"`
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key"`
	// Room is an opaque private-room capability, empty for the public room.
	Room  string `json:"room,omitempty"`
	Name  string `json:"name,omitempty"`  // control: advertised device name
	Proto string `json:"proto,omitempty"` // open
	Dst   string `json:"dst,omitempty"`   // open: destination overlay IP
	Port  uint16 `json:"port,omitempty"`  // open: destination port
	ID    string `json:"id,omitempty"`    // accept: Incoming.ID

	// Fingerprint is the SHA-256 of the sender's flow certificate, as 64 hex
	// digits. Sending it offers an end-to-end encrypted flow (open, accept).
	Fingerprint string `json:"fingerprint,omitempty"`
	// Endpoint is reserved. The hub still pairs two offers that carry it, but
	// agents negotiate direct links through LinkPort and never send it.
	Endpoint string `json:"endpoint,omitempty"`
}

// Challenge is a fresh nonce issued by the hub for one connection.
type Challenge struct {
	Nonce string `json:"nonce"`
}

// Proof carries a DER-encoded ECDSA signature of the challenge.
type Proof struct {
	Signature string `json:"signature"`
}

// Reply is the hub's answer to Hello and, on a control stream, to Ping.
// Peer lists and incoming requests share the control stream as separate frames.
type Reply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	IP    string `json:"ip,omitempty"`   // control: this account's address
	Name  string `json:"name,omitempty"` // control: this account's display name
	CIDR  string `json:"cidr,omitempty"` // control: authoritative address space

	// Secure reports that both sides offered a fingerprint, so the flow is
	// end-to-end encrypted. Fingerprint is then the other side's.
	Secure      bool   `json:"secure,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Direct reports that both sides offered an endpoint too. The hub then
	// relays nothing; ID names the flow and Endpoint is the other side's address.
	Direct   bool   `json:"direct,omitempty"`
	ID       string `json:"id,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

// ValidPeerID reports whether id is a canonical SHA-256 device identifier.
func ValidPeerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ValidateRelayOnly bounds and validates a device-based direct deny list.
func ValidateRelayOnly(ids []string) error {
	if len(ids) > 4096 {
		return errors.New("too many overlay peer policies")
	}
	for _, id := range ids {
		if !ValidPeerID(id) {
			return errors.New("invalid overlay peer ID")
		}
	}
	return nil
}

// ValidateName accepts an optional, single-line advertised device name.
// Empty selects the hub's identity-derived default.
func ValidateName(name string) error {
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 128 || strings.TrimSpace(name) != name || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return errors.New("device name must be at most 128 characters without control characters or surrounding whitespace")
	}
	return nil
}

// DirectStatus describes the latest local direct connection attempt, not policy.
type DirectStatus string

const (
	DirectConnecting  DirectStatus = "connecting"
	DirectSucceeded   DirectStatus = "succeeded"
	DirectFailed      DirectStatus = "failed"
	DirectUnavailable DirectStatus = "unavailable"
	DirectCanceled    DirectStatus = "canceled"
)

// FlowPath is the transport of the last established flow.
type FlowPath string

const (
	PathDirect FlowPath = "direct"
	PathRelay  FlowPath = "relay"
)

// Peer is one other broadcasting account.
type Peer struct {
	// ID is the SHA-256 digest of the device's persistent public key.
	ID   string `json:"id,omitempty"`
	IP   string `json:"ip"`
	Name string `json:"name"`
	// Flow counts describe established local flows, never direct eligibility.
	DirectFlows int `json:"directFlows"`
	RelayFlows  int `json:"relayFlows"`
	// These are local observations. The hub's peer table is not their authority.
	DirectAllowed bool         `json:"directAllowed"`
	DirectStatus  DirectStatus `json:"directStatus,omitempty"`
	LastPath      FlowPath     `json:"lastPath,omitempty"`
}

// Incoming asks the destination agent to open an accept stream for a flow.
type Incoming struct {
	PeerID string `json:"peer_id,omitempty"`
	ID     string `json:"id"`
	Proto  string `json:"proto"`
	Src    string `json:"src"`
	Port   uint16 `json:"port"`

	// Fingerprint and Endpoint carry the requester's offer, when it made one.
	Fingerprint string `json:"fingerprint,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
}

// Event is any frame the hub pushes on a control stream after the Reply.
// Exactly one field is set.
type Event struct {
	Peers    *[]Peer   `json:"peers,omitempty"`
	Incoming *Incoming `json:"incoming,omitempty"`
	Pong     bool      `json:"pong,omitempty"`
}

// Ping is sent by the agent on a control stream to keep NAT state alive.
type Ping struct {
	Ping bool `json:"ping"`
}

// ErrUnavailable is the only reason the hub gives when a destination is
// missing, hidden or not allowed, so a requester cannot probe for hidden accounts.
const ErrUnavailable = "peer unavailable"

// State is the client-visible overlay status of one connected session.
// Available is false with a Reason when the engine or platform cannot carry
// the overlay; Broadcasting reports the connect-time choice.
type State struct {
	Available    bool   `json:"available"`
	Reason       string `json:"reason,omitempty"`
	Broadcasting bool   `json:"broadcasting"`
	Connected    bool   `json:"connected"` // control stream registered with the hub
	IP           string `json:"ip,omitempty"`
	Name         string `json:"name,omitempty"`
	Peers        []Peer `json:"peers"`
}

// WriteFrame writes one length-prefixed JSON frame.
func WriteFrame(w io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > UsableFrame {
		return fmt.Errorf("overlay frame size %d is out of bounds", len(payload))
	}
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(payload)), uint16(len(payload)))
	_, err = w.Write(append(frame, payload...))
	return err
}

// ReadFrame reads one length-prefixed JSON frame into value.
func ReadFrame(r io.Reader, value any) error {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size == 0 || size > MaxFrame {
		return errors.New("overlay frame size is out of bounds")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	return json.Unmarshal(payload, value)
}

// WriteDatagram writes one UDP payload as a 16-bit length-prefixed record.
func WriteDatagram(w io.Writer, payload []byte) error {
	if len(payload) > UsableDatagram {
		return errors.New("overlay datagram is too large")
	}
	_, err := w.Write(append(binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(payload)), uint16(len(payload))), payload...))
	return err
}

// ReadDatagram reads one record written by WriteDatagram into buffer.
func ReadDatagram(r io.Reader, buffer []byte) (int, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	size := int(binary.BigEndian.Uint16(header[:]))
	if size > len(buffer) {
		return 0, errors.New("overlay datagram exceeds buffer")
	}
	_, err := io.ReadFull(r, buffer[:size])
	return size, err
}

// Assignable reports whether address may be handed to an account.
func Assignable(address netip.Addr) bool {
	return AssignableIn(CIDR, address)
}
