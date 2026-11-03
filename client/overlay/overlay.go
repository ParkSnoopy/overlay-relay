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
	Version = 2
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
	Version   int    `json:"version"`
	Kind      string `json:"kind"`
	PublicKey string `json:"public_key"`
	Proto     string `json:"proto,omitempty"` // open
	Dst       string `json:"dst,omitempty"`   // open: destination overlay IP
	Port      uint16 `json:"port,omitempty"`  // open: destination port
	ID        string `json:"id,omitempty"`    // accept: Incoming.ID

	// Fingerprint is the SHA-256 of the sender's flow certificate, as 64 hex
	// digits. Sending it offers an end-to-end encrypted flow (open, accept).
	Fingerprint string `json:"fingerprint,omitempty"`
	// Endpoint is the sender's public UDP address, ip:port. Sending it with a
	// fingerprint offers a direct connection (open, accept).
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

// Peer is one other broadcasting account.
type Peer struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

// Incoming asks the destination agent to open an accept stream for a flow.
type Incoming struct {
	ID    string `json:"id"`
	Proto string `json:"proto"`
	Src   string `json:"src"`
	Port  uint16 `json:"port"`

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
	if !CIDR.Contains(address) || !address.Is4() {
		return false
	}
	b := address.As4()
	return (b[2] != 0 || b[3] != 0) && (b[2] != 255 || b[3] != 255)
}
