package overlayagent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"time"

	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5"
	"github.com/pion/transport/v5/stdnet"
)

const (
	methodWebRTC = "webrtc"
	methodICE    = "ice"
	methodLibp2p = "libp2p"

	// defaultDirectTimeout bounds how long one method may take to come up.
	defaultDirectTimeout = 10 * time.Second
	// gatherTimeout bounds candidate gathering, which includes STUN lookups.
	gatherTimeout = 3 * time.Second
	// iceDisconnected and iceFailed bound how long a silent path survives.
	iceDisconnected = 5 * time.Second
	iceFailed       = 15 * time.Second
	iceKeepAlive    = 2 * time.Second
	// directIdle ends a QUIC link that heard nothing from the peer.
	directIdle      = time.Minute
	directKeepAlive = 15 * time.Second
)

var (
	errNoMethod  = errors.New("overlay peer shares no direct connection method")
	errNoAddress = errors.New("overlay has no direct candidate address")
)

// defaultMethods is the order in which direct methods are tried.
var defaultMethods = []string{methodWebRTC, methodICE, methodLibp2p}

// DirectOptions configures direct links. Two peers that both enable it
// negotiate a link over the encrypted relay and, once it is up, carry new
// flows on it instead of the hub. The relay keeps serving every flow that
// opens before a link exists or after one fails. It needs encryption.
type DirectOptions struct {
	// STUNServers lists host:port STUN servers asked from outside the VPN to
	// learn public UDP addresses. At least one is required.
	STUNServers []string
	// ListenPacket opens an IPv4 UDP socket. Every direct method calls it for
	// each socket it needs. Return a socket that bypasses the VPN. Nil listens
	// on all addresses, any port.
	ListenPacket func(ctx context.Context) (net.PacketConn, error)
	// Timeout bounds each method's connection attempt. Zero means ten seconds.
	Timeout time.Duration
	// Methods lists the methods to try, in order: "webrtc", "ice" and "libp2p".
	// Nil tries all of them in that order.
	Methods []string
	// Net replaces the operating system network stack of the ICE based methods.
	// It exists for network simulation; nil uses ListenPacket and the host stack.
	Net transport.Net
}

// session is one method's attempt to bring up a link with one peer.
type session interface {
	// apply gives the initiator the peer's answer. The responder never calls it.
	apply(answer json.RawMessage) error
	// connect blocks until the link is up or ctx ends.
	connect(ctx context.Context) (link, error)
	// close releases everything the attempt holds. It is safe after connect.
	close()
}

// linkPeer is what a method may know about the other end.
type linkPeer struct {
	id          string
	fingerprint string // the peer's flow certificate fingerprint, authenticated by the relay stream
	initiator   bool
}

// method is one way to bring up a direct link.
type method interface {
	name() string
	// syncs reports whether both sides must start at (nearly) the same moment.
	syncs() bool
	// offer starts the initiator's side and returns its offer.
	offer(ctx context.Context, peer *linkPeer) (session, json.RawMessage, error)
	// answer starts the responder's side and returns its answer.
	answer(ctx context.Context, peer *linkPeer, offer json.RawMessage) (session, json.RawMessage, error)
	// close releases state shared by all attempts.
	close()
}

// directState holds what every direct method shares.
type directState struct {
	options  *DirectOptions
	identity *identity
	timeout  time.Duration
	network  transport.Net
	servers  []*stun.URI
	methods  []method
}

func newDirectState(options *DirectOptions, id *identity) (*directState, error) {
	d := &directState{options: options, identity: id, timeout: options.Timeout}
	if d.timeout <= 0 {
		d.timeout = defaultDirectTimeout
	}
	for _, server := range options.STUNServers {
		uri, err := stun.ParseURI("stun:" + server)
		if err != nil {
			return nil, err
		}
		d.servers = append(d.servers, uri)
	}
	if len(d.servers) == 0 {
		return nil, errNoAddress
	}
	d.network = options.Net
	if d.network == nil {
		std, err := stdnet.NewNet()
		if err != nil {
			return nil, err
		}
		d.network = &hostNet{Net: std, listen: options.ListenPacket}
	}
	names := options.Methods
	if names == nil {
		names = defaultMethods
	}
	for _, name := range names {
		switch name {
		case methodWebRTC:
			d.methods = append(d.methods, &webrtcMethod{state: d})
		case methodICE:
			d.methods = append(d.methods, &iceMethod{state: d})
		case methodLibp2p:
			d.methods = append(d.methods, &libp2pMethod{state: d})
		}
	}
	return d, nil
}

func (d *directState) names() []string {
	names := make([]string, len(d.methods))
	for i, m := range d.methods {
		names[i] = m.name()
	}
	return names
}

func (d *directState) method(name string) method {
	for _, m := range d.methods {
		if m.name() == name {
			return m
		}
	}
	return nil
}

func (d *directState) close() {
	for _, m := range d.methods {
		m.close()
	}
}

// common returns this side's methods that the other side also offers, in this side's order.
func (d *directState) common(theirs []string) []string {
	var shared []string
	for _, name := range d.names() {
		if slices.Contains(theirs, name) {
			shared = append(shared, name)
		}
	}
	return shared
}

// hostNet is the host network stack, except that UDP sockets come from the
// caller's ListenPacket so they bypass the VPN.
type hostNet struct {
	*stdnet.Net
	listen func(ctx context.Context) (net.PacketConn, error)
}

func (n *hostNet) ListenPacket(network, address string) (net.PacketConn, error) {
	if n.listen == nil {
		return n.Net.ListenPacket(network, address)
	}
	if network != "udp" && network != "udp4" {
		return nil, errors.New("overlay direct sockets are IPv4 only")
	}
	return n.listen(context.Background())
}

func (n *hostNet) ListenUDP(network string, address *net.UDPAddr) (transport.UDPConn, error) {
	if n.listen == nil {
		return n.Net.ListenUDP(network, address)
	}
	socket, err := n.ListenPacket(network, "")
	if err != nil {
		return nil, err
	}
	if udp, ok := socket.(transport.UDPConn); ok {
		return udp, nil
	}
	return &udpAdapter{PacketConn: socket}, nil
}

// udpAdapter gives a plain packet socket the UDP socket surface ICE expects.
type udpAdapter struct {
	net.PacketConn
}

var errUnconnected = errors.New("overlay direct socket has no peer")

func (c *udpAdapter) RemoteAddr() net.Addr { return nil }

func (c *udpAdapter) Read([]byte) (int, error)  { return 0, errUnconnected }
func (c *udpAdapter) Write([]byte) (int, error) { return 0, errUnconnected }

func (c *udpAdapter) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	n, from, err := c.ReadFrom(b)
	udp, _ := from.(*net.UDPAddr)
	return n, udp, err
}

func (c *udpAdapter) ReadMsgUDP(b, _ []byte) (int, int, int, *net.UDPAddr, error) {
	n, from, err := c.ReadFromUDP(b)
	return n, 0, 0, from, err
}

func (c *udpAdapter) WriteToUDP(b []byte, to *net.UDPAddr) (int, error) { return c.WriteTo(b, to) }

func (c *udpAdapter) WriteMsgUDP(b, _ []byte, to *net.UDPAddr) (int, int, error) {
	n, err := c.WriteTo(b, to)
	return n, 0, err
}

func (c *udpAdapter) SetReadBuffer(n int) error {
	if s, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return s.SetReadBuffer(n)
	}
	return nil
}

func (c *udpAdapter) SetWriteBuffer(n int) error {
	if s, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return s.SetWriteBuffer(n)
	}
	return nil
}
