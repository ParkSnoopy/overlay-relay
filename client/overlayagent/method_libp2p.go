package overlayagent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/control"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	libp2pProtocol protocol.ID = "/overlay-relay/link/1"
	// libp2pRedial spaces the dials that punch the NAT while a link comes up.
	libp2pRedial = time.Second
)

// libp2pMethod links two peers with a libp2p host over QUIC. Both hosts dial
// each other at the same moment, which is the hole punch libp2p's DCUtR
// performs; the relayed negotiation stream replaces the circuit relay that
// would otherwise coordinate it. Each attempt uses a fresh random peer ID that
// travels over that authenticated stream, and the host accepts only that ID.
type libp2pMethod struct {
	state *directState
}

func (m *libp2pMethod) name() string { return methodLibp2p }
func (m *libp2pMethod) syncs() bool  { return true }
func (m *libp2pMethod) close()       {}

type libp2pOffer struct {
	ID    string   `json:"i"`
	Addrs []string `json:"a"`
}

type libp2pSession struct {
	method *libp2pMethod
	peer   *linkPeer
	host   host.Host
	socket *stunConn
	gate   *pinGate
	remote peer.AddrInfo

	connected chan struct{}
	lost      chan struct{}
	streams   chan network.Stream
	once      sync.Once
	closed    sync.Once
}

// pinGate admits only the one peer ID the negotiation named.
type pinGate struct {
	mu   sync.Mutex
	want peer.ID
}

func (g *pinGate) pin(id peer.ID) {
	g.mu.Lock()
	g.want = id
	g.mu.Unlock()
}

func (g *pinGate) allowed(id peer.ID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.want != "" && id == g.want
}

func (g *pinGate) InterceptPeerDial(id peer.ID) bool                 { return g.allowed(id) }
func (g *pinGate) InterceptAddrDial(id peer.ID, _ ma.Multiaddr) bool { return g.allowed(id) }
func (g *pinGate) InterceptAccept(network.ConnMultiaddrs) bool       { return true }
func (g *pinGate) InterceptSecured(_ network.Direction, id peer.ID, _ network.ConnMultiaddrs) bool {
	return g.allowed(id)
}
func (g *pinGate) InterceptUpgraded(network.Conn) (bool, control.DisconnectReason) { return true, 0 }

var _ connmgr.ConnectionGater = (*pinGate)(nil)

func (m *libp2pMethod) session(ctx context.Context, p *linkPeer) (*libp2pSession, error) {
	key, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	s := &libp2pSession{
		method: m, peer: p, gate: &pinGate{},
		connected: make(chan struct{}), lost: make(chan struct{}), streams: make(chan network.Stream, 16),
	}
	listen := func(_ string, _ *net.UDPAddr) (net.PacketConn, error) {
		socket, err := m.state.listenSocket(ctx)
		if err != nil {
			return nil, err
		}
		s.socket = socket
		return socket, nil
	}
	h, err := libp2p.New(
		libp2p.Identity(key),
		libp2p.NoTransports,
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.QUICReuse(quicreuse.NewConnManager, quicreuse.OverrideListenUDP(listen)),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/udp/0/quic-v1"),
		libp2p.ConnectionGater(s.gate),
		libp2p.ResourceManager(&network.NullResourceManager{}),
		libp2p.DisableRelay(),
		libp2p.DisableMetrics(),
		libp2p.DisableIdentifyAddressDiscovery(),
	)
	if err != nil {
		return nil, err
	}
	s.host = h
	h.SetStreamHandler(libp2pProtocol, func(stream network.Stream) {
		if stream.Conn().RemotePeer() != s.remote.ID {
			_ = stream.Reset()
			return
		}
		select {
		case s.streams <- stream:
		default:
			_ = stream.Reset()
		}
	})
	h.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(_ network.Network, conn network.Conn) {
			if conn.RemotePeer() == s.remote.ID {
				s.once.Do(func() { close(s.connected) })
			}
		},
		DisconnectedF: func(n network.Network, conn network.Conn) {
			if conn.RemotePeer() == s.remote.ID && n.Connectedness(conn.RemotePeer()) != network.Connected {
				select {
				case <-s.connected:
					// Host.Close waits for this callback, so it must not close the host inline.
					go s.close()
				default:
				}
			}
		},
	})
	if s.socket == nil {
		s.close()
		return nil, errNoAddress
	}
	return s, nil
}

// addresses lists where the peer can reach this host: the public mapping
// STUN reports, then the local interface addresses for peers on the same LAN.
func (s *libp2pSession) addresses(ctx context.Context) ([]string, error) {
	port := s.socket.LocalAddr().(*net.UDPAddr).Port
	var addrs []string
	if public, err := s.socket.query(ctx, s.method.state.servers); err == nil {
		addrs = append(addrs, quicAddr(public))
	}
	interfaces, _ := net.InterfaceAddrs()
	for _, candidate := range interfaces {
		prefix, err := netip.ParsePrefix(candidate.String())
		if err != nil || !prefix.Addr().Is4() || prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() {
			continue
		}
		addrs = append(addrs, quicAddr(netip.AddrPortFrom(prefix.Addr(), uint16(port))))
	}
	if len(addrs) == 0 {
		return nil, errNoAddress
	}
	return addrs, nil
}

func quicAddr(endpoint netip.AddrPort) string {
	return "/ip4/" + endpoint.Addr().String() + "/udp/" + itoa(int(endpoint.Port())) + "/quic-v1"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [8]byte
	i := len(digits)
	for ; n > 0; n /= 10 {
		i--
		digits[i] = byte('0' + n%10)
	}
	return string(digits[i:])
}

func (s *libp2pSession) describe(ctx context.Context) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, gatherTimeout)
	defer cancel()
	addrs, err := s.addresses(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(libp2pOffer{ID: s.host.ID().String(), Addrs: addrs})
}

func (s *libp2pSession) apply(data json.RawMessage) error {
	var remote libp2pOffer
	if err := json.Unmarshal(data, &remote); err != nil {
		return errors.New("invalid libp2p description")
	}
	id, err := peer.Decode(remote.ID)
	if err != nil || len(remote.Addrs) == 0 || len(remote.Addrs) > 16 || id == s.host.ID() {
		return errors.New("invalid libp2p description")
	}
	info := peer.AddrInfo{ID: id}
	for _, raw := range remote.Addrs {
		addr, err := ma.NewMultiaddr(raw)
		if err != nil {
			continue
		}
		info.Addrs = append(info.Addrs, addr)
	}
	if len(info.Addrs) == 0 {
		return errors.New("invalid libp2p description")
	}
	s.remote = info
	s.gate.pin(id)
	return nil
}

func (m *libp2pMethod) offer(ctx context.Context, p *linkPeer) (session, json.RawMessage, error) {
	s, err := m.session(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	data, err := s.describe(ctx)
	if err != nil {
		s.close()
		return nil, nil, err
	}
	return s, data, nil
}

func (m *libp2pMethod) answer(ctx context.Context, p *linkPeer, offer json.RawMessage) (session, json.RawMessage, error) {
	s, err := m.session(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	if err := s.apply(offer); err != nil {
		s.close()
		return nil, nil, err
	}
	data, err := s.describe(ctx)
	if err != nil {
		s.close()
		return nil, nil, err
	}
	return s, data, nil
}

// connect dials the peer repeatedly until a connection forms in either direction.
func (s *libp2pSession) connect(ctx context.Context) (link, error) {
	go func() {
		ticker := time.NewTicker(libp2pRedial)
		defer ticker.Stop()
		for {
			dialCtx, cancel := context.WithTimeout(ctx, libp2pRedial*4)
			_ = s.host.Connect(dialCtx, s.remote)
			cancel()
			select {
			case <-s.connected:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	select {
	case <-s.connected:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	l := &libp2pLink{session: s}
	l.linkBase = newLinkBase(methodLibp2p, s.close)
	go func() {
		<-s.lost
		l.close()
	}()
	return l, nil
}

func (s *libp2pSession) close() {
	s.closed.Do(func() {
		close(s.lost)
		_ = s.host.Close()
	})
}

// libp2pLink opens one libp2p stream per flow.
type libp2pLink struct {
	*linkBase
	session *libp2pSession
}

func (l *libp2pLink) open(ctx context.Context) (net.Conn, error) {
	stream, err := l.session.host.NewStream(ctx, l.session.remote.ID, libp2pProtocol)
	if err != nil {
		return nil, err
	}
	return newStreamConn(&libp2pStream{Stream: stream}, l.session.peer.id), nil
}

func (l *libp2pLink) accept(ctx context.Context) (net.Conn, error) {
	select {
	case stream := <-l.session.streams:
		return newStreamConn(&libp2pStream{Stream: stream}, l.session.peer.id), nil
	case <-l.session.lost:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// libp2pStream adds the half-close contract flows expect.
type libp2pStream struct {
	network.Stream
}

func (s *libp2pStream) CloseWrite() error { return s.Stream.CloseWrite() }

func (s *libp2pStream) Close() error {
	return errors.Join(s.Stream.CloseWrite(), s.Stream.CloseRead())
}
