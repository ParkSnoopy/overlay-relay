package overlayagent

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/quic-go/quic-go"
)

// linkServerName is the nominal TLS server name of a link. The peer is
// identified by its pinned certificate, never by this name.
const linkServerName = "overlay-link"

// iceMethod links two peers with a bare ICE agent: Pion ICE picks the UDP
// path and QUIC, pinned to both agents' flow certificates, secures it and
// multiplexes the flows. It needs no SDP and no data channel.
type iceMethod struct {
	state *directState
}

func (m *iceMethod) name() string { return methodICE }
func (m *iceMethod) syncs() bool  { return false }
func (m *iceMethod) close()       {}

// iceOffer is what each side sends: ICE credentials and gathered candidates.
type iceOffer struct {
	Ufrag      string   `json:"u"`
	Pwd        string   `json:"p"`
	Candidates []string `json:"c"`
}

type iceSession struct {
	method    *iceMethod
	peer      *linkPeer
	agent     *ice.Agent
	remote    iceOffer
	failed    chan struct{}
	failOnce  sync.Once
	closeOnce sync.Once
}

func (m *iceMethod) session(peer *linkPeer) (*iceSession, error) {
	agent, err := ice.NewAgentWithOptions(
		ice.WithNet(m.state.network),
		ice.WithUrls(m.state.servers),
		ice.WithNetworkTypes([]ice.NetworkType{ice.NetworkTypeUDP4}),
		ice.WithCandidateTypes([]ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}),
		ice.WithMulticastDNSMode(ice.MulticastDNSModeDisabled),
		ice.WithDisconnectedTimeout(iceDisconnected),
		ice.WithFailedTimeout(iceFailed),
		ice.WithKeepaliveInterval(iceKeepAlive),
	)
	if err != nil {
		return nil, err
	}
	s := &iceSession{method: m, peer: peer, agent: agent, failed: make(chan struct{})}
	err = agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		if state == ice.ConnectionStateFailed || state == ice.ConnectionStateClosed {
			s.failOnce.Do(func() { close(s.failed) })
		}
	})
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// gather returns this side's credentials and candidates once gathering ends or times out.
func (s *iceSession) gather(ctx context.Context) (json.RawMessage, error) {
	var (
		mu         sync.Mutex
		candidates []string
	)
	complete := make(chan struct{})
	err := s.agent.OnCandidate(func(candidate ice.Candidate) {
		if candidate == nil {
			close(complete)
			return
		}
		mu.Lock()
		candidates = append(candidates, candidate.Marshal())
		mu.Unlock()
	})
	if err == nil {
		err = s.agent.GatherCandidates()
	}
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(gatherTimeout)
	defer timer.Stop()
	select {
	case <-complete:
	case <-timer.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	ufrag, pwd, err := s.agent.GetLocalUserCredentials()
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	if len(candidates) == 0 {
		return nil, errNoAddress
	}
	return json.Marshal(iceOffer{Ufrag: ufrag, Pwd: pwd, Candidates: candidates})
}

func (s *iceSession) apply(data json.RawMessage) error {
	var remote iceOffer
	if err := json.Unmarshal(data, &remote); err != nil || remote.Ufrag == "" || remote.Pwd == "" || len(remote.Candidates) == 0 {
		return errors.New("invalid ICE description")
	}
	for _, raw := range remote.Candidates {
		candidate, err := ice.UnmarshalCandidate(raw)
		if err != nil {
			continue
		}
		if err := s.agent.AddRemoteCandidate(candidate); err != nil {
			continue
		}
	}
	s.remote = remote
	return nil
}

func (m *iceMethod) offer(ctx context.Context, peer *linkPeer) (session, json.RawMessage, error) {
	s, err := m.session(peer)
	if err != nil {
		return nil, nil, err
	}
	data, err := s.gather(ctx)
	if err != nil {
		s.close()
		return nil, nil, err
	}
	return s, data, nil
}

func (m *iceMethod) answer(ctx context.Context, peer *linkPeer, offer json.RawMessage) (session, json.RawMessage, error) {
	s, err := m.session(peer)
	if err != nil {
		return nil, nil, err
	}
	if err := s.apply(offer); err != nil {
		s.close()
		return nil, nil, err
	}
	data, err := s.gather(ctx)
	if err != nil {
		s.close()
		return nil, nil, err
	}
	return s, data, nil
}

func (s *iceSession) connect(ctx context.Context) (link, error) {
	var (
		conn *ice.Conn
		err  error
	)
	if s.peer.initiator {
		conn, err = s.agent.Dial(ctx, s.remote.Ufrag, s.remote.Pwd)
	} else {
		conn, err = s.agent.Accept(ctx, s.remote.Ufrag, s.remote.Pwd)
	}
	if err != nil {
		return nil, err
	}
	state := s.method.state
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	transport := &quic.Transport{Conn: &pairConn{Conn: conn, remote: remote}}
	config := &quic.Config{HandshakeIdleTimeout: state.timeout, MaxIdleTimeout: directIdle, KeepAlivePeriod: directKeepAlive}
	var connection *quic.Conn
	if s.peer.initiator {
		connection, err = transport.Dial(ctx, remote, state.identity.clientConfig(s.peer.fingerprint, linkServerName, directALPN), config)
	} else {
		var listener *quic.Listener
		listener, err = transport.Listen(state.identity.serverConfig(s.peer.fingerprint, directALPN), config)
		if err == nil {
			connection, err = listener.Accept(ctx)
			_ = listener.Close()
		}
	}
	if err != nil {
		_ = transport.Close()
		_ = conn.Close()
		return nil, err
	}
	l := &quicLink{connection: connection, peerID: s.peer.id}
	l.linkBase = newLinkBase(methodICE, func() {
		_ = connection.CloseWithError(0, "")
		_ = transport.Close()
		_ = conn.Close()
		s.close()
	})
	go func() {
		select {
		case <-connection.Context().Done():
		case <-s.failed:
		}
		l.close()
	}()
	return l, nil
}

func (s *iceSession) close() {
	s.closeOnce.Do(func() { _ = s.agent.Close() })
}

// pairConn presents the single ICE path as a packet socket for QUIC.
type pairConn struct {
	*ice.Conn
	remote net.Addr
}

func (c *pairConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.remote, err
}

func (c *pairConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Conn.Write(p) }

// quicLink multiplexes flows over one QUIC connection.
type quicLink struct {
	*linkBase
	connection *quic.Conn
	peerID     string
}

func (l *quicLink) open(ctx context.Context) (net.Conn, error) {
	stream, err := l.connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return newStreamConn(&quicStream{Stream: stream}, l.peerID), nil
}

func (l *quicLink) accept(ctx context.Context) (net.Conn, error) {
	stream, err := l.connection.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return newStreamConn(&quicStream{Stream: stream}, l.peerID), nil
}

// quicStream adds the half-close contract flows expect. Closing a stream
// leaves the connection and its other streams alone.
type quicStream struct {
	*quic.Stream
}

func (s *quicStream) CloseWrite() error { return s.Stream.Close() }

func (s *quicStream) Close() error {
	err := s.Stream.Close()
	s.CancelRead(0)
	return err
}
