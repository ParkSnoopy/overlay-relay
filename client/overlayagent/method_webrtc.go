package overlayagent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/pion/datachannel"
	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

const (
	// dataChunk is the largest message written to the data channel. It stays
	// below the 64 KiB SCTP limit every peer accepts.
	dataChunk = 16 * 1024
	// dataBuffer holds one whole incoming message; a short read buffer would drop it.
	dataBuffer = 64 * 1024
)

// webrtcMethod links two peers with a WebRTC data channel: ICE finds the path,
// DTLS secures it, and a stream multiplexer carries the flows. The SDP travels
// over the relayed negotiation stream, which pins both agents' certificates.
type webrtcMethod struct {
	state *directState
}

func (m *webrtcMethod) name() string { return methodWebRTC }
func (m *webrtcMethod) syncs() bool  { return false }
func (m *webrtcMethod) close()       {}

func (m *webrtcMethod) newConnection() (*webrtc.PeerConnection, error) {
	engine := webrtc.SettingEngine{}
	engine.SetNet(m.state.network)
	engine.DetachDataChannels()
	engine.SetICETimeouts(iceDisconnected, iceFailed, iceKeepAlive)
	engine.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	engine.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(engine))
	servers := make([]string, len(m.state.servers))
	for i, server := range m.state.servers {
		servers[i] = server.String()
	}
	return api.NewPeerConnection(webrtc.Configuration{ICEServers: []webrtc.ICEServer{{URLs: servers}}})
}

// webrtcSession is one WebRTC attempt.
type webrtcSession struct {
	method    *webrtcMethod
	peer      *linkPeer
	pc        *webrtc.PeerConnection
	opened    chan *dataConn
	failed    chan struct{}
	failOnce  sync.Once
	closeOnce sync.Once
}

func (m *webrtcMethod) session(peer *linkPeer) (*webrtcSession, error) {
	pc, err := m.newConnection()
	if err != nil {
		return nil, err
	}
	s := &webrtcSession{method: m, peer: peer, pc: pc, opened: make(chan *dataConn, 1), failed: make(chan struct{})}
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			s.failOnce.Do(func() { close(s.failed) })
		}
	})
	return s, nil
}

// watch hands the detached channel to connect once it opens.
func (s *webrtcSession) watch(channel *webrtc.DataChannel) {
	channel.OnOpen(func() {
		raw, err := channel.DetachWithDeadline()
		if err != nil {
			s.failOnce.Do(func() { close(s.failed) })
			return
		}
		select {
		case s.opened <- newDataConn(raw):
		default:
			_ = raw.Close()
		}
	})
}

// describe returns the local description once candidate gathering ends or times out.
func (s *webrtcSession) describe(ctx context.Context) (json.RawMessage, error) {
	gathered := webrtc.GatheringCompletePromise(s.pc)
	timer := time.NewTimer(gatherTimeout)
	defer timer.Stop()
	select {
	case <-gathered:
	case <-timer.C:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return json.Marshal(s.pc.LocalDescription())
}

func (m *webrtcMethod) offer(ctx context.Context, peer *linkPeer) (session, json.RawMessage, error) {
	s, err := m.session(peer)
	if err != nil {
		return nil, nil, err
	}
	channel, err := s.pc.CreateDataChannel("overlay", nil)
	if err != nil {
		s.close()
		return nil, nil, err
	}
	s.watch(channel)
	offer, err := s.pc.CreateOffer(nil)
	if err == nil {
		err = s.pc.SetLocalDescription(offer)
	}
	if err != nil {
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

func (m *webrtcMethod) answer(ctx context.Context, peer *linkPeer, offer json.RawMessage) (session, json.RawMessage, error) {
	var remote webrtc.SessionDescription
	if err := json.Unmarshal(offer, &remote); err != nil || remote.Type != webrtc.SDPTypeOffer {
		return nil, nil, errors.New("invalid WebRTC offer")
	}
	s, err := m.session(peer)
	if err != nil {
		return nil, nil, err
	}
	s.pc.OnDataChannel(s.watch)
	if err := s.pc.SetRemoteDescription(remote); err != nil {
		s.close()
		return nil, nil, err
	}
	reply, err := s.pc.CreateAnswer(nil)
	if err == nil {
		err = s.pc.SetLocalDescription(reply)
	}
	if err != nil {
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

func (s *webrtcSession) apply(answer json.RawMessage) error {
	var remote webrtc.SessionDescription
	if err := json.Unmarshal(answer, &remote); err != nil || remote.Type != webrtc.SDPTypeAnswer {
		return errors.New("invalid WebRTC answer")
	}
	return s.pc.SetRemoteDescription(remote)
}

func (s *webrtcSession) connect(ctx context.Context) (link, error) {
	select {
	case raw := <-s.opened:
		return s.link(raw)
	case <-s.failed:
		return nil, errDirectFailed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *webrtcSession) link(raw *dataConn) (link, error) {
	config := yamux.DefaultConfig()
	config.LogOutput = io.Discard
	config.MaxMessageSize = dataChunk
	var (
		session *yamux.Session
		err     error
	)
	if s.peer.initiator {
		session, err = yamux.Client(raw, config, nil)
	} else {
		session, err = yamux.Server(raw, config, nil)
	}
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	l := &yamuxLink{session: session, peerID: s.peer.id}
	l.linkBase = newLinkBase(methodWebRTC, func() {
		// Closing the peer connection first ends the SCTP reads the session waits on.
		s.close()
		_ = session.Close()
	})
	go func() {
		select {
		case <-session.CloseChan():
		case <-s.failed:
		}
		l.close()
	}()
	return l, nil
}

func (s *webrtcSession) close() {
	s.closeOnce.Do(func() { _ = s.pc.Close() })
}

// yamuxLink multiplexes flows over one reliable byte pipe.
type yamuxLink struct {
	*linkBase
	session *yamux.Session
	peerID  string
}

func (l *yamuxLink) open(context.Context) (net.Conn, error) {
	stream, err := l.session.OpenStream(context.Background())
	if err != nil {
		return nil, err
	}
	return newStreamConn(stream, l.peerID), nil
}

func (l *yamuxLink) accept(context.Context) (net.Conn, error) {
	stream, err := l.session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return newStreamConn(stream, l.peerID), nil
}

// dataConn presents a detached data channel as a net.Conn. The channel keeps
// message boundaries, so reads buffer a whole message and hand it out in
// pieces, and writes split into chunks below the SCTP message limit.
type dataConn struct {
	channel datachannel.ReadWriteCloserDeadliner
	rmu     sync.Mutex
	buffer  []byte
	pending []byte
	wmu     sync.Mutex
}

func newDataConn(channel datachannel.ReadWriteCloserDeadliner) *dataConn {
	return &dataConn{channel: channel, buffer: make([]byte, dataBuffer)}
}

func (c *dataConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		n, err := c.channel.Read(c.buffer)
		if err != nil {
			return 0, err
		}
		c.pending = c.buffer[:n]
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *dataConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), dataChunk)]
		n, err := c.channel.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
		p = p[len(chunk):]
	}
	return written, nil
}

// Close also ends a Read that waits on a silent peer; SCTP would block it otherwise.
func (c *dataConn) Close() error {
	_ = c.channel.SetReadDeadline(time.Unix(1, 0))
	return c.channel.Close()
}
func (c *dataConn) LocalAddr() net.Addr                { return namedAddr("webrtc") }
func (c *dataConn) RemoteAddr() net.Addr               { return namedAddr("webrtc") }
func (c *dataConn) SetReadDeadline(t time.Time) error  { return c.channel.SetReadDeadline(t) }
func (c *dataConn) SetWriteDeadline(t time.Time) error { return c.channel.SetWriteDeadline(t) }
func (c *dataConn) SetDeadline(t time.Time) error {
	return errors.Join(c.channel.SetReadDeadline(t), c.channel.SetWriteDeadline(t))
}
