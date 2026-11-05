package overlayagent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const (
	// defaultDirectTimeout bounds how long a direct connection may take to come up.
	defaultDirectTimeout = 10 * time.Second
	stunTimeout          = 3 * time.Second
	stunRetry            = 500 * time.Millisecond
	// punchEvery spaces the packets that open the NAT toward the peer.
	punchEvery = 200 * time.Millisecond
	// directIdle ends a direct connection that heard nothing from the peer.
	directIdle      = time.Minute
	directKeepAlive = 15 * time.Second
	// closeLinger gives the last bytes of a closed flow time to be acknowledged
	// before the QUIC connection ends.
	closeLinger = 3 * time.Second
	// flowStart is the first byte on a direct stream. QUIC announces a stream to
	// the peer only when data arrives, so the requester sends this byte to let
	// the destination accept the stream before the application has written.
	flowStart byte = 0x01
)

var (
	errUnknownFlow = errors.New("overlay direct connection is not expected")
	errNoEndpoint  = errors.New("overlay public endpoint is unknown")
	errDirectStart = errors.New("overlay direct stream did not start")

	// punchPacket opens the NAT. Its first two bits are zero, so QUIC treats it
	// as a non-QUIC packet and the receiver drops it.
	punchPacket = []byte{0x00, 'o', 'r', 'p', '1'}
)

// direct owns the UDP socket shared by STUN, hole punching and QUIC.
type direct struct {
	identity  *identity
	transport *quic.Transport
	listener  *quic.Listener
	socket    net.PacketConn
	stun      []string
	timeout   time.Duration
	config    *quic.Config

	mu       sync.Mutex
	expected map[string]*expectation
	probes   map[stunTransaction]chan netip.AddrPort
}

// expectation owns a flow's hole punching and, for incoming flows, its QUIC accept.
type expectation struct {
	owner       *direct
	id          string
	fingerprint string
	arrived     chan *quic.Conn
	endpoint    netip.AddrPort // protected by owner.mu; may learn a peer-facing NAT port
	observed    chan struct{}
}

// startDirect opens the socket and starts serving direct connections until ctx ends.
func startDirect(ctx context.Context, options *DirectOptions, id *identity) (*direct, error) {
	listen := options.ListenPacket
	if listen == nil {
		listen = func(ctx context.Context) (net.PacketConn, error) {
			var config net.ListenConfig
			return config.ListenPacket(ctx, "udp", ":0")
		}
	}
	socket, err := listen(ctx)
	if err != nil {
		return nil, err
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultDirectTimeout
	}
	d := &direct{
		identity:  id,
		transport: &quic.Transport{Conn: socket},
		socket:    socket,
		stun:      append([]string(nil), options.STUNServers...),
		timeout:   timeout,
		config: &quic.Config{
			HandshakeIdleTimeout: timeout,
			MaxIdleTimeout:       directIdle,
			KeepAlivePeriod:      directKeepAlive,
		},
		expected: map[string]*expectation{},
		probes:   map[stunTransaction]chan netip.AddrPort{},
	}
	serverConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{directALPN},
		// The flow id arrives as the server name and selects the pinned peer.
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			fingerprint, ok := d.fingerprintFor(hello.ServerName)
			if !ok {
				return nil, errUnknownFlow
			}
			return id.serverConfig(fingerprint, directALPN), nil
		},
	}
	listener, err := d.transport.Listen(serverConfig, d.config)
	if err != nil {
		_ = d.transport.Close()
		_ = socket.Close()
		return nil, err
	}
	d.listener = listener
	go d.acceptLoop(ctx)
	go d.readNonQUIC(ctx)
	context.AfterFunc(ctx, d.close)
	return d, nil
}

func (d *direct) close() {
	_ = d.listener.Close()
	_ = d.transport.Close()
	_ = d.socket.Close()
}

func (d *direct) fingerprintFor(id string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.expected[id]
	if !ok || exp.fingerprint == "" {
		return "", false
	}
	return exp.fingerprint, true
}

// acceptLoop hands each connected peer to the flow that expects it.
func (d *direct) acceptLoop(ctx context.Context) {
	for {
		conn, err := d.listener.Accept(ctx)
		if err != nil {
			return
		}
		d.mu.Lock()
		exp := d.expected[conn.ConnectionState().TLS.ServerName]
		d.mu.Unlock()
		if exp == nil {
			_ = conn.CloseWithError(0, "")
			continue
		}
		select {
		case exp.arrived <- conn:
		default:
			_ = conn.CloseWithError(0, "")
		}
	}
}

// readNonQUIC routes STUN responses to the query waiting for them.
func (d *direct) readNonQUIC(ctx context.Context) {
	buffer := make([]byte, 1500)
	for {
		n, from, err := d.transport.ReadNonQUICPacket(ctx, buffer)
		if err != nil {
			return
		}
		if d.observePunch(buffer[:n], from) {
			continue
		}
		tx, endpoint, err := parseSTUN(buffer[:n])
		if err != nil {
			continue
		}
		d.mu.Lock()
		reply := d.probes[tx]
		d.mu.Unlock()
		if reply != nil {
			select {
			case reply <- endpoint:
			default:
			}
		}
	}
}

// endpoint asks the STUN servers in order for this socket's public address.
func (d *direct) endpoint(ctx context.Context) (netip.AddrPort, error) {
	for _, server := range d.stun {
		address, err := net.ResolveUDPAddr("udp", server)
		if err != nil {
			continue
		}
		if endpoint, err := d.query(ctx, address); err == nil {
			return endpoint, nil
		}
	}
	return netip.AddrPort{}, errNoEndpoint
}

func (d *direct) query(ctx context.Context, server net.Addr) (netip.AddrPort, error) {
	var tx stunTransaction
	if _, err := rand.Read(tx[:]); err != nil {
		return netip.AddrPort{}, err
	}
	reply := make(chan netip.AddrPort, 1)
	d.mu.Lock()
	d.probes[tx] = reply
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.probes, tx)
		d.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, stunTimeout)
	defer cancel()
	request := stunRequest(tx)
	ticker := time.NewTicker(stunRetry)
	defer ticker.Stop()
	for {
		if _, err := d.transport.WriteTo(request, server); err != nil {
			return netip.AddrPort{}, err
		}
		select {
		case endpoint := <-reply:
			return unmap(endpoint), nil
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// unmap turns an IPv4-mapped IPv6 address back into IPv4.
func unmap(endpoint netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
}

// expect registers the flow id before the accept is sent, so the requester
// can never reach the listener ahead of the registration.
func (d *direct) expect(id, fingerprint, endpoint string) *expectation {
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil
	}
	exp := &expectation{owner: d, id: id, fingerprint: fingerprint, arrived: make(chan *quic.Conn, 1),
		endpoint: unmap(address), observed: make(chan struct{}, 1)}
	d.mu.Lock()
	d.expected[id] = exp
	d.mu.Unlock()
	return exp
}

// cancel forgets the expectation. It is safe to call more than once and on nil.
func (e *expectation) cancel() {
	if e == nil {
		return
	}
	e.owner.mu.Lock()
	delete(e.owner.expected, e.id)
	e.owner.mu.Unlock()
	select {
	case conn := <-e.arrived:
		_ = conn.CloseWithError(0, "")
	default:
	}
}

// await waits for the requester's QUIC connection and its first stream.
func (e *expectation) await(ctx context.Context, reply *overlay.Reply) (net.Conn, error) {
	d := e.owner
	if _, err := udpAddress(reply.Endpoint); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	go e.punch(ctx)
	select {
	case conn := <-e.arrived:
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			_ = conn.CloseWithError(0, "")
			return nil, err
		}
		var first [1]byte
		if _, err := io.ReadFull(stream, first[:]); err != nil || first[0] != flowStart {
			_ = conn.CloseWithError(0, "")
			return nil, errDirectStart
		}
		return newStreamConn(conn, stream), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// dial connects to the destination's endpoint and opens the flow's stream.
func (d *direct) dial(ctx context.Context, reply *overlay.Reply) (net.Conn, error) {
	// An outbound discovery must not authorize an incoming QUIC handshake.
	exp := d.expect(reply.ID, "", reply.Endpoint)
	if exp == nil {
		return nil, errNoEndpoint
	}
	defer exp.cancel()
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	go exp.punch(ctx)
	remote := exp.peerEndpoint(ctx)
	clientConfig := d.identity.clientConfig(reply.Fingerprint, reply.ID, directALPN)
	conn, err := d.transport.Dial(ctx, remote, clientConfig, d.config)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err == nil {
		_, err = stream.Write([]byte{flowStart})
	}
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	return newStreamConn(conn, stream), nil
}

func udpAddress(endpoint string) (net.Addr, error) {
	parsed, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, err
	}
	return net.UDPAddrFromAddrPort(unmap(parsed)), nil
}

// streamConn presents one QUIC stream as a net.Conn. Closing it sends the end
// of the stream, stops reading, and ends the connection after a short linger.
type streamConn struct {
	*quic.Stream
	conn       *quic.Conn
	closeWrite sync.Once
	closeAll   sync.Once
}

func newStreamConn(conn *quic.Conn, stream *quic.Stream) *streamConn {
	return &streamConn{Stream: stream, conn: conn}
}

func (c *streamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// CloseWrite ends this side's direction and leaves reading open.
func (c *streamConn) CloseWrite() error {
	var err error
	c.closeWrite.Do(func() { err = c.Stream.Close() })
	return err
}

// Close ends the flow. The QUIC connection stays up briefly so queued bytes
// reach the peer.
func (c *streamConn) Close() error {
	err := c.CloseWrite()
	c.CancelRead(0)
	c.closeAll.Do(func() {
		go func() {
			timer := time.NewTimer(closeLinger)
			defer timer.Stop()
			select {
			case <-c.conn.Context().Done():
			case <-timer.C:
				_ = c.conn.CloseWithError(0, "")
			}
		}()
	})
	return err
}
