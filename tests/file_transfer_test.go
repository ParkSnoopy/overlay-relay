package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
	"github.com/ParkSnoopy/overlay-relay/client/overlayagent"
)

// A file travels as a header, then its bytes, then a SHA-256 digest back to the
// sender. The header holds the byte size (uint64) and the name length (uint16),
// followed by the name.
//
// Stream flows send the header, the raw bytes and the digest.
// Datagram flows send the header, then one chunk per overlay record, cut at
// overlay.UsableFrame bytes. The receiver acknowledges the header and every chunk
// but the last, so the sender never outruns the local datagram socket.
const (
	ackByte     byte = 0x06
	headerFixed      = 8 + 2
)

// encodeHeader builds the file header for one transfer.
func encodeHeader(name string, size int64) []byte {
	buffer := binary.BigEndian.AppendUint64(nil, uint64(size))
	buffer = binary.BigEndian.AppendUint16(buffer, uint16(len(name)))
	return append(buffer, name...)
}

// parseHeader validates a complete header and returns the file name and size.
func parseHeader(data []byte) (fileName string, fileSize int64, err error) {
	if len(data) <= headerFixed {
		return "", 0, errors.New("file header is truncated")
	}
	size := int64(binary.BigEndian.Uint64(data[:8]))
	nameLen := int(binary.BigEndian.Uint16(data[8:headerFixed]))
	name := string(data[headerFixed:])
	if nameLen == 0 || len(data) != headerFixed+nameLen || size < 0 {
		return "", 0, errors.New("file header is malformed")
	}
	if name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", 0, errors.New("file name is not a plain base name")
	}
	return name, size, nil
}

// readStreamHeader reads one header from a byte stream.
func readStreamHeader(r io.Reader) (fileName string, fileSize int64, err error) {
	fixed := make([]byte, headerFixed)
	if _, err := io.ReadFull(r, fixed); err != nil {
		return "", 0, err
	}
	rest := make([]byte, binary.BigEndian.Uint16(fixed[8:]))
	if _, err := io.ReadFull(r, rest); err != nil {
		return "", 0, err
	}
	return parseHeader(append(fixed, rest...))
}

// fileSink stores files received from the peer. It serves both flow kinds on
// loopback, and the agent under test dials it as the local service.
type fileSink struct {
	dir string
	tcp net.Listener
	udp net.PacketConn
}

func startSink(t *testing.T, dir string) *fileSink {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tcp.Close()
		_ = udp.Close()
	})
	go serveStreams(tcp, dir)
	go serveDatagrams(udp, dir)
	return &fileSink{dir: dir, tcp: tcp, udp: udp}
}

func serveStreams(listener net.Listener, dir string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			// A failure reaches the sender as a missing or wrong digest.
			_ = receiveStream(conn, dir)
		}()
	}
}

func receiveStream(conn net.Conn, dir string) error {
	name, size, err := readStreamHeader(conn)
	if err != nil {
		return err
	}
	file, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	digest := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(file, digest), conn, size); err != nil {
		return err
	}
	_, err = conn.Write(digest.Sum(nil))
	return err
}

func serveDatagrams(pc net.PacketConn, dir string) {
	for {
		if err := receiveDatagrams(pc, dir); errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

func receiveDatagrams(pc net.PacketConn, dir string) error {
	buffer := make([]byte, 64<<10)
	n, peer, err := pc.ReadFrom(buffer)
	if err != nil {
		return err
	}
	name, size, err := parseHeader(buffer[:n])
	if err != nil {
		return err
	}
	file, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if _, err := pc.WriteTo([]byte{ackByte}, peer); err != nil {
		return err
	}
	digest := sha256.New()
	for remaining := size; remaining > 0; {
		n, _, err := pc.ReadFrom(buffer)
		if err != nil {
			return err
		}
		if int64(n) > remaining {
			return errors.New("chunk exceeds the declared size")
		}
		if _, err := file.Write(buffer[:n]); err != nil {
			return err
		}
		_, _ = digest.Write(buffer[:n])
		remaining -= int64(n)
		if remaining > 0 {
			if _, err := pc.WriteTo([]byte{ackByte}, peer); err != nil {
				return err
			}
		}
	}
	_, err = pc.WriteTo(digest.Sum(nil), peer)
	return err
}

// sendStream sends one file over a stream flow and checks the digest reply.
func sendStream(flow net.Conn, source io.Reader, name string, size int64) (int, error) {
	if _, err := flow.Write(encodeHeader(name, size)); err != nil {
		return 0, err
	}
	digest := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(flow, digest), source, size); err != nil {
		return 0, err
	}
	reply := make([]byte, sha256.Size)
	if _, err := io.ReadFull(flow, reply); err != nil {
		return 0, err
	}
	if !bytes.Equal(reply, digest.Sum(nil)) {
		return 0, errors.New("receiver digest does not match the sent bytes")
	}
	return 1, nil
}

// sendDatagrams sends one file over a datagram flow, one record per chunk. It
// returns the number of chunk records sent.
func sendDatagrams(flow net.Conn, source io.Reader, name string, size int64) (int, error) {
	if _, err := flow.Write(encodeHeader(name, size)); err != nil {
		return 0, err
	}
	if err := expectAck(flow); err != nil {
		return 0, err
	}
	digest := sha256.New()
	buffer := make([]byte, overlay.UsableFrame)
	chunks := 0
	for remaining := size; remaining > 0; {
		n, err := io.ReadFull(source, buffer[:min(int64(len(buffer)), remaining)])
		if err != nil {
			return chunks, err
		}
		_, _ = digest.Write(buffer[:n])
		if _, err := flow.Write(buffer[:n]); err != nil {
			return chunks, err
		}
		chunks++
		remaining -= int64(n)
		if remaining > 0 {
			if err := expectAck(flow); err != nil {
				return chunks, err
			}
		}
	}
	reply := make([]byte, 64)
	n, err := flow.Read(reply)
	if err != nil {
		return chunks, err
	}
	if !bytes.Equal(reply[:n], digest.Sum(nil)) {
		return chunks, errors.New("receiver digest does not match the sent bytes")
	}
	return chunks, nil
}

func expectAck(flow net.Conn) error {
	reply := make([]byte, 16)
	n, err := flow.Read(reply)
	if err != nil {
		return err
	}
	if n != 1 || reply[0] != ackByte {
		return errors.New("receiver did not acknowledge the chunk")
	}
	return nil
}

// sendFile opens a flow to the peer through the hub and sends one file.
func sendFile(ctx context.Context, agent *overlayagent.Agent, peer netip.Addr, proto, path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	flow, err := agent.Outbound(ctx, proto, netip.AddrPortFrom(peer, 9000))
	if err != nil {
		return 0, err
	}
	defer func() { _ = flow.Close() }()
	if err := flow.SetDeadline(time.Now().Add(2 * time.Minute)); err != nil {
		return 0, err
	}
	name := filepath.Base(path)
	if proto == overlay.ProtoUDP {
		return sendDatagrams(flow, file, name, info.Size())
	}
	return sendStream(flow, file, name, info.Size())
}

// sourceBytes makes deterministic content. Text content compresses well and
// random content does not, so both chunk kinds are exercised.
func sourceBytes(size int, text bool) []byte {
	buffer := make([]byte, 0, size+64)
	if text {
		for line := 0; len(buffer) < size; line++ {
			buffer = fmt.Appendf(buffer, "line %08d overlay relay compressible payload\n", line)
		}
	} else {
		rng := rand.New(rand.NewPCG(20261102, 1))
		for len(buffer) < size {
			buffer = binary.LittleEndian.AppendUint64(buffer, rng.Uint64())
		}
	}
	return buffer[:size]
}

func writeSource(t *testing.T, name string, size int, text bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, sourceBytes(size, text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireSameFile(t *testing.T, source, received string) {
	t.Helper()
	want, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(received)
	if err != nil {
		t.Fatalf("received file missing: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("%s: received %d bytes, want %d matching bytes", filepath.Base(source), len(got), len(want))
	}
}

// transferEnv is one hub with two registered agents, each with its own sink.
type transferEnv struct {
	alice, bob         *overlayagent.Agent
	aliceIP, bobIP     netip.Addr
	aliceSink, bobSink *fileSink
}

func newFileAgent(hub string, account account, states chan<- overlay.State, sink *fileSink, compression bool) *overlayagent.Agent {
	return overlayagent.New(overlayagent.Config{
		Secret:      account.secret,
		Compression: compression,
		Dial: func(ctx context.Context) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp", hub)
		},
		DialLocal: func(ctx context.Context, proto string, _ uint16, _ netip.Addr) (net.Conn, error) {
			var dialer net.Dialer
			if proto == overlay.ProtoUDP {
				return dialer.DialContext(ctx, "udp", sink.udp.LocalAddr().String())
			}
			return dialer.DialContext(ctx, "tcp", sink.tcp.Addr().String())
		},
		OnState: func(state overlay.State) {
			select {
			case states <- state:
			default:
			}
		},
	})
}

func startTransferEnv(t *testing.T, compression bool) *transferEnv {
	t.Helper()
	hubBinary := buildHub(t)
	alice := account{name: "alice", secret: overlay.SecretUserPass("hysteria", "alice", "alice-password")}
	bob := account{name: "bob", secret: overlay.SecretUserPass("hysteria", "bob", "bob-password")}
	hub := startHub(t, hubBinary, overlay.Peers{Version: overlay.Version, Accounts: []overlay.Account{accountEntry(t, alice), accountEntry(t, bob)}})

	aliceSink := startSink(t, t.TempDir())
	bobSink := startSink(t, t.TempDir())
	aliceStates := make(chan overlay.State, 64)
	bobStates := make(chan overlay.State, 64)
	env := &transferEnv{
		alice:     newFileAgent(hub.address, alice, aliceStates, aliceSink, compression),
		bob:       newFileAgent(hub.address, bob, bobStates, bobSink, compression),
		aliceSink: aliceSink,
		bobSink:   bobSink,
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = env.alice.Run(ctx) }()
	go func() { _ = env.bob.Run(ctx) }()
	env.aliceIP = <-env.alice.Ready()
	env.bobIP = <-env.bob.Ready()
	waitFor(t, aliceStates, func(state overlay.State) bool {
		return state.Connected && len(state.Peers) == 1 && state.Peers[0].IP == env.bobIP.String()
	})
	waitFor(t, bobStates, func(state overlay.State) bool {
		return state.Connected && len(state.Peers) == 1 && state.Peers[0].IP == env.aliceIP.String()
	})
	return env
}

// exchangeFiles sends one file each way and checks the stored bytes match.
func exchangeFiles(t *testing.T, env *transferEnv, proto string, size int, text bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	aliceSource := writeSource(t, "from-alice.bin", size, text)
	bobSource := writeSource(t, "from-bob.bin", size, text)

	aliceChunks, err := sendFile(ctx, env.alice, env.bobIP, proto, aliceSource)
	if err != nil {
		t.Fatalf("alice to bob: %v", err)
	}
	requireSameFile(t, aliceSource, filepath.Join(env.bobSink.dir, "from-alice.bin"))

	bobChunks, err := sendFile(ctx, env.bob, env.aliceIP, proto, bobSource)
	if err != nil {
		t.Fatalf("bob to alice: %v", err)
	}
	requireSameFile(t, bobSource, filepath.Join(env.aliceSink.dir, "from-bob.bin"))

	if proto == overlay.ProtoUDP {
		want := (size + overlay.UsableFrame - 1) / overlay.UsableFrame
		if aliceChunks != want || bobChunks != want {
			t.Fatalf("datagram chunks alice=%d bob=%d, want %d frame-sized records each", aliceChunks, bobChunks, want)
		}
	}
}

// TestFileTransferBetweenAgents sends files both ways between two Go agents
// through the Rust hub. The UDP case cuts a file of several megabytes into
// frame-sized records with a partial last chunk. The compressed case sends
// compressible text through flow compression.
func TestFileTransferBetweenAgents(t *testing.T) {
	t.Run("tcp stream", func(t *testing.T) {
		exchangeFiles(t, startTransferEnv(t, false), overlay.ProtoTCP, 4<<20, false)
	})
	t.Run("udp frames", func(t *testing.T) {
		exchangeFiles(t, startTransferEnv(t, false), overlay.ProtoUDP, 3<<20+4321, false)
	})
	t.Run("tcp compressed", func(t *testing.T) {
		exchangeFiles(t, startTransferEnv(t, true), overlay.ProtoTCP, 4<<20, true)
	})
}
