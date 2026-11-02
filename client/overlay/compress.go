package overlay

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// A compressed flow carries bytes as chunks: kind (1 byte), body length
// (2 bytes, big-endian), body. chunkRaw stores the plain bytes as they are;
// chunkDeflate stores a DEFLATE stream that inflates to the plain bytes. A
// writer picks DEFLATE only for chunks that shrink. Both ends of a flow must
// enable the setting, because the hub relays the bytes unchanged.
const (
	chunkRaw     byte = 0
	chunkDeflate byte = 1
	// CompressedChunkSize bounds the plain bytes carried by one chunk.
	CompressedChunkSize = UsableFrame
	// chunkMinDeflate is the smallest plain chunk worth an attempt at compression.
	chunkMinDeflate = 512
)

// ErrChunk reports a malformed compressed chunk.
var ErrChunk = errors.New("overlay compressed chunk is malformed")

// Compressed wraps a flow so that every write is split into chunks, and each
// chunk is DEFLATE-compressed when that makes it smaller. Reads undo the
// framing. Read and Write errors are returned unchanged. A read that fails in
// the middle of a chunk leaves the stream unusable, so callers close it.
func Compressed(conn net.Conn) net.Conn {
	return &compressedConn{Conn: conn}
}

type compressedConn struct {
	net.Conn
	rmu     sync.Mutex
	pending []byte
	wmu     sync.Mutex
}

// Read returns decoded bytes, reading whole chunks from the flow as needed.
func (c *compressedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pending) == 0 {
		if err := c.readChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *compressedConn) readChunk() error {
	var header [3]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return err
	}
	body := make([]byte, binary.BigEndian.Uint16(header[1:]))
	if _, err := io.ReadFull(c.Conn, body); err != nil {
		return err
	}
	switch header[0] {
	case chunkRaw:
		if len(body) > CompressedChunkSize {
			return ErrChunk
		}
		c.pending = body
	case chunkDeflate:
		plain, err := inflate(body)
		if err != nil {
			return err
		}
		c.pending = plain
	default:
		return ErrChunk
	}
	return nil
}

// Write splits p into chunks of at most CompressedChunkSize plain bytes.
func (c *compressedConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	for written < len(p) {
		end := min(written+CompressedChunkSize, len(p))
		if err := writeChunk(c.Conn, p[written:end]); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

// CloseWrite ends the write direction. It forwards to the underlying flow when
// that supports half-close, and closes the flow otherwise.
func (c *compressedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

func writeChunk(w net.Conn, plain []byte) error {
	kind, body := chunkRaw, plain
	if len(plain) >= chunkMinDeflate {
		if packed, ok := deflate(plain); ok {
			kind, body = chunkDeflate, packed
		}
	}
	frame := make([]byte, 0, 3+len(body))
	frame = append(frame, kind)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(body)))
	frame = append(frame, body...)
	_, err := w.Write(frame)
	return err
}

// deflate returns the compressed form of plain only when it is smaller.
func deflate(plain []byte) ([]byte, bool) {
	var buffer bytes.Buffer
	writer, err := flate.NewWriter(&buffer, flate.BestSpeed)
	if err != nil {
		return nil, false
	}
	if _, err := writer.Write(plain); err != nil {
		return nil, false
	}
	if err := writer.Close(); err != nil {
		return nil, false
	}
	if buffer.Len() >= len(plain) {
		return nil, false
	}
	return buffer.Bytes(), true
}

func inflate(body []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(body))
	defer func() { _ = reader.Close() }()
	// Cap the output so a hostile chunk cannot expand beyond one chunk.
	plain, err := io.ReadAll(io.LimitReader(reader, CompressedChunkSize+1))
	if err != nil {
		return nil, err
	}
	if len(plain) > CompressedChunkSize {
		return nil, ErrChunk
	}
	return plain, nil
}
