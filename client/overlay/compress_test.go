package overlay

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func TestCompressedRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	writer := Compressed(left)
	reader := Compressed(right)

	text := bytes.Repeat([]byte("overlay relay compressible line\n"), 4000)
	noise := make([]byte, 40<<10)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}

	errs := make(chan error, 1)
	go func() {
		defer func() { _ = writer.Close() }()
		if _, err := writer.Write(text); err != nil {
			errs <- err
			return
		}
		_, err := writer.Write(noise)
		errs <- err
	}()

	got := make([]byte, len(text)+len(noise))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errs; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got[:len(text)], text) || !bytes.Equal(got[len(text):], noise) {
		t.Fatal("decoded bytes differ from the written bytes")
	}
	_ = reader.Close()
}

func TestCompressedRejectsUnknownChunkKind(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	reader := Compressed(right)
	go func() { _, _ = left.Write([]byte{7, 0, 1, 'x'}) }()

	if _, err := reader.Read(make([]byte, 8)); err != ErrChunk {
		t.Fatalf("unknown chunk kind: got %v, want ErrChunk", err)
	}
	_ = reader.Close()
}

func TestCompressedRejectsOversizedInflate(t *testing.T) {
	packed, ok := deflate(make([]byte, CompressedChunkSize+1))
	if !ok {
		t.Fatal("zero-filled input must compress")
	}
	if _, err := inflate(packed); err != ErrChunk {
		t.Fatalf("oversized inflate: got %v, want ErrChunk", err)
	}
}
