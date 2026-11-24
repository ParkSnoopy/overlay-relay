package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ParkSnoopy/overlay-relay/client/overlay"
)

const hubWriteTimeout = 10 * time.Second

var errHubFrame = errors.New("invalid overlay frame")

// Read the shared bounded envelope, but decode object member names literally.
// encoding/json's usual case-insensitive struct matching would give otherwise
// unknown input fields meaning they did not have on the Rust hub.
func readHubFields(r io.Reader, allowUnknown bool, fields ...storeField) error {
	var raw json.RawMessage
	if err := overlay.ReadFrame(r, &raw); err != nil {
		return err
	}
	return decodeStoreObject(raw, allowUnknown, fields...)
}

func readHubHello(r io.Reader) (overlay.Hello, error) {
	var hello overlay.Hello
	var version uint32
	err := readHubFields(r, true,
		optionalField("version", &version), optionalField("kind", &hello.Kind), optionalField("public_key", &hello.PublicKey),
		optionalField("room", &hello.Room), optionalField("room_id", &hello.RoomID), optionalField("name", &hello.Name),
		optionalField("domain", &hello.Domain), optionalField("peer_pages", &hello.PeerPages),
		optionalField("domain_explicit", &hello.DomainExplicit),
		optionalField("peer_id", &hello.PeerID), optionalField("proto", &hello.Proto), optionalField("dst", &hello.Dst),
		nullableField("port", &hello.Port), optionalField("id", &hello.ID),
		optionalField("fingerprint", &hello.Fingerprint), optionalField("endpoint", &hello.Endpoint))
	hello.Version = int(version)
	return hello, err
}

func readHubProof(r io.Reader) ([]byte, error) {
	var proof overlay.Proof
	if err := readHubFields(r, true, requiredField("signature", &proof.Signature)); err != nil {
		return nil, err
	}
	return hex.DecodeString(proof.Signature)
}

func readHubControlRequest(r io.Reader) (overlay.ControlRequest, error) {
	var request overlay.ControlRequest
	var resolve *json.RawMessage
	if err := readHubFields(r, true, optionalField("ping", &request.Ping), nullableField("resolve", &resolve)); err != nil {
		return request, err
	}
	if resolve != nil {
		request.Resolve = new(overlay.NameQuery)
		if err := decodeStoreObject(*resolve, true,
			requiredField("id", &request.Resolve.ID), requiredField("label", &request.Resolve.Label)); err != nil {
			return request, err
		}
	}
	return request, nil
}

func encodeHubJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeStoreJSON(&buf, value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

func sendHubFrame(conn net.Conn, value any) error {
	payload, err := encodeHubJSON(value)
	if err != nil {
		return err
	}
	return sendHubJSON(conn, payload)
}

func sendHubJSON(conn net.Conn, payload []byte) error {
	if len(payload) == 0 || len(payload) > overlay.UsableFrame {
		return errHubFrame
	}
	if err := conn.SetWriteDeadline(time.Now().Add(hubWriteTimeout)); err != nil {
		return err
	}
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, len(payload)+2), uint16(len(payload)))
	frame = append(frame, payload...)
	count, err := conn.Write(frame)
	if err != nil {
		return err
	}
	if count != len(frame) {
		return io.ErrShortWrite
	}
	return conn.SetWriteDeadline(time.Time{})
}

func hubRefuse(conn net.Conn, reason string) {
	_ = sendHubFrame(conn, overlay.Reply{Error: reason})
}

type hubOffer struct {
	fingerprint, endpoint string
}

func parseHubOffer(fingerprint, endpoint string) (hubOffer, bool) {
	if fingerprint == "" {
		return hubOffer{}, endpoint == ""
	}
	if len(fingerprint) != 64 {
		return hubOffer{}, false
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return hubOffer{}, false
	}
	if endpoint != "" {
		address, ok := parseHubEndpoint(endpoint)
		if !ok {
			return hubOffer{}, false
		}
		endpoint = address
	}
	return hubOffer{fingerprint: strings.ToLower(fingerprint), endpoint: endpoint}, true
}

func parseHubEndpoint(value string) (string, bool) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.Port() == 0 {
		return "", false
	}
	addr := endpoint.Addr()
	if !addr.Is4In6() && (addr.IsUnspecified() || addr.IsMulticast()) {
		return "", false
	}
	if zone := addr.Zone(); zone != "" {
		scope, err := strconv.ParseUint(zone, 10, 32)
		if err != nil {
			return "", false
		}
		zone = ""
		if scope != 0 {
			zone = strconv.FormatUint(scope, 10)
		}
		endpoint = netip.AddrPortFrom(addr.WithZone(zone), endpoint.Port())
	}
	return endpoint.String(), true
}

func hubPairReply(id string, own, peer hubOffer) overlay.Reply {
	reply := overlay.Reply{OK: true}
	if own.fingerprint != "" && peer.fingerprint != "" {
		reply.Secure = true
		reply.Fingerprint = peer.fingerprint
	}
	if own.endpoint != "" && peer.endpoint != "" {
		reply.Direct = true
		reply.ID, reply.Endpoint = id, peer.endpoint
	}
	return reply
}
