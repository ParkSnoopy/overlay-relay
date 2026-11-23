package main

import (
	"encoding/json"
	"net"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	hubSignalTimeout    = 90 * time.Second
	hubSignalBytes      = 64 << 10
	hubSignalMessages   = 32
	hubLegacySignalWire = 4
)

type hubSignal struct {
	Type    string   `json:"t"`
	Methods []string `json:"m,omitempty"`
	Method  string   `json:"s,omitempty"`
	Data    any      `json:"d,omitempty"`
	Error   string   `json:"e,omitempty"`
}

type hubWebRTCData struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type hubICEData struct {
	Ufrag      string   `json:"u"`
	Password   string   `json:"p"`
	Candidates []string `json:"c"`
}

func hubSignalMethod(method string) bool { return method == "webrtc" || method == "ice" }

func readHubSignal(conn net.Conn) (hubSignal, error) {
	var message hubSignal
	var data *json.RawMessage
	err := readHubFields(conn, false,
		requiredField("t", &message.Type), optionalField("m", &message.Methods),
		optionalField("s", &message.Method), nullableField("d", &data), optionalField("e", &message.Error))
	if err != nil {
		return message, err
	}
	if data != nil {
		message.Data = parseHubSignalData(*data, message.Type, message.Method)
		if message.Data == nil {
			return message, errHubFrame
		}
	}
	return message, nil
}

func parseHubSignalData(raw json.RawMessage, kind, method string) any {
	switch method {
	case "webrtc":
		var data hubWebRTCData
		if decodeStoreObject(raw, false, requiredField("type", &data.Type), requiredField("sdp", &data.SDP)) != nil ||
			data.Type != kind || !hubSignalText(data.SDP, 12<<10) ||
			!strings.HasPrefix(data.SDP, "v=0\r\n") || !strings.Contains(data.SDP, "m=application ") {
			return nil
		}
		return data
	case "ice":
		var data hubICEData
		if decodeStoreObject(raw, false, requiredField("u", &data.Ufrag), requiredField("p", &data.Password), requiredField("c", &data.Candidates)) != nil ||
			!hubSignalText(data.Ufrag, 256) || !hubSignalText(data.Password, 256) ||
			len(data.Candidates) == 0 || len(data.Candidates) > 32 {
			return nil
		}
		for _, candidate := range data.Candidates {
			if candidate == "" || len(candidate) > 1024 || strings.IndexFunc(candidate, unicode.IsControl) >= 0 {
				return nil
			}
		}
		return data
	default:
		return nil
	}
}

func hubSignalText(text string, limit int) bool {
	return text != "" && len(text) <= limit && strings.IndexByte(text, 0) < 0
}

func (m *hubSignal) valid(wire int) bool {
	noMethod := m.Method == "" && len(m.Methods) == 0
	switch m.Type {
	case "hello":
		limit := 2
		if wire == hubLegacySignalWire {
			limit++
		}
		return len(m.Methods) <= limit && slices.ContainsFunc(m.Methods, hubSignalMethod) &&
			!slices.ContainsFunc(m.Methods, func(method string) bool {
				return !hubSignalMethod(method) && (wire != hubLegacySignalWire || method != "libp2p")
			}) && m.Method == "" && m.Data == nil && m.Error == ""
	case "offer", "answer":
		return m.Data != nil && len(m.Methods) == 0 && m.Error == ""
	case "done":
		return hubSignalMethod(m.Method) && m.Data == nil && len(m.Methods) == 0 && m.Error == ""
	case "fail":
		return noMethod && m.Data == nil && (m.Error == "busy" || m.Error == "unsupported method" || m.Error == "method failed")
	case "sync", "next", "end":
		return noMethod && m.Data == nil && m.Error == ""
	default:
		return false
	}
}

func forwardHubSignal(src, dst net.Conn, wire int) error {
	used := 0
	var offered []string
	for index := range hubSignalMessages {
		message, err := readHubSignal(src)
		if err != nil {
			return err
		}
		if !message.valid(wire) || (index == 0 && message.Type != "hello" && message.Type != "fail") ||
			(index == 0 && message.Error == "method failed") || (index != 0 && message.Type == "hello") {
			return errHubFrame
		}
		if message.Type == "offer" || message.Type == "answer" {
			if slices.Contains(offered, message.Method) {
				return errHubFrame
			}
			offered = append(offered, message.Method)
		}
		payload, err := encodeHubJSON(message)
		if err != nil {
			return err
		}
		used += len(payload)
		if used > hubSignalBytes {
			return errHubFrame
		}
		if message.Type == "hello" && wire == hubLegacySignalWire {
			message.Methods = slices.DeleteFunc(message.Methods, func(method string) bool { return !hubSignalMethod(method) })
			payload, err = encodeHubJSON(message)
			if err != nil {
				return err
			}
		}
		if err := sendHubJSON(dst, payload); err != nil {
			return err
		}
		if message.Type == "done" || message.Type == "end" || (message.Type == "fail" && message.Error != "method failed") {
			return nil
		}
	}
	return errHubFrame
}
