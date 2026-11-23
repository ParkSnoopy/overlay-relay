package overlayagent

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestMagicDNS(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, label string
		qtype       uint16
		code        int
		address     string
	}{
		{"dEsK.On.SnOo.", "desk", dns.TypeA, dns.RcodeSuccess, "10.77.0.2"},
		{`\100esk.\111n.\115noo.`, "desk", dns.TypeA, dns.RcodeSuccess, "10.77.0.2"},
		{"desk.on.snoo.", "desk", dns.TypeAAAA, dns.RcodeSuccess, ""},
		{"desk.on.snoo.", "desk", dns.TypeANY, dns.RcodeSuccess, ""},
		{"unknown.on.snoo.", "unknown", dns.TypeA, dns.RcodeNameError, ""},
		{"unknown.on.snoo.", "unknown", dns.TypeAAAA, dns.RcodeNameError, ""},
		{"bad-answer.on.snoo.", "bad-answer", dns.TypeA, dns.RcodeServerFailure, ""},
		{"hub-error.on.snoo.", "hub-error", dns.TypeA, dns.RcodeServerFailure, ""},
		{"on.snoo.", "", dns.TypeSOA, dns.RcodeNameError, ""},
		{"snoo.", "", dns.TypeSOA, dns.RcodeNameError, ""},
		{"extra.desk.on.snoo.", "", dns.TypeA, dns.RcodeNameError, ""},
		{"_extra.on.snoo.", "", dns.TypeA, dns.RcodeNameError, ""},
		{`desk\.on.snoo.`, "", dns.TypeA, dns.RcodeNameError, ""},
		{"dEsK.SnOo.", "", dns.TypeA, dns.RcodeNameError, ""},
		{`desk.\115noo.`, "", dns.TypeA, dns.RcodeNameError, ""},
		{"desk.on.snoo.example.", "", dns.TypeA, -1, ""},
		{"desk.notsnoo.", "", dns.TypeA, -1, ""},
		{".", "", dns.TypeNS, -1, ""},
		{`desk.on\.snoo.`, "", dns.TypeA, -1, ""},
	} {
		t.Run(tc.name+"/"+dns.TypeToString[tc.qtype], func(t *testing.T) {
			request := new(dns.Msg).SetQuestion(tc.name, tc.qtype)
			var lookedUp []string
			reply := magicDNS(t.Context(), request, func(_ context.Context, label string) (netip.Addr, error) {
				lookedUp = append(lookedUp, label)
				switch label {
				case "desk":
					return netip.MustParseAddr("10.77.0.2"), nil
				case "bad-answer":
					return netip.MustParseAddr("192.0.2.9"), nil
				case "hub-error":
					return netip.Addr{}, errors.New("hub failure")
				default:
					return netip.Addr{}, nil
				}
			})
			if strings.Join(lookedUp, ",") != tc.label || (tc.label == "" && len(lookedUp) != 0) {
				t.Fatalf("looked up %q, want %q", lookedUp, tc.label)
			}
			if tc.code < 0 {
				if reply != nil || ProtectedDNSName(tc.name) {
					t.Fatalf("claimed ordinary DNS: %v", reply)
				}
				return
			}
			if !ProtectedDNSName(tc.name) || reply == nil || !reply.Response || !reply.RecursionAvailable || reply.Id != request.Id ||
				reply.Rcode != tc.code || len(reply.Question) != 1 || reply.Question[0] != request.Question[0] {
				t.Fatalf("unexpected DNS reply: %v", reply)
			}
			if tc.address == "" {
				if len(reply.Answer) != 0 || len(reply.Ns) != 0 || len(reply.Extra) != 0 {
					t.Fatalf("expected empty reply without cacheable records: %v", reply)
				}
				return
			}
			if !reply.Authoritative || len(reply.Answer) != 1 {
				t.Fatalf("expected one authoritative answer: %v", reply)
			}
			a, ok := reply.Answer[0].(*dns.A)
			if !ok || a.Hdr.Ttl != 0 || a.Hdr.Name != tc.name || a.A.String() != tc.address {
				t.Fatalf("unexpected DNS resource record: %v", reply.Answer[0])
			}
		})
	}
}

func TestMagicDNSRejectsBeforeLookup(t *testing.T) {
	t.Parallel()
	for _, privateName := range []string{"desk.on.snoo.", "desk.snoo."} {
		public := dns.Question{Name: "example.test.", Qclass: dns.ClassINET, Qtype: dns.TypeA}
		request := new(dns.Msg).SetQuestion(privateName, dns.TypeA)
		private := request.Question[0]
		for _, questions := range [][]dns.Question{{public, private}, {private, public}, {private, private}} {
			request.Question = questions
			assertMagicDNSReject(t, request, dns.RcodeFormatError)
		}
		request.Question = []dns.Question{private}
		request.Opcode = dns.OpcodeNotify
		assertMagicDNSReject(t, request, dns.RcodeFormatError)
		request.Opcode = dns.OpcodeQuery
		request.Question[0].Qclass = dns.ClassCHAOS
		assertMagicDNSReject(t, request, dns.RcodeNameError)
	}
}

func assertMagicDNSReject(t *testing.T, request *dns.Msg, want int) {
	t.Helper()
	reply := magicDNS(t.Context(), request, func(context.Context, string) (netip.Addr, error) {
		t.Fatal("rejected query reached the hub")
		return netip.Addr{}, nil
	})
	if reply == nil || reply.Rcode != want || len(reply.Answer) != 0 {
		t.Fatalf("unhandled query %v: %v", request, reply)
	}
}
