package overlayagent

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
)

// MagicDNSZone is the fully qualified suffix for room-local device names.
const MagicDNSZone = "on.snoo."

// ProtectedDNSName reports whether a name is in Magic DNS or its retired parent
// namespace. Callers must not forward either namespace to ordinary DNS.
func ProtectedDNSName(name string) bool {
	return dns.IsSubDomain("snoo.", canonicalQueryName(name))
}

// MagicDNS answers a protected request through the router's authenticated hub.
// A nil router still shields both namespaces. Only a nil result permits forwarding.
func (r *Router) MagicDNS(ctx context.Context, request *dns.Msg) *dns.Msg {
	return magicDNS(ctx, request, r.LookupName)
}

// MagicDNS answers a protected request through the agent's authenticated hub.
// A nil result means none of the questions is in a protected namespace.
func (a *Agent) MagicDNS(ctx context.Context, request *dns.Msg) *dns.Msg {
	return magicDNS(ctx, request, a.LookupName)
}

func magicDNS(ctx context.Context, request *dns.Msg, lookup func(context.Context, string) (netip.Addr, error)) *dns.Msg {
	for _, q := range request.Question {
		name := canonicalQueryName(q.Name)
		if !dns.IsSubDomain("snoo.", name) {
			continue
		}
		response := new(dns.Msg).SetRcode(request, dns.RcodeNameError)
		response.RecursionAvailable = true
		if len(request.Question) != 1 || request.Opcode != dns.OpcodeQuery || request.Response {
			response.Rcode = dns.RcodeFormatError
			return response
		}
		if q.Qclass != dns.ClassINET {
			return response
		}
		response.Authoritative = true
		labels := dns.SplitDomainName(name)
		if len(labels) != 3 || !dns.IsSubDomain(MagicDNSZone, name) || !validNameLabel(labels[0]) {
			return response
		}
		ip, err := lookup(ctx, labels[0])
		if err != nil || (ip.IsValid() && (!ip.Is4() || !ip.IsPrivate())) {
			response.Authoritative = false
			response.Rcode = dns.RcodeServerFailure
			return response
		}
		if ip.IsValid() {
			response.Rcode = dns.RcodeSuccess
			if q.Qtype == dns.TypeA {
				// The owner is stable, but its live lease is not cacheable.
				response.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   net.IP(ip.AsSlice()),
				}}
			}
		}
		return response
	}
	return nil
}

// Callers which did not unpack a wire message may supply escaped ASCII bytes.
// Classify those names as an upstream server would see them after unpacking.
func canonicalQueryName(name string) string {
	name = dns.Fqdn(name)
	if strings.ContainsRune(name, '\\') {
		var wire [255]byte
		if n, err := dns.PackDomainName(name, wire[:], 0, nil, false); err == nil {
			if unpacked, _, err := dns.UnpackDomainName(wire[:n], 0); err == nil {
				name = unpacked
			}
		}
	}
	return dns.CanonicalName(name)
}
