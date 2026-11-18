package overlay

import (
	"strings"
	"testing"
)

func TestRelayFirewallOrderAndSelectors(t *testing.T) {
	peer := strings.Repeat("ab", 32)
	rules := []FirewallRule{
		{Action: "allow", Peer: peer, Protocol: ProtoTCP, Start: 443, End: 443},
		{Action: "deny", Protocol: "both", Start: 1, End: 65535},
	}
	if err := ValidateFirewall(rules); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		peer, protocol string
		port           uint16
		blocked        bool
	}{
		{peer, ProtoTCP, 443, false}, {peer, ProtoUDP, 443, true},
		{strings.Repeat("cd", 32), ProtoTCP, 443, true}, {peer, ProtoTCP, 442, true},
		{peer, ProtoTCP, 1, true}, {peer, ProtoUDP, 65535, true},
	} {
		if got := FirewallBlocked(rules, c.peer, c.protocol, c.port); got != c.blocked {
			t.Fatalf("selector %s/%d: blocked=%t", c.protocol, c.port, got)
		}
	}
	rules[0], rules[1] = rules[1], rules[0]
	if !FirewallBlocked(rules, peer, ProtoTCP, 443) {
		t.Fatal("rule order ignored")
	}
	if FirewallBlocked(nil, peer, ProtoTCP, 443) {
		t.Fatal("empty policy blocked traffic")
	}
}

func TestRelayFirewallStrictDecode(t *testing.T) {
	for _, raw := range []string{
		"null", "{}", `[{"action":"deny","peer":"","protocol":"icmp","start":1,"end":1}]`,
		`[{"action":"other","peer":"","protocol":"tcp","start":1,"end":1}]`,
		`[{"action":"deny","peer":"","protocol":"tcp","start":2,"end":1}]`,
		`[{"action":"deny","peer":"","protocol":"udp","start":0,"end":1}]`,
		`[{"action":"deny","peer":"","protocol":"udp","start":1,"end":65536}]`,
		`[{"action":"deny","peer":"","protocol":"both","start":1,"end":1,"unknown":true}]`,
		"[] true",
	} {
		if _, err := DecodeFirewall([]byte(raw)); err == nil {
			t.Fatalf("invalid policy accepted: %s", raw)
		}
	}
	for _, raw := range []string{"", "[]", `[{"action":"allow","peer":"","protocol":"both","start":1,"end":65535}]`} {
		if _, err := DecodeFirewall([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := DecodeFirewall([]byte("[" + strings.Repeat("{} ,", 257) + "{}]")); err == nil {
		t.Fatal("oversized rule list accepted")
	}
}
