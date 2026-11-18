package overlay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// DecodeFirewall decodes optional policy strictly. An absent field keeps older
// settings compatible; explicit null, unknown fields and malformed rules fail.
func DecodeFirewall(raw []byte) ([]FirewallRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > 65536 {
		return nil, errors.New("relay firewall policy is too large")
	}
	var rules []FirewallRule
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rules); err != nil {
		return nil, err
	}
	if rules == nil {
		return nil, errors.New("relay firewall must be an array")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("unexpected relay firewall data")
	}
	if err := ValidateFirewall(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// FirewallRule allows or denies incoming hub-relayed flows to a service range.
// Peer is an authenticated device ID (SHA-256 of the public key), or empty for
// every peer. Rules do not filter direct links, discovery or signaling.
type FirewallRule struct {
	Action   string `json:"action"`
	Peer     string `json:"peer"`
	Protocol string `json:"protocol"`
	Start    uint16 `json:"start"`
	End      uint16 `json:"end"`
}

// ValidateFirewall bounds the policy and rejects malformed selectors and ports.
func ValidateFirewall(rules []FirewallRule) error {
	if len(rules) > 256 {
		return errors.New("too many relay firewall rules")
	}
	for _, rule := range rules {
		if rule.Peer != "" && !ValidPeerID(rule.Peer) {
			return errors.New("invalid relay firewall device ID")
		}
		if rule.Action != "allow" && rule.Action != "deny" {
			return errors.New("invalid relay firewall action")
		}
		if rule.Protocol != ProtoTCP && rule.Protocol != ProtoUDP && rule.Protocol != "both" {
			return errors.New("invalid relay firewall protocol")
		}
		if rule.Start == 0 || rule.End < rule.Start {
			return errors.New("invalid relay firewall port range")
		}
	}
	return nil
}

// FirewallBlocked evaluates validated rules in order. The first matching rule
// decides; unmatched traffic is allowed. A final global deny rule denies the rest.
func FirewallBlocked(rules []FirewallRule, peer, protocol string, port uint16) bool {
	for _, rule := range rules {
		if (rule.Peer == "" || rule.Peer == peer) && (rule.Protocol == "both" || rule.Protocol == protocol) && port >= rule.Start && port <= rule.End {
			return rule.Action == "deny"
		}
	}
	return false
}
