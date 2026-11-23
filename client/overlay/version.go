package overlay

import relay "github.com/ParkSnoopy/overlay-relay"

// Retain the public client constants; the hub and client share one definition.
const (
	ReleaseVersion      = relay.ReleaseVersion
	Version             = relay.WireVersion
	AuthDomain          = relay.AuthDomain
	PreviousWireVersion = relay.PreviousWireVersion
	PreviousAuthDomain  = relay.PreviousAuthDomain
)
