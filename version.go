// Package relay defines the shared release and wire versions of the overlay relay.
package relay

const ReleaseVersion = "0.5.5"

// Wire versions are negotiated independently of release versions. The domain
// strings are also public Go constants and are part of the signed wire format.
const (
	WireVersion         = 5
	PreviousWireVersion = WireVersion - 1
	AuthDomain          = "overlay-relay/auth/v5:"
	PreviousAuthDomain  = "overlay-relay/auth/v4:"
)