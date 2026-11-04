//! Wire contract shared with the overlay client: frame payloads, stream kinds,
//! error strings and the limits both sides enforce.

use serde::{Deserialize, Serialize};

/// The only accepted wire version, carried in `Hello.version`.
pub const VERSION: u32 = 2;

/// Port the hub listens on inside its private container network.
pub const PORT: u16 = 6697;

/// Address the hub binds.
pub const LISTEN_ADDRESS: &str = "0.0.0.0:6697";

/// Largest JSON payload of one control frame, in bytes.
pub const MAX_FRAME: usize = 16 << 10;

/// Largest UDP payload carried as one datagram record.
pub const MAX_DATAGRAM: usize = 65535;

/// Bytes kept free below each transport limit, so headers and encoding overhead
/// never cross a hard bound. Writers stay under the usable limits.
pub const SAFETY_SPACE: usize = 128;

/// Largest payload the hub writes as one frame.
pub const USABLE_FRAME: usize = MAX_FRAME - SAFETY_SPACE;

/// Largest payload the hub writes as one datagram record.
pub const USABLE_DATAGRAM: usize = MAX_DATAGRAM - SAFETY_SPACE;

/// Most accounts one peers table may hold.
pub const MAX_ACCOUNTS: usize = 4096;

/// Flows one account may hold at once.
pub const MAX_FLOWS_PER_ACCOUNT: usize = 256;

/// Unanswered open requests one destination may have at once.
pub const MAX_PENDING_PER_ACCOUNT: usize = 4;

/// Hello kind that registers a broadcasting account.
pub const KIND_CONTROL: &str = "control";

/// Hello kind that opens a relayed flow to a broadcasting peer.
pub const KIND_OPEN: &str = "open";

/// Hello kind that answers an incoming request.
pub const KIND_ACCEPT: &str = "accept";

/// TCP protocol name in `Hello.proto` and `Incoming.proto`.
pub const PROTO_TCP: &str = "tcp";

/// UDP protocol name in `Hello.proto` and `Incoming.proto`.
pub const PROTO_UDP: &str = "udp";

/// The only reason given when a destination is missing, hidden or refused.
pub const ERR_UNAVAILABLE: &str = "peer unavailable";

/// Reason given when an identity does not authenticate or an accept is not allowed.
pub const ERR_UNAUTHORIZED: &str = "unauthorized";

/// Reason given for an unknown Hello kind.
pub const ERR_INVALID_REQUEST: &str = "invalid request";

/// Accepts an optional, single-line device name of at most 128 characters.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    name.trim() == name && name.chars().count() <= 128 && !name.chars().any(char::is_control)
}

/// First frame on every stream a client opens to the hub.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hello {
    /// Wire version; must equal [`VERSION`].
    pub version: u32,
    /// Stream kind: [`KIND_CONTROL`], [`KIND_OPEN`] or [`KIND_ACCEPT`].
    pub kind: String,
    /// Hex-encoded uncompressed P-384 public key.
    pub public_key: String,
    /// Control only: optional advertised device name. Empty uses the default.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Expected destination device ID for an open; prevents address reuse races.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub peer_id: String,
    /// Protocol for an open request.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proto: String,
    /// Destination overlay `IPv4` address for an open request.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub dst: String,
    /// Destination port for an open request; must be nonzero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Incoming identifier for an accept request.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// SHA-256 fingerprint (64 hex digits) of the sender's flow certificate.
    /// Present means the sender offers an end-to-end encrypted flow.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// Public UDP endpoint (`ip:port`) of the sender. Present, together with a
    /// fingerprint, means the sender offers a direct connection.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
}

/// Fresh nonce issued to one connection.
#[derive(Debug, Serialize, Deserialize)]
pub struct Challenge {
    /// Hex-encoded challenge bytes.
    pub nonce: String,
}

/// Signature of a challenge by the client's P-384 key.
#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    /// Hex-encoded DER ECDSA signature.
    pub signature: String,
}

/// The hub's answer to a [`Hello`] and, on a control stream, to a ping.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Reply {
    /// Whether the request succeeded.
    pub ok: bool,
    /// Reason for a failure, omitted when empty.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// Control only: the account's overlay address.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ip: String,
    /// Control only: the account's display name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Open and accept only: both sides offered a fingerprint, so the flow is
    /// end-to-end encrypted.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub secure: bool,
    /// Open and accept only: both sides offered an endpoint, so the flow
    /// continues on a direct connection and the hub relays nothing.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub direct: bool,
    /// Direct only: the flow identifier both sides use to find each other.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// Secure only: the other side's flow certificate fingerprint.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// Direct only: the other side's public UDP endpoint.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
}

impl Reply {
    /// A successful reply with no fields set.
    #[must_use]
    pub fn accepted() -> Self {
        Self {
            ok: true,
            ..Self::default()
        }
    }

    /// A failed reply carrying `error`.
    #[must_use]
    pub fn failed(error: &str) -> Self {
        Self {
            error: error.to_owned(),
            ..Self::default()
        }
    }

    /// The success reply of a paired flow. `peer` is the other side's offer;
    /// the flow is secure only when both sides offered a fingerprint, and
    /// direct only when both also offered an endpoint.
    #[must_use]
    pub fn paired(id: &str, own: &Offer, peer: &Offer) -> Self {
        let secure = own.secure() && peer.secure();
        let direct = own.direct() && peer.direct();
        Self {
            ok: true,
            secure,
            direct,
            id: if direct { id.to_owned() } else { String::new() },
            fingerprint: if secure {
                peer.fingerprint.clone()
            } else {
                String::new()
            },
            endpoint: if direct {
                peer.endpoint.clone()
            } else {
                String::new()
            },
            ..Self::default()
        }
    }

    /// The control registration reply carrying the account's address and name.
    #[must_use]
    pub fn registered(ip: &str, name: &str) -> Self {
        Self {
            ok: true,
            ip: ip.to_owned(),
            name: name.to_owned(),
            ..Self::default()
        }
    }
}

/// One other broadcasting account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    /// Stable SHA-256 identifier of the device's public key.
    pub id: String,
    /// The peer's overlay `IPv4` address.
    pub ip: String,
    /// The peer's display name.
    pub name: String,
}

/// A request asking the destination agent to open an accept stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incoming {
    /// Stable identifier of the authenticated requesting device.
    pub peer_id: String,
    /// Identifier to echo in the accept Hello.
    pub id: String,
    /// Transport protocol of the flow.
    pub proto: String,
    /// Requester's overlay `IPv4` address.
    pub src: String,
    /// Destination port requested.
    pub port: u16,
    /// The requester's flow certificate fingerprint, when it offers encryption.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// The requester's public UDP endpoint, when it offers a direct connection.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
}

/// A frame the hub pushes on a control stream after the registration reply.
/// Exactly one variant is serialized per frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Event {
    /// The current list of other broadcasting accounts, sorted by address.
    Peers(Vec<Peer>),
    /// An incoming flow request.
    Incoming(Incoming),
    /// Answer to a ping.
    Pong(bool),
}

/// What one side offers for a flow beyond the plain relay: encryption (a
/// fingerprint) and, on top of it, a direct connection (an endpoint).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Offer {
    /// Lowercase hex SHA-256 of the side's flow certificate; empty means no offer.
    pub fingerprint: String,
    /// Canonical `ip:port` of the side's public UDP endpoint; empty means none.
    pub endpoint: String,
}

impl Offer {
    /// Validates the offer fields of a Hello. An endpoint without a
    /// fingerprint, a malformed fingerprint and a malformed endpoint are all invalid.
    #[must_use]
    pub fn parse(fingerprint: &str, endpoint: &str) -> Option<Self> {
        if fingerprint.is_empty() {
            return endpoint.is_empty().then(Self::default);
        }
        let valid = fingerprint.len() == FINGERPRINT_DIGITS
            && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !valid {
            return None;
        }
        let endpoint = if endpoint.is_empty() {
            String::new()
        } else {
            parse_endpoint(endpoint)?.to_string()
        };
        Some(Self {
            fingerprint: fingerprint.to_ascii_lowercase(),
            endpoint,
        })
    }

    /// Whether this side offers end-to-end encryption.
    #[must_use]
    pub const fn secure(&self) -> bool {
        !self.fingerprint.is_empty()
    }

    /// Whether this side offers a direct connection.
    #[must_use]
    pub const fn direct(&self) -> bool {
        self.secure() && !self.endpoint.is_empty()
    }
}

/// Hex digits in a SHA-256 fingerprint.
pub const FINGERPRINT_DIGITS: usize = 64;

/// Parses a public endpoint. Port zero, unspecified and multicast addresses
/// can never be reached and are refused.
fn parse_endpoint(value: &str) -> Option<std::net::SocketAddr> {
    let address: std::net::SocketAddr = value.parse().ok()?;
    let usable =
        address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast();
    usable.then_some(address)
}

/// Keep-alive frame sent by the agent on a control stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    /// Must be `true` for the stream to stay open.
    #[serde(default)]
    pub ping: bool,
}
