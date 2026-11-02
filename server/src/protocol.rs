//! Wire contract shared with the overlay client: frame payloads, stream kinds,
//! error strings and the limits both sides enforce.

use serde::{Deserialize, Serialize};

/// The only accepted wire version, carried in `Hello.version`.
pub const VERSION: u32 = 1;

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

/// Reason given when a token does not authenticate or an accept is not allowed.
pub const ERR_UNAUTHORIZED: &str = "unauthorized";

/// Reason given for an unknown Hello kind.
pub const ERR_INVALID_REQUEST: &str = "invalid request";

/// First frame on every stream a client opens to the hub.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Hello {
    /// Wire version; must equal [`VERSION`].
    pub version: u32,
    /// Stream kind: [`KIND_CONTROL`], [`KIND_OPEN`] or [`KIND_ACCEPT`].
    pub kind: String,
    /// Hex-encoded 32-byte bearer token derived by the client.
    pub token: String,
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
    /// The peer's overlay `IPv4` address.
    pub ip: String,
    /// The peer's display name.
    pub name: String,
}

/// A request asking the destination agent to open an accept stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incoming {
    /// Identifier to echo in the accept Hello.
    pub id: String,
    /// Transport protocol of the flow.
    pub proto: String,
    /// Requester's overlay `IPv4` address.
    pub src: String,
    /// Destination port requested.
    pub port: u16,
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

/// Keep-alive frame sent by the agent on a control stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    /// Must be `true` for the stream to stay open.
    #[serde(default)]
    pub ping: bool,
}
