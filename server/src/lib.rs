//! Authenticated rendezvous and byte relay for overlay accounts.
//!
//! A [`Hub`] accepts connections only from admitted source addresses, challenges
//! each presented public key to prove possession, and relays flows between accounts that
//! chose to broadcast. Each account keeps one stable overlay address. The hub
//! never logs credentials, tokens, verifiers, payloads or peer names.
//!
//! The wire format is the one spoken by the overlay Go client: 16-bit
//! big-endian length-prefixed JSON frames, and length-prefixed datagram records
//! for UDP flows.

#[cfg(test)]
#[macro_use]
mod testing;

mod accept;
mod address;
mod assignments;
mod config;
mod control;
mod dns;
mod error;
mod frame;
mod hub;
mod open;
mod protocol;
mod splice;
mod state;
mod verifier;

pub use address::{AddressSpace, FIRST_ADDRESS, LAST_ADDRESS, assignable, lowest_free};
pub use config::Config;
pub use dns::{Resolver, SystemResolver, admitted};
pub use error::{Error, Result};
pub use frame::{read_datagram, read_frame, send_frame, write_datagram, write_frame};
pub use hub::{Hub, Shared, persist, unix_now};
pub use protocol::{
    Challenge,
    ERR_INVALID_REQUEST,
    ERR_UNAUTHORIZED,
    ERR_UNAVAILABLE,
    Event,
    Hello,
    Incoming,
    KIND_ACCEPT,
    KIND_CONTROL,
    KIND_OPEN,
    LISTEN_ADDRESS,
    MAX_ACCOUNTS,
    MAX_DATAGRAM,
    MAX_FLOWS_PER_ACCOUNT,
    MAX_FRAME,
    MAX_PENDING_PER_ACCOUNT,
    PORT,
    PROTO_TCP,
    PROTO_UDP,
    Peer,
    Ping,
    Proof,
    Reply,
    VERSION,
};
pub use verifier::Verifier;
