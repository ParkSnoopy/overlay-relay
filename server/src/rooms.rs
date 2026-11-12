//! Operator approval of private rooms.
//!
//! A private room is the opaque capability a client derives from its room ID
//! and password. The hub refuses a capability until an operator approves it.
//! The first request for a capability is recorded in `rooms-pending.json`,
//! which only the hub writes. `overlay-hub rooms approve` copies it into
//! `rooms.json`, which only that command writes. Approval therefore fixes the
//! room to the password its first requester used, and the hub reads the
//! approved file on every private-room connection without a restart.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::ErrorKind,
    path::Path,
};

use serde::{Deserialize, Serialize};

use crate::{
    assignments::write_then_rename,
    error::{Error, Result},
};

/// File name of the approved capabilities inside the data directory.
pub const APPROVED_FILE: &str = "rooms.json";

/// File name of the requested, not yet approved capabilities.
pub const PENDING_FILE: &str = "rooms-pending.json";

/// Requests kept for the operator. Further new rooms are refused unrecorded.
pub const MAX_PENDING: usize = 64;

/// The first device that asked for a room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Verifier hex of the requesting device.
    pub peer: String,
    /// Display name the device presented.
    pub name: String,
    /// Unix time in seconds of the first request.
    pub requested: u64,
}

/// What `overlay-hub rooms list` prints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    /// Waiting requests, keyed by room capability.
    pub pending: BTreeMap<String, Request>,
    /// Approved room capabilities.
    pub approved: BTreeSet<String>,
}

/// Reports whether `room` is a canonical room capability (64 lowercase hex digits).
#[must_use]
pub fn valid_room(room: &str) -> bool {
    room.len() == 64
        && room
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match tokio::fs::read(path).await {
        Ok(raw) => Ok(Some(raw)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Loads the approved capabilities. A missing file is empty; a corrupt one is
/// an error so the hub refuses private rooms rather than guessing.
///
/// # Errors
/// Returns an error when the file cannot be read or parsed.
pub async fn load_approved(directory: &Path) -> Result<BTreeSet<String>> {
    let Some(raw) = read_optional(&directory.join(APPROVED_FILE)).await? else {
        return Ok(BTreeSet::new());
    };
    Ok(serde_json::from_slice(&raw)?)
}

/// Loads the waiting requests. A missing file is empty.
///
/// # Errors
/// Returns an error when the file cannot be read or parsed.
pub async fn load_pending(directory: &Path) -> Result<BTreeMap<String, Request>> {
    let Some(raw) = read_optional(&directory.join(PENDING_FILE)).await? else {
        return Ok(BTreeMap::new());
    };
    Ok(serde_json::from_slice(&raw)?)
}

/// Atomically replaces the waiting requests.
///
/// # Errors
/// Returns an error when the file cannot be written.
pub async fn save_pending(directory: &Path, pending: &BTreeMap<String, Request>) -> Result<()> {
    write_json(directory, PENDING_FILE, &serde_json::to_vec(pending)?).await
}

/// Lists the waiting and approved rooms.
///
/// # Errors
/// Returns an error when either file cannot be read or parsed.
pub async fn listing(directory: &Path) -> Result<Listing> {
    let approved = load_approved(directory).await?;
    let mut pending = load_pending(directory).await?;
    pending.retain(|room, _| !approved.contains(room));
    Ok(Listing { pending, approved })
}

/// Approves a requested room. Approving an approved room succeeds.
///
/// # Errors
/// Returns an error when `room` is malformed or was never requested, or when
/// a file cannot be read or written.
pub async fn approve(directory: &Path, room: &str) -> Result<()> {
    if !valid_room(room) {
        return Err(Error::Config("room is not a valid capability"));
    }
    let mut approved = load_approved(directory).await?;
    if approved.contains(room) {
        return Ok(());
    }
    if !load_pending(directory).await?.contains_key(room) {
        return Err(Error::Config("room has not been requested"));
    }
    approved.insert(room.to_owned());
    write_json(directory, APPROVED_FILE, &serde_json::to_vec(&approved)?).await
}

async fn write_json(directory: &Path, name: &str, raw: &[u8]) -> Result<()> {
    let suffix: [u8; 8] = rand::random();
    let temporary = directory.join(format!(".rooms-{}", hex::encode(suffix)));
    let result = write_then_rename(&temporary, &directory.join(name), raw).await;
    if result.is_err() {
        tokio::fs::remove_file(&temporary).await.ok();
    }
    result
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{Request, approve, listing, load_approved, save_pending, valid_room};
    use crate::error::Result;

    fn request() -> Request {
        Request {
            peer: "00".repeat(32),
            name: "DUMMY device".to_owned(),
            requested: 7,
        }
    }

    #[test]
    fn rooms_are_lowercase_hex_digests() -> Result<()> {
        ensure!(valid_room(&"ab".repeat(32)), "a digest must be accepted");
        ensure!(!valid_room(&"AB".repeat(32)), "uppercase must be refused");
        ensure!(!valid_room("ab"), "a short value must be refused");
        Ok(())
    }

    #[tokio::test]
    async fn only_requested_rooms_can_be_approved() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let room = "ab".repeat(32);
        ensure!(
            approve(dir.path(), &room).await.is_err(),
            "an unrequested room must be refused"
        );
        let mut pending = BTreeMap::new();
        pending.insert(room.clone(), request());
        save_pending(dir.path(), &pending).await?;
        approve(dir.path(), &room).await?;
        ensure!(
            load_approved(dir.path()).await?.contains(&room),
            "the approved file must hold the room"
        );
        let listed = listing(dir.path()).await?;
        ensure!(
            listed.pending.is_empty(),
            "an approved room must leave the waiting list"
        );
        approve(dir.path(), &room).await
    }
}
