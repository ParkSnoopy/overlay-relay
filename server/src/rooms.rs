//! Operator approval of private rooms.
//!
//! A private room is a room ID plus a password proof the client derives from
//! the password. The hub refuses a room until an operator approves it. The
//! first request for a room ID is recorded in `rooms-pending.json` with the
//! password proof of its first requester; only the hub writes that file.
//! `overlay-hub rooms approve` copies the room into `rooms.json`, which only
//! the `rooms` command writes. Approval therefore fixes the room to the
//! password its first requester used. A room ID is unique: a request for a
//! known ID with another proof is denied and never recorded as a new request.
//! The hub reads both files on every private-room connection, so approval and
//! removal need no restart. A room is addressed by the SHA-256 hex of its ID.

use std::{collections::BTreeMap, io::ErrorKind, path::Path};

use ring::digest;
use serde::{Deserialize, Serialize};

use crate::{
    assignments::write_then_rename,
    error::{Error, Result},
};

/// File name of the approved rooms inside the data directory.
pub const APPROVED_FILE: &str = "rooms.json";

/// File name of the requested, not yet approved rooms.
pub const PENDING_FILE: &str = "rooms-pending.json";

/// Requests kept for the operator. Further new rooms are refused unrecorded.
pub const MAX_PENDING: usize = 64;

/// A room request: the first device that asked and the password proof it used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Room ID the device asked for.
    pub id: String,
    /// Password proof of the first requester; never listed.
    pub proof: String,
    /// Verifier hex of the requesting device.
    pub peer: String,
    /// Display name the device presented.
    pub name: String,
    /// Unix time in seconds of the first request.
    pub requested: u64,
}

/// An approved room and the password proof that opens it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approved {
    /// Room ID.
    pub id: String,
    /// Password proof fixed by the first requester; never listed.
    pub proof: String,
}

/// A listed room request without its password proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiting {
    /// Room ID the device asked for.
    pub id: String,
    /// Verifier hex of the requesting device.
    pub peer: String,
    /// Display name the device presented.
    pub name: String,
    /// Unix time in seconds of the first request.
    pub requested: u64,
}

/// What `overlay-hub rooms list` prints, keyed by room key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    /// Waiting requests.
    pub pending: BTreeMap<String, Waiting>,
    /// Approved rooms: key to room ID.
    pub approved: BTreeMap<String, String>,
}

/// How the hub treats a device that asks for a private room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The room is approved and the proof matches.
    Approved,
    /// The room awaits approval; the proof matches its first request.
    Waiting,
    /// The room ID is known and the proof differs.
    Denied,
}

/// Returns the room key: the SHA-256 hex of the room ID.
#[must_use]
pub fn key(id: &str) -> String {
    hex::encode(digest::digest(&digest::SHA256, id.as_bytes()))
}

/// Reports whether `room` is a canonical room key (64 lowercase hex digits).
#[must_use]
pub fn valid_room(room: &str) -> bool {
    room.len() == 64
        && room
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Compares two proofs without stopping at the first difference.
fn same(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left
            .bytes()
            .zip(right.bytes())
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

async fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match tokio::fs::read(path).await {
        Ok(raw) => Ok(Some(raw)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn load_approved(directory: &Path) -> Result<BTreeMap<String, Approved>> {
    let Some(raw) = read_optional(&directory.join(APPROVED_FILE)).await? else {
        return Ok(BTreeMap::new());
    };
    Ok(serde_json::from_slice(&raw)?)
}

async fn load_pending(directory: &Path) -> Result<BTreeMap<String, Request>> {
    let Some(raw) = read_optional(&directory.join(PENDING_FILE)).await? else {
        return Ok(BTreeMap::new());
    };
    Ok(serde_json::from_slice(&raw)?)
}

async fn save_pending(directory: &Path, pending: &BTreeMap<String, Request>) -> Result<()> {
    write_json(directory, PENDING_FILE, &serde_json::to_vec(pending)?).await
}

async fn save_approved(directory: &Path, approved: &BTreeMap<String, Approved>) -> Result<()> {
    write_json(directory, APPROVED_FILE, &serde_json::to_vec(approved)?).await
}

/// Decides whether a device may use the private room `id`. An unknown room is
/// recorded as a waiting request with its first requester; a known room never
/// gains a second request. The caller serializes calls.
///
/// # Errors
/// Returns an error when a room file cannot be read, parsed or written.
pub async fn admit(
    directory: &Path,
    id: &str,
    proof: &str,
    peer: &str,
    name: &str,
    requested: u64,
) -> Result<Admission> {
    let room = key(id);
    if let Some(approved) = load_approved(directory).await?.get(&room) {
        return Ok(if same(&approved.proof, proof) {
            Admission::Approved
        } else {
            Admission::Denied
        });
    }
    let mut pending = load_pending(directory).await?;
    if let Some(request) = pending.get(&room) {
        return Ok(if same(&request.proof, proof) {
            Admission::Waiting
        } else {
            Admission::Denied
        });
    }
    if pending.len() >= MAX_PENDING {
        return Ok(Admission::Waiting);
    }
    pending.insert(
        room,
        Request {
            id: id.to_owned(),
            proof: proof.to_owned(),
            peer: peer.to_owned(),
            name: name.to_owned(),
            requested,
        },
    );
    save_pending(directory, &pending).await?;
    Ok(Admission::Waiting)
}

/// Lists the waiting and approved rooms.
///
/// # Errors
/// Returns an error when either file cannot be read or parsed.
pub async fn listing(directory: &Path) -> Result<Listing> {
    let approved = load_approved(directory).await?;
    let pending = load_pending(directory)
        .await?
        .into_iter()
        .filter(|(room, _)| !approved.contains_key(room))
        .map(|(room, request)| {
            (
                room,
                Waiting {
                    id: request.id,
                    peer: request.peer,
                    name: request.name,
                    requested: request.requested,
                },
            )
        })
        .collect();
    let approved = approved
        .into_iter()
        .map(|(room, entry)| (room, entry.id))
        .collect();
    Ok(Listing { pending, approved })
}

/// Approves a requested room. Approving an approved room succeeds.
///
/// # Errors
/// Returns an error when `room` is malformed or was never requested, or when
/// a file cannot be read or written.
pub async fn approve(directory: &Path, room: &str) -> Result<()> {
    if !valid_room(room) {
        return Err(Error::Config("room is not a valid key"));
    }
    let mut approved = load_approved(directory).await?;
    if approved.contains_key(room) {
        return Ok(());
    }
    let mut pending = load_pending(directory).await?;
    let Some(request) = pending.remove(room) else {
        return Err(Error::Config("room has not been requested"));
    };
    approved.insert(
        room.to_owned(),
        Approved {
            id: request.id,
            proof: request.proof,
        },
    );
    save_approved(directory, &approved).await?;
    save_pending(directory, &pending).await
}

/// Removes an approved or waiting room. A device that asks for the room
/// again starts a new request. Devices already connected stay until they
/// reconnect.
///
/// # Errors
/// Returns an error when `room` is malformed or unknown, or when a file
/// cannot be read or written.
pub async fn remove(directory: &Path, room: &str) -> Result<()> {
    if !valid_room(room) {
        return Err(Error::Config("room is not a valid key"));
    }
    let mut approved = load_approved(directory).await?;
    let mut pending = load_pending(directory).await?;
    let found = approved.remove(room).is_some() | pending.remove(room).is_some();
    if !found {
        return Err(Error::Config("room is unknown"));
    }
    save_approved(directory, &approved).await?;
    save_pending(directory, &pending).await
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
    use super::{Admission, admit, approve, key, listing, remove, valid_room};
    use crate::error::Result;

    #[test]
    fn rooms_are_lowercase_hex_digests() -> Result<()> {
        ensure!(
            valid_room(&key("DUMMY room")),
            "a room key must be accepted"
        );
        ensure!(!valid_room(&"AB".repeat(32)), "uppercase must be refused");
        ensure!(!valid_room("ab"), "a short value must be refused");
        Ok(())
    }

    #[tokio::test]
    async fn a_known_room_id_never_gains_a_second_request() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let first = admit(dir.path(), "DUMMY room", "aa", "p1", "first", 7).await?;
        ensure!(first == Admission::Waiting, "a new room must wait");
        let other = admit(dir.path(), "DUMMY room", "bb", "p2", "second", 8).await?;
        ensure!(
            other == Admission::Denied,
            "another password must be denied"
        );
        let listed = listing(dir.path()).await?;
        ensure!(
            listed.pending.len() == 1
                && listed
                    .pending
                    .get(&key("DUMMY room"))
                    .map(|room| room.name.as_str())
                    == Some("first"),
            "the first requester must stay the only request"
        );
        approve(dir.path(), &key("DUMMY room")).await?;
        ensure!(
            admit(dir.path(), "DUMMY room", "aa", "p1", "first", 9).await? == Admission::Approved,
            "the first password must open the approved room"
        );
        ensure!(
            admit(dir.path(), "DUMMY room", "bb", "p2", "second", 9).await? == Admission::Denied,
            "another password must stay denied after approval"
        );
        ensure!(
            listing(dir.path()).await?.pending.is_empty(),
            "an approved room must leave the waiting list"
        );
        Ok(())
    }

    #[tokio::test]
    async fn removal_forgets_a_room_and_a_new_request_may_follow() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let room = key("DUMMY room");
        ensure!(
            approve(dir.path(), &room).await.is_err(),
            "an unrequested room must not be approved"
        );
        ensure!(
            remove(dir.path(), &room).await.is_err(),
            "an unknown room must not be removed"
        );
        admit(dir.path(), "DUMMY room", "aa", "p1", "first", 7).await?;
        approve(dir.path(), &room).await?;
        remove(dir.path(), &room).await?;
        ensure!(
            admit(dir.path(), "DUMMY room", "bb", "p2", "second", 8).await? == Admission::Waiting,
            "a removed room accepts a new first request"
        );
        Ok(())
    }
}
