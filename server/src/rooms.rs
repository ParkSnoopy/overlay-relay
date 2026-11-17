//! Operator-created private rooms.
//!
//! A private room is a room ID, a display name and the password proof a client
//! derives from the password. The operator creates the room with
//! `overlay-hub rooms create`; the hub never creates one. A device that asks
//! for an unknown room ID, or for a known one with another proof, is refused.
//! Only the `rooms` command writes `rooms.json`; the hub reads it on every
//! private-room connection, so creation and removal need no restart. A room is
//! addressed by the SHA-256 hex of its ID, and the hub never learns the password.

use std::{collections::BTreeMap, io::ErrorKind, path::Path};

use ring::digest;
use serde::{Deserialize, Serialize};

use crate::{
    assignments::write_then_rename,
    error::{Error, Result},
    protocol::valid_name,
};

/// File name of the created rooms inside the data directory.
pub const ROOMS_FILE: &str = "rooms.json";

/// A created room and the password proof that opens it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Room {
    /// Room ID.
    pub id: String,
    /// Display name shown to the room's members; empty falls back to the ID.
    #[serde(default)]
    pub name: String,
    /// Password proof fixed at creation; never listed.
    pub proof: String,
    /// Whether new payload relay flows may be opened in this room.
    #[serde(default = "relay_default")]
    pub relay: bool,
}

/// A listed room without its password proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listed {
    /// Room ID.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Whether payload relay is permitted.
    pub relay: bool,
}

/// What `overlay-hub rooms list` prints, keyed by room key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    /// Public-room payload relay policy.
    pub public_relay: bool,
    /// Created rooms.
    pub rooms: BTreeMap<String, Listed>,
}

/// How the hub treats a device that asks for a private room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The room exists and the proof matches; carries the room's display name.
    Admitted(String),
    /// No room has this ID.
    Unknown,
    /// The room ID is known and the proof differs.
    Denied,
    /// Storage is unavailable or the selected record is invalid.
    Unavailable,
}

/// Returns the room key: the SHA-256 hex of the room ID.
#[must_use]
pub fn key(id: &str) -> String {
    hex::encode(digest::digest(&digest::SHA256, id.as_bytes()))
}

/// Reports whether `room` is a canonical room key or proof (64 lowercase hex digits).
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

async fn load(directory: &Path) -> Result<BTreeMap<String, serde_json::Value>> {
    match tokio::fs::read(directory.join(ROOMS_FILE)).await {
        Ok(raw) => {
            let value: serde_json::Value = serde_json::from_slice(&raw)?;
            if let Some(legacy) = value.as_array() {
                let mut rooms = BTreeMap::new();
                for entry in legacy {
                    let room = entry
                        .as_str()
                        .filter(|room| valid_room(room))
                        .ok_or(Error::Config("legacy room key is not valid"))?;
                    rooms.insert(room.to_owned(), serde_json::Value::Null);
                }
                return Ok(rooms);
            }
            Ok(serde_json::from_value(value)?)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(error) => Err(error.into()),
    }
}

fn decode_room(room_key: &str, value: serde_json::Value) -> Result<Room> {
    let room: Room = serde_json::from_value(value)?;
    if room.id.is_empty()
        || !valid_name(&room.id)
        || !valid_name(&room.name)
        || !valid_room(&room.proof)
        || key(&room.id) != room_key
    {
        return Err(Error::Config("room record is not valid"));
    }
    Ok(room)
}

async fn save<T: Serialize + Sync>(directory: &Path, rooms: &BTreeMap<String, T>) -> Result<()> {
    let suffix: [u8; 8] = rand::random();
    let temporary = directory.join(format!(".rooms-{}", hex::encode(suffix)));
    let result = write_then_rename(
        &temporary,
        &directory.join(ROOMS_FILE),
        &serde_json::to_vec(rooms)?,
    )
    .await;
    if result.is_err() {
        tokio::fs::remove_file(&temporary).await.ok();
    }
    result
}

/// Decides whether a device may use the private room `id`.
///
/// # Errors
/// Returns an error when the room file cannot be read or parsed.
pub async fn admit(directory: &Path, id: &str, proof: &str) -> Result<Admission> {
    let room_key = key(id);
    let rooms = load(directory).await?;
    let room = rooms
        .get(&room_key)
        .cloned()
        .map(|value| decode_room(&room_key, value))
        .transpose()?;
    Ok(match room {
        None => Admission::Unknown,
        Some(room) if same(&room.proof, proof) => {
            Admission::Admitted(if room.name.is_empty() {
                room.id
            } else {
                room.name
            })
        }
        Some(_) => Admission::Denied,
    })
}

/// Lists the created rooms.
///
/// # Errors
/// Returns an error when the room file cannot be read or parsed.
pub async fn listing(directory: &Path) -> Result<Listing> {
    let mut records = load(directory).await?;
    let public_relay = public_policy(records.remove("public"))?;
    let rooms = records
        .into_iter()
        .map(|(room, entry)| {
            let Ok(entry) = decode_room(&room, entry) else {
                return (
                    room,
                    Listed {
                        id: String::new(),
                        name: "Invalid room record — replace or remove".to_owned(),
                        relay: false,
                    },
                );
            };
            let name = if entry.name.is_empty() {
                entry.id.clone()
            } else {
                entry.name
            };
            (
                room,
                Listed {
                    id: entry.id,
                    name,
                    relay: entry.relay,
                },
            )
        })
        .collect();
    Ok(Listing {
        public_relay,
        rooms,
    })
}

/// Creates a room. A room ID is unique, so creating a known ID fails.
///
/// # Errors
/// Returns an error when the ID, name or proof is malformed, when the room
/// exists, or when the room file cannot be read or written.
pub async fn create(directory: &Path, id: &str, name: &str, proof: &str) -> Result<()> {
    configure(directory, id, name, proof, false, None).await
}

/// Replaces one existing room after explicit operator confirmation.
///
/// # Errors
/// Rejects invalid input, missing rooms and unreadable or unwritable storage.
pub async fn replace(directory: &Path, id: &str, name: &str, proof: &str) -> Result<()> {
    configure(directory, id, name, proof, true, None).await
}

/// Creates or explicitly replaces a room with an optional relay policy.
///
/// # Errors
/// Rejects invalid input, conflicting existence or inaccessible storage.
pub async fn configure(
    directory: &Path,
    id: &str,
    name: &str,
    proof: &str,
    replace: bool,
    relay: Option<bool>,
) -> Result<()> {
    if id.is_empty() || !valid_name(id) {
        return Err(Error::Config("room ID is not valid"));
    }
    if !valid_name(name) {
        return Err(Error::Config("room name is not valid"));
    }
    if !valid_room(proof) {
        return Err(Error::Config("room password proof is not valid"));
    }
    // Preserve unrelated entries, including records from older binaries. Only
    // the explicitly selected key is rewritten into the current schema.
    let mut rooms = load(directory).await?;
    let room = key(id);
    if rooms.contains_key(&room) && !replace {
        return Err(Error::Config("room already exists"));
    }
    if !rooms.contains_key(&room) && replace {
        return Err(Error::Config("room is unknown"));
    }
    let relay = relay.unwrap_or_else(|| {
        rooms
            .get(&room)
            .and_then(|entry| entry.get("relay"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true)
    });
    rooms.insert(
        room,
        serde_json::to_value(Room {
            id: id.to_owned(),
            name: name.to_owned(),
            proof: proof.to_owned(),
            relay,
        })?,
    );
    save(directory, &rooms).await
}

const fn relay_default() -> bool {
    true
}

fn public_policy(value: Option<serde_json::Value>) -> Result<bool> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Policy {
        relay: bool,
    }
    value.map_or(Ok(true), |value| {
        serde_json::from_value::<Policy>(value)
            .map(|policy| policy.relay)
            .map_err(Into::into)
    })
}

/// Reads the current payload relay policy. Empty ID denotes the public room.
///
/// # Errors
/// Unknown, malformed or unreadable room policy fails closed.
pub async fn relay_allowed(directory: &Path, id: &str) -> Result<bool> {
    let mut rooms = load(directory).await?;
    if id.is_empty() {
        return public_policy(rooms.remove("public"));
    }
    let room_key = key(id);
    let value = rooms
        .remove(&room_key)
        .ok_or(Error::Config("room is unknown"))?;
    Ok(decode_room(&room_key, value)?.relay)
}

/// Changes only relay policy, preserving passwords and unrelated records.
/// `public` names the public room; private rooms use their hashed key.
///
/// # Errors
/// Rejects malformed or missing room keys and inaccessible storage.
pub async fn set_relay(directory: &Path, room: &str, relay: bool) -> Result<()> {
    if room != "public" && !valid_room(room) {
        return Err(Error::Config("room is not a valid key"));
    }
    let mut rooms = load(directory).await?;
    let value = if room == "public" {
        serde_json::json!({"relay": relay})
    } else {
        let value = rooms
            .get(room)
            .cloned()
            .ok_or(Error::Config("room is unknown"))?;
        let mut record = decode_room(room, value)?;
        record.relay = relay;
        serde_json::to_value(record)?
    };
    rooms.insert(room.to_owned(), value);
    save(directory, &rooms).await
}

/// Removes a room. Devices already connected stay until they reconnect.
///
/// # Errors
/// Returns an error when `room` is malformed or unknown, or when the room
/// file cannot be read or written.
pub async fn remove(directory: &Path, room: &str) -> Result<()> {
    if !valid_room(room) {
        return Err(Error::Config("room is not a valid key"));
    }
    let mut rooms = load(directory).await?;
    if rooms.remove(room).is_none() {
        return Err(Error::Config("room is unknown"));
    }
    save(directory, &rooms).await
}

#[cfg(test)]
mod tests {
    use super::{Admission, admit, create, key, listing, remove, valid_room};
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
    async fn only_a_created_room_with_its_proof_is_admitted() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let proof = "ab".repeat(32);
        ensure!(
            admit(dir.path(), "DUMMY room", &proof).await? == Admission::Unknown,
            "a room nobody created must be unknown"
        );
        create(dir.path(), "DUMMY room", "DUMMY name", &proof).await?;
        ensure!(
            admit(dir.path(), "DUMMY room", &proof).await?
                == Admission::Admitted("DUMMY name".to_owned()),
            "the creation proof must open the room"
        );
        ensure!(
            admit(dir.path(), "DUMMY room", &"cd".repeat(32)).await? == Admission::Denied,
            "another proof must be denied"
        );
        ensure!(
            create(dir.path(), "DUMMY room", "other", &"cd".repeat(32))
                .await
                .is_err(),
            "a room ID is unique"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_unnamed_room_shows_its_id_and_removal_forgets_it() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let proof = "ab".repeat(32);
        create(dir.path(), "DUMMY room", "", &proof).await?;
        let listed = listing(dir.path()).await?;
        ensure!(
            listed
                .rooms
                .get(&key("DUMMY room"))
                .map(|room| room.name.as_str())
                == Some("DUMMY room"),
            "an empty name must fall back to the ID"
        );
        ensure!(
            remove(dir.path(), "nope").await.is_err(),
            "a malformed key must be refused"
        );
        remove(dir.path(), &key("DUMMY room")).await?;
        ensure!(
            remove(dir.path(), &key("DUMMY room")).await.is_err(),
            "a removed room is unknown"
        );
        ensure!(
            admit(dir.path(), "DUMMY room", &proof).await? == Admission::Unknown,
            "a removed room must refuse its old proof"
        );
        Ok(())
    }

    #[tokio::test]
    async fn invalid_rooms_are_not_created() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let proof = "ab".repeat(32);
        ensure!(
            create(dir.path(), "", "name", &proof).await.is_err(),
            "an empty ID must be refused"
        );
        ensure!(
            create(dir.path(), "id", "bad\nname", &proof).await.is_err(),
            "a multi-line name must be refused"
        );
        ensure!(
            create(dir.path(), "id", "name", "short").await.is_err(),
            "a malformed proof must be refused"
        );
        Ok(())
    }
}
