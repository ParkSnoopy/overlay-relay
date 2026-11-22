//! Durable room-local host labels. Addresses are only taken from live controls.

use std::{
    collections::BTreeMap,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tracing::warn;
use unicode_general_category::{GeneralCategory, get_general_category};

use crate::{
    assignments::write_then_rename,
    error::{Error, Result},
    rooms,
    verifier::Verifier,
};

const FILE_NAME: &str = "names.json";
const MAX_NAMES: usize = 16384;
const MAX_FILE: u64 = 4 << 20;
const ALIAS_PREFIX: &str = "id-";
const CORRUPT: Error = Error::Config("overlay name bindings are corrupt");
const UNAVAILABLE: Error = Error::Config("overlay name bindings are unavailable");

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    room: String,
    label: String,
    device: String,
}

/// Stores immutable name ownership independently of address assignments.
#[derive(Debug)]
pub struct Namespace {
    directory: PathBuf,
    rooms: BTreeMap<String, BTreeMap<String, Verifier>>,
    count: usize,
    failed: bool,
}

impl Namespace {
    pub(crate) async fn load(directory: &Path) -> Self {
        let mut names = Self {
            directory: directory.to_owned(),
            rooms: BTreeMap::new(),
            count: 0,
            failed: false,
        };
        if let Err(error) = names.read().await {
            warn!(error = %error, "overlay DNS is disabled until its name store is repaired and the hub restarts");
            names.failed = true;
        }
        names
    }

    async fn read(&mut self) -> Result<()> {
        let file = match tokio::fs::File::open(self.directory.join(FILE_NAME)).await {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let mut raw = Vec::new();
        if file.take(MAX_FILE + 1).read_to_end(&mut raw).await? as u64 > MAX_FILE {
            return Err(CORRUPT);
        }
        let bindings: Vec<Binding> = serde_json::from_slice(&raw).map_err(|_| CORRUPT)?;
        if bindings.len() > MAX_NAMES {
            return Err(CORRUPT);
        }
        for Binding {
            room,
            label,
            device,
        } in bindings
        {
            let Some(owner) = Verifier::from_hex(&device).filter(|_| rooms::valid_room(&device))
            else {
                return Err(CORRUPT);
            };
            if (!room.is_empty() && !rooms::valid_room(&room))
                || !valid_label(&label)
                || alias_label(&label)
                || self
                    .rooms
                    .entry(room)
                    .or_default()
                    .insert(label, owner)
                    .is_some()
            {
                return Err(CORRUPT);
            }
            self.count += 1;
        }
        Ok(())
    }

    /// Claim a normalized label once. Reconnects and collisions never change its owner.
    pub(crate) async fn reserve(&mut self, room: &str, name: &str, owner: Verifier) {
        if self.failed || self.count >= MAX_NAMES {
            return;
        }
        let Some(label) = normalize(name).filter(|label| !alias_label(label)) else {
            return;
        };
        let names = self.rooms.entry(room.to_owned()).or_default();
        if names.contains_key(&label) {
            return;
        }
        names.insert(label, owner);
        if let Err(error) = self.save().await {
            // A directory sync can fail after rename. Do not publish or allow any
            // conflicting reservation until the next load establishes disk state.
            warn!(error = %error, "overlay DNS name bindings could not be saved");
            self.failed = true;
        } else {
            self.count += 1;
        }
    }

    async fn save(&self) -> Result<()> {
        let bindings: Vec<_> = self
            .rooms
            .iter()
            .flat_map(|(room, labels)| {
                labels.iter().map(|(label, owner)| {
                    Binding {
                        room: room.clone(),
                        label: label.clone(),
                        device: owner.to_hex(),
                    }
                })
            })
            .collect();
        let raw = serde_json::to_vec(&bindings)?;
        let path = self.directory.join(FILE_NAME);
        let suffix: [u8; 8] = rand::random();
        let temporary = self
            .directory
            .join(format!(".names-{}", hex::encode(suffix)));
        if let Err(error) = write_then_rename(&temporary, &path, &raw).await {
            tokio::fs::remove_file(&temporary).await.ok();
            return Err(error);
        }
        tokio::fs::File::open(&self.directory)
            .await?
            .sync_all()
            .await?;
        Ok(())
    }

    pub(crate) fn owner(&self, room: &str, label: &str) -> Result<Option<Verifier>> {
        if self.failed {
            return Err(UNAVAILABLE);
        }
        if !valid_label(label) {
            return Ok(None);
        }
        if alias_label(label) {
            let encoded = &label[ALIAS_PREFIX.len()..];
            let owner = BASE32_NOPAD
                .decode(encoded.to_ascii_uppercase().as_bytes())
                .ok()
                .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
                .map(Verifier::from_digest);
            return Ok(owner);
        }
        Ok(self
            .rooms
            .get(room)
            .and_then(|names| names.get(label))
            .copied())
    }
}

/// Returns the stable room key without the rotatable admission proof.
pub fn room_key(room: &str) -> &str {
    room.split_once(':').map_or(room, |(key, _)| key)
}

fn alias_label(label: &str) -> bool {
    label.len() == ALIAS_PREFIX.len() + 52
        && label.strip_prefix(ALIAS_PREFIX).is_some_and(|encoded| {
            encoded
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        })
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

// Match the host-label conversion used by the former client-side resolver.
fn normalize(name: &str) -> Option<String> {
    use GeneralCategory::{
        ClosePunctuation,
        ConnectorPunctuation,
        DashPunctuation,
        DecimalNumber,
        EnclosingMark,
        FinalPunctuation,
        InitialPunctuation,
        LetterNumber,
        LowercaseLetter,
        ModifierLetter,
        NonspacingMark,
        OpenPunctuation,
        OtherLetter,
        OtherNumber,
        OtherPunctuation,
        SpacingMark,
        TitlecaseLetter,
        UppercaseLetter,
    };
    let mut value = String::new();
    let mut separator = false;
    for character in name.chars() {
        match get_general_category(character) {
            _ if character == '-' => (),
            _ if character.is_whitespace() => {
                separator = !value.is_empty();
                continue;
            }
            ClosePunctuation | ConnectorPunctuation | DashPunctuation | FinalPunctuation
            | InitialPunctuation | OpenPunctuation | OtherPunctuation => {
                separator = !value.is_empty();
                continue;
            }
            DecimalNumber | LetterNumber | OtherNumber | LowercaseLetter | ModifierLetter
            | OtherLetter | TitlecaseLetter | UppercaseLetter | EnclosingMark | NonspacingMark
            | SpacingMark => (),
            _ => return None,
        }
        if separator && character != '-' {
            value.push('-');
        }
        separator = false;
        value.push(character);
    }
    let label = idna::domain_to_ascii(value.trim_matches('-')).ok()?;
    valid_label(&label).then_some(label)
}
