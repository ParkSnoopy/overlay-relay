//! Persistence of known identities in `ips.json`.
//!
//! The file maps verifier hex to the identity's address and the Unix time it
//! was last seen. Writes go through a temporary file created with mode 0600,
//! fsynced, then renamed over the old file.

use std::{
    collections::{BTreeMap, HashMap},
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use crate::{
    error::{Error, Result},
    verifier::Verifier,
};

/// File name of the persisted identities inside the data directory.
pub const FILE_NAME: &str = "ips.json";

/// One persisted identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// The identity's overlay address.
    pub ip: Ipv4Addr,
    /// Unix time in seconds when the identity last authenticated or disconnected.
    pub seen: u64,
}

/// File form of a [`Record`]. A bare address is the older form and counts as
/// seen at load time.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Stored {
    Record { ip: IpAddr, seen: u64 },
    Address(IpAddr),
}

/// Loads the persisted identities. A missing file yields an empty map; an
/// unreadable or corrupt file is an error, never silent renumbering.
///
/// # Errors
/// Returns `Error::CorruptAssignments` when the JSON is not a verifier-to-record
/// object, and `Error::Io` when the file cannot be read.
pub async fn load(path: &Path, now: u64) -> Result<HashMap<Verifier, Record>> {
    let raw = match tokio::fs::read(path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error.into()),
    };
    let stored: Option<HashMap<String, Stored>> =
        serde_json::from_slice(&raw).map_err(|_| Error::CorruptAssignments)?;
    let mut records = HashMap::new();
    for (key, value) in stored.unwrap_or_default() {
        let (ip, seen) = match value {
            Stored::Record { ip, seen } => (ip, seen),
            Stored::Address(ip) => (ip, now),
        };
        let (Some(verifier), IpAddr::V4(ip)) = (Verifier::from_hex(&key), ip) else {
            continue;
        };
        records.insert(verifier, Record { ip, seen });
    }
    Ok(records)
}

/// Atomically replaces the persisted identities.
///
/// # Errors
/// Returns an error when the temporary file cannot be created, written,
/// synced or renamed. The temporary file is removed on failure.
pub async fn save(path: &Path, records: &HashMap<Verifier, Record>) -> Result<()> {
    let document: BTreeMap<String, Stored> = records
        .iter()
        .map(|(verifier, record)| {
            (
                verifier.to_hex(),
                Stored::Record {
                    ip: IpAddr::V4(record.ip),
                    seen: record.seen,
                },
            )
        })
        .collect();
    let raw = serde_json::to_vec(&document)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let suffix: [u8; 8] = rand::random();
    let temporary = directory.join(format!(".ips-{}", hex::encode(suffix)));
    let result = write_then_rename(&temporary, path, &raw).await;
    if result.is_err() {
        tokio::fs::remove_file(&temporary).await.ok();
    }
    result
}

async fn write_then_rename(temporary: &Path, path: &Path, raw: &[u8]) -> Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temporary)
        .await?;
    file.write_all(raw).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(temporary, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::Ipv4Addr, os::unix::fs::PermissionsExt};

    use super::{FILE_NAME, Record, load, save};
    use crate::{
        error::{Error, Result},
        verifier::Verifier,
    };

    #[tokio::test]
    async fn saved_records_load_back_with_private_mode() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(FILE_NAME);
        let verifier = Verifier::from_digest([9; 32]);
        let record = Record {
            ip: Ipv4Addr::new(10, 77, 0, 7),
            seen: 1_700_000_000,
        };
        let mut records = HashMap::new();
        records.insert(verifier, record);
        save(&path, &records).await?;
        ensure_eq!(
            load(&path, 0).await?,
            records,
            "saved records must load back"
        );
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        ensure_eq!(mode, 0o600, "ips.json must not be world-readable");
        Ok(())
    }

    #[tokio::test]
    async fn bare_address_loads_as_seen_now() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(FILE_NAME);
        let verifier = Verifier::from_digest([3; 32]);
        tokio::fs::write(&path, format!(r#"{{"{}":"10.77.0.4"}}"#, verifier.to_hex())).await?;
        let records = load(&path, 42).await?;
        let expected = Record {
            ip: Ipv4Addr::new(10, 77, 0, 4),
            seen: 42,
        };
        ensure_eq!(
            records.get(&verifier),
            Some(&expected),
            "an address-only entry must load as seen now"
        );
        Ok(())
    }

    #[tokio::test]
    async fn missing_file_loads_empty() -> Result<()> {
        let dir = tempfile::tempdir()?;
        ensure!(
            load(&dir.path().join(FILE_NAME), 0).await?.is_empty(),
            "missing file must load empty"
        );
        Ok(())
    }

    #[tokio::test]
    async fn corrupt_file_is_an_error() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(FILE_NAME);
        tokio::fs::write(&path, b"garbage").await?;
        ensure!(
            matches!(load(&path, 0).await, Err(Error::CorruptAssignments)),
            "garbage must be a corrupt-assignments error"
        );
        Ok(())
    }

    #[tokio::test]
    async fn null_document_is_empty() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(FILE_NAME);
        tokio::fs::write(&path, b"null").await?;
        ensure!(
            load(&path, 0).await?.is_empty(),
            "null document must load empty"
        );
        Ok(())
    }
}
