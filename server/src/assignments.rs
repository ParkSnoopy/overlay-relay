//! Persistence of overlay address assignments in `ips.json`.
//!
//! The file maps verifier hex to an `IPv4` address. Writes go through a temporary
//! file created with mode 0600, fsynced, then renamed over the old file.

use std::{
    collections::{BTreeMap, HashMap},
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use tokio::io::AsyncWriteExt;

use crate::{
    error::{Error, Result},
    verifier::Verifier,
};

/// File name of the persisted assignments inside the data directory.
pub const FILE_NAME: &str = "ips.json";

/// Loads the persisted assignments. A missing file yields an empty map; an
/// unreadable or corrupt file is an error, never silent renumbering.
///
/// # Errors
/// Returns `Error::CorruptAssignments` when the JSON is not a verifier-to-address
/// object, and `Error::Io` when the file cannot be read.
pub async fn load(path: &Path) -> Result<HashMap<Verifier, Ipv4Addr>> {
    let raw = match tokio::fs::read(path).await {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error.into()),
    };
    let stored: Option<HashMap<String, IpAddr>> =
        serde_json::from_slice(&raw).map_err(|_| Error::CorruptAssignments)?;
    let mut assignments = HashMap::new();
    for (key, value) in stored.unwrap_or_default() {
        let (Some(verifier), IpAddr::V4(address)) = (Verifier::from_hex(&key), value) else {
            continue;
        };
        assignments.insert(verifier, address);
    }
    Ok(assignments)
}

/// Atomically replaces the persisted assignments.
///
/// # Errors
/// Returns an error when the temporary file cannot be created, written,
/// synced or renamed. The temporary file is removed on failure.
pub async fn save(path: &Path, assignments: &HashMap<Verifier, Ipv4Addr>) -> Result<()> {
    let document: BTreeMap<String, Ipv4Addr> = assignments
        .iter()
        .map(|(verifier, address)| (verifier.to_hex(), *address))
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

    use super::{FILE_NAME, load, save};
    use crate::{
        error::{Error, Result},
        verifier::Verifier,
    };

    #[tokio::test]
    async fn saved_assignments_load_back_with_private_mode() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(FILE_NAME);
        let verifier = Verifier::from_digest([9; 32]);
        let address = Ipv4Addr::new(10, 77, 0, 7);
        let mut assignments = HashMap::new();
        assignments.insert(verifier, address);
        save(&path, &assignments).await?;
        ensure_eq!(
            load(&path).await?,
            assignments,
            "saved assignments must load back"
        );
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        ensure_eq!(mode, 0o600, "ips.json must not be world-readable");
        Ok(())
    }

    #[tokio::test]
    async fn missing_file_loads_empty() -> Result<()> {
        let dir = tempfile::tempdir()?;
        ensure!(
            load(&dir.path().join(FILE_NAME)).await?.is_empty(),
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
            matches!(load(&path).await, Err(Error::CorruptAssignments)),
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
            load(&path).await?.is_empty(),
            "null document must load empty"
        );
        Ok(())
    }
}
