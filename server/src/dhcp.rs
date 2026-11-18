//! Hub-owned address pool, idle lease lifetime and device reservations.

use std::{
    collections::{BTreeMap, HashSet},
    io::ErrorKind,
    net::Ipv4Addr,
    path::Path,
};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use crate::{AddressSpace, Error, Result, Verifier, assignments};

/// Persisted DHCP policy inside the hub data directory.
pub const DHCP_FILE: &str = "dhcp.json";
/// Maximum serialized policy size, enforced before parsing or writing.
pub const MAX_DHCP_BYTES: usize = 64 * 1024;

/// A fixed address reserved for an authenticated device identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// SHA-256 identifier already used by the hub's assignment table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Legacy uncompressed SEC1 public key. New editors never submit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Reserved usable address, which may be outside the dynamic pool.
    pub ip: Ipv4Addr,
}

impl Binding {
    pub(crate) fn verifier(&self) -> Option<Verifier> {
        match (&self.device_id, &self.public_key) {
            (Some(id), None)
                if id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
            {
                Verifier::from_hex(id)
            }
            (None, Some(key)) if *key == key.to_ascii_lowercase() => Verifier::from_public_key(key),
            _ => None,
        }
    }
}

/// Administrative policy; never supplied or overridden by a connecting client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcp {
    /// First dynamic address, inclusive.
    pub start: Ipv4Addr,
    /// Last dynamic address, inclusive.
    pub end: Ipv4Addr,
    /// Idle lease lifetime in seconds; zero retains capacity-based reclamation.
    pub lease_seconds: u64,
    /// Permanent device reservations; neither leased nor evicted.
    pub bindings: Vec<Binding>,
}

impl Default for Dhcp {
    fn default() -> Self {
        Self::for_space(AddressSpace::default())
    }
}

impl Dhcp {
    /// Select the whole usable subnet and preserve capacity-based idle eviction.
    #[must_use]
    pub fn for_space(space: AddressSpace) -> Self {
        let (start, end) = space.host_bounds();
        Self {
            start,
            end,
            lease_seconds: 0,
            bindings: Vec::new(),
        }
    }

    /// Validate the entire policy before changing persisted or runtime state.
    ///
    /// # Errors
    /// Rejects noncanonical identities, duplicate identities/addresses, unusable addresses,
    /// reversed/out-of-subnet pools, excessive leases and oversized binding lists.
    pub fn validate(&self, space: AddressSpace) -> Result<()> {
        if !space.assignable(self.start) || !space.assignable(self.end) || self.start > self.end {
            return Err(Error::Config(
                "DHCP pool must be an ordered usable range within the hub subnet",
            ));
        }
        if self.lease_seconds > 31_536_000 || (self.lease_seconds != 0 && self.lease_seconds < 60) {
            return Err(Error::Config(
                "DHCP lease must be 0 or 60 through 31536000 seconds",
            ));
        }
        if self.bindings.len() > 256 {
            return Err(Error::Config("too many DHCP bindings"));
        }
        let mut keys = HashSet::new();
        let mut addresses = HashSet::new();
        for binding in &self.bindings {
            let verifier = binding.verifier().ok_or(Error::Config(
                "DHCP binding requires one valid device identity",
            ))?;
            if !space.assignable(binding.ip)
                || !keys.insert(verifier)
                || !addresses.insert(binding.ip)
            {
                return Err(Error::Config(
                    "DHCP bindings must have unique device identities and unique usable addresses",
                ));
            }
        }
        Ok(())
    }
}

/// Load validated policy; absence preserves the original full-subnet allocator.
///
/// # Errors
/// Unreadable, malformed or invalid policy fails closed rather than using defaults.
pub async fn load(directory: &Path, space: AddressSpace) -> Result<Dhcp> {
    let path = directory.join(DHCP_FILE);
    let file = match tokio::fs::File::open(&path).await {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Dhcp::for_space(space)),
        Err(error) => return Err(error.into()),
        Ok(file) => file,
    };
    let mut raw = Vec::new();
    file.take(MAX_DHCP_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .await?;
    decode(&raw, space)
}

/// Read the editor's policy and known devices without exposing raw keys.
///
/// # Errors
/// Returns a read or validation error for corrupt hub state.
pub async fn editor(directory: &Path, space: AddressSpace) -> Result<serde_json::Value> {
    let mut policy = load(directory, space).await?;
    let mut devices = BTreeMap::new();
    for (id, record) in assignments::load(&directory.join(assignments::FILE_NAME), 0).await? {
        devices.insert(id.to_hex(), (record.ip, record.name));
    }
    for binding in &mut policy.bindings {
        let id = binding
            .verifier()
            .ok_or(Error::Config("invalid DHCP binding"))?
            .to_hex();
        devices
            .entry(id.clone())
            .and_modify(|(ip, _)| *ip = binding.ip)
            .or_insert_with(|| (binding.ip, String::new()));
        binding.device_id = Some(id);
        binding.public_key = None;
    }
    let devices: BTreeMap<_, _> = devices
        .into_iter()
        .map(|(id, (ip, name))| (id, serde_json::json!({"ip": ip, "name": name})))
        .collect();
    Ok(serde_json::json!({"policy": policy, "devices": devices}))
}

/// Decode and validate bounded administrative input.
///
/// # Errors
/// Returns an error for oversized, malformed or invalid policy without writes.
pub fn decode(raw: &[u8], space: AddressSpace) -> Result<Dhcp> {
    if raw.len() > MAX_DHCP_BYTES {
        return Err(Error::Config("DHCP policy is too large"));
    }
    let policy: Dhcp = serde_json::from_slice(raw)?;
    policy.validate(space)?;
    Ok(policy)
}

/// Atomically save a validated policy, or remove the override for subnet defaults.
/// A hub restart activates allocation changes.
///
/// # Errors
/// Rejects invalid input before writing; reports persistence errors without replacing
/// the previous policy with incomplete data.
pub async fn save(directory: &Path, space: AddressSpace, raw: &[u8]) -> Result<()> {
    let policy = decode(raw, space)?;
    let path = directory.join(DHCP_FILE);
    if policy == Dhcp::for_space(space) {
        return match tokio::fs::remove_file(&path).await {
            Err(error) if error.kind() != ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        };
    }
    if policy
        .bindings
        .iter()
        .any(|binding| binding.device_id.is_some())
    {
        let assignments = assignments::load(&directory.join(assignments::FILE_NAME), 0).await?;
        let existing: HashSet<_> = load(directory, space)
            .await?
            .bindings
            .iter()
            .filter_map(Binding::verifier)
            .collect();
        for binding in &policy.bindings {
            if binding.device_id.is_some()
                && !binding
                    .verifier()
                    .is_some_and(|id| assignments.contains_key(&id) || existing.contains(&id))
            {
                return Err(Error::Config(
                    "DHCP binding requires a device known to this hub",
                ));
            }
        }
    }
    tokio::fs::create_dir_all(directory).await?;
    let temporary = directory.join(format!(".dhcp-{}", hex::encode(rand::random::<[u8; 8]>())));
    let result =
        assignments::write_then_rename(&temporary, &path, &serde_json::to_vec(&policy)?).await;
    if result.is_err() {
        tokio::fs::remove_file(&temporary).await.ok();
    }
    result
}
