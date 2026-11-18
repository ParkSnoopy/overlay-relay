//! Authoritative DHCP policy persistence and allocator regressions.
use std::{error::Error, fs, os::unix::fs::PermissionsExt};

use overlay_relay::{
    AddressSpace,
    Verifier,
    dhcp::{self, Binding, Dhcp},
};

const KEY: &str = concat!(
    "04",
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
);

#[tokio::test]
async fn persistence_rejects_invalid_input_without_mutation() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let space: AddressSpace = "10.77.0.0/30".parse()?;
    let mut policy = Dhcp::for_space(space);
    policy.lease_seconds = 3600;
    let raw = serde_json::to_vec(&policy)?;
    dhcp::save(dir.path(), space, &raw).await?;
    let path = dir.path().join(dhcp::DHCP_FILE);
    if dhcp::load(dir.path(), space).await? != policy
        || fs::metadata(&path)?.permissions().mode() & 0o777 != 0o600
    {
        return Err("saved policy or private mode differs".into());
    }
    let mut invalid = policy.clone();
    invalid.lease_seconds = 1;
    if dhcp::save(dir.path(), space, &serde_json::to_vec(&invalid)?)
        .await
        .is_ok()
        || fs::read(&path)? != raw
    {
        return Err("invalid lease was accepted or altered the saved policy".into());
    }
    for broken in [b"null".to_vec(), vec![b' '; dhcp::MAX_DHCP_BYTES + 1]] {
        fs::write(&path, broken)?;
        if dhcp::load(dir.path(), space).await.is_ok() {
            return Err("invalid stored policy loaded".into());
        }
    }

    dhcp::save(
        dir.path(),
        space,
        &serde_json::to_vec(&Dhcp::for_space(space))?,
    )
    .await?;
    let next_space: AddressSpace = "10.80.0.0/24".parse()?;
    if path.exists() || dhcp::load(dir.path(), next_space).await? != Dhcp::for_space(next_space) {
        return Err("restoring defaults retained subnet-specific policy".into());
    }
    Ok(())
}

#[test]
fn reservations_are_validated_before_mutation() -> Result<(), Box<dyn Error>> {
    let space: AddressSpace = "10.77.0.0/30".parse()?;
    let reserved_ip = "10.77.0.1".parse()?;

    let mut policy = Dhcp::for_space(space);
    policy.lease_seconds = 60;
    policy.bindings.push(Binding {
        device_id: None,
        public_key: Some(KEY.to_owned()),
        ip: reserved_ip,
    });
    policy.validate(space)?;
    policy.bindings.push(policy.bindings[0].clone());
    if policy.validate(space).is_ok() {
        return Err("duplicate binding was accepted".into());
    }
    policy.bindings.pop();
    let id = Verifier::from_public_key(KEY)
        .ok_or("invalid fixture key")?
        .to_hex();
    policy.bindings.push(Binding {
        device_id: Some(id.clone()),
        public_key: None,
        ip: "10.77.0.2".parse()?,
    });
    if policy.validate(space).is_ok() {
        return Err("legacy key and its device ID were accepted as distinct".into());
    }
    policy.bindings.remove(0);
    policy.validate(space)?;
    policy.bindings[0].device_id = Some(id.to_ascii_uppercase());
    if policy.validate(space).is_ok() {
        return Err("noncanonical device ID was accepted".into());
    }
    policy.bindings[0].device_id = None;
    policy.bindings[0].public_key = Some("04".repeat(97));
    if policy.validate(space).is_ok() {
        return Err("invalid public key was accepted".into());
    }
    Ok(())
}

#[tokio::test]
async fn editor_names_devices_without_exposing_legacy_keys() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let space: AddressSpace = "10.77.0.0/29".parse()?;
    let id = Verifier::from_public_key(KEY)
        .ok_or("invalid fixture key")?
        .to_hex();
    let unnamed = Verifier::from_digest([1; 32]).to_hex();
    let path = dir.path();
    tokio::fs::write(
        path.join("ips.json"),
        serde_json::to_vec(&serde_json::json!({
            id.clone(): {"ip": "10.77.0.2", "seen": 1, "name": "Test laptop"},
            unnamed.clone(): {"ip": "10.77.0.3", "seen": 1},
        }))?,
    )
    .await?;
    let policy = serde_json::json!({
        "start": "10.77.0.1", "end": "10.77.0.6", "lease_seconds": 0,
        "bindings": [{"public_key": KEY, "ip": "10.77.0.5"}],
    });
    dhcp::save(path, space, &serde_json::to_vec(&policy)?).await?;
    let editor = dhcp::editor(path, space).await?;
    if editor["devices"][&id] != serde_json::json!({"name": "Test laptop", "ip": "10.77.0.5"})
        || editor["devices"][&unnamed] != serde_json::json!({"name": "", "ip": "10.77.0.3"})
        || editor["policy"]["bindings"][0]
            != serde_json::json!({"device_id": id, "ip": "10.77.0.5"})
    {
        return Err("DHCP editor did not resolve devices to names, addresses and IDs".into());
    }
    Ok(())
}
