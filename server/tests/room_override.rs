//! Confirmed room replacement, including stale schemas.
use overlay_relay::{Admission, ROOMS_FILE, admit, create, key, listing, remove, replace};

#[tokio::test]
async fn replacement_preserves_other_rooms_and_requires_valid_input()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let old = "ab".repeat(32);
    let new = "cd".repeat(32);
    create(directory.path(), "DUMMY", "Old", &old).await?;
    create(directory.path(), "OTHER", "Other", &old).await?;
    if create(directory.path(), "DUMMY", "New", &new).await.is_ok()
        || replace(directory.path(), "MISSING", "New", &new)
            .await
            .is_ok()
        || replace(directory.path(), "DUMMY", "New", "invalid")
            .await
            .is_ok()
    {
        return Err("unsafe replacement accepted".into());
    }
    replace(directory.path(), "DUMMY", "New", &new).await?;
    if admit(directory.path(), "DUMMY", &old).await? != Admission::Denied
        || admit(directory.path(), "DUMMY", &new).await? != Admission::Admitted("New".into())
        || admit(directory.path(), "OTHER", &old).await? != Admission::Admitted("Other".into())
    {
        return Err("replacement did not preserve admission boundaries".into());
    }
    let path = directory.path().join(ROOMS_FILE);
    let mut data: serde_json::Value = serde_json::from_slice(&tokio::fs::read(&path).await?)?;
    data[key("DUMMY")] = serde_json::json!({"legacy": true});
    tokio::fs::write(&path, serde_json::to_vec(&data)?).await?;
    if admit(directory.path(), "OTHER", &old).await? != Admission::Admitted("Other".into())
        || admit(directory.path(), "DUMMY", &old).await.is_ok()
        || listing(directory.path()).await?.rooms.len() != 2
    {
        return Err("stale sibling blocked a healthy room or granted admission".into());
    }
    if create(directory.path(), "DUMMY", "New", &new).await.is_ok() {
        return Err("stale room silently overwritten".into());
    }
    replace(directory.path(), "DUMMY", "Repaired", &new).await?;
    if admit(directory.path(), "DUMMY", &new).await? != Admission::Admitted("Repaired".into()) {
        return Err("stale room was not repaired".into());
    }
    Ok(())
}

#[tokio::test]
async fn legacy_approval_keys_remain_denied_and_can_be_repaired()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let legacy = key("DUMMY");
    tokio::fs::write(
        directory.path().join(ROOMS_FILE),
        serde_json::to_vec(&vec![&legacy])?,
    )
    .await?;
    if admit(directory.path(), "DUMMY", &"ab".repeat(32))
        .await
        .is_ok()
        || !listing(directory.path()).await?.rooms.contains_key(&legacy)
    {
        return Err("legacy approval granted admission or disappeared".into());
    }
    create(directory.path(), "OTHER", "Other", &"ab".repeat(32)).await?;
    remove(directory.path(), &legacy).await?;
    if listing(directory.path()).await?.rooms.len() != 1 {
        return Err("legacy recovery changed unrelated rooms".into());
    }
    Ok(())
}
