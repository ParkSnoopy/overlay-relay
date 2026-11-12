//! Confirmed room replacement, including stale schemas.
use overlay_relay::{Admission, ROOMS_FILE, admit, create, key, replace};

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
    if create(directory.path(), "DUMMY", "New", &new).await.is_ok() {
        return Err("stale room silently overwritten".into());
    }
    replace(directory.path(), "DUMMY", "Repaired", &new).await?;
    if admit(directory.path(), "DUMMY", &new).await? != Admission::Admitted("Repaired".into()) {
        return Err("stale room was not repaired".into());
    }
    Ok(())
}
