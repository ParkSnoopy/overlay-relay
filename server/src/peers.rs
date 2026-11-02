//! The read-only accounts table written by the server manager.

use std::collections::HashSet;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::protocol::{MAX_ACCOUNTS, VERSION};
use crate::verifier::Verifier;

/// Largest peers table the hub reads, in bytes.
pub const MAX_PEERS_FILE: u64 = 4 << 20;

/// Longest display name accepted, in bytes.
pub const MAX_NAME_LEN: usize = 128;

/// One account in the peers table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    verifier: Verifier,
    name: String,
}

impl Account {
    /// The account's verifier.
    #[must_use]
    pub const fn verifier(&self) -> Verifier {
        self.verifier
    }

    /// The account's display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A validated peers table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peers {
    accounts: Vec<Account>,
}

#[derive(Deserialize)]
struct Document {
    version: u32,
    #[serde(default)]
    accounts: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    verifier: String,
    #[serde(default)]
    name: String,
}

impl Peers {
    /// Parses and validates a peers table: version 1, at most 4096 accounts,
    /// unique 64-digit hex verifiers and names of at most 128 bytes.
    ///
    /// # Errors
    /// Returns `Error::Json` when the bytes are not JSON of the expected shape
    /// and `Error::Peers` when validation fails.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let document: Document = serde_json::from_slice(raw)?;
        Self::validate(document)
    }

    /// The accounts in table order.
    #[must_use]
    pub fn accounts(&self) -> &[Account] {
        &self.accounts
    }

    fn validate(document: Document) -> Result<Self> {
        if document.version != VERSION || document.accounts.len() > MAX_ACCOUNTS {
            return Err(Error::Peers("invalid overlay peers table"));
        }
        let mut seen = HashSet::with_capacity(document.accounts.len());
        let mut accounts = Vec::with_capacity(document.accounts.len());
        for entry in document.accounts {
            let Some(verifier) = Verifier::from_hex(&entry.verifier) else {
                return Err(Error::Peers("invalid overlay account"));
            };
            if entry.name.len() > MAX_NAME_LEN || !seen.insert(verifier) {
                return Err(Error::Peers("invalid overlay account"));
            }
            accounts.push(Account {
                verifier,
                name: entry.name,
            });
        }
        Ok(Self { accounts })
    }
}

#[cfg(test)]
mod tests {
    use super::Peers;
    use crate::error::Error;
    use crate::verifier::Verifier;

    fn entry(byte: u8, name: &str) -> String {
        let hex = Verifier::from_digest([byte; 32]).to_hex();
        format!(r#"{{"verifier":"{hex}","name":"{name}"}}"#)
    }

    fn table(version: u32, entries: &[String]) -> Vec<u8> {
        format!(
            r#"{{"version":{version},"accounts":[{}]}}"#,
            entries.join(",")
        )
        .into_bytes()
    }

    #[test]
    fn valid_table_keeps_order_and_names() {
        let raw = table(1, &[entry(1, "alice"), entry(2, "bob")]);
        let names: Vec<String> = Peers::parse(&raw).map_or_else(
            |_| Vec::new(),
            |table| {
                table
                    .accounts()
                    .iter()
                    .map(|a| a.name().to_owned())
                    .collect()
            },
        );
        assert_eq!(names, vec!["alice".to_owned(), "bob".to_owned()]);
    }

    #[test]
    fn empty_table_is_valid() {
        assert!(Peers::parse(&table(1, &[])).is_ok());
    }

    #[test]
    fn wrong_version_is_rejected() {
        let result = Peers::parse(&table(2, &[entry(1, "alice")]));
        assert!(
            matches!(result, Err(Error::Peers(_))),
            "version 2 must fail"
        );
    }

    #[test]
    fn duplicate_verifiers_are_rejected() {
        let result = Peers::parse(&table(1, &[entry(1, "alice"), entry(1, "again")]));
        assert!(
            matches!(result, Err(Error::Peers(_))),
            "duplicate verifier must fail"
        );
    }

    #[test]
    fn bad_hex_verifier_is_rejected() {
        let raw = br#"{"version":1,"accounts":[{"verifier":"zz","name":"x"}]}"#;
        assert!(matches!(Peers::parse(raw), Err(Error::Peers(_))));
    }

    #[test]
    fn overlong_name_is_rejected() {
        let long = "n".repeat(129);
        let result = Peers::parse(&table(1, &[entry(1, &long)]));
        assert!(
            matches!(result, Err(Error::Peers(_))),
            "129-byte name must fail"
        );
        let exact = "n".repeat(128);
        assert!(
            Peers::parse(&table(1, &[entry(1, &exact)])).is_ok(),
            "128 bytes is allowed"
        );
    }

    #[test]
    fn too_many_accounts_are_rejected() {
        let entries: Vec<String> = (0..4097_u32)
            .map(|index| {
                let digest = index.to_be_bytes();
                let mut bytes = [0_u8; 32];
                bytes[..4].copy_from_slice(&digest);
                let hex = Verifier::from_digest(bytes).to_hex();
                format!(r#"{{"verifier":"{hex}","name":"n"}}"#)
            })
            .collect();
        assert!(matches!(
            Peers::parse(&table(1, &entries)),
            Err(Error::Peers(_))
        ));
    }

    #[test]
    fn malformed_json_is_an_error() {
        assert!(matches!(Peers::parse(b"{"), Err(Error::Json(_))));
    }
}
