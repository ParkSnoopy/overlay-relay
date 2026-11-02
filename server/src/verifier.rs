//! Account identifiers derived from public keys.

use std::fmt;

use sha2::{Digest, Sha256};

/// The SHA-256 digest of an uncompressed P-384 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Verifier([u8; 32]);

impl Verifier {
    /// Wraps an existing 32-byte digest.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Derives the identifier of an uncompressed P-384 public key.
    #[must_use]
    pub fn from_public_key(public_key: &str) -> Option<Self> {
        let raw: [u8; 97] = hex::decode(public_key).ok()?.try_into().ok()?;
        if raw[0] != 4 {
            return None;
        }
        p384::PublicKey::from_sec1_bytes(&raw).ok()?;
        let digest: [u8; 32] = Sha256::digest(raw).into();
        Some(Self(digest))
    }

    /// Parses a verifier stored as 64 hex digits in the peers table.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        let digest: [u8; 32] = hex::decode(text).ok()?.try_into().ok()?;
        Some(Self(digest))
    }

    /// Encodes the verifier as 64 lowercase hex digits.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    /// Compares two verifiers in time independent of where they differ.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        let difference = self
            .0
            .iter()
            .zip(other.0.iter())
            .fold(0_u8, |accumulated, (left, right)| {
                accumulated | (left ^ right)
            });
        difference == 0
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Verifier(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::Verifier;

    fn token_hex(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    #[test]
    fn public_key_derives_digest_of_raw_bytes() {
        let public_key = concat!(
            "04",
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
        );
        let verifier = Verifier::from_public_key(public_key);
        assert!(verifier.is_some(), "an encoded key must have an identifier");
        let hex = verifier.map_or_else(String::new, Verifier::to_hex);
        assert_eq!(hex.len(), 64);
        assert_eq!(Verifier::from_hex(&hex), verifier, "hex must round-trip");
    }

    #[test]
    fn malformed_keys_have_no_verifier() {
        assert!(Verifier::from_public_key("").is_none(), "empty key");
        assert!(
            Verifier::from_public_key("not-hex").is_none(),
            "non-hex key"
        );
        assert!(
            Verifier::from_public_key(&token_hex('1')[..62]).is_none(),
            "short key"
        );
        assert!(
            Verifier::from_public_key(&format!("04{}", "11".repeat(97))).is_none(),
            "long key"
        );
        assert!(
            Verifier::from_hex(&token_hex('z')).is_none(),
            "non-hex verifier"
        );
    }

    #[test]
    fn matching_is_exact() {
        let first = Verifier::from_digest([7; 32]);
        let mut other = [7_u8; 32];
        assert!(first.matches(&Verifier::from_digest(other)));
        other[31] = 8;
        assert!(
            !first.matches(&Verifier::from_digest(other)),
            "one differing byte"
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        let text = format!("{:?}", Verifier::from_digest([0xab; 32]));
        assert_eq!(text, "Verifier(<redacted>)");
    }
}
