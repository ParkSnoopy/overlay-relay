//! Account verifiers: the SHA-256 digest of a client's raw token bytes.
//! The hub stores and compares verifiers, never tokens.

use std::fmt;

use sha2::{Digest, Sha256};

/// The SHA-256 digest of a token's 32 raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Verifier([u8; 32]);

impl Verifier {
    /// Wraps an existing 32-byte digest.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Derives the verifier of a token given as 64 hex digits. Returns `None`
    /// when the token is not exactly 32 bytes of hex.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        let raw: [u8; 32] = hex::decode(token).ok()?.try_into().ok()?;
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
            .fold(0_u8, |accumulated, (left, right)| accumulated | (left ^ right));
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
    fn token_derives_digest_of_raw_bytes() {
        let token = token_hex('1');
        let verifier = Verifier::from_token(&token);
        assert!(verifier.is_some(), "a 64-digit hex token must be valid");
        let hex = verifier.map_or_else(String::new, Verifier::to_hex);
        assert_eq!(hex.len(), 64);
        assert_eq!(Verifier::from_hex(&hex), verifier, "hex must round-trip");
    }

    #[test]
    fn malformed_tokens_have_no_verifier() {
        assert!(Verifier::from_token("").is_none(), "empty token");
        assert!(Verifier::from_token("not-hex").is_none(), "non-hex token");
        assert!(Verifier::from_token(&token_hex('1')[..62]).is_none(), "short token");
        assert!(Verifier::from_token(&format!("{}00", token_hex('1'))).is_none(), "long token");
        assert!(Verifier::from_hex(&token_hex('z')).is_none(), "non-hex verifier");
    }

    #[test]
    fn matching_is_exact() {
        let first = Verifier::from_digest([7; 32]);
        let mut other = [7_u8; 32];
        assert!(first.matches(&Verifier::from_digest(other)));
        other[31] = 8;
        assert!(!first.matches(&Verifier::from_digest(other)), "one differing byte");
    }

    #[test]
    fn debug_output_is_redacted() {
        let text = format!("{:?}", Verifier::from_digest([0xab; 32]));
        assert_eq!(text, "Verifier(<redacted>)");
    }
}
