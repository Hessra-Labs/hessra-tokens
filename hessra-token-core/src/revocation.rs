//! Revocation identifier utilities for Biscuit tokens
//!
//! This module provides utilities for extracting and managing revocation identifiers
//! from Biscuit tokens. Each block in a token has a unique revocation ID that can be
//! used to revoke specific tokens or delegation levels.

use crate::Biscuit;
use std::fmt;

/// A revocation identifier for a Biscuit token block
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationId {
    inner: Vec<u8>,
}

impl RevocationId {
    /// Create a new RevocationId from raw bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// Get the raw bytes of the revocation ID
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Convert the revocation ID to a hex string for display/storage
    pub fn to_hex(&self) -> String {
        hex::encode(&self.inner)
    }

    /// Create a RevocationId from a hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        hex::decode(hex_str).map(Self::new)
    }
}

impl fmt::Display for RevocationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<Vec<u8>> for RevocationId {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

/// Extract all revocation IDs from a Biscuit token
///
/// Returns a vector of revocation IDs, one for each block in the token.
/// The first ID is for the authority block, followed by any attestation blocks.
pub fn get_revocation_ids(biscuit: &Biscuit) -> Vec<RevocationId> {
    biscuit
        .revocation_identifiers()
        .into_iter()
        .map(RevocationId::from)
        .collect()
}

/// Get the revocation ID for the authority (first) block
///
/// This is useful for authorization tokens which are short-lived and typically
/// only need the authority block's revocation ID.
pub fn get_authority_revocation_id(biscuit: &Biscuit) -> Option<RevocationId> {
    biscuit
        .revocation_identifiers()
        .into_iter()
        .next()
        .map(RevocationId::from)
}

/// Get the revocation ID for a specific block by index
///
/// - Index 0 is the authority block
/// - Index 1+ are attestation/delegation blocks
pub fn get_block_revocation_id(biscuit: &Biscuit, index: usize) -> Option<RevocationId> {
    biscuit
        .revocation_identifiers()
        .into_iter()
        .nth(index)
        .map(RevocationId::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use biscuit_auth::macros::biscuit;

    #[test]
    fn test_revocation_id_hex_conversion() {
        let bytes = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let rev_id = RevocationId::new(bytes.clone());

        // Test to_hex
        assert_eq!(rev_id.to_hex(), "0123456789abcdef");
        assert_eq!(rev_id.to_string(), "0123456789abcdef");

        // Test from_hex
        let from_hex = RevocationId::from_hex("0123456789abcdef").unwrap();
        assert_eq!(from_hex.as_bytes(), &bytes[..]);
        assert_eq!(rev_id, from_hex);
    }

    #[test]
    fn test_get_revocation_ids() {
        let keypair = KeyPair::new();

        // Create a simple biscuit
        let biscuit = biscuit!(
            r#"
                right("alice", "resource1", "read");
            "#
        )
        .build(&keypair)
        .unwrap();

        let rev_ids = get_revocation_ids(&biscuit);

        // Should have at least one revocation ID (for the authority block)
        assert!(!rev_ids.is_empty());
        assert_eq!(rev_ids.len(), 1);

        // The revocation ID should be non-empty
        assert!(!rev_ids[0].as_bytes().is_empty());
    }

    #[test]
    fn test_get_authority_revocation_id() {
        let keypair = KeyPair::new();

        let biscuit = biscuit!(
            r#"
                right("alice", "resource1", "read");
            "#
        )
        .build(&keypair)
        .unwrap();

        let auth_id = get_authority_revocation_id(&biscuit);
        assert!(auth_id.is_some());

        // Should match the first ID from get_revocation_ids
        let all_ids = get_revocation_ids(&biscuit);
        assert_eq!(auth_id.unwrap(), all_ids[0]);
    }

    #[test]
    fn test_unique_revocation_ids() {
        let keypair = KeyPair::new();

        // Create two identical biscuits
        let biscuit1 = biscuit!(
            r#"
                right("alice", "resource1", "read");
            "#
        )
        .build(&keypair)
        .unwrap();

        let biscuit2 = biscuit!(
            r#"
                right("alice", "resource1", "read");
            "#
        )
        .build(&keypair)
        .unwrap();

        let rev_id1 = get_authority_revocation_id(&biscuit1).unwrap();
        let rev_id2 = get_authority_revocation_id(&biscuit2).unwrap();

        // Even with identical content, revocation IDs should be different
        // (due to different signatures)
        assert_ne!(rev_id1, rev_id2);
    }
}
