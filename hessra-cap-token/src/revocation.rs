//! Revocation utilities for capability tokens
//!
//! Since capability tokens are meant to be short-lived (< 5 minutes),
//! we typically only need the authority block's revocation ID.

use hessra_token_core::{
    Biscuit, PublicKey, RevocationId, TokenError, get_authority_revocation_id, get_revocation_ids,
};

/// Get the revocation ID of a capability's **most recent** block.
///
/// For a plain capability this is the authority block; for an amended capability
/// (attenuated/attested) it is the latest amendment block, which is unique per
/// amendment. The ToolSystem uses this to key its single-use facet ledger by the
/// activation amendment.
pub fn latest_revocation_id(
    token: &str,
    public_key: PublicKey,
) -> Result<RevocationId, TokenError> {
    let biscuit = Biscuit::from_base64(token, public_key)?;
    get_revocation_ids(&biscuit)
        .last()
        .cloned()
        .ok_or_else(|| TokenError::generic("capability has no blocks"))
}

/// Get the revocation ID for a capability token
///
/// # Arguments
/// * `token` - Base64-encoded Biscuit token
/// * `public_key` - Public key to parse the token
///
/// # Returns
/// * `Ok(RevocationId)` - The revocation ID of the authority block
/// * `Err(TokenError)` - If the token cannot be parsed
pub fn get_capability_revocation_id(
    token: String,
    public_key: PublicKey,
) -> Result<RevocationId, TokenError> {
    let biscuit = Biscuit::from_base64(&token, public_key)?;

    get_authority_revocation_id(&biscuit).ok_or_else(|| {
        TokenError::generic("Failed to extract revocation ID from capability token".to_string())
    })
}

/// Get the revocation ID from raw token bytes
///
/// # Arguments
/// * `token_bytes` - Raw Biscuit token bytes
/// * `public_key` - Public key to parse the token
///
/// # Returns
/// * `Ok(RevocationId)` - The revocation ID of the authority block
/// * `Err(TokenError)` - If the token cannot be parsed
pub fn get_capability_revocation_id_from_bytes(
    token_bytes: Vec<u8>,
    public_key: PublicKey,
) -> Result<RevocationId, TokenError> {
    let biscuit = Biscuit::from(&token_bytes, public_key)?;

    get_authority_revocation_id(&biscuit).ok_or_else(|| {
        TokenError::generic("Failed to extract revocation ID from capability token".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::HessraCapability;
    use hessra_token_core::{KeyPair, decode_token};

    fn cap(keypair: &KeyPair, operation: &str) -> String {
        HessraCapability::new()
            .subject("user123")
            .resource("resource456")
            .operation(operation)
            .issue(keypair)
            .expect("issue capability")
    }

    #[test]
    fn test_get_capability_revocation_id() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token_b64 = cap(&keypair, "read");
        let token_bytes = decode_token(&token_b64).expect("Failed to decode token");

        // Get revocation ID from string
        let rev_id = get_capability_revocation_id(token_b64.clone(), public_key)
            .expect("Failed to get revocation ID");

        assert!(!rev_id.to_hex().is_empty());

        // Get revocation ID from bytes (should match)
        let rev_id_from_bytes = get_capability_revocation_id_from_bytes(token_bytes, public_key)
            .expect("Failed to get revocation ID from bytes");

        assert_eq!(rev_id.to_hex(), rev_id_from_bytes.to_hex());

        // For a plain capability, the latest block is the authority block.
        let latest = latest_revocation_id(&token_b64, public_key).expect("latest");
        assert_eq!(latest.to_hex(), rev_id.to_hex());
    }

    #[test]
    fn test_unique_revocation_ids_for_capability_tokens() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let token1 = cap(&keypair, "read");

        let keypair2 = KeyPair::new();
        let public_key2 = keypair2.public();
        let token2 = cap(&keypair2, "read");

        let rev_id1 = get_capability_revocation_id(token1, public_key)
            .expect("Failed to get first revocation ID");
        let rev_id2 = get_capability_revocation_id(token2, public_key2)
            .expect("Failed to get second revocation ID");

        assert_ne!(rev_id1.to_hex(), rev_id2.to_hex());
    }

    #[test]
    fn latest_revocation_id_tracks_amendments() {
        // Each amendment appends a block, so the latest revocation id changes and
        // differs from the authority block's -- the property the facet ledger keys on.
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let token = cap(&keypair, "read");

        let authority_id = get_capability_revocation_id(token.clone(), public_key).unwrap();
        let amended = HessraCapability::amend(&token, public_key)
            .unwrap()
            .designation("tenant", "t-1")
            .attenuate()
            .unwrap();
        let amended_id = latest_revocation_id(&amended, public_key).unwrap();

        assert_ne!(authority_id.to_hex(), amended_id.to_hex());
    }
}
