//! Revocation utilities for capability tokens
//!
//! Since capability tokens are meant to be short-lived (< 5 minutes),
//! we typically only need the authority block's revocation ID.

use hessra_token_core::{
    Biscuit, PublicKey, RevocationId, TokenError, get_authority_revocation_id,
};

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
    use crate::mint::create_biscuit;
    use hessra_token_core::{KeyPair, TokenTimeConfig, encode_token};

    #[test]
    fn test_get_capability_revocation_id() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token_bytes = create_biscuit(
            "user123".to_string(),
            "resource456".to_string(),
            "read".to_string(),
            keypair,
            TokenTimeConfig::default(),
        )
        .expect("Failed to create capability token");

        let token_string = encode_token(&token_bytes);

        // Get revocation ID from string
        let rev_id = get_capability_revocation_id(token_string.clone(), public_key)
            .expect("Failed to get revocation ID");

        assert!(!rev_id.to_hex().is_empty());

        // Get revocation ID from bytes (should match)
        let rev_id_from_bytes = get_capability_revocation_id_from_bytes(token_bytes, public_key)
            .expect("Failed to get revocation ID from bytes");

        assert_eq!(rev_id.to_hex(), rev_id_from_bytes.to_hex());
    }

    #[test]
    fn test_unique_revocation_ids_for_capability_tokens() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token1 = create_biscuit(
            "user123".to_string(),
            "resource456".to_string(),
            "read".to_string(),
            keypair,
            TokenTimeConfig::default(),
        )
        .expect("Failed to create first token");

        let keypair2 = KeyPair::new();
        let public_key2 = keypair2.public();
        let token2 = create_biscuit(
            "user123".to_string(),
            "resource456".to_string(),
            "read".to_string(),
            keypair2,
            TokenTimeConfig::default(),
        )
        .expect("Failed to create second token");

        let token1_string = encode_token(&token1);
        let token2_string = encode_token(&token2);

        let rev_id1 = get_capability_revocation_id(token1_string, public_key)
            .expect("Failed to get first revocation ID");

        let rev_id2 = get_capability_revocation_id(token2_string, public_key2)
            .expect("Failed to get second revocation ID");

        assert_ne!(rev_id1.to_hex(), rev_id2.to_hex());
    }

    #[test]
    fn test_revocation_id_with_short_lived_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let short_config = TokenTimeConfig {
            start_time: None,
            duration: 30,
        };

        let token = create_biscuit(
            "user123".to_string(),
            "resource456".to_string(),
            "write".to_string(),
            keypair,
            short_config,
        )
        .expect("Failed to create short-lived token");

        let token_string = encode_token(&token);

        let rev_id = get_capability_revocation_id(token_string, public_key)
            .expect("Failed to get revocation ID for short-lived token");

        assert!(!rev_id.to_hex().is_empty());
    }
}
