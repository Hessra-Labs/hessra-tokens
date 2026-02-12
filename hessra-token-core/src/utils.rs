use base64::{Engine, engine::general_purpose::URL_SAFE};
use std::fs::read_to_string;

use crate::error::TokenError;

pub use biscuit_auth::{Biscuit, PublicKey};

/// Encode binary token data to URL-safe base64 string
///
/// # Arguments
///
/// * `token_bytes` - Binary token data
///
/// # Returns
///
/// URL-safe base64 encoded token string
pub fn encode_token(token_bytes: &[u8]) -> String {
    URL_SAFE.encode(token_bytes)
}

/// Decode a URL-safe base64 encoded token string to binary
///
/// # Arguments
///
/// * `token_string` - URL-safe base64 encoded token string
///
/// # Returns
///
/// Binary token data or TokenError if decoding fails
pub fn decode_token(token_string: &str) -> Result<Vec<u8>, TokenError> {
    URL_SAFE
        .decode(token_string)
        .map_err(|e| TokenError::generic(format!("Failed to decode base64 token: {e}")))
}

pub fn public_key_from_pem_file(path: &str) -> Result<PublicKey, TokenError> {
    let key_string = read_to_string(path)
        .map_err(|e| TokenError::generic(format!("Failed to read file: {e}")))?;
    let key = PublicKey::from_pem(&key_string)
        .map_err(|e| TokenError::generic(format!("Failed to parse PEM: {e}")))?;
    Ok(key)
}

/// Extracts and parses a Biscuit token from a URL-safe base64 string
///
/// This is useful when you need to inspect the token contents directly
///
/// # Arguments
///
/// * `token_string` - URL-safe base64 encoded token string
/// * `public_key` - The public key used to verify the token signature
///
/// # Returns
///
/// The parsed Biscuit token or an error
pub fn parse_token(token_string: &str, public_key: PublicKey) -> Result<Biscuit, TokenError> {
    Ok(Biscuit::from_base64(token_string, public_key)?)
}
