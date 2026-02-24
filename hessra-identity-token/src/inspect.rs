extern crate biscuit_auth as biscuit;
use biscuit::macros::authorizer;
use chrono::Utc;
use hessra_token_core::{Biscuit, PublicKey, TokenError};

/// Result of inspecting an identity token
#[derive(Debug, Clone)]
pub struct InspectResult {
    /// The identity (subject or delegated actor) in the token
    pub identity: String,
    /// Unix timestamp when the token expires (if extractable)
    pub expiry: Option<i64>,
    /// Whether the token is currently expired
    pub is_expired: bool,
    /// Whether this is a delegated token (has attenuation blocks)
    pub is_delegated: bool,
    /// Namespace restriction (if present)
    pub namespace: Option<String>,
}

/// Inspects an identity token to extract the subject/actor information without requiring verification.
pub fn inspect_identity_token(
    token: String,
    public_key: PublicKey,
) -> Result<InspectResult, TokenError> {
    let biscuit = Biscuit::from_base64(&token, public_key)?;
    let now = Utc::now().timestamp();

    let authorizer = authorizer!(
        r#"
            time({now});
            actor($a) <- subject($a);
            allow if true;
        "#
    );

    let mut authorizer = authorizer
        .build(&biscuit)
        .map_err(|e| TokenError::internal(format!("Failed to build authorizer: {e}")))?;

    let subjects: Vec<(String,)> = authorizer
        .query("data($name) <- subject($name)")
        .map_err(|e| TokenError::internal(format!("Failed to query subject: {e}")))?;

    let base_identity = subjects
        .first()
        .map(|(s,)| s.clone())
        .ok_or_else(|| TokenError::internal("No subject found in token".to_string()))?;

    // Check if token has attenuation blocks (is delegated)
    let block_count = biscuit.block_count();
    let is_delegated = block_count > 1;

    // For delegated tokens, try to extract the most specific identity from checks
    let identity = if is_delegated {
        extract_delegated_identity(&biscuit).unwrap_or(base_identity.clone())
    } else {
        base_identity
    };

    let token_content = biscuit.print();
    let expiry = extract_expiry_from_content(&token_content);
    let namespace = extract_namespace_from_content(&token_content);

    let is_expired = expiry.is_some_and(|exp| exp < now);

    Ok(InspectResult {
        identity,
        expiry,
        is_expired,
        is_delegated,
        namespace,
    })
}

/// Extracts the most specific delegated identity from a token's blocks
fn extract_delegated_identity(biscuit: &Biscuit) -> Option<String> {
    let content = biscuit.print();

    if let Some(blocks_start) = content.find("blocks: [") {
        let blocks_section = &content[blocks_start..];

        if let Some(blocks_end) = blocks_section.find("\n}") {
            let blocks_content = &blocks_section[..blocks_end];

            let blocks: Vec<&str> = blocks_content.split("Block {").skip(1).collect();

            // Iterate backwards through blocks to find the last identity delegation
            for block in blocks.iter().rev() {
                if let Some(symbols_line_start) = block.find("symbols: [") {
                    let after_symbols = &block[symbols_line_start + 10..];
                    if let Some(symbols_end) = after_symbols.find(']') {
                        let symbols_str = &after_symbols[..symbols_end];

                        for symbol in symbols_str.split(',') {
                            let symbol = symbol.trim().trim_matches('"');
                            if symbol.contains(':')
                                && (symbol.starts_with("urn:")
                                    || symbol.starts_with("https:")
                                    || symbol.starts_with("mailto:")
                                    || symbol.contains("hessra"))
                            {
                                return Some(symbol.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Extracts expiry timestamp from token content
fn extract_expiry_from_content(content: &str) -> Option<i64> {
    let mut earliest_expiry: Option<i64> = None;

    for line in content.lines() {
        if line.contains("check if") && line.contains("time") && line.contains("<") {
            if let Some(pos) = line.find("$time <") {
                let after_lt = &line[pos + 8..].trim();
                let number_str = after_lt
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '-')
                    .collect::<String>();

                if let Ok(timestamp) = number_str.parse::<i64>() {
                    earliest_expiry = Some(earliest_expiry.map_or(timestamp, |e| e.min(timestamp)));
                }
            }
        }
    }

    earliest_expiry
}

/// Extracts namespace restriction from token content
fn extract_namespace_from_content(content: &str) -> Option<String> {
    for line in content.lines() {
        if line.contains("check if") && line.contains("namespace(") {
            if let Some(start_pos) = line.find("namespace(") {
                let after_namespace = &line[start_pos + 10..];

                if let Some(end_pos) = after_namespace.find(')') {
                    let namespace_str = &after_namespace[..end_pos].trim();
                    let namespace = namespace_str.trim_matches('"').trim_matches('\'');

                    if !namespace.is_empty() {
                        return Some(namespace.to_string());
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HessraIdentity, add_identity_attenuation_to_token};
    use hessra_token_core::{KeyPair, TokenTimeConfig};

    #[test]
    fn test_inspect_basic_identity_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let subject = "urn:hessra:alice".to_string();

        let token = HessraIdentity::new(subject.clone(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create token");

        let result = inspect_identity_token(token, public_key).expect("Failed to inspect token");

        assert_eq!(result.identity, subject);
        assert!(!result.is_expired);
        assert!(!result.is_delegated);
        assert!(result.expiry.is_some());
    }

    #[test]
    fn test_inspect_delegated_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let base_identity = "urn:hessra:alice".to_string();
        let delegated_identity = "urn:hessra:alice:laptop".to_string();

        let token = HessraIdentity::new(base_identity.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create token");

        let delegated_token = add_identity_attenuation_to_token(
            token,
            delegated_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to delegate token");

        let result = inspect_identity_token(delegated_token, public_key)
            .expect("Failed to inspect delegated token");

        assert_eq!(result.identity, delegated_identity);
        assert!(result.is_delegated);
        assert!(!result.is_expired);
    }

    #[test]
    fn test_inspect_expired_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let subject = "urn:hessra:alice".to_string();

        let expired_config = TokenTimeConfig {
            start_time: Some(0),
            duration: 1,
        };

        let token = HessraIdentity::new(subject.clone(), expired_config)
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create token");

        let result =
            inspect_identity_token(token, public_key).expect("Failed to inspect expired token");

        assert_eq!(result.identity, subject);
        assert!(result.is_expired);
        assert_eq!(result.expiry, Some(1));
    }

    #[test]
    fn test_inspect_multi_level_delegation() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let org_identity = "urn:hessra:company".to_string();
        let dept_identity = "urn:hessra:company:dept_eng".to_string();
        let user_identity = "urn:hessra:company:dept_eng:alice".to_string();

        let token = HessraIdentity::new(org_identity.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create token");

        let token = add_identity_attenuation_to_token(
            token,
            dept_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate to department");

        let token = add_identity_attenuation_to_token(
            token,
            user_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate to user");

        let result = inspect_identity_token(token, public_key)
            .expect("Failed to inspect multi-delegated token");

        assert_eq!(result.identity, user_identity);
        assert!(result.is_delegated);
    }

    #[test]
    fn test_backwards_search_finds_last_identity() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let base = "urn:hessra:base".to_string();
        let middle = "urn:hessra:base:middle".to_string();
        let final_id = "urn:hessra:base:middle:final".to_string();

        let token = HessraIdentity::new(base.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create token");

        let token = add_identity_attenuation_to_token(
            token,
            middle.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed first delegation");

        let token = add_identity_attenuation_to_token(
            token,
            final_id.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed final delegation");

        let result = inspect_identity_token(token, public_key).expect("Failed to inspect");

        assert_eq!(
            result.identity, final_id,
            "Should get the last delegated identity"
        );
        assert!(result.is_delegated);
    }

    #[test]
    fn test_inspect_namespace_restricted_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let subject = "urn:hessra:alice".to_string();
        let namespace = "example.com".to_string();

        let token = HessraIdentity::new(subject.clone(), TokenTimeConfig::default())
            .namespace_restricted(namespace.clone())
            .issue(&keypair)
            .expect("Failed to create namespace-restricted token");

        let result = inspect_identity_token(token, public_key)
            .expect("Failed to inspect namespace-restricted token");

        assert_eq!(result.identity, subject);
        assert_eq!(result.namespace, Some(namespace.clone()));
        assert!(!result.is_delegated);
    }

    #[test]
    fn test_inspect_non_namespace_restricted_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let subject = "urn:hessra:alice".to_string();

        let token = HessraIdentity::new(subject.clone(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create token");

        let result = inspect_identity_token(token, public_key).expect("Failed to inspect token");

        assert_eq!(result.identity, subject);
        assert_eq!(result.namespace, None);
    }

    #[test]
    fn test_inspect_delegatable_namespace_restricted_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let base_identity = "urn:hessra:org".to_string();
        let namespace = "myapp.hessra.dev".to_string();

        let token = HessraIdentity::new(base_identity.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .namespace_restricted(namespace.clone())
            .issue(&keypair)
            .expect("Failed to create token");

        let result = inspect_identity_token(token, public_key)
            .expect("Failed to inspect delegatable namespace-restricted token");

        assert_eq!(result.identity, base_identity);
        assert_eq!(result.namespace, Some(namespace));
        assert!(!result.is_delegated);
    }
}
