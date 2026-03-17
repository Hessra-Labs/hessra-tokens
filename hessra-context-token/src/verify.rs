extern crate biscuit_auth as biscuit;

use biscuit::Biscuit;
use biscuit::macros::authorizer;
use chrono::Utc;
use hessra_token_core::{PublicKey, TokenError};

/// Verifier for context tokens.
///
/// Checks that the context token is valid (not expired, properly signed).
///
/// # Example
/// ```rust
/// use hessra_context_token::{HessraContext, ContextVerifier};
/// use hessra_token_core::{KeyPair, TokenTimeConfig};
///
/// let keypair = KeyPair::new();
/// let public_key = keypair.public();
///
/// let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
///     .issue(&keypair)
///     .expect("Failed to create context token");
///
/// ContextVerifier::new(token, public_key)
///     .verify()
///     .expect("Should verify");
/// ```
pub struct ContextVerifier {
    token: String,
    public_key: PublicKey,
}

impl ContextVerifier {
    /// Creates a new context verifier.
    ///
    /// # Arguments
    /// * `token` - The base64-encoded context token to verify
    /// * `public_key` - The public key used to verify the token signature
    pub fn new(token: String, public_key: PublicKey) -> Self {
        Self { token, public_key }
    }

    /// Verify the context token.
    ///
    /// Checks that:
    /// - The token signature is valid
    /// - The token has not expired
    ///
    /// # Returns
    /// * `Ok(())` - If the token is valid
    /// * `Err(TokenError)` - If verification fails
    pub fn verify(self) -> Result<(), TokenError> {
        let biscuit = Biscuit::from_base64(&self.token, self.public_key)?;
        let now = Utc::now().timestamp();

        let authz = authorizer!(
            r#"
                time({now});
                allow if true;
            "#
        );

        authz
            .build(&biscuit)
            .map_err(|e| TokenError::internal(format!("failed to build authorizer: {e}")))?
            .authorize()
            .map_err(TokenError::from)?;

        Ok(())
    }

    /// Check that the context token does not contain any precluded exposure labels.
    ///
    /// Verifies the token (signature + expiration) and then checks that none of the
    /// token's `exposure(...)` facts match the precluded labels. Any match causes
    /// the method to return an error.
    ///
    /// This is the authorization-grade check. For diagnostics, use
    /// `extract_exposure_labels` or `inspect_context_token` instead.
    ///
    /// # Implementation Note
    ///
    /// Exposure facts live in first-party appended blocks. In biscuit-auth v6,
    /// authorizer deny-policies cannot see these facts due to block scoping
    /// (`Scope::Previous` is a no-op for the authorizer). Instead, we verify
    /// the token cryptographically first, then inspect the verified block data
    /// for precluded labels. The authorization decision is fully encapsulated --
    /// callers never handle raw labels.
    ///
    /// # Arguments
    /// * `precluded` - Labels that must NOT be present in the token's exposure facts.
    ///   Any match blocks the grant (OR semantics).
    ///
    /// # Returns
    /// * `Ok(())` - If no precluded labels are found (or precluded list is empty)
    /// * `Err(TokenError)` - If the token contains any precluded exposure label,
    ///   or if the token is invalid/expired
    pub fn check_precluded_exposures(self, precluded: &[String]) -> Result<(), TokenError> {
        let biscuit = Biscuit::from_base64(&self.token, self.public_key)?;
        let now = Utc::now().timestamp();

        // Verify signature and expiration
        let authz = authorizer!(
            r#"
                time({now});
                allow if true;
            "#
        );

        authz
            .build(&biscuit)
            .map_err(|e| TokenError::internal(format!("failed to build authorizer: {e}")))?
            .authorize()
            .map_err(TokenError::from)?;

        if precluded.is_empty() {
            return Ok(());
        }

        // Check verified block data for precluded exposure labels
        let block_count = biscuit.block_count();
        for i in 0..block_count {
            let block_source = biscuit.print_block_source(i).unwrap_or_default();
            for line in block_source.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("exposure(")
                    && let Some(label_str) = rest.strip_suffix(");")
                {
                    let label = label_str.trim_matches('"');
                    if precluded.iter().any(|p| p == label) {
                        return Err(TokenError::internal(format!(
                            "precluded exposure label present: {label}"
                        )));
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::HessraContext;
    use hessra_token_core::{KeyPair, TokenTimeConfig};

    #[test]
    fn test_verify_valid_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        ContextVerifier::new(token, public_key)
            .verify()
            .expect("Should verify valid token");
    }

    #[test]
    fn test_verify_expired_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let expired_config = TokenTimeConfig {
            start_time: Some(0),
            duration: 1,
        };

        let token = HessraContext::new("agent:test".to_string(), expired_config)
            .issue(&keypair)
            .expect("Failed to create expired context token");

        let result = ContextVerifier::new(token, public_key).verify();
        assert!(result.is_err(), "Expired token should fail verification");
    }

    #[test]
    fn test_verify_wrong_key() {
        let keypair = KeyPair::new();
        let wrong_keypair = KeyPair::new();
        let wrong_public_key = wrong_keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let result = ContextVerifier::new(token, wrong_public_key).verify();
        assert!(result.is_err(), "Token verified with wrong key should fail");
    }

    #[test]
    fn test_verify_exposed_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        // Add exposure -- token should still verify
        let exposed = crate::exposure::add_exposure(
            &token,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add exposure");

        ContextVerifier::new(exposed, public_key)
            .verify()
            .expect("Exposed token should still verify");
    }

    #[test]
    fn test_check_precluded_exposures_blocks_matching() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = crate::exposure::add_exposure(
            &token,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add exposure");

        let result = ContextVerifier::new(exposed, public_key)
            .check_precluded_exposures(&["PII:SSN".to_string()]);

        assert!(
            result.is_err(),
            "Should deny when precluded label is present"
        );
    }

    #[test]
    fn test_check_precluded_exposures_allows_non_matching() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = crate::exposure::add_exposure(
            &token,
            public_key,
            &["PII:email".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add exposure");

        ContextVerifier::new(exposed, public_key)
            .check_precluded_exposures(&["PII:SSN".to_string()])
            .expect("Should allow when precluded label is not present");
    }

    #[test]
    fn test_check_precluded_exposures_empty_list() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = crate::exposure::add_exposure(
            &token,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add exposure");

        ContextVerifier::new(exposed, public_key)
            .check_precluded_exposures(&[])
            .expect("Empty precluded list should pass");
    }

    #[test]
    fn test_check_precluded_exposures_expired_token_fails() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let expired_config = TokenTimeConfig {
            start_time: Some(0),
            duration: 1,
        };

        let token = HessraContext::new("agent:test".to_string(), expired_config)
            .issue(&keypair)
            .expect("Failed to create expired context token");

        let result = ContextVerifier::new(token, public_key)
            .check_precluded_exposures(&["PII:SSN".to_string()]);

        assert!(
            result.is_err(),
            "Expired token should fail even with non-matching precluded labels"
        );
    }

    #[test]
    fn test_check_precluded_exposures_clean_token_passes() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        ContextVerifier::new(token, public_key)
            .check_precluded_exposures(&["PII:SSN".to_string()])
            .expect("Clean token should pass any precluded check");
    }
}
