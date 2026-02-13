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
        assert!(
            result.is_err(),
            "Token verified with wrong key should fail"
        );
    }

    #[test]
    fn test_verify_tainted_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        // Add taint -- token should still verify
        let tainted = crate::taint::add_taint(
            &token,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add taint");

        ContextVerifier::new(tainted, public_key)
            .verify()
            .expect("Tainted token should still verify");
    }
}
