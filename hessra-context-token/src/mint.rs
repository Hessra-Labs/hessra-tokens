extern crate biscuit_auth as biscuit;

use biscuit::macros::biscuit;
use chrono::Utc;
use hessra_token_core::{KeyPair, TokenTimeConfig};
use std::error::Error;

/// Builder for creating Hessra context tokens.
///
/// Context tokens identify a session and track data exposure (taint labels)
/// as append-only Biscuit blocks.
///
/// # Example
/// ```rust
/// use hessra_context_token::HessraContext;
/// use hessra_token_core::{KeyPair, TokenTimeConfig};
///
/// let keypair = KeyPair::new();
/// let token = HessraContext::new(
///     "agent:openclaw".to_string(),
///     TokenTimeConfig::default(),
/// )
/// .issue(&keypair)
/// .expect("Failed to create context token");
/// ```
pub struct HessraContext {
    subject: String,
    time_config: TokenTimeConfig,
}

impl HessraContext {
    /// Creates a new context token builder.
    ///
    /// # Arguments
    /// * `subject` - The session owner identifier (e.g., "agent:openclaw")
    /// * `time_config` - Time configuration for token validity
    pub fn new(subject: String, time_config: TokenTimeConfig) -> Self {
        Self {
            subject,
            time_config,
        }
    }

    /// Issues (builds and signs) the context token.
    ///
    /// The authority block contains:
    /// - `context({subject})` - identifies the session owner
    /// - time expiration check
    ///
    /// # Arguments
    /// * `keypair` - The keypair to sign the token with
    ///
    /// # Returns
    /// Base64-encoded Biscuit token
    pub fn issue(self, keypair: &KeyPair) -> Result<String, Box<dyn Error>> {
        let start_time = self
            .time_config
            .start_time
            .unwrap_or_else(|| Utc::now().timestamp());
        let expiration = start_time + self.time_config.duration;
        let subject = self.subject;

        let builder = biscuit!(
            r#"
                context({subject});
                check if time($time), $time < {expiration};
            "#
        );

        let biscuit = builder.build(keypair)?;
        let token = biscuit.to_base64()?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::ContextVerifier;

    #[test]
    fn test_create_context_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        assert!(!token.is_empty());

        // Should verify successfully
        ContextVerifier::new(token, public_key)
            .verify()
            .expect("Should verify fresh context token");
    }

    #[test]
    fn test_expired_context_token() {
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
        assert!(
            result.is_err(),
            "Expired context token should fail verification"
        );
    }

    #[test]
    fn test_custom_time_config() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let config = TokenTimeConfig {
            start_time: None,
            duration: 7200, // 2 hours
        };

        let token = HessraContext::new("agent:test".to_string(), config)
            .issue(&keypair)
            .expect("Failed to create context token with custom config");

        ContextVerifier::new(token, public_key)
            .verify()
            .expect("Should verify context token with custom duration");
    }
}
