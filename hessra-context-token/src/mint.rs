extern crate biscuit_auth as biscuit;

use biscuit::builder::BiscuitBuilder;
use biscuit::macros::{biscuit, fact};
use chrono::Utc;
use hessra_token_core::{KeyPair, TokenTimeConfig};
use std::error::Error;

/// Builder for creating Hessra context tokens.
///
/// Context tokens identify a session and track data exposure as biscuit blocks.
/// Initial exposure labels (known at mint time) are stacked into the authority
/// block as sibling facts; subsequent exposures are added via `add_exposure`
/// in third-party blocks signed by the same issuer.
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
    initial_exposures: Vec<String>,
    initial_source: Option<String>,
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
            initial_exposures: Vec::new(),
            initial_source: None,
        }
    }

    /// Stack initial exposure labels into the authority block.
    ///
    /// All labels in `labels` land in the same authority block alongside the
    /// `context(subject)` fact, paired with one `exposure_source` and one
    /// `exposure_time`. Multiple calls accumulate labels; the most recent
    /// source replaces any earlier one (initial exposures share a single
    /// source by design).
    pub fn with_initial_exposures(mut self, labels: &[String], source: impl Into<String>) -> Self {
        for label in labels {
            if !self.initial_exposures.contains(label) {
                self.initial_exposures.push(label.clone());
            }
        }
        self.initial_source = Some(source.into());
        self
    }

    /// Issues (builds and signs) the context token.
    ///
    /// The authority block contains:
    /// - `context({subject})` - identifies the session owner
    /// - `exposure({label})` facts for each initial exposure (if any)
    /// - `exposure_source({source})` and `exposure_time({now})` (if any exposures)
    /// - time expiration check
    pub fn issue(self, keypair: &KeyPair) -> Result<String, Box<dyn Error>> {
        let start_time = self
            .time_config
            .start_time
            .unwrap_or_else(|| Utc::now().timestamp());
        let expiration = start_time + self.time_config.duration;
        let subject = self.subject;

        let mut builder: BiscuitBuilder = biscuit!(
            r#"
                context({subject});
                check if time($time), $time < {expiration};
            "#
        );

        if !self.initial_exposures.is_empty() {
            let now = Utc::now().timestamp();
            for label in &self.initial_exposures {
                let label = label.clone();
                builder = builder.fact(fact!(r#"exposure({label});"#))?;
            }
            if let Some(source) = self.initial_source {
                builder = builder.fact(fact!(r#"exposure_source({source});"#))?;
            }
            builder = builder.fact(fact!(r#"exposure_time({now});"#))?;
        }

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
            duration: 7200,
        };

        let token = HessraContext::new("agent:test".to_string(), config)
            .issue(&keypair)
            .expect("Failed to create context token with custom config");

        ContextVerifier::new(token, public_key)
            .verify()
            .expect("Should verify context token with custom duration");
    }

    #[test]
    fn test_initial_exposures_stacked_in_authority_block() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
            .with_initial_exposures(
                &["PII:email".to_string(), "PII:address".to_string()],
                "data:user-profile",
            )
            .issue(&keypair)
            .expect("Failed to create context token with initial exposures");

        // Both labels should be queryable, and the token should still have
        // only one block (the authority block).
        let biscuit =
            biscuit::Biscuit::from_base64(&token, public_key).expect("Failed to parse token");
        assert_eq!(
            biscuit.block_count(),
            1,
            "Initial exposures must be stacked into the authority block, not split into separate blocks"
        );

        let labels = crate::exposure::extract_exposure_labels(&token, public_key)
            .expect("Failed to extract initial exposure labels");
        assert_eq!(labels.len(), 2);
        assert!(labels.contains(&"PII:email".to_string()));
        assert!(labels.contains(&"PII:address".to_string()));
    }
}
