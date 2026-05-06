extern crate biscuit_auth as biscuit;

use biscuit::macros::biscuit;
use chrono::Utc;
use hessra_token_core::{KeyPair, TokenTimeConfig};
use std::error::Error;

/// Builder for creating Hessra identity tokens with flexible configuration.
///
/// # Terminology
/// - **Realm identity**: A configured principal inside a Realm (default, non-delegatable)
/// - **Delegatable identity**: An identity token that can be attenuated and delegated further
///
/// # Example
/// ```rust
/// use hessra_identity_token::HessraIdentity;
/// use hessra_token_core::{KeyPair, TokenTimeConfig};
///
/// let keypair = KeyPair::new();
/// let subject = "urn:hessra:alice".to_string();
///
/// // Basic realm identity (non-delegatable)
/// let token = HessraIdentity::new(subject.clone(), TokenTimeConfig::default())
///     .issue(&keypair)
///     .expect("Failed to create token");
///
/// // Delegatable identity
/// let token = HessraIdentity::new(subject, TokenTimeConfig::default())
///     .delegatable(true)
///     .issue(&keypair)
///     .expect("Failed to create token");
/// ```
pub struct HessraIdentity {
    subject: String,
    time_config: TokenTimeConfig,
    is_delegatable: bool,
}

impl HessraIdentity {
    /// Creates a new non-delegatable realm identity builder.
    ///
    /// # Arguments
    /// * `subject` - The identity subject (e.g., "urn:hessra:alice")
    /// * `time_config` - Time configuration for token expiration
    pub fn new(subject: String, time_config: TokenTimeConfig) -> Self {
        Self {
            subject,
            time_config,
            is_delegatable: false,
        }
    }

    /// Makes the identity token delegatable.
    ///
    /// When enabled, adds the delegation mechanic to the authority block:
    /// - `check if actor($a), $a == {subject} || $a.starts_with({subject} + ":")`
    /// - `property("delegatable")` fact for easy identification
    ///
    /// When disabled (default), only the exact subject can use the token:
    /// - `check if actor($a), $a == {subject}`
    ///
    /// # Arguments
    /// * `enabled` - Whether to enable delegation (false is noop)
    pub fn delegatable(mut self, enabled: bool) -> Self {
        self.is_delegatable = enabled;
        self
    }

    /// Issues (builds and signs) the identity token.
    ///
    /// # Arguments
    /// * `keypair` - The keypair to sign the token with
    ///
    /// # Returns
    /// Base64-encoded biscuit token
    pub fn issue(self, keypair: &KeyPair) -> Result<String, Box<dyn Error>> {
        let start_time = self
            .time_config
            .start_time
            .unwrap_or_else(|| Utc::now().timestamp());
        let expiration = start_time + self.time_config.duration;

        // Extract self fields for use in macro (macro doesn't support self.field directly)
        let subject = self.subject;
        let is_delegatable = self.is_delegatable;

        // Build the base biscuit with subject and time checks
        let biscuit_builder = if is_delegatable {
            // Delegatable identity: allows hierarchical actor check
            biscuit!(
                r#"
                    subject({subject});
                    check if actor($a), $a == {subject} || $a.starts_with({subject} + ":");
                    check if time($time), $time < {expiration};
                "#
            )
        } else {
            // Non-delegatable realm identity: exact actor match only
            biscuit!(
                r#"
                    subject({subject});
                    check if actor($a), $a == {subject};
                    check if time($time), $time < {expiration};
                "#
            )
        };

        // Build and sign the biscuit
        let biscuit = biscuit_builder.build(keypair)?;
        let token = biscuit.to_base64()?;
        Ok(token)
    }
}
