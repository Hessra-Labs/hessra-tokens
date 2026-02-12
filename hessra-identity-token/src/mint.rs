extern crate biscuit_auth as biscuit;

use biscuit::macros::{biscuit, check, rule};
use chrono::Utc;
use hessra_token_core::{KeyPair, TokenTimeConfig};
use std::error::Error;

/// Builder for creating Hessra identity tokens with flexible configuration.
///
/// # Terminology
/// - **Realm identity**: A configured principal inside a Realm (default, non-delegatable)
/// - **Domain identity**: A realm identity restricted to a specific domain
/// - **Delegatable identity**: An identity token that can be attenuated/delegated further
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
/// // Delegatable domain identity
/// let token = HessraIdentity::new(subject, TokenTimeConfig::default())
///     .delegatable(true)
///     .domain_restricted("myapp.hessra.dev".to_string())
///     .issue(&keypair)
///     .expect("Failed to create token");
/// ```
pub struct HessraIdentity {
    subject: String,
    time_config: TokenTimeConfig,
    is_delegatable: bool,
    domain: Option<String>,
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
            domain: None,
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

    /// Restricts the identity to a specific domain.
    ///
    /// Adds a domain restriction check to the authority block:
    /// - `check if domain({domain})`
    ///
    /// This creates a "domain identity" that can only be used within the specified domain.
    ///
    /// # Arguments
    /// * `domain` - The domain to restrict to (e.g., "myapp.hessra.dev")
    pub fn domain_restricted(mut self, domain: String) -> Self {
        self.domain = Some(domain);
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
        let domain = self.domain;

        // Build the base biscuit with subject and time checks
        let mut biscuit_builder = if is_delegatable {
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

        // Add domain restriction if specified
        if let Some(domain) = domain {
            biscuit_builder = biscuit_builder.check(check!(
                r#"
                    check if domain({domain});
                "#
            ))?;
            // This rule creates a fact that the subject is associated with the domain,
            // so that verifier can be sure that the subject is associated with the domain.
            biscuit_builder = biscuit_builder.rule(rule!(
                r#"
                    subject($d, $s) <- domain($d), subject($s);
                "#
            ))?;
        }

        // Build and sign the biscuit
        let biscuit = biscuit_builder.build(keypair)?;
        let token = biscuit.to_base64()?;
        Ok(token)
    }
}

/// Creates a basic realm identity token (delegatable).
pub fn create_identity_token(
    subject: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    HessraIdentity::new(subject, time_config)
        .delegatable(true)
        .issue(&key)
}

/// Creates a basic realm identity token (non-delegatable).
pub fn create_non_delegatable_identity_token(
    subject: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    HessraIdentity::new(subject, time_config).issue(&key)
}

/// Creates a domain-restricted identity token (non-delegatable).
pub fn create_domain_restricted_identity_token(
    subject: String,
    domain: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    HessraIdentity::new(subject, time_config)
        .domain_restricted(domain)
        .issue(&key)
}
