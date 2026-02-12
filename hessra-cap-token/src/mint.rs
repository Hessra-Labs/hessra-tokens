extern crate biscuit_auth as biscuit;

use biscuit::BiscuitBuilder;
use biscuit::macros::{biscuit, check};
use chrono::Utc;
use hessra_token_core::{Biscuit, KeyPair, TokenTimeConfig};
use std::error::Error;
use tracing::info;

use crate::verify::biscuit_key_from_string;

/// Builder for creating Hessra capability tokens with flexible configuration.
///
/// Capability tokens grant access to a resource+operation. The subject field is retained
/// for auditing, but the token no longer requires the verifier to prove who is presenting it.
/// Presenting the capability IS the authorization.
///
/// # Example
/// ```rust
/// use hessra_cap_token::HessraCapability;
/// use hessra_token_core::{KeyPair, TokenTimeConfig};
///
/// let keypair = KeyPair::new();
///
/// // Basic capability token
/// let token = HessraCapability::new(
///     "alice".to_string(),
///     "resource1".to_string(),
///     "read".to_string(),
///     TokenTimeConfig::default()
/// )
/// .issue(&keypair)
/// .expect("Failed to create token");
/// ```
pub struct HessraCapability {
    subject: Option<String>,
    resource: Option<String>,
    operation: Option<String>,
    time_config: TokenTimeConfig,
    domain: Option<String>,
    prefix_attenuator: Option<String>,
}

impl HessraCapability {
    /// Creates a new capability token builder.
    ///
    /// # Arguments
    /// * `subject` - The subject (user) identifier (retained for auditing)
    /// * `resource` - The resource identifier to grant access to
    /// * `operation` - The operation to grant access to
    /// * `time_config` - Time configuration for token validity
    pub fn new(
        subject: String,
        resource: String,
        operation: String,
        time_config: TokenTimeConfig,
    ) -> Self {
        Self {
            subject: Some(subject),
            resource: Some(resource),
            operation: Some(operation),
            time_config,
            domain: None,
            prefix_attenuator: None,
        }
    }

    /// Restricts the capability to a specific domain.
    ///
    /// Adds a domain restriction check to the authority block:
    /// - `check if domain({domain})`
    ///
    /// # Arguments
    /// * `domain` - The domain to restrict to (e.g., "myapp.hessra.dev")
    pub fn domain_restricted(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Restricts the capability to a specific prefix, provided by
    /// a specific third party.
    ///
    /// Adds a prefix restriction check to the authority block:
    /// - `check if prefix_added(true) trusting {prefix_attenuator}`
    ///
    /// # Arguments
    /// * `prefix_attenuator` - The public key string of the prefix attenuator
    pub fn prefix_restricted(mut self, prefix_attenuator: String) -> Self {
        self.prefix_attenuator = Some(prefix_attenuator);
        self
    }

    /// Issues (builds and signs) the capability token.
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

        let domain = self.domain;

        let subject = self.subject.ok_or("Token requires subject")?;
        let resource = self.resource.ok_or("Token requires resource")?;
        let operation = self.operation.ok_or("Token requires operation")?;

        // Build authority block -- subject removed from the check.
        // The right fact still has 3 fields (subject stays for auditing).
        // $sub becomes a free variable -- the token no longer demands the
        // verifier prove who is presenting it.
        let mut biscuit_builder = biscuit!(
            r#"
                right({subject}, {resource}, {operation});
                check if resource($res), operation($op), right($sub, $res, $op);
                check if time($time), $time < {expiration};
            "#
        );

        // Add domain restriction if specified
        if let Some(domain) = domain {
            biscuit_builder = biscuit_builder.check(check!(
                r#"
                    check if domain({domain});
                "#
            ))?;
        }

        // Enforce prefix restriction if specified
        if let Some(prefix_attenuator) = self.prefix_attenuator {
            let prefix_key = biscuit_key_from_string(prefix_attenuator)?;
            biscuit_builder = biscuit_builder.check(check!(
                r#"
                    check if prefix_added(true) trusting {prefix_key};
                "#
            ))?;
        }

        // Build and sign the biscuit
        let biscuit = biscuit_builder.build(keypair)?;
        info!("biscuit (authority): {}", biscuit);
        let token = biscuit.to_base64()?;
        Ok(token)
    }
}

/// Creates a base biscuit builder with custom time configuration.
fn create_base_biscuit_builder_with_time(
    subject: String,
    resource: String,
    operation: String,
    time_config: TokenTimeConfig,
) -> Result<BiscuitBuilder, Box<dyn Error>> {
    let start_time = time_config
        .start_time
        .unwrap_or_else(|| Utc::now().timestamp());
    let expiration = start_time + time_config.duration;

    let biscuit_builder = biscuit!(
        r#"
            right({subject}, {resource}, {operation});
            check if resource($res), operation($op), right($sub, $res, $op);
            check if time($time), $time < {expiration};
        "#
    );

    Ok(biscuit_builder)
}

/// Creates a biscuit (not serialized, not base64 encoded) with custom time configuration.
pub fn create_raw_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<Biscuit, Box<dyn Error>> {
    let biscuit = create_base_biscuit_builder_with_time(subject, resource, operation, time_config)?
        .build(&key)?;

    info!("biscuit (authority): {}", biscuit);

    Ok(biscuit)
}

/// Creates a new biscuit token as binary bytes.
///
/// # Arguments
///
/// * `subject` - The subject (user) identifier (for auditing)
/// * `resource` - The resource identifier to grant access to
/// * `operation` - The operation to grant access to
/// * `key` - The key pair used to sign the token
/// * `time_config` - Time configuration for token validity
pub fn create_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let biscuit = create_raw_biscuit(subject, resource, operation, key, time_config)?;
    let token = biscuit.to_vec()?;
    Ok(token)
}

/// Creates a base64-encoded biscuit token with custom time configuration.
fn create_base64_biscuit(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    let biscuit = create_raw_biscuit(subject, resource, operation, key, time_config)?;
    let token = biscuit.to_base64()?;
    Ok(token)
}

/// Creates a base64-encoded capability token with default time configuration (5 minutes).
pub fn create_token(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
) -> Result<String, Box<dyn Error>> {
    create_base64_biscuit(
        subject,
        resource,
        operation,
        key,
        TokenTimeConfig::default(),
    )
}

/// Creates a base64-encoded capability token with custom time configuration.
pub fn create_token_with_time(
    subject: String,
    resource: String,
    operation: String,
    key: KeyPair,
    time_config: TokenTimeConfig,
) -> Result<String, Box<dyn Error>> {
    create_base64_biscuit(subject, resource, operation, key, time_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{CapabilityVerifier, verify_token_local};
    use chrono::Utc;

    #[test]
    fn test_create_biscuit() {
        let subject = "test@test.com".to_owned();
        let resource: String = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();
        let token = create_biscuit(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            TokenTimeConfig::default(),
        )
        .unwrap();

        let token_string = hessra_token_core::encode_token(&token);
        let res = verify_token_local(&token_string, public_key, &resource, &operation);
        assert!(res.is_ok());
    }

    #[test]
    fn test_capability_without_subject() {
        let subject = "alice".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        let token =
            create_token(subject.clone(), resource.clone(), operation.clone(), root).unwrap();

        // Verify without subject -- the core capability change
        let res = verify_token_local(&token, public_key, &resource, &operation);
        assert!(
            res.is_ok(),
            "Capability verification without subject should succeed"
        );
    }

    #[test]
    fn test_capability_with_optional_subject() {
        let subject = "alice".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        let token =
            create_token(subject.clone(), resource.clone(), operation.clone(), root).unwrap();

        // Verify with optional subject check
        let res = CapabilityVerifier::new(
            token.clone(),
            public_key,
            resource.clone(),
            operation.clone(),
        )
        .with_subject(subject.clone())
        .verify();
        assert!(
            res.is_ok(),
            "Verification with correct subject should succeed"
        );

        // Verify with wrong subject should fail
        let res = CapabilityVerifier::new(
            token.clone(),
            public_key,
            resource.clone(),
            operation.clone(),
        )
        .with_subject("bob".to_string())
        .verify();
        assert!(res.is_err(), "Verification with wrong subject should fail");
    }

    #[test]
    fn test_wrong_resource_rejected() {
        let root = KeyPair::new();
        let public_key = root.public();
        let token = create_token(
            "alice".to_string(),
            "res1".to_string(),
            "read".to_string(),
            root,
        )
        .unwrap();

        let res = verify_token_local(&token, public_key, "res2", "read");
        assert!(res.is_err(), "Wrong resource should be rejected");
    }

    #[test]
    fn test_wrong_operation_rejected() {
        let root = KeyPair::new();
        let public_key = root.public();
        let token = create_token(
            "alice".to_string(),
            "res1".to_string(),
            "read".to_string(),
            root,
        )
        .unwrap();

        let res = verify_token_local(&token, public_key, "res1", "write");
        assert!(res.is_err(), "Wrong operation should be rejected");
    }

    #[test]
    fn test_biscuit_expiration() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        // Create a valid token
        let token =
            create_token(subject.clone(), resource.clone(), operation.clone(), root).unwrap();
        let res = verify_token_local(&token, public_key, &resource, &operation);
        assert!(res.is_ok());

        // Create an expired token
        let root = KeyPair::new();
        let public_key = root.public();
        let token = create_token_with_time(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            root,
            TokenTimeConfig {
                start_time: Some(Utc::now().timestamp() - 301),
                duration: 300,
            },
        )
        .unwrap();
        let res = verify_token_local(&token, public_key, &resource, &operation);
        assert!(res.is_err(), "Expired token should be rejected");
    }

    #[test]
    fn test_domain_restricted_capability() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraCapability::new(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .domain_restricted("myapp.hessra.dev".to_string())
        .issue(&keypair)
        .expect("Failed to create domain-restricted token");

        // Should pass with matching domain
        let res = CapabilityVerifier::new(
            token.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_domain("myapp.hessra.dev".to_string())
        .verify();
        assert!(res.is_ok(), "Should pass with matching domain");

        // Should fail without domain
        let res = verify_token_local(&token, public_key, "resource1", "read");
        assert!(res.is_err(), "Should fail without domain");

        // Should fail with wrong domain
        let res = CapabilityVerifier::new(
            token.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_domain("wrong.com".to_string())
        .verify();
        assert!(res.is_err(), "Should fail with wrong domain");
    }

    #[test]
    fn test_prefix_restriction() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let prefix_key = KeyPair::new();
        let prefix_public_key = hex::encode(prefix_key.public().to_bytes());
        let prefix_public_key_str = format!("ed25519/{prefix_public_key}");

        let token = HessraCapability::new(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .prefix_restricted(prefix_public_key_str)
        .issue(&keypair)
        .expect("Failed to create prefix-restricted token");

        // Without prefix attenuation, verification should fail
        let res = verify_token_local(&token, public_key, "resource1", "read");
        assert!(res.is_err(), "Should fail without prefix attenuation");

        // Add prefix restriction via attenuate module
        let attenuated = crate::attenuate::add_prefix_restriction_to_token(
            token,
            public_key,
            "tenant/123/user/456/".to_string(),
            prefix_key,
        )
        .expect("Failed to add prefix restriction");

        // Now verify with matching prefix
        let res = CapabilityVerifier::new(
            attenuated.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_prefix("tenant/123/user/456/".to_string())
        .verify();
        assert!(res.is_ok(), "Should pass with matching prefix");

        // Wrong prefix should fail
        let res = CapabilityVerifier::new(
            attenuated.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_prefix("tenant/999/user/456/".to_string())
        .verify();
        assert!(res.is_err(), "Should fail with wrong prefix");
    }

    #[test]
    fn test_builder_issue() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraCapability::new(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .issue(&keypair)
        .expect("Failed to create token");

        let res = verify_token_local(&token, public_key, "resource1", "read");
        assert!(res.is_ok());
    }

    #[test]
    fn test_custom_time_config() {
        let root = KeyPair::new();
        let public_key = root.public();

        // Create token with custom start time (1 hour in the past) and longer duration (2 hours)
        let past_time = Utc::now().timestamp() - 3600;
        let time_config = TokenTimeConfig {
            start_time: Some(past_time),
            duration: 7200,
        };

        let token = create_token_with_time(
            "alice".to_string(),
            "res1".to_string(),
            "read".to_string(),
            root,
            time_config,
        )
        .unwrap();

        let res = verify_token_local(&token, public_key, "res1", "read");
        assert!(res.is_ok());
    }
}
