extern crate biscuit_auth as biscuit;

use biscuit::macros::{biscuit, check};
use chrono::Utc;
use hessra_token_core::{KeyPair, TokenTimeConfig};
use std::error::Error;
use tracing::info;

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
    namespace: Option<String>,
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
            namespace: None,
        }
    }

    /// Restricts the capability to a specific namespace.
    ///
    /// Adds a namespace restriction check to the authority block:
    /// - `check if namespace({namespace})`
    ///
    /// # Arguments
    /// * `namespace` - The namespace to restrict to (e.g., "myapp.hessra.dev")
    pub fn namespace_restricted(mut self, namespace: String) -> Self {
        self.namespace = Some(namespace);
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

        let namespace = self.namespace;

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

        // Add namespace restriction if specified
        if let Some(namespace) = namespace {
            biscuit_builder = biscuit_builder.check(check!(
                r#"
                    check if namespace({namespace});
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::CapabilityVerifier;
    use chrono::Utc;

    #[test]
    fn test_create_and_verify_capability() {
        let subject = "test@test.com".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        let token = HessraCapability::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig::default(),
        )
        .issue(&root)
        .expect("Failed to create token");

        let res = CapabilityVerifier::new(token, public_key, resource, operation).verify();
        assert!(res.is_ok());
    }

    #[test]
    fn test_capability_without_subject() {
        let subject = "alice".to_owned();
        let resource = "res1".to_string();
        let operation = "read".to_string();
        let root = KeyPair::new();
        let public_key = root.public();

        let token = HessraCapability::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig::default(),
        )
        .issue(&root)
        .expect("Failed to create token");

        // Verify without subject -- the core capability change
        let res = CapabilityVerifier::new(token, public_key, resource, operation).verify();
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

        let token = HessraCapability::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig::default(),
        )
        .issue(&root)
        .expect("Failed to create token");

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

        let token = HessraCapability::new(
            "alice".to_string(),
            "res1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .issue(&root)
        .expect("Failed to create token");

        let res =
            CapabilityVerifier::new(token, public_key, "res2".to_string(), "read".to_string())
                .verify();
        assert!(res.is_err(), "Wrong resource should be rejected");
    }

    #[test]
    fn test_wrong_operation_rejected() {
        let root = KeyPair::new();
        let public_key = root.public();

        let token = HessraCapability::new(
            "alice".to_string(),
            "res1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .issue(&root)
        .expect("Failed to create token");

        let res =
            CapabilityVerifier::new(token, public_key, "res1".to_string(), "write".to_string())
                .verify();
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
        let token = HessraCapability::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig::default(),
        )
        .issue(&root)
        .expect("Failed to create token");

        let res = CapabilityVerifier::new(token, public_key, resource.clone(), operation.clone())
            .verify();
        assert!(res.is_ok());

        // Create an expired token
        let root = KeyPair::new();
        let public_key = root.public();
        let token = HessraCapability::new(
            subject.clone(),
            resource.clone(),
            operation.clone(),
            TokenTimeConfig {
                start_time: Some(Utc::now().timestamp() - 301),
                duration: 300,
            },
        )
        .issue(&root)
        .expect("Failed to create expired token");

        let res = CapabilityVerifier::new(token, public_key, resource, operation).verify();
        assert!(res.is_err(), "Expired token should be rejected");
    }

    #[test]
    fn test_namespace_restricted_capability() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraCapability::new(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .namespace_restricted("myapp.hessra.dev".to_string())
        .issue(&keypair)
        .expect("Failed to create namespace-restricted token");

        // Should pass with matching namespace
        let res = CapabilityVerifier::new(
            token.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_namespace("myapp.hessra.dev".to_string())
        .verify();
        assert!(res.is_ok(), "Should pass with matching namespace");

        // Should fail without namespace
        let res = CapabilityVerifier::new(
            token.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .verify();
        assert!(res.is_err(), "Should fail without namespace");

        // Should fail with wrong namespace
        let res = CapabilityVerifier::new(
            token.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_namespace("wrong.com".to_string())
        .verify();
        assert!(res.is_err(), "Should fail with wrong namespace");
    }

    #[test]
    fn test_designation_attenuation() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Mint a basic token
        let token = HessraCapability::new(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .issue(&keypair)
        .expect("Failed to create token");

        // Attenuate with a designation
        let attenuated = crate::attenuate::DesignationBuilder::from_base64(token, public_key)
            .expect("Failed to create designation builder")
            .designate("tenant_id".to_string(), "t-123".to_string())
            .attenuate_base64()
            .expect("Failed to attenuate");

        // Verify with matching designation
        let res = CapabilityVerifier::new(
            attenuated.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_designation("tenant_id".to_string(), "t-123".to_string())
        .verify();
        assert!(res.is_ok(), "Should pass with matching designation");

        // Verify with wrong designation value
        let res = CapabilityVerifier::new(
            attenuated.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_designation("tenant_id".to_string(), "t-999".to_string())
        .verify();
        assert!(res.is_err(), "Should fail with wrong designation value");

        // Verify without designation should fail
        let res = CapabilityVerifier::new(
            attenuated.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .verify();
        assert!(res.is_err(), "Should fail without designation");
    }

    #[test]
    fn test_multi_designation() {
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

        // Attenuate with multiple designations
        let attenuated = crate::attenuate::DesignationBuilder::from_base64(token, public_key)
            .expect("Failed to create designation builder")
            .designate("tenant_id".to_string(), "t-123".to_string())
            .designate("user_id".to_string(), "u-456".to_string())
            .attenuate_base64()
            .expect("Failed to attenuate");

        // Verify with both designations
        let res = CapabilityVerifier::new(
            attenuated.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_designation("tenant_id".to_string(), "t-123".to_string())
        .with_designation("user_id".to_string(), "u-456".to_string())
        .verify();
        assert!(res.is_ok(), "Should pass with both designations");

        // Verify with only one designation should fail (missing the other)
        let res = CapabilityVerifier::new(
            attenuated.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_designation("tenant_id".to_string(), "t-123".to_string())
        .verify();
        assert!(res.is_err(), "Should fail with missing designation");
    }

    #[test]
    fn test_namespace_plus_designation() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraCapability::new(
            "alice".to_string(),
            "resource1".to_string(),
            "read".to_string(),
            TokenTimeConfig::default(),
        )
        .namespace_restricted("myapp.hessra.dev".to_string())
        .issue(&keypair)
        .expect("Failed to create token");

        // Attenuate with designation
        let attenuated = crate::attenuate::DesignationBuilder::from_base64(token, public_key)
            .expect("Failed to create designation builder")
            .designate("tenant_id".to_string(), "t-123".to_string())
            .attenuate_base64()
            .expect("Failed to attenuate");

        // Verify with both namespace and designation
        let res = CapabilityVerifier::new(
            attenuated.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_namespace("myapp.hessra.dev".to_string())
        .with_designation("tenant_id".to_string(), "t-123".to_string())
        .verify();
        assert!(
            res.is_ok(),
            "Should pass with both namespace and designation"
        );

        // Should fail without namespace
        let res = CapabilityVerifier::new(
            attenuated.clone(),
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .with_designation("tenant_id".to_string(), "t-123".to_string())
        .verify();
        assert!(res.is_err(), "Should fail without namespace");
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

        let res = CapabilityVerifier::new(
            token,
            public_key,
            "resource1".to_string(),
            "read".to_string(),
        )
        .verify();
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

        let token = HessraCapability::new(
            "alice".to_string(),
            "res1".to_string(),
            "read".to_string(),
            time_config,
        )
        .issue(&root)
        .expect("Failed to create token");

        let res =
            CapabilityVerifier::new(token, public_key, "res1".to_string(), "read".to_string())
                .verify();
        assert!(res.is_ok());
    }
}
