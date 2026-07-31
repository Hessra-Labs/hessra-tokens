extern crate biscuit_auth as biscuit;

use biscuit::Biscuit;
use biscuit::macros::{authorizer, authorizer_merge};
use chrono::Utc;
use hessra_token_core::{PublicKey, TokenError};

/// Verifier for context tokens with a fluent builder for exclusion checks.
///
/// `.verify()` always enforces the signature + expiration. Each `.excludes(...)`
/// asserts a candidate `exposure({label})` fact into the authorizer; if the
/// token carries a matching `reject if exposure({label})` rule (added by any
/// signer, in any block), that reject fires and authorization fails. No
/// `trusting` scope is involved -- reject rules apply to the whole token.
///
/// # Example
/// ```rust
/// use hessra_context_token::{HessraContext, ContextVerifier, add_exposure};
/// use hessra_token_core::{KeyPair, TokenTimeConfig};
///
/// let keypair = KeyPair::new();
/// let public_key = keypair.public();
///
/// let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
///     .issue(&keypair)
///     .expect("Failed to mint context token");
///
/// let exposed = add_exposure(
///     &token,
///     &keypair,
///     &["PII:email".to_string()],
///     "data:user-profile".to_string(),
/// ).expect("Failed to add exposure");
///
/// // Passes -- "PII:SSN" is not attested.
/// ContextVerifier::new(exposed.clone(), public_key)
///     .excludes("PII:SSN")
///     .verify()
///     .expect("clean of PII:SSN");
///
/// // Fails -- "PII:email" is attested.
/// assert!(ContextVerifier::new(exposed, public_key)
///     .excludes("PII:email")
///     .verify()
///     .is_err());
/// ```
pub struct ContextVerifier {
    token: String,
    public_key: PublicKey,
    excludes: Vec<String>,
}

impl ContextVerifier {
    /// Creates a new context verifier.
    pub fn new(token: String, public_key: PublicKey) -> Self {
        Self {
            token,
            public_key,
            excludes: Vec::new(),
        }
    }

    /// Add an exposure label that must NOT be present in the token.
    ///
    /// Chainable. Each call asserts one candidate `exposure({label})` fact; if
    /// the token rejects any of them, the handout is blocked (OR semantics across
    /// all excluded labels).
    pub fn excludes(mut self, label: impl Into<String>) -> Self {
        self.excludes.push(label.into());
        self
    }

    /// Run authorization.
    ///
    /// Always enforces signature + expiration. Each `.excludes(...)` label is
    /// asserted as an `exposure({label})` fact in a single authorizer pass; a
    /// matching `reject if exposure({label})` rule anywhere in the token fires
    /// the reject and fails verification.
    pub fn verify(self) -> Result<(), TokenError> {
        let biscuit = Biscuit::from_base64(&self.token, self.public_key)?;
        let now = Utc::now().timestamp();

        // Assert the candidate exposure facts for every excluded label in one
        // pass. A token reject rule for any of them aborts authorization; the
        // empty case collapses to a plain signature + expiration check.
        let mut authz = authorizer!(
            r#"
                time({now});
                allow if true;
            "#
        );

        for excluded in &self.excludes {
            let label = excluded.clone();
            authz = authorizer_merge!(authz, r#"exposure({label});"#);
        }

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
    use crate::exposure::add_exposure;
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
    fn test_verify_exposed_token_no_excludes() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            &keypair,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add exposure");

        ContextVerifier::new(exposed, public_key)
            .verify()
            .expect("Exposed token should still verify when no excludes are set");
    }

    #[test]
    fn test_excludes_matching_label_fails() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            &keypair,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add exposure");

        let result = ContextVerifier::new(exposed, public_key)
            .excludes("PII:SSN")
            .verify();

        assert!(
            result.is_err(),
            "Should deny when an excluded label is attested"
        );
    }

    #[test]
    fn test_excludes_non_matching_label_passes() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            &keypair,
            &["PII:email".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add exposure");

        ContextVerifier::new(exposed, public_key)
            .excludes("PII:SSN")
            .verify()
            .expect("Should allow when no excluded label is attested");
    }

    #[test]
    fn test_excludes_chained_any_match_fails() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            &keypair,
            &["PII:email".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add exposure");

        let result = ContextVerifier::new(exposed, public_key)
            .excludes("PII:SSN")
            .excludes("PII:email")
            .excludes("PII:dob")
            .verify();

        assert!(
            result.is_err(),
            "Should deny when any chained exclude matches an attested label"
        );
    }

    #[test]
    fn test_excludes_chained_none_match_passes() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            &keypair,
            &["PII:email".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add exposure");

        ContextVerifier::new(exposed, public_key)
            .excludes("PII:SSN")
            .excludes("PII:dob")
            .verify()
            .expect("Should pass when none of the chained excludes match");
    }

    #[test]
    fn test_excludes_clean_token_passes() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        ContextVerifier::new(token, public_key)
            .excludes("PII:SSN")
            .verify()
            .expect("Clean token should pass any excludes check");
    }

    #[test]
    fn test_excludes_expired_token_fails() {
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
            .excludes("PII:SSN")
            .verify();

        assert!(
            result.is_err(),
            "Expired token should fail even with non-matching excludes"
        );
    }

    /// Sketch parity: verify the three-exposure scenario from
    /// `/Users/jakev/code/playground/context-token/src/main.rs`.
    #[test]
    fn test_sketch_parity_three_exposures() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:sketch".to_string(), TokenTimeConfig::default())
            .with_initial_exposures(&["exposure1".to_string()], "source1")
            .issue(&keypair)
            .expect("Failed to mint");

        let token = add_exposure(
            &token,
            &keypair,
            &["exposure2".to_string()],
            "source2".to_string(),
        )
        .unwrap();

        let token = add_exposure(
            &token,
            &keypair,
            &["exposure3".to_string()],
            "source3".to_string(),
        )
        .unwrap();

        assert!(
            ContextVerifier::new(token.clone(), public_key)
                .excludes("exposure1")
                .verify()
                .is_err()
        );
        assert!(
            ContextVerifier::new(token.clone(), public_key)
                .excludes("exposure2")
                .verify()
                .is_err()
        );
        assert!(
            ContextVerifier::new(token.clone(), public_key)
                .excludes("exposure3")
                .verify()
                .is_err()
        );
        ContextVerifier::new(token, public_key)
            .excludes("exposure4")
            .verify()
            .expect("exposure4 is absent");
    }

    /// By design under reject-if: a `reject if exposure(X)` appended by *any*
    /// signer (here a throwaway/ephemeral keypair) is honored. Rejects are
    /// monotonic -- they can only make a token more restrictive -- so no
    /// `trusting` scope is needed and any party may tighten the token.
    #[test]
    fn test_third_party_reject_from_ephemeral_key_applies() {
        let issuer = KeyPair::new();
        let issuer_pubkey = issuer.public();

        let ephemeral = KeyPair::new();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&issuer)
            .expect("Failed to mint");

        // Append a reject rule signed by an unrelated ephemeral keypair.
        let biscuit = Biscuit::from_base64(&token, issuer_pubkey).unwrap();
        let third_party_request = biscuit.third_party_request().unwrap();
        let reject_block = biscuit::macros::block!(r#"reject if exposure("blocked");"#);
        let signed = third_party_request
            .create_block(&ephemeral.private(), reject_block)
            .unwrap();
        let tightened = biscuit
            .append_third_party(ephemeral.public(), signed)
            .unwrap();
        let tightened_token = tightened.to_base64().unwrap();

        // The reject applies even though it was not signed by the issuer.
        let result = ContextVerifier::new(tightened_token.clone(), issuer_pubkey)
            .excludes("blocked")
            .verify();
        assert!(
            result.is_err(),
            "a reject appended by any signer must be honored"
        );

        // ...but only for the label it names.
        ContextVerifier::new(tightened_token, issuer_pubkey)
            .excludes("other")
            .verify()
            .expect("unrelated excludes must still pass");
    }

    /// An attacker-appended `exposure(X)` *fact* (not a reject) is inert: reject
    /// rules in other blocks do not see sibling-block facts, and enumeration
    /// reads `exposed_label`, not `exposure`. So it cannot cause a spurious
    /// failure nor leak into the reported labels.
    #[test]
    fn test_injected_exposure_fact_is_inert() {
        use crate::exposure::extract_exposure_labels;

        let issuer = KeyPair::new();
        let issuer_pubkey = issuer.public();
        let attacker = KeyPair::new();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&issuer)
            .expect("Failed to mint");

        let exposed = add_exposure(
            &token,
            &issuer,
            &["PII:email".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add exposure");

        // Attacker grafts a bare exposure(...) fact in a third-party block.
        let biscuit = Biscuit::from_base64(&exposed, issuer_pubkey).unwrap();
        let third_party_request = biscuit.third_party_request().unwrap();
        let attacker_block = biscuit::macros::block!(r#"exposure("PII:SSN");"#);
        let signed = third_party_request
            .create_block(&attacker.private(), attacker_block)
            .unwrap();
        let tampered = biscuit
            .append_third_party(attacker.public(), signed)
            .unwrap();
        let tampered_token = tampered.to_base64().unwrap();

        // The injected fact does not trip an unrelated excludes check.
        ContextVerifier::new(tampered_token.clone(), issuer_pubkey)
            .excludes("PII:dob")
            .verify()
            .expect("a grafted exposure fact must not cause spurious failure");

        // And it does not appear in the enumerated labels.
        let labels = extract_exposure_labels(&tampered_token, issuer_pubkey)
            .expect("Failed to extract labels");
        assert_eq!(labels, vec!["PII:email".to_string()]);
    }
}
