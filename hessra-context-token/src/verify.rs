extern crate biscuit_auth as biscuit;

use biscuit::Biscuit;
use biscuit::macros::authorizer;
use chrono::Utc;
use hessra_token_core::{PublicKey, TokenError};

/// Verifier for context tokens with a fluent builder for exclusion checks.
///
/// `.verify()` always enforces the signature + expiration. Each `.excludes(...)`
/// accumulates a Datalog deny rule scoped with `trusting authority, {pubkey}`,
/// so authorization fails if the token carries any of the excluded exposure
/// labels attested by the issuer.
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
    /// Chainable. Each call accumulates one deny rule; any match blocks
    /// the grant (OR semantics across all excluded labels).
    pub fn excludes(mut self, label: impl Into<String>) -> Self {
        self.excludes.push(label.into());
        self
    }

    /// Run authorization.
    ///
    /// Always enforces signature + expiration. If any `.excludes(...)` labels
    /// were registered, each is checked via a Datalog deny rule scoped to
    /// `trusting authority, {pubkey}` so only issuer-attested facts can
    /// trigger the deny.
    pub fn verify(self) -> Result<(), TokenError> {
        let biscuit = Biscuit::from_base64(&self.token, self.public_key)?;
        let now = Utc::now().timestamp();
        let pk = self.public_key;

        if self.excludes.is_empty() {
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

            return Ok(());
        }

        // Check each excluded label with its own authorize() pass. Each pass
        // uses the macro form for compile-time substitution of {now}, {pk},
        // and {label}. Any deny match aborts with an error tagged by label.
        for excluded in &self.excludes {
            let label = excluded.clone();
            let authz = authorizer!(
                r#"
                    time({now});
                    deny if exposure({label}) trusting authority, {pk};
                    allow if true;
                "#
            );

            authz
                .build(&biscuit)
                .map_err(|e| TokenError::internal(format!("failed to build authorizer: {e}")))?
                .authorize()
                .map_err(|_| {
                    TokenError::internal(format!("precluded exposure label present: {excluded}"))
                })?;
        }

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

    /// Security-critical: exposure facts attested by a *different* keypair
    /// must NOT trigger the issuer-scoped deny rule. The `trusting authority,
    /// {issuer_pubkey}` scope is what enforces this.
    #[test]
    fn test_excludes_ignores_facts_from_other_signers() {
        let issuer = KeyPair::new();
        let issuer_pubkey = issuer.public();

        let attacker = KeyPair::new();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&issuer)
            .expect("Failed to mint");

        // Try to use the attacker's keypair to attest a third-party block.
        // This will sign the block with the attacker's key but append it under
        // the attacker's public key, NOT the issuer's. The `trusting authority,
        // {issuer_pubkey}` scope on the deny rule should ignore it.
        let biscuit = Biscuit::from_base64(&token, issuer_pubkey).unwrap();
        let third_party_request = biscuit.third_party_request().unwrap();
        let attacker_block = biscuit::macros::block!(r#"exposure("PII:SSN");"#);
        let signed = third_party_request
            .create_block(&attacker.private(), attacker_block)
            .unwrap();
        let tampered = biscuit
            .append_third_party(attacker.public(), signed)
            .unwrap();
        let tampered_token = tampered.to_base64().unwrap();

        // The deny rule is scoped to the issuer's pubkey; the attacker-attested
        // PII:SSN fact must NOT trigger it.
        ContextVerifier::new(tampered_token, issuer_pubkey)
            .excludes("PII:SSN")
            .verify()
            .expect("attacker-attested exposure must not affect issuer-scoped check");
    }
}
