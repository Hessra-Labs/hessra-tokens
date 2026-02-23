mod attenuate;
mod inspect;
mod jit;
mod mint;
mod revocation;
mod verify;

pub use attenuate::add_identity_attenuation_to_token;
pub use inspect::{InspectResult, inspect_identity_token};
pub use jit::create_short_lived_identity_token;
pub use mint::{
    HessraIdentity, create_identity_token, create_namespace_restricted_identity_token,
    create_non_delegatable_identity_token,
};
pub use revocation::{
    IdentityRevocation, get_active_identity_revocation, get_identity_revocations,
};
pub use verify::{IdentityVerifier, verify_bearer_token, verify_identity_token};

#[cfg(test)]
mod tests {
    use super::*;
    use hessra_token_core::{KeyPair, TokenTimeConfig};

    #[test]
    fn test_basic_identity_token_creation_and_verification() {
        // Create a keypair for signing
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Test 1: Create and verify non-delegatable realm identity token with exact match
        let subject = "urn:hessra:alice".to_string();
        let token = HessraIdentity::new(subject.clone(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create identity token");

        // Should pass with exact identity
        assert!(
            verify_identity_token(token.clone(), public_key, subject.clone()).is_ok(),
            "Verification should succeed with exact identity match"
        );

        // Should pass verification as a bearer token
        assert!(
            verify_bearer_token(token.clone(), public_key).is_ok(),
            "Verification should succeed as a bearer token"
        );

        // Should fail with different identity
        assert!(
            verify_identity_token(token.clone(), public_key, "urn:hessra:bob".to_string()).is_err(),
            "Verification should fail with different identity"
        );

        // Non-delegatable realm identity: hierarchical identities should NOT work
        // because the base token only allows exact match: $a == {subject}
        assert!(
            verify_identity_token(
                token.clone(),
                public_key,
                "urn:hessra:alice:agent".to_string()
            )
            .is_err(),
            "Hierarchical identity should fail for non-delegatable realm identity"
        );

        // Test 2: Create and verify delegatable realm identity token
        let delegatable_token = HessraIdentity::new(subject.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create delegatable identity token");

        // Exact identity should work
        assert!(
            verify_identity_token(delegatable_token.clone(), public_key, subject.clone()).is_ok(),
            "Exact identity should work with delegatable token"
        );

        // Hierarchical identities should work with delegatable tokens
        assert!(
            verify_identity_token(
                delegatable_token.clone(),
                public_key,
                "urn:hessra:alice:agent".to_string()
            )
            .is_ok(),
            "Hierarchical identity should work with delegatable realm identity"
        );
    }

    #[test]
    fn test_single_level_delegation() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create base delegatable identity token
        let base_identity = "urn:hessra:alice".to_string();
        let token = HessraIdentity::new(base_identity.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create delegatable identity token");

        // Attenuate to a more specific identity
        let delegated_identity = "urn:hessra:alice:laptop".to_string();
        let attenuated_result = add_identity_attenuation_to_token(
            token.clone(),
            delegated_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        );

        let attenuated_token = match attenuated_result {
            Ok(t) => t,
            Err(e) => panic!("Failed to attenuate token: {e:?}"),
        };

        // Original identity should NOT work with attenuated token (delegation restricts usage)
        let base_verify_result =
            verify_identity_token(attenuated_token.clone(), public_key, base_identity.clone());
        assert!(
            base_verify_result.is_err(),
            "Base identity should NOT verify with attenuated token - use original token instead"
        );

        // Delegated identity should work
        assert!(
            verify_identity_token(
                attenuated_token.clone(),
                public_key,
                delegated_identity.clone()
            )
            .is_ok(),
            "Delegated identity should verify"
        );

        // Delegated identities don't work as bearer tokens
        assert!(
            verify_bearer_token(attenuated_token.clone(), public_key).is_err(),
            "Delegated identity should not verify as a bearer token"
        );

        // Different branch should fail
        assert!(
            verify_identity_token(
                attenuated_token.clone(),
                public_key,
                "urn:hessra:alice:phone".to_string()
            )
            .is_err(),
            "Different branch of delegation should fail"
        );

        // Completely different identity should fail
        assert!(
            verify_identity_token(
                attenuated_token.clone(),
                public_key,
                "urn:hessra:bob".to_string()
            )
            .is_err(),
            "Completely different identity should fail"
        );
    }

    #[test]
    fn test_multi_level_delegation_chain() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create organizational hierarchy
        let org_identity = "urn:hessra:company".to_string();
        let dept_identity = "urn:hessra:company:dept_eng".to_string();
        let user_identity = "urn:hessra:company:dept_eng:alice".to_string();
        let device_identity = "urn:hessra:company:dept_eng:alice:laptop".to_string();

        // Create base delegatable token for organization
        let token = HessraIdentity::new(org_identity.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create delegatable org token");

        // First attenuation: org -> department
        let token = add_identity_attenuation_to_token(
            token,
            dept_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate to department");

        // Second attenuation: department -> user
        let token = add_identity_attenuation_to_token(
            token,
            user_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate to user");

        // Third attenuation: user -> device
        let token = add_identity_attenuation_to_token(
            token,
            device_identity.clone(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate to device");

        // After all attenuations, only the most specific identity should work
        // (all checks must pass, so we get the intersection)
        assert!(
            verify_identity_token(token.clone(), public_key, org_identity).is_err(),
            "Organization level should NOT work after delegation to device"
        );
        assert!(
            verify_identity_token(token.clone(), public_key, dept_identity).is_err(),
            "Department level should NOT work after delegation to device"
        );
        assert!(
            verify_identity_token(token.clone(), public_key, user_identity).is_err(),
            "User level should NOT work after delegation to device"
        );
        assert!(
            verify_identity_token(token.clone(), public_key, device_identity).is_ok(),
            "Device level SHOULD work - it's the delegated identity"
        );

        // Different branches should fail
        assert!(
            verify_identity_token(
                token.clone(),
                public_key,
                "urn:hessra:company:dept_hr".to_string()
            )
            .is_err(),
            "Different department should fail"
        );
        assert!(
            verify_identity_token(
                token.clone(),
                public_key,
                "urn:hessra:company:dept_eng:bob".to_string()
            )
            .is_err(),
            "Different user in same department should fail"
        );
        assert!(
            verify_identity_token(
                token.clone(),
                public_key,
                "urn:hessra:company:dept_eng:alice:phone".to_string()
            )
            .is_err(),
            "Different device for same user should fail"
        );
    }

    #[test]
    fn test_time_based_expiration() {
        let identity = "urn:hessra:alice".to_string();

        // Create token that's already expired
        let expired_config = TokenTimeConfig {
            start_time: Some(0), // Unix epoch
            duration: 1,         // 1 second
        };

        let expired_keypair = KeyPair::new();
        let expired_public_key = expired_keypair.public();
        let expired_token = HessraIdentity::new(identity.clone(), expired_config)
            .issue(&expired_keypair)
            .expect("Failed to create expired token");

        // Should fail verification due to expiration
        assert!(
            verify_identity_token(expired_token, expired_public_key, identity.clone()).is_err(),
            "Expired token should fail verification"
        );

        // Create valid base delegatable token with long duration
        let valid_config = TokenTimeConfig {
            start_time: None,
            duration: 3600, // 1 hour
        };

        let valid_keypair = KeyPair::new();
        let valid_public_key = valid_keypair.public();
        let valid_token = HessraIdentity::new(identity.clone(), valid_config)
            .delegatable(true)
            .issue(&valid_keypair)
            .expect("Failed to create valid delegatable token");

        // Attempt to attenuate with already expired time, this should fail because
        // the attenuation call verifies that the token attenuation is possible.
        assert!(
            add_identity_attenuation_to_token(
                valid_token.clone(),
                "urn:hessra:alice:laptop".to_string(),
                valid_public_key, // Use the same public key that signed the token
                expired_config,
            )
            .is_err(),
            "Attenuating a token with an expired time should fail"
        );
    }

    #[test]
    fn test_uri_validation_edge_cases() {
        // Test with different URI schemes
        // Note: Current implementation assumes ":" as hierarchy delimiter
        let test_cases = vec![
            ("urn:hessra:user", "urn:hessra:user:device"),
            (
                "https://example.com/user",
                "https://example.com/user:device",
            ), // Use : for hierarchy
            ("mailto:user@example.com", "mailto:user@example.com:device"),
            ("user", "user:device"), // Simple non-URI format
        ];

        for (base, delegated) in test_cases {
            // Create a new keypair for each test case
            let keypair = KeyPair::new();
            let public_key = keypair.public();

            let token = HessraIdentity::new(base.to_string(), TokenTimeConfig::default())
                .delegatable(true)
                .issue(&keypair)
                .unwrap_or_else(|_| panic!("Failed to create delegatable token for {base}"));

            let attenuated = add_identity_attenuation_to_token(
                token,
                delegated.to_string(),
                public_key, // Use the same public key
                TokenTimeConfig::default(),
            )
            .unwrap_or_else(|_| panic!("Failed to attenuate {base} to {delegated}"));

            // After attenuation, only the delegated identity should work
            assert!(
                verify_identity_token(attenuated.clone(), public_key, base.to_string()).is_err(),
                "Base identity {base} should NOT verify after delegation"
            );
            assert!(
                verify_identity_token(attenuated, public_key, delegated.to_string()).is_ok(),
                "Delegated identity {delegated} should verify"
            );
        }
    }

    #[test]
    fn test_prefix_attack_prevention() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Create delegatable token for alice
        let alice_token =
            HessraIdentity::new("urn:hessra:alice".to_string(), TokenTimeConfig::default())
                .delegatable(true)
                .issue(&keypair)
                .expect("Failed to create delegatable alice token");

        // alice2 should not be able to verify (even though "alice" is a prefix of "alice2")
        assert!(
            verify_identity_token(
                alice_token.clone(),
                public_key,
                "urn:hessra:alice2".to_string()
            )
            .is_err(),
            "alice2 should not verify against alice token"
        );

        // Create attenuated token
        let attenuated = add_identity_attenuation_to_token(
            alice_token,
            "urn:hessra:alice:device".to_string(),
            public_key,
            TokenTimeConfig::default(),
        )
        .expect("Failed to attenuate");

        // Similar prefix attacks on attenuated token
        assert!(
            verify_identity_token(
                attenuated.clone(),
                public_key,
                "urn:hessra:alice:device2".to_string()
            )
            .is_err(),
            "device2 should not verify against device"
        );
        assert!(
            verify_identity_token(
                attenuated,
                public_key,
                "urn:hessra:alice2:device".to_string()
            )
            .is_err(),
            "alice2:device should not verify"
        );
    }

    #[test]
    fn test_empty_identity_handling() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        // Test 1: Non-delegatable empty identity
        let result =
            HessraIdentity::new("".to_string(), TokenTimeConfig::default()).issue(&keypair);

        // This should succeed in creation (empty string is valid)
        assert!(
            result.is_ok(),
            "Should be able to create non-delegatable token with empty identity"
        );

        let token = result.unwrap();

        // Verification with empty identity should work
        assert!(
            verify_identity_token(token.clone(), public_key, "".to_string()).is_ok(),
            "Empty identity should verify against empty identity token"
        );

        // Non-empty identity should fail (non-delegatable requires exact match)
        assert!(
            verify_identity_token(token.clone(), public_key, "urn:hessra:anyone".to_string())
                .is_err(),
            "Non-empty identity should not verify against non-delegatable empty identity token"
        );

        assert!(
            verify_identity_token(token, public_key, ":something".to_string()).is_err(),
            "Identity starting with : should not match non-delegatable empty identity"
        );

        // Test 2: Delegatable empty identity
        let delegatable_token = HessraIdentity::new("".to_string(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create delegatable empty identity token");

        // Empty identity should work
        assert!(
            verify_identity_token(delegatable_token.clone(), public_key, "".to_string()).is_ok(),
            "Empty identity should verify against delegatable empty identity token"
        );

        // Something starting with ":" would pass due to starts_with check
        assert!(
            verify_identity_token(delegatable_token, public_key, ":something".to_string()).is_ok(),
            "Identity starting with : would match delegatable empty identity's hierarchy check"
        );
    }

    #[test]
    fn test_namespace_restricted_identity_verification() {
        use verify::IdentityVerifier;

        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let subject = "urn:hessra:alice".to_string();
        let namespace = "example.com".to_string();

        // Test 1: Non-delegatable namespace-restricted token
        let ns_token = HessraIdentity::new(subject.clone(), TokenTimeConfig::default())
            .namespace_restricted(namespace.clone())
            .issue(&keypair)
            .expect("Failed to create namespace-restricted token");

        // Should pass with matching namespace using builder
        assert!(
            IdentityVerifier::new(ns_token.clone(), public_key)
                .with_identity(subject.clone())
                .with_namespace(namespace.clone())
                .verify()
                .is_ok(),
            "Verification should succeed with matching namespace"
        );

        // Should pass with matching namespace using builder and ensuring subject in namespace
        assert!(
            IdentityVerifier::new(ns_token.clone(), public_key)
                .with_identity(subject.clone())
                .with_namespace(namespace.clone())
                .ensure_subject_in_namespace()
                .verify()
                .is_ok(),
            "Verification should succeed with matching namespace"
        );

        // Should fail without namespace context
        assert!(
            verify_identity_token(ns_token.clone(), public_key, subject.clone()).is_err(),
            "Verification should fail without namespace context"
        );

        // Should fail with wrong namespace
        assert!(
            IdentityVerifier::new(ns_token.clone(), public_key)
                .with_identity(subject.clone())
                .with_namespace("wrong.com".to_string())
                .verify()
                .is_err(),
            "Verification should fail with wrong namespace"
        );

        // Bearer verification should fail (needs namespace fact)
        assert!(
            verify_bearer_token(ns_token.clone(), public_key).is_err(),
            "Bearer verification should fail without namespace context"
        );

        // Bearer with namespace should pass
        assert!(
            IdentityVerifier::new(ns_token.clone(), public_key)
                .with_namespace(namespace.clone())
                .verify()
                .is_ok(),
            "Bearer verification should pass with namespace context"
        );

        // Test 2: Delegatable namespace-restricted token
        let delegatable_ns_token = HessraIdentity::new(subject.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .namespace_restricted(namespace.clone())
            .issue(&keypair)
            .expect("Failed to create delegatable namespace-restricted token");

        // Should pass with exact identity and namespace
        assert!(
            IdentityVerifier::new(delegatable_ns_token.clone(), public_key)
                .with_identity(subject.clone())
                .with_namespace(namespace.clone())
                .ensure_subject_in_namespace()
                .verify()
                .is_ok(),
            "Delegatable token should verify with exact identity and namespace"
        );

        // Should pass with hierarchical identity and namespace
        assert!(
            IdentityVerifier::new(delegatable_ns_token.clone(), public_key)
                .with_identity("urn:hessra:alice:laptop".to_string())
                .with_namespace(namespace.clone())
                .ensure_subject_in_namespace()
                .verify()
                .is_ok(),
            "Delegatable token should verify with hierarchical identity and namespace"
        );

        // Should fail with hierarchical identity but no namespace
        assert!(
            verify_identity_token(
                delegatable_ns_token.clone(),
                public_key,
                "urn:hessra:alice:laptop".to_string()
            )
            .is_err(),
            "Delegatable token should fail without namespace context"
        );

        // Test 3: Non-namespace-restricted token with namespace context
        // (extra context shouldn't break verification)
        let regular_token = HessraIdentity::new(subject.clone(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create regular token");

        // Regular token should pass with or without namespace context
        assert!(
            verify_identity_token(regular_token.clone(), public_key, subject.clone()).is_ok(),
            "Regular token should verify without namespace context"
        );

        assert!(
            IdentityVerifier::new(regular_token.clone(), public_key)
                .with_identity(subject.clone())
                .with_namespace(namespace.clone())
                .verify()
                .is_ok(),
            "Regular token should verify even with extra namespace context"
        );

        // Test 4: Ensure subject in namespace
        // This should fail because the subject is not associated with the namespace
        assert!(
            IdentityVerifier::new(regular_token.clone(), public_key)
                .with_identity(subject.clone())
                .with_namespace(namespace.clone())
                .ensure_subject_in_namespace()
                .verify()
                .is_err(),
            "Regular token should fail to verify with ensure subject in namespace"
        );
    }
}
