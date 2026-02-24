extern crate biscuit_auth as biscuit;
use biscuit::macros::block;
use chrono::Utc;
use hessra_token_core::{Biscuit, KeyPair, PublicKey, TokenError};

/// Create a short-lived version of an identity token for just-in-time use
///
/// This function takes an existing identity token and creates an attenuated version
/// that expires in 5 seconds. This is designed for security - the short-lived token
/// can be safely sent over the network while the original long-lived token stays secure
/// on the client.
pub fn create_short_lived_identity_token(
    token: String,
    public_key: PublicKey,
) -> Result<String, TokenError> {
    let biscuit = Biscuit::from_base64(&token, public_key)?;
    let ephemeral_key = KeyPair::new();
    let expiration = Utc::now().timestamp() + 5;

    let time_block = block!(
        r#"
            check if time($time), $time < {expiration};
        "#
    );

    let third_party_request = biscuit.third_party_request()?;
    let time_block = third_party_request.create_block(&ephemeral_key.private(), time_block)?;
    let attenuated_biscuit = biscuit.append_third_party(ephemeral_key.public(), time_block)?;
    let token = attenuated_biscuit.to_base64()?;

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HessraIdentity, verify::IdentityVerifier};
    use hessra_token_core::{KeyPair, TokenTimeConfig};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_short_lived_token_creation() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let identity = "urn:hessra:test:user".to_string();

        let base_token = HessraIdentity::new(identity.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create base token");

        let short_lived = create_short_lived_identity_token(base_token.clone(), public_key)
            .expect("Failed to create short-lived token");

        assert_ne!(base_token, short_lived);

        assert!(
            IdentityVerifier::new(short_lived.clone(), public_key)
                .with_identity(identity.clone())
                .verify()
                .is_ok(),
            "Short-lived token should verify immediately"
        );
    }

    #[test]
    fn test_short_lived_token_expiration() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();
        let identity = "urn:hessra:test:user".to_string();

        let base_token = HessraIdentity::new(identity.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create base token");

        let short_lived = create_short_lived_identity_token(base_token, public_key)
            .expect("Failed to create short-lived token");

        assert!(
            IdentityVerifier::new(short_lived.clone(), public_key)
                .with_identity(identity.clone())
                .verify()
                .is_ok(),
            "Token should verify immediately after creation"
        );

        // Wait for 6 seconds (token expires in 5)
        thread::sleep(Duration::from_secs(6));

        assert!(
            IdentityVerifier::new(short_lived, public_key)
                .with_identity(identity)
                .verify()
                .is_err(),
            "Token should fail verification after 5 seconds"
        );
    }

    #[test]
    fn test_short_lived_preserves_identity() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let alice = "urn:hessra:alice".to_string();
        let bob = "urn:hessra:bob".to_string();

        let alice_token = HessraIdentity::new(alice.clone(), TokenTimeConfig::default())
            .delegatable(true)
            .issue(&keypair)
            .expect("Failed to create alice token");

        let short_lived = create_short_lived_identity_token(alice_token, public_key)
            .expect("Failed to create short-lived token");

        assert!(
            IdentityVerifier::new(short_lived.clone(), public_key)
                .with_identity(alice)
                .verify()
                .is_ok(),
            "Should verify with correct identity"
        );

        assert!(
            IdentityVerifier::new(short_lived, public_key)
                .with_identity(bob)
                .verify()
                .is_err(),
            "Should not verify with different identity"
        );
    }
}
