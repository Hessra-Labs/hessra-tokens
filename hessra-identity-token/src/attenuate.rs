extern crate biscuit_auth as biscuit;
use biscuit::macros::block;
use chrono::Utc;
use hessra_token_core::{Biscuit, KeyPair, PublicKey, TokenError, TokenTimeConfig};

use crate::verify::verify_identity_token;

pub fn add_identity_attenuation_to_token(
    token: String,
    identity: String,
    public_key: PublicKey,
    time_config: TokenTimeConfig,
) -> Result<String, TokenError> {
    let ephemeral_key = KeyPair::new();
    let biscuit = Biscuit::from_base64(&token, public_key)?;
    let start_time = time_config
        .start_time
        .unwrap_or_else(|| Utc::now().timestamp());
    let expiration = start_time + time_config.duration;
    let ident = identity.clone();
    let identity_block = block!(
        r#"
            check if actor($a), $a == {identity} || $a.starts_with({identity} + ":");
            check if time($time), $time < {expiration};
        "#
    );

    let third_party_request = biscuit.third_party_request()?;

    let identity_block =
        third_party_request.create_block(&ephemeral_key.private(), identity_block)?;

    let attenuated_biscuit = biscuit.append_third_party(ephemeral_key.public(), identity_block)?;

    let token = attenuated_biscuit.to_base64()?;

    // Verifying the token after attenuating it ensures that the token *can* be attenuated.
    verify_identity_token(token.clone(), public_key, ident).map_err(|e| {
        TokenError::AttenuationFailed {
            reason: format!("Failed to verify attenuated token: {e}"),
        }
    })?;
    Ok(token)
}
