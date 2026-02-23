extern crate biscuit_auth as biscuit;

use biscuit::macros::block;
use hessra_token_core::{Biscuit, PublicKey, TokenError, utils};

/// Builder for adding designation blocks to capability tokens.
///
/// Designations are standard Biscuit attenuation blocks that narrow the scope
/// of a capability token by specifying which specific object/resource instance
/// the token applies to. Unlike prefix restrictions (which required third-party
/// blocks), designations use regular append-only blocks and do not require a
/// signing key.
///
/// # Example
/// ```rust,no_run
/// use hessra_cap_token::DesignationBuilder;
/// use hessra_token_core::PublicKey;
///
/// # fn example(token: String, public_key: PublicKey) -> Result<(), Box<dyn std::error::Error>> {
/// let attenuated = DesignationBuilder::from_base64(token, public_key)?
///     .designate("tenant_id".to_string(), "t-123".to_string())
///     .designate("user_id".to_string(), "u-456".to_string())
///     .attenuate_base64()?;
/// # Ok(())
/// # }
/// ```
pub struct DesignationBuilder {
    token: Vec<u8>,
    public_key: PublicKey,
    designations: Vec<(String, String)>,
}

impl DesignationBuilder {
    /// Create a new DesignationBuilder from raw token bytes.
    ///
    /// # Arguments
    /// * `token` - The binary token data
    /// * `public_key` - The public key to verify the token
    pub fn new(token: Vec<u8>, public_key: PublicKey) -> Self {
        Self {
            token,
            public_key,
            designations: Vec::new(),
        }
    }

    /// Create a new DesignationBuilder from a base64-encoded token string.
    ///
    /// # Arguments
    /// * `token` - The base64-encoded token string
    /// * `public_key` - The public key to verify the token
    pub fn from_base64(token: String, public_key: PublicKey) -> Result<Self, TokenError> {
        let token_bytes = utils::decode_token(&token)?;
        Ok(Self::new(token_bytes, public_key))
    }

    /// Add a designation (label, value) pair to narrow the token's scope.
    ///
    /// Each designation adds a `check if designation(label, value)` to the token,
    /// requiring the verifier to provide matching `designation(label, value)` facts.
    ///
    /// # Arguments
    /// * `label` - The designation dimension (e.g., "tenant_id", "user_id", "region")
    /// * `value` - The specific value for this dimension (e.g., "t-123", "u-456", "us-east-1")
    pub fn designate(mut self, label: String, value: String) -> Self {
        self.designations.push((label, value));
        self
    }

    /// Attenuate the token with all accumulated designations.
    ///
    /// Returns the attenuated token as binary bytes.
    pub fn attenuate(self) -> Result<Vec<u8>, TokenError> {
        let biscuit = Biscuit::from(&self.token, self.public_key)?;

        let mut block_builder = block!(r#""#);

        for (label, value) in &self.designations {
            let label = label.clone();
            let value = value.clone();
            block_builder = block_builder
                .check(biscuit::macros::check!(
                    r#"check if designation({label}, {value});"#
                ))
                .map_err(|e| TokenError::AttenuationFailed {
                    reason: format!("Failed to add designation check: {e}"),
                })?;
        }

        let attenuated =
            biscuit
                .append(block_builder)
                .map_err(|e| TokenError::AttenuationFailed {
                    reason: format!("Failed to append designation block: {e}"),
                })?;

        attenuated
            .to_vec()
            .map_err(|e| TokenError::AttenuationFailed {
                reason: format!("Failed to serialize attenuated token: {e}"),
            })
    }

    /// Attenuate the token and return as a base64-encoded string.
    pub fn attenuate_base64(self) -> Result<String, TokenError> {
        let bytes = self.attenuate()?;
        Ok(utils::encode_token(&bytes))
    }
}
