extern crate biscuit_auth as biscuit;

use biscuit::Algorithm;
use biscuit::macros::{authorizer, check, fact};
use chrono::Utc;
use hessra_token_core::{
    Biscuit, PublicKey, TokenError, parse_capability_failure, parse_check_failure,
};

/// Builder for verifying Hessra capability tokens with flexible configuration.
///
/// By default, capability verification only checks resource + operation.
/// Subject verification is optional via `.with_subject()`.
///
/// # Example
/// ```no_run
/// use hessra_cap_token::{CapabilityVerifier, HessraCapability};
/// use hessra_token_core::{KeyPair, TokenTimeConfig};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let keypair = KeyPair::new();
/// let public_key = keypair.public();
/// let token = HessraCapability::new(
///     "user123".to_string(),
///     "resource456".to_string(),
///     "read".to_string(),
///     TokenTimeConfig::default(),
/// )
/// .issue(&keypair)?;
///
/// // Basic capability verification (no subject check)
/// CapabilityVerifier::new(
///     token.clone(),
///     public_key,
///     "resource456".to_string(),
///     "read".to_string(),
/// )
/// .verify()?;
///
/// // With optional subject verification
/// CapabilityVerifier::new(
///     token.clone(),
///     public_key,
///     "resource456".to_string(),
///     "read".to_string(),
/// )
/// .with_subject("user123".to_string())
/// .verify()?;
/// # Ok(())
/// # }
/// ```
pub struct CapabilityVerifier {
    token: String,
    public_key: PublicKey,
    resource: String,
    operation: String,
    subject: Option<String>,
    namespace: Option<String>,
    designations: Vec<(String, String)>,
}

impl CapabilityVerifier {
    /// Creates a new capability verifier for a base64-encoded token.
    ///
    /// # Arguments
    /// * `token` - The base64-encoded capability token to verify
    /// * `public_key` - The public key used to verify the token signature
    /// * `resource` - The resource identifier to verify
    /// * `operation` - The operation to verify
    pub fn new(token: String, public_key: PublicKey, resource: String, operation: String) -> Self {
        Self {
            token,
            public_key,
            resource,
            operation,
            subject: None,
            namespace: None,
            designations: Vec::new(),
        }
    }

    /// Adds an optional subject verification check.
    ///
    /// When set, the authorizer adds a check that the minted subject matches.
    /// This is optional -- pure capability verification does not require it.
    ///
    /// # Arguments
    /// * `subject` - The subject to verify in the token's right fact
    pub fn with_subject(mut self, subject: String) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Adds a namespace restriction to the verification.
    ///
    /// # Arguments
    /// * `namespace` - The namespace to verify against (e.g., "example.com")
    pub fn with_namespace(mut self, namespace: String) -> Self {
        self.namespace = Some(namespace);
        self
    }

    /// Adds a designation fact to the verification.
    ///
    /// Each designation provides a `designation(label, value)` fact that the
    /// token's designation checks will verify against.
    ///
    /// # Arguments
    /// * `label` - The designation dimension (e.g., "tenant_id")
    /// * `value` - The specific value (e.g., "t-123")
    pub fn with_designation(mut self, label: String, value: String) -> Self {
        self.designations.push((label, value));
        self
    }

    /// Performs the token verification with the configured parameters.
    ///
    /// # Returns
    /// * `Ok(())` - If the token is valid and meets all verification requirements
    /// * `Err(TokenError)` - If verification fails for any reason
    pub fn verify(self) -> Result<(), TokenError> {
        let biscuit = Biscuit::from_base64(&self.token, self.public_key)?;
        let now = Utc::now().timestamp();
        let resource = self.resource.clone();
        let operation = self.operation.clone();

        // Build the capability authorizer -- no subject fact needed
        let mut authz = authorizer!(
            r#"
                time({now});
                resource({resource});
                operation({operation});
                allow if true;
            "#
        );

        // Optional: add subject check when caller wants to verify who minted the token
        if let Some(ref subject) = self.subject {
            let subject = subject.clone();
            let resource = self.resource.clone();
            let operation = self.operation.clone();
            authz = authz.check(check!(
                r#"check if right({subject}, {resource}, {operation});"#
            ))?;
        }

        // Add namespace fact if specified
        if let Some(namespace) = self.namespace.clone() {
            authz = authz.fact(fact!(r#"namespace({namespace});"#))?;
        }

        // Add designation facts
        for (label, value) in &self.designations {
            let label = label.clone();
            let value = value.clone();
            authz = authz.fact(fact!(r#"designation({label}, {value});"#))?;
        }

        match authz.build(&biscuit)?.authorize() {
            Ok(_) => Ok(()),
            Err(e) => Err(convert_capability_error(
                e,
                self.subject.as_deref(),
                Some(&self.resource),
                Some(&self.operation),
                &self.namespace,
            )),
        }
    }
}

/// Takes a public key encoded as a string in the format "ed25519/..." or "secp256r1/..."
/// and returns a PublicKey.
pub fn biscuit_key_from_string(key: String) -> Result<PublicKey, TokenError> {
    let parts = key.split('/').collect::<Vec<&str>>();
    if parts.len() != 2 {
        return Err(TokenError::invalid_key_format(
            "Key must be in format 'algorithm/hexkey'",
        ));
    }

    let alg = match parts[0] {
        "ed25519" => Algorithm::Ed25519,
        "secp256r1" => Algorithm::Secp256r1,
        _ => {
            return Err(TokenError::invalid_key_format(
                "Unsupported algorithm, must be ed25519 or secp256r1",
            ));
        }
    };

    let key_bytes = hex::decode(parts[1])?;

    let key = PublicKey::from_bytes(&key_bytes, alg)
        .map_err(|e| TokenError::invalid_key_format(e.to_string()))?;

    Ok(key)
}

/// Convert biscuit authorization errors to detailed capability errors
fn convert_capability_error(
    err: biscuit::error::Token,
    subject: Option<&str>,
    resource: Option<&str>,
    operation: Option<&str>,
    namespace: &Option<String>,
) -> TokenError {
    use biscuit::error::{Logic, Token};

    match err {
        Token::FailedLogic(logic_err) => match &logic_err {
            Logic::Unauthorized { checks, .. } | Logic::NoMatchingPolicy { checks } => {
                for failed_check in checks.iter() {
                    let (block_id, check_id, rule) = match failed_check {
                        biscuit::error::FailedCheck::Block(block_check) => (
                            block_check.block_id,
                            block_check.check_id,
                            block_check.rule.clone(),
                        ),
                        biscuit::error::FailedCheck::Authorizer(auth_check) => {
                            (0, auth_check.check_id, auth_check.rule.clone())
                        }
                    };

                    let parsed_error = parse_check_failure(block_id, check_id, &rule);

                    match parsed_error {
                        TokenError::NamespaceMismatch {
                            expected,
                            block_id,
                            check_id,
                            ..
                        } => {
                            return TokenError::NamespaceMismatch {
                                expected,
                                provided: namespace.clone(),
                                block_id,
                                check_id,
                            };
                        }
                        TokenError::Expired { .. } => return parsed_error,
                        _ => {}
                    }
                }

                // Check if this looks like a rights denial (no matching policy)
                if matches!(logic_err, Logic::NoMatchingPolicy { .. }) {
                    return parse_capability_failure(
                        subject,
                        resource,
                        operation,
                        &format!("{checks:?}"),
                    );
                }

                TokenError::from(Token::FailedLogic(logic_err))
            }
            other => TokenError::from(Token::FailedLogic(other.clone())),
        },
        other => TokenError::from(other),
    }
}
