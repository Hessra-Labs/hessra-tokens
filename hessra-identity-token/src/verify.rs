extern crate biscuit_auth as biscuit;
use biscuit::macros::{authorizer, fact, policy};
use chrono::Utc;
use hessra_token_core::{Biscuit, PublicKey, TokenError, parse_check_failure};

/// Builder for verifying Hessra identity tokens with flexible configuration.
pub struct IdentityVerifier {
    token: String,
    public_key: PublicKey,
    identity: Option<String>,
    namespace: Option<String>,
    ensure_subject_in_namespace: bool,
}

impl IdentityVerifier {
    /// Creates a new identity verifier for the given token and public key.
    pub fn new(token: String, public_key: PublicKey) -> Self {
        Self {
            token,
            public_key,
            identity: None,
            namespace: None,
            ensure_subject_in_namespace: false,
        }
    }

    /// Adds an identity requirement to the verification.
    pub fn with_identity(mut self, identity: String) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Adds a namespace restriction to the verification.
    pub fn with_namespace(mut self, namespace: String) -> Self {
        self.namespace = Some(namespace);
        self
    }

    /// Ensures that the subject is associated with the namespace.
    pub fn ensure_subject_in_namespace(mut self) -> Self {
        self.ensure_subject_in_namespace = true;
        self
    }

    /// Performs the token verification with the configured parameters.
    pub fn verify(self) -> Result<(), TokenError> {
        let biscuit = Biscuit::from_base64(&self.token, self.public_key)?;
        let now = Utc::now().timestamp();

        let expected_identity = self.identity.clone();
        let expected_namespace = self.namespace.clone();

        let mut authz = if let Some(identity) = self.identity {
            authorizer!(
                r#"
                    time({now});
                    actor({identity});
                "#
            )
        } else {
            authorizer!(
                r#"
                    time({now});
                    actor($a) <- subject($a);
                "#
            )
        };

        if let Some(namespace) = self.namespace {
            authz = authz.fact(fact!(r#"namespace({namespace});"#))?;
        }

        if self.ensure_subject_in_namespace {
            authz = authz.policy(policy!(
                r#"
                    allow if subject($d, $s), namespace($d), subject($s);
                "#
            ))?;
        } else {
            authz = authz.policy(policy!(
                r#"
                    allow if true;
                "#
            ))?;
        }

        let mut authz = authz
            .build(&biscuit)
            .map_err(|e| TokenError::internal(format!("Failed to build authorizer: {e}")))?;

        match authz.authorize() {
            Ok(_) => Ok(()),
            Err(e) => Err(convert_identity_verification_error(
                e,
                expected_identity,
                expected_namespace,
            )),
        }
    }
}

fn convert_identity_verification_error(
    err: biscuit::error::Token,
    expected_identity: Option<String>,
    expected_namespace: Option<String>,
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

                    let enhanced_error = match &parsed_error {
                        TokenError::NamespaceMismatch {
                            expected,
                            block_id,
                            check_id,
                            ..
                        } => TokenError::NamespaceMismatch {
                            expected: expected.clone(),
                            provided: expected_namespace.clone(),
                            block_id: *block_id,
                            check_id: *check_id,
                        },
                        TokenError::IdentityMismatch { expected, .. } => {
                            if let Some(identity) = &expected_identity {
                                TokenError::IdentityMismatch {
                                    expected: expected.clone(),
                                    actual: identity.clone(),
                                }
                            } else {
                                return parsed_error;
                            }
                        }
                        TokenError::HierarchyViolation {
                            expected,
                            delegatable,
                            block_id,
                            check_id,
                            ..
                        } => {
                            if let Some(identity) = &expected_identity {
                                TokenError::HierarchyViolation {
                                    expected: expected.clone(),
                                    actual: identity.clone(),
                                    delegatable: *delegatable,
                                    block_id: *block_id,
                                    check_id: *check_id,
                                }
                            } else {
                                return parsed_error;
                            }
                        }
                        TokenError::Expired { .. } | TokenError::CheckFailed { .. } => {
                            return parsed_error;
                        }
                        _ => continue,
                    };

                    return enhanced_error;
                }

                TokenError::from(Token::FailedLogic(logic_err))
            }
            other => TokenError::from(Token::FailedLogic(other.clone())),
        },
        other => TokenError::from(other),
    }
}
