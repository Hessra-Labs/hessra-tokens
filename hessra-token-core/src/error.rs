use thiserror::Error;

/// Detailed error type for hessra-token operations with specific failure information
#[derive(Error, Debug, Clone)]
pub enum TokenError {
    // ===== Signature and Format Errors =====
    /// Token signature verification failed
    #[error("Invalid token signature: {details}")]
    InvalidSignature { details: String },

    /// The root public key was not recognized
    #[error("Unknown public key - token was not signed by a recognized authority")]
    UnknownPublicKey,

    /// Invalid key format provided
    #[error("Invalid key format: {reason}")]
    InvalidKeyFormat { reason: String },

    /// Token deserialization failed
    #[error("Failed to deserialize token: {reason}")]
    DeserializationError { reason: String },

    /// Token serialization failed
    #[error("Failed to serialize token: {reason}")]
    SerializationError { reason: String },

    /// Base64 decoding failed
    #[error("Failed to decode base64 token: {reason}")]
    Base64DecodingError { reason: String },

    /// Token format version is not supported
    #[error("Unsupported token version: expected {maximum}-{minimum}, got {actual}")]
    UnsupportedVersion {
        maximum: u32,
        minimum: u32,
        actual: u32,
    },

    // ===== Verification Errors (Common) =====
    /// Token has expired
    #[error("Token expired at {expired_at}, current time is {current_time}")]
    Expired {
        /// When the token expired (Unix timestamp)
        expired_at: i64,
        /// Current time when verification was attempted (Unix timestamp)
        current_time: i64,
        /// Block ID where the expiration check failed
        block_id: u32,
        /// Check ID within the block
        check_id: u32,
    },

    /// Domain restriction check failed
    #[error("Domain mismatch: expected '{expected}', {}", match provided {
        Some(p) => format!("got '{p}'"),
        None => "no domain provided".to_string(),
    })]
    DomainMismatch {
        /// Expected domain from token
        expected: String,
        /// Domain provided during verification (if any)
        provided: Option<String>,
        /// Block ID where the check failed
        block_id: u32,
        /// Check ID within the block
        check_id: u32,
    },

    /// A generic check failed (couldn't parse semantic meaning)
    #[error("Verification check failed in block {block_id}, check {check_id}: {rule}")]
    CheckFailed {
        /// Block ID where the check failed
        block_id: u32,
        /// Check ID within the block
        check_id: u32,
        /// The Datalog rule that failed
        rule: String,
    },

    // ===== Identity Token Errors =====
    /// Identity/actor mismatch
    #[error("Identity mismatch: expected '{expected}', got '{actual}'")]
    IdentityMismatch {
        /// Expected identity
        expected: String,
        /// Actual identity provided
        actual: String,
    },

    /// Identity hierarchy violation (delegation not allowed)
    #[error(
        "Identity hierarchy violation: actor '{actual}' is not authorized for identity '{expected}' (delegatable: {delegatable})"
    )]
    HierarchyViolation {
        /// Base identity that issued the token
        expected: String,
        /// Actor attempting to use the token
        actual: String,
        /// Whether delegation was allowed
        delegatable: bool,
        /// Block ID where the check failed
        block_id: u32,
        /// Check ID within the block
        check_id: u32,
    },

    /// Token attenuation failed
    #[error("Token attenuation failed: {reason}")]
    AttenuationFailed { reason: String },

    /// Bearer token not allowed in this context
    #[error("Bearer token not allowed: {reason}")]
    BearerNotAllowed { reason: String },

    // ===== Capability Token Errors =====
    /// Capability rights denied
    #[error("Authorization denied: {subject} does not have permission to perform '{operation}' on '{resource}'", subject = subject.as_deref().unwrap_or("<capability bearer>"))]
    RightsDenied {
        /// Subject requesting the action (None for pure capability tokens)
        subject: Option<String>,
        /// Resource being accessed
        resource: String,
        /// Operation being performed
        operation: String,
    },

    /// No authorization policy matched and checks failed
    #[error("No matching authorization policy found. Failed checks: {}", format_check_failures(.failed_checks))]
    NoMatchingPolicy {
        /// List of checks that failed
        failed_checks: Vec<CheckFailure>,
    },

    /// Authorization policy matched but checks failed
    #[error("Authorization policy {policy_type} matched (index {policy_index}), but the following checks failed: {}", format_check_failures(.failed_checks))]
    PolicyMatchedButChecksFailed {
        /// Type of policy that matched (Allow/Deny)
        policy_type: String,
        /// Index of the policy
        policy_index: usize,
        /// List of checks that failed
        failed_checks: Vec<CheckFailure>,
    },

    // ===== Execution Errors =====
    /// Datalog execution limit reached
    #[error("Token verification exceeded execution limits: {reason}")]
    ExecutionLimitReached { reason: String },

    /// Datalog expression evaluation failed
    #[error("Token verification expression error: {reason}")]
    ExpressionError { reason: String },

    /// Invalid block rule
    #[error("Invalid rule in block {block_id}: {rule}")]
    InvalidBlockRule { block_id: u32, rule: String },

    // ===== Generic Errors =====
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Generic error with message
    #[error("{0}")]
    Generic(String),
}

/// Details about a failed check from biscuit verification
#[derive(Debug, Clone)]
pub struct CheckFailure {
    /// Block ID (None if from authorizer)
    pub block_id: Option<u32>,
    /// Check ID
    pub check_id: u32,
    /// The Datalog rule that failed
    pub rule: String,
}

impl std::fmt::Display for CheckFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(block_id) = self.block_id {
            write!(
                f,
                "Check #{} in block #{}: {}",
                self.check_id, block_id, self.rule
            )
        } else {
            write!(f, "Check #{} in authorizer: {}", self.check_id, self.rule)
        }
    }
}

fn format_check_failures(checks: &[CheckFailure]) -> String {
    checks
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

impl TokenError {
    // ===== Helper Methods for Common Error Checks =====

    /// Check if this error is due to token expiration
    pub fn is_expired(&self) -> bool {
        matches!(self, TokenError::Expired { .. })
    }

    /// Check if this error is due to domain mismatch
    pub fn is_domain_mismatch(&self) -> bool {
        matches!(self, TokenError::DomainMismatch { .. })
    }

    /// Check if this error is due to identity mismatch
    pub fn is_identity_mismatch(&self) -> bool {
        matches!(
            self,
            TokenError::IdentityMismatch { .. } | TokenError::HierarchyViolation { .. }
        )
    }

    /// Check if this error is due to authorization rights denial
    pub fn is_rights_denied(&self) -> bool {
        matches!(self, TokenError::RightsDenied { .. })
    }

    /// Check if this error is a signature/format error
    pub fn is_signature_error(&self) -> bool {
        matches!(
            self,
            TokenError::InvalidSignature { .. }
                | TokenError::UnknownPublicKey
                | TokenError::DeserializationError { .. }
                | TokenError::Base64DecodingError { .. }
        )
    }

    /// Get the expiration time if this is an expiration error
    pub fn get_expiration_time(&self) -> Option<i64> {
        match self {
            TokenError::Expired { expired_at, .. } => Some(*expired_at),
            _ => None,
        }
    }

    /// Get the expected domain if this is a domain mismatch error
    pub fn get_expected_domain(&self) -> Option<&str> {
        match self {
            TokenError::DomainMismatch { expected, .. } => Some(expected.as_str()),
            _ => None,
        }
    }

    /// Get the missing rights if this is a rights denied error
    pub fn get_denied_access(&self) -> Option<(Option<&str>, &str, &str)> {
        match self {
            TokenError::RightsDenied {
                subject,
                resource,
                operation,
            } => Some((subject.as_deref(), resource.as_str(), operation.as_str())),
            _ => None,
        }
    }

    // ===== Constructor Helper Methods =====

    /// Create a generic error
    pub fn generic<S: Into<String>>(msg: S) -> Self {
        TokenError::Generic(msg.into())
    }

    /// Create an internal error
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        TokenError::Internal(msg.into())
    }

    /// Create an invalid key format error
    pub fn invalid_key_format<S: Into<String>>(reason: S) -> Self {
        TokenError::InvalidKeyFormat {
            reason: reason.into(),
        }
    }
}

// ===== Conversions from biscuit-auth errors =====

impl From<biscuit_auth::error::Token> for TokenError {
    fn from(err: biscuit_auth::error::Token) -> Self {
        use biscuit_auth::error::{Logic, MatchedPolicy, Token};

        match err {
            Token::Format(format_err) => {
                use biscuit_auth::error::Format;
                match format_err {
                    Format::Signature(sig_err) => TokenError::InvalidSignature {
                        details: sig_err.to_string(),
                    },
                    Format::UnknownPublicKey => TokenError::UnknownPublicKey,
                    Format::DeserializationError(msg) | Format::BlockDeserializationError(msg) => {
                        TokenError::DeserializationError { reason: msg }
                    }
                    Format::SerializationError(msg) | Format::BlockSerializationError(msg) => {
                        TokenError::SerializationError { reason: msg }
                    }
                    Format::Version {
                        maximum,
                        minimum,
                        actual,
                    } => TokenError::UnsupportedVersion {
                        maximum,
                        minimum,
                        actual,
                    },
                    Format::InvalidKey(msg) => TokenError::InvalidKeyFormat { reason: msg },
                    other => TokenError::Generic(other.to_string()),
                }
            }
            Token::Base64(base64_err) => TokenError::Base64DecodingError {
                reason: base64_err.to_string(),
            },
            Token::FailedLogic(logic_err) => match logic_err {
                Logic::Unauthorized { policy, checks } => {
                    let failed_checks = convert_failed_checks(checks);
                    let (policy_type, policy_index) = match policy {
                        MatchedPolicy::Allow(idx) => ("Allow", idx),
                        MatchedPolicy::Deny(idx) => ("Deny", idx),
                    };
                    TokenError::PolicyMatchedButChecksFailed {
                        policy_type: policy_type.to_string(),
                        policy_index,
                        failed_checks,
                    }
                }
                Logic::NoMatchingPolicy { checks } => {
                    let failed_checks = convert_failed_checks(checks);
                    TokenError::NoMatchingPolicy { failed_checks }
                }
                Logic::InvalidBlockRule(block_id, rule) => {
                    TokenError::InvalidBlockRule { block_id, rule }
                }
                Logic::AuthorizerNotEmpty => {
                    TokenError::Internal("Authorizer already contains a token".to_string())
                }
            },
            Token::RunLimit(limit) => TokenError::ExecutionLimitReached {
                reason: limit.to_string(),
            },
            Token::Execution(expr) => TokenError::ExpressionError {
                reason: expr.to_string(),
            },
            Token::Language(lang_err) => TokenError::Generic(lang_err.to_string()),
            other => TokenError::Generic(other.to_string()),
        }
    }
}

/// Convert biscuit FailedCheck to our CheckFailure type
fn convert_failed_checks(checks: Vec<biscuit_auth::error::FailedCheck>) -> Vec<CheckFailure> {
    checks
        .into_iter()
        .map(|check| match check {
            biscuit_auth::error::FailedCheck::Block(block_check) => CheckFailure {
                block_id: Some(block_check.block_id),
                check_id: block_check.check_id,
                rule: block_check.rule,
            },
            biscuit_auth::error::FailedCheck::Authorizer(auth_check) => CheckFailure {
                block_id: None,
                check_id: auth_check.check_id,
                rule: auth_check.rule,
            },
        })
        .collect()
}

impl From<hex::FromHexError> for TokenError {
    fn from(err: hex::FromHexError) -> Self {
        TokenError::InvalidKeyFormat {
            reason: err.to_string(),
        }
    }
}

impl From<&str> for TokenError {
    fn from(err: &str) -> Self {
        TokenError::Generic(err.to_string())
    }
}

impl From<String> for TokenError {
    fn from(err: String) -> Self {
        TokenError::Generic(err)
    }
}
