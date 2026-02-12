/// Utilities for parsing Datalog rules from biscuit token verification failures
/// to extract semantic information for better error messages.
use crate::error::TokenError;
use regex::Regex;
use std::sync::OnceLock;

/// Parse a failed check to extract specific error information
pub fn parse_check_failure(block_id: u32, check_id: u32, rule: &str) -> TokenError {
    // Try parsing as expiration check
    if let Some(error) = try_parse_expiration(block_id, check_id, rule) {
        return error;
    }

    // Try parsing as domain check
    if let Some(error) = try_parse_domain(block_id, check_id, rule) {
        return error;
    }

    // Try parsing as identity check
    if let Some(error) = try_parse_identity(block_id, check_id, rule) {
        return error;
    }

    // Try parsing as hierarchy check
    if let Some(error) = try_parse_hierarchy(block_id, check_id, rule) {
        return error;
    }

    // Fallback to generic check failed
    TokenError::CheckFailed {
        block_id,
        check_id,
        rule: rule.to_string(),
    }
}

/// Try to parse an expiration check failure
/// Pattern: "check if time($time), $time < TIMESTAMP"
fn try_parse_expiration(block_id: u32, check_id: u32, rule: &str) -> Option<TokenError> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"check if time\(\$\w+\), \$\w+ < (\d+)").unwrap());

    if let Some(captures) = re.captures(rule) {
        if let Some(timestamp_str) = captures.get(1) {
            if let Ok(expired_at) = timestamp_str.as_str().parse::<i64>() {
                // We don't have the current time from the rule, so we'll use a placeholder
                // The actual current time will be filled in by the verification logic
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);

                return Some(TokenError::Expired {
                    expired_at,
                    current_time,
                    block_id,
                    check_id,
                });
            }
        }
    }

    None
}

/// Try to parse a domain check failure
/// Pattern: "check if domain("example.com")"
fn try_parse_domain(block_id: u32, check_id: u32, rule: &str) -> Option<TokenError> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"check if domain\("([^"]+)"\)"#).unwrap());

    if let Some(captures) = re.captures(rule) {
        if let Some(domain_match) = captures.get(1) {
            let expected = domain_match.as_str().to_string();
            return Some(TokenError::DomainMismatch {
                expected,
                provided: None,
                block_id,
                check_id,
            });
        }
    }

    None
}

/// Try to parse an identity check failure
/// Pattern: "check if actor($a), $a == "identity""
fn try_parse_identity(_block_id: u32, _check_id: u32, rule: &str) -> Option<TokenError> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re =
        RE.get_or_init(|| Regex::new(r#"check if actor\(\$\w+\), \$\w+ == "([^"]+)""#).unwrap());

    if let Some(captures) = re.captures(rule) {
        if let Some(identity_match) = captures.get(1) {
            let expected = identity_match.as_str().to_string();
            // We don't know the actual identity from the rule alone
            // This will be filled in by the verification logic
            return Some(TokenError::IdentityMismatch {
                expected,
                actual: "<unknown>".to_string(),
            });
        }
    }

    None
}

/// Try to parse a hierarchy check failure
/// Pattern: "check if actor($a), $a == "base" || $a.starts_with("base:")"
fn try_parse_hierarchy(block_id: u32, check_id: u32, rule: &str) -> Option<TokenError> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r#"check if actor\(\$\w+\), \$\w+ == "([^"]+)" \|\| \$\w+\.starts_with\("([^"]+):"\)"#,
        )
        .unwrap()
    });

    if let Some(captures) = re.captures(rule) {
        if let Some(base_identity_match) = captures.get(1) {
            let expected = base_identity_match.as_str().to_string();
            let delegatable = rule.contains("starts_with");

            return Some(TokenError::HierarchyViolation {
                expected,
                actual: "<unknown>".to_string(),
                delegatable,
                block_id,
                check_id,
            });
        }
    }

    None
}

/// Parse capability check failures from the policy/facts
pub fn parse_capability_failure(
    subject: Option<&str>,
    resource: Option<&str>,
    operation: Option<&str>,
    rule: &str,
) -> TokenError {
    // Try to extract subject, resource, operation from the rule if not provided
    let (parsed_subject, parsed_resource, parsed_operation) = parse_authz_from_rule(rule);

    let subject = subject.or(parsed_subject.as_deref());
    let resource = resource
        .or(parsed_resource.as_deref())
        .unwrap_or("<unknown>");
    let operation = operation
        .or(parsed_operation.as_deref())
        .unwrap_or("<unknown>");

    TokenError::RightsDenied {
        subject: subject.map(|s| s.to_string()),
        resource: resource.to_string(),
        operation: operation.to_string(),
    }
}

/// Try to extract subject, resource, operation from authorization rule
/// Pattern: "allow if subject($sub), resource($res), operation($op), right($sub, $res, $op)"
fn parse_authz_from_rule(rule: &str) -> (Option<String>, Option<String>, Option<String>) {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r#"right\("([^"]+)", "([^"]+)", "([^"]+)"\)"#).unwrap());

    if let Some(captures) = re.captures(rule) {
        let subject = captures.get(1).map(|m| m.as_str().to_string());
        let resource = captures.get(2).map(|m| m.as_str().to_string());
        let operation = captures.get(3).map(|m| m.as_str().to_string());
        return (subject, resource, operation);
    }

    (None, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_expiration() {
        let rule = "check if time($time), $time < 1735689600";
        let error = try_parse_expiration(0, 0, rule);

        assert!(error.is_some());
        if let Some(TokenError::Expired { expired_at, .. }) = error {
            assert_eq!(expired_at, 1735689600);
        } else {
            panic!("Expected Expired error");
        }
    }

    #[test]
    fn test_parse_domain() {
        let rule = r#"check if domain("example.com")"#;
        let error = try_parse_domain(0, 0, rule);

        assert!(error.is_some());
        if let Some(TokenError::DomainMismatch { expected, .. }) = error {
            assert_eq!(expected, "example.com");
        } else {
            panic!("Expected DomainMismatch error");
        }
    }

    #[test]
    fn test_parse_identity() {
        let rule = r#"check if actor($a), $a == "user@example.com""#;
        let error = try_parse_identity(0, 0, rule);

        assert!(error.is_some());
        if let Some(TokenError::IdentityMismatch { expected, .. }) = error {
            assert_eq!(expected, "user@example.com");
        } else {
            panic!("Expected IdentityMismatch error");
        }
    }

    #[test]
    fn test_parse_hierarchy() {
        let rule = r#"check if actor($a), $a == "base" || $a.starts_with("base:")"#;
        let error = try_parse_hierarchy(0, 0, rule);

        assert!(error.is_some());
        if let Some(TokenError::HierarchyViolation {
            expected,
            delegatable,
            ..
        }) = error
        {
            assert_eq!(expected, "base");
            assert!(delegatable);
        } else {
            panic!("Expected HierarchyViolation error");
        }
    }

    #[test]
    fn test_parse_authz_from_rule() {
        let rule = r#"allow if subject($sub), resource($res), operation($op), right("user@example.com", "/api/data", "read")"#;
        let (subject, resource, operation) = parse_authz_from_rule(rule);

        assert_eq!(subject, Some("user@example.com".to_string()));
        assert_eq!(resource, Some("/api/data".to_string()));
        assert_eq!(operation, Some("read".to_string()));
    }

    #[test]
    fn test_parse_check_failure_expiration() {
        let rule = "check if time($time), $time < 1735689600";
        let error = parse_check_failure(0, 0, rule);

        assert!(matches!(error, TokenError::Expired { .. }));
    }

    #[test]
    fn test_parse_check_failure_domain() {
        let rule = r#"check if domain("example.com")"#;
        let error = parse_check_failure(0, 0, rule);

        assert!(matches!(error, TokenError::DomainMismatch { .. }));
    }

    #[test]
    fn test_parse_check_failure_unknown() {
        let rule = "check if some_unknown_check()";
        let error = parse_check_failure(0, 0, rule);

        assert!(matches!(error, TokenError::CheckFailed { .. }));
    }
}
