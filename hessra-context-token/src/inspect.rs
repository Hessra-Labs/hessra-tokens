extern crate biscuit_auth as biscuit;

use biscuit::macros::authorizer;
use chrono::Utc;
use hessra_token_core::{Biscuit, PublicKey, TokenError};

/// Result of inspecting a context token.
#[derive(Debug, Clone)]
pub struct ContextInspectResult {
    /// The subject (session owner) in the context token.
    pub subject: String,
    /// The taint labels accumulated in the context token.
    pub taint_labels: Vec<String>,
    /// The taint sources that contributed taint labels.
    pub taint_sources: Vec<String>,
    /// Unix timestamp when the token expires (if extractable).
    pub expiry: Option<i64>,
    /// Whether the token is currently expired.
    pub is_expired: bool,
    /// Number of taint blocks appended to the token.
    pub taint_block_count: usize,
}

/// Inspects a context token to extract session and taint information.
///
/// This performs signature verification but does not enforce time checks,
/// so expired tokens can still be inspected.
///
/// # Arguments
/// * `token` - The base64-encoded context token
/// * `public_key` - The public key used to verify the token signature
///
/// # Returns
/// Inspection result with subject, taint labels, sources, and expiry info
pub fn inspect_context_token(
    token: String,
    public_key: PublicKey,
) -> Result<ContextInspectResult, TokenError> {
    let biscuit = Biscuit::from_base64(&token, public_key)?;
    let now = Utc::now().timestamp();

    // Extract the subject from the authority block via an authorizer query
    let authorizer = authorizer!(
        r#"
            time({now});
            allow if true;
        "#
    );

    let mut authorizer = authorizer
        .build(&biscuit)
        .map_err(|e| TokenError::internal(format!("failed to build authorizer: {e}")))?;

    let subjects: Vec<(String,)> = authorizer
        .query("data($name) <- context($name)")
        .map_err(|e| TokenError::internal(format!("failed to query context subject: {e}")))?;

    let subject = subjects
        .first()
        .map(|(s,)| s.clone())
        .unwrap_or_default();

    // Extract taint labels and sources from block source strings
    let mut taint_labels = Vec::new();
    let mut taint_sources = Vec::new();
    let mut taint_block_count = 0;

    let block_count = biscuit.block_count();
    for i in 0..block_count {
        let block_source = biscuit.print_block_source(i).unwrap_or_default();
        let mut block_has_taint = false;

        for line in block_source.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("taint(") {
                if let Some(label_str) = rest.strip_suffix(");") {
                    let label = label_str.trim_matches('"').to_string();
                    if !taint_labels.contains(&label) {
                        taint_labels.push(label);
                    }
                    block_has_taint = true;
                }
            }
            if let Some(rest) = trimmed.strip_prefix("taint_source(") {
                if let Some(source_str) = rest.strip_suffix(");") {
                    let source = source_str.trim_matches('"').to_string();
                    if !taint_sources.contains(&source) {
                        taint_sources.push(source);
                    }
                }
            }
        }

        if block_has_taint {
            taint_block_count += 1;
        }
    }

    // Extract expiry from token content
    let token_content = biscuit.print();
    let expiry = extract_expiry_from_content(&token_content);
    let is_expired = expiry.is_some_and(|exp| exp < now);

    Ok(ContextInspectResult {
        subject,
        taint_labels,
        taint_sources,
        expiry,
        is_expired,
        taint_block_count,
    })
}

/// Extracts expiry timestamp from token content.
fn extract_expiry_from_content(content: &str) -> Option<i64> {
    let mut earliest_expiry: Option<i64> = None;

    for line in content.lines() {
        if line.contains("check if") && line.contains("time") && line.contains("<") {
            if let Some(pos) = line.find("$time <") {
                let after_lt = &line[pos + 8..].trim();
                let number_str = after_lt
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '-')
                    .collect::<String>();

                if let Ok(timestamp) = number_str.parse::<i64>() {
                    earliest_expiry = Some(earliest_expiry.map_or(timestamp, |e| e.min(timestamp)));
                }
            }
        }
    }

    earliest_expiry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::HessraContext;
    use crate::taint::add_taint;
    use hessra_token_core::{KeyPair, TokenTimeConfig};

    #[test]
    fn test_inspect_fresh_context() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let result =
            inspect_context_token(token, public_key).expect("Failed to inspect context token");

        assert_eq!(result.subject, "agent:openclaw");
        assert!(result.taint_labels.is_empty());
        assert!(result.taint_sources.is_empty());
        assert!(!result.is_expired);
        assert!(result.expiry.is_some());
        assert_eq!(result.taint_block_count, 0);
    }

    #[test]
    fn test_inspect_tainted_context() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let tainted = add_taint(
            &token,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add taint");

        let result =
            inspect_context_token(tainted, public_key).expect("Failed to inspect tainted context");

        assert_eq!(result.subject, "agent:openclaw");
        assert_eq!(result.taint_labels, vec!["PII:SSN".to_string()]);
        assert_eq!(result.taint_sources, vec!["data:user-ssn".to_string()]);
        assert_eq!(result.taint_block_count, 1);
    }

    #[test]
    fn test_inspect_multi_tainted_context() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let tainted = add_taint(
            &token,
            public_key,
            &["PII:email".to_string(), "PII:address".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add profile taint");

        let more_tainted = add_taint(
            &tainted,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add SSN taint");

        let result = inspect_context_token(more_tainted, public_key)
            .expect("Failed to inspect multi-tainted context");

        assert_eq!(result.subject, "agent:openclaw");
        assert_eq!(result.taint_labels.len(), 3);
        assert!(result.taint_labels.contains(&"PII:email".to_string()));
        assert!(result.taint_labels.contains(&"PII:address".to_string()));
        assert!(result.taint_labels.contains(&"PII:SSN".to_string()));
        assert_eq!(result.taint_sources.len(), 2);
        assert_eq!(result.taint_block_count, 2);
    }

    #[test]
    fn test_inspect_expired_context() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let expired_config = TokenTimeConfig {
            start_time: Some(0),
            duration: 1,
        };

        let token = HessraContext::new("agent:test".to_string(), expired_config)
            .issue(&keypair)
            .expect("Failed to create expired context token");

        let result = inspect_context_token(token, public_key)
            .expect("Should be able to inspect expired token");

        assert_eq!(result.subject, "agent:test");
        assert!(result.is_expired);
        assert_eq!(result.expiry, Some(1));
    }
}
