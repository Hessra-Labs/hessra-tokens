extern crate biscuit_auth as biscuit;

use biscuit::macros::{authorizer, rule};
use chrono::Utc;
use hessra_token_core::{Biscuit, PublicKey, TokenError};

/// Result of inspecting a context token.
#[derive(Debug, Clone)]
pub struct ContextInspectResult {
    /// The subject (session owner) in the context token.
    pub subject: String,
    /// The exposure labels accumulated in the context token (issuer-attested).
    pub exposure_labels: Vec<String>,
    /// The exposure sources that contributed exposure labels (issuer-attested).
    pub exposure_sources: Vec<String>,
    /// Unix timestamp when the token expires (if extractable).
    pub expiry: Option<i64>,
    /// Whether the token is currently expired.
    pub is_expired: bool,
    /// Number of exposure blocks: every block past the authority block is
    /// an issuer exposure block under the third-party scheme.
    pub exposure_block_count: usize,
}

/// Inspects a context token to extract session and exposure information.
///
/// All exposure data is fetched via Datalog queries scoped with
/// `trusting authority, {public_key}`, so only facts attested by the issuer
/// surface here.
///
/// This is a diagnostic method. No authorization decision should flow from
/// inspect output -- use `ContextVerifier::excludes(...).verify()` for that.
pub fn inspect_context_token(
    token: String,
    public_key: PublicKey,
) -> Result<ContextInspectResult, TokenError> {
    let biscuit = Biscuit::from_base64(&token, public_key)?;
    let now = Utc::now().timestamp();

    let authz = authorizer!(
        r#"
            time({now});
            allow if true;
        "#
    );

    let mut authorizer = authz
        .build(&biscuit)
        .map_err(|e| TokenError::internal(format!("failed to build authorizer: {e}")))?;

    let subjects: Vec<(String,)> = authorizer
        .query("data($name) <- context($name)")
        .map_err(|e| TokenError::internal(format!("failed to query context subject: {e}")))?;
    let subject = subjects.first().map(|(s,)| s.clone()).unwrap_or_default();

    let pk = public_key;
    let label_results: Vec<(String,)> = authorizer
        .query_all(rule!(
            r#"data($l) <- exposure($l) trusting authority, {pk}"#
        ))
        .map_err(|e| TokenError::internal(format!("failed to query exposure labels: {e}")))?;

    let mut exposure_labels: Vec<String> = Vec::new();
    for (label,) in label_results {
        if !exposure_labels.contains(&label) {
            exposure_labels.push(label);
        }
    }

    let source_results: Vec<(String,)> = authorizer
        .query_all(rule!(
            r#"data($s) <- exposure_source($s) trusting authority, {pk}"#
        ))
        .map_err(|e| TokenError::internal(format!("failed to query exposure sources: {e}")))?;

    let mut exposure_sources: Vec<String> = Vec::new();
    for (source,) in source_results {
        if !exposure_sources.contains(&source) {
            exposure_sources.push(source);
        }
    }

    // Under the third-party scheme, every block past the authority block is
    // an exposure block. (Initial exposures, if any, live in the authority
    // block itself and are not counted here.)
    let block_count = biscuit.block_count();
    let exposure_block_count = block_count.saturating_sub(1);

    let token_content = biscuit.print();
    let expiry = extract_expiry_from_content(&token_content);
    let is_expired = expiry.is_some_and(|exp| exp < now);

    Ok(ContextInspectResult {
        subject,
        exposure_labels,
        exposure_sources,
        expiry,
        is_expired,
        exposure_block_count,
    })
}

/// Extracts expiry timestamp from token content.
fn extract_expiry_from_content(content: &str) -> Option<i64> {
    let mut earliest_expiry: Option<i64> = None;

    for line in content.lines() {
        if line.contains("check if")
            && line.contains("time")
            && line.contains("<")
            && let Some(pos) = line.find("$time <")
        {
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

    earliest_expiry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure::add_exposure;
    use crate::mint::HessraContext;
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
        assert!(result.exposure_labels.is_empty());
        assert!(result.exposure_sources.is_empty());
        assert!(!result.is_expired);
        assert!(result.expiry.is_some());
        assert_eq!(result.exposure_block_count, 0);
    }

    #[test]
    fn test_inspect_exposed_context() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            &keypair,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add exposure");

        let result =
            inspect_context_token(exposed, public_key).expect("Failed to inspect exposed context");

        assert_eq!(result.subject, "agent:openclaw");
        assert_eq!(result.exposure_labels, vec!["PII:SSN".to_string()]);
        assert_eq!(result.exposure_sources, vec!["data:user-ssn".to_string()]);
        assert_eq!(result.exposure_block_count, 1);
    }

    #[test]
    fn test_inspect_multi_exposed_context() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            &keypair,
            &["PII:email".to_string(), "PII:address".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add profile exposure");

        let more_exposed = add_exposure(
            &exposed,
            &keypair,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add SSN exposure");

        let result = inspect_context_token(more_exposed, public_key)
            .expect("Failed to inspect multi-exposed context");

        assert_eq!(result.subject, "agent:openclaw");
        assert_eq!(result.exposure_labels.len(), 3);
        assert!(result.exposure_labels.contains(&"PII:email".to_string()));
        assert!(result.exposure_labels.contains(&"PII:address".to_string()));
        assert!(result.exposure_labels.contains(&"PII:SSN".to_string()));
        assert_eq!(result.exposure_sources.len(), 2);
        assert_eq!(result.exposure_block_count, 2);
    }

    #[test]
    fn test_inspect_initial_exposures_in_authority_block() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
            .with_initial_exposures(
                &["PII:email".to_string(), "PII:address".to_string()],
                "data:user-profile",
            )
            .issue(&keypair)
            .expect("Failed to create context token");

        let result = inspect_context_token(token, public_key)
            .expect("Failed to inspect token with initial exposures");

        assert_eq!(result.subject, "agent:openclaw");
        assert_eq!(result.exposure_labels.len(), 2);
        assert!(result.exposure_labels.contains(&"PII:email".to_string()));
        assert!(result.exposure_labels.contains(&"PII:address".to_string()));
        assert_eq!(
            result.exposure_sources,
            vec!["data:user-profile".to_string()]
        );
        // Initial exposures live in the authority block; no third-party blocks added.
        assert_eq!(result.exposure_block_count, 0);
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
