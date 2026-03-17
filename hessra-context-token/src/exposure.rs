//! Exposure tracking operations for context tokens.
//!
//! Exposure labels are added as append-only Biscuit blocks. Each block contains
//! `exposure({label})` facts. Labels accumulate and cannot be removed.

extern crate biscuit_auth as biscuit;

use biscuit::Biscuit;
use biscuit::macros::block;
use chrono::Utc;
use hessra_token_core::{KeyPair, PublicKey, TokenError};
use std::error::Error;

/// Add exposure labels to a context token.
///
/// Creates a new Biscuit block containing `exposure({label})` facts for each
/// provided label, and `exposure_source({source})` identifying where the exposure
/// came from.
///
/// This operation is append-only: the resulting token has strictly more exposure
/// than the input token.
///
/// # Arguments
/// * `token` - The base64-encoded context token
/// * `public_key` - The public key used to verify the token signature
/// * `labels` - The exposure labels to add (e.g., `["PII:SSN", "PII:email"]`)
/// * `source` - The data source that produced the exposure (e.g., `"data:user-ssn"`)
///
/// # Returns
/// Updated base64-encoded context token with exposure labels appended
pub fn add_exposure(
    token: &str,
    public_key: PublicKey,
    labels: &[String],
    source: String,
) -> Result<String, Box<dyn Error>> {
    if labels.is_empty() {
        return Ok(token.to_string());
    }

    let biscuit = Biscuit::from_base64(token, public_key)?;

    let now = Utc::now().timestamp();

    // Build a block with exposure facts
    let mut block_builder = block!(
        r#"
            exposure_source({source});
            exposure_time({now});
        "#
    );

    for label in labels {
        let label_str = label.clone();
        block_builder = block_builder.fact(biscuit::macros::fact!(r#"exposure({label_str});"#))?;
    }

    let new_biscuit = biscuit.append(block_builder)?;
    let new_token = new_biscuit.to_base64()?;

    Ok(new_token)
}

/// Extract all exposure labels from a context token by parsing its Biscuit blocks.
///
/// Iterates through all blocks in the token looking for `exposure("label")` facts
/// and returns the deduplicated set of labels.
///
/// This is a diagnostic/inspection method. For authorization decisions, use
/// `ContextVerifier::check_precluded_exposures` instead, which delegates to the
/// Biscuit authorization engine.
///
/// # Arguments
/// * `token` - The base64-encoded context token
/// * `public_key` - The public key used to verify the token signature
///
/// # Returns
/// Deduplicated list of exposure label strings
pub fn extract_exposure_labels(
    token: &str,
    public_key: PublicKey,
) -> Result<Vec<String>, TokenError> {
    let biscuit = Biscuit::from_base64(token, public_key)?;

    let mut labels = Vec::new();

    // Iterate through all blocks looking for exposure facts
    let block_count = biscuit.block_count();
    for i in 0..block_count {
        let block_source = biscuit.print_block_source(i).unwrap_or_default();
        // Parse exposure facts from block source: lines like `exposure("PII:SSN");`
        for line in block_source.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("exposure(")
                && let Some(label_str) = rest.strip_suffix(");")
            {
                // Remove quotes
                let label = label_str.trim_matches('"').to_string();
                if !labels.contains(&label) {
                    labels.push(label);
                }
            }
        }
    }

    Ok(labels)
}

/// Fork a context token for a sub-agent, inheriting the parent's exposure.
///
/// Creates a fresh context token for the child subject, pre-populated with
/// all of the parent's exposure labels. This prevents contamination laundering
/// through delegation.
///
/// # Arguments
/// * `parent_token` - The base64-encoded parent context token
/// * `parent_public_key` - The public key used to verify the parent token
/// * `child_subject` - The child subject identifier (e.g., "agent:openclaw:subtask-1")
/// * `time_config` - Time configuration for the child context token
/// * `keypair` - The keypair to sign the child token with
///
/// # Returns
/// Base64-encoded child context token with inherited exposure
pub fn fork_context(
    parent_token: &str,
    parent_public_key: PublicKey,
    child_subject: String,
    time_config: hessra_token_core::TokenTimeConfig,
    keypair: &KeyPair,
) -> Result<String, Box<dyn Error>> {
    // Extract parent's exposure labels
    let parent_labels = extract_exposure_labels(parent_token, parent_public_key)?;

    // Create a fresh context for the child
    let child_token = crate::mint::HessraContext::new(child_subject, time_config).issue(keypair)?;

    // If parent has no exposure, just return the fresh child context
    if parent_labels.is_empty() {
        return Ok(child_token);
    }

    // Apply all parent exposure labels to the child
    add_exposure(
        &child_token,
        keypair.public(),
        &parent_labels,
        "inherited".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::HessraContext;
    use hessra_token_core::TokenTimeConfig;

    #[test]
    fn test_add_exposure_labels() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        // No exposure initially
        let labels = extract_exposure_labels(&token, public_key).expect("Failed to extract labels");
        assert!(labels.is_empty());

        // Add exposure
        let exposed = add_exposure(
            &token,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add exposure");

        let labels =
            extract_exposure_labels(&exposed, public_key).expect("Failed to extract labels");
        assert_eq!(labels, vec!["PII:SSN".to_string()]);
    }

    #[test]
    fn test_add_empty_exposure_is_noop() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let result = add_exposure(&token, public_key, &[], "source".to_string())
            .expect("Failed with empty exposure");

        assert_eq!(result, token);
    }

    #[test]
    fn test_multiple_exposure_labels() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            public_key,
            &["PII:email".to_string(), "PII:address".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add exposure");

        let labels =
            extract_exposure_labels(&exposed, public_key).expect("Failed to extract labels");
        assert_eq!(labels.len(), 2);
        assert!(labels.contains(&"PII:email".to_string()));
        assert!(labels.contains(&"PII:address".to_string()));
    }

    #[test]
    fn test_cumulative_exposure() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        // First exposure
        let exposed = add_exposure(
            &token,
            public_key,
            &["PII:email".to_string(), "PII:address".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add first exposure");

        // Second exposure
        let more_exposed = add_exposure(
            &exposed,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add second exposure");

        let labels =
            extract_exposure_labels(&more_exposed, public_key).expect("Failed to extract labels");
        assert_eq!(labels.len(), 3);
        assert!(labels.contains(&"PII:email".to_string()));
        assert!(labels.contains(&"PII:address".to_string()));
        assert!(labels.contains(&"PII:SSN".to_string()));
    }

    #[test]
    fn test_duplicate_exposure_labels_deduplicated() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add first exposure");

        // Add same label again
        let double_exposed = add_exposure(
            &exposed,
            public_key,
            &["PII:SSN".to_string()],
            "another-source".to_string(),
        )
        .expect("Failed to add duplicate exposure");

        let labels =
            extract_exposure_labels(&double_exposed, public_key).expect("Failed to extract labels");
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], "PII:SSN");
    }

    #[test]
    fn test_fork_context_inherits_exposure() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let parent = HessraContext::new("agent:parent".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create parent context");

        // Expose the parent
        let exposed_parent = add_exposure(
            &parent,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add exposure to parent");

        // Fork for child
        let child = fork_context(
            &exposed_parent,
            public_key,
            "agent:parent:child".to_string(),
            TokenTimeConfig::default(),
            &keypair,
        )
        .expect("Failed to fork context");

        // Child should inherit parent's exposure
        let child_labels =
            extract_exposure_labels(&child, public_key).expect("Failed to extract child labels");
        assert_eq!(child_labels, vec!["PII:SSN".to_string()]);
    }

    #[test]
    fn test_fork_clean_context() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let parent = HessraContext::new("agent:parent".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create parent context");

        // Fork without any exposure on parent
        let child = fork_context(
            &parent,
            public_key,
            "agent:parent:child".to_string(),
            TokenTimeConfig::default(),
            &keypair,
        )
        .expect("Failed to fork context");

        let child_labels =
            extract_exposure_labels(&child, public_key).expect("Failed to extract child labels");
        assert!(child_labels.is_empty());
    }

    #[test]
    fn test_fork_inherits_multiple_exposure_labels() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let parent = HessraContext::new("agent:parent".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create parent context");

        // Add multiple exposure labels
        let exposed = add_exposure(
            &parent,
            public_key,
            &["PII:email".to_string(), "PII:address".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add profile exposure");

        let more_exposed = add_exposure(
            &exposed,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add SSN exposure");

        // Fork
        let child = fork_context(
            &more_exposed,
            public_key,
            "agent:parent:child".to_string(),
            TokenTimeConfig::default(),
            &keypair,
        )
        .expect("Failed to fork context");

        let child_labels =
            extract_exposure_labels(&child, public_key).expect("Failed to extract child labels");
        assert_eq!(child_labels.len(), 3);
        assert!(child_labels.contains(&"PII:email".to_string()));
        assert!(child_labels.contains(&"PII:address".to_string()));
        assert!(child_labels.contains(&"PII:SSN".to_string()));
    }
}
