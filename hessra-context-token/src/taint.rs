//! Taint tracking operations for context tokens.
//!
//! Taint labels are added as append-only Biscuit blocks. Each block contains
//! `taint({label})` facts. Labels accumulate and cannot be removed.

extern crate biscuit_auth as biscuit;

use biscuit::Biscuit;
use biscuit::macros::block;
use chrono::Utc;
use hessra_token_core::{KeyPair, PublicKey, TokenError};
use std::error::Error;

/// Add taint labels to a context token.
///
/// Creates a new Biscuit block containing `taint({label})` facts for each
/// provided label, and `taint_source({source})` identifying where the taint
/// came from.
///
/// This operation is append-only: the resulting token has strictly more taint
/// than the input token.
///
/// # Arguments
/// * `token` - The base64-encoded context token
/// * `public_key` - The public key used to verify the token signature
/// * `labels` - The taint labels to add (e.g., `["PII:SSN", "PII:email"]`)
/// * `source` - The data source that produced the taint (e.g., `"data:user-ssn"`)
///
/// # Returns
/// Updated base64-encoded context token with taint labels appended
pub fn add_taint(
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

    // Build a block with taint facts
    let mut block_builder = block!(
        r#"
            taint_source({source});
            taint_time({now});
        "#
    );

    for label in labels {
        let label_str = label.clone();
        block_builder = block_builder.fact(biscuit::macros::fact!(r#"taint({label_str});"#))?;
    }

    let new_biscuit = biscuit.append(block_builder)?;
    let new_token = new_biscuit.to_base64()?;

    Ok(new_token)
}

/// Extract all taint labels from a context token by parsing its Biscuit blocks.
///
/// Iterates through all blocks in the token looking for `taint("label")` facts
/// and returns the deduplicated set of labels.
///
/// # Arguments
/// * `token` - The base64-encoded context token
/// * `public_key` - The public key used to verify the token signature
///
/// # Returns
/// Deduplicated list of taint label strings
pub fn extract_taint_labels(token: &str, public_key: PublicKey) -> Result<Vec<String>, TokenError> {
    let biscuit = Biscuit::from_base64(token, public_key)?;

    let mut labels = Vec::new();

    // Iterate through all blocks looking for taint facts
    let block_count = biscuit.block_count();
    for i in 0..block_count {
        let block_source = biscuit.print_block_source(i).unwrap_or_default();
        // Parse taint facts from block source: lines like `taint("PII:SSN");`
        for line in block_source.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("taint(") {
                if let Some(label_str) = rest.strip_suffix(");") {
                    // Remove quotes
                    let label = label_str.trim_matches('"').to_string();
                    if !labels.contains(&label) {
                        labels.push(label);
                    }
                }
            }
        }
    }

    Ok(labels)
}

/// Fork a context token for a sub-agent, inheriting the parent's taint.
///
/// Creates a fresh context token for the child subject, pre-populated with
/// all of the parent's taint labels. This prevents contamination laundering
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
/// Base64-encoded child context token with inherited taint
pub fn fork_context(
    parent_token: &str,
    parent_public_key: PublicKey,
    child_subject: String,
    time_config: hessra_token_core::TokenTimeConfig,
    keypair: &KeyPair,
) -> Result<String, Box<dyn Error>> {
    // Extract parent's taint labels
    let parent_labels = extract_taint_labels(parent_token, parent_public_key)?;

    // Create a fresh context for the child
    let child_token =
        crate::mint::HessraContext::new(child_subject, time_config).issue(keypair)?;

    // If parent has no taint, just return the fresh child context
    if parent_labels.is_empty() {
        return Ok(child_token);
    }

    // Apply all parent taint labels to the child
    add_taint(
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
    fn test_add_taint_labels() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        // No taint initially
        let labels = extract_taint_labels(&token, public_key).expect("Failed to extract labels");
        assert!(labels.is_empty());

        // Add taint
        let tainted = add_taint(
            &token,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add taint");

        let labels =
            extract_taint_labels(&tainted, public_key).expect("Failed to extract labels");
        assert_eq!(labels, vec!["PII:SSN".to_string()]);
    }

    #[test]
    fn test_add_empty_taint_is_noop() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let result = add_taint(&token, public_key, &[], "source".to_string())
            .expect("Failed with empty taint");

        assert_eq!(result, token);
    }

    #[test]
    fn test_multiple_taint_labels() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let tainted = add_taint(
            &token,
            public_key,
            &["PII:email".to_string(), "PII:address".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add taint");

        let labels =
            extract_taint_labels(&tainted, public_key).expect("Failed to extract labels");
        assert_eq!(labels.len(), 2);
        assert!(labels.contains(&"PII:email".to_string()));
        assert!(labels.contains(&"PII:address".to_string()));
    }

    #[test]
    fn test_cumulative_taint() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        // First taint
        let tainted = add_taint(
            &token,
            public_key,
            &["PII:email".to_string(), "PII:address".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add first taint");

        // Second taint
        let more_tainted = add_taint(
            &tainted,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add second taint");

        let labels =
            extract_taint_labels(&more_tainted, public_key).expect("Failed to extract labels");
        assert_eq!(labels.len(), 3);
        assert!(labels.contains(&"PII:email".to_string()));
        assert!(labels.contains(&"PII:address".to_string()));
        assert!(labels.contains(&"PII:SSN".to_string()));
    }

    #[test]
    fn test_duplicate_taint_labels_deduplicated() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let tainted = add_taint(
            &token,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add first taint");

        // Add same label again
        let double_tainted = add_taint(
            &tainted,
            public_key,
            &["PII:SSN".to_string()],
            "another-source".to_string(),
        )
        .expect("Failed to add duplicate taint");

        let labels =
            extract_taint_labels(&double_tainted, public_key).expect("Failed to extract labels");
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0], "PII:SSN");
    }

    #[test]
    fn test_fork_context_inherits_taint() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let parent = HessraContext::new("agent:parent".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create parent context");

        // Taint the parent
        let tainted_parent = add_taint(
            &parent,
            public_key,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add taint to parent");

        // Fork for child
        let child = fork_context(
            &tainted_parent,
            public_key,
            "agent:parent:child".to_string(),
            TokenTimeConfig::default(),
            &keypair,
        )
        .expect("Failed to fork context");

        // Child should inherit parent's taint
        let child_labels =
            extract_taint_labels(&child, public_key).expect("Failed to extract child labels");
        assert_eq!(child_labels, vec!["PII:SSN".to_string()]);
    }

    #[test]
    fn test_fork_clean_context() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let parent = HessraContext::new("agent:parent".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create parent context");

        // Fork without any taint on parent
        let child = fork_context(
            &parent,
            public_key,
            "agent:parent:child".to_string(),
            TokenTimeConfig::default(),
            &keypair,
        )
        .expect("Failed to fork context");

        let child_labels =
            extract_taint_labels(&child, public_key).expect("Failed to extract child labels");
        assert!(child_labels.is_empty());
    }

    #[test]
    fn test_fork_inherits_multiple_taint_labels() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let parent = HessraContext::new("agent:parent".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create parent context");

        // Add multiple taint labels
        let tainted = add_taint(
            &parent,
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

        // Fork
        let child = fork_context(
            &more_tainted,
            public_key,
            "agent:parent:child".to_string(),
            TokenTimeConfig::default(),
            &keypair,
        )
        .expect("Failed to fork context");

        let child_labels =
            extract_taint_labels(&child, public_key).expect("Failed to extract child labels");
        assert_eq!(child_labels.len(), 3);
        assert!(child_labels.contains(&"PII:email".to_string()));
        assert!(child_labels.contains(&"PII:address".to_string()));
        assert!(child_labels.contains(&"PII:SSN".to_string()));
    }
}
