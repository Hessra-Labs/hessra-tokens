//! Exposure tracking operations for context tokens.
//!
//! Each `add_exposure` call appends a third-party block signed by the issuer's
//! keypair. All labels passed in a single call land in the same block as sibling
//! `exposure({label})` facts (one block per logical exposure event). The
//! `trusting authority, {pubkey}` scope on verifier rules and queries pins
//! exposure facts to the issuer, so only issuer-attested labels participate
//! in authorization or extraction.

extern crate biscuit_auth as biscuit;

use biscuit::Biscuit;
use biscuit::macros::{block, fact, rule};
use chrono::Utc;
use hessra_token_core::{KeyPair, PublicKey, TokenError};
use std::error::Error;

/// Append a batch of exposure labels to a context token in one third-party block.
///
/// The new block is signed by `keypair` (the issuer's keypair) so that verifiers
/// scoped with `trusting authority, {pubkey}` see these facts. All `labels` from
/// this single call land in the same block alongside a single `exposure_source`
/// and `exposure_time` fact.
///
/// # Arguments
/// * `token` - The base64-encoded context token
/// * `keypair` - The issuer's keypair (signs the new block; public key verifies the input)
/// * `labels` - The exposure labels to add (stacked into one block)
/// * `source` - The data source that produced the exposure (e.g., `"data:user-ssn"`)
///
/// # Returns
/// Updated base64-encoded context token with one new third-party block appended.
pub fn add_exposure(
    token: &str,
    keypair: &KeyPair,
    labels: &[String],
    source: String,
) -> Result<String, Box<dyn Error>> {
    if labels.is_empty() {
        return Ok(token.to_string());
    }

    let public_key = keypair.public();
    let biscuit = Biscuit::from_base64(token, public_key)?;

    let now = Utc::now().timestamp();

    let mut block_builder = block!(
        r#"
            exposure_source({source});
            exposure_time({now});
        "#
    );

    for label in labels {
        let label = label.clone();
        block_builder = block_builder.fact(fact!(r#"exposure({label});"#))?;
    }

    let third_party_request = biscuit.third_party_request()?;
    let third_party_block = third_party_request.create_block(&keypair.private(), block_builder)?;
    let new_biscuit = biscuit.append_third_party(public_key, third_party_block)?;
    let new_token = new_biscuit.to_base64()?;

    Ok(new_token)
}

/// Extract all exposure labels attested by the issuer from a context token.
///
/// Runs a Datalog query scoped to `trusting authority, {public_key}`, which
/// matches `exposure(...)` facts in the authority block and in third-party
/// blocks signed by `public_key`. Facts from other origins are filtered out.
///
/// This is a diagnostic/inspection method. For authorization decisions, build
/// a `ContextVerifier` and chain `.excludes(...).verify()` instead.
///
/// # Arguments
/// * `token` - The base64-encoded context token
/// * `public_key` - The public key used to verify the token signature and to scope the query
///
/// # Returns
/// Deduplicated list of exposure label strings.
pub fn extract_exposure_labels(
    token: &str,
    public_key: PublicKey,
) -> Result<Vec<String>, TokenError> {
    let biscuit = Biscuit::from_base64(token, public_key)?;
    let now = Utc::now().timestamp();

    let authz = biscuit::macros::authorizer!(
        r#"
            time({now});
        "#
    );

    let mut authorizer = authz
        .build(&biscuit)
        .map_err(|e| TokenError::internal(format!("failed to build authorizer: {e}")))?;

    let pk = public_key;
    let results: Vec<(String,)> = authorizer
        .query_all(rule!(
            r#"data($l) <- exposure($l) trusting authority, {pk}"#
        ))
        .map_err(|e| TokenError::internal(format!("failed to query exposure labels: {e}")))?;

    let mut labels: Vec<String> = Vec::new();
    for (label,) in results {
        if !labels.contains(&label) {
            labels.push(label);
        }
    }

    Ok(labels)
}

/// Fork a context token for a sub-agent, inheriting the parent's exposure.
///
/// Creates a fresh context token for the child subject, pre-populated with all
/// of the parent's exposure labels stacked into the child's authority block.
/// This prevents exposure laundering through delegation.
///
/// # Arguments
/// * `parent_token` - The base64-encoded parent context token
/// * `parent_public_key` - The public key used to verify the parent token
/// * `child_subject` - The child subject identifier (e.g., "agent:openclaw:subtask-1")
/// * `time_config` - Time configuration for the child context token
/// * `keypair` - The keypair to sign the child token with (same issuer)
///
/// # Returns
/// Base64-encoded child context token with inherited exposure.
pub fn fork_context(
    parent_token: &str,
    parent_public_key: PublicKey,
    child_subject: String,
    time_config: hessra_token_core::TokenTimeConfig,
    keypair: &KeyPair,
) -> Result<String, Box<dyn Error>> {
    let parent_labels = extract_exposure_labels(parent_token, parent_public_key)?;

    let mut builder = crate::mint::HessraContext::new(child_subject, time_config);
    if !parent_labels.is_empty() {
        builder = builder.with_initial_exposures(&parent_labels, "inherited");
    }
    builder.issue(keypair)
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

        let labels = extract_exposure_labels(&token, public_key).expect("Failed to extract labels");
        assert!(labels.is_empty());

        let exposed = add_exposure(
            &token,
            &keypair,
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

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let result = add_exposure(&token, &keypair, &[], "source".to_string())
            .expect("Failed with empty exposure");

        assert_eq!(result, token);
    }

    #[test]
    fn test_multiple_labels_stacked_in_one_block() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            &keypair,
            &[
                "PII:email".to_string(),
                "PII:address".to_string(),
                "PII:SSN".to_string(),
            ],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add exposure");

        // Three labels in a single call must produce exactly one new block.
        let pre = Biscuit::from_base64(&token, public_key)
            .unwrap()
            .block_count();
        let post = Biscuit::from_base64(&exposed, public_key)
            .unwrap()
            .block_count();
        assert_eq!(
            post,
            pre + 1,
            "all labels must land in one third-party block"
        );

        let labels =
            extract_exposure_labels(&exposed, public_key).expect("Failed to extract labels");
        assert_eq!(labels.len(), 3);
        assert!(labels.contains(&"PII:email".to_string()));
        assert!(labels.contains(&"PII:address".to_string()));
        assert!(labels.contains(&"PII:SSN".to_string()));
    }

    #[test]
    fn test_cumulative_exposure_across_calls() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let exposed = add_exposure(
            &token,
            &keypair,
            &["PII:email".to_string(), "PII:address".to_string()],
            "data:user-profile".to_string(),
        )
        .expect("Failed to add first exposure");

        let more_exposed = add_exposure(
            &exposed,
            &keypair,
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
            &keypair,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add first exposure");

        let double_exposed = add_exposure(
            &exposed,
            &keypair,
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

        let exposed_parent = add_exposure(
            &parent,
            &keypair,
            &["PII:SSN".to_string()],
            "data:user-ssn".to_string(),
        )
        .expect("Failed to add exposure to parent");

        let child = fork_context(
            &exposed_parent,
            public_key,
            "agent:parent:child".to_string(),
            TokenTimeConfig::default(),
            &keypair,
        )
        .expect("Failed to fork context");

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

        let exposed = add_exposure(
            &parent,
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
