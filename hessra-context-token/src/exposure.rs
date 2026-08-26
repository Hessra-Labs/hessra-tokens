//! Exposure tracking operations for context tokens.
//!
//! Each `add_exposure` call appends a third-party block signed by the issuer's
//! keypair. All labels passed in a single call land in the same block as sibling
//! `reject if exposure({label})` rules (one block per logical exposure event),
//! each paired with an `exposed_label({label})` metadata fact. Enforcement flows
//! from the reject rules (any signer can append one; no `trusting` scope needed),
//! while enumeration queries the `exposed_label` facts scoped to
//! `trusting authority, {pubkey}` so only issuer-attested labels are reported.

extern crate biscuit_auth as biscuit;

use biscuit::Biscuit;
use biscuit::macros::{block, block_merge, rule};
use chrono::Utc;
use hessra_token_core::{KeyPair, PublicKey, TokenError};
use std::error::Error;

/// Append a batch of exposure labels to a context token in one third-party block.
///
/// The new block is signed by `keypair` (the issuer's keypair). All `labels`
/// from this single call land in the same block as `reject if exposure({label})`
/// rules paired with `exposed_label({label})` facts, alongside a single
/// `exposure_source` and `exposure_time` fact.
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
        block_builder = block_merge!(
            block_builder,
            r#"
                reject if exposure({label});
                exposed_label({label});
            "#
        );
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
/// matches `exposed_label(...)` facts in the authority block and in third-party
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
            r#"data($l) <- exposed_label($l) trusting authority, {pk}"#
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

/// Fold a context token's accumulated exposure into a single fresh authority
/// block, under a new expiry.
///
/// This is both **compaction** and **renewal**, because for an append-only
/// accumulator they are the same operation. Exposure can never be dropped, so
/// extending a session past its token's expiry means re-minting with every
/// label carried forward -- and re-minting with every label carried forward is
/// exactly what collapses a chain of third-party blocks back to one.
///
/// Two properties the caller depends on:
///
/// - **Lossless.** Every label comes back through
///   [`extract_exposure_labels`], including synthesized compounds (see
///   [`crate::compound_label`]), because a compound is an ordinary label.
/// - **Provenance-preserving.** Every distinct `exposure_source` from the
///   discarded blocks is re-recorded, so a caller that intersects recorded
///   sources against the objects capable of conferring a label still has an
///   answer afterwards.
///
/// What does *not* survive is the pairing of a source to a particular block,
/// and the per-block `exposure_time`. Neither was ever readable per label --
/// `exposure_source` is a bare fact with no label argument -- so nothing that
/// was recoverable before becomes unrecoverable here.
///
/// The new token is signed by `keypair` and rooted at its public key, so the
/// issuer must be the same principal that signed the input.
///
/// # Arguments
/// * `token` - The base64-encoded context token to compact
/// * `public_key` - The public key used to verify the input token
/// * `time_config` - Time configuration for the compacted token (the new expiry)
/// * `keypair` - The keypair to sign the compacted token with (same issuer)
pub fn compact_context(
    token: &str,
    public_key: PublicKey,
    time_config: hessra_token_core::TokenTimeConfig,
    keypair: &KeyPair,
) -> Result<String, Box<dyn Error>> {
    remint(token, public_key, None, time_config, keypair)
}

/// Fork a context token for a sub-agent, inheriting the parent's exposure.
///
/// Creates a fresh context token for the child subject, pre-populated with all
/// of the parent's exposure labels stacked into the child's authority block.
/// This prevents exposure laundering through delegation.
///
/// Mechanically identical to [`compact_context`] apart from the subject: a fork
/// is a re-mint that renames, a compaction is a re-mint that does not.
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
    remint(
        parent_token,
        parent_public_key,
        Some(child_subject),
        time_config,
        keypair,
    )
}

/// Re-mint `token`'s exposure into a fresh authority block.
///
/// The shared body of [`compact_context`] and [`fork_context`]; the only thing
/// that distinguishes them is `subject` -- `None` keeps the input token's own
/// subject (a compaction), `Some` renames it (a fork).
fn remint(
    token: &str,
    public_key: PublicKey,
    subject: Option<String>,
    time_config: hessra_token_core::TokenTimeConfig,
    keypair: &KeyPair,
) -> Result<String, Box<dyn Error>> {
    let inspected = crate::inspect::inspect_context_token(token.to_string(), public_key)?;
    let subject = subject.unwrap_or_else(|| inspected.subject.clone());

    let mut builder = crate::mint::HessraContext::new(subject, time_config);
    if !inspected.exposure_labels.is_empty() {
        builder = builder.with_initial_exposures(&inspected.exposure_labels, "inherited");
    }
    // Carry every contributing source forward alongside the synthetic
    // "inherited" marker, so provenance survives the fold.
    if !inspected.exposure_sources.is_empty() {
        builder = builder.with_exposure_sources(&inspected.exposure_sources);
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
    fn test_compound_added_post_mint_is_enumerable() {
        // The property the old compound-reject encoding could not offer: a
        // conjunction conferred after mint comes back out of
        // `extract_exposure_labels`, so a re-mint cannot silently drop it.
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        let compound = crate::compound_label(&["credentials:local", "untrusted_input"])
            .expect("Failed to build compound label");
        let tightened = add_exposure(
            &token,
            &keypair,
            std::slice::from_ref(&compound),
            "policy:conjunction".to_string(),
        )
        .expect("Failed to add compound exposure");

        let labels =
            extract_exposure_labels(&tightened, public_key).expect("Failed to extract labels");
        assert_eq!(labels, vec![compound.clone()]);

        // A member alone does not block; the conjunction does.
        crate::verify::ContextVerifier::new(tightened.clone(), public_key)
            .excludes("credentials:local")
            .verify()
            .expect("a member of the conjunction must not block on its own");
        let result = crate::verify::ContextVerifier::new(tightened, public_key)
            .excludes(compound)
            .verify();
        assert!(result.is_err(), "the conjunction must block");
    }

    #[test]
    fn test_compact_folds_blocks_and_preserves_labels_and_sources() {
        // The headline compaction claim: many third-party blocks collapse to a
        // single authority block, with nothing lost that was readable before.
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let mut token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");
        for (label, source) in [
            ("untrusted_input", "tool:web-fetch"),
            ("PII:SSN", "tool:read-file"),
            ("credentials:local", "tool:keychain"),
        ] {
            token = add_exposure(&token, &keypair, &[label.to_string()], source.to_string())
                .expect("Failed to add exposure");
        }

        let before = crate::inspect_context_token(token.clone(), public_key).unwrap();
        assert_eq!(before.exposure_block_count, 3);

        let compacted = compact_context(&token, public_key, TokenTimeConfig::default(), &keypair)
            .expect("Failed to compact context");
        let after = crate::inspect_context_token(compacted.clone(), public_key).unwrap();

        // One block, same subject, same labels.
        assert_eq!(after.exposure_block_count, 0);
        assert_eq!(after.subject, "agent:test");
        let mut want = before.exposure_labels.clone();
        let mut got = after.exposure_labels.clone();
        want.sort();
        got.sort();
        assert_eq!(got, want);

        // Every contributing source survives the fold -- the property that
        // keeps "which object conferred this" answerable after a renewal.
        for source in ["tool:web-fetch", "tool:read-file", "tool:keychain"] {
            assert!(
                after.exposure_sources.iter().any(|s| s == source),
                "source {source} was lost in compaction; sources: {:?}",
                after.exposure_sources
            );
        }

        // And the folded labels still block.
        let result = crate::verify::ContextVerifier::new(compacted, public_key)
            .excludes("PII:SSN")
            .verify();
        assert!(result.is_err(), "a compacted label must still preclude");
    }

    #[test]
    fn test_compact_carries_compound_labels() {
        // The regression the old encoding could not pass: a conjunction must
        // survive a re-mint. As a two-label reject rule it carried no
        // `exposed_label` fact and was silently dropped here.
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let compound = crate::compound_label(&["credentials:local", "untrusted_input"]).unwrap();
        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");
        let token = add_exposure(
            &token,
            &keypair,
            std::slice::from_ref(&compound),
            "policy:conjunction".to_string(),
        )
        .expect("Failed to add compound exposure");

        let compacted = compact_context(&token, public_key, TokenTimeConfig::default(), &keypair)
            .expect("Failed to compact context");

        let labels = extract_exposure_labels(&compacted, public_key).unwrap();
        assert_eq!(labels, vec![compound.clone()]);
        let result = crate::verify::ContextVerifier::new(compacted, public_key)
            .excludes(compound)
            .verify();
        assert!(result.is_err(), "the compound must survive compaction");
    }

    #[test]
    fn test_compact_renews_expiry() {
        // Renewal is the other half: compaction moves the deadline, which is
        // the only way an append-only context outlives its original TTL.
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let base = 1_000_000_000;
        let token = HessraContext::new(
            "agent:test".to_string(),
            TokenTimeConfig {
                start_time: Some(base),
                duration: 300,
            },
        )
        .with_initial_exposures(&["untrusted_input".to_string()], "seed")
        .issue(&keypair)
        .expect("Failed to create context token");

        let old_expiry = crate::inspect_context_token(token.clone(), public_key)
            .unwrap()
            .expiry
            .expect("expiry should be extractable");
        assert_eq!(old_expiry, base + 300);

        let renewed = compact_context(
            &token,
            public_key,
            TokenTimeConfig {
                start_time: Some(base + 200),
                duration: 3600,
            },
            &keypair,
        )
        .expect("Failed to renew context");

        let new_expiry = crate::inspect_context_token(renewed.clone(), public_key)
            .unwrap()
            .expiry
            .expect("expiry should be extractable");
        assert_eq!(new_expiry, base + 200 + 3600);
        assert!(new_expiry > old_expiry, "renewal must extend the deadline");

        // Renewed, but not laundered: the label came along.
        let labels = extract_exposure_labels(&renewed, public_key).unwrap();
        assert_eq!(labels, vec!["untrusted_input".to_string()]);
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
