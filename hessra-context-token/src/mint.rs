extern crate biscuit_auth as biscuit;

use biscuit::builder::BiscuitBuilder;
use biscuit::macros::{biscuit, biscuit_merge};
use chrono::Utc;
use hessra_token_core::{KeyPair, TokenTimeConfig};
use std::error::Error;

/// Builder for creating Hessra context tokens.
///
/// Context tokens identify a session and track data exposure as biscuit blocks.
/// Each exposure label becomes a `reject if exposure({label})` rule (plus an
/// `exposed_label({label})` metadata fact for enumeration). Initial labels
/// (known at mint time) are stacked into the authority block; subsequent
/// exposures are added via `add_exposure` in third-party blocks.
///
/// # Example
/// ```rust
/// use hessra_context_token::HessraContext;
/// use hessra_token_core::{KeyPair, TokenTimeConfig};
///
/// let keypair = KeyPair::new();
/// let token = HessraContext::new(
///     "agent:openclaw".to_string(),
///     TokenTimeConfig::default(),
/// )
/// .issue(&keypair)
/// .expect("Failed to create context token");
/// ```
pub struct HessraContext {
    subject: String,
    time_config: TokenTimeConfig,
    initial_exposures: Vec<String>,
    initial_sources: Vec<String>,
}

impl HessraContext {
    /// Creates a new context token builder.
    ///
    /// # Arguments
    /// * `subject` - The session owner identifier (e.g., "agent:openclaw")
    /// * `time_config` - Time configuration for token validity
    pub fn new(subject: String, time_config: TokenTimeConfig) -> Self {
        Self {
            subject,
            time_config,
            initial_exposures: Vec::new(),
            initial_sources: Vec::new(),
        }
    }

    /// Stack initial exposure labels into the authority block.
    ///
    /// All labels in `labels` land in the same authority block alongside the
    /// `context(subject)` fact, paired with one `exposure_time`. Multiple calls
    /// accumulate both labels and sources: every distinct `source` is recorded
    /// as its own `exposure_source` fact.
    ///
    /// Accumulating rather than replacing is what lets a compaction
    /// ([`crate::compact_context`]) fold many third-party blocks into one
    /// authority block without collapsing provenance -- a caller that
    /// intersects the recorded sources against the objects capable of
    /// conferring a label would otherwise lose its answer at every re-mint.
    pub fn with_initial_exposures(mut self, labels: &[String], source: impl Into<String>) -> Self {
        for label in labels {
            if !self.initial_exposures.contains(label) {
                self.initial_exposures.push(label.clone());
            }
        }
        let source = source.into();
        if !self.initial_sources.contains(&source) {
            self.initial_sources.push(source);
        }
        self
    }

    /// Record additional `exposure_source` facts without adding labels.
    ///
    /// Compaction needs this: the sources it is carrying forward came from
    /// blocks it is discarding, and they do not line up one-to-one with the
    /// labels being restacked.
    pub fn with_exposure_sources(mut self, sources: &[String]) -> Self {
        for source in sources {
            if !self.initial_sources.contains(source) {
                self.initial_sources.push(source.clone());
            }
        }
        self
    }

    /// Issues (builds and signs) the context token.
    ///
    /// The authority block contains:
    /// - `context({subject})` - identifies the session owner
    /// - `reject if exposure({label})` rules for each initial exposure (if any),
    ///   which fire when a verifier asserts the matching `exposure({label})` fact
    /// - `exposed_label({label})` metadata facts for enumeration (if any)
    /// - `exposure_source({source})` and `exposure_time({now})` (if any exposures)
    /// - time expiration check
    pub fn issue(self, keypair: &KeyPair) -> Result<String, Box<dyn Error>> {
        let start_time = self
            .time_config
            .start_time
            .unwrap_or_else(|| Utc::now().timestamp());
        let expiration = start_time + self.time_config.duration;
        let subject = self.subject;

        let mut builder: BiscuitBuilder = biscuit!(
            r#"
                context({subject});
                check if time($time), $time < {expiration};
            "#
        );

        // Sources are emitted on their own condition, not nested under labels:
        // a compaction can carry provenance for labels it restacks, and a
        // caller that supplied only sources should not have them silently
        // dropped.
        if !self.initial_exposures.is_empty() || !self.initial_sources.is_empty() {
            let now = Utc::now().timestamp();
            for label in &self.initial_exposures {
                let label = label.clone();
                builder = biscuit_merge!(
                    builder,
                    r#"
                        reject if exposure({label});
                        exposed_label({label});
                    "#
                );
            }
            for source in &self.initial_sources {
                let source = source.clone();
                builder = biscuit_merge!(builder, r#"exposure_source({source});"#);
            }
            builder = biscuit_merge!(builder, r#"exposure_time({now});"#);
        }

        let biscuit = builder.build(keypair)?;
        let token = biscuit.to_base64()?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::ContextVerifier;

    #[test]
    fn test_create_context_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
            .issue(&keypair)
            .expect("Failed to create context token");

        assert!(!token.is_empty());

        ContextVerifier::new(token, public_key)
            .verify()
            .expect("Should verify fresh context token");
    }

    #[test]
    fn test_expired_context_token() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let expired_config = TokenTimeConfig {
            start_time: Some(0),
            duration: 1,
        };

        let token = HessraContext::new("agent:test".to_string(), expired_config)
            .issue(&keypair)
            .expect("Failed to create expired context token");

        let result = ContextVerifier::new(token, public_key).verify();
        assert!(
            result.is_err(),
            "Expired context token should fail verification"
        );
    }

    #[test]
    fn test_custom_time_config() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let config = TokenTimeConfig {
            start_time: None,
            duration: 7200,
        };

        let token = HessraContext::new("agent:test".to_string(), config)
            .issue(&keypair)
            .expect("Failed to create context token with custom config");

        ContextVerifier::new(token, public_key)
            .verify()
            .expect("Should verify context token with custom duration");
    }

    #[test]
    fn test_synthesized_compound_behaves_as_a_plain_label() {
        // A conjunction is conferred as one derived label, so it blocks on a
        // single asserted fact -- the two-label reject rule is gone, and with it
        // the need for the verifier to assert both members together.
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let compound = crate::compound_label(&["credentials:local", "untrusted_input"])
            .expect("Failed to build compound label");
        let token = HessraContext::new("agent:test".to_string(), TokenTimeConfig::default())
            .with_initial_exposures(std::slice::from_ref(&compound), "policy")
            .issue(&keypair)
            .expect("Failed to create context token");

        // Neither member alone blocks: only the synthesized label was conferred.
        ContextVerifier::new(token.clone(), public_key)
            .excludes("credentials:local")
            .verify()
            .expect("a member of an unconferred conjunction must not block");
        ContextVerifier::new(token.clone(), public_key)
            .excludes("untrusted_input")
            .verify()
            .expect("a member of an unconferred conjunction must not block");

        // The compound itself blocks, asserted on its own.
        let result = ContextVerifier::new(token.clone(), public_key)
            .excludes(compound.clone())
            .verify();
        assert!(result.is_err(), "the synthesized compound must block");

        // And unlike a compound reject rule, it is enumerable -- which is what
        // lets a re-mint carry it forward.
        let labels = crate::extract_exposure_labels(&token, public_key)
            .expect("Failed to extract exposure labels");
        assert_eq!(labels, vec![compound]);
    }

    #[test]
    fn test_initial_exposures_stacked_in_authority_block() {
        let keypair = KeyPair::new();
        let public_key = keypair.public();

        let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
            .with_initial_exposures(
                &["PII:email".to_string(), "PII:address".to_string()],
                "data:user-profile",
            )
            .issue(&keypair)
            .expect("Failed to create context token with initial exposures");

        // Both labels should be queryable, and the token should still have
        // only one block (the authority block).
        let biscuit =
            biscuit::Biscuit::from_base64(&token, public_key).expect("Failed to parse token");
        assert_eq!(
            biscuit.block_count(),
            1,
            "Initial exposures must be stacked into the authority block, not split into separate blocks"
        );

        let labels = crate::exposure::extract_exposure_labels(&token, public_key)
            .expect("Failed to extract initial exposure labels");
        assert_eq!(labels.len(), 2);
        assert!(labels.contains(&"PII:email".to_string()));
        assert!(labels.contains(&"PII:address".to_string()));
    }
}
