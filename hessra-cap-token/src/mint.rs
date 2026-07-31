extern crate biscuit_auth as biscuit;

use std::time::Duration;

use biscuit::macros::{biscuit, check};
use chrono::Utc;
use hessra_token_core::{KeyPair, PublicKey, TokenError, TokenTimeConfig};
use tracing::debug;

/// Builder for minting Hessra capability tokens.
///
/// A capability authorizes `(subject, resource, operation)`. Presenting the
/// capability IS the authorization -- the subject is retained on the `right`
/// fact for auditing but is not checked by default. Scope can be narrowed with
/// designations (`check if designation(label, value)`), bound to a single
/// verifier with [`Self::anchor`], and made **latent** (inert until activated)
/// with [`Self::latent`].
///
/// # Example
/// ```rust
/// use hessra_cap_token::HessraCapability;
/// use hessra_token_core::KeyPair;
/// use std::time::Duration;
///
/// let authority = KeyPair::new();
/// let token = HessraCapability::new()
///     .subject("toolsystem")
///     .resource("compute:run")
///     .operation("invoke")
///     .anchor("tool:compute")
///     .valid_for(Duration::from_secs(3600))
///     .issue(&authority)
///     .expect("issue capability");
/// ```
#[derive(Default)]
pub struct HessraCapability {
    subject: Option<String>,
    resource: Option<String>,
    operation: Option<String>,
    /// `check if designation(label, value)` constraints (keyless-satisfiable).
    designations: Vec<(String, String)>,
    /// `check if designation(label, value) trusting {pk}` constraints -- the
    /// matching fact must be attested by `pk`.
    designations_trusting: Vec<(PublicKey, String, String)>,
    valid_for: Option<Duration>,
    /// When set, the capability is latent: `check if activation($a) trusting {pk}`
    /// makes it inert until a holder of `pk` attests an `activation` fact.
    latent: Option<PublicKey>,
    /// Clock + default-lifetime control. `start_time` overrides "now" (for
    /// testing); `duration` is the default lifetime used only when `valid_for`
    /// is unset. Defaults to the real wall clock with a 300s lifetime.
    time_config: TokenTimeConfig,
}

impl HessraCapability {
    /// Start a new, empty capability builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the subject (retained on the `right` fact for auditing; not checked
    /// at verify time by default).
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Set the resource this capability authorizes access to.
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Set the operation this capability authorizes.
    pub fn operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    /// Require a designation: adds `check if designation(label, value)`. The
    /// verifier must supply a matching `designation(label, value)` fact.
    pub fn designation(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.designations.push((label.into(), value.into()));
        self
    }

    /// Require a designation that must be attested by `pk`: adds
    /// `check if designation(label, value) trusting {pk}`. The matching fact is
    /// honored only when it comes from a block signed by `pk` (or the authority).
    pub fn designation_trusting(
        mut self,
        pk: PublicKey,
        label: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.designations_trusting
            .push((pk, label.into(), value.into()));
        self
    }

    /// Bind this capability to a single verifying principal. Sugar for
    /// `designation("anchor", anchor)`: the verifier proves "I am `<anchor>`" by
    /// supplying `designation("anchor", <its-own-id>)`. The check lives in the
    /// authority block, so it survives attenuation and cannot be redirected to
    /// another verifier.
    pub fn anchor(self, anchor: impl Into<String>) -> Self {
        self.designation("anchor", anchor)
    }

    /// Set how long the capability is valid from issuance. Defaults to 5 minutes.
    /// Latent capabilities are typically minted long-lived and tightened to a
    /// short window when activated.
    pub fn valid_for(mut self, duration: Duration) -> Self {
        self.valid_for = Some(duration);
        self
    }

    /// Make this capability latent: it stays inert until a holder of
    /// `activator_pk` attests an `activation` fact (see
    /// [`crate::HessraCapability::amend`] + `.activate()`). Adds
    /// `check if activation($a) trusting {activator_pk}`.
    pub fn latent(mut self, activator_pk: PublicKey) -> Self {
        self.latent = Some(activator_pk);
        self
    }

    /// Supply a [`TokenTimeConfig`] to control time. `start_time`, when set,
    /// overrides the issuance clock (the seam for deterministic expiry tests);
    /// `duration` supplies the default lifetime used only when [`Self::valid_for`]
    /// is not set. Without this call the real wall clock and a 300s default apply.
    pub fn with_time(mut self, time_config: TokenTimeConfig) -> Self {
        self.time_config = time_config;
        self
    }

    /// Issue (build and sign) the capability, returning the base64 token.
    pub fn issue(self, keypair: &KeyPair) -> Result<String, TokenError> {
        let subject = self
            .subject
            .ok_or_else(|| TokenError::generic("capability requires a subject"))?;
        let resource = self
            .resource
            .ok_or_else(|| TokenError::generic("capability requires a resource"))?;
        let operation = self
            .operation
            .ok_or_else(|| TokenError::generic("capability requires an operation"))?;

        let now = self
            .time_config
            .start_time
            .unwrap_or_else(|| Utc::now().timestamp());
        let valid_for = self
            .valid_for
            .map(|d| d.as_secs() as i64)
            .unwrap_or(self.time_config.duration);
        let expiration = now + valid_for;

        // Subject stays on the `right` fact for auditing; $sub is free in the
        // check, so the verifier is not required to prove who presents the token.
        let mut builder = biscuit!(
            r#"
                right({subject}, {resource}, {operation});
                check if resource($res), operation($op), right($sub, $res, $op);
                check if time($time), $time < {expiration};
            "#
        );

        for (label, value) in &self.designations {
            let (label, value) = (label.clone(), value.clone());
            builder = builder.check(check!(r#"check if designation({label}, {value});"#))?;
        }

        for (pk, label, value) in &self.designations_trusting {
            let (pk, label, value) = (*pk, label.clone(), value.clone());
            builder = builder.check(check!(
                r#"check if designation({label}, {value}) trusting {pk};"#
            ))?;
        }

        if let Some(activator_pk) = self.latent {
            builder = builder.check(check!(
                r#"check if activation($a) trusting {activator_pk};"#
            ))?;
        }

        let biscuit = builder.build(keypair)?;
        debug!("minted capability authority block: {}", biscuit);
        Ok(biscuit.to_base64()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::CapabilityVerifier;
    use std::time::Duration;

    fn issue(authority: &KeyPair) -> String {
        HessraCapability::new()
            .subject("alice")
            .resource("res1")
            .operation("read")
            .issue(authority)
            .expect("issue")
    }

    #[test]
    fn create_and_verify() {
        let root = KeyPair::new();
        let token = issue(&root);
        assert!(
            CapabilityVerifier::new(token, root.public(), "res1".into(), "read".into())
                .verify()
                .is_ok()
        );
    }

    #[test]
    fn wrong_resource_or_operation_rejected() {
        let root = KeyPair::new();
        let token = issue(&root);
        assert!(
            CapabilityVerifier::new(token.clone(), root.public(), "res2".into(), "read".into())
                .verify()
                .is_err()
        );
        assert!(
            CapabilityVerifier::new(token, root.public(), "res1".into(), "write".into())
                .verify()
                .is_err()
        );
    }

    #[test]
    fn missing_field_errors() {
        let root = KeyPair::new();
        assert!(
            HessraCapability::new()
                .resource("r")
                .operation("o")
                .issue(&root)
                .is_err()
        );
    }

    #[test]
    fn fresh_cap_within_window_passes() {
        let root = KeyPair::new();
        let token = HessraCapability::new()
            .subject("alice")
            .resource("res1")
            .operation("read")
            .valid_for(Duration::from_secs(60))
            .issue(&root)
            .unwrap();
        assert!(
            CapabilityVerifier::new(token, root.public(), "res1".into(), "read".into())
                .verify()
                .is_ok()
        );
    }

    #[test]
    fn expired_cap_rejected() {
        use hessra_token_core::TokenTimeConfig;

        let root = KeyPair::new();
        let base = 1_000_000_000;
        // Mint a 300s cap on a fixed clock, then verify 301s later -- past the
        // window. Deterministic, no sleep.
        let token = HessraCapability::new()
            .subject("alice")
            .resource("res1")
            .operation("read")
            .with_time(TokenTimeConfig {
                start_time: Some(base),
                duration: 300,
            })
            .issue(&root)
            .unwrap();
        assert!(
            CapabilityVerifier::new(token, root.public(), "res1".into(), "read".into())
                .with_time(TokenTimeConfig {
                    start_time: Some(base + 301),
                    duration: 300,
                })
                .verify()
                .is_err()
        );
    }

    #[test]
    fn anchor_binds_to_one_verifier() {
        let root = KeyPair::new();
        let token = HessraCapability::new()
            .subject("alice")
            .resource("res1")
            .operation("read")
            .anchor("webapp")
            .issue(&root)
            .unwrap();

        assert!(
            CapabilityVerifier::new(token.clone(), root.public(), "res1".into(), "read".into())
                .anchor("webapp")
                .verify()
                .is_ok()
        );
        // No anchor asserted -> fail closed.
        assert!(
            CapabilityVerifier::new(token.clone(), root.public(), "res1".into(), "read".into())
                .verify()
                .is_err()
        );
        // Wrong anchor -> rejected.
        assert!(
            CapabilityVerifier::new(token, root.public(), "res1".into(), "read".into())
                .anchor("bobapp")
                .verify()
                .is_err()
        );
    }
}
