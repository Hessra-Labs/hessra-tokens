extern crate biscuit_auth as biscuit;

use std::time::Duration;

use biscuit::Biscuit;
use biscuit::macros::{block, check, fact};
use chrono::Utc;
use hessra_token_core::{KeyPair, PublicKey, TokenError, TokenTimeConfig};

use crate::mint::HessraCapability;

impl HessraCapability {
    /// Open an existing capability for amendment. From here you add constraints
    /// (require-side) and/or attestations (provide-side), then finalize with
    /// either [`CapabilityAmendment::attenuate`] (keyless narrowing) or
    /// [`CapabilityAmendment::attest`] (a keyholder signs facts onto it).
    ///
    /// `root_pk` is the key the capability is rooted at (the authority's).
    pub fn amend(token: &str, root_pk: PublicKey) -> Result<CapabilityAmendment, TokenError> {
        let biscuit = Biscuit::from_base64(token, root_pk)?;
        Ok(CapabilityAmendment {
            biscuit,
            require_designations: Vec::new(),
            require_designations_trusting: Vec::new(),
            valid_for: None,
            attest_activation: false,
            attest_designations: Vec::new(),
            time_config: TokenTimeConfig::default(),
        })
    }
}

/// A pending amendment to an existing capability.
///
/// Two kinds of change accumulate here:
/// - **constraints** (require-side): [`Self::designation`],
///   [`Self::designation_trusting`], [`Self::valid_for`]. They tighten the
///   capability and are valid under either terminal.
/// - **attestations** (provide-side): [`Self::activate`],
///   [`Self::with_designation`]. They supply facts that only carry weight when
///   the amendment is signed, so they require the [`Self::attest`] terminal.
pub struct CapabilityAmendment {
    biscuit: Biscuit,
    require_designations: Vec<(String, String)>,
    require_designations_trusting: Vec<(PublicKey, String, String)>,
    valid_for: Option<Duration>,
    attest_activation: bool,
    attest_designations: Vec<(String, String)>,
    /// Clock control. `start_time`, when set, overrides "now" for the activation
    /// fact and the tightened-window deadline (the seam for deterministic tests).
    /// `duration` is not consulted here -- amend's time check is opt-in via
    /// [`Self::valid_for`].
    time_config: TokenTimeConfig,
}

impl CapabilityAmendment {
    /// Require a designation: adds `check if designation(label, value)`.
    pub fn designation(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.require_designations.push((label.into(), value.into()));
        self
    }

    /// Require a designation that must be attested by `pk`: adds
    /// `check if designation(label, value) trusting {pk}`.
    pub fn designation_trusting(
        mut self,
        pk: PublicKey,
        label: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.require_designations_trusting
            .push((pk, label.into(), value.into()));
        self
    }

    /// Tighten the capability's lifetime to `duration` from now. Checks only
    /// accumulate, so this can shorten the window, never extend it.
    pub fn valid_for(mut self, duration: Duration) -> Self {
        self.valid_for = Some(duration);
        self
    }

    /// Attest that this (latent) capability is active as of now: supplies an
    /// `activation` fact, satisfying a `latent` capability's activation check.
    /// Only meaningful under [`Self::attest`] (the signer vouches for it).
    pub fn activate(mut self) -> Self {
        self.attest_activation = true;
        self
    }

    /// Attest a designation fact: supplies `designation(label, value)`,
    /// satisfying a matching `designation_trusting` constraint. Mirrors
    /// [`crate::CapabilityVerifier::with_designation`]. Only meaningful under
    /// [`Self::attest`].
    pub fn with_designation(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.attest_designations.push((label.into(), value.into()));
        self
    }

    /// Supply a [`TokenTimeConfig`] to control time. Only `start_time` is used
    /// here: when set it overrides "now" for the activation fact and the
    /// tightened-window deadline (the seam for deterministic tests). `duration`
    /// is ignored -- amend's time check is opt-in via [`Self::valid_for`].
    pub fn with_time(mut self, time_config: TokenTimeConfig) -> Self {
        self.time_config = time_config;
        self
    }

    /// Resolve "now": the injected clock override, else the real wall clock.
    fn now(&self) -> i64 {
        self.time_config
            .start_time
            .unwrap_or_else(|| Utc::now().timestamp())
    }

    /// Finalize as a keyless attenuation: appends a first-party block carrying
    /// only the require-side constraints. Errors if any attestation (a
    /// provide-side fact) was added -- those require a signature via
    /// [`Self::attest`].
    pub fn attenuate(self) -> Result<String, TokenError> {
        if self.attest_activation || !self.attest_designations.is_empty() {
            return Err(TokenError::generic(
                "attenuate() cannot carry attested facts; use attest(keypair)",
            ));
        }
        let mut block = block!(r#""#);
        block = self.append_constraints(block)?;
        let appended = self
            .biscuit
            .append(block)
            .map_err(|e| TokenError::AttenuationFailed {
                reason: e.to_string(),
            })?;
        Ok(appended.to_base64()?)
    }

    /// Finalize as an attestation: a third-party block signed by `keypair`
    /// carrying the attested facts plus any constraints. The signer vouches for
    /// the facts; constraints (`trusting {keypair.public()}`) reference this
    /// signer so the matching facts are honored only from blocks it signed.
    pub fn attest(self, keypair: &KeyPair) -> Result<String, TokenError> {
        let now = self.now();
        let mut block = block!(r#""#);

        if self.attest_activation {
            block = block
                .fact(fact!(r#"activation({now});"#))
                .map_err(|e| TokenError::generic(format!("attest activation: {e}")))?;
        }
        for (label, value) in &self.attest_designations {
            let (label, value) = (label.clone(), value.clone());
            block = block
                .fact(fact!(r#"designation({label}, {value});"#))
                .map_err(|e| TokenError::generic(format!("attest designation: {e}")))?;
        }
        block = self.append_constraints(block)?;

        let request = self
            .biscuit
            .third_party_request()
            .map_err(|e| TokenError::generic(format!("attest request: {e}")))?;
        let signed = request
            .create_block(&keypair.private(), block)
            .map_err(|e| TokenError::generic(format!("attest sign: {e}")))?;
        let appended = self
            .biscuit
            .append_third_party(keypair.public(), signed)
            .map_err(|e| TokenError::generic(format!("attest append: {e}")))?;
        Ok(appended.to_base64()?)
    }

    /// Append the require-side constraints (shared by both terminals).
    fn append_constraints(
        &self,
        mut block: biscuit::builder::BlockBuilder,
    ) -> Result<biscuit::builder::BlockBuilder, TokenError> {
        for (label, value) in &self.require_designations {
            let (label, value) = (label.clone(), value.clone());
            block = block
                .check(check!(r#"check if designation({label}, {value});"#))
                .map_err(|e| TokenError::AttenuationFailed {
                    reason: e.to_string(),
                })?;
        }
        for (pk, label, value) in &self.require_designations_trusting {
            let (pk, label, value) = (*pk, label.clone(), value.clone());
            block = block
                .check(check!(
                    r#"check if designation({label}, {value}) trusting {pk};"#
                ))
                .map_err(|e| TokenError::AttenuationFailed {
                    reason: e.to_string(),
                })?;
        }
        if let Some(duration) = self.valid_for {
            let expiration = self.now() + duration.as_secs() as i64;
            block = block
                .check(check!(r#"check if time($t), $t < {expiration};"#))
                .map_err(|e| TokenError::AttenuationFailed {
                    reason: e.to_string(),
                })?;
        }
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::CapabilityVerifier;

    fn authority_cap(authority: &KeyPair) -> String {
        HessraCapability::new()
            .subject("alice")
            .resource("res1")
            .operation("read")
            .issue(authority)
            .unwrap()
    }

    #[test]
    fn keyless_designation_narrowing() {
        let root = KeyPair::new();
        let token = authority_cap(&root);
        let narrowed = HessraCapability::amend(&token, root.public())
            .unwrap()
            .designation("tenant", "t-1")
            .attenuate()
            .unwrap();

        // Matching designation passes.
        assert!(
            CapabilityVerifier::new(
                narrowed.clone(),
                root.public(),
                "res1".into(),
                "read".into()
            )
            .with_designation("tenant".into(), "t-1".into())
            .verify()
            .is_ok()
        );
        // Missing designation fails closed.
        assert!(
            CapabilityVerifier::new(narrowed, root.public(), "res1".into(), "read".into())
                .verify()
                .is_err()
        );
    }

    #[test]
    fn attenuate_rejects_attested_facts() {
        let root = KeyPair::new();
        let token = authority_cap(&root);
        let err = HessraCapability::amend(&token, root.public())
            .unwrap()
            .activate()
            .attenuate();
        assert!(err.is_err());
    }

    // --- latent capability lifecycle (ported from the old latent module) -------
    //
    // A latent cap is inert until the activator (ToolSystem) attests an
    // `activation` fact, and single-use via a per-activation facet pin
    // (`designation_trusting`) completed by a later facet attestation.

    use std::time::Duration;

    /// (authority keypair, activator/ts keypair)
    fn roles() -> (KeyPair, KeyPair) {
        (KeyPair::new(), KeyPair::new())
    }

    fn latent(authority: &KeyPair, ts: &KeyPair, anchor: &str) -> String {
        HessraCapability::new()
            .subject("agent")
            .resource("res:x")
            .operation("read")
            .anchor(anchor)
            .valid_for(Duration::from_secs(3600))
            .latent(ts.public())
            .issue(authority)
            .unwrap()
    }

    /// Activate: attest activation now, tighten to 5 min, pin a single-use facet.
    fn activate(latent: &str, authority: &KeyPair, ts: &KeyPair, facet: &str) -> String {
        HessraCapability::amend(latent, authority.public())
            .unwrap()
            .activate()
            .valid_for(Duration::from_secs(300))
            .designation_trusting(ts.public(), "facet", facet)
            .attest(ts)
            .unwrap()
    }

    /// Complete: attest the facet fact (the forward hop).
    fn complete(activated: &str, authority: &KeyPair, ts: &KeyPair, facet: &str) -> String {
        HessraCapability::amend(activated, authority.public())
            .unwrap()
            .with_designation("facet", facet)
            .attest(ts)
            .unwrap()
    }

    fn ok(token: &str, authority: &KeyPair, anchor: &str) -> bool {
        CapabilityVerifier::new(
            token.to_string(),
            authority.public(),
            "res:x".to_string(),
            "read".to_string(),
        )
        .anchor(anchor)
        .verify()
        .is_ok()
    }

    /// Like [`ok`], but verifies against a fixed clock `at`.
    fn ok_at(token: &str, authority: &KeyPair, anchor: &str, at: i64) -> bool {
        CapabilityVerifier::new(
            token.to_string(),
            authority.public(),
            "res:x".to_string(),
            "read".to_string(),
        )
        .anchor(anchor)
        .with_time(TokenTimeConfig {
            start_time: Some(at),
            ..Default::default()
        })
        .verify()
        .is_ok()
    }

    #[test]
    fn requires_both_activation_and_facet() {
        let (auth, ts) = roles();
        let latent = latent(&auth, &ts, "tool:x");

        // Inert at rest.
        assert!(!ok(&latent, &auth, "tool:x"));
        // Activated but not completed: facet pin unmet -> still inert.
        let activated = activate(&latent, &auth, &ts, "facet-A");
        assert!(!ok(&activated, &auth, "tool:x"));
        // Completed -> verifies.
        let completed = complete(&activated, &auth, &ts, "facet-A");
        assert!(ok(&completed, &auth, "tool:x"));
    }

    #[test]
    fn facet_bound_to_activation() {
        let (auth, ts) = roles();
        let latent = latent(&auth, &ts, "tool:x");
        let act_a = activate(&latent, &auth, &ts, "facet-A");
        let act_b = activate(&latent, &auth, &ts, "facet-B");

        assert!(ok(
            &complete(&act_a, &auth, &ts, "facet-A"),
            &auth,
            "tool:x"
        ));
        assert!(ok(
            &complete(&act_b, &auth, &ts, "facet-B"),
            &auth,
            "tool:x"
        ));
        // A facet from the other activation cannot satisfy this one.
        assert!(!ok(
            &complete(&act_b, &auth, &ts, "facet-A"),
            &auth,
            "tool:x"
        ));
        assert!(!ok(
            &complete(&act_a, &auth, &ts, "facet-B"),
            &auth,
            "tool:x"
        ));
    }

    #[test]
    fn activation_from_wrong_key_rejected() {
        // Activation attested by a rogue key; facet completed correctly by ts.
        // Fails only on the activation check.
        let (auth, ts) = roles();
        let rogue = KeyPair::new();
        let latent = latent(&auth, &ts, "tool:x");
        let activated = activate(&latent, &auth, &rogue, "facet-A");
        let completed = complete(&activated, &auth, &ts, "facet-A");
        assert!(!ok(&completed, &auth, "tool:x"));
    }

    #[test]
    fn facet_from_wrong_key_rejected() {
        // Activation correct (ts); facet completed by a rogue key. Fails only on
        // the facet pin.
        let (auth, ts) = roles();
        let rogue = KeyPair::new();
        let latent = latent(&auth, &ts, "tool:x");
        let activated = activate(&latent, &auth, &ts, "facet-A");
        let forged = complete(&activated, &auth, &rogue, "facet-A");
        assert!(!ok(&forged, &auth, "tool:x"));
    }

    #[test]
    fn activation_shortens_lifetime() {
        // The headline temporal claim: activating a long-lived latent cap
        // tightens its effective lifetime to the activation window (<=5 min),
        // even though the original mint window is still wide open.
        let (auth, ts) = roles();
        let base = 1_000_000_000;
        let clock = TokenTimeConfig {
            start_time: Some(base),
            ..Default::default()
        };

        // Latent cap minted with a 1-hour window on the fixed clock.
        let latent = HessraCapability::new()
            .subject("agent")
            .resource("res:x")
            .operation("read")
            .anchor("tool:x")
            .valid_for(Duration::from_secs(3600))
            .latent(ts.public())
            .with_time(clock)
            .issue(&auth)
            .unwrap();

        // Activate at `base`, tightening to a 5-minute window + facet pin.
        let activated = HessraCapability::amend(&latent, auth.public())
            .unwrap()
            .activate()
            .valid_for(Duration::from_secs(300))
            .designation_trusting(ts.public(), "facet", "f")
            .with_time(clock)
            .attest(&ts)
            .unwrap();
        let completed = HessraCapability::amend(&activated, auth.public())
            .unwrap()
            .with_designation("facet", "f")
            .with_time(clock)
            .attest(&ts)
            .unwrap();

        // Inside the activation window: ok.
        assert!(ok_at(&completed, &auth, "tool:x", base + 299));
        // Past the 5-min activation window but still within the original 1-hour
        // mint window: rejected -- activation shortened the lifetime.
        assert!(!ok_at(&completed, &auth, "tool:x", base + 301));
    }

    #[test]
    fn anchor_binds_latent_to_one_tool() {
        let (auth, ts) = roles();
        let latent = latent(&auth, &ts, "tool:a");
        let activated = activate(&latent, &auth, &ts, "facet-A");
        let completed = complete(&activated, &auth, &ts, "facet-A");
        assert!(!ok(&completed, &auth, "tool:b"));
        assert!(ok(&completed, &auth, "tool:a"));
    }
}
