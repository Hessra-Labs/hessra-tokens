//! Exposure label vocabulary: plain labels and synthesized compound labels.
//!
//! A **plain** label names one thing a session has been exposed to
//! (`untrusted_input`, `PII:SSN`). A **compound** label names a conjunction:
//! the canonical join of two or more plain labels, conferred by the exposure
//! writer at the moment the session holds all of its members.
//!
//! Compounds are ordinary labels. They get the same
//! `reject if exposure({label})` rule and the same `exposed_label({label})`
//! fact as anything else, which is what lets [`crate::extract_exposure_labels`]
//! recover them and lets a re-mint carry them forward. Nothing in this crate
//! evaluates a conjunction; the writer does that before it confers.
//!
//! ## Threat model
//!
//! A compound label is just its string, so nothing downstream can tell a
//! synthesized `a&b` from one a tool asked for by name. The defense is to
//! reject the delimiter where untrusted label declarations *enter* the system --
//! a tool manifest, a roster entry, a policy file -- using
//! [`validate_plain_label`]. Do that at load time, where it fails loudly, rather
//! than trusting this crate to sort it out at conferral time. This crate
//! deliberately does not validate on the write path: by then a synthesized
//! compound and a forged one are indistinguishable.

use hessra_token_core::TokenError;

/// Separates the members of a compound exposure label.
///
/// Chosen because it reads as conjunction and does not appear in the existing
/// label vocabulary, which uses `:` for namespacing (`PII:SSN`,
/// `filesystem:source`) and `_` inside segments (`untrusted_input`).
pub const COMPOUND_DELIMITER: char = '&';

/// Build the canonical compound label for `members`.
///
/// Members are validated, deduplicated, and sorted before joining, so the
/// argument order does not matter: `["b", "a"]` and `["a", "b"]` produce the
/// same label, and therefore the same reject rule and the same ledger identity.
///
/// # Errors
///
/// Returns an error if any member is empty, contains
/// [`COMPOUND_DELIMITER`], or if fewer than two distinct members remain. A
/// one-member conjunction is a plain label; ask for it by name instead of
/// routing it through here, so a policy rule that collapsed to one member
/// surfaces as a mistake rather than silently becoming a singleton.
pub fn compound_label<S: AsRef<str>>(members: &[S]) -> Result<String, TokenError> {
    let mut canonical: Vec<&str> = Vec::with_capacity(members.len());
    for member in members {
        let member = member.as_ref();
        validate_plain_label(member)?;
        if !canonical.contains(&member) {
            canonical.push(member);
        }
    }
    if canonical.len() < 2 {
        return Err(TokenError::generic(format!(
            "a compound exposure label needs at least two distinct members, got {}",
            canonical.len()
        )));
    }
    canonical.sort_unstable();
    Ok(canonical.join(&COMPOUND_DELIMITER.to_string()))
}

/// Validate a label supplied by an untrusted declaration (a tool manifest, a
/// roster entry, a policy file).
///
/// # Errors
///
/// Returns an error if `label` is empty or contains [`COMPOUND_DELIMITER`] --
/// the latter being an attempt, deliberate or not, to name a conjunction that
/// the exposure writer never synthesized.
pub fn validate_plain_label(label: &str) -> Result<(), TokenError> {
    if label.is_empty() {
        return Err(TokenError::generic("exposure label must not be empty"));
    }
    if label.contains(COMPOUND_DELIMITER) {
        return Err(TokenError::generic(format!(
            "exposure label {label:?} contains the reserved compound delimiter \
             {COMPOUND_DELIMITER:?}; compound labels are synthesized by the exposure \
             writer and cannot be declared"
        )));
    }
    Ok(())
}

/// Split a compound label back into its members, or `None` if `label` is plain.
///
/// The inverse of [`compound_label`] for a canonically-formed input, which is
/// what makes compounds re-derivable at compaction: read the members back, test
/// them against current policy, and re-synthesize.
pub fn compound_members(label: &str) -> Option<Vec<&str>> {
    if !label.contains(COMPOUND_DELIMITER) {
        return None;
    }
    Some(label.split(COMPOUND_DELIMITER).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compound_is_order_insensitive() {
        let a = compound_label(&["b", "a"]).unwrap();
        let b = compound_label(&["a", "b"]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, "a&b");
    }

    #[test]
    fn compound_dedupes_then_rejects_single_member() {
        // Three arguments naming two things is fine.
        assert_eq!(compound_label(&["a", "b", "a"]).unwrap(), "a&b");
        // Three arguments naming one thing is a policy mistake, not a singleton.
        assert!(compound_label(&["a", "a", "a"]).is_err());
        assert!(compound_label(&["a"]).is_err());
        assert!(compound_label::<&str>(&[]).is_err());
    }

    #[test]
    fn compound_of_three_is_supported() {
        // The two-label ceiling of the old reject-rule encoding is gone.
        assert_eq!(compound_label(&["c", "a", "b"]).unwrap(), "a&b&c");
    }

    #[test]
    fn members_cannot_smuggle_the_delimiter() {
        // Otherwise ["a&b", "c"] and ["a", "b&c"] would collide.
        assert!(compound_label(&["a&b", "c"]).is_err());
        assert!(validate_plain_label("a&b").is_err());
        assert!(validate_plain_label("").is_err());
        assert!(validate_plain_label("PII:SSN").is_ok());
        assert!(validate_plain_label("untrusted_input").is_ok());
    }

    #[test]
    fn members_round_trip() {
        let label = compound_label(&["financial:acct", "PII:SSN"]).unwrap();
        assert_eq!(
            compound_members(&label),
            Some(vec!["PII:SSN", "financial:acct"])
        );
        assert_eq!(compound_members("untrusted_input"), None);
    }
}
