//! # Hessra Context Token
//!
//! Context token implementation for information flow control (exposure tracking)
//! in the Hessra authorization system.
//!
//! Context tokens track what data an object (typically an AI agent) has been
//! exposed to during a session. Each data access adds exposure labels as
//! append-only biscuit blocks, which downstream systems use to restrict
//! available capabilities.
//!
//! ## Key Properties
//!
//! - **Append-only**: Exposure labels accumulate and cannot be removed within a session.
//! - **Reject-based enforcement**: Each label is recorded as a `reject if exposure({label})`
//!   rule. A verifier asserts the labels it cares about as `exposure({label})` facts; a
//!   matching reject rule fails authorization. Reject rules are monotonic and apply to the
//!   whole token regardless of which key signed them -- any party (even an ephemeral key)
//!   can tighten a token, and no `trusting` scope is needed on the authz path.
//! - **Enumerable**: Each label is also recorded as an `exposed_label({label})` metadata
//!   fact (a separate predicate the reject rules never test), queried with
//!   `trusting authority, {pubkey}` so only issuer-attested labels are reported.
//! - **Block-stacked**: All labels added in a single call land in the same block.
//! - **Inheritable**: Child contexts inherit parent exposure via `fork_context`.
//!
//! ## Authority Block
//!
//! ```datalog
//! context(subject);
//! check if time($time), $time < expiration;
//! // optional, only if mint-time exposures supplied:
//! reject if exposure(label_1);
//! exposed_label(label_1);
//! reject if exposure(label_2);
//! exposed_label(label_2);
//! exposure_source(source);
//! exposure_time(timestamp);
//! ```
//!
//! ## Third-party exposure blocks (one per `add_exposure` call)
//!
//! ```datalog
//! reject if exposure(label_a);
//! exposed_label(label_a);
//! reject if exposure(label_b);
//! exposed_label(label_b);
//! exposure_source(source);
//! exposure_time(timestamp);
//! ```
//!
//! ## Example
//!
//! ```rust
//! use hessra_context_token::{HessraContext, ContextVerifier, add_exposure};
//! use hessra_token_core::{KeyPair, TokenTimeConfig};
//!
//! let keypair = KeyPair::new();
//! let public_key = keypair.public();
//!
//! // Mint a fresh context token
//! let token = HessraContext::new("agent:openclaw".to_string(), TokenTimeConfig::default())
//!     .issue(&keypair)
//!     .expect("Failed to create context token");
//!
//! // Add exposure labels (stacked into one third-party block, signed by the issuer)
//! let exposed = add_exposure(
//!     &token,
//!     &keypair,
//!     &["PII:SSN".to_string()],
//!     "data:user-ssn".to_string(),
//! ).expect("Failed to add exposure");
//!
//! // Verify with chained exclusion checks
//! ContextVerifier::new(exposed.clone(), public_key)
//!     .excludes("PII:email")
//!     .verify()
//!     .expect("PII:email is not attested");
//!
//! assert!(ContextVerifier::new(exposed, public_key)
//!     .excludes("PII:SSN")
//!     .verify()
//!     .is_err());
//! ```

mod exposure;
mod inspect;
mod mint;
mod verify;

pub use exposure::{add_exposure, extract_exposure_labels, fork_context};
pub use inspect::{ContextInspectResult, inspect_context_token};
pub use mint::HessraContext;
pub use verify::ContextVerifier;

// Re-export commonly needed types from core
pub use hessra_token_core::{
    Biscuit, KeyPair, PublicKey, TokenError, TokenTimeConfig, decode_token, encode_token,
    parse_token, public_key_from_pem_file,
};
