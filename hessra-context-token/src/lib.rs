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
//! - **Issuer-attested**: Each exposure block is a third-party biscuit block signed by
//!   the issuer's keypair. Verifier rules and queries use `trusting authority, {pubkey}`
//!   to scope authorization decisions to issuer-attested facts only.
//! - **Block-stacked**: All labels added in a single call land in the same block.
//! - **Inheritable**: Child contexts inherit parent exposure via `fork_context`.
//! - **Pure Datalog authorization**: Exclusion checks run as biscuit deny policies.
//!   No string parsing on the authz path.
//!
//! ## Authority Block
//!
//! ```datalog
//! context(subject);
//! check if time($time), $time < expiration;
//! // optional, only if mint-time exposures supplied:
//! exposure(label_1);
//! exposure(label_2);
//! exposure_source(source);
//! exposure_time(timestamp);
//! ```
//!
//! ## Third-party exposure blocks (one per `add_exposure` call)
//!
//! ```datalog
//! exposure(label_a);
//! exposure(label_b);
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
