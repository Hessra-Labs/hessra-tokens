//! # Hessra Context Token
//!
//! Context token implementation for information flow control (exposure tracking)
//! in the Hessra authorization system.
//!
//! Context tokens track what data an object (typically an AI agent) has been
//! exposed to during a session. Each data access adds exposure labels as
//! append-only Biscuit blocks, which downstream systems use to restrict
//! available capabilities.
//!
//! ## Key Properties
//!
//! - **Append-only**: Exposure labels accumulate and cannot be removed within a session
//! - **Cryptographically enforced**: Each exposure block is signed, preventing forgery
//! - **Inheritable**: Child contexts inherit parent exposure via `fork_context`
//! - **Stateless verification**: Only a public key is needed to verify
//!
//! ## Authority Block
//!
//! ```datalog
//! context(subject);
//! check if time($time), $time < expiration;
//! ```
//!
//! ## Exposure Blocks
//!
//! Each exposure addition appends a block with:
//! ```datalog
//! exposure("PII:SSN");
//! exposure_source("data:user-ssn");
//! exposure_time(1234567890);
//! ```
//!
//! ## Example
//!
//! ```rust
//! use hessra_context_token::{HessraContext, ContextVerifier, add_exposure, extract_exposure_labels};
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
//! // Add exposure labels
//! let exposed = add_exposure(
//!     &token,
//!     public_key,
//!     &["PII:SSN".to_string()],
//!     "data:user-ssn".to_string(),
//! ).expect("Failed to add exposure");
//!
//! // Extract exposure labels (diagnostic only)
//! let labels = extract_exposure_labels(&exposed, public_key)
//!     .expect("Failed to extract exposure");
//! assert_eq!(labels, vec!["PII:SSN".to_string()]);
//!
//! // Verify the context token
//! ContextVerifier::new(exposed, public_key)
//!     .verify()
//!     .expect("Failed to verify context token");
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
