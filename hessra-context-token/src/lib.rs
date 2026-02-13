//! # Hessra Context Token
//!
//! Context token implementation for information flow control (taint tracking)
//! in the Hessra authorization system.
//!
//! Context tokens track what data an object (typically an AI agent) has been
//! exposed to during a session. Each data access adds taint labels as
//! append-only Biscuit blocks, which downstream systems use to restrict
//! available capabilities.
//!
//! ## Key Properties
//!
//! - **Append-only**: Taint labels accumulate and cannot be removed within a session
//! - **Cryptographically enforced**: Each taint block is signed, preventing forgery
//! - **Inheritable**: Child contexts inherit parent taint via `fork_context`
//! - **Stateless verification**: Only a public key is needed to verify
//!
//! ## Authority Block
//!
//! ```datalog
//! context(subject);
//! check if time($time), $time < expiration;
//! ```
//!
//! ## Taint Blocks
//!
//! Each taint addition appends a block with:
//! ```datalog
//! taint("PII:SSN");
//! taint_source("data:user-ssn");
//! taint_time(1234567890);
//! ```
//!
//! ## Example
//!
//! ```rust
//! use hessra_context_token::{HessraContext, ContextVerifier, add_taint, extract_taint_labels};
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
//! // Add taint labels
//! let tainted = add_taint(
//!     &token,
//!     public_key,
//!     &["PII:SSN".to_string()],
//!     "data:user-ssn".to_string(),
//! ).expect("Failed to add taint");
//!
//! // Extract taint labels
//! let labels = extract_taint_labels(&tainted, public_key)
//!     .expect("Failed to extract taint");
//! assert_eq!(labels, vec!["PII:SSN".to_string()]);
//!
//! // Verify the context token
//! ContextVerifier::new(tainted, public_key)
//!     .verify()
//!     .expect("Failed to verify context token");
//! ```

mod inspect;
mod mint;
mod taint;
mod verify;

pub use inspect::{ContextInspectResult, inspect_context_token};
pub use mint::HessraContext;
pub use taint::{add_taint, extract_taint_labels, fork_context};
pub use verify::ContextVerifier;

// Re-export commonly needed types from core
pub use hessra_token_core::{
    Biscuit, KeyPair, PublicKey, TokenError, TokenTimeConfig, decode_token, encode_token,
    parse_token, public_key_from_pem_file,
};
