//! # Hessra Capability Token
//!
//! Capability token implementation for the Hessra authorization system.
//!
//! This crate provides functionality for creating, verifying, and attenuating capability
//! tokens (biscuit tokens). Capability tokens follow the principle that presenting the
//! capability IS the authorization -- no subject verification is required by default.
//!
//! ## Key Design
//!
//! The authority block contains:
//! ```datalog
//! right(subject, resource, operation);
//! check if resource($res), operation($op), right($sub, $res, $op);
//! check if time($time), $time < expiration;
//! ```
//!
//! Note: `subject` is NOT checked by default. The `right` fact retains the subject
//! for auditing purposes, but the verifier only needs to provide `resource` and `operation`.
//!
//! ## Optional Subject Verification
//!
//! When stronger guarantees are needed, the verifier can opt into subject checking:
//! ```rust,no_run
//! # use hessra_cap_token::CapabilityVerifier;
//! # use hessra_token_core::KeyPair;
//! # let keypair = KeyPair::new();
//! # let public_key = keypair.public();
//! # let token = String::new();
//! CapabilityVerifier::new(token, public_key, "resource".into(), "read".into())
//!     .with_subject("alice".into())  // optional subject check
//!     .verify();
//! ```

pub(crate) mod attenuate;
mod mint;
mod revocation;
pub(crate) mod verify;

pub use attenuate::{add_prefix_restriction, add_prefix_restriction_to_token};
pub use mint::{HessraCapability, create_biscuit, create_token, create_token_with_time};
pub use revocation::{get_capability_revocation_id, get_capability_revocation_id_from_bytes};
pub use verify::{CapabilityVerifier, biscuit_key_from_string, verify_token_local};

// Re-export commonly needed types from core
pub use hessra_token_core::{
    Biscuit, KeyPair, PublicKey, TokenError, TokenTimeConfig, decode_token, encode_token,
    parse_token, public_key_from_pem_file,
};
