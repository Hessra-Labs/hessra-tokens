//! # Hessra Token Core
//!
//! Core utilities and types shared across Hessra token implementations.
//!
//! This crate provides common functionality used by both capability tokens
//! and identity tokens, including:
//!
//! - Token encoding/decoding utilities
//! - Time configuration for token validity
//! - Common error types
//! - Token classification and analysis
//! - Biscuit type re-exports

pub mod classifier;
pub mod error;
pub mod revocation;
pub mod rule_parser;
pub mod time;
pub mod utils;

pub use classifier::{
    BlockMetadata, BlockType, TokenClassification, TokenStructure, TokenType, classify_token,
};
pub use error::{CheckFailure, TokenError};
pub use revocation::{
    RevocationId, get_authority_revocation_id, get_block_revocation_id, get_revocation_ids,
};
pub use rule_parser::{parse_capability_failure, parse_check_failure};
pub use time::TokenTimeConfig;
pub use utils::{decode_token, encode_token, parse_token, public_key_from_pem_file};

// Re-export biscuit types that are needed for public API
pub use biscuit_auth::{Biscuit, KeyPair, PublicKey};
