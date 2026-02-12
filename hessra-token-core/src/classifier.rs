//! Token classification utilities for analyzing Biscuit token structure
//!
//! This module provides functionality to classify and analyze Hessra tokens,
//! extracting metadata about token type, structure, revocation IDs, and relationships.
//! This is primarily used for audit logging and building token relationship graphs.

use crate::{
    Biscuit,
    revocation::{RevocationId, get_revocation_ids},
};
use std::fmt;

/// The type of token
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenType {
    /// Identity token - represents an identity/principal
    Identity,
    /// Capability token - grants access to a resource
    Capability,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenType::Identity => write!(f, "identity"),
            TokenType::Capability => write!(f, "capability"),
        }
    }
}

/// The structural pattern of the token
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenStructure {
    /// Base token with no additional blocks (authority only)
    Base,
    /// Token with delegation blocks (identity tokens)
    Delegated { depth: usize },
    /// Token with JIT time attenuation/restriction
    TimeAttenuated,
    /// Token with multiple types of blocks
    Complex,
}

impl fmt::Display for TokenStructure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenStructure::Base => write!(f, "base"),
            TokenStructure::Delegated { depth } => write!(f, "delegated(depth={depth})"),
            TokenStructure::TimeAttenuated => write!(f, "time_attenuated"),
            TokenStructure::Complex => write!(f, "complex"),
        }
    }
}

/// The type/role of a specific block in a token
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockType {
    /// The authority (first) block
    Authority,
    /// A delegation block (for identity tokens)
    Delegation { delegated_identity: String },
    /// A time attenuation/restriction block
    TimeAttenuation,
    /// Unknown/other block type
    Other,
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockType::Authority => write!(f, "authority"),
            BlockType::Delegation { delegated_identity } => {
                write!(f, "delegation(identity={delegated_identity})")
            }
            BlockType::TimeAttenuation => write!(f, "time_attenuation"),
            BlockType::Other => write!(f, "other"),
        }
    }
}

/// Metadata about a specific block in a token
#[derive(Debug, Clone)]
pub struct BlockMetadata {
    /// The index of this block (0 = authority)
    pub index: usize,
    /// The revocation ID for this block
    pub revocation_id: RevocationId,
    /// The type/role of this block
    pub block_type: BlockType,
}

impl fmt::Display for BlockMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "block[{}]: {} (revoc_id={})",
            self.index,
            self.block_type,
            self.revocation_id.to_hex()
        )
    }
}

/// Complete classification of a token
#[derive(Debug, Clone)]
pub struct TokenClassification {
    /// The type of token
    pub token_type: TokenType,
    /// The structural pattern
    pub structure: TokenStructure,
    /// Metadata for each block
    pub blocks: Vec<BlockMetadata>,
    /// Subject/identity from the authority block
    pub subject: Option<String>,
    /// Resource (for capability tokens)
    pub resource: Option<String>,
    /// Operation (for capability tokens)
    pub operation: Option<String>,
}

impl TokenClassification {
    /// Get all revocation IDs from this token
    pub fn revocation_ids(&self) -> Vec<&RevocationId> {
        self.blocks.iter().map(|b| &b.revocation_id).collect()
    }

    /// Get the authority block's revocation ID
    pub fn authority_revocation_id(&self) -> Option<&RevocationId> {
        self.blocks.first().map(|b| &b.revocation_id)
    }

    /// Get the active/current revocation ID (last block)
    pub fn active_revocation_id(&self) -> Option<&RevocationId> {
        self.blocks.last().map(|b| &b.revocation_id)
    }

    /// Get the number of blocks
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

impl fmt::Display for TokenClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Token Classification:")?;
        writeln!(f, "  Type: {}", self.token_type)?;
        writeln!(f, "  Structure: {}", self.structure)?;
        if let Some(subject) = &self.subject {
            writeln!(f, "  Subject: {subject}")?;
        }
        if let Some(resource) = &self.resource {
            writeln!(f, "  Resource: {resource}")?;
        }
        if let Some(operation) = &self.operation {
            writeln!(f, "  Operation: {operation}")?;
        }
        writeln!(f, "  Blocks ({}):", self.blocks.len())?;
        for block in &self.blocks {
            writeln!(f, "    {block}")?;
        }
        Ok(())
    }
}

/// Classify a token by analyzing its structure and contents
///
/// This function examines a Biscuit token and extracts:
/// - Token type (identity vs capability)
/// - Token structure (base, delegated, etc.)
/// - All revocation IDs with their roles
/// - Subject, resource, operation (as applicable)
///
/// # Arguments
/// * `biscuit` - The Biscuit token to classify
///
/// # Returns
/// * `TokenClassification` - Complete classification of the token
pub fn classify_token(biscuit: &Biscuit) -> TokenClassification {
    // Get all revocation IDs
    let revocation_ids = get_revocation_ids(biscuit);

    // Get the token content for parsing
    let content = biscuit.print();

    // Determine token type and extract metadata
    let (token_type, subject, resource, operation) = determine_token_type(&content);

    // Analyze blocks to determine structure and classify each block
    let blocks = classify_blocks(biscuit, &revocation_ids, &content);

    // Determine the overall structure
    let structure = determine_structure(&blocks);

    TokenClassification {
        token_type,
        structure,
        blocks,
        subject,
        resource,
        operation,
    }
}

/// Determine the token type and extract basic metadata
fn determine_token_type(
    content: &str,
) -> (TokenType, Option<String>, Option<String>, Option<String>) {
    let mut is_identity = false;
    let mut is_capability = false;
    let mut subject = None;
    let mut resource = None;
    let mut operation = None;

    for line in content.lines() {
        let trimmed = line.trim();

        // Look for identity token markers
        if trimmed.starts_with("subject(") {
            is_identity = true;
            subject = extract_quoted_value(trimmed, "subject(");
        }

        // Look for capability token markers
        if trimmed.starts_with("right(") {
            is_capability = true;
            // right("subject", "resource", "operation")
            if let Some(values) = extract_right_values(trimmed) {
                subject = Some(values.0);
                resource = Some(values.1);
                operation = Some(values.2);
            }
        }
    }

    let token_type = if is_identity {
        TokenType::Identity
    } else if is_capability {
        TokenType::Capability
    } else {
        // Default to capability if unclear
        TokenType::Capability
    };

    (token_type, subject, resource, operation)
}

/// Classify all blocks in the token
fn classify_blocks(
    _biscuit: &Biscuit,
    revocation_ids: &[RevocationId],
    content: &str,
) -> Vec<BlockMetadata> {
    let mut blocks = Vec::new();

    // Parse the authority block (index 0)
    if let Some(auth_rev_id) = revocation_ids.first() {
        blocks.push(BlockMetadata {
            index: 0,
            revocation_id: auth_rev_id.clone(),
            block_type: BlockType::Authority,
        });
    }

    // Parse additional blocks if present
    if revocation_ids.len() > 1 {
        // Look for "blocks: [" section in the content
        if let Some(blocks_start) = content.find("blocks: [") {
            let blocks_section = &content[blocks_start..];

            // Split into individual block sections
            let block_strings: Vec<&str> = blocks_section
                .split("Block {")
                .skip(1) // Skip the part before the first block
                .collect();

            for (idx, block_str) in block_strings.iter().enumerate() {
                let block_index = idx + 1; // +1 because block 0 is authority
                if let Some(rev_id) = revocation_ids.get(block_index) {
                    let block_type = classify_block_type(block_str);
                    blocks.push(BlockMetadata {
                        index: block_index,
                        revocation_id: rev_id.clone(),
                        block_type,
                    });
                }
            }
        }
    }

    blocks
}

/// Classify the type of a specific block based on its content
fn classify_block_type(block_content: &str) -> BlockType {
    // Check for delegation (delegated_identity fact)
    if block_content.contains("delegated_identity(") {
        if let Some(identity) = extract_quoted_value(block_content, "delegated_identity(") {
            return BlockType::Delegation {
                delegated_identity: identity,
            };
        }
    }

    // Check for time attenuation (time checks)
    if block_content.contains("time(") && block_content.contains("check if") {
        return BlockType::TimeAttenuation;
    }

    BlockType::Other
}

/// Determine the overall token structure based on classified blocks
fn determine_structure(blocks: &[BlockMetadata]) -> TokenStructure {
    if blocks.len() == 1 {
        return TokenStructure::Base;
    }

    let mut has_delegation = false;
    let mut delegation_count = 0;
    let mut has_time_attenuation = false;

    for block in blocks.iter().skip(1) {
        // Skip authority block
        match &block.block_type {
            BlockType::Delegation { .. } => {
                has_delegation = true;
                delegation_count += 1;
            }
            BlockType::TimeAttenuation => {
                has_time_attenuation = true;
            }
            _ => {}
        }
    }

    // Determine structure based on combinations
    let complexity_count = [has_delegation, has_time_attenuation]
        .iter()
        .filter(|&&x| x)
        .count();

    if complexity_count > 1 {
        TokenStructure::Complex
    } else if has_delegation {
        TokenStructure::Delegated {
            depth: delegation_count,
        }
    } else if has_time_attenuation {
        TokenStructure::TimeAttenuated
    } else {
        TokenStructure::Base
    }
}

/// Extract a quoted string value from a fact
fn extract_quoted_value(line: &str, prefix: &str) -> Option<String> {
    if let Some(start_idx) = line.find(prefix) {
        let after_prefix = &line[start_idx + prefix.len()..];
        if let Some(first_quote) = after_prefix.find('"') {
            if let Some(second_quote) = after_prefix[first_quote + 1..].find('"') {
                return Some(
                    after_prefix[first_quote + 1..first_quote + 1 + second_quote].to_string(),
                );
            }
        }
    }
    None
}

/// Extract the three values from a right() fact
fn extract_right_values(line: &str) -> Option<(String, String, String)> {
    if let Some(start) = line.find("right(") {
        let content = &line[start + 6..];
        if let Some(end) = content.find(')') {
            let values_str = &content[..end];
            let values: Vec<&str> = values_str.split(',').map(|s| s.trim()).collect();

            if values.len() == 3 {
                let subject = values[0].trim_matches('"').to_string();
                let resource = values[1].trim_matches('"').to_string();
                let operation = values[2].trim_matches('"').to_string();
                return Some((subject, resource, operation));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use biscuit_auth::macros::biscuit;

    #[test]
    fn test_classify_base_capability_token() {
        let keypair = KeyPair::new();

        let biscuit = biscuit!(
            r#"
                right("alice", "resource1", "read");
            "#
        )
        .build(&keypair)
        .unwrap();

        let classification = classify_token(&biscuit);

        assert_eq!(classification.token_type, TokenType::Capability);
        assert_eq!(classification.structure, TokenStructure::Base);
        assert_eq!(classification.block_count(), 1);
        assert_eq!(classification.subject, Some("alice".to_string()));
        assert_eq!(classification.resource, Some("resource1".to_string()));
        assert_eq!(classification.operation, Some("read".to_string()));

        assert_eq!(classification.blocks[0].block_type, BlockType::Authority);
    }

    #[test]
    fn test_revocation_id_extraction() {
        let keypair = KeyPair::new();

        let biscuit = biscuit!(
            r#"
                right("alice", "resource1", "read");
            "#
        )
        .build(&keypair)
        .unwrap();

        let classification = classify_token(&biscuit);

        let auth_id = classification.authority_revocation_id();
        assert!(auth_id.is_some());
        assert!(!auth_id.unwrap().to_hex().is_empty());

        let active_id = classification.active_revocation_id();
        assert!(active_id.is_some());
        assert_eq!(auth_id, active_id);
    }

    #[test]
    fn test_display_classification() {
        let keypair = KeyPair::new();

        let biscuit = biscuit!(
            r#"
                right("alice", "resource1", "read");
            "#
        )
        .build(&keypair)
        .unwrap();

        let classification = classify_token(&biscuit);
        let display_str = format!("{classification}");

        assert!(display_str.contains("Token Classification"));
        assert!(display_str.contains("Type: capability"));
        assert!(display_str.contains("Structure: base"));
        assert!(display_str.contains("Subject: alice"));
    }
}
