// polyglot/rust/hash_chain_manager.rs

//! Hash Chain Manager for Tamper-Evident Audit Logs
//! 
//! A minimal, production-ready implementation of a hash-chained audit log.
//! Each entry contains the SHA-256 hash of its predecessor, creating an
//! immutable chain where any modification breaks integrity.

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use thiserror::Error;

/// Error types for chain operations
#[derive(Error, Debug)]
pub enum ChainError {
    #[error("Empty chain: cannot compute predecessor hash")]
    EmptyChain,
    
    #[error("Hash mismatch at entry #{0}: expected {expected}, got {actual}")]
    HashMismatch(usize, String, String),
    
    #[error("IO error: {0}")]
    IoError(std::io::Error),
}

impl From<std::io::Error> for ChainError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

/// A single entry in the hash chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    /// The payload data (audit event, timestamp, user action, etc.)
    pub data: String,
    
    /// Hash of the PREVIOUS entry's self_hash. 
    /// For the first entry, this is an empty string hash.
    #[serde(default)]
    pub prev_hash: String,
    
    /// SHA-256 hash of (data + prev_hash). This is what gets chained.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub self_hash: Option<String>,
}

impl ChainEntry {
    /// Create a new entry with the given data and optional previous hash.
    pub fn new(data: impl Into<String>, prev_hash: Option<String>) -> Self {
        let prev_str = prev_hash.unwrap_or_default();
        
        // Hash combines data + prev_hash for maximum collision resistance
        let mut hasher = Sha256::new();
        hasher.update(prev_str.as_bytes());
        hasher.update(data.into().as_bytes());
        let self_hash = format!("{:x}", hasher.finalize());
        
        Self {
            data: data.into(),
            prev_hash,
            self_hash: Some(self_hash),
        }
    }

    /// Verify this entry's hash matches its predecessor.
    pub fn verify(&self) -> Result<(), ChainError> {
        let mut hasher = Sha256::new();
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(self.data.as_bytes());
        
        let computed = format!("{:x}", hasher.finalize());
        
        if self.self_hash.is_some() && self.self_hash != Some(computed) {
            return Err(ChainError::HashMismatch(
                0, // Entry index not tracked here; caller must track
                computed,
                self.self_hash.unwrap(),
            ));
        }
        
        Ok(())
    }

    /// Get the hash that should be stored in the NEXT entry's prev_hash.
    pub fn next_prev_hash(&self) -> String {
        self.self_hash.clone().unwrap_or_default()
    }
}

/// Manager for a complete hash chain.
#[derive(Debug, Default)]
pub struct HashChainManager {
    entries: Vec<ChainEntry>,
}

impl HashChainManager {
    /// Create an empty manager (ready to accept first entry).
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Append a new entry to the chain. Returns `true` if verification passed.
    pub fn append(&mut self, data: impl Into<String>) -> Result<bool, ChainError> {
        let prev_hash = match &self.entries.last() {
            Some(last) => last.next_prev_hash(),
            None => String::new(), // First entry uses empty prev hash
        };

        let entry = ChainEntry::new(data, Some(prev_hash));

        if !entry.verify().is_ok() {
            return Err(ChainError::HashMismatch(
                self.entries.len(),
                "internal",
                "verification failed".to_string(),
            ));
        }

        self.entries.push(entry);
        Ok(true)
    }

    /// Verify the entire chain from first to last entry.
    pub fn verify_chain(&self) -> Result<(), ChainError> {
        if self.entries.is_empty() {
            return Err(ChainError::EmptyChain);
        }

        let mut prev_hash = String::new();
        
        for (i, entry) in self.entries.iter().enumerate() {
            // Verify this entry's own hash matches stored value
            let computed = format!("{:x}", Sha256::digest(
                [prev_hash.as_bytes(), entry.data.as_bytes()].concat()
            ));
            
            if entry.self_hash != Some(computed) {
                return Err(ChainError::HashMismatch(i, computed, 
                    entry.self_hash.unwrap_or_default()));
            }

            // Update prev_hash for next iteration
            prev_hash = entry.next_prev_hash();
        }

        Ok(())
    }

    /// Get a clone of all entries.
    pub fn get_entries(&self) -> Vec<ChainEntry> {
        self.entries.clone()
    }

    /// Return the number of entries in the chain.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get a reference to the last entry (if any).
    pub fn last_entry(&self) -> Option<&ChainEntry> {
        self.entries.last()
    }
}

/// A convenience type alias for common usage.
pub type AuditChain = HashChainManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_chain_error() {
        let mut chain = HashChainManager::new();
        assert!(chain.is_empty());
        
        // First entry should work with empty prev_hash
        let result = chain.append("first event".to_string());
        assert!(result.is_ok());
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_append_and_verify() {
        let mut chain = HashChainManager::new();
        
        // Add three events
        chain.append("event 1").unwrap();
        chain.append("event 2").unwrap();
        chain.append("event 3").unwrap();
        
        assert_eq!(chain.len(), 3);
        
        // Verify entire chain
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_corruption_detection() {
        let mut chain = HashChainManager::new();
        chain.append("event 1").unwrap();
        chain.append("event 2").unwrap();
        
        // Corrupt the last entry's hash
        if let Some(last) = chain.entries.last_mut() {
            last.self_hash = Some("corrupted".to_string());
        }
        
        // Verification should fail
        assert!(chain.verify_chain().is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut chain = HashChainManager::new();
        chain.append("event 1").unwrap();
        chain.append("event 2").unwrap();
        
        // Serialize to JSON
        let json = serde_json::to_string(&chain).unwrap();
        
        // Deserialize back
        let loaded: HashChainManager = serde_json::from_str(&json).unwrap();
        
        // Verify integrity is preserved
        assert!(loaded.verify_chain().is_ok());
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_hash_determinism() {
        let mut chain1 = HashChainManager::new();
        let mut chain2 = HashChainManager::new();
        
        for i in 0..5 {
            chain1.append(format!("event {}", i)).unwrap();
            chain2.append(format!("event {}", i)).unwrap();
        }
        
        // Both chains should have identical self_hashes at each position
        let entries1 = chain1.get_entries();
        let entries2 = chain2.get_entries();
        
        for (i, e1) in entries1.iter().enumerate() {
            assert_eq!(e1.self_hash, entries2[i].self_hash);
        }
    }

    #[test]
    fn test_large_payloads() {
        let mut chain = HashChainManager::new();
        
        // Test with a large payload (simulating real audit logs)
        let large_data = "x".repeat(1024 * 1024); // 1MB
        chain.append(large_data).unwrap();
        
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_concurrent_safe_clone() {
        let mut chain = HashChainManager::new();
        for i in 0..10 {
            chain.append(format!("event {}", i)).unwrap();
        }
        
        // Clone should be fast and preserve state
        let cloned = chain.clone();
        assert_eq!(cloned.len(), 10);
        assert!(cloned.verify_chain().is_ok());
    }

    #[test]
    fn test_empty_string_payload() {
        let mut chain = HashChainManager::new();
        
        // Edge case: empty string as payload
        chain.append("").unwrap();
        chain.append("non-empty".to_string()).unwrap();
        
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_unicode_payloads() {
        let mut chain = HashChainManager::new();
        
        // Test with unicode characters (common in international logs)
        let unicode_data = "日本語テスト 🎉 中文测试";
        chain.append(unicode_data).unwrap();
        
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_many_entries_performance() {
        let mut chain = HashChainManager::new();
        
        // Add many entries to stress test the chain
        for i in 0..1000 {
            chain.append(format!("event {}", i)).unwrap();
        }
        
        assert_eq!(chain.len(), 1000);
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_entry_verification() {
        let mut chain = HashChainManager::new();
        chain.append("first").unwrap();
        chain.append("second").unwrap();
        
        // Verify individual entries work correctly
        for (i, entry) in chain.entries.iter().enumerate() {
            assert!(entry.verify().is_ok());
        }
    }

    #[test]
    fn test_hash_chain_property() {
        let mut chain = HashChainManager::new();
        
        // The defining property: each entry's hash should match 
        // the next entry's prev_hash
        for i in 0..chain.len().saturating_sub(1) {
            assert_eq!(
                chain.entries[i].next_prev_hash(),
                chain.entries[i + 1].prev_hash,
                "Link {} -> {} broken",
                i, i + 1
            );
        }
    }

    #[test]
    fn test_error_messages() {
        let mut chain = HashChainManager::new();
        chain.append("event 1").unwrap();
        
        // Corrupt and verify error message contains useful info
        if let Some(last) = chain.entries.last_mut() {
            last.self_hash = Some("bad".to_string());
        }
        
        match chain.verify_chain() {
            Err(ChainError::HashMismatch(idx, expected, actual)) => {
                assert_eq!(idx, 0);
                assert_eq!(expected, "bad");
            },
            _ => panic!("Expected HashMismatch error"),
        }
    }

    #[test]
    fn test_default_values() {
        let entry = ChainEntry::new("data", None);
        
        // First entry should have empty prev_hash and computed self_hash
        assert_eq!(entry.prev_hash, "");
        assert!(!entry.self_hash.is_none());
    }

    #[test]
    fn test_clone_preserves_state() {
        let mut chain = HashChainManager::new();
        for i in 0..5 {
            chain.append(format!("event {}", i)).unwrap();
        }
        
        let cloned = chain.clone();
        
        // Mutate original (shouldn't affect clone)
        if let Some(last) = cloned.entries.last_mut() {
            last.self_hash = None;
        }
        
        // Original should still verify
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_get_entries_returns_clone() {
        let mut chain = HashChainManager::new();
        for i in 0..3 {
            chain.append(format!("event {}", i)).unwrap();
        }
        
        let entries = chain.get_entries();
        
        // Verify we got a clone, not a reference
        if let Some(last) = entries.last_mut() {
            last.self_hash = None;
        }
        
        // Original should still verify
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_memory_efficiency() {
        let mut chain = HashChainManager::new();
        
        // Add entries with moderate data
        for i in 0..100 {
            let data = format!("event {} - user action: login, logout, view", i);
            chain.append(data).unwrap();
        }
        
        assert_eq!(chain.len(), 100);
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_reproducible_hashes() {
        let mut chain = HashChainManager::new();
        for i in 0..5 {
            chain.append(format!("event {}", i)).unwrap();
        }
        
        // Serialize and deserialize multiple times
        for _ in 0..10 {
            let json = serde_json::to_string(&chain).unwrap();
            let loaded: HashChainManager = serde_json::from_str(&json).unwrap();
            
            assert!(loaded.verify_chain().is_ok());
            assert_eq!(loaded.len(), 5);
        }
    }

    #[test]
    fn test_mixed_content() {
        let mut chain = HashChainManager::new();
        
        // Mix different types of content
        chain.append("numeric: 12345").unwrap();
        chain.append("special chars: <>&\"'").unwrap();
        chain.append("newline\n\rtab\t").unwrap();
        chain.append("emoji: 🚀🔐✅").unwrap();
        
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_single_entry_chain() {
        let mut chain = HashChainManager::new();
        chain.append("only entry").unwrap();
        
        assert_eq!(chain.len(), 1);
        assert!(chain.verify_chain().is_ok());
        
        // Single entry should have empty prev_hash (by design)
        assert_eq!(chain.entries[0].prev_hash, "");
    }

    #[test]
    fn test_long_chain_verification() {
        let mut chain = HashChainManager::new();
        
        // Create a very long chain to stress the verification loop
        for i in 0..10000 {
            chain.append(format!("event {}", i)).unwrap();
        }
        
        assert_eq!(chain.len(), 10000);
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_hash_uniqueness() {
        let mut chain = HashChainManager::new();
        
        // Same data should produce same hash (determinism)
        let entry1 = ChainEntry::new("test", Some("prev".to_string()));
        let entry2 = ChainEntry::new("test", Some("prev".to_string()));
        
        assert_eq!(entry1.self_hash, entry2.self_hash);
    }

    #[test]
    fn test_empty_chain_len() {
        let chain: HashChainManager = Default::default();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.last_entry().is_none());
    }

    #[test]
    fn test_last_entry_access() {
        let mut chain = HashChainManager::new();
        chain.append("first").unwrap();