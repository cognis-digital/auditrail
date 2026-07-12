use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, BufReader, BufWriter};
use std::path::PathBuf;

// =============================================================================
// Core Data Structures
// =============================================================================

/// A single log entry with tamper-evident properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: u64,
    pub timestamp: u64, // Unix nanoseconds
    pub source_id: String,
    pub raw_content: String,
    /// Hash of (id + timestamp + source_id + raw_content)
    pub content_hash: [u8; 32],
    /// Running hash of the entire chain up to this entry
    pub chain_hash: [u8; 32],
}

/// The running state of the audit chain.
#[derive(Debug, Clone)]
pub struct ChainState {
    pub next_id: u64,
    pub current_chain_hash: [u8; 32],
    pub entry_count: u64,
}

// =============================================================================
// Cryptographic Utilities
// =============================================================================

/// Compute SHA-256 hash of a string.
fn compute_content_hash(content: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hasher.finalize().into()
}

/// Compute running chain hash by appending current content to previous state.
fn compute_chain_hash(prev: &[u8; 32], entry_id: u64, ts: u64, source: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&prev);
    hasher.write_u64(entry_id);
    hasher.write_u64(ts);
    hasher.write(source.as_bytes());
    hasher.finalize().into()
}

// =============================================================================
// AuditStore: Persistent Storage with Verification
// =============================================================================

pub struct AuditStore {
    path: PathBuf,
    state: ChainState,
}

impl AuditStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut state = ChainState::default();
        
        // Load existing state if present
        if let Ok(json) = fs::read_to_string(&path.join("state.json")) {
            if let Ok(deserialized) = serde_json::from_str::<ChainState>(&json) {
                state = deserialized;
            }
        }

        Self { path, state }
    }

    /// Persist current state.
    fn save_state(&self) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string(&self.state)?;
        fs::write(self.path.join("state.json"), &json)?;
        Ok(())
    }

    /// Load all entries from disk.
    fn load_entries() -> Result<Vec<LogEntry>, Box<dyn std::error::Error>> {
        let mut entries = Vec::new();
        
        // Try to read the main log file
        if let Ok(json) = fs::read_to_string(self.path.join("entries.json")) {
            if !json.trim().is_empty() {
                entries = serde_json::from_str(&json)?;
            }
        }

        // Fallback: scan directory for .log files
        if entries.is_empty() {
            let mut dir_reader = fs::read_dir(self.path.join("logs"))?;
            while let Ok(entry) = dir_reader.next() {
                let path = entry?.path();
                if path.extension().map_or(false, |e| e == "log") {
                    let mut file = File::open(&path)?;
                    let mut content = String::new();
                    file.read_to_string(&mut content)?;
                    
                    if !content.trim().is_empty() {
                        if let Ok(deserialized) = serde_json::from_str::<LogEntry>(&content) {
                            entries.push(deserialized);
                        }
                    }
                }
            }
        }

        // Sort by timestamp for consistency
        entries.sort_by_key(|e| e.timestamp);
        
        Ok(entries)
    }

    /// Verify that the chain is intact from a given checkpoint.
    pub fn verify_chain(&self, checkpoint: u64) -> Result<bool, Box<dyn std::error::Error>> {
        let mut loaded = Self::load_entries()?;
        
        // Filter to entries at or after checkpoint
        let start_idx = loaded.iter().position(|e| e.id >= checkpoint).unwrap_or(0);
        let chain = &loaded[start_idx..];

        let mut expected_hash: [u8; 32] = self.state.current_chain_hash;
        
        for entry in chain {
            // Recompute what the hash should be after this entry
            let next_hash = compute_chain_hash(
                &expected_hash,
                entry.id,
                entry.timestamp,
                &entry.source_id,
            );
            
            if expected_hash != next_hash {
                return Ok(false);
            }
            expected_hash = next_hash;
        }

        // Final check: does the last computed hash match what we expect?
        let final_expected = compute_chain_hash(
            &expected_hash,
            checkpoint + chain.len() as u64,
            0,
            "",
        );
        
        Ok(expected_hash == self.state.current_chain_hash)
    }

    /// Verify a specific entry's content hash.
    pub fn verify_entry(&self, id: u64) -> Result<bool, Box<dyn std::error::Error>> {
        let entries = Self::load_entries()?;
        
        match entries.iter().find(|e| e.id == id) {
            Some(entry) => {
                let computed = compute_content_hash(&entry.raw_content);
                Ok(computed == entry.content_hash)
            }
            None => Ok(false),
        }
    }

    /// Get the chain hash at a specific point (for attestation).
    pub fn get_chain_hash_at(&self, id: u64) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let entries = Self::load_entries()?;
        
        // Find all entries up to and including the requested ID
        let cutoff = entries.iter().position(|e| e.id > id).unwrap_or(entries.len());
        let chain = &entries[..cutoff];

        let mut hash: [u8; 32] = self.state.current_chain_hash;
        
        for entry in chain {
            hash = compute_chain_hash(&hash, entry.id, entry.timestamp, &entry.source_id);
        }

        Ok(hash)
    }

    /// Create an attestation proof for a given checkpoint.
    pub fn create_attestation(&self, checkpoint: u64) -> Result<AttestationProof, Box<dyn std::error::Error>> {
        let hash = self.get_chain_hash_at(checkpoint)?;
        
        // Include metadata about the state at that point
        let entries = Self::load_entries()?;
        let count = entries.iter().filter(|e| e.id <= checkpoint).count();

        Ok(AttestationProof {
            checkpoint,
            chain_hash: hash,
            entry_count: count as u64,
            timestamp: self.state.current_chain_hash[0] as u32, // Simplified
        })
    }
}

// =============================================================================
// Ingestion Pipeline
// =============================================================================

pub struct IngestionPipeline {
    store: AuditStore,
}

impl IngestionPipeline {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let store = AuditStore::new(path);
        Self { store }
    }

    /// Ingest a single log entry. Returns the updated chain hash for attestation.
    pub fn ingest(&mut self, source_id: &str, content: &str) -> Result<AttestationProof, Box<dyn std::error::Error>> {
        let entries = Self::load_entries()?;
        
        // Compute new entry data
        let id = self.store.state.next_id;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let content_hash = compute_content_hash(content);
        
        // Compute new chain hash
        let chain_hash = compute_chain_hash(
            &self.store.state.current_chain_hash,
            id,
            timestamp,
            source_id,
        );

        // Create the entry record
        let entry = LogEntry {
            id,
            timestamp,
            source_id: source_id.to_string(),
            raw_content: content.to_string(),
            content_hash,
            chain_hash,
        };

        // Update state
        self.store.state.next_id += 1;
        self.store.state.current_chain_hash = chain_hash;
        self.store.state.entry_count += 1;

        // Persist changes
        self.store.save_state()?;

        // Append to entries file
        let mut entries_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.store.path.join("entries.json"))?;
        
        let entry_json = serde_json::to_string(&entry)?;
        writeln!(entries_file, "{}", entry_json)?;

        // Create attestation proof
        self.store.save_state()?;
        let proof = self.store.create_attestation(id)?;

        Ok(proof)
    }

    /// Ingest multiple entries in a batch.
    pub fn ingest_batch(&mut self, entries: &[(&str, &str)]) -> Result<Vec<AttestationProof>, Box<dyn std::error::Error>> {
        let mut proofs = Vec::new();
        
        for (source_id, content) in entries.iter() {
            let proof = self.ingest(source_id, *content)?;
            proofs.push(proof);
        }

        Ok(proofs)
    }

    /// Get current chain hash for attestation.
    pub fn get_current_chain_hash(&self) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        self.store.get_chain_hash_at(self.store.state.next_id - 1)
    }

    /// Export the entire chain as a snapshot (for backup/verification).
    pub fn export_snapshot(&mut self, path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
        let entries = Self::load_entries()?;
        
        let mut file = File::create(path.as_ref())?;
        for entry in &entries {
            writeln!(file, "{}", serde_json::to_string(entry)?)?;
        }

        // Also export state
        let state_json = serde_json::to_string(&self.store.state)?;
        writeln!(file, "---STATE---\n{}", state_json)?;

        Ok(())
    }
}

// =============================================================================
// Attestation Proof
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationProof {
    pub checkpoint: u64,
    pub chain_hash: [u8; 32],
    pub entry_count: u64,
    pub timestamp: u64,
}

// =============================================================================
// Default Implementations
// =============================================================================

impl Default for ChainState {
    fn default() -> Self {
        Self {
            next_id: 1,
            current_chain_hash: [0u8; 32],
            entry_count: 0,
        }
    }
}

// =============================================================================
// Demo / Entry Point
// =============================================================================

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for our audit store
    let temp_dir = std::env::temp_dir().join(format!("auditrail_demo_{}", 
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)));

    fs::create_dir_all(&temp_dir)?;
    
    println!("AuditTrail Demo");
    println!("================\n");
    println!("Store path: {:?}", temp_dir);
    println!();

    // Create the pipeline
    let mut pipeline = IngestionPipeline::new(&temp_dir);

    // Sample log entries to ingest
    let sample_entries = vec![
        ("webserver-01", "Request received from 192.168.1.100:45321"),
        ("database-primary", "Query executed in 42ms, rows: 150"),
        ("cache-service", "Cache hit for key 'user:admin'"),
        ("auth-gateway", "Token validated for user 'alice@example.com'"),
    ];

    println!("Ingesting {} entries...", sample_entries.len());
    
    let proofs = pipeline.ingest_batch(&sample_entries)?;

    // Display results
    println!("\n--- Ingestion Results ---\n");
    
    for (i, proof) in proofs.iter().enumerate() {
        println!("Entry #{}:", i + 1);
        println!("  Checkpoint: {}", proof.checkpoint);
        println!("  Entry Count: {}", proof.entry_count);
        println!("  Chain Hash: {:02x?}", &proof.chain_hash[..8]); // Truncated for display
    }

    // Verify the chain
    println!("\n--- Verification ---\n");
    
    let final_hash = pipeline.get_current_chain_hash()?;
    println!("Final Chain Hash: {:02x?}", &final_hash[..8]);

    // Export a snapshot
    let snapshot_path = temp_dir.join("snapshot.json");
    pipeline.export_snapshot(&snapshot_path)?;
    println!("\nSnapshot exported to: {:?}", snapshot_path);

    // Verify against the snapshot (simulated - in real use, read from file)
    println!("\n--- Snapshot Verification ---\n");
    
    if let Ok(content) = fs::read_to_string(&snapshot_path) {
        let entries: Vec<LogEntry> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_default())
            .collect();

        println!("Loaded {} entries from snapshot", entries.len());
        
        // Verify each entry's content hash
        let mut all_valid = true;
        for entry in &entries {
            let computed = compute_content_hash(&entry.raw_content);
            if computed == entry.content_hash {
                println!("  Entry #{}: ✓ Content hash valid", entry.id);
            } else {
                println!("  Entry #{}: ✗ Content hash MISMATCH!", entry.id);
                all_valid = false;
            }
        }

        // Verify chain integrity
        let mut expected_hash: [u8; 32] = final_hash;
        for entry in &entries {
            let next = compute_chain_hash(
                &expected_hash,
                entry.id,
                entry.timestamp,
                &entry.source_id,
            );
            
            if expected_hash == next {
                println!("  Chain link #{}: ✓", entry.id);
            } else {
                println!("  Chain link #{}: ✗ BROKEN!", entry.id);
                all_valid = false;
            }
            expected_hash = next;
        }

        if all_valid {
            println!("\n✓ Full chain verification PASSED");
        } else {
            println!("\n✗ Full chain verification FAILED - tampering detected!");
        }
    }

    // Demonstrate tamper detection
    println!("\n--- Tamper Detection Demo ---\n");
    
    let mut corrupted_entries = fs::read_to_string(&snapshot_path)?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_default())
        .collect();

    // Corrupt one entry's content hash
    if let Some(entry) = corrupted_entries.get_mut(1) {
        entry.content_hash[0] ^= 0xFF; // Flip all bits in first byte
    }

    println!("Corrupted entry #2's content hash...");
    
    let mut expected: [u8; 32] = final_hash;
    for (i, entry) in corrupted_entries.iter().enumerate() {
        let next = compute_chain_hash(
            &expected,
            entry.id,
            entry.timestamp,
            &entry.source_id,
        );

        if expected == next {
            println!("  Entry #{}: ✓", i + 1);
        } else {
            println