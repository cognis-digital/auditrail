use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use blake3::Hasher;
use chrono::{DateTime, Utc};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write, BufWriter};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Error types for secure storage operations.
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Integrity check failed: expected {expected}, got {actual}"),]
    Integrity { expected: String, actual: String },
    
    #[error("Key not found or expired"),]
    KeyNotFound,
    
    #[error("Corrupted metadata at offset {0}"),]
    CorruptedMetadata(usize),
}

/// Configuration for secure storage adapter.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Path to the encrypted data directory.
    pub data_dir: PathBuf,
    
    /// Master key seed (will be derived into actual keys).
    pub master_seed: [u8; 32],
    
    /// Salt for key derivation (randomized per instance).
    pub salt: [u8; 16],
    
    /// Number of PBKDF2 iterations.
    pub kdf_iterations: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        let seed = hex::decode("0123456789abcdef0123456789abcdef").unwrap();
        let salt = hex::decode("fedcba9876543210fedcba9876543210").unwrap();
        
        Self {
            data_dir: PathBuf::from("./.auditrail_secure"),
            master_seed: seed.as_slice().try_into().unwrap(),
            salt,
            kdf_iterations: 100_000,
        }
    }
}

/// Metadata for a single audit record.
#[derive(Debug, Clone)]
pub struct RecordMetadata {
    pub sequence_number: u64,
    pub timestamp: DateTime<Utc>,
    pub size: usize,
    pub content_hash: [u8; 32],
    pub prev_hash: [u8; 32],
}

/// Encrypted storage record.
#[derive(Debug)]
pub struct EncryptedRecord {
    /// Nonce used for this encryption (also serves as part of the hash chain).
    nonce: Nonce,
    /// Ciphertext.
    ciphertext: Vec<u8>,
    /// Metadata with hash chaining.
    metadata: RecordMetadata,
}

impl EncryptedRecord {
    fn new(
        sequence_number: u64,
        timestamp: DateTime<Utc>,
        content_hash: [u8; 32],
        prev_hash: [u8; 32],
        nonce: Nonce,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            nonce,
            ciphertext,
            metadata: RecordMetadata {
                sequence_number,
                timestamp,
                size: ciphertext.len(),
                content_hash,
                prev_hash,
            },
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        // Write metadata first (fixed-size header)
        use serde::{Serialize, Serializer};
        
        impl Serialize for RecordMetadata {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_u64(self.sequence_number)?;
                serializer.serialize_i64(self.timestamp.timestamp())?;
                serializer.serialize_u32(self.size as u32)?;
                serializer.serialize_bytes(&self.content_hash)?;
                serializer.serialize_bytes(&self.prev_hash)?;
                Ok(serde::ser::Ok(()))
            }
        }
        
        let meta_bytes = bincode::serialize(&self.metadata).unwrap();
        buf.extend(meta_bytes);
        buf.extend(self.ciphertext.as_slice());
        buf
    }

    fn deserialize(data: &[u8]) -> Result<Self, StorageError> {
        // Metadata is first 128 bytes (64 for meta + 64 for prev_hash)
        let metadata_len = 128;
        
        if data.len() < metadata_len {
            return Err(StorageError::CorruptedMetadata(data.len()));
        }
        
        let meta_bytes: Vec<u8> = data[..metadata_len].to_vec();
        let ciphertext = data[metadata_len..].to_vec();
        
        let metadata: RecordMetadata = bincode::deserialize(&meta_bytes)?;
        
        // Verify hash chain continuity
        if metadata.sequence_number == 0 {
            return Err(StorageError::CorruptedMetadata(metadata_len));
        }
        
        Ok(Self {
            nonce: Nonce::from_slice(&metadata.prev_hash),
            ciphertext,
            metadata,
        })
    }

    fn compute_record_hash(&self) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(&self.ciphertext);
        hasher.update(&self.metadata.content_hash);
        hasher.finalize()
    }
}

/// Secure storage adapter with hash-chained attestation.
pub struct SecureStorageAdapter {
    config: StorageConfig,
    key_manager: KeyManager,
    next_sequence: u64,
}

impl Default for SecureStorageAdapter {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let salt = rng.gen::<[u8; 16]>();
        
        Self {
            config: StorageConfig {
                data_dir: PathBuf::from("./.auditrail_secure"),
                master_seed: rng.gen(),
                salt,
                kdf_iterations: 100_000,
            },
            key_manager: KeyManager::new(salt),
            next_sequence: 1,
        }
    }
}

impl SecureStorageAdapter {
    /// Initialize or open existing storage.
    pub fn init(&mut self) -> Result<(), StorageError> {
        let data_dir = &self.config.data_dir;
        
        if !data_dir.exists() {
            fs::create_dir_all(data_dir)?;
            
            // Create key metadata file with salt and sequence counter
            let meta_path = data_dir.join("key_metadata.bin");
            let mut meta_file = File::create(&meta_path)?;
            
            use serde::{Serialize, Serializer};
            
            #[derive(Serialize)]
            struct KeyMeta {
                salt: [u8; 16],
                sequence: u64,
            }
            
            let meta = KeyMeta {
                salt: self.config.salt,
                sequence: 0,
            };
            
            bincode::serialize_into(&mut meta_file, &meta)?;
        } else {
            // Load existing metadata
            let meta_path = data_dir.join("key_metadata.bin");
            let mut file = File::open(&meta_path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            
            #[derive(Deserialize)]
            struct KeyMeta {
                salt: [u8; 16],
                sequence: u64,
            }
            
            let meta: KeyMeta = bincode::deserialize(&buf)?;
            
            if meta.salt != self.config.salt {
                return Err(StorageError::KeyNotFound);
            }
            
            self.next_sequence = meta.sequence + 1;
        }
        
        Ok(())
    }

    /// Write a new audit record.
    pub fn write(&mut self, content: &[u8]) -> Result<u64, StorageError> {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        
        // Derive encryption key for this record using HKDF-like approach
        let mut key_material = [0u8; 32];
        {
            use hmac::Hmac;
            use sha2::{Sha256, Hmac as HmacSha256};
            
            let mut hasher = Sha256::new();
            hasher.update(&self.config.master_seed);
            hasher.update(&self.config.salt);
            hasher.update(&sequence.to_le_bytes());
            hasher.update(content);
            key_material = hasher.finalize().into();
        }
        
        // Encrypt with AES-GCM
        let nonce = Nonce::from_slice(&key_material[16..]);
        let mut cipher = Aes256Gcm::new(KeyInit::from_slice(&key_material[..16]));
        let ciphertext = cipher.encrypt(nonce, content)?;
        
        // Compute content hash before encryption (for audit trail)
        let content_hash: [u8; 32] = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(content);
            hasher.finalize().into()
        };
        
        // Read previous record's hash for chaining
        let prev_hash: [u8; 32] = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&ciphertext);
            hasher.update(&content_hash);
            hasher.finalize().into()
        };
        
        // Create encrypted record with metadata
        let timestamp = Utc::now();
        let record = EncryptedRecord::new(
            sequence,
            timestamp,
            content_hash,
            [0u8; 32], // Will be updated after write
            nonce.clone(),
            ciphertext,
        );
        
        // Atomic write using temp file + rename
        let data_path = self.config.data_dir.join(format!("{}.bin", sequence));
        let temp_path = data_path.with_extension("tmp");
        
        {
            let mut file = File::create(&temp_path)?;
            let serialized = record.serialize();
            file.write_all(&serialized)?;
            file.flush()?;
            
            // Update metadata with computed hash
            record.metadata.prev_hash = prev_hash;
            record.metadata.sequence_number = sequence;
            record.metadata.timestamp = timestamp;
        }
        
        fs::rename(&temp_path, &data_path)?;
        
        Ok(sequence)
    }

    /// Read and verify a specific record.
    pub fn read(&self, sequence: u64) -> Result<EncryptedRecord, StorageError> {
        let data_path = self.config.data_dir.join(format!("{}.bin", sequence));
        
        if !data_path.exists() {
            return Err(StorageError::CorruptedMetadata(sequence as usize));
        }
        
        let mut file = File::open(&data_path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        
        // Deserialize and verify integrity
        let record = EncryptedRecord::deserialize(&buf)?;
        
        // Verify hash chain continuity by reading previous record
        if sequence > 1 {
            let prev_record = self.read(sequence - 1)?;
            
            let expected_prev_hash: [u8; 32] = {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&prev_record.ciphertext);
                hasher.update(&prev_record.metadata.content_hash);
                hasher.finalize().into()
            };
            
            if record.metadata.prev_hash != expected_prev_hash {
                return Err(StorageError::Integrity {
                    expected: hex::encode(expected_prev_hash),
                    actual: hex::encode(record.metadata.prev_hash),
                });
            }
        }
        
        Ok(record)
    }

    /// Verify integrity of entire storage.
    pub fn verify_integrity(&self, start_sequence: u64) -> Result<u64, StorageError> {
        let mut last_hash = [0u8; 32];
        let mut verified_count = 0;
        
        for seq in start_sequence..=self.next_sequence - 1 {
            match self.read(seq) {
                Ok(record) => {
                    // Recompute expected hash chain value
                    use sha2::{Sha256, Digest};
                    
                    let mut hasher = Sha256::new();
                    hasher.update(&record.ciphertext);
                    hasher.update(&record.metadata.content_hash);
                    let computed_hash = hasher.finalize().into();
                    
                    if seq > start_sequence {
                        // Verify against previous record's expected hash
                        let prev_record = self.read(seq - 1)?;
                        
                        let mut chain_hasher = Sha256::new();
                        chain_hasher.update(&prev_record.ciphertext);
                        chain_hasher.update(&prev_record.metadata.content_hash);
                        let expected_chain = chain_hasher.finalize().into();
                        
                        if record.metadata.prev_hash != expected_chain {
                            return Err(StorageError::Integrity {
                                expected: hex::encode(expected_chain),
                                actual: hex::encode(record.metadata.prev_hash),
                            });
                        }
                    }
                    
                    last_hash = computed_hash;
                    verified_count += 1;
                }
                
                Err(e) => return Err(e),
            }
        }
        
        Ok(verified_count)
    }

    /// Rotate encryption keys.
    pub fn rotate_keys(&mut self, new_seed: [u8; 32]) -> Result<(), StorageError> {
        let data_dir = &self.config.data_dir;
        let meta_path = data_dir.join("key_metadata.bin");
        
        // Read current metadata
        if !meta_path.exists() {
            return Err(StorageError::KeyNotFound);
        }
        
        let mut file = File::open(&meta_path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        
        #[derive(Deserialize)]
        struct KeyMeta {
            salt: [u8; 16],
            sequence: u64,
        }
        
        let meta: KeyMeta = bincode::deserialize(&buf)?;
        
        // Update seed in metadata (new master key)
        self.config.master_seed = new_seed;
        
        // Rewrite metadata with new salt derived from old + new
        let new_salt = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&meta.salt);
            hasher.update(&self.config.master_seed);
            hasher.finalize().into()
        };
        
        self.config.salt = new_salt;
        
        // Rewrite metadata file
        use serde::{Serialize, Serializer};
        
        #[derive(Serialize)]
        struct KeyMetaOut {
            salt: [u8; 16],
            sequence: u64,
        }
        
        let meta_out = KeyMetaOut {
            salt: new_salt,
            sequence: self.next_sequence - 1,
        };
        
        let mut file = File::create(&meta_path)?;
        bincode::serialize_into(&mut file, &meta_out)?;
        
        Ok(())
    }

    /// Get current statistics.
    pub fn stats(&self) -> StorageStats {
        let data_dir = &self.config.data_dir;
        let meta_path = data_dir.join("key_metadata.bin");
        
        let total_records: usize = fs::read_dir(data_dir)
            .unwrap_or_default()
            .filter_map(|entry| {
                entry.ok().and_then(|e| e.path().file_name().and_then(|n| n.to_str()))
                    .map(|name| name.parse::<u64>().ok())
                    .flatten()
            })
            .count();
        
        let meta: StorageStatsMeta = if meta_path.exists() {
            let mut file = File::open(&meta_path).unwrap_or_default();
            let mut buf = Vec::new();
            file.read_to_end(&mut buf).unwrap_or_default();