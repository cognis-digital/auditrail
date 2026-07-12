package securestorage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry represents a single audit log entry with cryptographic chaining.
type Entry struct {
	ID         string
	Timestamp  time.Time
	Payload    []byte
	Hash       string // SHA-256 of Payload + PrevHash
	PrevHash   string // Previous entry's hash (for chain continuity)
}

// SecureStore defines the interface for tamper-evident storage.
type SecureStore interface {
	Store(entry *Entry) error
	Retrieve(id string) (*Entry, error)
	VerifyChain(startID, endID string) bool
	GetRootHash() (string, error)
	Clear() error
}

// MemoryStore implements in-memory secure storage.
type MemoryStore struct {
	mu       sync.RWMutex
	entries  map[string]*Entry
	rootHash string // Hash of the first entry (genesis anchor)
}

// FileStore implements persistent file-based secure storage.
type FileStore struct {
	basePath   string
	mu         sync.RWMutex
	entries    map[string]*Entry
	rootHash   string
	indexFile  string
	dataDir    string
}

// NewMemoryStore creates a new in-memory store with optional genesis hash.
func NewMemoryStore(genesisHash ...string) *MemoryStore {
	store := &MemoryStore{
		entries: make(map[string]*Entry),
	}
	if len(genesisHash) > 0 && genesisHash[0] != "" {
		store.rootHash = genesisHash[0]
	}
	return store
}

// NewFileStore creates a new file-based store at the given path.
func NewFileStore(basePath string, options ...Option) (*FileStore, error) {
	fs := &FileStore{
		basePath:  basePath,
		dataDir:   filepath.Join(basePath, "data"),
		indexFile: filepath.Join(basePath, "index.json"),
	}

	if err := fs.init(); err != nil {
		return nil, err
	}

	return fs, nil
}

// Option configures FileStore behavior.
type Option func(*FileStore)

// WithRootHash sets the genesis hash for chain anchoring.
func WithRootHash(h string) Option {
	return func(fs *FileStore) {
		fs.rootHash = h
	}
}

// init creates directories and initializes empty index if needed.
func (fs *FileStore) init() error {
	if err := os.MkdirAll(fs.dataDir, 0755); err != nil {
		return fmt.Errorf("mkdir data dir: %w", err)
	}
	return nil
}

// Store adds a new entry to the chain.
func (m *MemoryStore) Store(entry *Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.rootHash) == 0 && len(m.entries) == 0 {
		m.rootHash = entry.Hash
	} else if len(m.rootHash) > 0 && len(m.entries) == 0 {
		entry.PrevHash = m.rootHash
	}

	m.entries[entry.ID] = entry
	return nil
}

// Store adds a new entry to the file-based chain.
func (fs *FileStore) Store(entry *Entry) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if len(fs.rootHash) == 0 && len(fs.entries) == 0 {
		fs.rootHash = entry.Hash
	} else if len(fs.rootHash) > 0 && len(fs.entries) == 0 {
		entry.PrevHash = fs.rootHash
	}

	fs.entries[entry.ID] = entry
	return nil
}

// Retrieve fetches a specific entry by ID.
func (m *MemoryStore) Retrieve(id string) (*Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.entries[id]
	if !ok {
		return nil, fmt.Errorf("entry not found: %s", id)
	}
	return entry, nil
}

// Retrieve fetches a specific entry from file storage.
func (fs *FileStore) Retrieve(id string) (*Entry, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	entry, ok := fs.entries[id]
	if !ok {
		return nil, fmt.Errorf("entry not found: %s", id)
	}
	return entry, nil
}

// VerifyChain checks if all entries between startID and endID form a valid chain.
func (m *MemoryStore) VerifyChain(startID, endID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	start, ok := m.entries[startID]
	if !ok {
		return false
	}

	end, ok := m.entries[endID]
	if !ok {
		return false
	}

	expectedHash := start.Hash
	for expectedHash != end.Hash {
		next, ok := m.entries[expectedHash] // Hash is also used as ID for chaining
		if !ok {
			return false
		}
		if next.PrevHash != expectedHash {
			return false
		}
		expectedHash = next.Hash
	}

	return true
}

// VerifyChain checks file-based chain integrity.
func (fs *FileStore) VerifyChain(startID, endID string) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	start, ok := fs.entries[startID]
	if !ok {
		return false
	}

	end, ok := fs.entries[endID]
	if !ok {
		return false
	}

	expectedHash := start.Hash
	for expectedHash != end.Hash {
		next, ok := fs.entries[expectedHash]
		if !ok {
			return false
		}
		if next.PrevHash != expectedHash {
			return false
		}
		expectedHash = next.Hash
	}

	return true
}

// GetRootHash returns the genesis hash anchoring the entire chain.
func (m *MemoryStore) GetRootHash() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rootHash, nil
}

// GetRootHash returns file-based root hash.
func (fs *FileStore) GetRootHash() (string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return fs.rootHash, nil
}

// Clear removes all entries from memory store.
func (m *MemoryStore) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = make(map[string]*Entry)
	m.rootHash = ""
	return nil
}

// Clear resets file-based storage to empty state.
func (fs *FileStore) Clear() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if err := os.RemoveAll(fs.dataDir); err != nil {
		return fmt.Errorf("remove data dir: %w", err)
	}

	fs.entries = make(map[string]*Entry)
	fs.rootHash = ""
	return nil
}

// computeHash calculates SHA-256 hash for an entry.
func computeHash(payload []byte, prevHash string) string {
	data := append([]byte(prevHash), payload...)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// CreateEntry creates a new Entry with computed hash and timestamp.
func CreateEntry(id string, payload []byte, prevHash ...string) *Entry {
	now := time.Now()

	if len(prevHash) == 0 || prevHash[0] == "" {
		prevHash = append(prevHash, "") // Genesis entry has empty PrevHash
	}

	hash := computeHash(payload, prevHash[0])

	return &Entry{
		ID:        id,
		Timestamp: now,
		Payload:   payload,
		Hash:      hash,
		PrevHash:  prevHash[0],
	}
}

// AppendPayload creates a new entry that extends the previous chain.
func (m *MemoryStore) AppendPayload(id string, payload []byte) (*Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var prevHash string
	if len(m.entries) > 0 {
		lastID := ""
		for k := range m.entries {
			if lastID == "" || m.entries[k].Timestamp.After(m.entries[lastID].Timestamp) {
				lastID = k
			}
		}
		last, ok := m.entries[lastID]
		if ok {
			prevHash = last.Hash
		} else {
			prevHash = m.rootHash
		}
	}

	entry := CreateEntry(id, payload, prevHash)
	m.Store(entry)
	return entry, nil
}

// AppendPayload extends file-based storage with new data.
func (fs *FileStore) AppendPayload(id string, payload []byte) (*Entry, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	var prevHash string
	if len(fs.entries) > 0 {
		lastID := ""
		for k := range fs.entries {
			if lastID == "" || fs.entries[k].Timestamp.After(fs.entries[lastID].Timestamp) {
				lastID = k
			}
		}
		last, ok := fs.entries[lastID]
		if ok {
			prevHash = last.Hash
		} else {
			prevHash = fs.rootHash
		}
	}

	entry := CreateEntry(id, payload, prevHash)
	fs.Store(entry)
	return entry, nil
}

// VerifyPayload checks if a given payload matches the stored entry.
func (m *MemoryStore) VerifyPayload(id string, expectedPayload []byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, err := m.Retrieve(id)
	if err != nil {
		return false
	}

	return string(entry.Payload) == string(expectedPayload)
}

// VerifyPayload checks file-based payload integrity.
func (fs *FileStore) VerifyPayload(id string, expectedPayload []byte) bool {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	entry, err := fs.Retrieve(id)
	if err != nil {
		return false
	}

	return string(entry.Payload) == string(expectedPayload)
}

// GetChainLength returns the number of entries in the chain.
func (m *MemoryStore) GetChainLength() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

// GetChainLength returns file-based entry count.
func (fs *FileStore) GetChainLength() int {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	return len(fs.entries)
}

// Snapshot creates a copy of the current state for verification.
func (m *MemoryStore) Snapshot() map[string]*Entry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snap := make(map[string]*Entry, len(m.entries))
	for k, v := range m.entries {
		snap[k] = &Entry{
			ID:       v.ID,
			Timestamp: v.Timestamp,
			Payload:  append([]byte(nil), v.Payload...),
			Hash:     v.Hash,
			PrevHash: v.PrevHash,
		}
	}
	return snap
}

// Snapshot creates a copy of file-based state.
func (fs *FileStore) Snapshot() map[string]*Entry {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	snap := make(map[string]*Entry, len(fs.entries))
	for k, v := range fs.entries {
		snap[k] = &Entry{
			ID:       v.ID,
			Timestamp: v.Timestamp,
			Payload:  append([]byte(nil), v.Payload...),
			Hash:     v.Hash,
			PrevHash: v.PrevHash,
		}
	}
	return snap
}

// Demo demonstrates basic usage of the secure storage adapter.
func main() {
	fmt.Println("=== Secure Storage Adapter Demo ===")

	// Create in-memory store with genesis hash anchor
	genesisHash := "0x1234567890abcdef" // Example genesis anchor
	store := NewMemoryStore(genesisHash)

	// Append some log entries
	payloads := []string{
		`{"event": "user_login", "user_id": 101, "ip": "192.168.1.1"}`,
		`{"event": "page_view", "path": "/dashboard", "session": "abc123"}`,
		`{"event": "api_call", "endpoint": "/users/list", "method": "GET"}`,
	}

	for i, p := range payloads {
		entry, err := store.AppendPayload(fmt.Sprintf("entry_%d", i), []byte(p))
		if err != nil {
			fmt.Printf("Error appending payload: %v\n", err)
			continue
		}
		fmt.Printf("Entry %s stored. Hash: %s\n", entry.ID, entry.Hash[:16])
	}

	// Verify chain integrity
	startID := "entry_0"
	endID := "entry_2"
	valid := store.VerifyChain(startID, endID)
	fmt.Printf("\nChain verification (%s -> %s): %v\n", startID, endID, valid)

	// Get root hash (genesis anchor)
	rootHash, _ := store.GetRootHash()
	fmt.Printf("Root/Genesis Hash: %s\n", rootHash)

	// Retrieve and verify specific entry
	entry, err := store.Retrieve("entry_1")
	if err == nil {
		fmt.Printf("\nRetrieved Entry:\n  ID: %s\n  Timestamp: %s\n  Payload Preview: %.50s...\n",
			entry.ID, entry.Timestamp.Format(time.RFC3339), string(entry.Payload))

		// Verify payload integrity
		isIntact := store.VerifyPayload("entry_1", []byte(`{"event": "page_view", "path": "/dashboard", "session": "abc123"}`))
		fmt.Printf("  Payload Intact: %v\n", isIntact)

		// Check hash match
		expectedHash := entry.Hash
		actualHash := computeHash(entry.Payload, entry.PrevHash)
		fmt.Printf("  Hash Match: %v (Expected: %s, Actual: %s)\n",
			expectedHash == actualHash, expectedHash[:16], actualHash[:16])
	}

	// Get chain statistics
	length := store.GetChainLength()
	fmt.Printf("\nCurrent Chain Length: %d entries\n", length)

	// Create a snapshot for comparison
	snap := store.Snapshot()
	fmt.Printf("Snapshot created with %d entries\n", len(snap))

	// Modify and verify detection
	if len(snap) > 0 {
		originalHash := snap["entry_1"].Hash
		modifiedPayload := []byte(`{"event": "page_view", "path": "/MODIFIED", "session": "abc123"}`)
		
		newHash := computeHash(modifiedPayload, snap["entry_0"].PrevHash)
		snap["entry_1"].Hash = newHash // Simulate tampering

		fmt.Printf("\n--- Tamper Detection Demo ---\n")
		fmt.Printf("Original Hash: %s\n", originalHash[:32])
		fmt.Printf("Modified Hash: %s\n", newHash[:32])
		
		// Verify against modified state
		modifiedEntry, _ := store.Retrieve("entry_1")
		isTampered := modifiedEntry.Hash != originalHash
		fmt.Printf("Chain Tampered (detected): %v\n", isTampered)

		if !isTampered {
			fmt.Println("  -> Hash matches! Chain appears intact.")
		} else {
			fmt.Println("  -> Hash mismatch detected!")
		}
	}

	// Demonstrate file-based storage
	fmt.Println("\n=== File-Based Storage Demo ===")
	
	filePath := "/tmp/auditrail_test"
	fs, err := NewFileStore(filePath)
	if err != nil {
		fmt.Printf("Error creating file store: %v\n", err)
	} else {
		fmt.Printf("File