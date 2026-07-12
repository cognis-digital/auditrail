package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// =============================================================================
// Core Types
// =============================================================================

// LogEntry represents raw incoming log data.
type LogEntry struct {
	Timestamp    time.Time
	Source       string
	Level        string
	Message      string
	Metadata     map[string]string
}

// AuditRecord is a processed entry with cryptographic attestation.
type AuditRecord struct {
	Index        uint64
	ContentHash  [32]byte // SHA-256 of the serialized content
	PrevHash     [32]byte // Hash of previous record (chaining)
	Timestamp    time.Time
	Source       string
	Level        string
	Message      string
	Metadata     map[string]string
	Signature    []byte   // Optional HMAC for additional attestation
}

// ChainState tracks metadata about the audit chain.
type ChainState struct {
	mu         sync.RWMutex
	RootHash   [32]byte
	LastHash   [32]byte
	RecordCount uint64
	StartTime  time.Time
	EndTime    time.Time
}

// =============================================================================
// Hashing & Attestation
// =============================================================================

type hasher interface {
	Update([]byte) error
	Sum() ([32]byte, error)
}

func newSHA256Hasher() hasher {
	return sha256.New()
}

// computeContentHash serializes the entry and hashes it.
func (r *AuditRecord) ComputeContentHash(hasher hasher) error {
	data := &contentSerializer{
		Index:        r.Index,
		Timestamp:    r.Timestamp,
		Source:       r.Source,
		Level:        r.Level,
		Message:      r.Message,
		Metadata:     r.Metadata,
	}

	if _, err := data.writeTo(hasher); err != nil {
		return fmt.Errorf("serializing content for hash: %w", err)
	}

	sum, err := hasher.Sum()
	if err != nil {
		return fmt.Errorf("finalizing hash: %w", err)
	}

	r.ContentHash = sum
	return nil
}

// contentSerializer handles deterministic serialization.
type contentSerializer struct {
	Index        uint64
	Timestamp    time.Time
	Source       string
	Level        string
	Message      string
	Metadata     map[string]string
}

func (s *contentSerializer) writeTo(hasher hasher) error {
	// Write fixed-size fields first for deterministic ordering.
	binary.Write(hasher, binary.BigEndian, s.Index)
	
	timestamp := s.Timestamp.UnixNano()
	binary.Write(hasher, binary.BigEndian, timestamp)

	// String fields: length-prefixed to handle variable lengths safely.
	strLen := uint64(len(s.Source))
	binary.Write(hasher, binary.BigEndian, strLen)
	if _, err := io.WriteString(hasher, s.Source); err != nil {
		return fmt.Errorf("writing source: %w", err)
	}

	strLen = uint64(len(s.Level))
	binary.Write(hasher, binary.BigEndian, strLen)
	if _, err := io.WriteString(hasher, s.Level); err != nil {
		return fmt.Errorf("writing level: %w", err)
	}

	strLen = uint64(len(s.Message))
	binary.Write(hasher, binary.BigEndian, strLen)
	if _, err := io.WriteString(hasher, s.Message); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}

	// Metadata as sorted key-value pairs.
	keys := make([]string, 0, len(s.Metadata))
	for k := range s.Metadata {
		keys = append(keys, k)
	}
	sortStrings(keys)

	for _, k := range keys {
		v := s.Metadata[k]
		strLen = uint64(len(k))
		binary.Write(hasher, binary.BigEndian, strLen)
		if _, err := io.WriteString(hasher, k); err != nil {
			return fmt.Errorf("writing metadata key: %w", err)
		}

		strLen = uint64(len(v))
		binary.Write(hasher, binary.BigEndian, strLen)
		if _, err := io.WriteString(hasher, v); err != nil {
			return fmt.Errorf("writing metadata value: %w", err)
		}
	}

	return nil
}

// =============================================================================
// Chain Manager
// =============================================================================

type AuditChain struct {
	state    *ChainState
	hasher   hasher
	mu       sync.RWMutex
}

func NewAuditChain() (*AuditChain, error) {
	rootHash := [32]byte{} // Zero hash as initial root marker.
	
	chain := &AuditChain{
		state:  &ChainState{RootHash: rootHash, StartTime: time.Now()},
		hasher: newSHA256Hasher(),
	}

	if err := chain.reset(); err != nil {
		return nil, fmt.Errorf("initializing chain: %w", err)
	}

	return chain, nil
}

func (c *AuditChain) reset() error {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()

	c.state.RootHash = [32]byte{}
	c.state.LastHash = [32]byte{}
	c.state.RecordCount = 0
	c.state.StartTime = time.Now()
	c.state.EndTime = time.Now()

	return nil
}

// Ingest adds a log entry to the chain. Returns the created AuditRecord.
func (c *AuditChain) Ingest(ctx context.Context, entry LogEntry) (*AuditRecord, error) {
	c.mu.RLock()
	chainState := c.state
	c.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled during ingestion: %w", err)
	}

	record := &AuditRecord{
		Index:        chainState.RecordCount,
		Timestamp:    entry.Timestamp,
		Source:       entry.Source,
		Level:        entry.Level,
		Message:      entry.Message,
		Metadata:     make(map[string]string),
	}

	for k, v := range entry.Metadata {
		record.Metadata[k] = v
	}

	if err := record.ComputeContentHash(c.hasher); err != nil {
		return nil, fmt.Errorf("computing content hash: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Chain the hashes.
	record.PrevHash = chainState.LastHash
	
	if !chainState.RootHash.IsZero() && record.Index == 0 {
		// First real entry after reset — verify root continuity.
		expectedRoot := sha256.Sum256(record.ContentHash[:])
		if expectedRoot != chainState.RootHash {
			return nil, fmt.Errorf("root hash mismatch: got %x, expected %x", 
				record.ContentHash, chainState.RootHash)
		}
	}

	c.state.mu.Lock()
	c.state.LastHash = record.ContentHash
	c.state.RecordCount++
	c.state.EndTime = time.Now()
	c.state.mu.Unlock()

	return record, nil
}

// Verify reconstructs the chain and validates integrity.
func (c *AuditChain) Verify(ctx context.Context) error {
	c.mu.RLock()
	state := c.state
	lastHash := state.LastHash
	recordCount := state.RecordCount
	rootHash := state.RootHash
	c.mu.RUnlock()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled during verification: %w", err)
	}

	expectedRoot := sha256.Sum256(lastHash[:])
	if !rootHash.IsZero() && expectedRoot != rootHash {
		return fmt.Errorf("chain continuity failed: last hash %x vs root %x", 
			lastHash, rootHash)
	}

	return nil
}

// GetRootHash returns the current root of the chain.
func (c *AuditChain) GetRootHash() [32]byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	state := c.state
	if !state.RootHash.IsZero() {
		return state.RootHash
	}

	c.mu.Lock()
	root := sha256.Sum256(state.LastHash[:])
	state.RootHash = root
	c.mu.Unlock()

	return root
}

// =============================================================================
// Utility Functions
// =============================================================================

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[i] > s[j] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// IsZero checks if a hash is the initial zero value.
func (h [32]byte) IsZero() bool {
	for _, b := range h {
		if b != 0 {
			return false
		}
	}
	return true
}

// =============================================================================
// Entry Point / Demo
// =============================================================================

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	chain, err := NewAuditChain()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create chain: %v\n", err)
		os.Exit(1)
	}

	// Sample log entries.
	samples := []LogEntry{
		{
			Timestamp:    time.Now(),
			Source:       "auth-service",
			Level:        "INFO",
			Message:      "User login successful",
			Metadata:     map[string]string{"user_id": "12345"},
		},
		{
			Timestamp:    time.Now().Add(time.Second),
			Source:       "auth-service",
			Level:        "WARN",
			Message:      "Rate limit approaching",
			Metadata:     map[string]string{"endpoint": "/api/v1/login"},
		},
		{
			Timestamp:    time.Now().Add(time.Second * 2),
			Source:       "web-frontend",
			Level:        "ERROR",
			Message:      "Database connection timeout",
			Metadata:     map[string]string{"db_host": "primary-db"},
		},
	}

	fmt.Println("=== Audit Chain Ingestion Demo ===\n")

	for i, sample := range samples {
		record, err := chain.Ingest(ctx, sample)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ingest #%d failed: %v\n", i+1, err)
			continue
		}

		fmt.Printf("Record #%d:\n", record.Index)
		fmt.Printf("  Content Hash (first 16 chars): %x...\n", record.ContentHash[:16])
		fmt.Printf("  Previous Hash:   %x\n", record.PrevHash)
		fmt.Println()
	}

	// Verify the chain.
	if err := chain.Verify(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("=== Verification Passed ===\n")
	fmt.Printf("  Total Records: %d\n", chain.GetRecordCount())
	fmt.Printf("  Duration:      %.2fs\n", 
		time.Since(chain.GetStartTime()).Seconds())
	fmt.Printf("  Root Hash:     %x\n", chain.GetRootHash())

	// Demonstrate tamper detection.
	fmt.Println("\n=== Tamper Detection Demo ===")
	
	original := samples[0]
	modified := original
	modified.Message = "Modified maliciously"

	record, _ := chain.Ingest(ctx, modified)
	if err := record.ComputeContentHash(newSHA256Hasher()); err != nil {
		fmt.Fprintf(os.Stderr, "Recomputed hash: %v\n", err)
	}

	expectedRoot := sha256.Sum256(record.ContentHash[:])
	currentRoot := chain.GetRootHash()

	if expectedRoot == currentRoot {
		fmt.Println("  Chain appears intact (unexpected for modified entry)")
	} else {
		fmt.Printf("  Tamper detected! Root changed from %x to %x\n", 
			expectedRoot, currentRoot)
	}

	// Write chain state to disk.
	stateFile := "audit_chain.state"
	if err := chain.persistState(stateFile); err != nil {
		fmt.Fprintf(os.Stderr, "Persisting state failed: %v\n", err)
	} else {
		fmt.Printf("  State persisted to: %s\n", stateFile)
	}

	// Read back and verify.
	if err := chain.restoreState(stateFile); err != nil {
		fmt.Fprintf(os.Stderr, "Restoring state failed: %v\n", err)
	} else {
		fmt.Println("  State restored successfully")
	}
}

// =============================================================================
// Persistence Layer
// =============================================================================

func (c *AuditChain) persistState(path string) error {
	c.mu.RLock()
	state := c.state
	c.mu.RUnlock()

	data, err := marshalChainState(state)
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}

	f, err := os.Create(path + ".tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("writing state: %w", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing file: %w", err)
	}

	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("renaming temp file: %w", err)
	}

	f = nil // Mark as closed.
	return nil
}

func (c *AuditChain) restoreState(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c.reset()
	}
	if err != nil {
		return fmt.Errorf("reading state file: %w", err)
	}

	var state ChainState
	if _, err = unmarshalChainState(&state, data); err != nil {
		return fmt.Errorf("unmarshaling state: %w", err)
	}

	c.mu.Lock()
	c.state = &state
	c.hasher = newSHA256Hasher() // Reset hasher for fresh computation.
	c.mu.Unlock()

	return nil
}

func marshalChainState(state *ChainState) ([]byte, error) {
	var buf bytes.Buffer

	binary.Write(&buf, binary.BigEndian, state.RootHash)
	binary.Write(&buf, binary.BigEndian, state.LastHash)
	binary.Write(&buf, binary.BigEndian, state.RecordCount)
	
	timestamp := state.StartTime.UnixNano()
	binary.Write(&buf, binary.BigEndian, timestamp)

	timestamp = state.EndTime.UnixNano()
	binary.Write(&buf, binary.BigEndian, timestamp)

	return buf.Bytes(), nil
}

func unmarshalChainState(state *ChainState, data []byte) (int, error) {
	if len(data) < 256*4 { // Minimum: 4 hashes + timestamps + count.
		return 0, errors.New("truncated state file")
	}

	offset := 0

	state.RootHash = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	state.LastHash = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	state.RecordCount = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	timestamp := int64(binary.BigEndian.Uint64(data[offset:]))
	state.StartTime = time.Unix(0, timestamp)
	offset += 8

	timestamp = int64(binary.BigEndian.Uint64(data[offset:]))
	state.EndTime = time.Unix(0, timestamp)
	offset += 8

	return offset, nil
}

// =============================================================================
// Helper Methods on ChainState
// =============================================================================

func (s *ChainState) GetRecordCount() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.RecordCount
}

func (s *ChainState) GetStartTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.StartTime
}

func (s *ChainState) GetEndTime() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.EndTime
}