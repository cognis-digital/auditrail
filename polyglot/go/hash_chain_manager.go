package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Entry represents a single audit log entry in the hash chain.
type Entry struct {
	ID          uint64    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Payload     string    `json:"payload"`
	PrevHash    string    `json:"prev_hash,omitempty"`
	CurrentHash string    `json:"current_hash"`
	Meta        Meta      `json:"meta"`
}

// Meta holds optional metadata about the entry.
type Meta struct {
	Source   string `json:"source,omitempty"`
	User     string `json:"user,omitempty"`
	Action   string `json:"action,omitempty"`
	IP       string `json:"ip,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Chain represents the tamper-evident hash chain.
type Chain struct {
	mu      sync.RWMutex
	entries []Entry
	genesis string // Hash of genesis entry (empty string if not set)
	root    string // Current root hash (last entry's current_hash)
}

// NewChain creates a new empty audit chain with optional genesis data.
func NewChain(genesisData ...string) *Chain {
	c := &Chain{
		genesis: "",
	}
	if len(genesisData) > 0 {
		c.SetGenesis(genesisData[0])
	}
	return c
}

// SetGenesis initializes the chain with a genesis hash.
func (c *Chain) SetGenesis(hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.genesis = hash
	c.entries = []Entry{
		{
			ID:          0,
			Timestamp:   time.Now().UTC(),
			Payload:     "genesis",
			PrevHash:    "",
			CurrentHash: hash,
			Meta:        Meta{},
		},
	}
	c.root = hash
}

// Append adds a new entry to the chain with automatic hashing.
func (c *Chain) Append(payload string, meta ...Meta) Entry {
	c.mu.Lock()
	defer c.mu.Unlock()

	last := c.entries[len(c.entries)-1]
	nextHash := last.CurrentHash

	// Compute hash of: prev_hash + payload + timestamp
	hashInput := fmt.Sprintf("%s%s%d", nextHash, payload, time.Now().UnixNano())
	computedHash := sha256.Sum256([]byte(hashInput))
	hashStr := fmt.Sprintf("%x", computedHash)

	entry := Entry{
		ID:          uint64(len(c.entries)),
		Timestamp:   time.Now().UTC(),
		Payload:     payload,
		PrevHash:    last.CurrentHash,
		CurrentHash: hashStr,
		Meta:        Meta{},
	}

	if len(meta) > 0 {
		entry.Meta = meta[0]
	}

	c.entries = append(c.entries, entry)
	c.root = hashStr

	return entry
}

// GetLastHash returns the current root hash of the chain.
func (c *Chain) GetLastHash() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.entries) == 0 {
		return ""
	}
	return c.entries[len(c.entries)-1].CurrentHash
}

// Verify checks if the entire chain is intact from genesis to root.
func (c *Chain) Verify(expectedRoot string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(c.entries) == 0 {
		return expectedRoot == ""
	}

	expected := expectedRoot
	for i, entry := range c.entries {
		if i == 0 && expected != entry.CurrentHash {
			return false
		}
		if i > 0 && expected != entry.PrevHash {
			return false
		}
		hashInput := fmt.Sprintf("%s%s%d", entry.PrevHash, entry.Payload, entry.Timestamp.UnixNano())
		computed := sha256.Sum256([]byte(hashInput))
		expected = fmt.Sprintf("%x", computed)
	}

	return expected == c.root
}

// GetEntry retrieves an entry by index. Returns nil if out of bounds.
func (c *Chain) GetEntry(index int) Entry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if index < 0 || index >= len(c.entries) {
		return Entry{}
	}
	return c.entries[index]
}

// Len returns the number of entries in the chain.
func (c *Chain) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// ExportJSON serializes the entire chain to JSON bytes.
func (c *Chain) ExportJSON() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.entries) == 0 {
		return []byte(`{"entries":[],"genesis":"","root":""}`), nil
	}

	data := map[string]interface{}{
		"entries":   c.entries,
		"genesis":   c.genesis,
		"root":      c.root,
		"timestamp": time.Now().UTC(),
	}

	return json.Marshal(data)
}

// ImportJSON deserializes a chain from JSON bytes.
func (c *Chain) ImportJSON(b []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return fmt.Errorf("failed to unmarshal: %w", err)
	}

	c.entries = make([]Entry, 0)
	if entries, ok := data["entries"].([]interface{}); ok {
		for _, e := range entries {
			var entry Entry
			if err := json.Unmarshal(e.([]byte), &entry); err != nil {
				return fmt.Errorf("failed to unmarshal entry: %w", err)
			}
			c.entries = append(c.entries, entry)
		}
	}

	if g, ok := data["genesis"].(string); ok {
		c.genesis = g
	}
	if r, ok := data["root"].(string); ok {
		c.root = r
	}

	return nil
}

// CreateGenesis creates a genesis entry and returns its hash.
func CreateGenesis() (Entry, string) {
	genesisHash := sha256.Sum256([]byte("audit-trail-genesis-v1"))
	hashStr := fmt.Sprintf("%x", genesisHash)

	entry := Entry{
		ID:          0,
		Timestamp:   time.Now().UTC(),
		Payload:     "genesis",
		PrevHash:    "",
		CurrentHash: hashStr,
		Meta:        Meta{},
	}

	return entry, hashStr
}

// Snapshot captures a read-only copy of the chain state.
func (c *Chain) Snapshot() Chain {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snap := Chain{
		entries: make([]Entry, len(c.entries)),
		genesis: c.genesis,
		root:    c.root,
	}

	copy(snap.entries, c.entries)
	return snap
}

// Main/demo function to show the hash chain manager in action.
func main() {
	fmt.Println("=== Audit Trail Hash Chain Manager Demo ===\n")

	// Step 1: Create genesis entry
	genesisEntry, genesisHash := CreateGenesis()
	fmt.Printf("Genesis created:\n")
	fmt.Printf("  Payload: %s\n", genesisEntry.Payload)
	fmt.Printf("  Genesis Hash: %s\n\n", genesisHash)

	// Step 2: Initialize chain with genesis hash
	c := NewChain(genesisHash)
	fmt.Println("Chain initialized with genesis.")

	// Step 3: Append some audit entries
	testCases := []struct {
		payload string
		meta    Meta
	}{
		{"user login attempt", Meta{Source: "auth-service", User: "alice"}},
		{"file access /etc/passwd", Meta{Source: "web-server", Action: "read", IP: "192.168.1.50"}},
		{"config change: timeout=30s", Meta{Source: "admin-panel", User: "bob", Version: "v2.1"}},
		{"user logout", Meta{Source: "auth-service", User: "alice"}},
	}

	fmt.Println("Appending entries...")
	for i, tc := range testCases {
		entry := c.Append(tc.payload, tc.meta)
		fmt.Printf("Entry %d:\n", i+1)
		fmt.Printf("  Payload: %s\n", entry.Payload)
		fmt.Printf("  PrevHash: %s...\n", entry.PrevHash[:8])
		fmt.Printf("  CurrentHash: %s...\n", entry.CurrentHash[:8])
	}

	fmt.Println()

	// Step 4: Verify chain integrity
	expectedRoot := c.GetLastHash()
	fmt.Printf("Current Root Hash: %s\n", expectedRoot)
	fmt.Printf("Verification Result: %v\n\n", c.Verify(expectedRoot))

	// Step 5: Simulate tampering and verify detection
	tamperedChain := c.Snapshot()
	tamperedChain.entries[1].Payload = "TAMPERED PAYLOAD" // Modify entry 1

	fmt.Println("=== Tamper Detection Demo ===")
	fmt.Printf("Original Entry 1 Payload: %s\n", c.GetEntry(1).Payload)
	fmt.Printf("Tampered Entry 1 Payload: %s\n", tamperedChain.entries[1].Payload)
	fmt.Printf("Verification after tampering: %v (should be false)\n\n", tamperedChain.Verify(expectedRoot))

	// Step 6: Export and import demonstration
	exported, err := c.ExportJSON()
	if err != nil {
		fmt.Printf("Export error: %v\n", err)
	} else {
		fmt.Println("=== Export/Import Demo ===")
		fmt.Printf("Exported size: %d bytes\n", len(exported))
		
		imported := &Chain{}
		if err := imported.ImportJSON(exported); err != nil {
			fmt.Printf("Import error: %v\n", err)
		} else {
			fmt.Printf("Imported chain length: %d (original: %d)\n", imported.Len(), c.Len())
			fmt.Printf("Root hash matches: %v\n", imported.GetLastHash() == expectedRoot)
		}
	}

	// Step 7: Performance-ish demo with concurrent appends
	fmt.Println("\n=== Concurrent Append Demo ===")
	var wg sync.WaitGroup
	numGoroutines := 10
	entriesPerGoroutine := 50

	c2 := NewChain()

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < entriesPerGoroutine; i++ {
				c2.Append(fmt.Sprintf("goroutine-%d-iteration-%d", id, i))
			}
		}(g)
	}

	wg.Wait()
	fmt.Printf("Total entries after concurrent appends: %d\n", c2.Len())
	fmt.Printf("Final root hash: %s...\n", c2.GetLastHash()[:8])
	fmt.Printf("Chain verification: %v\n", c2.Verify(c2.GetLastHash()))

	// Step 8: Edge cases
	fmt.Println("\n=== Edge Cases ===")
	
	emptyChain := NewChain()
	fmt.Printf("Empty chain root hash: '%s'\n", emptyChain.GetLastHash())
	fmt.Printf("Empty chain verification (expecting empty): %v\n", emptyChain.Verify(""))

	// Out of bounds retrieval
	outOfBoundsEntry := c2.GetEntry(9999)
	fmt.Printf("Out of bounds entry ID: %d, Payload: '%s'\n", outOfBoundsEntry.ID, outOfBoundsEntry.Payload)

	// Negative index
	negativeEntry := c2.GetEntry(-1)
	fmt.Printf("Negative index entry ID: %d, Payload: '%s'\n", negativeEntry.ID, negativeEntry.Payload)

	fmt.Println("\n=== Demo Complete ===")
}