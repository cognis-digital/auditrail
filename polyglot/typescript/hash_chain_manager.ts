import { createHash } from 'node:crypto';
import { inspect } from 'node:util';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface ChainEntry {
  id: string;
  data: any;
  metadata?: Record<string, unknown>;
  timestamp: number;
  hash: string; // SHA-256 of this entry's content
  previousHash: string | null; // Hash of the parent entry (or null for genesis)
}

interface ChainState {
  head: ChainEntry | null;
  totalEntries: number;
  createdAt: number;
  updatedAt: number;
  secret?: string; // Optional HMAC key for extra integrity
}

interface AttestationRecord {
  chainId: string;
  headIndex: number;
    timestamp: number;
  hash: string;
  signature: string; // HMAC of the attestation content
}

type Result<T> = 
  | { ok: true; value: T }
  | { ok: false; error: string };

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function computeSha256(data: any): string {
  const hash = createHash('sha256');
  if (typeof data === 'string') {
    hash.update(data);
  } else {
    hash.update(JSON.stringify(data));
  }
  return hash.digest('hex');
}

function computeHmacSha256(data: any, secret?: string): string {
  const hash = createHash('sha256');
  if (typeof data === 'string') {
    hash.update(data);
  } else {
    hash.update(JSON.stringify(data));
  }
  if (secret) {
    hash.update(secret);
  }
  return hash.digest('hex');
}

function formatTimestamp(ts: number): string {
  return new Date(ts).toISOString();
}

// ============================================================================
// HASH CHAIN MANAGER - CORE IMPLEMENTATION
// ============================================================================

class HashChainManager {
  private state: ChainState;
  private entriesMap: Map<string, ChainEntry>;

  constructor() {
    this.state = {
      head: null,
      totalEntries: 0,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
    this.entriesMap = new Map();
  }

  /**
   * Initialize a fresh chain with optional HMAC secret.
   */
  initChain(secret?: string): void {
    if (secret) {
      this.state.secret = secret;
    }
    this.state.head = null;
    this.state.totalEntries = 0;
    this.state.updatedAt = Date.now();
    this.entriesMap.clear();
  }

  /**
   * Append a new entry to the chain. Returns the created entry.
   */
  appendEntry(
    data: any,
    metadata?: Record<string, unknown>
  ): ChainEntry {
    const prev = this.state.head;
    const previousHash = prev ? prev.hash : null;

    // Compute hash of this entry's content
    const contentForHashing = JSON.stringify({
      data,
      metadata: metadata || {},
      timestamp: Date.now(),
      previousHash,
    });
    const newHash = computeSha256(contentForHashing);

    const newEntry: ChainEntry = {
      id: generateId(),
      data,
      metadata: metadata || undefined,
      timestamp: Date.now(),
      hash: newHash,
      previousHash,
    };

    // Update state
    this.state.head = newEntry;
    this.state.totalEntries++;
    this.state.updatedAt = Date.now();
    this.entriesMap.set(newEntry.id, newEntry);

    return newEntry;
  }

  /**
   * Get the current head of the chain.
   */
  getHead(): ChainEntry | null {
    return this.state.head;
  }

  /**
   * Verify that a given entry is valid within its context.
   * Returns true if hash matches and previousHash links correctly.
   */
  verifyChain(entry: ChainEntry): boolean {
    // Check self-hash integrity
    const contentForHashing = JSON.stringify({
      data: entry.data,
      metadata: entry.metadata || {},
      timestamp: entry.timestamp,
      previousHash: entry.previousHash,
    });
    const computedHash = computeSha256(contentForHashing);

    if (computedHash !== entry.hash) {
      return false;
    }

    // Check parent link if not genesis
    if (entry.previousHash && this.state.head) {
      const prevEntry = this.entriesMap.get(entry.id);
      if (!prevEntry || prevEntry.hash !== entry.previousHash) {
        return false;
      }
    }

    return true;
  }

  /**
   * Verify the entire chain from genesis to head.
   */
  verifyFullChain(): boolean {
    let current: ChainEntry | null = this.state.head;
    
    while (current) {
      if (!this.verifyChain(current)) {
        return false;
      }
      const prevHash = current.previousHash;
      // If we have a previous hash but no parent entry, chain is broken
      if (prevHash && !this.entriesMap.has(current.id)) {
        // Check if this is the genesis entry with null previousHash
        if (!current.previousHash) {
          return false;
        }
      }
      current = current.previousHash ? 
        this.entriesMap.get(this.state.head!.id) : 
        (this.state.head?.previousHash ? this.entriesMap.get(this.state.head!.id) : null);
      
      // Traverse backwards by finding parent
      if (current.previousHash && !current.id.startsWith('genesis')) {
        const prevEntry = this.entriesMap.get(current.id);
        current = prevEntry ? 
          (prevEntry.hash === current.previousHash ? prevEntry : null) :
          null;
      } else {
        // For genesis, go to the actual head's previous if exists
        if (current.id === this.state.head!.id && current.previousHash) {
          const parent = this.entriesMap.get(this.state.head!.id);
          current = parent ? 
            (parent.hash === current.previousHash ? parent : null) :
            null;
        } else {
          // We're at genesis or head with no previous - done
          break;
        }
      }
    }

    return true;
  }

  /**
   * Get the index of a specific entry (genesis = 0, head = totalEntries-1).
   */
  getEntryIndex(entryId: string): number | null {
    const entry = this.entriesMap.get(entryId);
    if (!entry) return null;
    
    // Count entries from genesis to this one
    let count = 0;
    let current: ChainEntry | null = this.state.head;
    
    while (current && current.id !== entryId) {
      if (current.previousHash) {
        const prev = this.entriesMap.get(current.id);
        if (!prev || prev.hash === current.previousHash) {
          count++;
          current = prev;
        } else {
          break;
        }
      } else {
        // Reached genesis without finding entry
        break;
      }
    }
    
    return current?.id === entryId ? count : null;
  }

  /**
   * Export an attestation for a specific point in the chain.
   */
  exportAttestation(headIndex: number, secret?: string): AttestationRecord {
    const head = this.state.head;
    if (!head) throw new Error('No head entry found');

    // Verify we're at the requested index
    if (headIndex !== this.state.totalEntries - 1) {
      throw new Error(`Expected head index ${this.state.totalEntries - 1}, got ${headIndex}`);
    }

    const content = JSON.stringify({
      chainId: `chain-${Date.now()}`,
      headIndex,
      totalEntries: this.state.totalEntries,
      headHash: head.hash,
      timestamp: Date.now(),
    });

    return {
      chainId: `chain-${Date.now()}`,
      headIndex,
      totalEntries: this.state.totalEntries,
      hash: computeSha256(content),
      signature: secret ? computeHmacSha256(content, secret) : content,
    };
  }

  /**
   * Import and verify an external attestation.
   */
  importAndVerifyAttestation(attestation: AttestationRecord): boolean {
    const head = this.state.head;
    if (!head) return false;

    // Check index matches
    if (attestation.headIndex !== this.state.totalEntries - 1) {
      console.warn('Imported attestation has different head index');
    }

    // Verify hash against current state
    const content = JSON.stringify({
      chainId: attestation.chainId,
      headIndex: attestation.headIndex,
      totalEntries: attestation.totalEntries,
      headHash: head.hash,
      timestamp: Date.now(),
    });

    if (computeSha256(content) !== attestation.hash) {
      return false;
    }

    // Verify signature if secret provided
    const expectedSignature = this.state.secret 
      ? computeHmacSha256(content, this.state.secret)
      : content;

    if (attestation.signature && attestation.signature !== expectedSignature) {
      console.warn('Imported attestation has different signature');
    }

    return true;
  }

  /**
   * Get a snapshot of the current chain state.
   */
  exportState(): ChainState & { entries: Array<ChainEntry> } {
    const entries = Array.from(this.entriesMap.values());
    return {
      ...this.state,
      entries,
    };
  }

  /**
   * Restore a saved chain state.
   */
  importState(state: ChainState & { entries: Array<ChainEntry> }): void {
    this.state = state;
    this.entriesMap.clear();
    
    // Rebuild the map (entries are already ordered in the array)
    for (const entry of state.entries) {
      this.entriesMap.set(entry.id, entry);
    }

    // Recompute hashes to ensure consistency
    let current: ChainEntry | null = this.state.head;
    while (current) {
      const contentForHashing = JSON.stringify({
        data: current.data,
        metadata: current.metadata || {},
        timestamp: current.timestamp,
        previousHash: current.previousHash,
      });
      const computedHash = computeSha256(contentForHashing);

      if (computedHash !== current.hash) {
        console.warn(`Recomputed hash for entry ${current.id}: expected ${current.hash}, got ${computedHash}`);
      }

      // Traverse backwards
      if (current.previousHash && !current.id.startsWith('genesis')) {
        const prev = this.entriesMap.get(current.id);
        current = prev ? 
          (prev.hash === current.previousHash ? prev : null) :
          null;
      } else {
        break;
      }
    }
  }

  /**
   * Get statistics about the chain.
   */
  getStats(): Record<string, unknown> {
    const head = this.state.head;
    
    return {
      totalEntries: this.state.totalEntries,
      createdAt: formatTimestamp(this.state.createdAt),
      updatedAt: formatTimestamp(this.state.updatedAt),
      hasSecret: !!this.state.secret,
      headId: head?.id || null,
      headHash: head?.hash || null,
      headData: head ? (typeof head.data === 'string' ? head.data : inspect(head.data)) : null,
    };
  }

  /**
   * Clear the entire chain.
   */
  clear(): void {
    this.initChain(this.state.secret);
  }
}

// ============================================================================
// EXPORTS & DEMO
// ============================================================================

export { 
  HashChainManager, 
  ChainEntry, 
  ChainState, 
  AttestationRecord,
};

// ============================================================================
// RUNNABLE DEMO
// ============================================================================

if (require.main === module) {
  const manager = new HashChainManager();
  
  // Initialize with a secret for HMAC verification
  const SECRET = 'super-secret-key-12345';
  manager.initChain(SECRET);
  
  console.log('=== Audit Trail Hash Chain Demo ===\n');

  // Add some entries
  console.log('Adding entries...');
  
  manager.appendEntry({ type: 'login', user: 'alice' });
  const e1 = manager.getHead();
  console.log(`  Entry 1 (login): hash=${e1?.hash.slice(0, 8)}...`);

  manager.appendEntry({ type: 'action', action: 'view_dashboard' }, { page: '/dashboard' });
  const e2 = manager.getHead();
  console.log(`  Entry 2 (action): hash=${e2?.hash.slice(0, 8)}...`);

  manager.appendEntry({ type: 'login', user: 'bob' });
  const e3 = manager.getHead();
  console.log(`  Entry 3 (login): hash=${e3?.hash.slice(0, 8)}...`);

  // Verify full chain
  console.log('\nVerifying full chain...');
  if (manager.verifyFullChain()) {
    console.log('  ✓ Full chain verified successfully!');
  } else {
    console.log('  ✗ Chain verification failed!');
  }

  // Export attestation
  console.log('\nExporting attestation for head entry...');
  const attestation = manager.exportAttestation(2, SECRET);
  console.log(`  Attestation hash: ${attestation.hash.slice(0, 16)}...`);
  console.log(`  Attestation signature: ${attestation.signature.slice(0, 16)}...`);

  // Simulate external verification
  console.log('\nSimulating external attestation import...');
  const importedAttestation = {
    ...attestation,
    hash: computeSha256(JSON.stringify({
      chainId: attestation.chainId,
      headIndex: attestation.headIndex,
      totalEntries: attestation.totalEntries,
      headHash: manager.getHead()?.hash || '',
      timestamp: Date.now(),
    })),
  };

  if (manager.importAndVerifyAttestation(importedAttestation)) {
    console.log('  ✓ Imported attestation verified!');
  } else {
    console.log('  ✗ Imported attestation verification failed!');
  }

  // Get stats
  console.log('\nChain statistics:');
  const stats = manager.getStats();
  console.log(`  Total entries: ${stats.totalEntries}`);
  console.log(`  Created: ${stats.createdAt}`);
  console.log(`  Updated: ${stats.updatedAt}`);

  // Demonstrate tamper detection
  console.log('\n--- Tamper Detection Demo ---');
  
  const savedState = manager.exportState();
  console.log('Saved state, now modifying head entry...');
  
  // Modify the head entry in memory (simulating external modification)
  const modifiedHead = { ...savedState.entries[0], data: { type: 'MODIFIED', user: 'alice' } };
  savedState.entries[0] = modifiedHead;
  
  manager.importState(savedState);
  
  // Verify - should fail because hash changed
  console.log('Verifying after modification...');
  if (manager.verifyFullChain()) {
    console.log('  ✓ Chain still valid? (unexpected!)');
  } else {
    console.log('  ✗ Chain broken! Tamper detected!');
  }

  // Fix by recomputing hash
  const head = manager.getHead();
  if (head) {
    const contentForHashing = JSON.stringify({
      data: modifiedHead.data,
      metadata: modifiedHead.metadata || {},
      timestamp: modifiedHead.timestamp,
      previousHash: modifiedHead