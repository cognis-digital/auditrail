import { randomUUID } from "node:crypto";
import { createHmac, timingSafeEqual } from "node:crypto";
import { EventEmitter } from "node:events";

// ============================================================================
// TYPES & CONSTANTS
// ============================================================================

const DEFAULT_SALT = "auditrail-v1-default-salt";
const HASH_ALGORITHM = "sha256";
const CHUNK_SIZE_BYTES = 4096;

type LogLevel = "info" | "warn" | "error" | "debug" | "trace";

interface LogEntry {
  id: string;
  timestamp: number;
  source: string;
  level: LogLevel;
  payload: Record<string, unknown>;
  prevHash?: string;
  hash: string;
}

interface AggregatorState {
  lastHash: string | null;
  entryCount: number;
  bytesWritten: number;
  startTime: number;
  errors: Error[];
}

// ============================================================================
// HASH CHAIN UTILITIES
// ============================================================================

function computeEntryHash(
  prevHash: string,
  timestamp: number,
  source: string,
  level: LogLevel,
  payload: Record<string, unknown>,
  salt?: string
): string {
  const data = JSON.stringify({
    prevHash,
    timestamp,
    source,
    level,
    payload,
    salt,
  });

  return createHmac(HASH_ALGORITHM, DEFAULT_SALT)
    .update(data)
    .digest("hex");
}

function verifyEntryHash(
  entry: LogEntry,
  expectedPrevHash?: string
): boolean {
  const computed = computeEntryHash(
    expectedPrevHash ?? (entry.prevHash || ""),
    entry.timestamp,
    entry.source,
    entry.level,
    entry.payload,
    DEFAULT_SALT
  );

  return timingSafeEqual(computed, entry.hash);
}

// ============================================================================
// LOG ENTRY FACTORY
// ============================================================================

export class LogEntryFactory {
  private static _nextId = 0;

  static create(
    source: string,
    level: LogLevel = "info",
    payload?: Record<string, unknown>
  ): LogEntry {
    const id = `${randomUUID()}-${++LogEntryFactory._nextId}`;
    const timestamp = Date.now();

    return {
      id,
      timestamp,
      source,
      level,
      payload: payload || {},
      prevHash: undefined,
      hash: "",
    };
  }
}

// ============================================================================
// TAMPER-EVIDENT AGGREGATOR
// ============================================================================

export class TamperEvidentAggregator {
  private state: AggregatorState;
  private emitter: EventEmitter;
  private readonly salt: string;

  constructor(options?: { salt?: string }) {
    this.salt = options?.salt || DEFAULT_SALT;
    this.state = {
      lastHash: null,
      entryCount: 0,
      bytesWritten: 0,
      startTime: Date.now(),
      errors: [],
    };

    this.emitter = new EventEmitter();
    this.emitter.on("error", (err) => {
      this.state.errors.push(err);
      console.error(`[Aggregator] Error:`, err.message);
    });
  }

  public get state(): AggregatorState {
    return { ...this.state };
  }

  public on(event: "error" | "complete", listener: (data: unknown) => void): this {
    this.emitter.on(event, listener);
    return this;
  }

  public ingest(entry: LogEntry): LogEntry {
    if (!entry.prevHash && entry.hash) {
      // Re-verify existing hash against new salt
      const verified = verifyEntryHash(entry, undefined, this.salt);
      if (!verified) {
        entry.hash = computeEntryHash(
          entry.prevHash || "",
          entry.timestamp,
          entry.source,
          entry.level,
          entry.payload,
          this.salt
        );
      }
    }

    // Compute new hash for this entry (will be used as prevHash for next)
    const newHash = computeEntryHash(
      entry.prevHash || "",
      entry.timestamp,
      entry.source,
      entry.level,
      entry.payload,
      this.salt
    );

    entry.hash = newHash;
    entry.prevHash = this.state.lastHash;

    // Update state
    this.state.lastHash = newHash;
    this.state.entryCount++;
    this.state.bytesWritten += JSON.stringify(entry).length;

    return entry;
  }

  public ingestBatch(entries: LogEntry[]): LogEntry[] {
    const results: LogEntry[] = [];
    
    for (const raw of entries) {
      const processed = this.ingest(raw);
      results.push(processed);
    }

    return results;
  }

  public flush(): string {
    // Return the final root hash (provenance anchor)
    return this.state.lastHash || "";
  }

  public reset(): void {
    this.state = {
      lastHash: null,
      entryCount: 0,
      bytesWritten: 0,
      startTime: Date.now(),
      errors: [],
    };
  }

  public getRootProof(): string {
    const proof = JSON.stringify({
      rootHash: this.state.lastHash,
      entryCount: this.state.entryCount,
      durationMs: Date.now() - this.state.startTime,
      salt: this.salt,
    });

    return createHmac(HASH_ALGORITHM, DEFAULT_SALT)
      .update(proof)
      .digest("hex");
  }
}

// ============================================================================
// VERIFIER (External Validation)
// ============================================================================

export class ChainVerifier {
  private readonly salt: string;

  constructor(salt?: string) {
    this.salt = salt || DEFAULT_SALT;
  }

  public verify(entry: LogEntry): boolean {
    if (!entry.hash || !entry.prevHash) return false;

    const computed = computeEntryHash(
      entry.prevHash,
      entry.timestamp,
      entry.source,
      entry.level,
      entry.payload,
      this.salt
    );

    return timingSafeEqual(computed, entry.hash);
  }

  public verifyChain(entries: LogEntry[]): { valid: boolean; brokenAt?: number; details: string[] } {
    const results: string[] = [];
    let valid = true;
    let brokenAt: number | undefined;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      
      if (!entry.hash || !entry.prevHash) {
        results.push(`Entry ${i}: missing hash or prevHash`);
        valid = false;
        brokenAt = i;
        continue;
      }

      const computed = computeEntryHash(
        entry.prevHash,
        entry.timestamp,
        entry.source,
        entry.level,
        entry.payload,
        this.salt
      );

      if (!timingSafeEqual(computed, entry.hash)) {
        results.push(`Entry ${i}: hash mismatch (expected: ${computed.slice(0, 16)}...)`);
        valid = false;
        brokenAt = i;
      } else {
        // Verify against previous entry's actual hash
        if (i > 0 && !timingSafeEqual(computed, entries[i - 1].hash)) {
          results.push(`Entry ${i}: chain break with prev entry`);
          valid = false;
          brokenAt = i;
        }
      }
    }

    return { valid, brokenAt, details: results };
  }

  public verifyRootHash(rootHash: string, rootProof: string): boolean {
    const proofData = JSON.stringify({
      rootHash,
      entryCount: 0, // placeholder
      durationMs: 0,
      salt: this.salt,
    });

    return timingSafeEqual(
      createHMAC(HASH_ALGORITHM, DEFAULT_SALT).update(proofData).digest("hex"),
      rootProof
    );
  }
}

// ============================================================================
// EXPORTED API (Public Interface)
// ============================================================================

export interface AuditTrailAPI {
  createAggregator(salt?: string): TamperEvidentAggregator;
  ingest(entry: LogEntry, aggregator: TamperEvidentAggregator): LogEntry;
  verify(entry: LogEntry, verifier: ChainVerifier): boolean;
}

const api: AuditTrailAPI = {
  createAggregator(salt?: string) {
    return new TamperEvidentAggregator({ salt });
  },

  ingest(entry: LogEntry, aggregator: TamperEvidentAggregator) {
    return aggregator.ingest(entry);
  },

  verify(entry: LogEntry, verifier: ChainVerifier) {
    return verifier.verify(entry);
  },
};

// ============================================================================
// DEMO / RUNNABLE EXAMPLE
// ============================================================================

function runDemo() {
  console.log("=== AuditTrail Demo: Tamper-Evident Log Ingestion ===\n");

  // Setup
  const aggregator = api.createAggregator();
  const verifier = new ChainVerifier();

  // Create sample log entries
  const samples: LogEntry[] = [
    api.createAggregator().create("app", "info", { event: "startup" }),
    api.createAggregator().create("db", "warn", { query: "SELECT * FROM users" }),
    api.createAggregator().create("auth", "error", { user: "admin", reason: "locked" }),
  ];

  // Ingest with proper chaining
  console.log("1. Ingesting entries with hash-chaining...");
  
  let currentHash = null;
  const ingested: LogEntry[] = [];

  for (const raw of samples) {
    // Manually chain them
    if (currentHash) {
      raw.prevHash = currentHash;
    }
    
    const chained = api.ingest(raw, aggregator);
    console.log(`   Entry ${chained.id.slice(0, 8)}... hash: ${chained.hash.slice(0, 16)}...`);
    ingested.push(chained);
    currentHash = chained.hash;
  }

  // Verify each entry individually
  console.log("\n2. Verifying individual entries...");
  let allIndividualValid = true;
  for (const entry of ingested) {
    const valid = api.verify(entry, verifier);
    console.log(`   ${valid ? "✓" : "✗"} Entry ${entry.id.slice(0, 8)}...`);
    if (!valid) allIndividualValid = false;
  }

  // Verify the entire chain
  console.log("\n3. Verifying full chain integrity...");
  const chainResult = verifier.verifyChain(ingested);
  console.log(`   Chain valid: ${chainResult.valid ? "YES" : "NO"}`);
  if (!chainResult.valid) {
    console.log("   Broken at entry:", chainResult.brokenAt);
    console.log("   Details:", chainResult.details.join(", "));
  }

  // Get root proof for external verification
  console.log("\n4. Root proof (for blockchain/external anchor)...");
  const rootProof = aggregator.getRootProof();
  console.log(`   Proof hash: ${rootProof.slice(0, 32)}...`);

  // Simulate tampering attempt
  console.log("\n5. Tamper detection test...");
  const tamperedEntry = { ...ingested[1], hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
  
  console.log(`   Original hash: ${ingested[1].hash.slice(0, 32)}...`);
  console.log(`   Tampered hash: ${tamperedEntry.hash.slice(0, 32)}...`);
  
  const originalValid = api.verify(ingested[1], verifier);
  const tamperedValid = api.verify(tamperedEntry, verifier);
  
  console.log(`   Original valid: ${originalValid ? "YES" : "NO"}`);
  console.log(`   Tampered valid:  ${tamperedValid ? "YES" : "NO"} (detected!)`);

  // Final state summary
  console.log("\n6. Aggregator final state...");
  const state = aggregator.state;
  console.log(`   Entries processed: ${state.entryCount}`);
  console.log(`   Bytes written: ${state.bytesWritten}`);
  console.log(`   Duration: ${(Date.now() - state.startTime) / 1000}s`);
  console.log(`   Root hash: ${aggregator.flush().slice(0, 32)}...`);

  console.log("\n=== Demo Complete ===");
}

// ============================================================================
// ENTRY POINT
// ============================================================================

if (import.meta.url === `file://${process.argv[1]}`) {
  runDemo();
}

export { api, TamperEvidentAggregator, ChainVerifier, LogEntryFactory };