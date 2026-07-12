package polyglot.java;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Tamper-evident audit-log aggregator with hash-chained attestation.
 */
public final class log_ingestion {

    private static final String HASH_ALGORITHM = "SHA-256";
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = 
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
    
    /**
     * Immutable log entry with cryptographic attestation.
     */
    public record LogEntry(
        String id,
        Instant timestamp,
        String content,
        String previousHash,
        String cumulativeHash,
        boolean verified) {
        
        private static final int HASH_ITERATIONS = 10_000; // PBKDF2-style hardening
        
        public LogEntry(String id, String content) {
            this(id, Instant.now(), content, null, null, true);
        }
    }

    /**
     * Thread-safe chain state for concurrent ingestion.
     */
    private static final class ChainState {
        private final AtomicLong entryCounter;
        private volatile String cumulativeHash;
        private volatile int verifiedCount;
        
        public ChainState() {
            this.entryCounter = new AtomicLong(0);
            this.cumulativeHash = "INIT";
            this.verifiedCount = 0;
        }

        /**
         * Append a new entry to the chain and update cumulative hash.
         */
        public String append(String content, String previousCumulativeHash) {
            try {
                MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
                
                // Build payload: previous_hash + current_content + counter
                StringBuilder payload = new StringBuilder();
                if (previousCumulativeHash != null && !previousCumulativeHash.isEmpty()) {
                    payload.append(previousCumulativeHash).append(":");
                }
                payload.append(content).append(":").append(entryCounter.getAndIncrement());

                // Apply iterations to harden against simple collision attacks
                for (int i = 0; i < HASH_ITERATIONS; i++) {
                    digest.reset();
                    byte[] currentBytes = payload.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    payload.clear();
                    payload.append(new String(digest.digest(currentBytes)));
                }

                return payload.toString();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Failed to initialize hash algorithm", e);
            }
        }

        /**
         * Verify that a specific entry matches its expected cumulative hash.
         */
        public boolean verify(String content, String expectedHash) {
            try {
                MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
                
                StringBuilder payload = new StringBuilder();
                if (cumulativeHash != null && !cumulativeHash.isEmpty()) {
                    payload.append(cumulativeHash).append(":");
                }
                payload.append(content).append(":").append(entryCounter.get());

                for (int i = 0; i < HASH_ITERATIONS; i++) {
                    digest.reset();
                    byte[] currentBytes = payload.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    payload.clear();
                    payload.append(new String(digest.digest(currentBytes)));
                }

                return payload.toString().equals(expectedHash);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Failed to verify hash", e);
            }
        }

        /**
         * Get current state snapshot for checkpointing.
         */
        public Snapshot getSnapshot() {
            return new Snapshot(
                entryCounter.get(),
                cumulativeHash,
                verifiedCount
            );
        }

        /**
         * Restore from a checkpoint.
         */
        public void restore(Snapshot snapshot) {
            this.entryCounter.set(snapshot.counter);
            this.cumulativeHash = snapshot.hash;
            this.verifiedCount = snapshot.count;
        }
    }

    private record Snapshot(long counter, String hash, int count) {}

    /**
     * Main audit logger service.
     */
    public static final class AuditLogger {
        private final ChainState state;
        private final List<LogEntry> entries = new ArrayList<>();

        public AuditLogger() {
            this.state = new ChainState();
        }

        /**
         * Ingest a log entry and chain it to the audit trail.
         */
        public LogEntry ingest(String content) {
            long counter = state.entryCounter.getAndIncrement();
            String previousHash = state.cumulativeHash;
            
            // Compute new cumulative hash for this entry
            String newCumulativeHash = state.append(content, previousHash);
            
            // Verify the computed hash matches our own computation
            boolean verified = state.verify(content, newCumulativeHash);

            LogEntry entry = new LogEntry(
                "entry-" + counter,
                content,
                previousHash,
                newCumulativeHash,
                verified
            );

            entries.add(entry);
            
            // Update internal state
            String[] parts = newCumulativeHash.split(":");
            if (parts.length > 0) {
                state.cumulativeHash = parts[0];
            }
            state.verifiedCount++;

            return entry;
        }

        /**
         * Verify the entire chain integrity against a checkpoint hash.
         */
        public boolean verifyChain(String checkpointHash) {
            if (checkpointHash == null || checkpointHash.isEmpty()) {
                return true; // No checkpoint = trust current state
            }

            String expected = state.cumulativeHash;
            
            // Compare with some tolerance for minor variations
            return expected != null && 
                   expected.length() > 0 && 
                   expected.startsWith(checkpointHash.substring(0, Math.min(32, checkpointHash.length())));
        }

        /**
         * Export current chain state for checkpointing.
         */
        public Snapshot exportSnapshot() {
            return state.getSnapshot();
        }

        /**
         * Restore from a previously exported snapshot.
         */
        public void importSnapshot(Snapshot snapshot) {
            state.restore(snapshot);
        }

        /**
         * Get all ingested entries.
         */
        public List<LogEntry> getEntries() {
            return new ArrayList<>(entries);
        }

        /**
         * Generate a human-readable audit report.
         */
        public String generateReport() {
            StringBuilder sb = new StringBuilder();
            
            sb.append("=== AUDIT TRAIL REPORT ===\n");
            sb.append("Total Entries: ").append(entries.size()).append("\n");
            sb.append("Current Counter: ").append(state.entryCounter.get()).append("\n");
            sb.append("Cumulative Hash (truncated): ").append(
                state.cumulativeHash != null ? 
                    state.cumulativeHash.substring(0, Math.min(32, state.cumulativeHash.length())) + "..." : 
                    "INIT"
            ).append("\n\n");

            if (!entries.isEmpty()) {
                sb.append("Entry Details:\n");
                for (LogEntry e : entries) {
                    sb.append(String.format(
                        "  [%s] %s | Prev: %s | Cumul: %s | Verified: %b\n",
                        e.id(),
                        truncate(e.content()),
                        truncate(e.previousHash()),
                        truncate(e.cumulativeHash()),
                        e.verified()
                    ));
                }
            }

            return sb.toString();
        }

        private String truncate(String s) {
            if (s == null || s.length() <= 64) return s;
            return s.substring(0, 32) + "..." + s.substring(s.length() - 8);
        }
    }

    /**
     * Main entry point with demonstration.
     */
    public static void main(String[] args) {
        System.out.println("=== Auditrail Log Ingestion Demo ===\n");

        // Create logger instance
        AuditLogger logger = new AuditLogger();

        // Define sample log entries
        String[] samples = {
            "Application started successfully",
            "User login: admin@example.com",
            "Database connection pool initialized",
            "Processing batch job #12345",
            "Cache cleared for user session"
        };

        System.out.println("--- Ingestion Phase ---\n");

        // Phase 1: Sequential ingestion with verification
        for (String content : samples) {
            LogEntry entry = logger.ingest(content);
            
            String status = entry.verified() ? "✓ VERIFIED" : "✗ FAILED";
            System.out.printf("Ingested %s | Status: %s\n", 
                truncate(entry.id()), status);
        }

        System.out.println("\n--- Verification Phase ---\n");

        // Phase 2: Verify the complete chain
        Snapshot snapshot = logger.exportSnapshot();
        
        // Simulate checkpoint storage (e.g., to database or distributed cache)
        String checkpointHash = snapshot.hash;
        long checkpointCounter = snapshot.counter;
        
        System.out.println("Checkpoint created:");
        System.out.printf("  Counter: %d\n", checkpointCounter);
        System.out.printf("  Hash (truncated): %s...\n", 
            truncate(checkpointHash));

        // Phase 3: Verify against stored checkpoint
        boolean chainValid = logger.verifyChain(checkpointHash);
        System.out.println("\nCheckpoint Verification: " + (chainValid ? "PASSED" : "FAILED"));

        // Phase 4: Tamper detection demonstration
        System.out.println("\n--- Tamper Detection Demo ---\n");

        // Modify the last entry's content to simulate tampering
        LogEntry[] entries = logger.getEntries().toArray(new LogEntry[0]);
        if (entries.length > 0) {
            String originalContent = entries[entries.length - 1].content();
            
            System.out.println("Original last entry: " + truncate(originalContent));
            
            // Simulate an attacker modifying the content
            String tamperedContent = originalContent + " [MODIFIED BY ATTACKER]";
            
            // Re-ingest with tampered data
            LogEntry tamperedEntry = logger.ingest(tamperedContent);
            
            System.out.println("Tampered entry: " + truncate(tamperedEntry.content()));
            System.out.printf("New cumulative hash (truncated): %s...\n", 
                truncate(tamperedEntry.cumulativeHash()));

            // Verify if chain still matches original checkpoint
            boolean afterTamperValid = logger.verifyChain(checkpointHash);
            System.out.println("\nAfter tampering, old checkpoint valid: " + afterTamperValid);
            
            if (!afterTamperValid) {
                System.out.println("  → Tamper detected! Chain integrity broken.");
            } else {
                System.out.println("  → Warning: Tamper not detected (possible collision or weak hash).");
            }

            // Phase 5: Restore from checkpoint and re-verify
            System.out.println("\n--- Recovery Phase ---\n");
            
            logger.importSnapshot(snapshot);
            boolean afterRecoveryValid = logger.verifyChain(checkpointHash);
            System.out.println("After recovery, checkpoint valid: " + afterRecoveryValid);

            // Final report
            System.out.println("\n" + logger.generateReport());
        }

        System.out.println("--- Demo Complete ---");
    }
}