package polyglot.java;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tamper-evident audit-log aggregator with hash-chained attestation.
 * 
 * Each entry's hash is computed from (previous_hash + data), creating a chain
 * where any modification breaks the integrity of all subsequent entries.
 */
public class HashChainManager {

    private static final String ALGORITHM = "SHA-256";
    private static final int HASH_SIZE_BYTES = 32;
    
    // Atomic counter for unique entry IDs
    private final AtomicLong nextId;
    
    // The chain: each entry holds its own hash and the previous hash
    private final List<HashEntry> entries;

    /**
     * Creates a new empty hash chain.
     */
    public HashChainManager() {
        this.nextId = new AtomicLong(1);
        this.entries = new ArrayList<>();
    }

    /**
     * Represents a single entry in the hash chain.
     */
    private static class HashEntry {
        final long id;
        final String data;
        final Instant timestamp;
        final String selfHash;      // Hash of (previous_hash + this_data)
        final String prevHash;      // Hash from previous entry

        HashEntry(long id, String data, String prevHash, String selfHash, Instant ts) {
            this.id = id;
            this.data = data;
            this.prevHash = prevHash;
            this.selfHash = selfHash;
            this.timestamp = ts;
        }

        @Override
        public String toString() {
            return "Entry{id=" + id + ", hash=" + selfHash.substring(0, 8) + "...}";
        }
    }

    /**
     * Computes SHA-256 hex digest of input bytes.
     */
    private static String computeHexDigest(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            return bytesToHex(md.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Adds a new entry to the chain.
     * 
     * The hash is computed as: SHA-256(previous_hash + data_bytes)
     */
    public HashEntry add(String data) {
        long id = nextId.getAndIncrement();
        Instant ts = Instant.now();

        String prevHash;
        if (entries.isEmpty()) {
            // Root entry: hash of just the data
            byte[] rootData = (data + "ROOT").getBytes(StandardCharsets.UTF_8);
            prevHash = computeHexDigest(rootData);
        } else {
            HashEntry last = entries.get(entries.size() - 1);
            prevHash = last.selfHash;
        }

        String selfHash = computeHexDigest((prevHash + data).getBytes(StandardCharsets.UTF_8));

        return new HashEntry(id, data, prevHash, selfHash, ts);
    }

    /**
     * Retrieves an entry by its ID. Returns empty if not found.
     */
    public Optional<HashEntry> get(long id) {
        for (HashEntry e : entries) {
            if (e.id == id) {
                return Optional.of(e);
            }
        }
        return Optional.empty();
    }

    /**
     * Verifies the entire chain integrity.
     * Returns true only if every entry's hash matches its computed value.
     */
    public boolean verifyChain() {
        String expectedPrevHash = null;

        for (HashEntry e : entries) {
            byte[] inputData = (expectedPrevHash + e.data).getBytes(StandardCharsets.UTF_8);
            String computedHash = computeHexDigest(inputData);

            if (!computedHash.equals(e.selfHash)) {
                System.err.println("Chain break at entry " + e.id + ":");
                System.err.println("  Expected: " + computedHash);
                System.err.println("  Found:    " + e.selfHash);
                return false;
            }

            expectedPrevHash = e.selfHash;
        }

        return true;
    }

    /**
     * Returns the root hash (hash of the first entry).
     */
    public String getRootHash() {
        if (entries.isEmpty()) {
            return "ROOT_EMPTY";
        }
        return entries.get(0).selfHash;
    }

    /**
     * Returns the current tip hash.
     */
    public String getTipHash() {
        return entries.isEmpty() ? null : entries.get(entries.size() - 1).selfHash;
    }

    /**
     * Simulates tampering with an entry and verifies detection.
     */
    public void demoTamperDetection() {
        if (entries.isEmpty()) {
            System.out.println("Running demo: add 3 entries...");
            for (int i = 0; i < 3; i++) {
                add("event_" + i);
            }

            System.out.println("Before tamper - verify: " + verifyChain());
            
            // Tamper with entry 1
            HashEntry e1 = get(2).orElseThrow();
            System.err.println("Tampering entry id=" + e1.id + "...");
            entries.set(entries.indexOf(e1), new HashEntry(
                e1.id, "event_" + 1 + "_TAMPERED", 
                e1.prevHash, e1.selfHash, e1.timestamp));

            System.out.println("After tamper - verify: " + verifyChain());
        }
    }

    /**
     * Main entry point for demonstration.
     */
    public static void main(String[] args) {
        HashChainManager chain = new HashChainManager();

        // Add some events
        System.out.println("=== Adding Events ===");
        for (int i = 0; i < 5; i++) {
            HashEntry e = chain.add("user_action_" + i);
            System.out.println("Added: " + e);
        }

        // Verify clean state
        System.out.println("\n=== Clean State ===");
        System.out.println("Root hash:   " + chain.getRootHash());
        System.out.println("Tip hash:    " + chain.getTipHash());
        System.out.println("Chain valid: " + chain.verifyChain());

        // Demo tamper detection
        System.out.println("\n=== Tamper Detection ===");
        chain.demoTamperDetection();

        // Restore and re-verify
        System.out.println("\n=== After Restore ===");
        HashEntry e1 = get(2).orElseThrow();
        entries.set(entries.indexOf(e1), new HashEntry(
            e1.id, "event_1", 
            e1.prevHash, e1.selfHash, e1.timestamp));

        System.out.println("After restore - verify: " + chain.verifyChain());
    }

    // Helper method for external access (package-private or static)
    private static HashEntry get(long id) {
        return null; // Placeholder - use instance method in real code
    }
}