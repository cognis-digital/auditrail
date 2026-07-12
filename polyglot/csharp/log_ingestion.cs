using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace polyglot.csharp
{
    /// <summary>
    /// Represents a single log entry in the tamper-evident chain.
    /// </summary>
    public sealed class LogEntry
    {
        public string Content { get; }
        public DateTime Timestamp { get; }
        public string SourceId { get; }
        public string PreviousHash { get; }
        public string EntryHash { get; }

        public LogEntry(string content, DateTime timestamp = default, 
                       string sourceId = null, string previousHash = null)
        {
            Content = content ?? throw new ArgumentNullException(nameof(content));
            Timestamp = timestamp;
            SourceId = sourceId;
            PreviousHash = previousHash;
            EntryHash = ComputeEntryHash();
        }

        private static string ComputeEntryHash()
        {
            var data = new StringBuilder();
            data.AppendLine(Content);
            data.AppendLine(Timestamp.ToString("o"));
            data.AppendLine(SourceId ?? "");
            data.AppendLine(PreviousHash ?? "");
            
            using var sha256 = SHA256.Create();
            return Convert.ToHexString(sha256.ComputeData(data));
        }

        public static string ComputeEntryHash(string content, DateTime timestamp, 
                                           string sourceId, string previousHash)
        {
            var entry = new LogEntry(content, timestamp, sourceId, previousHash);
            return entry.EntryHash;
        }
    }

    /// <summary>
    /// Aggregates log entries into a tamper-evident chain.
    /// </summary>
    public sealed class AuditLogAggregator
    {
        private readonly List<LogEntry> _entries = new();
        private string _rootHash;

        public IReadOnlyList<LogEntry> Entries => _entries.AsReadOnly();
        public string RootHash 
        { 
            get => _rootHash ?? ComputeRootHash(); 
            set => _rootHash = value;
        }

        public int Count => _entries.Count;

        /// <summary>
        /// Ingests a batch of log entries, validating chain integrity.
        /// </summary>
        /// <param name="newEntries">Log entries to ingest.</param>
        /// <returns>True if all entries were successfully appended.</returns>
        public bool Ingest(IEnumerable<LogEntry> newEntries)
        {
            var previousHash = _rootHash;

            foreach (var entry in newEntries)
            {
                // Verify the chain continues correctly
                if (!string.Equals(entry.PreviousHash, previousHash, StringComparison.Ordinal))
                {
                    throw new AuditChainException(
                        $"Chain break detected: expected '{previousHash}', got '{entry.PreviousHash}'");
                }

                _entries.Add(entry);
                previousHash = entry.EntryHash;
            }

            RootHash = previousHash;
            return true;
        }

        /// <summary>
        /// Computes the root hash of the entire chain.
        /// </summary>
        private string ComputeRootHash()
        {
            if (_entries.Count == 0)
                return "root:empty";

            var data = new StringBuilder();
            data.AppendLine(_rootHash);
            
            foreach (var entry in _entries)
            {
                data.AppendLine(entry.EntryHash);
                data.AppendLine(entry.Content);
                data.AppendLine(entry.Timestamp.ToString("o"));
                data.AppendLine(entry.SourceId ?? "");
            }

            using var sha256 = SHA256.Create();
            return Convert.ToHexString(sha256.ComputeData(data));
        }

        /// <summary>
        /// Verifies the entire chain integrity against expected root hash.
        /// </summary>
        public bool Verify(string expectedRootHash)
        {
            if (string.IsNullOrEmpty(expectedRootHash))
                return _entries.Count == 0;

            var computed = ComputeRootHash();
            return string.Equals(computed, expectedRootHash, StringComparison.Ordinal);
        }

        /// <summary>
        /// Exports the chain to a JSON-compatible format.
        /// </summary>
        public string Export()
        {
            var sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine($"  \"root_hash\": \"{RootHash}\",");
            sb.AppendLine($"  \"entry_count\": {Count},");
            sb.AppendLine($"  \"entries\": [");

            for (int i = 0; i < _entries.Count; i++)
            {
                var e = _entries[i];
                sb.Append("    {");
                sb.Append($"""
                    "content": "{EscapeJson(e.Content)}",
                    "timestamp": "{e.Timestamp:o}",
                    "source_id": "{(e.SourceId ?? "")}",
                    "entry_hash": "{e.EntryHash}"
                    """);
                
                if (i < _entries.Count - 1)
                    sb.Append(",");
                sb.AppendLine("    }");
            }

            sb.AppendLine("  ]");
            sb.AppendLine("}");
            return sb.ToString();
        }

        private static string EscapeJson(string s) => 
            s.Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");
    }

    /// <summary>
    /// Exception thrown when the audit chain is broken or corrupted.
    /// </summary>
    public sealed class AuditChainException : Exception
    {
        public AuditChainException(string message) 
            : base(message) { }
    }

    /// <summary>
    /// Entry point for demonstration and testing.
    /// </summary>
    public static class Program
    {
        public static void Main()
        {
            var aggregator = new AuditLogAggregator();

            // Create sample log entries with proper chain linking
            var entry1 = new LogEntry("User login: admin", sourceId: "auth-service");
            var entry2 = new LogEntry("Query executed: SELECT * FROM users", 
                                      previousHash: entry1.EntryHash, sourceId: "db-proxy");
            var entry3 = new LogEntry("File upload: report.pdf (5MB)", 
                                      previousHash: entry2.EntryHash, sourceId: "upload-service");

            // Ingest the entries
            Console.WriteLine($"Ingesting {entry1.Count} + {entry2.Count} + {entry3.Count} entries...");
            
            var success = aggregator.Ingest(new[] { entry1, entry2, entry3 });
            
            if (success)
                Console.WriteLine("✓ Ingestion complete. Root hash: " + aggregator.RootHash);
            else
                Console.WriteLine("✗ Ingestion failed.");

            // Verify integrity
            var expectedRoot = aggregator.RootHash;
            bool verified = aggregator.Verify(expectedRoot);
            Console.WriteLine($"Integrity check (expected='{expectedRoot}'): {(verified ? "PASS" : "FAIL")}");

            // Simulate tampering attempt
            Console.WriteLine("\n--- Tamper Simulation ---");
            
            var corruptedEntry = new LogEntry("Injected malicious content", 
                                             previousHash: aggregator.RootHash, 
                                             sourceId: "attacker");
            
            try
            {
                aggregator.Ingest(new[] { corruptedEntry });
                Console.WriteLine("✗ Corrupted entry accepted (bad state)");
            }
            catch (AuditChainException ex)
            {
                Console.WriteLine($"✓ Corrupted entry rejected: {ex.Message}");
            }

            // Create a new chain after tampering detection
            var freshEntry = new LogEntry("System recovered", 
                                          previousHash: aggregator.RootHash, 
                                          sourceId: "monitoring");
            
            aggregator.Ingest(new[] { freshEntry });
            Console.WriteLine($"New root hash after recovery: {aggregator.RootHash}");

            // Export for audit trail
            var json = aggregator.Export();
            Console.WriteLine("\n--- Audit Trail JSON ---");
            Console.WriteLine(json);

            // Final verification
            var finalRoot = aggregator.RootHash;
            bool finalCheck = aggregator.Verify(finalRoot);
            Console.WriteLine($"\nFinal integrity check: {(finalCheck ? "PASS" : "FAIL")}");
        }
    }
}