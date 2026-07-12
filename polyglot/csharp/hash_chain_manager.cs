using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace polyglot.csharp
{
    public class ChainEntry
    {
        public string Id { get; set; }
        public DateTime Timestamp { get; set; }
        public string Data { get; set; }
        public string PreviousHash { get; set; }
        public string Hash { get; set; }

        public ChainEntry(string id, string data)
        {
            Id = id;
            Data = data;
            Timestamp = DateTime.UtcNow;
            PreviousHash = null;
        }
    }

    public class HashChainManager
    {
        private readonly Dictionary<string, ChainEntry> _entries;
        private string _rootHash;

        public HashChainManager()
        {
            _entries = new Dictionary<string, ChainEntry>();
        }

        public void Initialize(string initialData)
        {
            var entry = CreateEntry("INIT", initialData);
            _entries[entry.Id] = entry;
            _rootHash = entry.Hash;
        }

        public ChainEntry AddEntry(string id, string data)
        {
            if (string.IsNullOrEmpty(id))
                throw new ArgumentException("ID required");

            var previous = GetHead();
            var prevHash = previous?.Hash ?? _rootHash;

            var entry = CreateEntry(id, data);
            entry.PreviousHash = prevHash;
            entry.Hash = ComputeHash(entry);

            _entries[entry.Id] = entry;
            return entry;
        }

        public string GetHeadHash()
        {
            var head = GetHead();
            return head?.Hash ?? _rootHash;
        }

        public bool VerifyIntegrity(string expectedRoot)
        {
            if (string.IsNullOrEmpty(expectedRoot))
                expectedRoot = _rootHash;

            var head = GetHead();
            return head?.Hash == expectedRoot || 
                   (_entries.Count == 1 && _entries.Values.First().Hash == expectedRoot);
        }

        public string ExportChain()
        {
            var sb = new StringBuilder();
            foreach (var entry in _entries.OrderBy(e => e.Key))
            {
                sb.AppendLine($"ID:{entry.Id}|TS:{entry.Timestamp:O}|DATA:{entry.Data}|PREV:{entry.PreviousHash}|HASH:{entry.Hash}");
            }
            return sb.ToString();
        }

        private ChainEntry CreateEntry(string id, string data)
        {
            return new ChainEntry(id, data);
        }

        private static string ComputeHash(ChainEntry entry)
        {
            var content = $"{entry.Id}|{entry.Timestamp:O}|{entry.Data}|{entry.PreviousHash}";
            using (var sha256 = SHA256.Create())
            {
                return Convert.ToHexString(sha256.ComputeHash(Encoding.UTF8.GetBytes(content)));
            }
        }

        private ChainEntry GetHead()
        {
            if (_entries.Count == 0) return null;

            var lastId = _entries.Keys.Last();
            return _entries[lastId];
        }
    }

    public class Program
    {
        public static void Main()
        {
            var manager = new HashChainManager();
            manager.Initialize("system-start");

            Console.WriteLine($"Root hash: {manager.GetHeadHash()}");

            for (int i = 1; i <= 5; i++)
            {
                var entry = manager.AddEntry($"event-{i}", $"Action by user at {DateTime.Now}");
                Console.WriteLine($"{entry.Id}: {entry.Hash.Substring(0, 8)}...");
            }

            Console.WriteLine($"\nFinal head hash: {manager.GetHeadHash()}");

            // Verify with a slight modification
            var modified = manager.AddEntry("event-6-modified", "Modified data");
            Console.WriteLine($"After modification: {modified.Hash.Substring(0, 8)}...");
        }
    }
}