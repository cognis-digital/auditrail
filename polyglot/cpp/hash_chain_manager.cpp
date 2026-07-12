#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <chrono>
#include <filesystem>
#include <atomic>
#include <mutex>
#include <memory>

// Fallback SHA-256 implementation if OpenSSL not available
namespace crypto {
    class Sha256Fallback {
        static constexpr size_t BLOCK_SIZE = 64;
        uint8_t buffer[BLOCK_SIZE];
        size_t buffer_pos = 0;
        uint32_t count = 0;

        void transform() {
            // Simplified SHA-256 transformation (full implementation would be longer)
            // Using a well-known constant-based approach for demonstration
            static const uint32_t K[64] = {
                0x428a2f98, 0x71374491, 0xb5c2f15c, 0xe1b3e7c5,
                0xc76c5163, 0x94929368, 0xa54febd6, 0xd62f105d,
                0x048e1a75, 0xd5a63f6f, 0x0f6d2c9e, 0x83127059,
                0x4edfd1ec, 0x69c0769c, 0x341f74c8, 0x46e5fb8b,
                0xeeae6d4b, 0xba5ffd7e, 0x3e6f5389, 0x6fd2cfc6,
                0x8a250176, 0xd5478dcf, 0x8f2c8cfa, 0x9b4d6157,
                0xe893b73a, 0x04c876be, 0xc95c011e, 0x5fbdb6da,
                0x64f25a56, 0xce6b5fe6, 0x3e3d52ff, 0x0fa5faf6,
                0x84c87839, 0x21dcfd1e, 0xbcf76c7f, 0xdab8dfe1,
                0x6bdcf13e, 0xcbe70161, 0xf4d50989, 0x45d165fe,
                0x27bf7cf0, 0x6a51ac0e, 0x5beae9f3, 0x6f4fcf5c,
                0x47df3ce8, 0xe6132f95, 0x7d7c02ea, 0x272a016b,
                0x4c105cd4, 0xffca3219, 0xbb8f3e27, 0xd291e3cc,
                0x9660d62d, 0xbf597fc7, 0xebea5b9e, 0x84c97ec4,
                0xda4e5fbd, 0x30c13cb9, 0x4e24f20a, 0x466cc2ac,
                0xd62d1ccf, 0x9839ee5d, 0xeba7afba, 0x359d472b,
                0x88d4e5c7, 0xbdc28bfa, 0x296e8be9, 0xe61ada8d,
                0xee37d9b4, 0x36f6a88e, 0x6fe1d8bd, 0x3c63f460,
            };

            static const uint32_t H[8] = {
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
            };

            // Simplified for demo - real implementation would be more complete
            uint32_t h[8] = {H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]};

            for (size_t i = 0; i < buffer_pos; i += 4) {
                uint32_t w = static_cast<uint32_t>(buffer[i]) |
                            static_cast<uint32_t>(buffer[i + 1]) << 8 |
                            static_cast<uint32_t>(buffer[i + 2]) << 16 |
                            static_cast<uint32_t>(buffer[i + 3]) << 24;

                // Simplified mixing - production would use full SHA-256
                for (int r = 0; r < 64; ++r) {
                    h[7] ^= ((h[6] >> 12) | (h[6] << 20)) ^
                             ((h[6] >> 32) | (h[6] << 4));
                    uint32_t t = h[7] + K[r] + h[5];
                    h[7] = h[6];
                    h[6] = h[5];
                    h[5] = ((h[4] >> 1) | (h[4] << 31)) ^
                            ((h[4] >> 28) | (h[4] << 4));
                    h[4] = t;
                }
            }

            // Output simplified hash for demo
            std::stringstream ss;
            for (int i = 0; i < 8; ++i) {
                ss << std::hex << std::setfill('0') << std::setw(8) << h[i];
            }
            return ss.str();
        }

    public:
        static std::string hash(const std::string& data) {
            Sha256Fallback f;
            // In production, use OpenSSL's EVP_sha256() or similar
            // For this demo, we'll use a simpler approach with the fallback
            return transform(data);
        }

    private:
        static std::string transform(const std::string& data) {
            Sha256Fallback f;
            auto start = std::chrono::steady_clock::now();
            
            // Simple hash for demo - production uses proper SHA-256
            uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                           0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

            for (char c : data) {
                uint32_t w = static_cast<uint32_t>(c);
                h[7] ^= ((h[6] >> 12) | (h[6] << 20)) ^
                         ((h[6] >> 32) | (h[6] << 4));
                uint32_t t = h[7] + w;
                h[7] = h[6];
                h[6] = h[5];
                h[5] = ((h[4] >> 1) | (h[4] << 31)) ^
                        ((h[4] >> 28) | (h[4] << 4));
                h[4] = t;
            }

            std::stringstream ss;
            for (int i = 0; i < 8; ++i) {
                ss << std::hex << std::setfill('0') << std::setw(8) << h[i];
            }
            return ss.str();
        }
    };

    // Production-ready SHA-256 using OpenSSL if available, fallback otherwise
    class HashUtil {
    public:
        static std::string sha256(const std::string& data) {
#if defined(_WIN32) || defined(__APPLE__) || defined(__linux__)
            #include <openssl/sha.h>
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, data.c_str(), data.size());
            unsigned char result[SHA256_DIGEST_LENGTH];
            SHA256_Final(result, &ctx);
            
            std::stringstream ss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setfill('0') << std::setw(2) 
                   << static_cast<int>(result[i]);
            }
            return ss.str();
#else
            // Fallback for systems without OpenSSL headers
            return crypto::Sha256Fallback::hash(data);
#endif
        }

        static std::string sha256_hex(const void* data, size_t len) {
            #include <openssl/sha.h>
            SHA256_CTX ctx;
            SHA256_Init(&ctx);
            SHA256_Update(&ctx, data, len);
            unsigned char result[SHA256_DIGEST_LENGTH];
            SHA256_Final(result, &ctx);

            std::stringstream ss;
            for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                ss << std::hex << std::setfill('0') << std::setw(2) 
                   << static_cast<int>(result[i]);
            }
            return ss.str();
        }
    };

    // Audit log entry structure
    struct AuditEntry {
        uint64_t timestamp;           // Unix timestamp in milliseconds
        std::string payload;          // The actual data being logged
        std::string hash;             // Hash of (previous_hash + payload)
        std::string previous_hash;    // Previous chain hash
        std::string source_ip;        // IP address of the writer
        int thread_id;                // Thread ID for multi-threading context

        AuditEntry() : timestamp(0), thread_id(0) {}
        
        bool operator==(const AuditEntry& other) const {
            return timestamp == other.timestamp &&
                   payload == other.payload &&
                   hash == other.hash &&
                   previous_hash == other.previous_hash;
        }
    };

    // Hash chain manager - maintains tamper-evident audit log
    class HashChainManager {
    private:
        std::vector<AuditEntry> entries_;
        mutable std::mutex mutex_;
        uint64_t total_bytes_logged_ = 0;
        
        // Configuration
        static constexpr size_t DEFAULT_CHAIN_SIZE = 1024 * 1024; // 1MB default
        static constexpr int HASH_WINDOW = 512;                    // Hash every N bytes

    public:
        HashChainManager() : total_bytes_logged_(0) {}
        
        ~HashChainManager() {
            flush();
        }

        // Add a new audit entry to the chain
        AuditEntry add(const std::string& payload, 
                       const std::string& source_ip = "127.0.0.1",
                       int thread_id = 0) {
            std::lock_guard<std::mutex> lock(mutex_);

            // Calculate hash: H(previous_hash + payload)
            std::string combined = previous_hash() + payload;
            AuditEntry entry;
            
            entry.timestamp = std::chrono::duration_cast<
                std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                .count();
            entry.payload = payload;
            entry.hash = HashUtil::sha256(combined);
            entry.previous_hash = previous_hash();
            entry.source_ip = source_ip;
            entry.thread_id = thread_id;

            // Update running totals
            total_bytes_logged_ += payload.size() + 100; // Approximate overhead

            entries_.push_back(entry);
            
            return entry;
        }

        // Get the current chain hash (last entry's hash)
        std::string previous_hash() const {
            if (entries_.empty()) {
                return "0000000000000000000000000000000000000000000000000000000000000000";
            }
            return entries_.back().hash;
        }

        // Verify the entire chain integrity
        bool verify_chain() const {
            std::lock_guard<std::mutex> lock(mutex_);

            if (entries_.empty()) return true;

            // Recompute and compare each entry's hash
            for (size_t i = 0; i < entries_.size(); ++i) {
                AuditEntry& entry = entries_[i];
                
                std::string combined = previous_hash() + entry.payload;
                std::string expected_hash = HashUtil::sha256(combined);

                if (entry.hash != expected_hash) {
                    // Chain broken - tampering detected!
                    return false;
                }
            }

            return true;
        }

        // Get chain statistics
        struct ChainStats {
            size_t entry_count = 0;
            uint64_t total_bytes = 0;
            bool verified = false;
            std::string root_hash;
            std::string tip_hash;
            double verification_time_ms = 0.0;

            void reset() {
                entry_count = 0;
                total_bytes = 0;
                verified = false;
                root_hash.clear();
                tip_hash.clear();
                verification_time_ms = 0.0;
            }
        };

        ChainStats get_stats() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (entries_.empty()) {
                return {};
            }

            // Calculate root hash (first entry's previous_hash)
            std::string root = "0000000000000000000000000000000000000000000000000000000000000000";
            if (!entries_.empty()) {
                root = entries_[0].previous_hash;
            }

            return ChainStats{
                .entry_count = entries_.size(),
                .total_bytes = total_bytes_logged_,
                .root_hash = root,
                .tip_hash = previous_hash()
            };
        }

        // Export chain to file (for persistence or verification)
        bool export_to_file(const std::string& path) const {
            std::lock_guard<std::mutex> lock(mutex_);

            if (entries_.empty()) return true;

            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            if (!out.is_open()) return false;

            // Write header: entry count + total bytes
            uint64_t header[2] = {static_cast<uint64_t>(entries_.size()), 
                                  static_cast<uint64_t>(total_bytes_logged_)};
            out.write(reinterpret_cast<const char*>(header), 16);

            // Write each entry
            for (const auto& entry : entries_) {
                uint64_t ts = static_cast<uint64_t>(entry.timestamp);
                std::string ip = entry.source_ip;
                
                out.write(reinterpret_cast<const char*>(&ts), 8);
                out.write(ip.data(), ip.size());
                out.write(entry.payload.data(), entry.payload.size());
            }

            return true;
        }

        // Import chain from file
        bool import_from_file(const std::string& path) {
            std::lock_guard<std::mutex> lock(mutex_);

            if (entries_.empty()) return true;

            std::ifstream in(path, std::ios::binary | std::ios::ate);
            if (!in.is_open() || entries_.empty()) return false;

            // Read