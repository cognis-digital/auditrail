#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <filesystem>
#include <chrono>
#include <atomic>
#include <iomanip>
#include <memory>

// SHA-256 implementation (pure C++ for portability)
namespace crypto {

class Sha256 {
public:
    static constexpr size_t BLOCK_SIZE = 64;
    static constexpr size_t DIGEST_SIZE = 32;

    void reset() {
        h[0] = 0x6a09e667ULL;
        h[1] = 0xbb67ae85ULL;
        h[2] = 0x3c6ef372ULL;
        h[3] = 0xa54ff53aULL;
        h[4] = 0x510e527fULL;
        h[5] = 0x9b05688cULL;
        h[6] = 0x1f83d9abULL;
        h[7] = 0x5be0cd19ULL;
        count = 0;
    }

    void update(const uint8_t* data, size_t len) {
        if (count < BLOCK_SIZE) {
            for (size_t i = 0; i < len && count < BLOCK_SIZE; ++i) {
                buffer[count++] = data[i];
            }
            if (count == BLOCK_SIZE) {
                transform();
            }
        } else {
            // Full block, process in chunks
            size_t remaining = len;
            while (remaining >= BLOCK_SIZE) {
                transform(buffer);
                remaining -= BLOCK_SIZE;
            }
            for (size_t i = 0; i < remaining; ++i) {
                buffer[count++] = data[len - remaining + i];
            }
        }
    }

    void update(const std::string& str) {
        uint8_t buf[128];
        size_t len = str.size();
        for (size_t i = 0; i < len && i < 128; ++i) {
            buf[i] = static_cast<uint8_t>(str[i]);
        }
        update(buf, std::min(len, 128U));
    }

    void finish() {
        if (count < BLOCK_SIZE) {
            for (size_t i = count; i < BLOCK_SIZE; ++i) {
                buffer[i] = 0x80;
            }
            while (count % 64 != 56) {
                buffer[count++] = 0x00;
            }
        }

        uint64_t t1, t2, t3, t4, t5, t6, t7, t8;
        memcpy(&t1, &h[0], sizeof(t1));
        memcpy(&t2, &h[1], sizeof(t2));
        memcpy(&t3, &h[2], sizeof(t3));
        memcpy(&t4, &h[3], sizeof(t4));
        memcpy(&t5, &h[4], sizeof(t5));
        memcpy(&t6, &h[5], sizeof(t6));
        memcpy(&t7, &h[6], sizeof(t7));
        memcpy(&t8, &h[7], sizeof(t8));

        // Final transform with padding bits already set
        t1 = (t1 >> 2) | (t1 << 30);
        t2 = (t2 >> 2) | (t2 << 30);
        t3 = (t3 >> 2) | (t3 << 30);
        t4 = (t4 >> 2) | (t4 << 30);
        t5 = (t5 >> 2) | (t5 << 30);
        t6 = (t6 >> 2) | (t6 << 30);
        t7 = (t7 >> 2) | (t7 << 30);
        t8 = (t8 >> 2) | (t8 << 30);

        h[0] ^= static_cast<uint32_t>(t1 ^ t5);
        h[1] ^= static_cast<uint32_t>(t2 ^ t6);
        h[2] ^= static_cast<uint32_t>(t3 ^ t7);
        h[3] ^= static_cast<uint32_t>(t4 ^ t8);
        h[4] ^= static_cast<uint32_t>(t5 ^ t1);
        h[5] ^= static_cast<uint32_t>(t6 ^ t2);
        h[6] ^= static_cast<uint32_t>(t7 ^ t3);
        h[7] ^= static_cast<uint32_t>(t8 ^ t4);

        memcpy(&h[0], &t1, sizeof(t1));
        memcpy(&h[1], &t2, sizeof(t2));
        memcpy(&h[2], &t3, sizeof(t3));
        memcpy(&h[3], &t4, sizeof(t4));
        memcpy(&h[4], &t5, sizeof(t5));
        memcpy(&h[5], &t6, sizeof(t6));
        memcpy(&h[6], &t7, sizeof(t7));
        memcpy(&h[7], &t8, sizeof(t8));

        count = 0;
    }

    std::string digest() {
        finish();
        char hex[65];
        for (int i = 0; i < DIGEST_SIZE; ++i) {
            sprintf(hex + 2 * i, "%02x", h[i]);
        }
        return std::string(hex);
    }

private:
    uint8_t buffer[BLOCK_SIZE];
    size_t count;
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c2f15c, 0xe1b30e81,
        0x380af165, 0xc4bdeac2, 0x6beff82d, 0xa637ec86,
        0x1a4f5aa5, 0xd0683dd9, 0xf0b2f73e, 0x036ef3bb,
        0x2f497b1c, 0xad1b4684, 0x6d6cd205, 0x4e6db468,
        0x9249d4c9, 0xa353dade, 0xcefa5f97, 0x87c07877,
        0xa54ff53a, 0x618dcf12, 0x6b6fe1d4, 0x1a4f5aa5,
        0xd0683dd9, 0xf0b2f73e, 0x036ef3bb, 0x2f497b1c,
        0xad1b4684, 0x6d6cd205, 0x4e6db468, 0x9249d4c9,
        0xa353dade, 0xcefa5f97, 0x87c07877, 0xa54ff53a,
        0x618dcf12, 0x6b6fe1d4, 0x1a4f5aa5, 0xd0683dd9,
        0xf0b2f73e, 0x036ef3bb, 0x2f497b1c, 0xad1b4684,
        0x6d6cd205, 0x4e6db468, 0x9249d4c9, 0xa353dade,
        0xcefa5f97, 0x87c07877, 0xa54ff53a, 0x618dcf12,
        0x6b6fe1d4, 0x1a4f5aa5, 0xd0683dd9, 0xf0b2f73e,
        0x036ef3bb, 0x2f497b1c, 0xad1b4684, 0x6d6cd205,
        0x4e6db468, 0x9249d4c9, 0xa353dade, 0xcefa5f97,
        0x87c07877, 0xa54ff53a, 0x618dcf12, 0x6b6fe1d4
    };

    static constexpr uint32_t R[64] = {
        0x5a827999, 0x6ed9e61c, 0xf61ef377, 0x871c3715,
        0x676f02d4, 0x8d2c4c87, 0xa952de34, 0xe8c1b85d,
        0x6d6c20a0, 0x8da4f527, 0xd807090a, 0xefcdab19,
        0xc377c1dd, 0xf79e151e, 0xa123a8a3, 0xbadcf4d6,
        0x326d8ce7, 0x7a674b4f, 0x5a4d5a25, 0x6c3cd922,
        0x1dfc6e51, 0x4ccdd5e6, 0xf81995fc, 0x3956c65b,
        0xa74fe542, 0x6d6c20a0, 0x8da4f527, 0xd807090a,
        0xefcdab19, 0xc377c1dd, 0xf79e151e, 0xa123a8a3,
        0xbadcf4d6, 0x326d8ce7, 0x7a674b4f, 0x5a4d5a25,
        0x6c3cd922, 0x1dfc6e51, 0x4ccdd5e6, 0xf81995fc,
        0x3956c65b, 0xa74fe542, 0x6d6c20a0, 0x8da4f527,
        0xd807090a, 0xefcdab19, 0xc377c1dd, 0xf79e151e,
        0xa123a8a3, 0xbadcf4d6, 0x326d8ce7, 0x7a674b4f,
        0x5a4d5a25, 0x6c3cd922, 0x1dfc6e51, 0x4ccdd5e6,
        0xf81995fc, 0x3956c65b, 0xa74fe542, 0x6d6c20a0,
        0x8da4f527, 0xd807090a, 0xefcdab19, 0xc377c1dd
    };

    static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    void transform() {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = buffer[i * 4] | (buffer[i * 4 + 1] << 8) |
                   (buffer[i * 4 + 2] << 16) | (buffer[i * 4 + 3] << 24);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = rotr(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        uint32_t a, b, c, d, e, f, g, h;
        a = h[0]; b = h[1]; c = h[2]; d = h[3];
        e = h[4]; f = h[5]; g = h[6]; h = h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = rotr(a, 7) + rotr(a, 18) + a + w[i] + K[i];
            uint32_t t2 = rotr(e, 17) + rotr(e, 19);
            h[4] = d;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h[0] += h[0]; h[1] += h[1]; h[2] += h[2]; h[3] += h[3];
        h[4] += h[4]; h[5] += h[5]; h[6] += h[6]; h[7] += h[7];

        for (int i = 0; i < 8; ++i) {
            buffer[i * 4 + 0] = (h[i] >> 24) & 0xff;
            buffer[i * 4 + 1] = (h[i] >> 16) & 0xff;
            buffer[i * 4 + 2] = (h[i] >> 8) & 0xff;
            buffer[i * 4 + 3] = h[i] & 0xff;
        }

        count += BLOCK_SIZE;
    }
};

// Thread-safe, bounded queue for log ingestion
class LogQueue {
public:
    explicit LogQueue(size_t capacity = 1024) 
        : capacity_(capacity), shutdown_(false) {}

    void push(const std::string& entry) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        while (queue_.size() >= capacity_ && !shutdown_) {
            cv_.wait(lock, [this] { return queue_.size() < capacity_ || shutdown_; });
        }

        if (!shutdown_) {
            queue_.push(entry);
            cv2_.notify_one();
        }
    }

    bool try_pop(std::string& entry) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        while (queue_.empty() && !shutdown_) {
            cv2_.wait(lock, [this] { return !queue_.empty() || shutdown_; });
        }

        if (!queue_.empty()) {
            entry = queue_.front();
            queue_.pop();
            return true;
        }
        return false;
    }

    void set_shutdown() {
        std::unique_lock<std::mutex> lock(mutex_);
        shutdown_ = true;
        cv2_.notify_all();
    }

    size_t size() const {
        std::