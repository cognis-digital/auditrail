#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* SHA-256 constants and state */
#define SHA256_H0 0x6a09e667ULL
#define SHA256_H1 0xbb67ae85ULL
#define SHA256_H2 0x3c6ef372ULL
#define SHA256_H3 0xa54ff53aULL
#define SHA256_H4 0x510e527fULL
#define SHA256_H5 0x9b05688cULL
#define SHA256_H6 0x1f83d9abULL
#define SHA256_H7 0x5be0cd19ULL

typedef struct {
    uint64_t h[8];
} sha256_ctx;

static void sha256_init(sha256_ctx *ctx) {
    ctx->h[0] = SHA256_H0;
    ctx->h[1] = SHA256_H1;
    ctx->h[2] = SHA256_H2;
    ctx->h[3] = SHA256_H3;
    ctx->h[4] = SHA256_H4;
    ctx->h[5] = SHA256_H5;
    ctx->h[6] = SHA256_H6;
    ctx->h[7] = SHA256_H7;
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t *data) {
    /* Simplified transformation - full implementation omitted for brevity */
    /* In production, use OpenSSL or libcrypto */
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c2f15c, 0xe1b3e7c5,
        0xc76c5163, 0x949ae46f, 0xd5a4ff5d, 0x6b4cc0da,
        0xf61e2562, 0x10384e6c, 0xcfb11e3f, 0x71374491,
        0xb5c2f15c, 0xe1b3e7c5, 0xc76c5163, 0x949ae46f,
    };
    
    /* Placeholder transform - real impl uses full SHA-256 */
}

/* Simplified SHA-256 for demo - use OpenSSL in production */
static void sha256_simple(const uint8_t *data, size_t len, uint8_t *out) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c2f15c, 0xe1b3e7c5,
        0xc76c5163, 0x949ae46f, 0xd5a4ff5d, 0x6b4cc0da,
        0xf61e2562, 0x10384e6c, 0xcfb11e3f, 0x71374491,
        0xb5c2f15c, 0xe1b3e7c5, 0xc76c5163, 0x949ae46f,
    };

    uint8_t buffer[64];
    size_t i;
    
    /* Pad message */
    len *= 8;
    for (i = 0; i < len % 64 && i < 56; i++) {
        buffer[i] = data[i / 8];
    }
    while (len % 64) buffer[len++] = 0x80;
    while (len < 56) buffer[len++] = 0;
    
    /* Process blocks */
    for (; len >= 64; len -= 64) {
        uint32_t w[16];
        uint32_t a, b, c, d, e, f, g, h;
        
        for (i = 0; i < 16; i++) w[i] = buffer[i * 4] | 
                                      (buffer[i * 4 + 1] << 8) |
                                      (buffer[i * 4 + 2] << 16) |
                                      (buffer[i * 4 + 3] << 24);
        
        a = b = c = d = e = f = g = h = 0;
        for (i = 0; i < 64; i++) {
            uint32_t t, S, T1, T2;
            
            if (i < 16) {
                T1 = b + ((a >> 7) | (a << 25)) + w[i] + K[i];
                T2 = d ^ (e & f) ^ g;
            } else {
                uint32_t S0 = ((a >> 11) | (a << 45)), S1 = ((e >> 13) | (e << 49));
                T1 = b + S0 + ((a >> 7) | (a << 25)) + w[i] + K[i];
                T2 = d ^ (e & f) ^ g;
            }
            
            t = h + T1;
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = t ^ S1 ^ T2;
        }
        
        /* Add to state */
    }
    
    /* Output - simplified */
}

/* ============================================================================ */
/* AUDIT ENTRY STRUCTURE                                                       */
/* ============================================================================ */

#define MAX_ENTRY_SIZE 4096
#define INITIAL_CHAIN_CAPACITY 8

typedef struct {
    uint64_t timestamp;           /* Unix epoch nanoseconds */
    size_t data_len;             /* Length of audit payload */
    uint8_t data[MAX_ENTRY_SIZE];/* Actual payload (inline for small entries) */
    uint8_t prev_hash[32];       /* Previous entry's hash (for chaining) */
    uint8_t current_hash[32];    /* Hash of this entry + previous hash */
} audit_entry;

typedef struct {
    audit_entry *head;           /* Most recent entry */
    audit_entry *tail;           /* Oldest entry */
    uint64_t root_hash[32];      /* Hash of entire chain (for quick verify) */
    size_t capacity;             /* Current allocated entries */
} hash_chain;

/* ============================================================================ */
/* CHAIN MANAGEMENT                                                           */
/* ============================================================================ */

static void init_chain(hash_chain *chain, uint64_t initial_capacity) {
    chain->head = NULL;
    chain->tail = NULL;
    sha256_init(&chain->root_hash);
    chain->capacity = initial_capacity;
}

static audit_entry* new_entry(void) {
    audit_entry *e = malloc(sizeof(audit_entry));
    if (!e) return NULL;
    
    e->timestamp = time(NULL) * 1000000000ULL; /* nanoseconds */
    e->data_len = 0;
    sha256_init(&e->current_hash);
    memcpy(e->prev_hash, "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    
    return e;
}

static void free_entry(audit_entry *e) {
    if (e) {
        /* Inline data is freed with struct */
        memset(e, 0, sizeof(audit_entry));
        free(e);
    }
}

/* ============================================================================ */
/* HASH CHAINING                                                              */
/* ============================================================================ */

static void compute_entry_hash(audit_entry *entry) {
    uint8_t combined[64];
    size_t i;
    
    /* Combine previous hash + current data for this entry's hash */
    memcpy(combined, entry->prev_hash, 32);
    memcpy(combined + 32, entry->data, entry->data_len);
    
    sha256_simple(combined, 64, entry->current_hash);
}

static void append_entry(hash_chain *chain, const uint8_t *payload, 
                         size_t payload_len) {
    audit_entry *new_e = new_entry();
    if (!new_e) return;
    
    memcpy(new_e->data, payload, payload_len);
    new_e->data_len = payload_len;
    
    /* Compute hash */
    compute_entry_hash(new_e);
    
    /* Link into chain */
    if (chain->tail) {
        memcpy(new_e->prev_hash, chain->tail->current_hash, 32);
    } else {
        memset(new_e->prev_hash, 0, 32);
    }
    
    new_e->timestamp = time(NULL) * 1000000000ULL;
    
    /* Update chain pointers */
    if (chain->head == NULL) {
        chain->head = chain->tail = new_e;
    } else {
        chain->tail->next = new_e;
        chain->tail = new_e;
    }
}

/* ============================================================================ */
/* INTEGRITY VERIFICATION                                                     */
/* ============================================================================ */

static int verify_chain(hash_chain *chain) {
    audit_entry *e = chain->head;
    uint8_t expected[32];
    
    if (!e) return 1; /* Empty chain is valid */
    
    while (e) {
        uint8_t combined[64];
        
        memcpy(combined, e->prev_hash, 32);
        memcpy(combined + 32, e->data, e->data_len);
        
        sha256_simple(combined, 64, expected);
        
        if (memcmp(expected, e->current_hash, 32) != 0) {
            return 0; /* Hash mismatch */
        }
        
        e = e->next;
    }
    
    return 1;
}

static void compute_root_hash(hash_chain *chain) {
    audit_entry *e = chain->head;
    uint8_t combined[64];
    size_t i, len;
    
    if (!e) {
        sha256_init(&chain->root_hash);
        return;
    }
    
    /* Walk from head to tail */
    while (e) {
        memcpy(combined, e->prev_hash, 32);
        memcpy(combined + 32, e->data, e->data_len);
        
        sha256_simple(combined, 64, &combined[0]);
        
        /* XOR into root hash */
        for (i = 0; i < 32; i++) {
            chain->root_hash[i] ^= combined[i];
        }
        
        e = e->next;
    }
}

/* ============================================================================ */
/* UTILITY FUNCTIONS                                                          */
/* ============================================================================ */

static void print_entry(audit_entry *e, const char *label) {
    printf("%s: ts=%llu, len=%zu\n", label, 
           (unsigned long long)e->timestamp, e->data_len);
    
    if (e->data_len > 0 && e->data[0] != '\0') {
        printf("  data: %.*s\n", (int)e->data_len, e->data);
    }
}

static void print_chain(hash_chain *chain) {
    audit_entry *e = chain->head;
    int i = 0;
    
    printf("Chain head: ");
    if (e) {
        print_entry(e, "HEAD");
        while ((e = e->next)) {
            print_entry(e, ++i);
        }
    } else {
        printf("(empty)\n");
    }
}

static void hex_dump(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0 && i < len - 1) printf("\n");
    }
}

/* ============================================================================ */
/* DEMO / TEST CODE                                                           */
/* ============================================================================ */

static void run_demo(void) {
    hash_chain chain;
    const char *messages[] = {
        "User login: admin",
        "Query executed: SELECT * FROM users",
        "Config change: timeout=30s",
        "Backup completed successfully"
    };
    int i, ret;
    
    printf("=== Hash Chain Manager Demo ===\n\n");
    
    init_chain(&chain, INITIAL_CHAIN_CAPACITY);
    
    for (i = 0; i < 4; i++) {
        append_entry(&chain, messages[i], strlen(messages[i]));
        printf("Added entry %d: '%s'\n", i + 1, messages[i]);
    }
    
    printf("\n--- Chain Structure ---\n");
    print_chain(&chain);
    
    printf("\n--- Root Hash (for quick verify) ---\n");
    compute_root_hash(&chain);
    hex_dump(chain.root_hash, 32);
    printf("\n");
    
    printf("--- Verification Test ---\n");
    ret = verify_chain(&chain);
    printf("Chain valid: %s\n", ret ? "YES" : "NO");
    
    /* Tamper test */
    if (ret) {
        audit_entry *e = chain.head;
        e->data[0] ^= 0xFF; /* Flip a bit */
        
        printf("\n--- After Tampering ---\n");
        ret = verify_chain(&chain);
        printf("Chain valid: %s\n", ret ? "YES" : "NO");
    }
    
    /* Restore and re-verify */
    if (!ret) {
        audit_entry *e = chain.head;
        e->data[0] ^= 0xFF; /* Flip back */
        
        printf("\n--- After Restoration ---\n");
        ret = verify_chain(&chain);
        printf("Chain valid: %s\n", ret ? "YES" : "NO");
    }
    
    printf("\n=== Demo Complete ===\n");
}

/* ============================================================================ */
/* MAIN ENTRY POINT                                                           */
/* ============================================================================ */

int main(void) {
    run_demo();
    return 0;
}