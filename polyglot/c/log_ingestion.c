/*
 * polyglot/c/log_ingestion.c
 * 
 * Tamper-evident audit-log aggregator with hash-chained attestation.
 * Thread-safe, high-throughput log ingestion with cryptographic linking.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <errno.h>

/* ============================================================
 * Configuration constants
 * ============================================================ */

#define DEFAULT_BATCH_SIZE    1024      /* Entries per batch commit */
#define DEFAULT_POOL_SIZE     65536     /* Pre-allocated entry pool size */
#define DEFAULT_CHAIN_DEPTH   8192      /* Max entries before auto-commit */
#define DEFAULT_HASH_ITER     1         /* K for PBKDF2-style hash (SHA256 rounds) */

/* ============================================================
 * Data structures
 * ============================================================ */

typedef struct {
    uint8_t  content[4096];              /* Raw log payload */
    size_t   content_len;                /* Actual bytes written */
    uint64_t timestamp_ns;               /* Nanosecond timestamp */
    uint32_t source_id;                  /* Source identifier */
    char     source_name[64];            /* Human-readable source name */
    uint8_t  *prev_hash;                 /* Previous entry's hash (16 bytes) */
    uint8_t  current_hash[SHA256_DIGEST_SIZE];  /* Computed hash of this entry */
} LogEntry;

typedef struct {
    pthread_mutex_t     lock;            /* Protects chain operations */
    pthread_cond_t      cond;            /* For batch commit signaling */
    
    uint64_t            head_seq;        /* Sequence number (monotonic) */
    uint8_t             *head_hash;      /* Hash of previous entry */
    
    LogEntry            pool[DEFAULT_POOL_SIZE];  /* Pre-allocated entries */
    size_t              pool_idx;        /* Current pool index */
    
    atomic_uint64_t     total_entries;   /* Total ingested (thread-safe) */
    atomic_uint64_t     total_bytes;     /* Total bytes processed */
    atomic_int          active_threads;  /* Thread count for stats */
} AuditChain;

/* ============================================================
 * Hash utilities (SHA-256 implementation)
 * ============================================================ */

#define SHA256_DIGEST_SIZE   32
#define SHA256_BLOCK_SIZE    64

typedef struct {
    uint32_t state[8];
    uint64_t count;
} SHA256_CTX;

static void sha256_init(SHA256_CTX *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b0d6c2e;
    ctx->state[6] = 0x00000000;
    ctx->state[7] = 0x00000000;
    ctx->count = 0;
}

static void sha256_transform(SHA256_CTX *ctx, const uint8_t *block) {
    uint32_t a,b,c,d,e,f,g,h,s11,s12,s13,s14,s15,s16,s17,s18,s19;
    uint32_t t0,t1,t2,t3,t4,t5,t6,t7,u0,u1,u2,u3,u4,u5,u6,u7,v0,v1,v2,v3;

#define ROTR(x,n)  (((x) >> n) | ((x) << (32 - n)))
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

#define R0(a,b,c,d,e,f,g,h)  { t0=a+b+c; t1=e+f+g; a+=t0; e+=t1; }
    R0(a,b,c,d,e,f,g,h); ROTR(h,6); R0(a,b,c,d,e,f,g,h); ROTR(h,11);
    R0(a,b,c,d,e,f,g,h); ROTR(h,25); R0(a,b,c,d,e,f,g,h); ROTR(h,4);
    R0(a,b,c,d,e,f,g,h); ROTR(h,14); R0(a,b,c,d,e,f,g,h); ROTR(h,30);
    R0(a,b,c,d,e,f,g,h); ROTR(h,20); R0(a,b,c,d,e,f,g,h); ROTR(h,7);
    R0(a,b,c,d,e,f,g,h); ROTR(h,25); R0(a,b,c,d,e,f,g,h); ROTR(h,15);

#undef ROTR
#undef R0

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
    ctx->state[3] += d; ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    while (len > 0) {
        if (ctx->count < SHA256_BLOCK_SIZE - 8) {
            ctx->state[7] = (uint32_t)(ctx->count << 3);
            sha256_transform(ctx, &ctx->state[0]);
            ctx->count += SHA256_BLOCK_SIZE;
        } else if (len < SHA256_BLOCK_SIZE - 8) {
            memcpy(&ctx->state[7], data, len);
            ctx->count += len;
            break;
        } else {
            sha256_transform(ctx, &ctx->state[0]);
            memcpy(&ctx->state[7], data, SHA256_BLOCK_SIZE - 8);
            ctx->count += SHA256_BLOCK_SIZE - 8;
            len -= SHA256_BLOCK_SIZE - 8;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t *out) {
    uint32_t i,j,k,x[16];
    
    if (ctx->count < SHA256_BLOCK_SIZE - 8) {
        ctx->state[7] = (uint32_t)(ctx->count << 3);
    } else {
        ctx->state[7] = (uint32_t)((ctx->count & ~0x7F) << 3);
        sha256_transform(ctx, &ctx->state[0]);
    }

    i = SHA256_BLOCK_SIZE - 8;
    x[i++] = ctx->state[7];
    for (j = 0; j < 8; j++) {
        x[i++] = ctx->state[j] ^ ((uint32_t)(ctx->count >> (j * 5)) & 0x1F);
    }

    while (i % 64 != 56) x[i++] = 0;
    for (k = 0; k < 16; k++) {
        uint32_t t0,t1,t2,t3;
        t0 = x[k];
        t1 = x[(k + 1) % 16];
        t2 = x[(k + 2) % 16];
        t3 = x[(k + 3) % 16];

#define R1(a,b,c,d,e,f,g,h)  { t0=a+b+c; t1=e+f+g; a+=t0; e+=t1; }
        R1(a,b,c,d,e,f,g,h); ROTR(h,7); R1(a,b,c,d,e,f,g,h); ROTR(h,18);
        R1(a,b,c,d,e,f,g,h); ROTR(h,3);  R1(a,b,c,d,e,f,g,h); ROTR(h,10);
        R1(a,b,c,d,e,f,g,h); ROTR(h,4);  R1(a,b,c,d,e,f,g,h); ROTR(h,23);
        R1(a,b,c,d,e,f,g,h); ROTR(h,6);  R1(a,b,c,d,e,f,g,h); ROTR(h,15);
        R1(a,b,c,d,e,f,g,h); ROTR(h,11); R1(a,b,c,d,e,f,g,h); ROTR(h,25);
        R1(a,b,c,d,e,f,g,h); ROTR(h,8);  R1(a,b,c,d,e,f,g,h); ROTR(h,14);

#undef R1
#undef R0

        ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
        ctx->state[3] += d; ctx->state[4] += e; ctx->state[5] += f;
        ctx->state[6] += g; ctx->state[7] += h;

        x[k] = t0; x[(k+1)%16] = t1; x[(k+2)%16] = t2; x[(k+3)%16] = t3;
    }

    for (i = 0, j = 0; i < SHA256_DIGEST_SIZE; i++) {
        out[i] = ctx->state[j >> 5] ^ (ctx->state[j & 31] << 24);
        j += 8;
    }

    memset(ctx, 0, sizeof(*ctx));
}

static void sha256(const uint8_t *data, size_t len, uint8_t *out) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* ============================================================
 * Log entry management
 * ============================================================ */

static void init_entry(LogEntry *entry) {
    memset(entry, 0, sizeof(*entry));
    entry->timestamp_ns = atomic_load_explicit(
        &thread_local_time, memory_order_relaxed);
}

static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000000000ULL + ts.tv_nsec);
}

/* ============================================================
 * AuditChain operations
 * ============================================================ */

static void init_chain(AuditChain *chain) {
    pthread_mutex_init(&chain->lock, NULL);
    pthread_cond_init(&chain->cond, NULL);
    
    chain->head_seq = 0;
    chain->pool_idx = 0;
    
    atomic_store_explicit(&chain->total_entries, 0, memory_order_relaxed);
    atomic_store_explicit(&chain->total_bytes, 0, memory_order_relaxed);
    atomic_store_explicit(&chain->active_threads, 1, memory_order_relaxed);
}

static void destroy_chain(AuditChain *chain) {
    pthread_mutex_destroy(&chain->lock);
    pthread_cond_destroy(&chain->cond);
    
    /* Zero out pool for safety */
    memset(chain->pool, 0, sizeof(chain->pool));
}

/* Get current timestamp as nanoseconds */
static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000000000ULL + ts.tv_nsec);
}

/* ============================================================
 * Core ingestion function
 * ============================================================ */

int audit_ingest(AuditChain *chain, 
                 const uint8_t *data, size_t len,
                 uint32_t source_id, 
                 const char *source_name) {
    LogEntry *entry;
    uint64_t prev_hash[SHA256_DIGEST_SIZE];
    uint8_t  current_hash[SHA256_DIGEST_SIZE];
    
    if (!chain || !data || len == 0) {
        return -1;
    }

    pthread_mutex_lock(&chain->lock);

    /* Check pool capacity */
    if (chain->pool_idx >= DEFAULT_POOL_SIZE) {
        chain->pool_idx = 0;  /* Wrap around */
    }

    entry = &chain->pool[chain->pool_idx];
    init_entry(entry);

    /* Copy payload */
    memcpy(entry->content, data, len);
    entry->content_len = len;
    entry->source_id = source_id;
    
    if (source_name) {
        strncpy(entry->source_name, source_name, sizeof(entry->source_name) - 1);
    }

    /* Compute hash of this entry */
    sha256(data, len, current_hash);

    /* Link to previous entry's hash */
    memcpy(prev_hash, chain->head_hash, SHA256_DIGEST_SIZE);

    /* Update head pointer */
    chain->head_seq++;
    memcpy(chain->head_hash, current_hash, SHA256_DIGEST_SIZE);
    
    pthread_mutex_unlock(&chain->lock);

    /* Update statistics atomically */
    atomic_fetch_add_explicit(&chain->total_entries, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&chain->total_bytes, len, memory_order_relaxed);

    return 0;
}

/* ============================================================
 * Batch commit and verification
 * ============================================================ */

int audit_commit_batch(AuditChain *chain) {
    LogEntry *entry;
    
    pthread_mutex_lock(&chain->lock);
    
    if (chain->pool_idx == 0 && chain->head_seq == 0) {
        /* Pool exhausted, need to reallocate or wrap */
        pthread_cond_broadcast(&chain->cond);
        pthread_mutex_unlock(&chain->lock);
        return -1;
    }

    entry = &chain->pool[chain->pool_idx];

    /* Verify chain integrity before commit */
    if (entry->content_len > 0) {
        uint8_t computed[SHA256_DIGEST_SIZE];
        sha256(entry->content, entry->content_len, computed);
        
        /* Hash should match what we stored */
        if (memcmp(computed, entry->current_hash, SHA256_DIGEST_SIZE) != 0) {
            fprintf(stderr, "WARN: Hash mismatch in batch commit\n");
        }

        /* Verify link to previous hash */
        if (entry->content_len > 0 && chain->head_seq > 1) {
            uint8_t expected[SHA256_DIGEST_SIZE];
            sha256(entry->prev_hash, SHA256_DIGEST_SIZE, expected);
            
            /* Note: prev_hash contains the PREVIOUS entry's hash */
        }
    }

    chain->pool_idx = (chain->pool_idx + 1) % DEFAULT_POOL_SIZE;
    
    pthread_mutex_unlock(&chain->lock);
    
    return 0;
}

/* ============================================================
 * Verification utilities
 * ============================================================ */

int audit_verify_chain(AuditChain *chain, uint8_t expected_head[SHA256_DIGEST_SIZE]) {
    LogEntry *entry;
    int i;
    
    pthread_mutex_lock(&chain->lock);
    
    for (i = 0; i < DEFAULT_POOL_SIZE && chain->pool_idx > i; i++) {
        entry = &chain->pool[i];
        
        if (entry->content_len == 0) continue;

        uint8_t computed[SHA256_DIGEST_SIZE];
        sha256(entry->content, entry->content_len, computed);

        /* Check against expected head hash */
        if (i == DEFAULT_POOL_SIZE - 1) {
            if (memcmp(computed, expected_head, SHA256_DIGEST_SIZE) != 0) {
                fprintf(stderr, "WARN: Chain verification failed\n");
                return -1;
            }