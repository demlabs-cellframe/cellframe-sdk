/*
 * mmap-based persistent threshold storage for blocks chain.
 *
 * Two mmap'd files per chain:
 *   threshold_index.bin  — open-addressing hash table
 *   threshold_data.bin   — append-only block data
 *
 * Copyright (c) 2025
 * Licensed under GNU General Public License v3.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "dap_common.h"
#include "dap_file_utils.h"
#include "dap_mmap_file.h"
#include "dap_chain_cs_blocks_mmap.h"

#define LOG_TAG "blocks_mmap"

/* Index file constants */
#define THRESHOLD_MAGIC      0x5448524C54485348ULL  /* "THRLTSHH" */
#define THRESHOLD_VERSION    1
#define THRESHOLD_INITIAL_CAP (1 << 20)             /* 1M slots */
#define THRESHOLD_MAX_LOAD   70                     /* grow at 70% fill */

/* Slot states */
#define SLOT_EMPTY     0
#define SLOT_OCCUPIED  1
#define SLOT_DELETED   2

/* Index file header — 64 bytes, page-aligned */
typedef struct threshold_index_header {
    uint64_t magic;
    uint64_t version;
    uint64_t capacity;
    uint64_t count;
    uint64_t data_file_size;
    uint8_t  reserved[24];
} DAP_ALIGN_PACKED threshold_index_header_t;

/* Index slot — 48 bytes */
typedef struct threshold_index_slot {
    uint8_t  state;                   /* SLOT_EMPTY / OCCUPIED / DELETED */
    uint8_t  pad[3];
    uint32_t data_offset_lo;          /* Low 32 bits of offset into data file */
    uint32_t data_size;               /* Block data size */
    uint32_t data_offset_hi;          /* High 32 bits of offset */
    dap_chain_hash_fast_t hash;       /* Block hash (key) */
} DAP_ALIGN_PACKED threshold_index_slot_t;

#define SLOT_SIZE sizeof(threshold_index_slot_t)

DAP_STATIC_INLINE uint64_t s_slot_offset(uint64_t capacity, uint64_t idx)
{
    (void)capacity;
    return sizeof(threshold_index_header_t) + idx * SLOT_SIZE;
}

DAP_STATIC_INLINE uint64_t s_index_file_size(uint64_t capacity)
{
    return sizeof(threshold_index_header_t) + capacity * SLOT_SIZE;
}

DAP_STATIC_INLINE uint64_t s_data_offset(threshold_index_slot_t *slot)
{
    return ((uint64_t)slot->data_offset_hi << 32) | slot->data_offset_lo;
}

DAP_STATIC_INLINE void s_set_data_offset(threshold_index_slot_t *slot, uint64_t offset)
{
    slot->data_offset_lo = (uint32_t)(offset & 0xFFFFFFFF);
    slot->data_offset_hi = (uint32_t)(offset >> 32);
}

/* FNV-1a hash for probing */
DAP_STATIC_INLINE uint64_t s_hash_to_idx(const dap_chain_hash_fast_t *hash, uint64_t capacity)
{
    const uint8_t *data = hash->raw;
    uint64_t h = 0xcbf29ce484222325ULL;  /* FNV offset basis */
    for (size_t i = 0; i < sizeof(dap_chain_hash_fast_t); i++) {
        h ^= data[i];
        h *= 0x100000001b3ULL;  /* FNV prime */
    }
    return h % capacity;
}

/* Get slot at index */
DAP_STATIC_INLINE threshold_index_slot_t *s_slot_at(dap_mmap_file_t *index, uint64_t idx)
{
    return (threshold_index_slot_t *)(dap_mmap_file_ptr(index) + s_slot_offset(0, idx));
}

/* Read header */
DAP_STATIC_INLINE threshold_index_header_t *s_header(dap_mmap_file_t *index)
{
    return (threshold_index_header_t *)dap_mmap_file_ptr(index);
}

/* Forward declarations */
static int s_grow_index(threshold_mmap_ctx_t *ctx);

/* ---- Public API ---- */

threshold_mmap_ctx_t *threshold_mmap_init(const char *dir, const char *chain_name)
{
    if (!dir || !chain_name)
        return NULL;

    char index_path[1024], data_path[1024];
    snprintf(index_path, sizeof(index_path), "%s/threshold_index.bin", dir);
    snprintf(data_path, sizeof(data_path), "%s/threshold_data.bin", dir);

    /* Ensure directory exists */
    if (!dap_dir_test(dir))
        dap_mkdir_with_parents(dir);

    /* Open or create data file */
    dap_mmap_file_t *data = dap_mmap_file_open(data_path, true, false);
    if (!data) {
        log_it(L_ERROR, "Cannot open threshold data file for chain %s", chain_name);
        return NULL;
    }

    /* Open or create index file */
    bool index_is_new = !dap_file_test(index_path);
    dap_mmap_file_t *index = dap_mmap_file_open(index_path, true, false);
    if (!index) {
        log_it(L_ERROR, "Cannot open threshold index file for chain %s", chain_name);
        dap_mmap_file_close(data);
        return NULL;
    }

    threshold_mmap_ctx_t *ctx = DAP_NEW_Z(threshold_mmap_ctx_t);
    if (!ctx) {
        dap_mmap_file_close(index);
        dap_mmap_file_close(data);
        return NULL;
    }

    pthread_mutexattr_t l_attr;
    pthread_mutexattr_init(&l_attr);
    pthread_mutexattr_settype(&l_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&ctx->lock, &l_attr);
    pthread_mutexattr_destroy(&l_attr);
    ctx->index = index;
    ctx->data = data;

    if (index_is_new || dap_mmap_file_size(index) < sizeof(threshold_index_header_t)) {
        /* Initialize fresh index */
        uint64_t cap = THRESHOLD_INITIAL_CAP;
        uint64_t idx_file_size = s_index_file_size(cap);

        if (dap_mmap_file_resize(index, idx_file_size) < 0) {
            log_it(L_ERROR, "Cannot resize fresh index file for chain %s", chain_name);
            dap_mmap_file_close(index);
            dap_mmap_file_close(data);
            DAP_DELETE(ctx);
            return NULL;
        }

        /* Write header */
        threshold_index_header_t *hdr = s_header(index);
        memset(hdr, 0, sizeof(*hdr));
        hdr->magic = THRESHOLD_MAGIC;
        hdr->version = THRESHOLD_VERSION;
        hdr->capacity = cap;
        hdr->count = 0;
        hdr->data_file_size = 0;

        /* Zero all slots */
        memset(dap_mmap_file_ptr(index) + sizeof(threshold_index_header_t),
               0, cap * SLOT_SIZE);

        ctx->capacity = cap;
        ctx->count = 0;

        log_it(L_NOTICE, "Created fresh threshold for chain %s: capacity=%" DAP_UINT64_FORMAT_U,
               chain_name, cap);
    } else {
        /* Restore from existing index */
        threshold_index_header_t *hdr = s_header(index);
        if (hdr->magic != THRESHOLD_MAGIC || hdr->version != THRESHOLD_VERSION) {
            log_it(L_ERROR, "Threshold index file corrupted for chain %s "
                   "(magic=0x%" DAP_UINT64_FORMAT_X " version=%" DAP_UINT64_FORMAT_U ")",
                   chain_name, hdr->magic, hdr->version);
            dap_mmap_file_close(index);
            dap_mmap_file_close(data);
            DAP_DELETE(ctx);
            return NULL;
        }
        ctx->capacity = hdr->capacity;
        ctx->count = hdr->count;

        log_it(L_NOTICE, "Restored threshold for chain %s: count=%" DAP_UINT64_FORMAT_U
               " capacity=%" DAP_UINT64_FORMAT_U, chain_name, ctx->count, ctx->capacity);
    }

    return ctx;
}

void threshold_mmap_destroy(threshold_mmap_ctx_t *ctx)
{
    if (!ctx)
        return;

    /* Update header with final state before closing */
    if (ctx->index && dap_mmap_file_ptr(ctx->index)) {
        threshold_index_header_t *hdr = s_header(ctx->index);
        hdr->count = ctx->count;
        hdr->data_file_size = dap_mmap_file_size(ctx->data);
    }

    if (ctx->data)
        dap_mmap_file_close(ctx->data);
    if (ctx->index)
        dap_mmap_file_close(ctx->index);
    pthread_mutex_destroy(&ctx->lock);
    DAP_DELETE(ctx);
}

int threshold_mmap_add(threshold_mmap_ctx_t *ctx,
                       const dap_chain_hash_fast_t *hash,
                       const void *block_data, size_t block_size)
{
    if (!ctx || !hash || !block_data || block_size == 0)
        return -1;

    pthread_mutex_lock(&ctx->lock);

    /* Check if already present */
    size_t existing_size;
    if (threshold_mmap_find(ctx, hash, &existing_size)) {
        pthread_mutex_unlock(&ctx->lock);
        return 1;  /* Already in threshold */
    }

    /* Grow index if needed */
    if (ctx->count * 100 >= ctx->capacity * THRESHOLD_MAX_LOAD) {
        if (s_grow_index(ctx) < 0) {
            log_it(L_ERROR, "Cannot grow threshold index");
            pthread_mutex_unlock(&ctx->lock);
            return -1;
        }
    }

    /* Append block data to data file */
    ssize_t data_offset = dap_mmap_file_append(ctx->data, block_data, block_size);
    if (data_offset < 0) {
        log_it(L_ERROR, "Cannot append block data to threshold");
        pthread_mutex_unlock(&ctx->lock);
        return -1;
    }

    /* Insert into index — linear probing */
    uint64_t idx = s_hash_to_idx(hash, ctx->capacity);
    threshold_index_slot_t *slot = NULL;

    for (uint64_t i = 0; i < ctx->capacity; i++) {
        slot = s_slot_at(ctx->index, idx);
        if (slot->state == SLOT_EMPTY || slot->state == SLOT_DELETED)
            break;
        idx = (idx + 1) % ctx->capacity;
    }

    slot->state = SLOT_OCCUPIED;
    slot->hash = *hash;
    slot->data_size = (uint32_t)block_size;
    s_set_data_offset(slot, (uint64_t)data_offset);

    ctx->count++;

    /* Update header */
    threshold_index_header_t *hdr = s_header(ctx->index);
    hdr->count = ctx->count;
    hdr->data_file_size = dap_mmap_file_size(ctx->data);

    pthread_mutex_unlock(&ctx->lock);
    return 0;
}

const void *threshold_mmap_find(threshold_mmap_ctx_t *ctx,
                                const dap_chain_hash_fast_t *hash,
                                size_t *size_out)
{
    if (!ctx || !hash)
        return NULL;

    pthread_mutex_lock(&ctx->lock);

    uint64_t idx = s_hash_to_idx(hash, ctx->capacity);

    for (uint64_t i = 0; i < ctx->capacity; i++) {
        threshold_index_slot_t *slot = s_slot_at(ctx->index, idx);

        if (slot->state == SLOT_EMPTY)
            break;  /* Not found */

        if (slot->state == SLOT_OCCUPIED &&
                memcmp(&slot->hash, hash, sizeof(dap_chain_hash_fast_t)) == 0) {
            /* Found — return pointer into data mmap (zero-copy) */
            uint64_t off = s_data_offset(slot);
            uint64_t data_sz = dap_mmap_file_size(ctx->data);
            if (off + slot->data_size > data_sz) {
                log_it(L_ERROR, "Threshold index slot has data offset %" DAP_UINT64_FORMAT_U
                       " + size %u beyond data file %" DAP_UINT64_FORMAT_U ", corrupt entry",
                       off, slot->data_size, data_sz);
                pthread_mutex_unlock(&ctx->lock);
                return NULL;
            }
            if (size_out)
                *size_out = slot->data_size;
            const char *data_base = (const char *)dap_mmap_file_ptr(ctx->data);
            pthread_mutex_unlock(&ctx->lock);
            return data_base + off;
        }

        idx = (idx + 1) % ctx->capacity;
    }

    pthread_mutex_unlock(&ctx->lock);
    return NULL;  /* Not found */
}

int threshold_mmap_del(threshold_mmap_ctx_t *ctx,
                       const dap_chain_hash_fast_t *hash)
{
    if (!ctx || !hash)
        return -1;

    pthread_mutex_lock(&ctx->lock);

    uint64_t idx = s_hash_to_idx(hash, ctx->capacity);

    for (uint64_t i = 0; i < ctx->capacity; i++) {
        threshold_index_slot_t *slot = s_slot_at(ctx->index, idx);

        if (slot->state == SLOT_EMPTY)
            break;  /* Not found */

        if (slot->state == SLOT_OCCUPIED &&
                memcmp(&slot->hash, hash, sizeof(dap_chain_hash_fast_t)) == 0) {
            /* Mark as deleted */
            slot->state = SLOT_DELETED;
            ctx->count--;

            /* Update header */
            threshold_index_header_t *hdr = s_header(ctx->index);
            hdr->count = ctx->count;

            pthread_mutex_unlock(&ctx->lock);
            return 0;
        }

        idx = (idx + 1) % ctx->capacity;
    }

    pthread_mutex_unlock(&ctx->lock);
    return -1;  /* Not found */
}

uint64_t threshold_mmap_count(threshold_mmap_ctx_t *ctx)
{
    return ctx ? ctx->count : 0;
}

int64_t threshold_mmap_iter(threshold_mmap_ctx_t *ctx,
                            threshold_mmap_iter_cb cb, void *arg)
{
    if (!ctx || !cb)
        return -1;

    pthread_mutex_lock(&ctx->lock);

    const char *data_base = (const char *)dap_mmap_file_ptr(ctx->data);
    uint64_t data_sz = dap_mmap_file_size(ctx->data);
    int64_t iterated = 0;

    for (uint64_t i = 0; i < ctx->capacity; i++) {
        threshold_index_slot_t *slot = s_slot_at(ctx->index, i);

        if (slot->state != SLOT_OCCUPIED)
            continue;

        uint64_t off = s_data_offset(slot);
        if (off + slot->data_size > data_sz) {
            log_it(L_ERROR, "Threshold iterator: slot %" DAP_UINT64_FORMAT_U
                   " has data offset %" DAP_UINT64_FORMAT_U " + size %u beyond data file "
                   "%" DAP_UINT64_FORMAT_U ", skipping corrupt entry", i, off, slot->data_size, data_sz);
            continue;
        }

        const void *block_data = data_base + off;
        int ret = cb(&slot->hash, block_data, slot->data_size, arg);
        iterated++;

        if (ret != 0)
            break;
    }

    pthread_mutex_unlock(&ctx->lock);
    return iterated;
}

/* ---- Internal: Grow index ---- */

static int s_grow_index(threshold_mmap_ctx_t *ctx)
{
    uint64_t old_cap = ctx->capacity;
    uint64_t new_cap = old_cap * 2;
    uint64_t new_file_size = s_index_file_size(new_cap);

    log_it(L_NOTICE, "Growing threshold index: %" DAP_UINT64_FORMAT_U " -> %" DAP_UINT64_FORMAT_U
           " slots (%" DAP_UINT64_FORMAT_U " bytes)", old_cap, new_cap, new_file_size);

    /* Create a temporary new index file */
    char new_path[1024 + 4];  /* path[1024] + ".new" */
    snprintf(new_path, sizeof(new_path), "%s.new", ctx->index->path);

    dap_mmap_file_t *new_index = dap_mmap_file_open(new_path, true, false);
    if (!new_index) {
        log_it(L_ERROR, "Cannot create new index file for grow");
        return -1;
    }

    if (dap_mmap_file_resize(new_index, new_file_size) < 0) {
        log_it(L_ERROR, "Cannot resize new index file");
        dap_mmap_file_close(new_index);
        unlink(new_path);
        return -1;
    }

    /* Initialize new header and zero slots */
    threshold_index_header_t *new_hdr = (threshold_index_header_t *)dap_mmap_file_ptr(new_index);
    memset(new_hdr, 0, sizeof(*new_hdr));
    new_hdr->magic = THRESHOLD_MAGIC;
    new_hdr->version = THRESHOLD_VERSION;
    new_hdr->capacity = new_cap;
    new_hdr->count = 0;
    new_hdr->data_file_size = dap_mmap_file_size(ctx->data);
    memset(dap_mmap_file_ptr(new_index) + sizeof(threshold_index_header_t),
           0, new_cap * SLOT_SIZE);

    /* Rehash all occupied slots from old → new */
    const char *data_base = (const char *)dap_mmap_file_ptr(ctx->data);
    uint64_t rehashed = 0;

    for (uint64_t i = 0; i < old_cap; i++) {
        threshold_index_slot_t *old_slot = s_slot_at(ctx->index, i);
        if (old_slot->state != SLOT_OCCUPIED)
            continue;

        /* Find slot in new table */
        uint64_t idx = s_hash_to_idx(&old_slot->hash, new_cap);
        threshold_index_slot_t *new_slot = NULL;

        for (uint64_t j = 0; j < new_cap; j++) {
            new_slot = (threshold_index_slot_t *)(dap_mmap_file_ptr(new_index) +
                       s_slot_offset(new_cap, idx));
            if (new_slot->state == SLOT_EMPTY)
                break;
            idx = (idx + 1) % new_cap;
        }

        /* Copy slot */
        *new_slot = *old_slot;
        rehashed++;
    }

    new_hdr->count = rehashed;

    /* Sync new file, close old, rename */
    dap_mmap_file_sync(new_index);
    dap_mmap_file_close(ctx->index);
    unlink(ctx->index->path);  /* Remove old file */

    /* Rename new → old */
    if (rename(new_path, ctx->index->path) < 0) {
        log_it(L_ERROR, "Cannot rename new index file: %s", dap_strerror(errno));
        ctx->index = new_index;
        ctx->capacity = new_cap;
        ctx->count = rehashed;
        return -1;
    }

    /* Reopen with the original path */
    dap_mmap_file_close(new_index);
    ctx->index = dap_mmap_file_open(ctx->index->path, false, false);
    if (!ctx->index) {
        log_it(L_CRITICAL, "Cannot reopen index file after grow!");
        return -1;
    }

    ctx->capacity = new_cap;
    ctx->count = rehashed;

    log_it(L_NOTICE, "Threshold index grown successfully: %" DAP_UINT64_FORMAT_U
           " slots, %" DAP_UINT64_FORMAT_U " entries", new_cap, rehashed);

    return 0;
}
