/*
 * mmap-based persistent threshold storage for blocks chain.
 * Stores out-of-order blocks in mmap'd files that survive node restart.
 *
 * Each chain gets a pair of files in its storage directory:
 *   threshold_index.bin  — open-addressing hash table (mmap'd)
 *   threshold_data.bin   — append-only block data (mmap'd)
 *
 * Copyright (c) 2025
 * Licensed under GNU General Public License v3.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>
#include "dap_hash.h"

/**
 * @struct threshold_mmap_ctx
 * @brief Context for a per-chain mmap'd threshold queue.
 */
typedef struct threshold_mmap_ctx {
    struct dap_mmap_file *index;     /**< mmap'd index file */
    struct dap_mmap_file *data;      /**< mmap'd data file */
    uint64_t              capacity;  /**< Number of index slots */
    uint64_t              count;     /**< Number of occupied slots */
    bool       drain_in_progress;    /**< Reentrancy guard for drain */
    pthread_mutex_t       lock;      /**< Protects mmap operations from concurrent access */
} threshold_mmap_ctx_t;

/**
 * Initialize or restore a mmap'd threshold for a chain.
 * Opens existing files if present, creates fresh ones otherwise.
 * @param dir        Chain storage directory path
 * @param chain_name Chain name (e.g. "main")
 * @return Context or NULL on error
 */
threshold_mmap_ctx_t *threshold_mmap_init(const char *dir, const char *chain_name);

/**
 * Destroy context: msync, munmap, close fds.
 */
void threshold_mmap_destroy(threshold_mmap_ctx_t *ctx);

/**
 * Add a block to the threshold.
 * @return 0 on success, -1 on error, 1 if already present
 */
int threshold_mmap_add(threshold_mmap_ctx_t *ctx,
                       const dap_chain_hash_fast_t *hash,
                       const void *block_data, size_t block_size);

/**
 * Find a block by hash. Returns pointer into mmap'd data (zero-copy).
 * @param size_out Receives block size if found
 * @return Pointer to block data, or NULL if not found
 */
const void *threshold_mmap_find(threshold_mmap_ctx_t *ctx,
                                const dap_chain_hash_fast_t *hash,
                                size_t *size_out);

/**
 * Delete a block from the threshold.
 * @return 0 on success, -1 if not found
 */
int threshold_mmap_del(threshold_mmap_ctx_t *ctx,
                       const dap_chain_hash_fast_t *hash);

/**
 * Get number of blocks in the threshold.
 */
uint64_t threshold_mmap_count(threshold_mmap_ctx_t *ctx);

/**
 * Iterator callback type.
 * @param hash  Block hash
 * @param data  Pointer to block data (mmap'd, zero-copy)
 * @param size  Block data size
 * @param arg   User argument
 * @return 0 to continue, non-zero to stop iteration
 */
typedef int (*threshold_mmap_iter_cb)(const dap_chain_hash_fast_t *hash,
                                      const void *data, size_t size,
                                      void *arg);

/**
 * Iterate over all blocks in the threshold.
 * Calls cb() for each OCCUPIED slot.
 * @return Number of blocks iterated, or -1 on error
 */
int64_t threshold_mmap_iter(threshold_mmap_ctx_t *ctx,
                            threshold_mmap_iter_cb cb, void *arg);
