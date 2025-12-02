/*
 * Authors:
 * Olzhas Zharasbaev
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2025
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "dap_chain_cache.h"
#include "dap_global_db.h"
#include "dap_string.h"
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>

/**
 * @brief Performance timing macros
 */
#define CACHE_TIMING_START() \
    struct timeval _cache_t_start, _cache_t_end; \
    gettimeofday(&_cache_t_start, NULL)

#define CACHE_TIMING_END_US() \
    (gettimeofday(&_cache_t_end, NULL), \
     (_cache_t_end.tv_sec - _cache_t_start.tv_sec) * 1000000ULL + \
     (_cache_t_end.tv_usec - _cache_t_start.tv_usec))

#define CACHE_TIMING_LOG(cache, label) \
    do { \
        if ((cache)->debug) { \
            uint64_t _elapsed_us = CACHE_TIMING_END_US(); \
            log_it(L_DEBUG, "[CACHE-TIMING] %s: %.3f ms", label, _elapsed_us / 1000.0); \
        } \
    } while(0)

/**
 * @brief Compact cell index structures
 * Must be defined BEFORE dap_chain_cache_sequential_t
 */
typedef struct DAP_ALIGN_PACKED dap_chain_block_index_entry {
    dap_hash_fast_t block_hash;    // 32 bytes
    uint64_t        file_offset;   // 8 bytes
    uint32_t        block_size;    // 4 bytes
    uint32_t        tx_count;      // 4 bytes
} dap_chain_block_index_entry_t;

typedef struct DAP_ALIGN_PACKED dap_chain_cell_compact_header {
    uint64_t cell_id;              // 8 bytes
    uint32_t block_count;          // 4 bytes
    uint32_t reserved;             // 4 bytes (alignment)
} dap_chain_cell_compact_header_t;

/**
 * @brief Batch entry for bulk cache writes
 */
typedef struct dap_chain_cache_batch_entry {
    dap_hash_fast_t block_hash;
    dap_chain_cache_entry_t cache_entry;
} dap_chain_cache_batch_entry_t;

/**
 * @brief Sequential cell cache for fast loading (no hash table!)
 * 
 * Optimized for sequential file reading:
 * - No hash table overhead
 * - No hash_fast() computation on cache hit
 * - Simple array with current index pointer
 * - O(1) check per block (just compare offset)
 * 
 * Trust model: If ready marker exists, we trust the cache completely.
 * No hash verification on repeated loads - maximum speed.
 */
typedef struct dap_chain_cache_sequential {
    dap_chain_block_index_entry_t *entries; // Sorted array from GlobalDB
    uint32_t count;                          // Total entries
    uint32_t current_idx;                    // Current position for sequential access
    uint64_t cell_id;                        // Cell ID for validation
} dap_chain_cache_sequential_t;

/**
 * @brief Legacy: In-memory cell cache for batch loading (DEPRECATED)
 * Hash table for fast O(1) lookups during cell file loading
 * Kept for backward compatibility, will be removed
 */
typedef struct dap_chain_cache_cell_entry {
    dap_hash_fast_t block_hash;           // Key
    dap_chain_cache_entry_t cache_entry;  // Value
    UT_hash_handle hh;                     // UTHash handle
} dap_chain_cache_cell_entry_t;

/**
 * @brief Internal cache structure
 */
struct dap_chain_cache {
    dap_chain_t *chain;                     // Chain handle
    
    // Configuration
    dap_chain_cache_mode_t mode;            // Cache mode (full/cached)
    bool incremental_save;                  // Save each block immediately
    uint32_t compaction_threshold;          // Compaction trigger (block count)
    bool compaction_async;                  // Run compaction in background
    bool debug;                             // Debug logging
    bool legacy_fallback;                   // Allow fallback to legacy groups (local.cache, old per-chain)
    
    // Incremental save state
    atomic_uint incremental_count;          // Incremental blocks saved (atomic for thread-safety)
    
    // Statistics (basic)
    atomic_ullong cache_hits;               // Blocks loaded from cache
    atomic_ullong cache_misses;             // Blocks fully validated
    atomic_ullong blocks_cached;            // Total blocks in cache
    atomic_ullong incremental_saved;        // Incremental saves count
    atomic_ullong compactions_count;        // Compaction runs
    atomic_ullong compaction_time_ms;       // Total compaction time
    
    // Performance statistics (microseconds for precision)
    atomic_ullong total_lookup_time_us;     // Total time spent in lookups
    atomic_ullong total_save_time_us;       // Total time spent in saves
    atomic_ullong gdb_get_calls;            // Number of GlobalDB get calls
    atomic_ullong gdb_set_calls;            // Number of GlobalDB set calls
    atomic_ullong gdb_get_time_us;          // Time spent in GlobalDB get
    atomic_ullong gdb_set_time_us;          // Time spent in GlobalDB set
    
    // Compaction state
    pthread_mutex_t compaction_lock;        // Prevent concurrent compaction
    bool compaction_in_progress;            // Compaction running flag
    
    // Batch write buffer (for performance during cell loading)
    dap_chain_cache_batch_entry_t *batch_buffer;  // Buffer for batched writes
    size_t batch_size;                      // Current number of entries in buffer
    size_t batch_capacity;                  // Buffer capacity
    pthread_mutex_t batch_lock;             // Protect batch buffer
    
    // GlobalDB group names
    char *gdb_group;                        // "chain.cache"
    char *gdb_subgroup;                     // "{net_name}.{chain_name}"
    
    // Validation/cleanup metrics
    atomic_ullong invalid_entries_ignored;  // Legacy entries skipped due to invalid size/corruption
};

/**
 * @brief GlobalDB key format helpers
 */

// Get GlobalDB group name for cache
#define DAP_CHAIN_CACHE_GDB_GROUP "chain.cache"

// Build subgroup name: "{net_name}.{chain_name}"
static inline char *s_cache_build_subgroup(dap_chain_t *a_chain)
{
    return dap_strdup_printf("%s.%s", a_chain->net_name, a_chain->name);
}

// Build incremental key: "{subgroup}.incremental.{block_number}"
static inline char *s_cache_build_incremental_key(const char *a_subgroup, uint64_t a_block_number)
{
    return dap_strdup_printf("%s.incremental.%"DAP_UINT64_FORMAT_U, a_subgroup, a_block_number);
}

// Build compacted key: "{subgroup}.{cell_id}"
static inline char *s_cache_build_compacted_key(const char *a_subgroup, uint64_t a_cell_id)
{
    return dap_strdup_printf("%s.%016"DAP_UINT64_FORMAT_x, a_subgroup, a_cell_id);
}

// Build block key from hash with network and chain prefix
// Format: "{net}.{chain}.{hash}" to separate different chains in same group
static inline char *s_cache_build_block_key_ex(const char *a_subgroup, const dap_hash_fast_t *a_hash)
{
    char *l_hash_str = dap_hash_fast_to_str_new(a_hash);
    char *l_key = dap_strdup_printf("%s.%s", a_subgroup, l_hash_str);
    DAP_DELETE(l_hash_str);
    return l_key;
}

// Legacy wrapper (for now)
static inline char *s_cache_build_block_key(const dap_hash_fast_t *a_hash)
{
    return dap_hash_fast_to_str_new(a_hash);
}

// Build cell key: "{subgroup}.cell_<id>"
static inline char *s_cache_build_cell_key(const char *a_subgroup, uint64_t a_cell_id)
{
    return dap_strdup_printf("%s.cell_%016"DAP_UINT64_FORMAT_x, a_subgroup, a_cell_id);
}

// Build "cell ready" marker key: "{subgroup}.cell_<id>.ready"
static inline char *s_cache_build_cell_ready_key(const char *a_subgroup, uint64_t a_cell_id)
{
    return dap_strdup_printf("%s.cell_%016"DAP_UINT64_FORMAT_x".ready", a_subgroup, a_cell_id);
}

// Save compact cell index into GlobalDB
int dap_chain_cache_save_cell_index(struct dap_chain_cache *a_cache,
                                    uint64_t a_cell_id,
                                    const dap_chain_block_index_entry_t *a_entries,
                                    uint32_t a_count);

/**
 * @brief Load cell cache as sequential array (no hash table)
 * 
 * Returns a simple array structure for O(1) sequential access.
 * No UTHash overhead, no memory fragmentation.
 * 
 * @param a_cache Cache handle
 * @param a_cell_id Cell ID to load
 * @return Sequential cache structure or NULL if not available
 */
dap_chain_cache_sequential_t *dap_chain_cache_load_cell_sequential(
    struct dap_chain_cache *a_cache, 
    uint64_t a_cell_id);

/**
 * @brief Check if current file position matches cache entry
 * 
 * Ultra-fast O(1) check without hash computation.
 * Trusts cache completely if ready marker was set.
 * On hit, returns the cached block hash (needed for callback_atom_add).
 * 
 * @param a_seq Sequential cache structure
 * @param a_file_offset Current file offset
 * @param a_block_size Block size at this offset
 * @param a_out_hash OUT: Block hash from cache (only set on hit, can be NULL)
 * @return true if cache hit (skip validation), false if cache miss
 */
bool dap_chain_cache_sequential_check(
    dap_chain_cache_sequential_t *a_seq,
    uint64_t a_file_offset,
    uint32_t a_block_size,
    dap_hash_fast_t *a_out_hash);

/**
 * @brief Free sequential cache structure
 * 
 * @param a_seq Sequential cache to free
 */
void dap_chain_cache_sequential_free(dap_chain_cache_sequential_t *a_seq);

// Append single block index entry into compact cell record (read-modify-write)
int dap_chain_cache_append_cell_entry(struct dap_chain_cache *a_cache,
                                      uint64_t a_cell_id,
                                      const dap_chain_block_index_entry_t *a_entry);

/**
 * @brief Internal functions
 */

// Compaction worker (runs in background thread)
void *s_cache_compaction_worker(void *a_arg);

// Schedule compaction task
int s_cache_schedule_compaction(dap_chain_cache_t *a_cache);

// Perform compaction (synchronous)
int s_cache_compact_sync(dap_chain_cache_t *a_cache);

// GlobalDB operations
int s_cache_gdb_set(dap_chain_cache_t *a_cache,
                    const char *a_key,
                    const void *a_value,
                    size_t a_value_size);

int s_cache_gdb_get(dap_chain_cache_t *a_cache,
                    const char *a_key,
                    void **a_out_value,
                    size_t *a_out_size);

int s_cache_gdb_del(dap_chain_cache_t *a_cache,
                    const char *a_key);

// Batch operations for performance during cell loading
int dap_chain_cache_batch_add(dap_chain_cache_t *a_cache,
                               const dap_hash_fast_t *a_block_hash,
                               uint64_t a_cell_id,
                               uint64_t a_file_offset,
                               uint32_t a_block_size,
                               uint32_t a_tx_count);

int dap_chain_cache_batch_flush(dap_chain_cache_t *a_cache);

// Collect all incremental entries for compaction
dap_global_db_obj_t *s_cache_collect_incremental_entries(dap_chain_cache_t *a_cache,
                                                          size_t *a_out_count);

// Merge incremental entries into compacted structure
int s_cache_merge_incremental_to_compacted(dap_chain_cache_t *a_cache,
                                            dap_global_db_obj_t *a_entries,
                                            size_t a_count);

// Delete incremental entries after compaction
int s_cache_delete_incremental_entries(dap_chain_cache_t *a_cache,
                                        dap_global_db_obj_t *a_entries,
                                        size_t a_count);

