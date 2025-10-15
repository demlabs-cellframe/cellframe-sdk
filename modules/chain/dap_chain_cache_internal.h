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
#include <pthread.h>
#include <stdatomic.h>

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
    
    // Incremental save state
    atomic_uint incremental_count;          // Incremental blocks saved (atomic for thread-safety)
    
    // Statistics
    atomic_ullong cache_hits;               // Blocks loaded from cache
    atomic_ullong cache_misses;             // Blocks fully validated
    atomic_ullong blocks_cached;            // Total blocks in cache
    atomic_ullong incremental_saved;        // Incremental saves count
    atomic_ullong compactions_count;        // Compaction runs
    atomic_ullong compaction_time_ms;       // Total compaction time
    
    // Compaction state
    pthread_mutex_t compaction_lock;        // Prevent concurrent compaction
    bool compaction_in_progress;            // Compaction running flag
    
    // GlobalDB group names
    char *gdb_group;                        // "chain.cache"
    char *gdb_subgroup;                     // "{net_name}.{chain_name}"
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

// Build block key from hash
static inline char *s_cache_build_block_key(const dap_hash_fast_t *a_hash)
{
    return dap_hash_fast_to_str_new(a_hash);
}

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

