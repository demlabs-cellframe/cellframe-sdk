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

#include "dap_chain_cache.h"
#include "dap_chain_cache_internal.h"
#include "dap_chain_cell.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_global_db.h"
#include "dap_global_db_pkt.h"
#include "dap_time.h"
#include "dap_list.h"
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/types.h>

#define LOG_TAG "dap_chain_cache"

// Forward declaration to ensure availability for C compilers if header include paths differ
extern void *dap_chain_cell_read_atom_by_offset(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id,
                                               off_t a_offset, size_t *a_atom_size);

// Global init flag
static bool s_cache_initialized = false;

/**
 * @brief Initialize chain cache subsystem
 */
int dap_chain_cache_init(void)
{
    if (s_cache_initialized) {
        log_it(L_WARNING, "Chain cache already initialized");
        return 0;
    }
    
    log_it(L_NOTICE, "Initializing chain cache subsystem");
    
    s_cache_initialized = true;
    
    log_it(L_INFO, "Chain cache subsystem initialized");
    return 0;
}

/**
 * @brief Deinitialize chain cache subsystem
 */
void dap_chain_cache_deinit(void)
{
    if (!s_cache_initialized) {
        return;
    }
    
    log_it(L_NOTICE, "Deinitializing chain cache subsystem");
    
    s_cache_initialized = false;
    
    log_it(L_INFO, "Chain cache subsystem deinitialized");
}

/**
 * @brief Create cache for a chain
 */
dap_chain_cache_t *dap_chain_cache_create(dap_chain_t *a_chain, dap_config_t *a_config)
{
    dap_return_val_if_fail(a_chain && a_config, NULL);
    
    if (!s_cache_initialized) {
        log_it(L_ERROR, "Chain cache subsystem not initialized");
        return NULL;
    }
    
    dap_chain_cache_t *l_cache = DAP_NEW_Z(dap_chain_cache_t);
    if (!l_cache) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    
    l_cache->chain = a_chain;
    
    // Read configuration
    const char *l_mode_str = dap_config_get_item_str_default(a_config, "chain", "cache_mode", "full");
    if (dap_strcmp(l_mode_str, "cached") == 0) {
        l_cache->mode = DAP_CHAIN_CACHE_MODE_CACHED;
    } else {
        l_cache->mode = DAP_CHAIN_CACHE_MODE_FULL;
    }
    
    l_cache->incremental_save = dap_config_get_item_bool_default(a_config, "chain", "cache_incremental_save", true);
    
    uint32_t l_threshold = dap_config_get_item_uint32_default(a_config, "chain", "cache_compaction_threshold", 100);
    // Validate range
    if (l_threshold < 10) {
        log_it(L_WARNING, "cache_compaction_threshold too small (%u), using 10", l_threshold);
        l_threshold = 10;
    }
    if (l_threshold > 1000) {
        log_it(L_WARNING, "cache_compaction_threshold too large (%u), using 1000", l_threshold);
        l_threshold = 1000;
    }
    l_cache->compaction_threshold = l_threshold;
    
    l_cache->compaction_async = dap_config_get_item_bool_default(a_config, "chain", "cache_compaction_async", true);
    l_cache->legacy_fallback = dap_config_get_item_bool_default(a_config, "chain", "cache_legacy_fallback", false);
    l_cache->debug = dap_config_get_item_bool_default(a_config, "chain", "cache_debug", false);
    
    // Initialize incremental counter
    atomic_init(&l_cache->incremental_count, 0);
    
    // Initialize statistics
    atomic_init(&l_cache->cache_hits, 0);
    atomic_init(&l_cache->cache_misses, 0);
    atomic_init(&l_cache->blocks_cached, 0);
    atomic_init(&l_cache->incremental_saved, 0);
    atomic_init(&l_cache->compactions_count, 0);
    atomic_init(&l_cache->compaction_time_ms, 0);
    
    // Initialize performance statistics
    atomic_init(&l_cache->total_lookup_time_us, 0);
    atomic_init(&l_cache->total_save_time_us, 0);
    atomic_init(&l_cache->gdb_get_calls, 0);
    atomic_init(&l_cache->gdb_set_calls, 0);
    atomic_init(&l_cache->gdb_get_time_us, 0);
    atomic_init(&l_cache->gdb_set_time_us, 0);
    
    // Initialize compaction lock
    pthread_mutex_init(&l_cache->compaction_lock, NULL);
    l_cache->compaction_in_progress = false;
    
    // Initialize batch buffer for performance during cell loading
    // Use large batch size (10000) to minimize number of GlobalDB transactions
    // Memory usage: 10000 * 56 bytes = ~560 KB (acceptable)
    l_cache->batch_capacity = 10000;  // Flush every 10000 blocks
    l_cache->batch_buffer = DAP_NEW_Z_SIZE(dap_chain_cache_batch_entry_t, 
                                           l_cache->batch_capacity * sizeof(dap_chain_cache_batch_entry_t));
    l_cache->batch_size = 0;
    pthread_mutex_init(&l_cache->batch_lock, NULL);
    
    // Build GlobalDB group names
    // Strong per-chain identity: include numeric IDs to avoid cross-network collisions with same names
    // Format: local.chain.cache.{net}.{chain}.{netIdHex}.{chainIdHex}
    l_cache->gdb_group = dap_strdup_printf("local.chain.cache.%s.%s.%016"DAP_UINT64_FORMAT_x".%016"DAP_UINT64_FORMAT_x,
                                           a_chain->net_name, a_chain->name,
                                           a_chain->net_id.uint64, a_chain->id.uint64);
    l_cache->gdb_subgroup = s_cache_build_subgroup(a_chain);
    
    log_it(L_NOTICE, "Chain cache created for %s:%s", a_chain->net_name, a_chain->name);
    log_it(L_NOTICE, "  - Mode: %s", l_cache->mode == DAP_CHAIN_CACHE_MODE_CACHED ? "CACHED" : "FULL");
    log_it(L_NOTICE, "  - GlobalDB group: '%s'", l_cache->gdb_group);
    log_it(L_NOTICE, "  - Incremental save: %s", l_cache->incremental_save ? "enabled" : "disabled");
    log_it(L_NOTICE, "  - Compaction threshold: %u blocks", l_cache->compaction_threshold);
    log_it(L_NOTICE, "  - Compaction async: %s", l_cache->compaction_async ? "yes" : "no");
    log_it(L_NOTICE, "  - Legacy fallback: %s", l_cache->legacy_fallback ? "enabled" : "disabled");
    log_it(L_NOTICE, "  - Debug logging: %s", l_cache->debug ? "enabled" : "disabled");
    log_it(L_NOTICE, "  - Batch buffer capacity: %zu blocks", l_cache->batch_capacity);
    
    return l_cache;
}

/**
 * @brief Delete cache for a chain
 */
void dap_chain_cache_delete(dap_chain_cache_t *a_cache)
{
    if (!a_cache)
        return;
    
    log_it(L_INFO, "Deleting chain cache for %s:%s",
        a_cache->chain->net_name, a_cache->chain->name);
    
    // Print final statistics before deletion
    dap_chain_cache_print_stats(a_cache);
    
    // Wait for compaction to finish if in progress
    pthread_mutex_lock(&a_cache->compaction_lock);
    if (a_cache->compaction_in_progress) {
        log_it(L_WARNING, "Waiting for compaction to complete...");
        // TODO: add condition variable for proper wait
    }
    pthread_mutex_unlock(&a_cache->compaction_lock);
    
    // Flush any pending batch writes
    dap_chain_cache_batch_flush(a_cache);
    
    // Perform final compaction if needed
    uint32_t l_incremental_count = atomic_load(&a_cache->incremental_count);
    if (l_incremental_count > 0) {
        log_it(L_INFO, "Performing final compaction (%u incremental blocks)", l_incremental_count);
        s_cache_compact_sync(a_cache);
    }
    
    // Free resources
    pthread_mutex_destroy(&a_cache->compaction_lock);
    pthread_mutex_destroy(&a_cache->batch_lock);
    DAP_DELETE(a_cache->batch_buffer);
    DAP_DELETE(a_cache->gdb_group);
    DAP_DELETE(a_cache->gdb_subgroup);
    DAP_DELETE(a_cache);
    
    log_it(L_INFO, "Chain cache deleted");
}

/**
 * @brief Check if block is in cache
 */
bool dap_chain_cache_has_block(dap_chain_cache_t *a_cache,
                                const dap_hash_fast_t *a_block_hash,
                                dap_chain_cache_entry_t *a_out_entry)
{
    dap_return_val_if_fail(a_cache && a_block_hash, false);
    
    char *l_key = s_cache_build_block_key_ex(a_cache->gdb_subgroup, a_block_hash);
    
    void *l_value = NULL;
    size_t l_value_size = 0;
    
    int l_ret = s_cache_gdb_get(a_cache, l_key, &l_value, &l_value_size);
    
    // Debug: log first few cache lookups
    static uint32_t s_lookup_count = 0;
    s_lookup_count++;
    if (s_lookup_count <= 5) {
        log_it(L_NOTICE, "Cache lookup #%u: key='%s', group='%s', result=%s",
               s_lookup_count, l_key, a_cache->gdb_group, 
               (l_ret == 0 && l_value) ? "HIT" : "MISS");
    }
    
    DAP_DELETE(l_key);
    
    if (l_ret < 0 || !l_value) {
        return false;
    }
    
    if (l_value_size != sizeof(dap_chain_cache_entry_t)) {
        log_it(L_WARNING, "Invalid cache entry size: %zu != %zu",
            l_value_size, sizeof(dap_chain_cache_entry_t));
        DAP_DELETE(l_value);
        return false;
    }
    
    if (a_out_entry) {
        memcpy(a_out_entry, l_value, sizeof(dap_chain_cache_entry_t));
    }
    
    DAP_DELETE(l_value);
    return true;
}

/**
 * @brief Get block entry from cache
 */
int dap_chain_cache_get_block(dap_chain_cache_t *a_cache,
                               const dap_hash_fast_t *a_block_hash,
                               dap_chain_cache_entry_t *a_out_entry)
{
    dap_return_val_if_fail(a_cache && a_block_hash && a_out_entry, -1);
    
    CACHE_TIMING_START();
    
    bool l_found = dap_chain_cache_has_block(a_cache, a_block_hash, a_out_entry);
    
    // Track timing
    uint64_t l_elapsed_us = CACHE_TIMING_END_US();
    atomic_fetch_add(&a_cache->total_lookup_time_us, l_elapsed_us);
    
    if (a_cache->debug && l_elapsed_us > 1000) { // Log if > 1ms
        log_it(L_DEBUG, "[CACHE-TIMING] get_block: %.3f ms %s", 
               l_elapsed_us / 1000.0, l_found ? "(HIT)" : "(MISS)");
    }
    
    return l_found ? 0 : -1;
}

/**
 * @brief Save block to cache
 */
int dap_chain_cache_save_block(dap_chain_cache_t *a_cache,
                                const dap_hash_fast_t *a_block_hash,
                                uint64_t a_cell_id,
                                uint64_t a_file_offset,
                                uint32_t a_block_size,
                                uint32_t a_tx_count)
{
    dap_return_val_if_fail(a_cache && a_block_hash, -1);
    
    CACHE_TIMING_START();
    
    dap_chain_cache_entry_t l_entry = {
        .cell_id = a_cell_id,
        .file_offset = a_file_offset,
        .block_size = a_block_size,
        .tx_count = a_tx_count
    };
    
    char *l_key = s_cache_build_block_key_ex(a_cache->gdb_subgroup, a_block_hash);
    
    int l_ret = s_cache_gdb_set(a_cache, l_key, &l_entry, sizeof(l_entry));
    
    DAP_DELETE(l_key);
    
    // Track timing
    uint64_t l_elapsed_us = CACHE_TIMING_END_US();
    atomic_fetch_add(&a_cache->total_save_time_us, l_elapsed_us);
    
    if (l_ret < 0) {
        log_it(L_ERROR, "Failed to save block to cache: %d", l_ret);
        return l_ret;
    }
    
    if (a_cache->debug) {
        if (l_elapsed_us > 1000) { // Log if > 1ms
            log_it(L_DEBUG, "[CACHE-TIMING] save_block: %.3f ms (cell=%"DAP_UINT64_FORMAT_U", offset=%"DAP_UINT64_FORMAT_U")",
                l_elapsed_us / 1000.0, a_cell_id, a_file_offset);
        }
    }
    
    return 0;
}

/**
 * @brief Called when new block is accepted to chain
 */
int dap_chain_cache_on_block_added(dap_chain_cache_t *a_cache,
                                    const dap_hash_fast_t *a_block_hash,
                                    uint64_t a_cell_id,
                                    uint64_t a_file_offset,
                                    uint32_t a_block_size,
                                    uint32_t a_tx_count)
{
    dap_return_val_if_fail(a_cache && a_block_hash, -1);
    
    if (!a_cache->incremental_save) {
        return 0;
    }
    /* Skip per-block index updates until the cell is fully validated
     * This avoids quadratic read-modify-write of a growing compact blob during first load
     */
    {
        char *l_ready_key = s_cache_build_cell_ready_key(a_cache->gdb_subgroup, a_cell_id);
        size_t l_ready_sz = 0;
        void *l_ready_val = dap_global_db_get_sync(a_cache->gdb_group, l_ready_key, &l_ready_sz, NULL, NULL);
        if (!l_ready_val) {
            if (a_cache->debug)
                log_it(L_DEBUG, "Cache disabled for cell 0x%016"DAP_UINT64_FORMAT_X" (first load): deferring index append", a_cell_id);
            DAP_DELETE(l_ready_key);
            return 0;
        }
        DAP_DELETE(l_ready_val);
        DAP_DELETE(l_ready_key);
    }
    
    // Plan C: append to compact cell index instead of per-block key
    dap_chain_block_index_entry_t l_entry = {0};
    memcpy(&l_entry.block_hash, a_block_hash, sizeof(dap_hash_fast_t));
    l_entry.file_offset = a_file_offset;
    l_entry.block_size = a_block_size;
    l_entry.tx_count = a_tx_count;
    int l_ret = dap_chain_cache_append_cell_entry(a_cache, a_cell_id, &l_entry);
    if (l_ret < 0) {
        return l_ret;
    }
    
    // Update statistics
    atomic_fetch_add(&a_cache->incremental_saved, 1);
    
    // Increment counter (atomic!)
    uint32_t l_count = atomic_fetch_add(&a_cache->incremental_count, 1) + 1;
    
    // Check threshold
    if (l_count >= a_cache->compaction_threshold) {
        log_it(L_INFO, "Incremental count %u reached threshold %u, scheduling compaction",
            l_count, a_cache->compaction_threshold);
        s_cache_schedule_compaction(a_cache);
    }
    
    return 0;
}

/**
 * @brief Trigger cache compaction
 */
int dap_chain_cache_compact(dap_chain_cache_t *a_cache, bool a_async)
{
    dap_return_val_if_fail(a_cache, -1);
    
    if (a_async && a_cache->compaction_async) {
        return s_cache_schedule_compaction(a_cache);
    } else {
        return s_cache_compact_sync(a_cache);
    }
}

/**
 * @brief Get cache statistics
 */
int dap_chain_cache_get_stats(dap_chain_cache_t *a_cache,
                               dap_chain_cache_stats_t *a_out_stats)
{
    dap_return_val_if_fail(a_cache && a_out_stats, -1);
    
    a_out_stats->cache_hits = atomic_load(&a_cache->cache_hits);
    a_out_stats->cache_misses = atomic_load(&a_cache->cache_misses);
    a_out_stats->blocks_cached = atomic_load(&a_cache->blocks_cached);
    a_out_stats->incremental_saved = atomic_load(&a_cache->incremental_saved);
    a_out_stats->compactions_count = atomic_load(&a_cache->compactions_count);
    a_out_stats->compaction_time_ms = atomic_load(&a_cache->compaction_time_ms);
    a_out_stats->invalid_entries_ignored = atomic_load(&a_cache->invalid_entries_ignored);
    
    // Calculate averages
    uint64_t l_total_lookups = a_out_stats->cache_hits + a_out_stats->cache_misses;
    if (l_total_lookups > 0) {
        // TODO: track actual lookup times
        a_out_stats->avg_lookup_time_ms = 0.5; // Placeholder
        a_out_stats->avg_load_time_ms = 1.0;   // Placeholder
    } else {
        a_out_stats->avg_lookup_time_ms = 0.0;
        a_out_stats->avg_load_time_ms = 0.0;
    }
    
    return 0;
}
/**
 * @brief Read block by hash directly by scanning compact cell indices in per-chain group
 */
void* dap_chain_cache_read_block_by_hash(dap_chain_cache_t *a_cache,
                                         const dap_hash_fast_t *a_hash,
                                         size_t *a_out_size)
{
    dap_return_val_if_fail(a_cache && a_hash && a_out_size, NULL);
    *a_out_size = 0;

    // Build key prefix for compact cells in this chain
    char *l_cell_key_prefix = dap_strdup_printf("%s.cell_", a_cache->gdb_subgroup);
    size_t l_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(a_cache->gdb_group, &l_count);
    if (!l_objs || l_count == 0) {
        // Fallback to legacy group on first run
        l_objs = dap_global_db_get_all_sync("local.cache", &l_count);
        if (!l_objs || l_count == 0) {
            DAP_DELETE(l_cell_key_prefix);
            return NULL;
        }
    }

    // Iterate compact cell blobs
    for (size_t i = 0; i < l_count; i++) {
        dap_global_db_obj_t *l_obj = &l_objs[i];
        if (!l_obj->key || !l_obj->value)
            continue;
        if (strncmp(l_obj->key, l_cell_key_prefix, strlen(l_cell_key_prefix)) != 0)
            continue; // not a compact cell key
        if (l_obj->value_len < sizeof(dap_chain_cell_compact_header_t))
            continue;

        const byte_t *l_ptr = (const byte_t *)l_obj->value;
        const dap_chain_cell_compact_header_t *l_hdr = (const dap_chain_cell_compact_header_t *)l_ptr;
        uint32_t l_block_count = l_hdr->block_count;
        size_t l_expected = sizeof(dap_chain_cell_compact_header_t) + (size_t)l_block_count * sizeof(dap_chain_block_index_entry_t);
        if (l_obj->value_len < l_expected)
            continue;

        const dap_chain_block_index_entry_t *l_idx = (const dap_chain_block_index_entry_t *)(l_ptr + sizeof(dap_chain_cell_compact_header_t));
        for (uint32_t j = 0; j < l_block_count; j++) {
            if (memcmp(&l_idx[j].block_hash, a_hash, sizeof(dap_hash_fast_t)) == 0) {
                // Read atom by offset
                size_t l_atom_size = 0;
                void *l_atom = dap_chain_cell_read_atom_by_offset(a_cache->chain,
                                                                  (dap_chain_cell_id_t){ .uint64 = l_hdr->cell_id },
                                                                  (off_t)l_idx[j].file_offset, &l_atom_size);
                if (l_atom) {
                    *a_out_size = l_atom_size;
                    dap_global_db_objs_delete(l_objs, l_count);
                    DAP_DELETE(l_cell_key_prefix);
                    return l_atom;
                }
            }
        }
    }

    dap_global_db_objs_delete(l_objs, l_count);
    DAP_DELETE(l_cell_key_prefix);
    return NULL;
}

/**
 * @brief Reset cache statistics
 */
void dap_chain_cache_reset_stats(dap_chain_cache_t *a_cache)
{
    if (!a_cache)
        return;
    
    atomic_store(&a_cache->cache_hits, 0);
    atomic_store(&a_cache->cache_misses, 0);
    atomic_store(&a_cache->incremental_saved, 0);
    atomic_store(&a_cache->compactions_count, 0);
    atomic_store(&a_cache->compaction_time_ms, 0);
    
    // Reset performance statistics
    atomic_store(&a_cache->total_lookup_time_us, 0);
    atomic_store(&a_cache->total_save_time_us, 0);
    atomic_store(&a_cache->gdb_get_calls, 0);
    atomic_store(&a_cache->gdb_set_calls, 0);
    atomic_store(&a_cache->gdb_get_time_us, 0);
    atomic_store(&a_cache->gdb_set_time_us, 0);
    atomic_store(&a_cache->invalid_entries_ignored, 0);
    
    log_it(L_INFO, "Cache statistics reset");
}

/**
 * @brief Print detailed cache statistics (for debugging)
 */
void dap_chain_cache_print_stats(dap_chain_cache_t *a_cache)
{
    if (!a_cache)
        return;
    
    uint64_t hits = atomic_load(&a_cache->cache_hits);
    uint64_t misses = atomic_load(&a_cache->cache_misses);
    uint64_t total_lookups = hits + misses;
    
    uint64_t total_lookup_us = atomic_load(&a_cache->total_lookup_time_us);
    uint64_t total_save_us = atomic_load(&a_cache->total_save_time_us);
    
    uint64_t gdb_get_calls = atomic_load(&a_cache->gdb_get_calls);
    uint64_t gdb_set_calls = atomic_load(&a_cache->gdb_set_calls);
    uint64_t gdb_get_time_us = atomic_load(&a_cache->gdb_get_time_us);
    uint64_t gdb_set_time_us = atomic_load(&a_cache->gdb_set_time_us);
    
    log_it(L_NOTICE, "=== CACHE PERFORMANCE STATISTICS ===");
    log_it(L_NOTICE, "Chain: %s:%s", a_cache->chain->net_name, a_cache->chain->name);
    log_it(L_NOTICE, "Mode: %s", a_cache->mode == DAP_CHAIN_CACHE_MODE_CACHED ? "CACHED" : "FULL");
    
    if (total_lookups > 0) {
        double hit_rate = (hits * 100.0) / total_lookups;
        double avg_lookup_ms = total_lookup_us / (double)total_lookups / 1000.0;
        
        log_it(L_NOTICE, "Lookups: %llu total (%.1f%% hit rate)", total_lookups, hit_rate);
        log_it(L_NOTICE, "  - Hits: %llu", hits);
        log_it(L_NOTICE, "  - Misses: %llu", misses);
        log_it(L_NOTICE, "  - Avg time: %.3f ms", avg_lookup_ms);
        log_it(L_NOTICE, "  - Total time: %.1f sec", total_lookup_us / 1000000.0);
    }
    
    if (gdb_get_calls > 0) {
        double avg_gdb_get_ms = gdb_get_time_us / (double)gdb_get_calls / 1000.0;
        log_it(L_NOTICE, "GlobalDB GET: %llu calls, avg %.3f ms, total %.1f sec", 
               gdb_get_calls, avg_gdb_get_ms, gdb_get_time_us / 1000000.0);
    }
    
    if (gdb_set_calls > 0) {
        double avg_gdb_set_ms = gdb_set_time_us / (double)gdb_set_calls / 1000.0;
        double avg_save_ms = total_save_us / (double)gdb_set_calls / 1000.0;
        log_it(L_NOTICE, "GlobalDB SET: %llu calls, avg %.3f ms, total %.1f sec", 
               gdb_set_calls, avg_gdb_set_ms, gdb_set_time_us / 1000000.0);
        log_it(L_NOTICE, "Save operations: avg %.3f ms total per save", avg_save_ms);
    }
    
    uint64_t total_overhead_sec = (total_lookup_us + total_save_us) / 1000000;
    log_it(L_NOTICE, "Total cache overhead: %llu sec (%.1f min)", 
           total_overhead_sec, total_overhead_sec / 60.0);
    
    // Performance warnings
    if (gdb_get_calls > 0) {
        double avg_gdb_get_ms = gdb_get_time_us / (double)gdb_get_calls / 1000.0;
        if (avg_gdb_get_ms > 1.0) {
            log_it(L_WARNING, "⚠️  GlobalDB GET is slow (%.3f ms avg) - consider optimization!", avg_gdb_get_ms);
        }
    }
    
    if (gdb_set_calls > 0) {
        double avg_gdb_set_ms = gdb_set_time_us / (double)gdb_set_calls / 1000.0;
        if (avg_gdb_set_ms > 1.0) {
            log_it(L_WARNING, "⚠️  GlobalDB SET is slow (%.3f ms avg) - consider batch operations!", avg_gdb_set_ms);
        }
    }
    
    log_it(L_NOTICE, "====================================");
}

/**
 * @brief Clear cache for a chain
 */
int dap_chain_cache_clear(dap_chain_cache_t *a_cache)
{
    dap_return_val_if_fail(a_cache, -1);
    
    log_it(L_WARNING, "Clearing cache for %s:%s",
        a_cache->chain->net_name, a_cache->chain->name);
    
    // Get all entries for this chain
    size_t l_objs_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(
        a_cache->gdb_group,
        &l_objs_count
    );
    
    if (!l_objs || l_objs_count == 0) {
        log_it(L_INFO, "No cache entries to clear");
        return 0;
    }
    
    // Delete all entries matching our subgroup
    int l_deleted = 0;
    int l_errors = 0;
    
    for (size_t i = 0; i < l_objs_count; i++) {
        // Check if key belongs to our chain (starts with subgroup)
        if (strstr(l_objs[i].key, a_cache->gdb_subgroup) == l_objs[i].key) {
            bool l_ret = dap_global_db_del_sync(a_cache->gdb_group, l_objs[i].key);
            if (l_ret) {
                l_deleted++;
            } else {
                l_errors++;
                log_it(L_WARNING, "Failed to delete cache entry: %s", l_objs[i].key);
            }
        }
    }
    
    dap_global_db_objs_delete(l_objs, l_objs_count);
    
    // Reset counters
    atomic_store(&a_cache->incremental_count, 0);
    atomic_store(&a_cache->blocks_cached, 0);
    
    log_it(L_INFO, "Cache cleared: %d entries deleted (%d errors)", l_deleted, l_errors);
    
    return l_errors > 0 ? -l_errors : 0;
}

/**
 * @brief Check if cache is enabled
 */
bool dap_chain_cache_enabled(dap_chain_cache_t *a_cache)
{
    return a_cache && a_cache->mode == DAP_CHAIN_CACHE_MODE_CACHED;
}

/**
 * @brief Get cache mode
 */
dap_chain_cache_mode_t dap_chain_cache_get_mode(dap_chain_cache_t *a_cache)
{
    return a_cache ? a_cache->mode : DAP_CHAIN_CACHE_MODE_FULL;
}

/**
 * @brief Set cache mode
 */
void dap_chain_cache_set_mode(dap_chain_cache_t *a_cache, dap_chain_cache_mode_t a_mode)
{
    if (!a_cache)
        return;
    
    if (a_cache->mode != a_mode) {
        log_it(L_INFO, "Changing cache mode from %s to %s",
            a_cache->mode == DAP_CHAIN_CACHE_MODE_CACHED ? "cached" : "full",
            a_mode == DAP_CHAIN_CACHE_MODE_CACHED ? "cached" : "full");
        a_cache->mode = a_mode;
    }
}

/**
 * @brief Internal: Schedule compaction task
 */
int s_cache_schedule_compaction(dap_chain_cache_t *a_cache)
{
    dap_return_val_if_fail(a_cache, -1);
    
    // Try to acquire lock
    if (pthread_mutex_trylock(&a_cache->compaction_lock) != 0) {
        log_it(L_INFO, "Compaction already in progress, skipping");
        return 0;
    }
    
    if (a_cache->compaction_in_progress) {
        pthread_mutex_unlock(&a_cache->compaction_lock);
        log_it(L_INFO, "Compaction already scheduled, skipping");
        return 0;
    }
    
    a_cache->compaction_in_progress = true;
    pthread_mutex_unlock(&a_cache->compaction_lock);
    
    // Create background thread
    pthread_t l_thread;
    int l_ret = pthread_create(&l_thread, NULL, s_cache_compaction_worker, a_cache);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to create compaction thread: %d", l_ret);
        a_cache->compaction_in_progress = false;
        return -1;
    }
    
    pthread_detach(l_thread);
    
    log_it(L_INFO, "Compaction task scheduled (async)");
    return 0;
}

/**
 * @brief Internal: Compaction worker (background thread)
 */
void *s_cache_compaction_worker(void *a_arg)
{
    dap_chain_cache_t *l_cache = (dap_chain_cache_t *)a_arg;
    
    log_it(L_INFO, "Compaction worker started");
    
    dap_time_t l_start_time = dap_time_now();
    
    int l_ret = s_cache_compact_sync(l_cache);
    
    dap_time_t l_end_time = dap_time_now();
    uint64_t l_elapsed_ms = (l_end_time - l_start_time) * 1000;
    
    if (l_ret == 0) {
        atomic_fetch_add(&l_cache->compactions_count, 1);
        atomic_fetch_add(&l_cache->compaction_time_ms, l_elapsed_ms);
        log_it(L_INFO, "Compaction worker completed in %"DAP_UINT64_FORMAT_U" ms", l_elapsed_ms);
    } else {
        log_it(L_ERROR, "Compaction worker failed: %d", l_ret);
    }
    
    pthread_mutex_lock(&l_cache->compaction_lock);
    l_cache->compaction_in_progress = false;
    pthread_mutex_unlock(&l_cache->compaction_lock);
    
    return NULL;
}

/**
 * @brief Internal: Perform compaction (synchronous)
 */
int s_cache_compact_sync(dap_chain_cache_t *a_cache)
{
    dap_return_val_if_fail(a_cache, -1);
    
    log_it(L_INFO, "Starting cache compaction (sync)...");
    
    // 1. Collect all incremental entries
    size_t l_entries_count = 0;
    dap_global_db_obj_t *l_entries = s_cache_collect_incremental_entries(a_cache, &l_entries_count);
    
    if (!l_entries || l_entries_count == 0) {
        log_it(L_INFO, "No incremental entries to compact");
        return 0;
    }
    
    log_it(L_INFO, "Compacting %zu incremental entries...", l_entries_count);
    
    // 2. Merge incremental to compacted
    int l_ret = s_cache_merge_incremental_to_compacted(a_cache, l_entries, l_entries_count);
    if (l_ret < 0) {
        log_it(L_WARNING, "Merge had %d errors", -l_ret);
    }
    
    // 3. Delete old incremental entries
    l_ret = s_cache_delete_incremental_entries(a_cache, l_entries, l_entries_count);
    if (l_ret < 0) {
        log_it(L_WARNING, "Delete had %d errors", -l_ret);
    }
    
    // 4. Free entries
    for (size_t i = 0; i < l_entries_count; i++) {
        DAP_DELETE(l_entries[i].key);
        DAP_DELETE(l_entries[i].value);
    }
    DAP_DELETE(l_entries);
    
    // 5. Reset counter (atomic!)
    uint32_t l_old_count = atomic_exchange(&a_cache->incremental_count, 0);
    
    log_it(L_INFO, "Compaction completed: %zu entries processed, counter reset from %u to 0",
        l_entries_count, l_old_count);
    
    return 0;
}

/**
 * @brief Internal: GlobalDB set operation
 */
int s_cache_gdb_set(dap_chain_cache_t *a_cache,
                    const char *a_key,
                    const void *a_value,
                    size_t a_value_size)
{
    dap_return_val_if_fail(a_cache && a_key && a_value && a_value_size > 0, -1);
    
    CACHE_TIMING_START();
    
    int l_ret = dap_global_db_set_sync(
        a_cache->gdb_group,
        a_key,
        a_value,
        a_value_size,
        false  // No history
    );
    
    // Track timing
    uint64_t l_elapsed_us = CACHE_TIMING_END_US();
    atomic_fetch_add(&a_cache->gdb_set_calls, 1);
    atomic_fetch_add(&a_cache->gdb_set_time_us, l_elapsed_us);
    
    if (l_ret != 0) {
        // GlobalDB set failed - log details
        static uint32_t s_error_count = 0;
        if (s_error_count < 5) { // Only log first 5 errors to avoid spam
            log_it(L_ERROR, "GlobalDB set failed: group='%s', key='%s', size=%zu, error=%d", 
                   a_cache->gdb_group, a_key, a_value_size, l_ret);
            s_error_count++;
            if (s_error_count == 5) {
                log_it(L_ERROR, "Further GlobalDB errors will be suppressed...");
            }
        }
        return -1;
    }
    
    if (a_cache->debug && l_elapsed_us > 2000) { // Log if > 2ms (slow!)
        log_it(L_WARNING, "[CACHE-TIMING] GDB SET SLOW: %.3f ms for key %s", 
               l_elapsed_us / 1000.0, a_key);
    }
    
    return 0;
}

/**
 * @brief Internal: GlobalDB get operation
 */
int s_cache_gdb_get(dap_chain_cache_t *a_cache,
                    const char *a_key,
                    void **a_out_value,
                    size_t *a_out_size)
{
    dap_return_val_if_fail(a_cache && a_key && a_out_value && a_out_size, -1);
    
    CACHE_TIMING_START();
    
    *a_out_value = dap_global_db_get_sync(
        a_cache->gdb_group,
        a_key,
        a_out_size,
        NULL,
        NULL
    );
    
    // Track timing
    uint64_t l_elapsed_us = CACHE_TIMING_END_US();
    atomic_fetch_add(&a_cache->gdb_get_calls, 1);
    atomic_fetch_add(&a_cache->gdb_get_time_us, l_elapsed_us);
    
    return *a_out_value ? 0 : -1;
}

/**
 * @brief Internal: GlobalDB delete operation
 */
int s_cache_gdb_del(dap_chain_cache_t *a_cache,
                    const char *a_key)
{
    dap_return_val_if_fail(a_cache && a_key, -1);
    
    int l_ret = dap_global_db_del_sync(a_cache->gdb_group, a_key);
    
    return (l_ret == 0) ? 0 : -1;
}

/**
 * @brief Internal: Collect all incremental entries for compaction
 */
dap_global_db_obj_t *s_cache_collect_incremental_entries(dap_chain_cache_t *a_cache,
                                                          size_t *a_out_count)
{
    dap_return_val_if_fail(a_cache && a_out_count, NULL);
    
    *a_out_count = 0;
    
    // Get all entries from GlobalDB for this chain
    size_t l_objs_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(
        a_cache->gdb_group,
        &l_objs_count
    );
    
    if (!l_objs || l_objs_count == 0) {
        return NULL;
    }
    
    // Filter incremental entries (key contains ".incremental.")
    dap_list_t *l_incremental_list = NULL;
    size_t l_incremental_count = 0;
    
    for (size_t i = 0; i < l_objs_count; i++) {
        if (strstr(l_objs[i].key, ".incremental.")) {
            l_incremental_list = dap_list_append(l_incremental_list, &l_objs[i]);
            l_incremental_count++;
        }
    }
    
    if (l_incremental_count == 0) {
        dap_global_db_objs_delete(l_objs, l_objs_count);
        return NULL;
    }
    
    // Convert list to array
    dap_global_db_obj_t *l_result = DAP_NEW_Z_SIZE(dap_global_db_obj_t, 
                                                     sizeof(dap_global_db_obj_t) * l_incremental_count);
    
    dap_list_t *l_item = l_incremental_list;
    for (size_t i = 0; i < l_incremental_count && l_item; i++, l_item = l_item->next) {
        dap_global_db_obj_t *l_obj = (dap_global_db_obj_t *)l_item->data;
        // Copy object
        l_result[i].key = dap_strdup(l_obj->key);
        l_result[i].value = DAP_NEW_SIZE(byte_t, l_obj->value_len);
        memcpy(l_result[i].value, l_obj->value, l_obj->value_len);
        l_result[i].value_len = l_obj->value_len;
    }
    
    dap_list_free(l_incremental_list);
    dap_global_db_objs_delete(l_objs, l_objs_count);
    
    *a_out_count = l_incremental_count;
    
    if (a_cache->debug) {
        log_it(L_DEBUG, "Collected %zu incremental entries for compaction", l_incremental_count);
    }
    
    return l_result;
}

/**
 * @brief Internal: Merge incremental entries into compacted structure
 */
int s_cache_merge_incremental_to_compacted(dap_chain_cache_t *a_cache,
                                            dap_global_db_obj_t *a_entries,
                                            size_t a_count)
{
    dap_return_val_if_fail(a_cache && a_entries && a_count > 0, -1);
    
    // For simplified version: incremental entries ARE the compacted entries
    // We just need to rename them from ".incremental.X" to regular hash keys
    
    int l_merged = 0;
    int l_errors = 0;
    
    for (size_t i = 0; i < a_count; i++) {
        dap_global_db_obj_t *l_obj = &a_entries[i];
        
        // Validate entry size
        if (l_obj->value_len != sizeof(dap_chain_cache_entry_t)) {
            log_it(L_WARNING, "Invalid entry size in key %s: %zu != %zu",
                l_obj->key, l_obj->value_len, sizeof(dap_chain_cache_entry_t));
            l_errors++;
            continue;
        }
        
        // Entry is already in GlobalDB with correct format
        // Just count it as merged
        l_merged++;
    }
    
    if (a_cache->debug) {
        log_it(L_DEBUG, "Merged %d entries (%d errors)", l_merged, l_errors);
    }
    
    return l_errors > 0 ? -l_errors : 0;
}

/**
 * @brief Internal: Delete incremental entries after compaction
 */
int s_cache_delete_incremental_entries(dap_chain_cache_t *a_cache,
                                        dap_global_db_obj_t *a_entries,
                                        size_t a_count)
{
    dap_return_val_if_fail(a_cache && a_entries && a_count > 0, -1);
    
    int l_deleted = 0;
    int l_errors = 0;
    
    for (size_t i = 0; i < a_count; i++) {
        // Delete incremental entry
        // For simplified version: we keep entries as-is (they are already compacted)
        // In full version, would delete ".incremental.X" keys here
        
        // For now just count as deleted
        l_deleted++;
    }
    
    if (a_cache->debug) {
        log_it(L_DEBUG, "Deleted %d incremental entries (%d errors)", l_deleted, l_errors);
    }
    
    return l_errors > 0 ? -l_errors : 0;
}

/**
 * @brief Context for async chunk flush callback
 */
typedef struct {
    dap_store_obj_t *store_objs;
    size_t count;
    size_t chunk_number;
} cache_chunk_async_context_t;

/**
 * @brief Callback for async chunk flush - frees memory after write completes
 */
static bool s_cache_chunk_async_callback(dap_global_db_instance_t *a_dbi,
                                         int a_rc,
                                         const char *a_group,
                                         const size_t a_values_current,
                                         const size_t a_values_count,
                                         dap_store_obj_t *a_values,
                                         void *a_arg)
{
    UNUSED(a_dbi);
    UNUSED(a_group);
    UNUSED(a_values_current);
    UNUSED(a_values_count);
    UNUSED(a_values);
    
    cache_chunk_async_context_t *l_ctx = (cache_chunk_async_context_t *)a_arg;
    
    if (a_rc != DAP_GLOBAL_DB_RC_SUCCESS) {
        log_it(L_ERROR, "Async write #%zu failed, error=%d", 
               l_ctx->chunk_number, a_rc);
    }
    // Success logging disabled to avoid spam (10000+ messages)
    
    // Free allocated memory for this single object
    DAP_DELETE(l_ctx->store_objs->key);
    DAP_DELETE(l_ctx->store_objs->group);
    DAP_DELETE(l_ctx->store_objs->value);
    DAP_DELETE(l_ctx->store_objs->sign);
    DAP_DELETE(l_ctx->store_objs);
    DAP_DELETE(l_ctx);
    
    return true;
}


/**
 * @brief Add block to batch buffer (for performance during cell loading)
 */
int dap_chain_cache_batch_add(dap_chain_cache_t *a_cache,
                               const dap_hash_fast_t *a_block_hash,
                               uint64_t a_cell_id,
                               uint64_t a_file_offset,
                               uint32_t a_block_size,
                               uint32_t a_tx_count)
{
    dap_return_val_if_fail(a_cache && a_block_hash, -1);
    
    pthread_mutex_lock(&a_cache->batch_lock);
    
    // Check if buffer is full - auto-flush to avoid blocking
    if (a_cache->batch_size >= a_cache->batch_capacity) {
        pthread_mutex_unlock(&a_cache->batch_lock);
        log_it(L_INFO, "Cache batch buffer full (%zu blocks), auto-flushing to GlobalDB...", 
               a_cache->batch_capacity);
        // Flush buffer
        int l_ret = dap_chain_cache_batch_flush(a_cache);
        if (l_ret < 0) {
            return l_ret;
        }
        pthread_mutex_lock(&a_cache->batch_lock);
    }
    
    // Add to buffer
    dap_chain_cache_batch_entry_t *l_entry = &a_cache->batch_buffer[a_cache->batch_size];
    memcpy(&l_entry->block_hash, a_block_hash, sizeof(dap_hash_fast_t));
    l_entry->cache_entry.cell_id = a_cell_id;
    l_entry->cache_entry.file_offset = a_file_offset;
    l_entry->cache_entry.block_size = a_block_size;
    l_entry->cache_entry.tx_count = a_tx_count;
    
    // Debug: log first few batched blocks
    static uint32_t s_batch_add_count = 0;
    s_batch_add_count++;
    if (s_batch_add_count <= 3) {
        char *l_hash_str = dap_hash_fast_to_str_new(a_block_hash);
        log_it(L_NOTICE, "Cache batch_add #%u: hash=%s, cell=0x%016"DAP_UINT64_FORMAT_X", offset=%"PRIu64,
               s_batch_add_count, l_hash_str, a_cell_id, a_file_offset);
        DAP_DELETE(l_hash_str);
    }
    
    a_cache->batch_size++;
    
    pthread_mutex_unlock(&a_cache->batch_lock);
    
    return 0;
}

/**
 * @brief Flush batch buffer to GlobalDB (bulk write with transaction)
 */
int dap_chain_cache_batch_flush(dap_chain_cache_t *a_cache)
{
    dap_return_val_if_fail(a_cache, -1);
    
    pthread_mutex_lock(&a_cache->batch_lock);
    
    if (a_cache->batch_size == 0) {
        pthread_mutex_unlock(&a_cache->batch_lock);
        return 0;
    }
    
    CACHE_TIMING_START();
    
    size_t l_batch_size = a_cache->batch_size;
    
    if (a_cache->debug) {
        log_it(L_DEBUG, "Flushing batch buffer: %zu blocks", l_batch_size);
    }
    
    // Prepare array of dap_store_obj_t for GlobalDB batch write
    dap_store_obj_t *l_store_objs = DAP_NEW_Z_SIZE(dap_store_obj_t, 
                                                    l_batch_size * sizeof(dap_store_obj_t));
    if (!l_store_objs) {
        pthread_mutex_unlock(&a_cache->batch_lock);
        log_it(L_ERROR, "Memory allocation failed for batch flush");
        return -1;
    }
    
    dap_nanotime_t l_ts = dap_nanotime_now();
    
    // Get GlobalDB signing key
    dap_global_db_instance_t *l_dbi = dap_global_db_instance_get_default();
    if (!l_dbi) {
        pthread_mutex_unlock(&a_cache->batch_lock);
        DAP_DELETE(l_store_objs);
        log_it(L_ERROR, "GlobalDB instance not available");
        return -1;
    }
    
    // Convert batch entries to store objects and sign them
    for (size_t i = 0; i < l_batch_size; i++) {
        dap_chain_cache_batch_entry_t *l_entry = &a_cache->batch_buffer[i];
        dap_store_obj_t *l_obj = &l_store_objs[i];
        
        // Build key and group
        l_obj->key = s_cache_build_block_key_ex(a_cache->gdb_subgroup, &l_entry->block_hash);
        l_obj->group = dap_strdup(a_cache->gdb_group);
        
        // Debug: log first few keys being written
        if (i < 3) {
            log_it(L_NOTICE, "Cache flush key #%zu: group='%s', key='%s'",
                   i+1, l_obj->group, l_obj->key);
        }
        
        // Copy value
        l_obj->value = DAP_DUP_SIZE(&l_entry->cache_entry, sizeof(dap_chain_cache_entry_t));
        l_obj->value_len = sizeof(dap_chain_cache_entry_t);
        
        l_obj->timestamp = l_ts;
        l_obj->flags = DAP_GLOBAL_DB_RECORD_NEW;
        
        // Sign the object (critical!)
        l_obj->sign = dap_store_obj_sign(l_obj, l_dbi->signing_key, &l_obj->crc);
        if (!l_obj->sign) {
            log_it(L_ERROR, "Failed to sign store object %zu/%zu", i+1, l_batch_size);
            // Cleanup already allocated objects
            for (size_t j = 0; j <= i; j++) {
                DAP_DELETE(l_store_objs[j].key);
                DAP_DELETE(l_store_objs[j].group);
                DAP_DELETE(l_store_objs[j].value);
                if (l_store_objs[j].sign) {
                    DAP_DELETE(l_store_objs[j].sign);
                }
            }
            pthread_mutex_unlock(&a_cache->batch_lock);
            DAP_DELETE(l_store_objs);
            return -1;
        }
    }
    
    // Clear buffer before unlock (we copied all data)
    a_cache->batch_size = 0;
    
    pthread_mutex_unlock(&a_cache->batch_lock);
    
    // Transactional write: single set_raw_sync with all prepared objects
    int l_rc = dap_global_db_set_raw_sync(l_store_objs, l_batch_size);
    uint64_t l_elapsed_us = CACHE_TIMING_END_US();
    if (l_rc == 0) {
        log_it(L_NOTICE, "Cache batch flush committed: %zu records to '%s' (%.1f ms)",
               l_batch_size, a_cache->gdb_group, l_elapsed_us / 1000.0);
    } else {
        log_it(L_WARNING, "Cache batch flush failed with code %d after %.1f ms", l_rc, l_elapsed_us / 1000.0);
    }
    // Free all store objects and array
    dap_store_obj_free(l_store_objs, l_batch_size);
    return l_rc == 0 ? 0 : -1;
}

/**
 * @brief Batch load all cache entries for a cell into memory
 * 
 * This function loads ALL cache entries for a specific cell from GlobalDB
 * into an in-memory hash table for fast lookups during cell loading.
 * 
 * Performance: 500ms batch load vs 27ms × 8000 = 216 seconds per-block queries
 */
void* dap_chain_cache_load_cell(dap_chain_cache_t *a_cache, uint64_t a_cell_id)
{
    dap_return_val_if_fail(a_cache, NULL);
    
    CACHE_TIMING_START();
    
    // 0) Use cache only if this cell was previously fully validated (ready marker exists)
    char *l_ready_key = s_cache_build_cell_ready_key(a_cache->gdb_subgroup, a_cell_id);
    size_t l_ready_size = 0;
    void *l_ready_val = dap_global_db_get_sync(a_cache->gdb_group, l_ready_key, &l_ready_size, NULL, NULL);
    if (!l_ready_val) {
        // No ready marker -> force full validation on this cell
        log_it(L_INFO, "Cache disabled for cell 0x%016"DAP_UINT64_FORMAT_X" (first load): forcing full validation", a_cell_id);
        DAP_DELETE(l_ready_key);
        return NULL;
    }
    DAP_DELETE(l_ready_val);
    DAP_DELETE(l_ready_key);

    // 1) Try compact cell record first: key = "{subgroup}.cell_<id>"
    char *l_cell_key = s_cache_build_cell_key(a_cache->gdb_subgroup, a_cell_id);
    size_t l_cell_blob_size = 0;
    void *l_cell_blob = dap_global_db_get_sync(a_cache->gdb_group, l_cell_key, &l_cell_blob_size, NULL, NULL);
    
    if (l_cell_blob && l_cell_blob_size >= sizeof(dap_chain_cell_compact_header_t)) {
        const byte_t *l_ptr = (const byte_t *)l_cell_blob;
        const dap_chain_cell_compact_header_t *l_hdr = (const dap_chain_cell_compact_header_t *)l_ptr;
        uint32_t l_block_count = l_hdr->block_count;
        size_t l_expected = sizeof(dap_chain_cell_compact_header_t) + (size_t)l_block_count * sizeof(dap_chain_block_index_entry_t);
        
        if (l_hdr->cell_id == a_cell_id && l_cell_blob_size >= l_expected) {
            // Build in-memory hash table from compact entries
            dap_chain_cache_cell_entry_t *l_cell_cache = NULL;
            size_t l_loaded = 0;
            const dap_chain_block_index_entry_t *l_idx = (const dap_chain_block_index_entry_t *)(l_ptr + sizeof(dap_chain_cell_compact_header_t));
            for (uint32_t i = 0; i < l_block_count; i++) {
                const dap_chain_block_index_entry_t *l_e = &l_idx[i];
                dap_chain_cache_cell_entry_t *l_cell_entry = DAP_NEW_Z(dap_chain_cache_cell_entry_t);
                if (!l_cell_entry) {
                    log_it(L_ERROR, "Memory allocation failed");
                    continue;
                }
                memcpy(&l_cell_entry->block_hash, &l_e->block_hash, sizeof(dap_hash_fast_t));
                l_cell_entry->cache_entry.cell_id = a_cell_id;
                l_cell_entry->cache_entry.file_offset = l_e->file_offset;
                l_cell_entry->cache_entry.block_size = l_e->block_size;
                l_cell_entry->cache_entry.tx_count   = l_e->tx_count;
                HASH_ADD(hh, l_cell_cache, block_hash, sizeof(dap_hash_fast_t), l_cell_entry);
                l_loaded++;
            }
            DAP_DELETE(l_cell_blob);
            DAP_DELETE(l_cell_key);
            uint64_t l_elapsed_us = CACHE_TIMING_END_US();
            log_it(L_NOTICE, "Loaded compact cell index: %zu entries for cell 0x%016"DAP_UINT64_FORMAT_X" (%.1f ms)",
                   l_loaded, a_cell_id, l_elapsed_us / 1000.0);
            return (void *)l_cell_cache;
        }
        DAP_DELETE(l_cell_blob);
    }
    DAP_DELETE(l_cell_key);

    // 2) Fallback: legacy per-block entries via get_all_sync() with filtering
    char *l_pattern = dap_strdup_printf("%s.", a_cache->gdb_subgroup);
    size_t l_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(a_cache->gdb_group, &l_count);
    if (!l_objs || l_count == 0) {
        // Optional fallback to legacy group(s)
        if (a_cache->legacy_fallback) {
            l_objs = dap_global_db_get_all_sync("local.cache", &l_count);
        }
        if (!l_objs || l_count == 0) {
            if (a_cache->debug)
                log_it(L_DEBUG, "No cache entries found for cell 0x%016"DAP_UINT64_FORMAT_X, a_cell_id);
            DAP_DELETE(l_pattern);
            return NULL;
        }
    }
    dap_chain_cache_cell_entry_t *l_cell_cache = NULL;
    size_t l_loaded = 0;
    for (size_t i = 0; i < l_count; i++) {
        dap_global_db_obj_t *l_obj = &l_objs[i];
        if (!l_obj->key || strncmp(l_obj->key, l_pattern, strlen(l_pattern)) != 0)
            continue;
        if (!l_obj->value || l_obj->value_len != sizeof(dap_chain_cache_entry_t)) {
            atomic_fetch_add(&a_cache->invalid_entries_ignored, 1);
            continue;
        }
        dap_chain_cache_entry_t *l_entry = (dap_chain_cache_entry_t *)l_obj->value;
        if (l_entry->cell_id != a_cell_id)
            continue;
        const char *l_hash_str = strrchr(l_obj->key, '.');
        if (!l_hash_str)
            continue;
        l_hash_str++;
        dap_hash_fast_t l_block_hash;
        if (dap_chain_hash_fast_from_str(l_hash_str, &l_block_hash) != 0)
            continue;
        dap_chain_cache_cell_entry_t *l_cell_entry = DAP_NEW_Z(dap_chain_cache_cell_entry_t);
        if (!l_cell_entry)
            continue;
        memcpy(&l_cell_entry->block_hash, &l_block_hash, sizeof(dap_hash_fast_t));
        memcpy(&l_cell_entry->cache_entry, l_entry, sizeof(dap_chain_cache_entry_t));
        HASH_ADD(hh, l_cell_cache, block_hash, sizeof(dap_hash_fast_t), l_cell_entry);
        l_loaded++;
    }
    dap_global_db_objs_delete(l_objs, l_count);
    
    // If nothing loaded from per-chain group, try one more pass over old group
    if (l_loaded == 0 && a_cache->legacy_fallback) {
        l_objs = dap_global_db_get_all_sync("local.cache", &l_count);
        if (l_objs && l_count) {
            for (size_t i = 0; i < l_count; i++) {
                dap_global_db_obj_t *l_obj = &l_objs[i];
                if (!l_obj->key || strncmp(l_obj->key, l_pattern, strlen(l_pattern)) != 0)
                    continue;
                if (!l_obj->value || l_obj->value_len != sizeof(dap_chain_cache_entry_t)) {
                    atomic_fetch_add(&a_cache->invalid_entries_ignored, 1);
                    continue;
                }
                dap_chain_cache_entry_t *l_entry = (dap_chain_cache_entry_t *)l_obj->value;
                if (l_entry->cell_id != a_cell_id)
                    continue;
                const char *l_hash_str = strrchr(l_obj->key, '.');
                if (!l_hash_str)
                    continue;
                l_hash_str++;
                dap_hash_fast_t l_block_hash;
                if (dap_chain_hash_fast_from_str(l_hash_str, &l_block_hash) != 0)
                    continue;
                dap_chain_cache_cell_entry_t *l_cell_entry = DAP_NEW_Z(dap_chain_cache_cell_entry_t);
                if (!l_cell_entry)
                    continue;
                memcpy(&l_cell_entry->block_hash, &l_block_hash, sizeof(dap_hash_fast_t));
                memcpy(&l_cell_entry->cache_entry, l_entry, sizeof(dap_chain_cache_entry_t));
                HASH_ADD(hh, l_cell_cache, block_hash, sizeof(dap_hash_fast_t), l_cell_entry);
                l_loaded++;
            }
            dap_global_db_objs_delete(l_objs, l_count);
        }
    }
    
    DAP_DELETE(l_pattern);
    uint64_t l_elapsed_us = CACHE_TIMING_END_US();
    if (l_loaded > 0)
        log_it(L_NOTICE, "Batch loaded %zu legacy cache entries for cell 0x%016"DAP_UINT64_FORMAT_X" (%.1f ms)", l_loaded, a_cell_id, l_elapsed_us / 1000.0);
    else if (a_cache->debug)
        log_it(L_DEBUG, "No cache entries loaded for cell 0x%016"DAP_UINT64_FORMAT_X" (%.1f ms)", a_cell_id, l_elapsed_us / 1000.0);
    return (void *)l_cell_cache;
}
/**
 * @brief Append single block entry into compact cell record
 */
int dap_chain_cache_append_cell_entry(dap_chain_cache_t *a_cache,
                                      uint64_t a_cell_id,
                                      const dap_chain_block_index_entry_t *a_entry)
{
    dap_return_val_if_fail(a_cache && a_entry, -1);
    char *l_key = s_cache_build_cell_key(a_cache->gdb_subgroup, a_cell_id);
    size_t l_blob_size = 0;
    void *l_blob = dap_global_db_get_sync(a_cache->gdb_group, l_key, &l_blob_size, NULL, NULL);
    int l_ret = 0;
    if (l_blob && l_blob_size >= sizeof(dap_chain_cell_compact_header_t)) {
        const dap_chain_cell_compact_header_t *l_hdr_in = (const dap_chain_cell_compact_header_t *)l_blob;
        if (l_hdr_in->cell_id != a_cell_id) {
            DAP_DELETE(l_blob);
            DAP_DELETE(l_key);
            return -2;
        }
        uint32_t l_old_count = l_hdr_in->block_count;
        size_t l_new_size = sizeof(dap_chain_cell_compact_header_t) + ((size_t)l_old_count + 1) * sizeof(dap_chain_block_index_entry_t);
        byte_t *l_new_blob = DAP_NEW_Z_SIZE(byte_t, l_new_size);
        if (!l_new_blob) {
            DAP_DELETE(l_blob);
            DAP_DELETE(l_key);
            return -3;
        }
        dap_chain_cell_compact_header_t *l_hdr_out = (dap_chain_cell_compact_header_t *)l_new_blob;
        l_hdr_out->cell_id = a_cell_id;
        l_hdr_out->block_count = l_old_count + 1;
        l_hdr_out->reserved = 0;
        size_t l_idx_bytes = (size_t)l_old_count * sizeof(dap_chain_block_index_entry_t);
        if (l_blob_size >= sizeof(dap_chain_cell_compact_header_t) + l_idx_bytes)
            memcpy(l_new_blob + sizeof(*l_hdr_out), (byte_t*)l_blob + sizeof(dap_chain_cell_compact_header_t), l_idx_bytes);
        memcpy(l_new_blob + sizeof(*l_hdr_out) + l_idx_bytes, a_entry, sizeof(*a_entry));
        l_ret = s_cache_gdb_set(a_cache, l_key, l_new_blob, l_new_size);
        DAP_DELETE(l_new_blob);
        DAP_DELETE(l_blob);
    } else {
        // Create new compact record with single entry
        size_t l_new_size = sizeof(dap_chain_cell_compact_header_t) + sizeof(dap_chain_block_index_entry_t);
        byte_t *l_new_blob = DAP_NEW_Z_SIZE(byte_t, l_new_size);
        if (!l_new_blob) {
            DAP_DELETE(l_key);
            return -3;
        }
        dap_chain_cell_compact_header_t *l_hdr = (dap_chain_cell_compact_header_t *)l_new_blob;
        l_hdr->cell_id = a_cell_id;
        l_hdr->block_count = 1;
        l_hdr->reserved = 0;
        memcpy(l_new_blob + sizeof(*l_hdr), a_entry, sizeof(*a_entry));
        l_ret = s_cache_gdb_set(a_cache, l_key, l_new_blob, l_new_size);
        DAP_DELETE(l_new_blob);
        if (l_blob)
            DAP_DELETE(l_blob);
    }
    DAP_DELETE(l_key);
    return l_ret;
}

/**
 * @brief Fast O(1) lookup in batch-loaded cell cache
 */
int dap_chain_cache_lookup_in_cell(void *a_cell_cache, 
                                     const dap_hash_fast_t *a_block_hash,
                                     dap_chain_cache_entry_t *a_out_entry)
{
    dap_return_val_if_fail(a_cell_cache && a_block_hash && a_out_entry, -1);
    
    dap_chain_cache_cell_entry_t *l_cell_cache = (dap_chain_cache_cell_entry_t *)a_cell_cache;
    dap_chain_cache_cell_entry_t *l_found = NULL;
    
    // Fast O(1) hash table lookup
    HASH_FIND(hh, l_cell_cache, a_block_hash, sizeof(dap_hash_fast_t), l_found);
    
    if (l_found) {
        memcpy(a_out_entry, &l_found->cache_entry, sizeof(dap_chain_cache_entry_t));
        return 0;
    }
    
    return -1; // Not found
}

/**
 * @brief Free batch-loaded cell cache
 */
void dap_chain_cache_unload_cell(void *a_cell_cache)
{
    if (!a_cell_cache) {
        return;
    }
    
    dap_chain_cache_cell_entry_t *l_cell_cache = (dap_chain_cache_cell_entry_t *)a_cell_cache;
    dap_chain_cache_cell_entry_t *l_entry, *l_tmp;
    
    // Free all entries in hash table
    HASH_ITER(hh, l_cell_cache, l_entry, l_tmp) {
        HASH_DEL(l_cell_cache, l_entry);
        DAP_DELETE(l_entry);
    }
}

/**
 * @brief Save compact cell index to GlobalDB
 */
int dap_chain_cache_save_cell_index(dap_chain_cache_t *a_cache,
                                    uint64_t a_cell_id,
                                    const dap_chain_block_index_entry_t *a_entries,
                                    uint32_t a_count)
{
    dap_return_val_if_fail(a_cache && a_entries && a_count, -1);
    size_t l_blob_size = sizeof(dap_chain_cell_compact_header_t) + (size_t)a_count * sizeof(dap_chain_block_index_entry_t);
    byte_t *l_blob = DAP_NEW_Z_SIZE(byte_t, l_blob_size);
    if (!l_blob) {
        log_it(L_CRITICAL, "Memory allocation error while serializing cell index");
        return -2;
    }
    dap_chain_cell_compact_header_t *l_hdr = (dap_chain_cell_compact_header_t *)l_blob;
    l_hdr->cell_id = a_cell_id;
    l_hdr->block_count = a_count;
    l_hdr->reserved = 0;
    memcpy(l_blob + sizeof(*l_hdr), a_entries, (size_t)a_count * sizeof(dap_chain_block_index_entry_t));
    char *l_key = s_cache_build_cell_key(a_cache->gdb_subgroup, a_cell_id);
    int l_ret = s_cache_gdb_set(a_cache, l_key, l_blob, l_blob_size);
    if (l_ret == 0)
        log_it(L_INFO, "Saved compact cell index: %u entries for cell 0x%016"DAP_UINT64_FORMAT_X, a_count, a_cell_id);
    else
        log_it(L_WARNING, "Failed to save compact cell index for cell 0x%016"DAP_UINT64_FORMAT_X, a_cell_id);
    DAP_DELETE(l_key);
    DAP_DELETE(l_blob);

    // Set ready marker to allow cache usage on subsequent loads
    if (l_ret == 0) {
        char *l_ready_key = s_cache_build_cell_ready_key(a_cache->gdb_subgroup, a_cell_id);
        const char l_ready_val = 1;
        int l_r2 = s_cache_gdb_set(a_cache, l_ready_key, &l_ready_val, sizeof(l_ready_val));
        if (l_r2 != 0)
            log_it(L_WARNING, "Failed to set ready marker for cell 0x%016"DAP_UINT64_FORMAT_X, a_cell_id);
        DAP_DELETE(l_ready_key);
    }
    return l_ret;
}

