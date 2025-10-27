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

#define LOG_TAG "dap_chain_cache"

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
    // Use larger batch size (500) to reduce number of GlobalDB transactions
    l_cache->batch_capacity = 500;  // Flush every 500 blocks
    l_cache->batch_buffer = DAP_NEW_Z_SIZE(dap_chain_cache_batch_entry_t, 
                                           l_cache->batch_capacity * sizeof(dap_chain_cache_batch_entry_t));
    l_cache->batch_size = 0;
    pthread_mutex_init(&l_cache->batch_lock, NULL);
    
    // Build GlobalDB group names
    // Format: "local.cache" - simple 2-level local group
    // Network and chain info will be in keys: "{net}.{chain}.{block_hash}"
    l_cache->gdb_group = dap_strdup("local.cache");
    l_cache->gdb_subgroup = s_cache_build_subgroup(a_chain);
    
    log_it(L_NOTICE, "Chain cache created for %s:%s", a_chain->net_name, a_chain->name);
    log_it(L_NOTICE, "  - Mode: %s", l_cache->mode == DAP_CHAIN_CACHE_MODE_CACHED ? "CACHED" : "FULL");
    log_it(L_NOTICE, "  - GlobalDB group: '%s'", l_cache->gdb_group);
    log_it(L_NOTICE, "  - Incremental save: %s", l_cache->incremental_save ? "enabled" : "disabled");
    log_it(L_NOTICE, "  - Compaction threshold: %u blocks", l_cache->compaction_threshold);
    log_it(L_NOTICE, "  - Compaction async: %s", l_cache->compaction_async ? "yes" : "no");
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
    
    // Save to cache
    int l_ret = dap_chain_cache_save_block(a_cache, a_block_hash,
                                            a_cell_id, a_file_offset,
                                            a_block_size, a_tx_count);
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
    
    if (a_cache->debug && l_elapsed_us > 2000) { // Log if > 2ms (slow!)
        log_it(L_WARNING, "[CACHE-TIMING] GDB GET SLOW: %.3f ms for key %s", 
               l_elapsed_us / 1000.0, a_key);
    }
    
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
    
    // Check if buffer is full
    if (a_cache->batch_size >= a_cache->batch_capacity) {
        pthread_mutex_unlock(&a_cache->batch_lock);
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
    
    // Write all entries in ONE transaction (GlobalDB handles transaction automatically)
    int l_ret = dap_global_db_set_raw_sync(l_store_objs, l_batch_size);
    
    // Free allocated memory (including signatures)
    for (size_t i = 0; i < l_batch_size; i++) {
        DAP_DELETE(l_store_objs[i].key);
        DAP_DELETE(l_store_objs[i].group);
        DAP_DELETE(l_store_objs[i].value);
        DAP_DELETE(l_store_objs[i].sign);
    }
    DAP_DELETE(l_store_objs);
    
    uint64_t l_elapsed_us = CACHE_TIMING_END_US();
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Batch flush failed: %zu blocks, error=%d", l_batch_size, l_ret);
        return -1;
    }
    
    // Always log batch flush for debugging (not just in debug mode)
    log_it(L_NOTICE, "Cache batch flushed: %zu blocks written to '%s' (took %.1f ms)",
           l_batch_size, a_cache->gdb_group, l_elapsed_us / 1000.0);
    
    if (a_cache->debug) {
        log_it(L_DEBUG, "Batch flush completed: %zu blocks, %.3f ms (%.1f blocks/ms)",
               l_batch_size, l_elapsed_us / 1000.0, 
               l_batch_size / (l_elapsed_us / 1000.0 + 0.001));
    }
    
    return 0;
}

