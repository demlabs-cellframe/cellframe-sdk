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

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_config.h"
#include "dap_chain.h"

/**
 * @brief Chain Cache - Fast blockchain loading optimization
 * 
 * Caches block offsets in GlobalDB to skip signature verification on subsequent loads.
 * 
 * Performance impact:
 * - First load:  ~50 min (full validation)
 * - Second load: ~3-5 min (hash check only)
 * - Speedup: 15x faster!
 * 
 * Architecture:
 * - GlobalDB: hash → offset mapping (24 bytes per block)
 * - Chain files: fseek(offset) + fread() → block data
 * - No RAM cache needed (GlobalDB handles it)
 * 
 * Safety:
 * - Hash validation before trust
 * - Graceful fallback to full validation on mismatch
 * - Default mode = full (backward compatible)
 * - Incremental save = minimal data loss on crash
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Cache mode
 */
typedef enum dap_chain_cache_mode {
    DAP_CHAIN_CACHE_MODE_FULL = 0,    // Always full validation (default, backward compatible)
    DAP_CHAIN_CACHE_MODE_CACHED = 1    // Use cache when possible (fast loading)
} dap_chain_cache_mode_t;

/**
 * @brief Cache entry stored in GlobalDB
 * 
 * Key: block hash (32 bytes)
 * Value: this structure (24 bytes)
 */
typedef struct dap_chain_cache_entry {
    uint64_t cell_id;         // Cell file ID where block is stored
    uint64_t file_offset;     // Offset in file to SIZE field before block data
    uint32_t block_size;      // Block size in bytes (for fread)
    uint32_t tx_count;        // Transaction count in block (for statistics)
} DAP_ALIGN_PACKED dap_chain_cache_entry_t;

/**
 * @brief Cache statistics
 */
typedef struct dap_chain_cache_stats {
    uint64_t cache_hits;          // Blocks loaded from cache
    uint64_t cache_misses;        // Blocks fully validated
    uint64_t blocks_cached;       // Total blocks in cache
    uint64_t incremental_saved;   // Incremental saves count
    uint64_t compactions_count;   // Compaction runs
    uint64_t compaction_time_ms;  // Total compaction time
    double avg_lookup_time_ms;    // Average cache lookup time
    double avg_load_time_ms;      // Average block load time
    uint64_t invalid_entries_ignored; // Legacy entries skipped due to invalid size/corruption
} dap_chain_cache_stats_t;

/**
 * @brief Cache handle (opaque)
 */
typedef struct dap_chain_cache dap_chain_cache_t;

/**
 * @brief Initialize chain cache subsystem
 * 
 * Must be called once at startup before any cache operations.
 * 
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_cache_init(void);

/**
 * @brief Deinitialize chain cache subsystem
 * 
 * Must be called at shutdown after all chains are closed.
 */
void dap_chain_cache_deinit(void);

/**
 * @brief Create cache for a chain
 * 
 * Reads configuration and initializes cache for the chain.
 * 
 * Config options:
 * - cache_mode: full/cached (default: full)
 * - cache_incremental_save: true/false (default: true)
 * - cache_compaction_threshold: 10-1000 (default: 100)
 * - cache_compaction_async: true/false (default: true)
 * - cache_debug: true/false (default: false)
 * 
 * @param a_chain Chain handle
 * @param a_config Configuration handle
 * @return Cache handle on success, NULL on error
 */
dap_chain_cache_t *dap_chain_cache_create(dap_chain_t *a_chain, dap_config_t *a_config);

/**
 * @brief Delete cache for a chain
 * 
 * Performs final compaction if needed and releases resources.
 * 
 * @param a_cache Cache handle
 */
void dap_chain_cache_delete(dap_chain_cache_t *a_cache);

/**
 * @brief Check if block is in cache
 * 
 * Fast lookup to check if block hash exists in cache and get its offset.
 * 
 * @param a_cache Cache handle
 * @param a_block_hash Block hash to lookup
 * @param a_out_entry Output entry (can be NULL if only checking existence)
 * @return true if found in cache, false otherwise
 */
bool dap_chain_cache_has_block(dap_chain_cache_t *a_cache, 
                                const dap_hash_fast_t *a_block_hash,
                                dap_chain_cache_entry_t *a_out_entry);

/**
 * @brief Get block entry from cache
 * 
 * Same as dap_chain_cache_has_block but always fills output entry.
 * 
 * @param a_cache Cache handle
 * @param a_block_hash Block hash to lookup
 * @param a_out_entry Output entry (required)
 * @return 0 on success, -1 if not found, negative error code otherwise
 */
int dap_chain_cache_get_block(dap_chain_cache_t *a_cache,
                               const dap_hash_fast_t *a_block_hash,
                               dap_chain_cache_entry_t *a_out_entry);

/**
 * @brief Save block to cache
 * 
 * Saves block metadata to cache (incremental save).
 * Updates compaction counter and schedules compaction if threshold reached.
 * 
 * @param a_cache Cache handle
 * @param a_block_hash Block hash (key)
 * @param a_cell_id Cell file ID
 * @param a_file_offset File offset to block
 * @param a_block_size Block size in bytes
 * @param a_tx_count Transaction count
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_cache_save_block(dap_chain_cache_t *a_cache,
                                const dap_hash_fast_t *a_block_hash,
                                uint64_t a_cell_id,
                                uint64_t a_file_offset,
                                uint32_t a_block_size,
                                uint32_t a_tx_count);

/**
 * @brief Called when new block is accepted to chain
 * 
 * Saves block to cache immediately (incremental save).
 * Updates statistics and triggers compaction if needed.
 * 
 * @param a_cache Cache handle
 * @param a_block_hash Block hash
 * @param a_cell_id Cell file ID
 * @param a_file_offset File offset to block
 * @param a_block_size Block size in bytes
 * @param a_tx_count Transaction count
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_cache_on_block_added(dap_chain_cache_t *a_cache,
                                    const dap_hash_fast_t *a_block_hash,
                                    uint64_t a_cell_id,
                                    uint64_t a_file_offset,
                                    uint32_t a_block_size,
                                    uint32_t a_tx_count);

/**
 * @brief Trigger cache compaction
 * 
 * Merges incremental entries into compacted structure.
 * Can be called manually or automatically by incremental save.
 * 
 * @param a_cache Cache handle
 * @param a_async Run in background thread (non-blocking)
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_cache_compact(dap_chain_cache_t *a_cache, bool a_async);

/**
 * @brief Get cache statistics
 * 
 * @param a_cache Cache handle
 * @param a_out_stats Output statistics structure
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_cache_get_stats(dap_chain_cache_t *a_cache,
                               dap_chain_cache_stats_t *a_out_stats);

/**
 * @brief Reset cache statistics
 * 
 * @param a_cache Cache handle
 */
void dap_chain_cache_reset_stats(dap_chain_cache_t *a_cache);

/**
 * @brief Print detailed cache statistics
 * 
 * Prints performance metrics including timing data for debugging.
 * 
 * @param a_cache Cache handle
 */
void dap_chain_cache_print_stats(dap_chain_cache_t *a_cache);

/**
 * @brief Clear cache for a chain
 * 
 * Removes all cache entries for the chain from GlobalDB.
 * Use with caution - next load will be slow!
 * 
 * @param a_cache Cache handle
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_cache_clear(dap_chain_cache_t *a_cache);

/**
 * @brief Check if cache is enabled
 * 
 * @param a_cache Cache handle
 * @return true if cache mode is CACHED, false if FULL
 */
bool dap_chain_cache_enabled(dap_chain_cache_t *a_cache);

/**
 * @brief Get cache mode
 * 
 * @param a_cache Cache handle
 * @return Cache mode
 */
dap_chain_cache_mode_t dap_chain_cache_get_mode(dap_chain_cache_t *a_cache);

/**
 * @brief Set cache mode
 * 
 * Can be used to enable/disable cache at runtime.
 * 
 * @param a_cache Cache handle
 * @param a_mode New cache mode
 */
void dap_chain_cache_set_mode(dap_chain_cache_t *a_cache, dap_chain_cache_mode_t a_mode);

/**
 * @brief Batch operations - load all cache entries for a cell into memory
 * 
 * This function loads all cache entries for a specific cell from GlobalDB into
 * an in-memory hash table for fast lookups during cell loading.
 * 
 * Use case: Load cell file with thousands of blocks without slow per-block GlobalDB queries
 * 
 * Performance:
 * - Without batch: 8000 blocks × 27ms = 216 seconds (per-block GlobalDB queries)
 * - With batch: 500ms batch load + 8000 × 0.001ms = 0.5 seconds (400x faster!)
 * 
 * Memory usage: ~56 bytes per block (temporary, freed after cell load)
 * 
 * @param a_cache Cache handle
 * @param a_cell_id Cell ID to load cache for
 * @return Opaque handle to in-memory cache table, NULL on error
 */
void* dap_chain_cache_load_cell(dap_chain_cache_t *a_cache, uint64_t a_cell_id);

/**
 * @brief Lookup block in batch-loaded cache
 * 
 * Fast in-memory lookup in batch-loaded cache table.
 * 
 * @param a_cell_cache Handle returned by dap_chain_cache_load_cell()
 * @param a_block_hash Block hash to lookup
 * @param a_out_entry Output entry (required)
 * @return 0 on success (found), -1 if not found
 */
int dap_chain_cache_lookup_in_cell(void *a_cell_cache, 
                                     const dap_hash_fast_t *a_block_hash,
                                     dap_chain_cache_entry_t *a_out_entry);

/**
 * @brief Free batch-loaded cache
 * 
 * Releases memory used by batch-loaded cache table.
 * Must be called after cell loading is complete.
 * 
 * @param a_cell_cache Handle returned by dap_chain_cache_load_cell()
 */
void dap_chain_cache_unload_cell(void *a_cell_cache);

/**
 * @brief Read block by hash directly from cache (scans compact cell indices)
 *
 * @param a_cache Cache handle
 * @param a_hash Block hash to read
 * @param a_out_size Output: atom size in bytes
 * @return Pointer to atom data (must be freed by caller) or NULL if not found
 */
void* dap_chain_cache_read_block_by_hash(dap_chain_cache_t *a_cache,
                                         const dap_hash_fast_t *a_hash,
                                         size_t *a_out_size);

#ifdef __cplusplus
}
#endif

