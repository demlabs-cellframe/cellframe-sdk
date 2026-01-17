/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2017
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include "dap_chain_block.h"
#include "dap_hash.h"
#include "uthash.h"
#include "dap_chain_ledger.h"
#include "dap_chain_cell.h"

typedef struct dap_chain_type_blocks dap_chain_type_blocks_t;

// Magic number for cache validation
#define DAP_CHAIN_BLOCK_CACHE_MAGIC 0x424C4B43  // "BLKC"
#define DAP_CHAIN_BLOCK_CACHE_VERSION 1

/**
 * @brief Serialized block cache entry for GlobalDB storage
 * 
 * This structure contains minimal data needed to restore block_cache
 * without full block verification. The actual block data is read from
 * the cell file using file_offset.
 */
typedef struct dap_chain_block_cache_db_entry {
    dap_chain_hash_fast_t block_hash;   // Block hash (key)
    uint64_t file_offset;               // Offset in cell file
    uint32_t block_size;                // Block size in bytes
    uint64_t block_number;              // Block number in chain
    int64_t ts_created;                 // Block creation timestamp
    uint16_t datum_count;               // Number of datums in block
    uint16_t sign_count;                // Number of signatures
    uint16_t generation;                // Block generation
    uint8_t flags;                      // Flags: bit0=is_genesis, bit1=is_blockgen
    uint8_t reserved;                   // Alignment padding
    // Followed by: int32_t datum_ret_codes[datum_count]
} DAP_ALIGN_PACKED dap_chain_block_cache_db_entry_t;

/**
 * @brief Header for serialized cell cache in GlobalDB
 */
typedef struct dap_chain_block_cache_db_header {
    uint32_t magic;                     // DAP_CHAIN_BLOCK_CACHE_MAGIC
    uint16_t version;                   // DAP_CHAIN_BLOCK_CACHE_VERSION
    uint16_t reserved;                  // Alignment
    uint64_t cell_id;                   // Cell ID
    uint32_t blocks_count;              // Number of blocks in this cell
    uint32_t total_datums;              // Total datums count (for validation)
} DAP_ALIGN_PACKED dap_chain_block_cache_db_header_t;

typedef struct dap_chain_block_cache {
    // Block's general non-nested attributes
    dap_chain_hash_fast_t block_hash;
    char block_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    size_t block_size;
    uint64_t block_number;

    // Local platform values representation
    time_t ts_created;

    // Block's datums
    size_t datum_count;
    dap_chain_datum_t ** datum;
    dap_hash_fast_t *datum_hash;

    // Extracted metadata
    dap_chain_hash_fast_t prev_hash;
    dap_chain_hash_fast_t anchor_hash;
    dap_chain_hash_fast_t merkle_root;
    dap_chain_hash_fast_t* links_hash;
    size_t links_hash_count;
    uint64_t nonce;
    uint64_t nonce2;
    bool is_genesis;
    bool is_blockgen;
    uint16_t generation;

    // Block's signatures
    size_t sign_count; // Number of signatures in block's tail
    //dap_sign_t **sign; // Pointer to signatures in block

    // Pointer to block itself
    dap_chain_block_t * block;

    // List for keeping pointers to list of atoms in side branches
    dap_list_t *forked_branches;

    // === Cache-related fields ===
    uint64_t file_offset;               // Offset of block in cell file
    dap_chain_cell_id_t cell_id;        // Cell ID where block is stored
    int32_t *datum_ret_codes;           // Return codes from ledger for each datum
    bool is_verified;                   // Block signatures were verified
    bool is_from_cache;                 // Block was loaded from cache (skip verification)

    // uthash handle
    UT_hash_handle hh, hh2;
} dap_chain_block_cache_t;

typedef struct dap_chain_block_forked_branch_atoms_table{
    dap_hash_fast_t block_hash;
    dap_chain_block_cache_t *block_cache;
    UT_hash_handle hh;
} dap_chain_block_forked_branch_atoms_table_t;

typedef struct dap_chain_block_forked_branch {
    dap_chain_block_cache_t *connected_block; // pointer to a block connected with this forked branch
    dap_chain_block_forked_branch_atoms_table_t *forked_branch_atoms;
} dap_chain_block_forked_branch_t;

int dap_chain_block_cache_init();
void dap_chain_block_cache_deinit();


dap_chain_block_cache_t *dap_chain_block_cache_new(dap_hash_fast_t *a_block_hash, dap_chain_block_t *a_block,
                                                   size_t a_block_size, uint64_t a_block_number, bool a_copy_block);
dap_chain_block_cache_t *dap_chain_block_cache_dup(dap_chain_block_cache_t *a_block);
int dap_chain_block_cache_update(dap_chain_block_cache_t *a_block_cache, dap_hash_fast_t *a_block_hash);
void dap_chain_block_cache_delete(dap_chain_block_cache_t *a_block_cache);

// Get the list of 'out_cond' items from previous transactions with summary out value. Put this summary value to a_value_out
dap_list_t * dap_chain_block_get_list_tx_cond_outs_with_val(dap_ledger_t *a_ledger, dap_chain_block_cache_t * a_block_cache, uint256_t *a_value_out);

// === Cache serialization functions ===

/**
 * @brief Serialize all block caches for a cell into a buffer for GlobalDB storage
 * 
 * @param a_blocks_hash uthash table of block caches
 * @param a_cell_id Cell ID
 * @param a_out_data Output buffer (allocated, caller must free)
 * @param a_out_size Output buffer size
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_block_cache_serialize_cell(dap_chain_block_cache_t *a_blocks_hash,
                                          uint64_t a_cell_id,
                                          uint8_t **a_out_data,
                                          size_t *a_out_size);

/**
 * @brief Deserialize block caches from GlobalDB buffer
 * 
 * Creates block_cache structures from serialized data. Block pointers
 * are set using file_offset from cache + mmap/file read.
 * 
 * @param a_data Serialized data from GlobalDB
 * @param a_size Data size
 * @param a_chain Chain context (for mmap access)
 * @param a_cell Cell context
 * @param a_out_blocks Output: array of restored block caches
 * @param a_out_count Output: number of blocks restored
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_block_cache_deserialize_cell(const uint8_t *a_data,
                                            size_t a_size,
                                            dap_chain_t *a_chain,
                                            dap_chain_cell_t *a_cell,
                                            dap_chain_block_cache_t ***a_out_blocks,
                                            size_t *a_out_count);

/**
 * @brief Save cell block cache to GlobalDB
 * 
 * Should be called after cell loading is complete (batch save).
 * 
 * @param a_chain Chain context
 * @param a_cell_id Cell ID
 * @param a_blocks uthash table of block caches
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_block_cache_save_to_gdb(dap_chain_t *a_chain,
                                       uint64_t a_cell_id,
                                       dap_chain_block_cache_t *a_blocks);

/**
 * @brief Load cell block cache from GlobalDB
 * 
 * @param a_chain Chain context
 * @param a_cell Cell context
 * @param a_out_blocks Output: array of restored block caches
 * @param a_out_count Output: number of blocks
 * @return 0 on success, -1 if no cache found, negative error otherwise
 */
int dap_chain_block_cache_load_from_gdb(dap_chain_t *a_chain,
                                         dap_chain_cell_t *a_cell,
                                         dap_chain_block_cache_t ***a_out_blocks,
                                         size_t *a_out_count);

/**
 * @brief Add single block to GlobalDB cache (incremental update)
 * 
 * Called when new block is added at runtime.
 * 
 * @param a_chain Chain context
 * @param a_block_cache Block cache to add
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_block_cache_add_to_gdb(dap_chain_t *a_chain,
                                      dap_chain_block_cache_t *a_block_cache);

/**
 * @brief Get GlobalDB group name for block cache
 * 
 * @param a_chain Chain context
 * @return Allocated string (caller must free)
 */
char *dap_chain_block_cache_get_gdb_group(dap_chain_t *a_chain);

/**
 * @brief Check if block cache exists in GlobalDB for cell
 * 
 * @param a_chain Chain context
 * @param a_cell_id Cell ID
 * @return true if cache exists
 */
bool dap_chain_block_cache_gdb_has_cell(dap_chain_t *a_chain, uint64_t a_cell_id);

