/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2017-2020
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
#include <time.h>
#include "dap_common.h"
#include "dap_chain_block_cache.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_global_db.h"
#include "dap_chain.h"

#define LOG_TAG "dap_chain_block_cache"

// GlobalDB group prefix for block cache
#define DAP_CHAIN_BLOCK_CACHE_GDB_PREFIX "local.blocks.cache"

/**
 * @brief dap_chain_block_cache_init
 * @return
 */
int dap_chain_block_cache_init()
{
    return 0;
}

/**
 * @brief dap_chain_block_cache_deinit
 */
void dap_chain_block_cache_deinit()
{

}

/**
 * @brief dap_chain_block_cache_new
 * @param a_block
 * @param a_block_size
 * @return
 */

dap_chain_block_cache_t *dap_chain_block_cache_new(dap_hash_fast_t *a_block_hash, dap_chain_block_t *a_block,
                                                   size_t a_block_size, uint64_t a_block_number, bool a_copy_block)
{
    if (! a_block)
        return NULL;

    dap_chain_block_cache_t * l_block_cache = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_block_cache_t, NULL);
    l_block_cache->block = a_copy_block ? DAP_DUP_SIZE_RET_VAL_IF_FAIL(a_block, a_block_size, NULL, l_block_cache) : a_block;
    l_block_cache->block_size = a_block_size;
    l_block_cache->block_number = a_block_number;
    l_block_cache->ts_created = a_block->hdr.ts_created;
    l_block_cache->sign_count = dap_chain_block_get_signs_count(a_block, a_block_size);
    if (dap_chain_block_cache_update(l_block_cache, a_block_hash)) {
        log_it(L_WARNING, "Block cache can't be created, possible cause corrupted block inside");
        if (a_copy_block)
            DAP_DELETE(l_block_cache->block);
        DAP_DELETE(l_block_cache);
        return NULL;
    }
    return l_block_cache;
}

/**
 * @brief dap_chain_block_cache_dup
 * @param a_block
 * @return
 */
dap_chain_block_cache_t * dap_chain_block_cache_dup(dap_chain_block_cache_t * a_block)
{
    dap_chain_block_cache_t *l_ret = DAP_DUP(a_block);
    if (!l_ret) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_ret->hh = (UT_hash_handle){ }; // Drop hash handle to prevent its usage
    return l_ret;
}

/**
 * @brief dap_chain_block_cache_update
 * @param a_block_cache
 */

int dap_chain_block_cache_update(dap_chain_block_cache_t *a_block_cache, dap_hash_fast_t *a_block_hash)
{
    assert(a_block_cache);
    assert(a_block_cache->block);
    if (a_block_hash)
        a_block_cache->block_hash = *a_block_hash;
    else
        dap_hash_fast(a_block_cache->block, a_block_cache->block_size, &a_block_cache->block_hash);

    dap_hash_fast_to_str(&a_block_cache->block_hash, a_block_cache->block_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);

    if (dap_chain_block_meta_extract(a_block_cache->block, a_block_cache->block_size,
                                        &a_block_cache->prev_hash,
                                        &a_block_cache->anchor_hash,
                                        &a_block_cache->merkle_root,
                                        &a_block_cache->links_hash,
                                        &a_block_cache->links_hash_count,
                                        &a_block_cache->is_genesis,
                                        &a_block_cache->nonce,
                                        &a_block_cache->nonce2,
                                        &a_block_cache->generation,
                                        &a_block_cache->is_blockgen)) {
        DAP_DEL_Z(a_block_cache->links_hash);
        return -1;
    }

    DAP_DEL_Z(a_block_cache->datum);
    a_block_cache->datum = dap_chain_block_get_datums(a_block_cache->block, a_block_cache->block_size, &a_block_cache->datum_count);

    if (a_block_cache->datum_count != a_block_cache->block->hdr.datum_count) {
        DAP_DEL_Z(a_block_cache->datum);
        DAP_DEL_Z(a_block_cache->links_hash);
        return -2;
    }

    DAP_DEL_Z(a_block_cache->datum_hash);
    a_block_cache->datum_hash = DAP_NEW_Z_SIZE(dap_hash_fast_t, a_block_cache->datum_count * sizeof(dap_hash_fast_t));
    if (!a_block_cache->datum_hash && a_block_cache->datum_count) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DEL_Z(a_block_cache->datum);
        DAP_DEL_Z(a_block_cache->links_hash);
        return -3;
    }
    for (size_t i = 0; i < a_block_cache->datum_count; i++)
        dap_chain_datum_calc_hash(a_block_cache->datum[i], a_block_cache->datum_hash + i);
    return 0;
}

/**
 * @brief dap_chain_block_cache_delete
 * @param a_block
 */
void dap_chain_block_cache_delete(dap_chain_block_cache_t * a_block_cache)
{
    DAP_DEL_Z(a_block_cache->datum);
    DAP_DEL_Z(a_block_cache->datum_hash);
    DAP_DEL_Z(a_block_cache->links_hash);
    DAP_DEL_Z(a_block_cache->datum_ret_codes);
    DAP_DELETE(a_block_cache);
}

/**
 * @brief dap_chain_datum_get_list_tx_outs_cond_with_val
 * @param a_ledger
 * @param a_block_cache
 * @param a_value_out
 * @return list of dap_chain_tx_used_out_item_t
 */
dap_list_t * dap_chain_block_get_list_tx_cond_outs_with_val(dap_ledger_t *a_ledger, dap_chain_block_cache_t *a_block_cache,
                                                            uint256_t *a_value_out)
{
    dap_list_t *l_list_used_out = NULL; // list of transaction with 'out' items
    dap_chain_tx_out_cond_t *l_tx_out_cond = NULL;
    uint256_t l_value_transfer = {};    
    for (size_t i = 0; i < a_block_cache->datum_count; i++) {
        if (a_block_cache->datum[i]->header.type_id != DAP_CHAIN_DATUM_TX)
            continue;
        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)a_block_cache->datum[i]->data;
        int l_out_idx_tmp = 0;
        if (NULL == (l_tx_out_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE,
                                                                     &l_out_idx_tmp)))
            continue;

        //Check whether used 'out' items
        dap_hash_fast_t *l_tx_hash = a_block_cache->datum_hash + i;
        if (!dap_ledger_tx_hash_is_used_out_item (a_ledger, l_tx_hash, l_out_idx_tmp, NULL)) {
            dap_chain_tx_used_out_item_t *l_item = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
            if (!l_item) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                if (l_list_used_out)
                    dap_list_free_full(l_list_used_out, NULL);
                return NULL;
            }
            l_item->tx_hash_fast = *l_tx_hash;
            l_item->num_idx_out = l_out_idx_tmp;
            l_item->value = l_tx_out_cond->header.value;
            l_list_used_out = dap_list_append(l_list_used_out, l_item);
            SUM_256_256(l_value_transfer, l_item->value, &l_value_transfer);
        }
    }
    if (IS_ZERO_256(l_value_transfer) || !l_list_used_out) {
        dap_list_free_full(l_list_used_out, NULL);
        return NULL;
    }
    else
        *a_value_out = l_value_transfer;
    return l_list_used_out;
}

// ============================================================================
// Cache Serialization Functions
// ============================================================================

/**
 * @brief Get GlobalDB group name for block cache
 */
char *dap_chain_block_cache_get_gdb_group(dap_chain_t *a_chain)
{
    dap_return_val_if_fail(a_chain, NULL);
    return dap_strdup_printf("%s.%s.%s", 
                             DAP_CHAIN_BLOCK_CACHE_GDB_PREFIX,
                             a_chain->net_name, 
                             a_chain->name);
}

/**
 * @brief Check if block cache exists in GlobalDB for cell
 */
bool dap_chain_block_cache_gdb_has_cell(dap_chain_t *a_chain, uint64_t a_cell_id)
{
    dap_return_val_if_fail(a_chain, false);
    
    char *l_group = dap_chain_block_cache_get_gdb_group(a_chain);
    if (!l_group)
        return false;
    
    char l_key[64];
    snprintf(l_key, sizeof(l_key), "cell_0x%016" DAP_UINT64_FORMAT_x, a_cell_id);
    
    // Check if key exists by trying to read it
    size_t l_data_size = 0;
    byte_t *l_data = dap_global_db_get_sync(l_group, l_key, &l_data_size, NULL, NULL);
    bool l_exists = (l_data != NULL);
    DAP_DEL_Z(l_data);
    
    DAP_DELETE(l_group);
    return l_exists;
}

/**
 * @brief Serialize all block caches for a cell into a buffer
 */
int dap_chain_block_cache_serialize_cell(dap_chain_block_cache_t *a_blocks_hash,
                                          uint64_t a_cell_id,
                                          uint8_t **a_out_data,
                                          size_t *a_out_size)
{
    dap_return_val_if_fail(a_out_data && a_out_size, -1);
    
    // Count blocks and total datums
    uint32_t l_blocks_count = 0;
    uint32_t l_total_datums = 0;
    dap_chain_block_cache_t *l_block, *l_tmp;
    
    HASH_ITER(hh, a_blocks_hash, l_block, l_tmp) {
        if (l_block->cell_id.uint64 == a_cell_id) {
            l_blocks_count++;
            l_total_datums += l_block->datum_count;
        }
    }
    
    if (l_blocks_count == 0) {
        log_it(L_WARNING, "No blocks found for cell 0x%016" DAP_UINT64_FORMAT_x, a_cell_id);
        *a_out_data = NULL;
        *a_out_size = 0;
        return 0;
    }
    
    // Calculate buffer size
    size_t l_header_size = sizeof(dap_chain_block_cache_db_header_t);
    size_t l_entries_size = l_blocks_count * sizeof(dap_chain_block_cache_db_entry_t);
    size_t l_ret_codes_size = l_total_datums * sizeof(int32_t);
    size_t l_total_size = l_header_size + l_entries_size + l_ret_codes_size;
    
    uint8_t *l_buffer = DAP_NEW_Z_SIZE(uint8_t, l_total_size);
    if (!l_buffer) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -2;
    }
    
    // Fill header
    dap_chain_block_cache_db_header_t *l_header = (dap_chain_block_cache_db_header_t *)l_buffer;
    l_header->magic = DAP_CHAIN_BLOCK_CACHE_MAGIC;
    l_header->version = DAP_CHAIN_BLOCK_CACHE_VERSION;
    l_header->cell_id = a_cell_id;
    l_header->blocks_count = l_blocks_count;
    l_header->total_datums = l_total_datums;
    
    // Fill entries
    uint8_t *l_ptr = l_buffer + l_header_size;
    
    HASH_ITER(hh, a_blocks_hash, l_block, l_tmp) {
        if (l_block->cell_id.uint64 != a_cell_id)
            continue;
        
        dap_chain_block_cache_db_entry_t *l_entry = (dap_chain_block_cache_db_entry_t *)l_ptr;
        
        l_entry->block_hash = l_block->block_hash;
        l_entry->file_offset = l_block->file_offset;
        l_entry->block_size = (uint32_t)l_block->block_size;
        l_entry->block_number = l_block->block_number;
        l_entry->ts_created = l_block->ts_created;
        l_entry->datum_count = (uint16_t)l_block->datum_count;
        l_entry->sign_count = (uint16_t)l_block->sign_count;
        l_entry->generation = l_block->generation;
        l_entry->flags = (l_block->is_genesis ? 0x01 : 0) | 
                         (l_block->is_blockgen ? 0x02 : 0);
        l_entry->reserved = 0;
        
        l_ptr += sizeof(dap_chain_block_cache_db_entry_t);
        
        // Write datum ret_codes
        if (l_block->datum_count > 0 && l_block->datum_ret_codes) {
            memcpy(l_ptr, l_block->datum_ret_codes, l_block->datum_count * sizeof(int32_t));
        }
        l_ptr += l_block->datum_count * sizeof(int32_t);
    }
    
    *a_out_data = l_buffer;
    *a_out_size = l_total_size;
    
    log_it(L_INFO, "Serialized %u blocks (%u datums) for cell 0x%016" DAP_UINT64_FORMAT_x ", size %zu bytes",
           l_blocks_count, l_total_datums, a_cell_id, l_total_size);
    
    return 0;
}

/**
 * @brief Deserialize block caches from GlobalDB buffer
 */
int dap_chain_block_cache_deserialize_cell(const uint8_t *a_data,
                                            size_t a_size,
                                            dap_chain_t *a_chain,
                                            dap_chain_cell_t *a_cell,
                                            dap_chain_block_cache_t ***a_out_blocks,
                                            size_t *a_out_count)
{
    dap_return_val_if_fail(a_data && a_chain && a_cell && a_out_blocks && a_out_count, -1);
    
    if (a_size < sizeof(dap_chain_block_cache_db_header_t)) {
        log_it(L_ERROR, "Cache data too small: %zu bytes", a_size);
        return -2;
    }
    
    // Validate header
    const dap_chain_block_cache_db_header_t *l_header = (const dap_chain_block_cache_db_header_t *)a_data;
    
    if (l_header->magic != DAP_CHAIN_BLOCK_CACHE_MAGIC) {
        log_it(L_ERROR, "Invalid cache magic: 0x%08X (expected 0x%08X)", 
               l_header->magic, DAP_CHAIN_BLOCK_CACHE_MAGIC);
        return -3;
    }
    
    if (l_header->version > DAP_CHAIN_BLOCK_CACHE_VERSION) {
        log_it(L_ERROR, "Unsupported cache version: %u (max supported: %u)", 
               l_header->version, DAP_CHAIN_BLOCK_CACHE_VERSION);
        return -4;
    }
    
    if (l_header->blocks_count == 0) {
        *a_out_blocks = NULL;
        *a_out_count = 0;
        return 0;
    }
    
    // Allocate output array
    dap_chain_block_cache_t **l_blocks = DAP_NEW_Z_COUNT(dap_chain_block_cache_t*, l_header->blocks_count);
    if (!l_blocks) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -5;
    }
    
    const uint8_t *l_ptr = a_data + sizeof(dap_chain_block_cache_db_header_t);
    const uint8_t *l_end = a_data + a_size;
    
    for (uint32_t i = 0; i < l_header->blocks_count; i++) {
        if (l_ptr + sizeof(dap_chain_block_cache_db_entry_t) > l_end) {
            log_it(L_ERROR, "Cache data truncated at block %u", i);
            goto cleanup_error;
        }
        
        const dap_chain_block_cache_db_entry_t *l_entry = (const dap_chain_block_cache_db_entry_t *)l_ptr;
        l_ptr += sizeof(dap_chain_block_cache_db_entry_t);
        
        // Read block from file using offset via unified API
        size_t l_block_size = 0;
        dap_chain_block_t *l_block = dap_chain_cell_read_atom_by_offset(
            a_chain, a_cell->id, (off_t)l_entry->file_offset, &l_block_size);
        
        bool l_block_allocated = (l_block != NULL && !a_chain->is_mapped);
        
        if (!l_block) {
            log_it(L_ERROR, "Failed to read block at offset %lu", (unsigned long)l_entry->file_offset);
            goto cleanup_error;
        }
        
        if (l_block_size != l_entry->block_size) {
            log_it(L_WARNING, "Block size mismatch: cached %u, file %zu", 
                   l_entry->block_size, l_block_size);
        }
        
        // Create block cache from restored data
        dap_chain_block_cache_t *l_cache = DAP_NEW_Z(dap_chain_block_cache_t);
        if (!l_cache) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            if (l_block_allocated)
                DAP_DELETE(l_block);
            goto cleanup_error;
        }
        
        // Fill from entry
        l_cache->block_hash = l_entry->block_hash;
        dap_hash_fast_to_str(&l_cache->block_hash, l_cache->block_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
        l_cache->block_size = l_entry->block_size;
        l_cache->block_number = l_entry->block_number;
        l_cache->ts_created = l_entry->ts_created;
        l_cache->datum_count = l_entry->datum_count;
        l_cache->sign_count = l_entry->sign_count;
        l_cache->generation = l_entry->generation;
        l_cache->is_genesis = (l_entry->flags & 0x01) != 0;
        l_cache->is_blockgen = (l_entry->flags & 0x02) != 0;
        l_cache->block = l_block;
        l_cache->file_offset = l_entry->file_offset;
        l_cache->cell_id = a_cell->id;
        l_cache->is_from_cache = true;
        l_cache->is_verified = true;  // Was verified when originally added
        
        // Extract datums from block
        l_cache->datum = dap_chain_block_get_datums(l_block, l_cache->block_size, &l_cache->datum_count);
        
        // Calculate datum hashes
        if (l_cache->datum_count > 0) {
            l_cache->datum_hash = DAP_NEW_Z_COUNT(dap_hash_fast_t, l_cache->datum_count);
            if (l_cache->datum_hash) {
                for (size_t j = 0; j < l_cache->datum_count; j++)
                    dap_chain_datum_calc_hash(l_cache->datum[j], l_cache->datum_hash + j);
            }
        }
        
        // Extract metadata from block
        dap_chain_block_meta_extract(l_block, l_cache->block_size,
                                     &l_cache->prev_hash, &l_cache->anchor_hash,
                                     &l_cache->merkle_root, &l_cache->links_hash,
                                     &l_cache->links_hash_count, &l_cache->is_genesis,
                                     &l_cache->nonce, &l_cache->nonce2,
                                     &l_cache->generation, &l_cache->is_blockgen);
        
        // Read datum ret_codes
        if (l_entry->datum_count > 0) {
            if (l_ptr + l_entry->datum_count * sizeof(int32_t) > l_end) {
                log_it(L_ERROR, "Cache data truncated at datum ret_codes");
                dap_chain_block_cache_delete(l_cache);
                goto cleanup_error;
            }
            
            l_cache->datum_ret_codes = DAP_NEW_Z_COUNT(int32_t, l_entry->datum_count);
            if (l_cache->datum_ret_codes) {
                memcpy(l_cache->datum_ret_codes, l_ptr, l_entry->datum_count * sizeof(int32_t));
            }
            l_ptr += l_entry->datum_count * sizeof(int32_t);
        }
        
        l_blocks[i] = l_cache;
    }
    
    *a_out_blocks = l_blocks;
    *a_out_count = l_header->blocks_count;
    
    log_it(L_INFO, "Deserialized %u blocks from cache for cell 0x%016" DAP_UINT64_FORMAT_x,
           l_header->blocks_count, l_header->cell_id);
    
    return 0;

cleanup_error:
    // Free already allocated blocks
    for (uint32_t j = 0; j < l_header->blocks_count && l_blocks[j]; j++) {
        if (!a_chain->is_mapped && l_blocks[j]->block)
            DAP_DELETE(l_blocks[j]->block);
        dap_chain_block_cache_delete(l_blocks[j]);
    }
    DAP_DELETE(l_blocks);
    return -6;
}

/**
 * @brief Save cell block cache to GlobalDB
 */
int dap_chain_block_cache_save_to_gdb(dap_chain_t *a_chain,
                                       uint64_t a_cell_id,
                                       dap_chain_block_cache_t *a_blocks)
{
    dap_return_val_if_fail(a_chain, -1);
    
    uint8_t *l_data = NULL;
    size_t l_size = 0;
    
    int l_ret = dap_chain_block_cache_serialize_cell(a_blocks, a_cell_id, &l_data, &l_size);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to serialize block cache: %d", l_ret);
        return l_ret;
    }
    
    if (!l_data || l_size == 0) {
        log_it(L_DEBUG, "No data to save for cell 0x%016" DAP_UINT64_FORMAT_x, a_cell_id);
        return 0;
    }
    
    char *l_group = dap_chain_block_cache_get_gdb_group(a_chain);
    if (!l_group) {
        DAP_DELETE(l_data);
        return -2;
    }
    
    char l_key[64];
    snprintf(l_key, sizeof(l_key), "cell_0x%016" DAP_UINT64_FORMAT_x, a_cell_id);
    
    l_ret = dap_global_db_set_sync(l_group, l_key, l_data, l_size, false);
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to save block cache to GlobalDB: %d", l_ret);
    } else {
        log_it(L_NOTICE, "Saved block cache for cell 0x%016" DAP_UINT64_FORMAT_x " to GlobalDB (%zu bytes)",
               a_cell_id, l_size);
    }
    
    DAP_DELETE(l_data);
    DAP_DELETE(l_group);
    
    return l_ret;
}

/**
 * @brief Load cell block cache from GlobalDB
 */
int dap_chain_block_cache_load_from_gdb(dap_chain_t *a_chain,
                                         dap_chain_cell_t *a_cell,
                                         dap_chain_block_cache_t ***a_out_blocks,
                                         size_t *a_out_count)
{
    dap_return_val_if_fail(a_chain && a_cell && a_out_blocks && a_out_count, -1);
    
    char *l_group = dap_chain_block_cache_get_gdb_group(a_chain);
    if (!l_group)
        return -2;
    
    char l_key[64];
    snprintf(l_key, sizeof(l_key), "cell_0x%016" DAP_UINT64_FORMAT_x, a_cell->id.uint64);
    
    size_t l_size = 0;
    uint8_t *l_data = dap_global_db_get_sync(l_group, l_key, &l_size, NULL, NULL);
    
    DAP_DELETE(l_group);
    
    if (!l_data || l_size == 0) {
        log_it(L_DEBUG, "No cache found for cell 0x%016" DAP_UINT64_FORMAT_x, a_cell->id.uint64);
        *a_out_blocks = NULL;
        *a_out_count = 0;
        return -1;  // No cache found
    }
    
    int l_ret = dap_chain_block_cache_deserialize_cell(l_data, l_size, a_chain, a_cell, 
                                                        a_out_blocks, a_out_count);
    
    DAP_DELETE(l_data);
    
    return l_ret;
}

/**
 * @brief Add single block to GlobalDB cache (incremental update)
 * 
 * For incremental updates, we need to:
 * 1. Load existing cache for the cell
 * 2. Add new block entry
 * 3. Save updated cache
 * 
 * This is not optimal for batch loading but works for runtime updates.
 */
int dap_chain_block_cache_add_to_gdb(dap_chain_t *a_chain,
                                      dap_chain_block_cache_t *a_block_cache)
{
    dap_return_val_if_fail(a_chain && a_block_cache, -1);
    
    char *l_group = dap_chain_block_cache_get_gdb_group(a_chain);
    if (!l_group)
        return -2;
    
    char l_key[64];
    snprintf(l_key, sizeof(l_key), "cell_0x%016" DAP_UINT64_FORMAT_x, a_block_cache->cell_id.uint64);
    
    // Load existing data
    size_t l_old_size = 0;
    uint8_t *l_old_data = dap_global_db_get_sync(l_group, l_key, &l_old_size, NULL, NULL);
    
    // Calculate new entry size
    size_t l_entry_size = sizeof(dap_chain_block_cache_db_entry_t) + 
                          a_block_cache->datum_count * sizeof(int32_t);
    
    size_t l_new_size;
    uint8_t *l_new_data;
    
    if (l_old_data && l_old_size >= sizeof(dap_chain_block_cache_db_header_t)) {
        // Append to existing cache
        dap_chain_block_cache_db_header_t *l_header = (dap_chain_block_cache_db_header_t *)l_old_data;
        
        if (l_header->magic != DAP_CHAIN_BLOCK_CACHE_MAGIC) {
            log_it(L_WARNING, "Invalid existing cache, creating new");
            DAP_DELETE(l_old_data);
            l_old_data = NULL;
            l_old_size = 0;
        }
    }
    
    if (l_old_data) {
        // Extend existing buffer
        l_new_size = l_old_size + l_entry_size;
        l_new_data = DAP_REALLOC(l_old_data, l_new_size);
        if (!l_new_data) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DELETE(l_old_data);
            DAP_DELETE(l_group);
            return -3;
        }
        
        // Update header
        dap_chain_block_cache_db_header_t *l_header = (dap_chain_block_cache_db_header_t *)l_new_data;
        l_header->blocks_count++;
        l_header->total_datums += a_block_cache->datum_count;
        
        // Append new entry at end
        uint8_t *l_ptr = l_new_data + l_old_size;
        dap_chain_block_cache_db_entry_t *l_entry = (dap_chain_block_cache_db_entry_t *)l_ptr;
        
        l_entry->block_hash = a_block_cache->block_hash;
        l_entry->file_offset = a_block_cache->file_offset;
        l_entry->block_size = (uint32_t)a_block_cache->block_size;
        l_entry->block_number = a_block_cache->block_number;
        l_entry->ts_created = a_block_cache->ts_created;
        l_entry->datum_count = (uint16_t)a_block_cache->datum_count;
        l_entry->sign_count = (uint16_t)a_block_cache->sign_count;
        l_entry->generation = a_block_cache->generation;
        l_entry->flags = (a_block_cache->is_genesis ? 0x01 : 0) | 
                         (a_block_cache->is_blockgen ? 0x02 : 0);
        l_entry->reserved = 0;
        
        l_ptr += sizeof(dap_chain_block_cache_db_entry_t);
        
        // Write datum ret_codes
        if (a_block_cache->datum_count > 0 && a_block_cache->datum_ret_codes) {
            memcpy(l_ptr, a_block_cache->datum_ret_codes, a_block_cache->datum_count * sizeof(int32_t));
        }
    } else {
        // Create new cache with header + one entry
        l_new_size = sizeof(dap_chain_block_cache_db_header_t) + l_entry_size;
        l_new_data = DAP_NEW_Z_SIZE(uint8_t, l_new_size);
        if (!l_new_data) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            DAP_DELETE(l_group);
            return -3;
        }
        
        // Fill header
        dap_chain_block_cache_db_header_t *l_header = (dap_chain_block_cache_db_header_t *)l_new_data;
        l_header->magic = DAP_CHAIN_BLOCK_CACHE_MAGIC;
        l_header->version = DAP_CHAIN_BLOCK_CACHE_VERSION;
        l_header->cell_id = a_block_cache->cell_id.uint64;
        l_header->blocks_count = 1;
        l_header->total_datums = a_block_cache->datum_count;
        
        // Fill entry
        uint8_t *l_ptr = l_new_data + sizeof(dap_chain_block_cache_db_header_t);
        dap_chain_block_cache_db_entry_t *l_entry = (dap_chain_block_cache_db_entry_t *)l_ptr;
        
        l_entry->block_hash = a_block_cache->block_hash;
        l_entry->file_offset = a_block_cache->file_offset;
        l_entry->block_size = (uint32_t)a_block_cache->block_size;
        l_entry->block_number = a_block_cache->block_number;
        l_entry->ts_created = a_block_cache->ts_created;
        l_entry->datum_count = (uint16_t)a_block_cache->datum_count;
        l_entry->sign_count = (uint16_t)a_block_cache->sign_count;
        l_entry->generation = a_block_cache->generation;
        l_entry->flags = (a_block_cache->is_genesis ? 0x01 : 0) | 
                         (a_block_cache->is_blockgen ? 0x02 : 0);
        l_entry->reserved = 0;
        
        l_ptr += sizeof(dap_chain_block_cache_db_entry_t);
        
        // Write datum ret_codes
        if (a_block_cache->datum_count > 0 && a_block_cache->datum_ret_codes) {
            memcpy(l_ptr, a_block_cache->datum_ret_codes, a_block_cache->datum_count * sizeof(int32_t));
        }
    }
    
    // Save to GlobalDB
    int l_ret = dap_global_db_set_sync(l_group, l_key, l_new_data, l_new_size, false);
    
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to save incremental block cache: %d", l_ret);
    } else {
        log_it(L_DEBUG, "Added block %s to cache for cell 0x%016" DAP_UINT64_FORMAT_x,
               a_block_cache->block_hash_str, a_block_cache->cell_id.uint64);
    }
    
    DAP_DELETE(l_new_data);
    DAP_DELETE(l_group);
    
    return l_ret;
}
