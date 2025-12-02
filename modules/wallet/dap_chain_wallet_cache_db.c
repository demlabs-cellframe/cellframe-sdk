/*
 * Authors:
 * Olzhas Zharasbaev
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.
 
 This file is part of DAP (Distributed Applications Platform) the open source project
 
    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

#include <stdlib.h>
#include <string.h>
#include "dap_chain_wallet_cache_db.h"
#include "dap_strfuncs.h"
#include "dap_common.h"
#include "dap_global_db.h"

#define LOG_TAG "dap_chain_wallet_cache_db"

/**
 * @brief Calculate total size needed for wallet cache DB record
 * @param a_tx_count Number of transactions
 * @param a_unspent_count Number of unspent outputs
 * @return Total size in bytes
 */
size_t dap_wallet_cache_db_calc_size(uint32_t a_tx_count, uint32_t a_unspent_count)
{
    size_t l_size = sizeof(dap_wallet_cache_db_t);
    
    // Add size for transaction records
    l_size += sizeof(dap_wallet_tx_cache_db_t) * a_tx_count;
    
    // Add size for unspent output records
    l_size += sizeof(dap_wallet_unspent_out_db_t) * a_unspent_count;
    
    return l_size;
}

/**
 * @brief Create new wallet cache DB record
 * @param a_addr Wallet address
 * @param a_net_id Network ID
 * @param a_chain_id Chain ID
 * @return Allocated wallet cache DB record or NULL on error
 */
dap_wallet_cache_db_t* dap_wallet_cache_db_create(dap_chain_addr_t *a_addr, 
                                                   dap_chain_net_id_t a_net_id,
                                                   dap_chain_id_t a_chain_id)
{
    dap_return_val_if_fail(a_addr, NULL);
    
    // Allocate initial structure (will be reallocated when adding data)
    size_t l_size = dap_wallet_cache_db_calc_size(0, 0);
    dap_wallet_cache_db_t *l_cache = DAP_NEW_Z_SIZE(dap_wallet_cache_db_t, l_size);
    if (!l_cache) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    l_cache->version = DAP_WALLET_CACHE_DB_VERSION;
    l_cache->wallet_addr = *a_addr;
    l_cache->net_id = a_net_id;
    l_cache->chain_id = a_chain_id;
    l_cache->tx_count = 0;
    l_cache->unspent_count = 0;
    l_cache->last_update = dap_time_now();
    
    return l_cache;
}

/**
 * @brief Free wallet cache DB record
 * @param a_cache Wallet cache DB record
 */
void dap_wallet_cache_db_free(dap_wallet_cache_db_t *a_cache)
{
    DAP_DELETE(a_cache);
}

/**
 * @brief Generate GlobalDB group name for wallet cache
 * @param a_net_id Network ID
 * @param a_chain_name Chain name
 * @return Allocated group string (caller must free)
 */
char* dap_wallet_cache_db_get_group(dap_chain_net_id_t a_net_id, const char *a_chain_name)
{
    dap_return_val_if_fail(a_chain_name, NULL);
    
    // Format: "wallet.cache.{net_id_hex}.{chain_name}"
    return dap_strdup_printf("local.wallet.cache.0x%016"DAP_UINT64_FORMAT_X".%s", 
                            a_net_id.uint64, a_chain_name);
}

/**
 * @brief Generate GlobalDB key for wallet address
 * @param a_wallet_addr Wallet address
 * @return Allocated key string (caller must free)
 */
char* dap_wallet_cache_db_get_key(dap_chain_addr_t *a_wallet_addr)
{
    dap_return_val_if_fail(a_wallet_addr, NULL);
    
    // Convert wallet address to hex string (returns static buffer)
    const char *l_addr_str = dap_chain_addr_to_str(a_wallet_addr);
    if (!l_addr_str) {
        log_it(L_ERROR, "Failed to convert wallet address to string");
        return NULL;
    }
    
    // Return a copy since static buffer will be overwritten on next call
    return dap_strdup(l_addr_str);
}

/**
 * @brief Save wallet cache to GlobalDB
 * @param a_cache Wallet cache data to save
 * @param a_cache_size Total size of cache including variable data
 * @param a_net_name Network name
 * @param a_chain_name Chain name
 * @return 0 on success, negative error code on failure
 */
int dap_wallet_cache_db_save(dap_wallet_cache_db_t *a_cache, size_t a_cache_size, const char *a_net_name, const char *a_chain_name)
{
    dap_return_val_if_fail(a_cache && a_cache_size > 0 && a_net_name && a_chain_name, -1);
    
    // Generate group and key
    char *l_group = dap_wallet_cache_db_get_group(a_cache->net_id, a_chain_name);
    if (!l_group) {
        log_it(L_ERROR, "Failed to generate GlobalDB group");
        return -2;
    }
    
    char *l_key = dap_wallet_cache_db_get_key(&a_cache->wallet_addr);
    if (!l_key) {
        log_it(L_ERROR, "Failed to generate GlobalDB key");
        DAP_DELETE(l_group);
        return -3;
    }
    
    // Update timestamp
    a_cache->last_update = dap_time_now();
    
    // Save to GlobalDB with actual size (including all variable data)
    bool l_result = dap_global_db_set_sync(l_group, l_key, a_cache, a_cache_size, false);
    
    DAP_DELETE(l_group);
    DAP_DELETE(l_key);
    
    if (l_result != DAP_GLOBAL_DB_RC_SUCCESS) {
        log_it(L_ERROR, "Failed to save wallet cache to GlobalDB");
        return -4;
    }
    
    log_it(L_DEBUG, "Saved wallet cache to GlobalDB: %u transactions, %u unspent outputs, %zu bytes",
             a_cache->tx_count, a_cache->unspent_count, a_cache_size);
    
    return 0;
}

/**
 * @brief Load wallet cache from GlobalDB
 * @param a_addr Wallet address
 * @param a_net_id Network ID
 * @param a_net_name Network name
 * @param a_chain_name Chain name
 * @return Loaded wallet cache or NULL if not found/error
 */
dap_wallet_cache_db_t* dap_wallet_cache_db_load(dap_chain_addr_t *a_addr, dap_chain_net_id_t a_net_id,
                                                 const char *a_net_name, const char *a_chain_name)
{
    dap_return_val_if_fail(a_addr && a_net_name && a_chain_name, NULL);
    
    // Generate group and key
    char *l_group = dap_wallet_cache_db_get_group(a_net_id, a_chain_name);
    if (!l_group) {
        log_it(L_ERROR, "Failed to generate GlobalDB group");
        return NULL;
    }
    
    char *l_key = dap_wallet_cache_db_get_key(a_addr);
    if (!l_key) {
        log_it(L_ERROR, "Failed to generate GlobalDB key");
        DAP_DELETE(l_group);
        return NULL;
    }
    
    // Load from GlobalDB
    size_t l_data_size = 0;
    dap_wallet_cache_db_t *l_cache = (dap_wallet_cache_db_t*)dap_global_db_get_sync(
        l_group, l_key, &l_data_size, NULL, NULL
    );
    
    DAP_DELETE(l_group);
    DAP_DELETE(l_key);
    
    if (!l_cache) {
        // Not an error - wallet simply doesn't have cached data yet
        log_it(L_INFO, "No wallet cache found in GlobalDB");
        return NULL;
    }
    
    // Verify version
    if (l_cache->version != DAP_WALLET_CACHE_DB_VERSION) {
        log_it(L_WARNING, "Wallet cache DB version mismatch: expected %u, got %u",
               DAP_WALLET_CACHE_DB_VERSION, l_cache->version);
        DAP_DELETE(l_cache);
        return NULL;
    }
    
    // Verify size
    size_t l_expected_size = dap_wallet_cache_db_calc_size(l_cache->tx_count, l_cache->unspent_count);
    if (l_data_size != l_expected_size) {
        log_it(L_ERROR, "Wallet cache DB size mismatch: expected %zu, got %zu",
               l_expected_size, l_data_size);
        DAP_DELETE(l_cache);
        return NULL;
    }
    
    log_it(L_DEBUG, "Loaded wallet cache from GlobalDB: %u transactions, %u unspent outputs",
             l_cache->tx_count, l_cache->unspent_count);
    
    return l_cache;
}
