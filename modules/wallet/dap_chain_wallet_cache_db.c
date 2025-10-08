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
    return dap_strdup_printf("wallet.cache.0x%016"DAP_UINT64_FORMAT_X".%s", 
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
