/*
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
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

#pragma once
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_ledger.h"


typedef enum dap_chain_wallet_getting_type {
    DAP_CHAIN_WALLET_CACHE_GET_FIRST = 0,
    DAP_CHAIN_WALLET_CACHE_GET_LAST,
    DAP_CHAIN_WALLET_CACHE_GET_NEXT,
    DAP_CHAIN_WALLET_CACHE_GET_PREVIOUS,
} dap_chain_wallet_getting_type_t;
typedef struct dap_chain_wallet_cache_iter {
    dap_chain_datum_tx_t *cur_tx;
    dap_chain_hash_fast_t *cur_hash;
    dap_chain_hash_fast_t *cur_atom_hash;
    uint32_t action;
    dap_chain_net_srv_uid_t uid;
    int ret_code;
    char *token_ticker;
    void *cur_item;
    void *cur_addr_cache;
} dap_chain_wallet_cache_iter_t;

#ifdef __cplusplus
extern "C" {
#endif

int dap_chain_wallet_cache_init();
int dap_chain_wallet_cache_deinit();

/**
 * @brief Load wallet cache for all opened wallets in the specified network
 * This function should be called when network transitions to NET_STATE_ONLINE
 * to ensure wallet cache is populated even if wallets were opened during NET_STATE_LOADING
 * @param a_net Network to load wallet cache for
 * @return 0 on success, -1 on error
 */
int dap_chain_wallet_cache_load_for_net(dap_chain_net_t *a_net);

/**
 * @brief Find next transactions after l_tx_hash_curr for wallet addr and save pointer to datum into a_tx. If l_tx_hash_curr is NULL then function find first tx for addr.
 * @param a_addr wallet address
 * @param a_token token ticker for transactions filtering  by it
 * @param a_tx output parameter. Pointer for storaging pointer to current datum
 * @param a_tx_hash_curr current tx hash. Receive start tx hash. Return hash of next tx that contained in a_datum
 * @param a_ret_code ledger return code for returned tx
 * @return  0 - ok
 *         -100 - wrong arguments
 *         -101 - addr is not found in cache
 */
int dap_chain_wallet_cache_tx_find(dap_chain_addr_t *a_addr, char *a_token, dap_chain_datum_tx_t **a_tx, 
                                                            dap_hash_fast_t *a_tx_hash_curr, int* a_ret_code);

/**
 * @brief Find next transactions after l_tx_hash_curr for wallet addr and save pointer to transaction into a_tx. 
 *         If l_tx_hash_curr is NULL then function find first tx for addr.
 * @param a_addr  wallet address
 * @param a_token output parameter. Return tx msin token tiker
 * @param a_ret_code output parameter. Return ledger return code for returned tx.
 * @param a_action output parameter. Return action for returned tx.
 * @param a_uid output parameter. Return service uid for returned tx.
 * @param a_tx output parameter. Pointer for storaging pointer to returned tx
 * @param a_tx_hash_curr current tx hash. Return hash of next tx that contained in a_datum and get start tx hash
 * @return  0 - ok
 *         -100 - wrong arguments
 *         -101 - addr is not found in cache
 */
int dap_chain_wallet_cache_tx_find_in_history(dap_chain_addr_t *a_addr, char **a_token, int* a_ret_code, dap_chain_tx_tag_action_type_t *a_action,
                                    dap_chain_net_srv_uid_t *a_uid, dap_chain_datum_tx_t **a_tx, dap_hash_fast_t *a_tx_hash_curr);


/**
 * @brief Find unspent outputs for addr in wallet cache
 * @param a_net pointer to a net in which to find tx
 * @param a_token_ticker token ticker for transactions filtering  by it
 * @param a_addr wallet address
 * @param a_outs_list output parameter. Retrun list of outputs
 * @param a_value_needed needed value
 * @param a_value_transfer output parameter. Sum of outs values in list
 * @return  0 - ok
 *         -100 - wrong arguments
 *         -101 - addr is not found in cache
 */
int dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t a_value_needed, uint256_t *a_value_transfer, bool a_mempool_check);
                                                    
int dap_chain_wallet_cache_tx_find_outs_mempool_check(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t *a_value_transfer, bool a_mempool_check);
                                                    
DAP_STATIC_INLINE int dap_chain_wallet_cache_tx_find_outs_with_val(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t a_value_needed, uint256_t *a_value_transfer)
{
    return dap_chain_wallet_cache_tx_find_outs_with_val_mempool_check(a_net, a_token_ticker, a_addr, a_outs_list, a_value_needed, a_value_transfer, true);
}
                                                    
DAP_STATIC_INLINE int dap_chain_wallet_cache_tx_find_outs(dap_chain_net_t *a_net, const char *a_token_ticker, const dap_chain_addr_t *a_addr, 
                                                    dap_list_t **a_outs_list, uint256_t *a_value_transfer)
{
    return dap_chain_wallet_cache_tx_find_outs_mempool_check(a_net, a_token_ticker, a_addr, a_outs_list, a_value_transfer, true);
}

dap_chain_wallet_cache_iter_t *dap_chain_wallet_cache_iter_create(dap_chain_addr_t a_addr);
void dap_chain_wallet_cache_iter_delete(dap_chain_wallet_cache_iter_t *a_iter);
dap_chain_datum_tx_t *dap_chain_wallet_cache_iter_get(dap_chain_wallet_cache_iter_t *a_iter, dap_chain_wallet_getting_type_t a_type);

#ifdef __cplusplus
}
#endif