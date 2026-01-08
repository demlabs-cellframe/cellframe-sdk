/*
 * Authors:
 * Cellframe Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2024-2025
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

   CellFrame SDK is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   CellFrame SDK is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file dap_chain_net_tx_legacy.c
 * @brief Legacy TX creation functions moved from mempool
 * 
 * REFACTORED: Functions moved from mempool to net/tx (correct layer)
 * - Mempool should ONLY manage TX storage (add/remove/find)
 * - TX creation belongs in net/tx module
 * - Uses ledger API (dap_ledger_get_utxo_for_value) for UTXO selection
 * 
 * RENAMED: dap_chain_mempool_* → dap_chain_net_tx_*
 */

#include "dap_chain_net_tx_legacy.h"
#include "dap_chain_mempool.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_datum_tx.h"
#include "dap_common.h"

#define LOG_TAG "net_tx_legacy"

// Forward declaration for mempool datum_add (still needed for adding TX to mempool)
extern char *dap_chain_mempool_datum_add(dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_hash_out_type);

/**
 * @brief Create a transfer transaction
 * 
 * REFACTORED: Uses dap_ledger_get_utxo_for_value instead of wallet functions
 */
char *dap_chain_net_tx_create(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
                               const dap_chain_addr_t *a_addr_from, const dap_chain_addr_t **a_addr_to,
                               const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX], uint256_t *a_value,
                               uint256_t a_value_fee, const char *a_hash_out_type,
                               size_t a_tx_num, dap_time_t *a_time_unlock)
{
    // check valid param
    dap_return_val_if_pass(!a_chain | !a_key_from || !a_addr_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            dap_chain_addr_check_sum(a_addr_from) || !a_tx_num || !a_value, NULL);
    for (size_t i = 0; i < a_tx_num; ++i) {
        dap_return_val_if_pass((a_addr_to && dap_chain_addr_check_sum(a_addr_to[i])) || IS_ZERO_256(a_value[i]), NULL);
    }

    const char *l_native_ticker = dap_chain_net_by_id(a_chain->net_id)->pub.native_ticker;
    bool l_single_channel = !dap_strcmp(a_token_ticker, l_native_ticker);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_total = {}, l_net_fee = {}, l_total_fee = {}, l_fee_transfer = {};
    for (size_t i = 0; i < a_tx_num; ++i) {
        SUM_256_256(l_value_total, a_value[i], &l_value_total);
    }
    uint256_t l_value_need = l_value_total;
    dap_chain_addr_t l_addr_fee = {};
    dap_list_t *l_list_fee_out = NULL;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_chain->net_id, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
    if (l_single_channel)
        SUM_256_256(l_value_need, l_total_fee, &l_value_need);
    else if (!IS_ZERO_256(l_total_fee)) {
        // REFACTORED: Use ledger API directly
        l_list_fee_out = dap_ledger_get_utxo_for_value(l_ledger, l_native_ticker,
                                                       a_addr_from, l_total_fee, &l_fee_transfer);
        if (!l_list_fee_out) {
            log_it(L_WARNING, "Not enough funds to pay fee");
            return NULL;
        }
    }
    dap_list_t *l_list_used_out = NULL;
    // REFACTORED: Use ledger API directly
    l_list_used_out = dap_ledger_get_utxo_for_value(l_ledger, a_token_ticker,
                                                    a_addr_from, l_value_need, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_WARNING, "Not enough funds to transfer");
        dap_list_free_full(l_list_fee_out, NULL);
        return NULL;
    }
    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
        dap_list_free_full(l_list_used_out, NULL);
        if (l_list_fee_out) {
            uint256_t l_value_fee_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_fee_out);
            assert(EQUAL_256(l_value_fee_items, l_fee_transfer));
            dap_list_free_full(l_list_fee_out, NULL);
        }

    }
    if (a_tx_num > 1) {
        uint32_t l_tx_num = a_tx_num;
        dap_chain_tx_tsd_t *l_out_count = dap_chain_datum_tx_item_tsd_create(&l_tx_num, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT, sizeof(uint32_t));
        dap_chain_datum_tx_add_item(&l_tx, l_out_count);
        DAP_DELETE(l_out_count);
    }
    
    uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
    for (size_t i = 0; i < a_tx_num; ++i) {
        if (dap_chain_datum_tx_add_out_std_item(&l_tx, a_addr_to[i], a_value[i], a_token_ticker, a_time_unlock ? a_time_unlock[i] : 0) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        } else if (l_single_channel){
            SUM_256_256(l_value_pack, a_value[i], &l_value_pack);
        }
    }
    uint256_t l_value_back;
    //coin back for multi channel
    if (!l_single_channel) {
        SUBTRACT_256_256(l_value_transfer, l_value_total, &l_value_back);
        if(!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back, a_token_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
    }
    // Network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, 
                                                l_single_channel ? a_token_ticker : l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        else if (l_single_channel){
            SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
        }
    }
    // Validator's fee
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }            
        else if (l_single_channel){
            SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);            
        }
    }
    // coin back
    if (l_single_channel)
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
    else
        SUBTRACT_256_256(l_fee_transfer, l_total_fee, &l_value_back);

    if(!IS_ZERO_256(l_value_back)) {
        if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_from, l_value_back,
                                                l_single_channel ? a_token_ticker : l_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast_t l_tx_hash;
    dap_hash_fast(l_tx, l_tx_size, &l_tx_hash);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    DAP_DELETE(l_tx);
    char *l_ret = dap_chain_mempool_datum_add(l_datum, a_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    return l_ret;
}

// TODO: Implement remaining 5 functions by copying from mempool and replacing:
// 1. dap_chain_wallet_get_list_tx_outs_with_val → dap_ledger_get_utxo_for_value
// 2. Function names: dap_chain_mempool_* → dap_chain_net_tx_*
// 
// Functions to port:
// - dap_chain_net_tx_create_massive
// - dap_chain_net_tx_create_cond_input  
// - dap_chain_net_tx_create_cond
// - dap_chain_net_base_tx_create
// - dap_chain_net_tx_create_event
