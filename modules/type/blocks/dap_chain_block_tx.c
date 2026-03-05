/*
 * Authors:
 * CellFrame Team <https://cellframe.net>
 * DeM Labs Inc.   <https://demlabs.net>
 * DeM Labs Open source community <https://gitlab.demlabs.net>
 *
 * Copyright  (c) 2017-2025
 * All rights reserved.

 * This file is part of CellFrame SDK
 *
 * CellFrame SDK is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * CellFrame SDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dap_chain_block_tx.h"
#include "dap_chain_block_cache.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_net_fee.h"  // Fee management (moved from net-tx to net core)
#include "dap_chain_net_api.h"  // Use net API for mempool (breaks blocks -> mempool cycle)
#include "dap_pkey.h"
#include "dap_sign.h"
#include "dap_chain_block_callbacks.h"  // Phase 5.3: Callback API for breaking stake cycle
#include "dap_chain_net_fee.h"  // Fee management (now in net core, NO net-tx dependency)

#define LOG_TAG "dap_chain_block_tx"

/**
 * @brief Make transfer transaction to collect a commission & insert to mempool
 * @details Collects fees from conditional outputs in blocks
 * @param a_blocks Block structure
 * @param a_key_from Private key for signing transaction
 * @param a_addr_to Destination address for collected fees
 * @param a_block_list List of block hashes to collect from
 * @param a_ledger Ledger instance to work with
 * @param a_native_ticker Native token ticker
 * @param a_net_id Network ID for fee calculation
 * @param a_value_fee Validator fee
 * @param a_hash_out_type Output hash type string
 * @return Transaction hash string on success, NULL on error
 */
char *dap_chain_block_tx_coll_fee_create(dap_chain_type_blocks_t *a_blocks, 
                                         dap_enc_key_t *a_key_from,
                                         const dap_chain_addr_t *a_addr_to, 
                                         dap_list_t *a_block_list,
                                         dap_ledger_t *a_ledger,
                                         const char *a_native_ticker,
                                         dap_chain_net_id_t a_net_id,
                                         uint256_t a_value_fee, 
                                         const char *a_hash_out_type)
{
    uint256_t                   l_value_out = {};
    uint256_t                   l_net_fee = {};
    dap_chain_datum_tx_t        *l_tx;
    dap_chain_addr_t            l_addr_fee = {};

    dap_return_val_if_fail(a_blocks && a_key_from && a_addr_to && a_block_list && a_ledger && a_native_ticker, NULL);
    dap_chain_t *l_chain = a_blocks->chain;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net_id, &l_net_fee, &l_addr_fee);
    dap_pkey_t *l_sign_pkey = dap_pkey_from_enc_key(a_key_from);
    if (!l_sign_pkey) {
        log_it(L_ERROR, "Can't serialize public key of sign certificate");
        return NULL;
    }
    //add tx
    if (NULL == (l_tx = dap_chain_datum_tx_create())) {
        log_it(L_WARNING, "Can't create datum tx");
        DAP_DELETE(l_sign_pkey);
        return NULL;
    }
    for(dap_list_t *bl = a_block_list; bl; bl = bl->next) {
        uint256_t l_value_out_block = {};
        dap_hash_sha3_256_t *l_block_hash = bl->data;
        dap_chain_block_cache_t *l_block_cache = dap_chain_block_cache_get_by_hash(a_blocks, l_block_hash);
        if (!l_block_cache) {
            char l_block_hash_str[DAP_HASH_SHA3_256_STR_SIZE];
            dap_hash_sha3_256_to_str(l_block_hash, l_block_hash_str, DAP_HASH_SHA3_256_STR_SIZE);
            log_it(L_ERROR, "Can't find cache for block hash %s", l_block_hash_str);
            continue;
        }
        //verification of signatures of all blocks
        dap_sign_t *l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, 0);
        if (!l_sign || !dap_pkey_compare_with_sign(l_sign_pkey, l_sign)) {
            log_it(L_WARNING, "Block %s signature does not match certificate key", l_block_cache->block_hash_str);
            continue;
        }

        dap_list_t *l_list_used_out = dap_chain_block_get_list_tx_cond_outs_with_val(a_ledger, l_block_cache, &l_value_out_block);
        if (!l_list_used_out)
            continue;

        //add 'in' items
        {
            uint256_t l_value_to_items = dap_chain_datum_tx_add_in_cond_item_list(&l_tx, l_list_used_out);
            assert(EQUAL_256(l_value_to_items, l_value_out_block));
#ifndef DAP_DEBUG
            UNUSED(l_value_to_items);
#endif
            dap_list_free_full(l_list_used_out, NULL);
        }
        SUM_256_256(l_value_out, l_value_out_block, &l_value_out);
    }
    dap_hash_sha3_256_t l_sign_pkey_hash;
    dap_hash_sha3_256(l_sign_pkey->pkey, l_sign_pkey->header.size, &l_sign_pkey_hash);
    DAP_DELETE(l_sign_pkey);

    if (dap_chain_datum_tx_get_size(l_tx) == sizeof(dap_chain_datum_tx_t)) {
        // tx is empty, no valid inputs
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    //add 'fee' items
    {
        uint256_t l_value_pack = {};
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, a_native_ticker) == 1)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else {
                log_it(L_WARNING, "Can't create net_fee out item in transaction fee");
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            else {
                log_it(L_WARNING, "Can't create valid_fee item in transaction fee");
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        if (compare256(l_value_out, l_value_pack) == 1)
            SUBTRACT_256_256(l_value_out, l_value_pack, &l_value_out);
        else {
            log_it(L_WARNING, "The transaction fee is greater than the sum of the block fees");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }

    // Check and apply sovereign tax for this key (via callback to avoid stake dependency)
    uint256_t l_value_tax = {};
    dap_chain_sovereign_tax_info_t *l_tax_info = dap_chain_block_callbacks_get_sovereign_tax(a_net_id, &l_sign_pkey_hash);
    if (l_tax_info && l_tax_info->has_tax && !IS_ZERO_256(l_tax_info->sovereign_tax) &&
                !dap_chain_addr_is_blank(&l_tax_info->sovereign_addr)) {
        MULT_256_COIN(l_value_out, l_tax_info->sovereign_tax, &l_value_tax);
        if (compare256(l_value_tax, l_value_out) < 1)
            SUBTRACT_256_256(l_value_out, l_value_tax, &l_value_out);
        else {
            DAP_DELETE(l_tax_info);
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Sovereign tax exceeds transaction value");
            return NULL;
        }
    }

    //add 'out' items
    if (!IS_ZERO_256(l_value_out)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, l_value_out, a_native_ticker) != 1) {
            DAP_DELETE(l_tax_info);
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create out item in transaction fee");
            return NULL;
        }
    }
    if (!IS_ZERO_256(l_value_tax)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_tax_info->sovereign_addr, l_value_tax, a_native_ticker) != 1) {
            DAP_DELETE(l_tax_info);
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create sovereign tax out item in transaction fee");
            return NULL;
        }
    }
    DAP_DELETE(l_tax_info);

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Can't sign item in transaction fee");
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    DAP_DELETE(l_tx);
    char *l_ret = dap_chain_net_api_datum_add_to_mempool(l_datum, l_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    return l_ret;
}


/**
 * @brief Make transfer transaction to collect block sign rewards and place it to the mempool
 * @param a_blocks Block structure
 * @param a_sign_key Private key for signing
 * @param a_addr_to Destination address for rewards
 * @param a_block_list List of block hashes to collect rewards from
 * @param a_ledger Ledger instance
 * @param a_native_ticker Native token ticker
 * @param a_net_id Network ID for fee calculation
 * @param a_value_fee Validator fee
 * @param a_hash_out_type Output hash type string
 * @return Transaction hash string on success, NULL on error
 */
char *dap_chain_block_tx_reward_create(dap_chain_type_blocks_t *a_blocks, 
                                       dap_enc_key_t *a_sign_key,
                                       dap_chain_addr_t *a_addr_to, 
                                       dap_list_t *a_block_list,
                                       dap_ledger_t *a_ledger,
                                       const char *a_native_ticker,
                                       dap_chain_net_id_t a_net_id,
                                       uint256_t a_value_fee, 
                                       const char *a_hash_out_type)
{
    dap_return_val_if_fail(a_blocks && a_sign_key && a_addr_to && a_block_list && a_ledger && a_native_ticker, NULL);
    dap_chain_t *l_chain = a_blocks->chain;
    //add tx
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Can't create datum tx");
        return NULL;
    }
    dap_pkey_t *l_sign_pkey = dap_pkey_from_enc_key(a_sign_key);
    if (!l_sign_pkey) {
        log_it(L_ERROR, "Can't serialize public key of sign certificate");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    dap_hash_sha3_256_t l_sign_pkey_hash;
    dap_pkey_get_hash(l_sign_pkey, &l_sign_pkey_hash);
    uint256_t l_value_out = uint256_0;
    for (dap_list_t *it = a_block_list; it; it = it->next) {
        dap_hash_sha3_256_t *l_block_hash = it->data;
        uint256_t l_reward_value = l_chain->callback_calc_reward(l_chain, l_block_hash, l_sign_pkey);
        if (IS_ZERO_256(l_reward_value)) {
            char l_block_hash_str[DAP_HASH_SHA3_256_STR_SIZE];
            dap_hash_sha3_256_to_str(l_block_hash, l_block_hash_str, DAP_HASH_SHA3_256_STR_SIZE);
            log_it(L_WARNING, "Block %s signatures does not match certificate key", l_block_hash_str);
            continue;
        }
        if (dap_ledger_is_used_reward(a_ledger, l_block_hash, &l_sign_pkey_hash)) {
            char l_block_hash_str[DAP_HASH_SHA3_256_STR_SIZE];
            dap_hash_sha3_256_to_str(l_block_hash, l_block_hash_str, DAP_HASH_SHA3_256_STR_SIZE);
            char l_sign_pkey_hash_str[DAP_HASH_SHA3_256_STR_SIZE];
            dap_hash_sha3_256_to_str(&l_sign_pkey_hash, l_sign_pkey_hash_str, DAP_HASH_SHA3_256_STR_SIZE);
            log_it(L_WARNING, "Block %s reward is already collected by signer %s", l_block_hash_str, l_sign_pkey_hash_str);
            continue;
        }
        //add 'in_reward' items
        if (dap_chain_datum_tx_add_in_reward_item(&l_tx, l_block_hash) != 1) {
            log_it(L_ERROR, "Can't create in_reward item for reward collect TX");
            continue;
        }
        SUM_256_256(l_value_out, l_reward_value, &l_value_out);
    }
    DAP_DELETE(l_sign_pkey);

    if (dap_chain_datum_tx_get_size(l_tx) == sizeof(dap_chain_datum_tx_t)) {
        // tx is empty, no valid inputs
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    uint256_t l_net_fee = uint256_0, l_total_fee = uint256_0;
    dap_chain_addr_t l_addr_fee = c_dap_chain_addr_blank;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net_id, &l_net_fee, &l_addr_fee);
    // Network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, a_native_ticker) == 1)
            SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);
        else {
            log_it(L_WARNING, "Can't create network fee out item for reward collect TX");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    // Validator's fee
    if (!IS_ZERO_256(a_value_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
            SUM_256_256(l_total_fee, a_value_fee, &l_total_fee);
        else {
            log_it(L_WARNING, "Can't create validator fee out item for reward collect TX");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }
    if (SUBTRACT_256_256(l_value_out, l_total_fee, &l_value_out)) {
        log_it(L_WARNING, "The transaction fee is greater than the sum of the block sign rewards");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    // Check and apply sovereign tax for this key (via callback to avoid stake dependency)
    uint256_t l_value_tax = {};
    dap_chain_sovereign_tax_info_t *l_tax_info = dap_chain_block_callbacks_get_sovereign_tax(a_net_id, &l_sign_pkey_hash);
    if (l_tax_info && l_tax_info->has_tax && !IS_ZERO_256(l_tax_info->sovereign_tax) &&
                !dap_chain_addr_is_blank(&l_tax_info->sovereign_addr)) {
        MULT_256_COIN(l_value_out, l_tax_info->sovereign_tax, &l_value_tax);
        if (compare256(l_value_tax, l_value_out) < 1)
            SUBTRACT_256_256(l_value_out, l_value_tax, &l_value_out);
        else {
            DAP_DELETE(l_tax_info);
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Sovereign tax exceeds transaction value");
            return NULL;
        }
    }
    //add 'out' items
    if (!IS_ZERO_256(l_value_out)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, l_value_out, a_native_ticker) != 1) {
            DAP_DELETE(l_tax_info);
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create out item in transaction fee");
            return NULL;
        }
    }
    if (!IS_ZERO_256(l_value_tax)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_tax_info->sovereign_addr, l_value_tax, a_native_ticker) != 1) {
            DAP_DELETE(l_tax_info);
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create sovereign tax out item in transaction fee");
            return NULL;
        }
    }
    DAP_DELETE(l_tax_info);
    // add 'sign' item
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_sign_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Can't sign item in transaction fee");
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    DAP_DELETE(l_tx);
    char *l_ret = dap_chain_net_api_datum_add_to_mempool(l_datum, l_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    return l_ret;
}

/**
 * @brief Get reward and fees from blocks before hardfork (stacked)
 * @param a_blocks Block structure
 * @param a_key_from Private key for signing
 * @param a_addr_to Destination address
 * @param a_ledger Ledger instance
 * @param a_native_ticker Native token ticker
 * @param a_net_id Network ID for fee calculation
 * @param a_value_fee Validator fee
 * @param a_hash_out_type Output hash type string
 * @return Transaction hash string on success, NULL on error
 */
char *dap_chain_block_tx_coll_fee_stack_create(dap_chain_type_blocks_t *a_blocks, 
                                               dap_enc_key_t *a_key_from,
                                               const dap_chain_addr_t *a_addr_to,
                                               dap_ledger_t *a_ledger,
                                               const char *a_native_ticker,
                                               dap_chain_net_id_t a_net_id,
                                               uint256_t a_value_fee, 
                                               const char *a_hash_out_type)
{
    uint256_t                   l_net_fee = {};
    dap_chain_datum_tx_t        *l_tx;
    dap_chain_addr_t            l_addr_fee = {};

    dap_return_val_if_fail(a_blocks && a_key_from && a_addr_to && a_ledger && a_native_ticker, NULL);

    dap_hash_sha3_256_t l_sign_pkey_hash;
    dap_enc_key_get_pkey_hash(a_key_from, DAP_HASH_TYPE_SHA3_256, l_sign_pkey_hash.raw, sizeof(dap_hash_sha3_256_t));
    dap_chain_addr_t l_addr_to = { };
    dap_chain_addr_fill(&l_addr_to, dap_sign_type_from_key_type(a_key_from->type), &l_sign_pkey_hash, a_net_id);
    dap_chain_t *l_chain = a_blocks->chain;
    assert(l_chain);
    assert(a_ledger);
    log_it(L_INFO, "Try to find tx with OUT addr %s", dap_chain_addr_to_str_static(&l_addr_to));
    dap_hash_sha3_256_t l_prev_tx_hash = {};
    dap_chain_datum_tx_t *l_prev_tx = dap_ledger_tx_find_by_addr(a_ledger, a_native_ticker, &l_addr_to, &l_prev_tx_hash, true);
    if (!l_prev_tx) {
        log_it(L_WARNING, "Can't find tx with OUT addr %s", dap_chain_addr_to_str_static(&l_addr_to));
        return NULL;
    }
    uint8_t *l_out_prev = dap_chain_datum_tx_item_get(l_prev_tx, NULL, NULL, TX_ITEM_TYPE_OUT_STD, NULL);
    if (!l_out_prev) {
        log_it(L_WARNING, "Can't find OUT_STD item in tx with addr %s", dap_chain_addr_to_str_static(&l_addr_to));
        return NULL;
    }
    
    if (NULL == (l_tx = dap_chain_datum_tx_create())) {
        log_it(L_WARNING, "Can't create datum tx");
        return NULL;
    }

    // add 'in' items
    if (dap_chain_datum_tx_add_in_item(&l_tx, &l_prev_tx_hash, 0) != 1) {
        log_it(L_WARNING, "Can't add in item in transaction fee");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // Check and apply sovereign tax for this key (via callback to avoid stake dependency)
    uint256_t l_value_tax = {}, l_value_out = ((dap_chain_tx_out_std_t *)l_out_prev)->value;
    if (IS_ZERO_256(l_value_out)) {
        log_it(L_WARNING, "OUT_STD item in tx with addr %s has zero value", dap_chain_addr_to_str_static(&l_addr_to));
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    dap_chain_sovereign_tax_info_t *l_tax_info = dap_chain_block_callbacks_get_sovereign_tax(a_net_id, &l_sign_pkey_hash);
    if (l_tax_info && l_tax_info->has_tax && !IS_ZERO_256(l_tax_info->sovereign_tax) &&
                !dap_chain_addr_is_blank(&l_tax_info->sovereign_addr)) {
        MULT_256_COIN(l_value_out, l_tax_info->sovereign_tax, &l_value_tax);
        if (compare256(l_value_tax, l_value_out) < 1)
            SUBTRACT_256_256(l_value_out, l_value_tax, &l_value_out);
        else {
            DAP_DELETE(l_tax_info);
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Sovereign tax exceeds transaction value");
            return NULL;
        }
    }
    if (!IS_ZERO_256(l_value_tax)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_tax_info->sovereign_addr, l_value_tax, a_native_ticker) != 1) {
            DAP_DELETE(l_tax_info);
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create sovereign tax out item in transaction fee");
            return NULL;
        }
    }
    DAP_DELETE(l_tax_info);

    // Network fee
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net_id, &l_net_fee, &l_addr_fee);
    //add 'fee' items
    {
        uint256_t l_value_pack = {};
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, a_native_ticker) == 1)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else {
                log_it(L_WARNING, "Can't create net_fee out item in transaction fee");
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            else {
                log_it(L_WARNING, "Can't create valid_fee item in transaction fee");
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        if (compare256(l_value_out, l_value_pack) == 1)
            SUBTRACT_256_256(l_value_out, l_value_pack, &l_value_out);
        else {
            log_it(L_WARNING, "The transaction fee is greater than the sum of the block fees");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }

    //add 'out' items
    if (!IS_ZERO_256(l_value_out)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, l_value_out, a_native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create out item in transaction fee");
            return NULL;
        }
    }
    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Can't sign item in transaction fee");
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    DAP_DELETE(l_tx);
    char *l_ret = dap_chain_net_api_datum_add_to_mempool(l_datum, l_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    return l_ret;
}

