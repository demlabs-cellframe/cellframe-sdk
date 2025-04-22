/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2019
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
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <memory.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#include <pthread.h>
#endif

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_http_client.h"
#include "dap_http_simple.h"
#include "dap_enc_base58.h"
#include "dap_enc_http.h"
#include "http_status_code.h"
#include "dap_chain_common.h"
#include "dap_chain_node.h"
#include "dap_global_db.h"
#include "dap_enc.h"
#include <dap_enc_http.h>
#include <dap_enc_key.h>
#include <dap_enc_ks.h>
#include "dap_chain_mempool.h"

#include "dap_common.h"
#include "dap_list.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_net_tx.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_wallet_cache.h"

#define LOG_TAG "dap_chain_mempool"

static bool s_tx_create_massive_gdb_save_callback(dap_global_db_instance_t *a_dbi,
                                                  int a_rc, const char *a_group,
                                                  const size_t a_values_total, const size_t a_values_count,
                                                  dap_global_db_obj_t *a_values, void *a_arg);

int dap_datum_mempool_init(void)
{
    return 0;
}

/**
 * @brief dap_chain_mempool_datum_add
 * @param a_datum
 * @return
 */
char *dap_chain_mempool_datum_add(const dap_chain_datum_t *a_datum, dap_chain_t *a_chain, const char *a_hash_out_type)
{
    dap_return_val_if_pass(!a_datum, NULL);

    dap_chain_hash_fast_t l_key_hash;
    dap_chain_datum_calc_hash(a_datum, &l_key_hash);
    char *l_key_str = dap_chain_hash_fast_to_str_new(&l_key_hash);
    const char *l_key_str_out = dap_strcmp(a_hash_out_type, "hex")
            ? dap_enc_base58_encode_hash_to_str_static(&l_key_hash)
            : l_key_str;

    const char *l_type_str;
    switch (a_datum->header.type_id) {
    case DAP_CHAIN_DATUM_TOKEN:
        l_type_str = "token";
        break;
    case DAP_CHAIN_DATUM_TOKEN_EMISSION: {
        size_t l_emission_size = a_datum->header.data_size;
        dap_chain_datum_token_emission_t *l_emission = dap_chain_datum_emission_read((byte_t*)a_datum->data, &l_emission_size);
        uint64_t l_net_id = l_emission ? l_emission->hdr.address.net_id.uint64 : 0;
        DAP_DELETE(l_emission);
        if (l_net_id != a_chain->net_id.uint64) {
            log_it(L_WARNING, "Datum emission with hash %s NOT placed in mempool: wallet addr net ID %lu != %lu chain net ID",
                   l_key_str_out, l_net_id, a_chain->net_id.uint64);
            DAP_DELETE(l_key_str);
            return NULL;
        }
        l_type_str = "emission";
        break;
    }
    case DAP_CHAIN_DATUM_TX:
        l_type_str = "transaction";
        break;
    default:
        DAP_DATUM_TYPE_STR(a_datum->header.type_id, l_type_str);
    }

    char *l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    int l_res = dap_global_db_set_sync(l_gdb_group, l_key_str, a_datum, dap_chain_datum_size(a_datum), false);//, NULL, NULL);
    if (l_res == DAP_GLOBAL_DB_RC_SUCCESS)
        log_it(L_NOTICE, "Datum %s with hash %s was placed in mempool group %s", l_type_str, l_key_str_out, l_gdb_group);
    else
        log_it(L_WARNING, "Can't place datum %s with hash %s in mempool group %s", l_type_str, l_key_str_out, l_gdb_group);
    char *ret = (l_res == DAP_GLOBAL_DB_RC_SUCCESS) ? dap_strdup(l_key_str_out) : NULL;
    DAP_DELETE(l_gdb_group);
    DAP_DELETE(l_key_str);
    return ret;
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
char *dap_chain_mempool_tx_create(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t** a_addr_to,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t *a_value, uint256_t a_value_fee, const char *a_hash_out_type, size_t a_tx_num)
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
        if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native_ticker, a_addr_from, &l_list_fee_out, l_total_fee, &l_fee_transfer) == -101)
            l_list_fee_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                    a_addr_from, l_total_fee, &l_fee_transfer);
        if (!l_list_fee_out) {
            log_it(L_WARNING, "Not enough funds to pay fee");
            return NULL;
        }
    }
    dap_list_t *l_list_used_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, a_token_ticker, a_addr_from, &l_list_used_out, l_value_need, &l_value_transfer) == -101)
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
                                            a_addr_from, l_value_need, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_WARNING, "Not enough funds to transfer");
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
    }

    uint256_t l_value_pack = {}; // how much datoshi add to 'out' items
    for (size_t i = 0; i < a_tx_num; ++i) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to[i], a_value[i], a_token_ticker) != 1) {            
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

/**
 * Make transfer transaction to collect a commission & insert to cache
 *
 * return hash_tx Ok, , NULL other Error
 */
char *dap_chain_mempool_tx_coll_fee_create(dap_chain_cs_blocks_t *a_blocks, dap_enc_key_t *a_key_from,
                                           const dap_chain_addr_t *a_addr_to, dap_list_t *a_block_list,
                                           uint256_t a_value_fee, const char *a_hash_out_type)
{
    uint256_t                   l_value_out = {};
    uint256_t                   l_net_fee = {};
    dap_chain_datum_tx_t        *l_tx;
    dap_chain_addr_t            l_addr_fee = {};

    dap_return_val_if_fail(a_blocks && a_key_from && a_addr_to && a_block_list, NULL);
    dap_chain_t *l_chain = a_blocks->chain;
    bool l_net_fee_used = dap_chain_net_tx_get_fee(l_chain->net_id, &l_net_fee, &l_addr_fee);
    dap_ledger_t *l_ledger = dap_chain_net_by_id(l_chain->net_id)->pub.ledger;
    dap_pkey_t *l_sign_pkey = dap_pkey_from_enc_key(a_key_from);
    if (!l_sign_pkey) {
        log_it(L_ERROR, "Can't serialize public key of sign certificate");
        return NULL;
    }
    //add tx
    if (NULL == (l_tx = dap_chain_datum_tx_create())) {
        log_it(L_WARNING, "Can't create datum tx");
        return NULL;
    }
    for(dap_list_t *bl = a_block_list; bl; bl = bl->next) {
        uint256_t l_value_out_block = {};
        dap_hash_fast_t *l_block_hash = bl->data;
        dap_chain_block_cache_t *l_block_cache = dap_chain_block_cache_get_by_hash(a_blocks, l_block_hash);
        if (!l_block_cache) {
            char l_block_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(l_block_hash, l_block_hash_str, DAP_HASH_FAST_STR_SIZE);
            log_it(L_ERROR, "Can't find cache for block hash %s", l_block_hash_str);
            continue;
        }
        //verification of signatures of all blocks
        dap_sign_t *l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, 0);
        if (!l_sign || !dap_pkey_compare_with_sign(l_sign_pkey, l_sign)) {
            log_it(L_WARNING, "Block %s signature does not match certificate key", l_block_cache->block_hash_str);
            continue;
        }

        dap_list_t *l_list_used_out = dap_chain_block_get_list_tx_cond_outs_with_val(l_ledger, l_block_cache, &l_value_out_block);
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
    dap_hash_fast_t l_sign_pkey_hash;
    dap_hash_fast(l_sign_pkey->pkey, l_sign_pkey->header.size, &l_sign_pkey_hash);
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
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, l_ledger->net->pub.native_ticker) == 1)
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

    // Check and apply sovereign tax for this key
    uint256_t l_value_tax = {};
    dap_chain_net_srv_stake_item_t *l_key_item = dap_chain_net_srv_stake_check_pkey_hash(l_chain->net_id, &l_sign_pkey_hash);
    if (l_key_item && !IS_ZERO_256(l_key_item->sovereign_tax) &&
                !dap_chain_addr_is_blank(&l_key_item->sovereign_addr)) {
        MULT_256_COIN(l_value_out, l_key_item->sovereign_tax, &l_value_tax);
        if (compare256(l_value_tax, l_value_out) < 1)
            SUBTRACT_256_256(l_value_out, l_value_tax, &l_value_out);
    }

    //add 'out' items
    if (!IS_ZERO_256(l_value_out)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, l_value_out, l_ledger->net->pub.native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create out item in transaction fee");
            return NULL;
        }
    }
    if (!IS_ZERO_256(l_value_tax)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_key_item->sovereign_addr, l_value_tax, l_ledger->net->pub.native_ticker) != 1) {
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
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    return l_ret;
}


/**
 * Make transfer transaction to collect block sign rewards and place it to the mempool
 *
 * return hash_tx Ok, NULL Error
 */
char *dap_chain_mempool_tx_reward_create(dap_chain_cs_blocks_t *a_blocks, dap_enc_key_t *a_sign_key,
                                         dap_chain_addr_t *a_addr_to, dap_list_t *a_block_list,
                                         uint256_t a_value_fee, const char *a_hash_out_type)
{
    dap_return_val_if_fail(a_blocks && a_sign_key && a_addr_to && a_block_list, NULL);
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
    dap_hash_fast_t l_sign_pkey_hash;
    dap_pkey_get_hash(l_sign_pkey, &l_sign_pkey_hash);
    uint256_t l_value_out = uint256_0;
    dap_ledger_t *l_ledger = dap_chain_net_by_id(l_chain->net_id)->pub.ledger;
    for (dap_list_t *it = a_block_list; it; it = it->next) {
        dap_hash_fast_t *l_block_hash = it->data;
        uint256_t l_reward_value = l_chain->callback_calc_reward(l_chain, l_block_hash, l_sign_pkey);
        if (IS_ZERO_256(l_reward_value)) {
            char l_block_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(l_block_hash, l_block_hash_str, DAP_HASH_FAST_STR_SIZE);
            log_it(L_WARNING, "Block %s signatures does not match certificate key", l_block_hash_str);
            continue;
        }
        if (dap_ledger_is_used_reward(l_ledger, l_block_hash, &l_sign_pkey_hash)) {
            char l_block_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(l_block_hash, l_block_hash_str, DAP_HASH_FAST_STR_SIZE);
            char l_sign_pkey_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_sign_pkey_hash, l_sign_pkey_hash_str, DAP_HASH_FAST_STR_SIZE);
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
    bool l_net_fee_used = dap_chain_net_tx_get_fee(l_chain->net_id, &l_net_fee, &l_addr_fee);
    // Network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee,l_ledger->net->pub.native_ticker) == 1)
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
    // Check and apply sovereign tax for this key
    uint256_t l_value_tax = {};
    dap_chain_net_srv_stake_item_t *l_key_item = dap_chain_net_srv_stake_check_pkey_hash(l_chain->net_id, &l_sign_pkey_hash);
    if (l_key_item && !IS_ZERO_256(l_key_item->sovereign_tax) &&
                !dap_chain_addr_is_blank(&l_key_item->sovereign_addr)) {
        MULT_256_COIN(l_value_out, l_key_item->sovereign_tax, &l_value_tax);
        if (compare256(l_value_tax, l_value_out) < 1)
            SUBTRACT_256_256(l_value_out, l_value_tax, &l_value_out);
    }
    //add 'out' items
    if (!IS_ZERO_256(l_value_out)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, l_value_out, l_ledger->net->pub.native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create out item in transaction fee");
            return NULL;
        }
    }
    if (!IS_ZERO_256(l_value_tax)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_key_item->sovereign_addr, l_value_tax, l_ledger->net->pub.native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create out item in transaction fee");
            return NULL;
        }
    }
    // add 'sign' item
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_sign_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Can't sign item in transaction fee");
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    DAP_DELETE(l_tx);
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    return l_ret;
}

/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
int dap_chain_mempool_tx_create_massive( dap_chain_t * a_chain, dap_enc_key_t *a_key_from,
        const dap_chain_addr_t* a_addr_from, const dap_chain_addr_t* a_addr_to,
        const char a_token_ticker[10], uint256_t a_value, uint256_t a_value_fee,
        size_t a_tx_num)
{
    // check valid param
    if(!a_chain | !a_key_from || !a_addr_from || !a_key_from->priv_key_data || !a_key_from->priv_key_data_size ||
            dap_chain_addr_check_sum(a_addr_from) || dap_chain_addr_check_sum(a_addr_to) ||
            IS_ZERO_256(a_value) || !a_tx_num){
        log_it(L_ERROR, "Wrong parameters in dap_chain_mempool_tx_create_massive() call");
        return -1;

    }
    const char *l_native_ticker = dap_chain_net_by_id(a_chain->net_id)->pub.native_ticker;
    if (dap_strcmp(a_token_ticker, l_native_ticker)) {
        log_it(L_WARNING, "dap_chain_mempool_tx_create_massive() should only be used with native token");
        return -2;
    }

    dap_global_db_obj_t * l_objs = DAP_NEW_Z_SIZE(dap_global_db_obj_t, a_tx_num * sizeof (dap_global_db_obj_t));
    uint256_t l_net_fee = {}, l_total_fee = {};
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_chain->net_id, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_net_fee, a_value_fee, &l_total_fee);
    // Search unused out:
    uint256_t l_single_val = {};
    SUM_256_256(a_value, l_total_fee, &l_single_val);
    uint256_t l_value_need = {};
    MULT_256_256(dap_chain_uint256_from(a_tx_num), l_single_val, &l_value_need);
    uint256_t l_value_transfer = {}; // how many coins to transfer
    const char *l_balance; dap_uint256_to_char(l_value_need, &l_balance);
    log_it(L_DEBUG, "Create %"DAP_UINT64_FORMAT_U" transactions, summary %s", a_tx_num, l_balance);
    dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
    dap_list_t *l_list_used_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, a_token_ticker, a_addr_from, &l_list_used_out, l_value_need, &l_value_transfer) == -101)
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
                                                                a_addr_from, l_value_need, &l_value_transfer);
    if (!l_list_used_out) {
        log_it(L_WARNING,"Not enough funds to transfer");
        DAP_DELETE(l_objs);
        return -2;
    }
    
    dap_chain_hash_fast_t l_tx_new_hash = {0};
    for (size_t i=0; i < a_tx_num; ++i){
        log_it(L_DEBUG, "Prepare tx %zu", i);
        // find the transactions from which to take away coins

        // create empty transaction
        dap_chain_datum_tx_t *l_tx_new = dap_chain_datum_tx_create();
        uint256_t l_value_back = {};
        // add 'in' items
        uint256_t l_value_to_items = {}; // how many coins to transfer

        dap_list_t *l_used_out, *l_tmp;
        DL_FOREACH_SAFE(l_list_used_out, l_used_out, l_tmp) {
            dap_chain_tx_used_out_item_t *l_item = l_used_out->data;
            char l_in_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
            dap_chain_hash_fast_to_str(&l_item->tx_hash_fast, l_in_hash_str, sizeof(l_in_hash_str));

            l_balance = dap_uint256_to_char(l_item->value, NULL);
            if (1 == dap_chain_datum_tx_add_in_item(&l_tx_new, &l_item->tx_hash_fast, l_item->num_idx_out)) {
                SUM_256_256(l_value_to_items, l_item->value, &l_value_to_items);
                log_it(L_DEBUG, "Added input %s with %s datoshi", l_in_hash_str, l_balance);
            } else {
                log_it(L_WARNING, "Can't add input from %s with %s datoshi", l_in_hash_str, l_balance);
            }
            DL_DELETE(l_list_used_out, l_used_out);
            DAP_DELETE(l_item);
            if (compare256(l_value_to_items, l_value_transfer) != -1)
                break;
        }
        if (compare256(l_value_to_items, l_single_val) == -1) {
            log_it(L_ERROR, "Not enough values on output to produce enough inputs: %s when need %s", l_balance, dap_uint256_to_char(l_single_val, NULL));
            dap_list_free_full(l_list_used_out, NULL);
            DAP_DELETE(l_objs);
            return -5;
        }

        // add 'out' items
        uint256_t l_value_pack = {}; // how much coin add to 'out' items
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx_new, a_addr_to, a_value, a_token_ticker) == 1)
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
        else {
            dap_chain_datum_tx_delete(l_tx_new);
            dap_list_free_full(l_list_used_out, NULL);
            DAP_DELETE(l_objs);
            return -3;
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx_new, &l_addr_fee, l_net_fee, a_token_ticker) == 1)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else {
                dap_chain_datum_tx_delete(l_tx_new);
                dap_list_free_full(l_list_used_out, NULL);
                DAP_DELETE(l_objs);
                return -3;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx_new, a_value_fee) == 1)
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            else {
                dap_chain_datum_tx_delete(l_tx_new);
                dap_list_free_full(l_list_used_out, NULL);
                DAP_DELETE(l_objs);
                return -3;
            }
        }
        // coin back
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if(dap_chain_datum_tx_add_out_ext_item(&l_tx_new, a_addr_from, l_value_back, a_token_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx_new);
                dap_list_free_full(l_list_used_out, NULL);
                DAP_DELETE(l_objs);
                return -3;
            }
        }

        // add 'sign' items
        if(dap_chain_datum_tx_add_sign_item(&l_tx_new, a_key_from) != 1) {
            dap_chain_datum_tx_delete(l_tx_new);
            dap_list_free_full(l_list_used_out, NULL);
            DAP_DELETE(l_objs);
            return -4;
        }
        // now tx is formed - calc size and hash
        size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx_new);
        dap_hash_fast(l_tx_new, l_tx_size, &l_tx_new_hash);
        // If we have value back - update balance cache
        if (!IS_ZERO_256(l_value_back)) {
            //log_it(L_DEBUG,"We have value back %"DAP_UINT64_FORMAT_U" now lets see how many outputs we have", l_value_back);
            int l_out_idx = 0;
            byte_t *l_item; size_t l_size;
            TX_ITEM_ITER_TX(l_item, l_size, l_tx_new) {
                switch (*l_item) {
                case TX_ITEM_TYPE_OUT_COND:
                    ++l_out_idx;
                    continue;
                case TX_ITEM_TYPE_OUT: case TX_ITEM_TYPE_OUT_EXT: case TX_ITEM_TYPE_OUT_STD:
                    if (*l_item != TX_ITEM_TYPE_OUT_STD) {
                        if ( dap_chain_addr_compare(a_addr_from, &((dap_chain_tx_out_t*)l_item)->addr) ) {
                            ++l_out_idx;
                            continue;
                        }
                    } else if ( dap_chain_addr_compare(a_addr_from, &((dap_chain_tx_out_std_t *)l_item)->addr) ) {
                        ++l_out_idx;
                        continue;
                    }

                    dap_chain_tx_used_out_item_t *l_item_back = DAP_NEW_Z(dap_chain_tx_used_out_item_t);
                    *l_item_back = (dap_chain_tx_used_out_item_t) {
                        .tx_hash_fast   = l_tx_new_hash,
                        .num_idx_out    = l_out_idx,
                        .value          = l_value_back
                    };
                    l_list_used_out = dap_list_prepend(l_list_used_out, l_item_back);
                    log_it(L_DEBUG,"Found change back output, stored back in UTXO table");
                    break;
                default:
                    continue;
                }
                break; // Chargeback out found, exit iteration
            }
        }
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_transfer);

        // Now produce datum
        dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx_new, l_tx_size);
        //dap_global_db_set_sync(l_gdb_group, l_key_str, a_datum, dap_chain_datum_size(l_datum), false);
        l_objs[i].key = dap_chain_hash_fast_to_str_new(&l_tx_new_hash);
        l_objs[i].value = (uint8_t *)l_datum;
        l_objs[i].value_len = dap_chain_datum_size(l_datum);
        l_objs[i].timestamp = dap_nanotime_now();
        log_it(L_DEBUG, "Prepared obj with key %s (value_len = %"DAP_UINT64_FORMAT_U")",
               l_objs[i].key ? l_objs[i].key :"NULL" , l_objs[i].value_len );
        dap_chain_datum_tx_delete(l_tx_new);

    }
    dap_list_free_full(l_list_used_out, NULL);
    char *l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    dap_global_db_set_multiple_zc(l_gdb_group, l_objs, a_tx_num, s_tx_create_massive_gdb_save_callback, NULL);
    DAP_DEL_Z(l_gdb_group);
    return 0;
}

/**
 * @brief s_tx_create_massive_gdb_save_callback
 * @param a_global_db_context
 * @param a_rc
 * @param a_group
 * @param a_key
 * @param a_values_total
 * @param a_values_shift
 * @param a_values_count
 * @param a_values
 * @param a_arg
 */
static bool s_tx_create_massive_gdb_save_callback(dap_global_db_instance_t *a_dbi,
                                                  int a_rc, const char *a_group,
                                                  const size_t a_values_total, const size_t a_values_count,
                                                  dap_global_db_obj_t *a_values, void *a_arg)
{
    if(!a_rc) {
        log_it(L_NOTICE, "%zu transaction are placed in mempool", a_values_total);
        return true;
    } else {
        log_it(L_ERROR, "Can't place %zu transactions  in mempool", a_values_total);
        return false;
    }
}


/**
 * Make transfer transaction & insert to cache
 *
 * return 0 Ok, -2 not enough funds to transfer, -1 other Error
 */
char* dap_chain_mempool_tx_create_cond_input(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_tx_prev_hash,
                                                          const dap_chain_addr_t *a_addr_to, dap_enc_key_t *a_key_tx_sign,
                                                          dap_chain_datum_tx_receipt_t *a_receipt, const char *a_hash_out_type, int *a_ret_status)
{
    dap_ledger_t * l_ledger = a_net ? dap_ledger_by_net_name( a_net->pub.name ) : NULL;
    if ( ! a_net || ! l_ledger || ! a_addr_to ){
        if (a_ret_status)
            *a_ret_status = DAP_CHAIN_MEMPOOL_RET_STATUS_BAD_ARGUMENTS;
        return NULL;
    }

    if (dap_chain_addr_check_sum (a_addr_to)) {
        log_it(L_ERROR, "Wrong address_to checksum");
        if (a_ret_status)
            *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_WRONG_ADDR;
        return NULL;
    }
    dap_chain_hash_fast_t l_tx_final_hash = dap_ledger_get_final_chain_tx_hash(l_ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, a_tx_prev_hash, true);
    if ( dap_hash_fast_is_blank(&l_tx_final_hash) ) {
        log_it(L_WARNING, "Requested conditional transaction is already used out");
        if (a_ret_status)
            *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_FIND_FINAL_TX_HASH;
        return NULL;
    }
    if (dap_strcmp(a_net->pub.native_ticker, dap_ledger_tx_get_token_ticker_by_hash(l_ledger, &l_tx_final_hash))) {
        log_it(L_WARNING, "Pay for service should be only in native token ticker");
        if (a_ret_status)
            *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_NATIVE_TOKEN;
        return NULL;
    }
    if (!dap_hash_fast_compare(&l_tx_final_hash, &a_receipt->receipt_info.prev_tx_cond_hash)){
        log_it(L_WARNING, "Tx hash in receipt doesn't match with hash of last tx cond.");
        if (a_ret_status)
            *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_NATIVE_TOKEN;
        return NULL;
    }

    dap_chain_datum_tx_t *l_tx_cond = dap_ledger_tx_find_by_hash(l_ledger, &l_tx_final_hash);
    int l_out_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(l_tx_cond, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, &l_out_cond_idx);
    if (!l_out_cond) {
        log_it(L_WARNING, "Requested conditioned transaction have no conditioned output");
        if (a_ret_status)
            *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_NO_COND_OUT;
        return NULL;
    }

    dap_chain_tx_out_cond_t *l_out_fee = dap_chain_datum_tx_out_cond_get(l_tx_cond, DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE, NULL);
    uint256_t l_fee = l_out_fee ? l_out_fee->header.value : uint256_0;
    uint256_t l_value_send = a_receipt->receipt_info.value_datoshi;
    uint256_t l_net_fee = {};
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_fee);
    SUM_256_256(l_value_send, l_net_fee, &l_value_send);
    SUM_256_256(l_value_send, l_fee, &l_value_send);
    if (compare256(l_out_cond->header.value, l_value_send) < 0) {
        log_it(L_WARNING, "Requested conditioned transaction have no enough funds");
        if (a_ret_status)
            *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_NOT_ENOUGH;
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_datum_tx_add_item(&l_tx, (byte_t*)a_receipt);
    // add 'in_cond' items
    if (1 != dap_chain_datum_tx_add_in_cond_item(&l_tx, &l_tx_final_hash, l_out_cond_idx, 0)) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can`t add tx cond input");
        if (a_ret_status)
            *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_TX_OUT;
        return NULL;
    }
    // add 'out' item
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, a_receipt->receipt_info.value_datoshi, a_net->pub.native_ticker) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can`t add tx output");
        if (a_ret_status)
            *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_TX_OUT;
        return NULL;
    }
    // add network fee
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, a_net->pub.native_ticker) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it( L_ERROR, "Can`t add tx output");
            if (a_ret_status)
                *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_TX_OUT;
            return NULL;
        }
    }
    // add validator's fee
    if (!IS_ZERO_256(l_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, l_fee) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it( L_ERROR, "Can`t add tx output");
            if (a_ret_status)
                *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_TX_OUT;
            return NULL;
        }
    }
    //add 'out_cond' item
    uint256_t l_new_val = {};
    uint256_t l_value_cond = l_out_cond->header.value;
    SUBTRACT_256_256(l_value_cond, l_value_send, &l_new_val);
    if (!IS_ZERO_256(l_new_val)){
        dap_chain_tx_out_cond_t *l_new_out_cond = DAP_DUP_SIZE(l_out_cond, sizeof(dap_chain_tx_out_cond_t) + l_out_cond->tsd_size);
        l_new_out_cond->header.value = l_new_val;
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_new_out_cond);
        DAP_DELETE(l_new_out_cond);
    }
    // add 'sign' item
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_tx_sign) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        if (a_ret_status)
            *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_CANT_ADD_SIGN;
        return NULL;
    }
    size_t l_tx_size = dap_chain_datum_tx_get_size( l_tx );
    dap_chain_datum_t *l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_TX, l_tx, l_tx_size );
    dap_chain_datum_tx_delete(l_tx);
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    if (a_ret_status)
        *a_ret_status = DAP_CHAIN_MEMPOOl_RET_STATUS_SUCCESS;
    return l_ret;
}

/**
 * Make transfer transaction
 *
 * return dap_chain_datum_t, NULL if Error
 */
char *dap_chain_mempool_tx_create_cond(dap_chain_net_t *a_net,
        dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
        const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
        uint256_t a_value, uint256_t a_value_per_unit_max,
        dap_chain_net_srv_price_unit_uid_t a_unit, dap_chain_net_srv_uid_t a_srv_uid,
        uint256_t a_value_fee, const void *a_cond,
        size_t a_cond_size, const char *a_hash_out_type)
{
    dap_ledger_t * l_ledger = a_net ? dap_ledger_by_net_name( a_net->pub.name ) : NULL;
    // check valid param
    if (!a_net || !l_ledger || !a_key_from || !a_key_cond ||
            !a_key_from->priv_key_data || !a_key_from->priv_key_data_size || IS_ZERO_256(a_value))
        return NULL;

    if (dap_strcmp(a_net->pub.native_ticker, a_token_ticker)) {
        log_it(L_WARNING, "Pay for service should be only in native token ticker");
        return NULL;
    }

    uint256_t l_net_fee = {};
    dap_chain_addr_t l_addr_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_fee);
    // find the transactions from which to take away coins
    uint256_t l_value_transfer = {}; // how many coins to transfer
    uint256_t l_value_need = {};
    SUM_256_256(a_value, a_value_fee, &l_value_need);
    if (l_net_fee_used) {
        SUM_256_256(l_value_need, l_net_fee, &l_value_need);
    }
    // where to take coins for service
    dap_chain_addr_t l_addr_from;
    dap_chain_addr_fill_from_key(&l_addr_from, a_key_from, a_net->pub.id);
    // list of transaction with 'out' items
    dap_list_t *l_list_used_out = NULL;
    if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, a_token_ticker, &l_addr_from, &l_list_used_out, l_value_need, &l_value_transfer) == -101)
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, a_token_ticker,
                                            &l_addr_from, l_value_need, &l_value_transfer);
    if(!l_list_used_out) {
        log_it( L_ERROR, "Nothing to transfer (not enough funds)");
        return NULL;
    }

    // create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    // add 'in' items
    {
        uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
        assert(EQUAL_256(l_value_to_items, l_value_transfer));
        dap_list_free_full(l_list_used_out, NULL);
    }
    // add 'out_cond' and 'out' items
    {
        uint256_t l_value_pack = {}; // how much coin add to 'out' items
        if(dap_chain_datum_tx_add_out_cond_item(&l_tx, a_key_cond, a_srv_uid, a_value, a_value_per_unit_max, a_unit, a_cond,
                a_cond_size) == 1) {
            SUM_256_256(l_value_pack, a_value, &l_value_pack);
        } else {
            dap_chain_datum_tx_delete(l_tx);
            log_it( L_ERROR, "Cant add conditional output");
            return NULL;
        }
        // Network fee
        if (l_net_fee_used) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_fee, l_net_fee, a_net->pub.native_ticker) == 1)
                SUM_256_256(l_value_pack, l_net_fee, &l_value_pack);
            else {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // Validator's fee
        if (!IS_ZERO_256(a_value_fee)) {
            if (dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee) == 1)
                SUM_256_256(l_value_pack, a_value_fee, &l_value_pack);
            else {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // coin back
        uint256_t l_value_back = {};
        SUBTRACT_256_256(l_value_transfer, l_value_pack, &l_value_back);
        if (!IS_ZERO_256(l_value_back)) {
            if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_from, l_value_back, a_net->pub.native_ticker) != 1) {
                dap_chain_datum_tx_delete(l_tx);
                log_it( L_ERROR, "Cant add coin back output");
                return NULL;
            }
        }
    }

    // add 'sign' items
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it( L_ERROR, "Can't add sign output");
        return NULL;
    }
    size_t l_tx_size = dap_chain_datum_tx_get_size( l_tx );
    dap_chain_datum_t *l_datum = dap_chain_datum_create( DAP_CHAIN_DATUM_TX, l_tx, l_tx_size );
    dap_chain_datum_tx_delete(l_tx);
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, a_hash_out_type);
    DAP_DELETE(l_datum);
    return l_ret;
}

char *dap_chain_mempool_base_tx_create(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_emission_hash,
                                       dap_chain_id_t a_emission_chain_id, uint256_t a_emission_value, const char *a_ticker,
                                       dap_chain_addr_t *a_addr_to, dap_enc_key_t *a_private_key,
                                       const char *a_hash_out_type, uint256_t a_value_fee)
{
    dap_return_val_if_fail(a_chain && a_emission_hash && a_private_key, NULL);
    uint256_t l_net_fee = {};
    uint256_t l_total_fee = a_value_fee;
    uint256_t l_value_transfer = {};
    dap_chain_addr_t l_addr_to_fee = {};
    dap_chain_addr_t l_addr_from_fee = {};

    dap_chain_addr_t *l_addr_to = a_addr_to;
    uint256_t l_emission_value = a_emission_value;
    const char *l_emission_ticker = a_ticker;

    if (!a_addr_to) {
        dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
        dap_chain_datum_token_emission_t *l_emission = dap_ledger_token_emission_find(l_net->pub.ledger, a_emission_hash);
        if (!l_emission) {
            log_it(L_WARNING, "Specified emission not found");
            return NULL;
        }
        // TODO add check for used emission
        l_emission_ticker = l_emission->hdr.ticker;
        l_emission_value = l_emission->hdr.value;
        l_addr_to = &l_emission->hdr.address;
    }

    const char *l_native_ticker = dap_chain_net_by_id(a_chain->net_id)->pub.native_ticker;
    bool not_native = dap_strcmp(l_emission_ticker, l_native_ticker);
    bool l_net_fee_used = IS_ZERO_256(a_value_fee) ? false :
                                                     dap_chain_net_tx_get_fee(a_chain->net_id, &l_net_fee, &l_addr_to_fee);
    if (l_net_fee_used)
        SUM_256_256(l_total_fee, l_net_fee, &l_total_fee);

    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    l_tx->header.ts_created = time(NULL);
    //in_ems
    dap_chain_tx_in_ems_t *l_in_ems = dap_chain_datum_tx_item_in_ems_create(a_emission_chain_id, a_emission_hash, l_emission_ticker);
    if (l_in_ems) {
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_in_ems);
        DAP_DELETE(l_in_ems);
    } else {
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    if (not_native && !IS_ZERO_256(l_total_fee))
    {
        if (dap_chain_addr_fill_from_key(&l_addr_from_fee, a_private_key, a_chain->net_id) != 0 ) {
            log_it(L_WARNING,"Can't fill address from transfer");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        dap_ledger_t *l_ledger = dap_chain_net_by_id(a_chain->net_id)->pub.ledger;
        // list of transaction with 'out' items
        dap_list_t *l_list_used_out = NULL;
        if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native_ticker, &l_addr_from_fee, &l_list_used_out, l_total_fee, &l_value_transfer) == -101)
            l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                                     &l_addr_from_fee, l_total_fee, &l_value_transfer);
        if (!l_list_used_out) {
            log_it(L_WARNING,"Not enough funds to transfer");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        //add in
        {
            uint256_t l_value_to_items = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
            assert(EQUAL_256(l_value_to_items, l_value_transfer));
            dap_list_free_full(l_list_used_out, NULL);
        }
         //add out
        uint256_t l_value_back = l_value_transfer; // how much datoshi add to 'out' items
        // Network fee
        if (l_net_fee_used) {
            SUBTRACT_256_256(l_value_back, l_net_fee, &l_value_back);
            if (!dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_to_fee, l_net_fee, l_native_ticker)){
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        if (!IS_ZERO_256(a_value_fee)) {
            SUBTRACT_256_256(l_value_back, a_value_fee, &l_value_back);
            if (!dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee)){
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        // coin back
        if (!dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_from_fee, l_value_back, l_native_ticker)) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
        if (!dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_to, l_emission_value, l_emission_ticker)) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    } else { //native ticker
        //this brunch not only for native ticker
        // it performs when we use service base tx with zero fee for non-native
        // have to use emission ticker for tx
        if (!IS_ZERO_256(a_value_fee)) {
            SUBTRACT_256_256(l_emission_value, a_value_fee, &l_emission_value);
            if (!dap_chain_datum_tx_add_fee_item(&l_tx, a_value_fee)){
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        if (l_net_fee_used) {
            SUBTRACT_256_256(l_emission_value, l_net_fee, &l_emission_value);
            if (!dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_to_fee, l_net_fee, l_native_ticker)) {
                dap_chain_datum_tx_delete(l_tx);
                return NULL;
            }
        }
        if (!dap_chain_datum_tx_add_out_ext_item(&l_tx, l_addr_to, l_emission_value, l_emission_ticker)) {
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }        
    }
    //sign item
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_private_key) < 0) {
        log_it(L_WARNING, "No private key for sign");
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);

    // Pack transaction into the datum
    dap_chain_datum_t * l_datum_tx = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_chain_datum_tx_delete(l_tx);
    char *l_ret = dap_chain_mempool_datum_add(l_datum_tx, a_chain, a_hash_out_type);
    DAP_DELETE(l_datum_tx);
    return l_ret;
}

dap_chain_datum_token_emission_t *dap_chain_mempool_emission_get(dap_chain_t *a_chain, const char *a_emission_hash_str)
{
    dap_chain_datum_t *l_emission = dap_chain_mempool_datum_get(a_chain, a_emission_hash_str);
    if (!l_emission || l_emission->header.type_id != DAP_CHAIN_DATUM_TOKEN_EMISSION)
        return NULL;
    size_t l_emission_size = l_emission->header.data_size;
    dap_chain_datum_token_emission_t *l_ret = dap_chain_datum_emission_read(l_emission->data, &l_emission_size);
    DAP_DELETE(l_emission);
    return l_ret;
}

dap_chain_datum_t *dap_chain_mempool_datum_get(dap_chain_t *a_chain, const char *a_datum_hash_str)
{
    size_t l_datum_size;
    char *l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)dap_global_db_get_sync(l_gdb_group,
                                                    a_datum_hash_str, &l_datum_size, NULL, NULL );
    if (!l_datum) {
        char *l_datum_hash_str_base58 = dap_enc_base58_to_hex_str_from_str(a_datum_hash_str);
        l_datum = (dap_chain_datum_t *)dap_global_db_get_sync(l_gdb_group,
                                    l_datum_hash_str_base58, &l_datum_size, NULL, NULL );
        DAP_DELETE(l_datum_hash_str_base58);
    }
    DAP_DELETE(l_gdb_group);
    
    if (l_datum_size >= sizeof(dap_chain_datum_t) && l_datum_size == dap_chain_datum_size(l_datum))
        return l_datum;
    DAP_DEL_Z(l_datum);
    return NULL;
}

dap_chain_datum_token_emission_t *dap_chain_mempool_datum_emission_extract(dap_chain_t *a_chain, byte_t *a_data, size_t a_size)
{
    if (!a_chain || !a_data || a_size < sizeof(dap_chain_datum_t))
        return NULL;
    dap_chain_datum_t *l_datum = (dap_chain_datum_t *)a_data;
    if ((l_datum->header.version_id != DAP_CHAIN_DATUM_VERSION) || (l_datum->header.type_id != DAP_CHAIN_DATUM_TOKEN_EMISSION) ||
            ((l_datum->header.data_size + sizeof(l_datum->header)) != a_size))
        return NULL;
    dap_chain_datum_token_emission_t *l_emission = (dap_chain_datum_token_emission_t *)l_datum->data;
    if (l_emission->hdr.type != DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH)
        return NULL;
    if (!l_emission->data.type_auth.signs_count)
        return NULL;
    char *l_ticker = l_emission->hdr.ticker;
    if (l_ticker[DAP_CHAIN_TICKER_SIZE_MAX - 1])
        return NULL;
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_chain->net_name);
    if (!l_net)
        return NULL;
    dap_chain_datum_token_t *l_token = dap_ledger_token_ticker_check(l_net->pub.ledger, l_ticker);
    if (!l_token)
        return NULL;
    if (l_token->subtype != DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE && l_token->type == DAP_CHAIN_DATUM_TOKEN_TYPE_DECL)
        return NULL;
    /*int l_signs_valid = 0;
    dap_sign_t *l_ems_sign = (dap_sign_t *)(l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size);
    for (int i = 0; i < l_emission->data.type_auth.signs_count; i++) {
        uint32_t l_ems_pkey_size = l_ems_sign->header.sign_pkey_size;
        dap_sign_t *l_token_sign = (dap_sign_t *)(l_token->tsd_n_signs + l_token->header_native_decl.tsd_total_size);
        for (int j = 0; j < l_token->signs_total; j++) {
            if (l_ems_pkey_size == l_ems_sign->header.sign_pkey_size &&
                    !memcmp(l_token_sign->pkey_n_sign, l_ems_sign->pkey_n_sign, l_ems_pkey_size)) {
                l_signs_valid++;
                break;
            }
            l_token_sign = (dap_sign_t *)((byte_t *)l_token_sign + dap_sign_get_size(l_token_sign));
        }
        l_ems_sign = (dap_sign_t *)((byte_t *)l_ems_sign + dap_sign_get_size(l_ems_sign));
    }
    if (l_signs_valid != l_emission->data.type_auth.signs_count)
        return NULL;*/
    return DAP_DUP_SIZE(l_emission, l_datum->header.data_size);
}

uint8_t* dap_datum_mempool_serialize(dap_datum_mempool_t *datum_mempool, size_t *size)
{
    size_t a_request_size = 2 * sizeof(uint16_t), shift_size = 0;
    for(int i = 0; i < datum_mempool->datum_count; i++) {
        a_request_size += dap_chain_datum_size(datum_mempool->data[i]) + sizeof(uint16_t);
    }
    uint8_t *l_ret = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(uint8_t, a_request_size, NULL);
    uint8_t *l_pos = dap_mempcpy(l_ret, &datum_mempool->version, sizeof(uint16_t));
    l_pos = dap_mempcpy(l_pos, &datum_mempool->datum_count, sizeof(uint16_t));
    for(int i = 0; i < datum_mempool->datum_count; i++) {
        size_t size_one = dap_chain_datum_size(datum_mempool->data[i]);
        l_pos = dap_mempcpy( dap_mempcpy(l_pos, &size_one, sizeof(uint16_t)), datum_mempool->data[i], size_one );
    }
    assert((size_t)(l_pos - l_ret) == a_request_size);
    if(size)
        *size = a_request_size;
    return l_ret;
}

dap_datum_mempool_t * dap_datum_mempool_deserialize(uint8_t *a_datum_mempool_ser, size_t a_datum_mempool_ser_size)
{
    size_t shift_size = 0;
    //uint8_t *a_datum_mempool_ser = DAP_NEW_Z_SIZE(uint8_t, datum_mempool_size / 2 + 1);
    //datum_mempool_size = hex2bin(a_datum_mempool_ser, datum_mempool_str_in, datum_mempool_size) / 2;
    dap_datum_mempool_t *datum_mempool = DAP_NEW_Z(dap_datum_mempool_t);
    if (!datum_mempool) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    datum_mempool->version = *(uint16_t*)(a_datum_mempool_ser + shift_size);
    shift_size += sizeof(uint16_t);
    datum_mempool->datum_count = *(uint16_t*)(a_datum_mempool_ser + shift_size);
    shift_size += sizeof(uint16_t);
    datum_mempool->data = DAP_NEW_Z_SIZE(dap_chain_datum_t*, datum_mempool->datum_count * sizeof(dap_chain_datum_t*));
    for(int i = 0; i < datum_mempool->datum_count; i++) {
        uint16_t size_one = *(uint16_t*)(a_datum_mempool_ser + shift_size);
        shift_size += sizeof(uint16_t);
        datum_mempool->data[i] = DAP_DUP((dap_chain_datum_t*)(a_datum_mempool_ser + shift_size));
        shift_size += size_one;
    }
    assert(shift_size == a_datum_mempool_ser_size);
    return datum_mempool;
}

void dap_datum_mempool_clean(dap_datum_mempool_t *datum)
{
    if(!datum)
        return;
    for(int i = 0; i < datum->datum_count; i++) {
        DAP_DELETE(datum->data[i]);
    }
    DAP_DELETE(datum->data);
    datum->data = NULL;
}

void dap_datum_mempool_free(dap_datum_mempool_t *datum)
{
    dap_datum_mempool_clean(datum);
    DAP_DELETE(datum);
}

/**
 *
 */
static char* s_calc_datum_hash(const void *a_datum_str, size_t datum_size)
{
    dap_chain_hash_fast_t a_hash;
    dap_hash_fast( a_datum_str, datum_size, &a_hash);
    size_t a_str_max = (sizeof(a_hash.raw) + 1) * 2 + 2; /* heading 0x */
    char *a_str = DAP_NEW_Z_SIZE(char, a_str_max);

//    size_t hash_len = dap_chain_hash_fast_to_str(&a_hash, a_str, a_str_max);
    dap_chain_hash_fast_to_str(&a_hash, a_str, a_str_max);

//    if(!hash_len) {
//        DAP_DELETE(a_str);
//        return NULL;
//    }

    return a_str;
}

static void enc_http_reply_encode_new(struct dap_http_simple *a_http_simple, dap_enc_key_t * key,
        enc_http_delegate_t * a_http_delegate)
{
    //dap_enc_key_t * key = dap_enc_ks_find_http(a_http_simple->http);
    if(key == NULL) {
        log_it(L_ERROR, "Can't find http key.");
        return;
    }
    if(a_http_delegate->response) {

        if(a_http_simple->reply)
            DAP_DELETE(a_http_simple->reply);

        size_t l_reply_size_max = dap_enc_code_out_size(a_http_delegate->key,
                a_http_delegate->response_size,
                DAP_ENC_DATA_TYPE_RAW);

        a_http_simple->reply = DAP_NEW_SIZE(void, l_reply_size_max);
        a_http_simple->reply_size = dap_enc_code(a_http_delegate->key,
                a_http_delegate->response, a_http_delegate->response_size,
                a_http_simple->reply, l_reply_size_max,
                DAP_ENC_DATA_TYPE_RAW);

        /*/ decode test
         size_t l_response_dec_size_max = a_http_simple->reply_size ? a_http_simple->reply_size * 2 + 16 : 0;
         char * l_response_dec = a_http_simple->reply_size ? DAP_NEW_Z_SIZE(char, l_response_dec_size_max) : NULL;
         size_t l_response_dec_size = 0;
         if(a_http_simple->reply_size)
         l_response_dec_size = dap_enc_decode(a_http_delegate->key,
         a_http_simple->reply, a_http_simple->reply_size,
         l_response_dec, l_response_dec_size_max,
         DAP_ENC_DATA_TYPE_RAW);
         l_response_dec_size_max = 0;*/
    }

}

/**
 * @brief
 * @param cl_st HTTP server instance
 * @param arg for return code
 */
void chain_mempool_proc(struct dap_http_simple *cl_st, void * arg)
{
    http_status_code_t * return_code = (http_status_code_t*) arg;
    // save key while it alive, i.e. still exist
    dap_enc_key_t *l_enc_key = dap_enc_ks_find_http(cl_st->http_client);
    //dap_enc_key_serialize_t *key_ser = dap_enc_key_serialize(key_tmp);
    //dap_enc_key_t *key = dap_enc_key_deserialize(key_ser, sizeof(dap_enc_key_serialize_t));

    // read header
    dap_http_header_t *hdr_session_close_id =
            (cl_st->http_client) ? dap_http_header_find(cl_st->http_client->in_headers, "SessionCloseAfterRequest") : NULL;
    dap_http_header_t *hdr_key_id =
            (hdr_session_close_id && cl_st->http_client) ? dap_http_header_find(cl_st->http_client->in_headers, "KeyID") : NULL;

    enc_http_delegate_t *l_enc_delegate = enc_http_request_decode(cl_st);
    if(l_enc_delegate) {
        char *suburl = l_enc_delegate->url_path;
        byte_t *l_request_data = l_enc_delegate->request_bytes;
        size_t l_request_size = l_enc_delegate->request_size;
        const char * l_gdb_datum_pool = dap_config_get_item_str_default(g_config, "mempool", "gdb_group", "datum-pool");
        //printf("!!***!!! chain_mempool_proc arg=%d suburl=%s str=%s len=%d\n", arg, suburl, request_str, request_size);
        if(l_request_data && l_request_size > 1) {
            //  find what to do
            uint8_t action = DAP_DATUM_MEMPOOL_NONE; //*(uint8_t*) request_str;
            if(l_enc_delegate->url_path_size > 0) {
                if(!strcmp(suburl, "add"))
                    action = DAP_DATUM_MEMPOOL_ADD;
                else if(!strcmp(suburl, "check"))
                    action = DAP_DATUM_MEMPOOL_CHECK;
                else if(!strcmp(suburl, "del"))
                    action = DAP_DATUM_MEMPOOL_DEL;
            }
            dap_datum_mempool_t *datum_mempool =
                    (action != DAP_DATUM_MEMPOOL_NONE) ?
                            dap_datum_mempool_deserialize((uint8_t*) l_request_data, (size_t) l_request_size) : NULL;
            if(datum_mempool){
                dap_datum_mempool_free(datum_mempool);
                char *a_key = s_calc_datum_hash(l_request_data, (size_t) l_request_size);
                switch (action)
                {
                case DAP_DATUM_MEMPOOL_ADD: // add datum in base
                    //a_value = DAP_NEW_Z_SIZE(char, request_size * 2);
                    //bin2hex((char*) a_value, (const unsigned char*) request_str, request_size);
                    if ( dap_global_db_set_sync(l_gdb_datum_pool, a_key, l_request_data, l_request_size, false) == 0 ) {
                        *return_code = Http_Status_OK;
                    }
                    log_it(L_INFO, "Insert hash: key=%s result:%s", a_key,
                            (*return_code == Http_Status_OK) ? "OK" : "False!");
                    break;

                case DAP_DATUM_MEMPOOL_CHECK: // check datum in base

                    strcpy(cl_st->reply_mime, "text/text");
                    size_t l_datum_size = 0;
                    byte_t *l_datum = dap_global_db_get_sync( l_gdb_datum_pool, a_key,&l_datum_size,NULL,NULL );
                    if(l_datum) {
                        l_enc_delegate->response = strdup("1");
                        DAP_DEL_Z(l_datum);
                        log_it(L_INFO, "Check hash: key=%s result: Present", a_key);
                    }
                    else {
                        l_enc_delegate->response = strdup("0");
                        log_it(L_INFO, "Check hash: key=%s result: Absent", a_key);
                    }
                    l_enc_delegate->response_size = l_datum_size;
                    *return_code = Http_Status_OK;
                    enc_http_reply_encode_new(cl_st, l_enc_key, l_enc_delegate);
                    break;

                case DAP_DATUM_MEMPOOL_DEL: // delete datum in base
                    strcpy(cl_st->reply_mime, "text/text");
                    if (dap_global_db_del_sync(l_gdb_datum_pool, a_key) == 0){
                        l_enc_delegate->response = dap_strdup("1");
                        log_it(L_INFO, "Delete hash: key=%s result: Ok", a_key);
                    } else {
                        l_enc_delegate->response = dap_strdup("0");
                        log_it(L_INFO, "Delete hash: key=%s result: False!", a_key);
                    }
                    // TODO rework to async processing and return result of delete action
                    *return_code = Http_Status_OK;
                    enc_http_reply_encode_new(cl_st, l_enc_key, l_enc_delegate);
                    break;

                default: // unsupported command
                    log_it(L_INFO, "Unknown request=%s! key=%s", (suburl) ? suburl : "-", a_key);
                    enc_http_delegate_delete(l_enc_delegate);
                    dap_enc_ks_delete(hdr_key_id->value);
                    *return_code = Http_Status_BadRequest;
                    return;
                }
                DAP_DEL_Z(a_key);
            } else
                *return_code = Http_Status_BadRequest;
        } else
            *return_code = Http_Status_BadRequest;

        enc_http_delegate_delete(l_enc_delegate);
    } else
        *return_code = Http_Status_Unauthorized;

    if (hdr_session_close_id && !strcmp(hdr_session_close_id->value, "yes") && hdr_key_id)
        // close session
        dap_enc_ks_delete(hdr_key_id->value);
}

/**
 * @brief chain_mempool_add_proc
 * @param sh HTTP server instance
 * @param url URL string
 */
void dap_chain_mempool_add_proc(dap_http_server_t * a_http_server, const char * a_url)
{
    dap_http_simple_proc_add(a_http_server, a_url, 4096, chain_mempool_proc);
}

/**
 * @breif dap_chain_mempool_filter
 * @param a_chain chain whose mempool will be filtered.
 * @param a_removed Pointer to a variable of type int which will store how many remote datums.
 */
void dap_chain_mempool_filter(dap_chain_t *a_chain, int *a_removed){
    if (!a_chain) {
        if (a_removed)
            *a_removed = 0;
        return;
    }
    int l_removed = 0;
    char * l_gdb_group = dap_chain_net_get_gdb_group_mempool_new(a_chain);
    size_t l_objs_size = 0;
    dap_time_t l_cut_off_time = dap_time_now() - 3 * 24 * 3600; // 3 days
    char l_cut_off_time_str[DAP_TIME_STR_SIZE] = {'\0'};
    dap_time_to_str_rfc822(l_cut_off_time_str, DAP_TIME_STR_SIZE, l_cut_off_time);
    dap_global_db_obj_t * l_objs = dap_global_db_get_all_sync(l_gdb_group, &l_objs_size);
    for (size_t i = 0; i < l_objs_size; i++) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t*)l_objs[i].value;
        if (!l_datum) {
            l_removed++;
            log_it(L_NOTICE, "Removed datum from mempool with \"%s\" key group %s: empty (possibly trash) value", l_objs[i].key, l_gdb_group);
            dap_global_db_del_sync(l_gdb_group, l_objs[i].key);
            continue;
        }
        size_t l_datum_size = dap_chain_datum_size(l_datum);
        //Filter data size
        if (l_datum_size != l_objs[i].value_len) {
            l_removed++;
            log_it(L_NOTICE, "Removed datum from mempool with \"%s\" key group %s. The size of the datum defined by the "
                             "function and the size specified in the record do not match.", l_objs[i].key, l_gdb_group);
            dap_global_db_del_sync(l_gdb_group, l_objs[i].key);
            continue;
        }
        //Filter hash
        if (dap_strcmp(dap_get_data_hash_str(l_datum->data, l_datum->header.data_size).s, l_objs[i].key) != 0) {
            l_removed++;
            log_it(L_NOTICE, "Removed datum from mempool with \"%s\" key group %s. The hash of the contents of the "
                             "datum does not match the key.", l_objs[i].key, l_gdb_group);
            dap_global_db_del_sync(l_gdb_group, l_objs[i].key);
            continue;
        }
        //Filter time
        if (l_datum->header.ts_create < l_cut_off_time) {
            l_removed++;
            log_it(L_NOTICE, "Removed datum from mempool with \"%s\" key group %s. The datum in the mempool was "
                             "created after the %s.", l_objs[i].key, l_gdb_group, l_cut_off_time_str);
            dap_global_db_del_sync(l_gdb_group, l_objs[i].key);
        }
        //Filter size decree
        if (l_datum->header.type_id == DAP_CHAIN_DATUM_DECREE) {
            size_t l_decree_size = dap_chain_datum_decree_get_size((dap_chain_datum_decree_t*)l_datum->data);
            if (l_datum->header.data_size != l_decree_size) {
                l_removed++;
                log_it(L_NOTICE, "Removed datum from mempool with \"%s\" key group %s. Decree datums do not have a "
                                 "valid size.", l_objs[i].key, l_gdb_group);
                dap_global_db_del_sync(l_gdb_group, l_objs[i].key);
            }
        }
    }
    dap_global_db_objs_delete(l_objs, l_objs_size);
    log_it(L_NOTICE, "Filter removed: %i records.", l_removed);
    DAP_DELETE(l_gdb_group);
}
